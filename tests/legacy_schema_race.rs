//! Deterministic reproduction with published alpha.2, private HOME and a fake Unix controller.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
struct Receiver(Child);
impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn command(binary: &Path, root: &Path) -> Command {
    let mut c = Command::new(binary);
    c.env_clear()
        .env("HOME", root)
        .env("PATH", root.join("bin"))
        .env("XDG_STATE_HOME", root.join("s"))
        .env("XDG_DATA_HOME", root.join("d"))
        .env("XDG_CONFIG_HOME", root.join("f"))
        .env("CODEX_HOME", root.join("c"))
        .env("CODEX_WAKE_RPC_SOCKET", root.join("socket"))
        .env("CODEX_WAKE_CODEX", "/bin/false")
        .env("CODEX_WAKE_GH", "/bin/false")
        .env("CODEX_WAKE_ENABLE_WEBHOOKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}
fn schema(db: &rusqlite::Connection) -> Vec<String> {
    db.prepare("SELECT name || ':' || coalesce(sql,'') FROM sqlite_master ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}
#[test]
#[ignore = "requires explicitly supplied published alpha.2 fixture; no service or credentials"]
fn alpha2_can_change_its_schema_after_a_rejected_upgrade() {
    let legacy =
        std::path::PathBuf::from(std::env::var_os("WAKE_LEGACY_BINARY").expect("legacy fixture"));
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("bin")).unwrap();
    let systemctl = root.join("bin/systemctl");
    fs::write(&systemctl,"#!/bin/sh\n[ \"$2\" = show ] || exit 99\nprintf 'LoadState=loaded\\nActiveState=active\\nMainPID=123\\n'\n").unwrap();
    fs::set_permissions(systemctl, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        command(&legacy, root)
            .args([
                "register",
                "--repo",
                "fixture/repo",
                "--run",
                "1",
                "--attempt",
                "1",
                "--thread",
                "11111111-1111-4111-8111-111111111111",
                "--sha",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ])
            .status()
            .unwrap()
            .success()
    );
    let db = rusqlite::Connection::open(root.join("s/codex-wake/state.sqlite3")).unwrap();
    db.busy_timeout(Duration::from_secs(15)).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let before = schema(&db);
    let listener = UnixListener::bind(root.join("socket")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let finish = stop.clone();
    let server = thread::spawn(move || {
        while !finish.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    thread::spawn(move || {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let Ok(mut ws) = tungstenite::accept(stream) else {
                            return;
                        };
                        while let Ok(tungstenite::Message::Text(text)) = ws.read() {
                            let message: Value = serde_json::from_str(&text).unwrap();
                            if let Some(id) = message.get("id")
                                && ws
                                    .send(tungstenite::Message::Text(
                                        json!({"id":id,"result":{"data":[]}}).to_string().into(),
                                    ))
                                    .is_err()
                            {
                                break;
                            }
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("private listener failed: {e}"),
            }
        }
    });
    let mut receiver = Receiver(command(&legacy, root).arg("receiver").spawn().unwrap());
    let pid = receiver.0.id();
    let digest = Sha256::digest(fs::read(&legacy).unwrap());
    let output = command(Path::new(env!("CARGO_BIN_EXE_codex-wake")), root)
        .env("CODEX_WAKE_COOPERATIVE_RECEIVER", "1")
        .arg("ensure")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        schema(&db),
        before,
        "updater altered schema while alpha.2 was fenced by the test's SQLite lock"
    );
    // Only alpha.2 can now make this schema change; the rejected updater has already exited.
    db.execute_batch("COMMIT").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let after = loop {
        let after = schema(&db);
        if after != before {
            break after;
        }
        assert!(
            Instant::now() < deadline,
            "legacy did not initialize workers"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert!(receiver.0.try_wait().unwrap().is_none());
    assert_eq!(receiver.0.id(), pid);
    assert_eq!(Sha256::digest(fs::read(&legacy).unwrap()), digest);
    assert!(!root.join("s/codex-wake/cooperative-upgrade.json").exists());
    let added: Vec<_> = after
        .iter()
        .filter(|s| !before.contains(s))
        .map(|s| s.split(':').next().unwrap())
        .collect();
    println!(
        "updater_rejected=true schema_unchanged_until_legacy_released=true pid_unchanged=true binary_unchanged=true journal_absent=true live_schema_comparison=false added_by_alpha2={added:?}"
    );
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
}
