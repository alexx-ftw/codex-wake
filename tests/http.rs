use hmac::{Hmac, Mac};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use sha2::Sha256;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

type HmacSha256 = Hmac<Sha256>;
const SECRET: &str = "local-http-test-secret";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const THREAD: &str = "11111111-1111-4111-8111-111111111111";

struct Receiver {
    child: Child,
    log: PathBuf,
}
impl Drop for Receiver {
    fn drop(&mut self) {
        let group = format!("-{}", self.child.id());
        let _ = Command::new("kill")
            .args(["-TERM", "--", &group])
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = Command::new("kill")
            .args(["-KILL", "--", &group])
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.log);
    }
}

fn cli(db: &Path, codex: &Path, args: &[&str]) -> std::process::Output {
    let root = db.parent().unwrap();
    let state = root.join("codex-wake");
    fs::create_dir_all(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    Command::new(env!("CARGO_BIN_EXE_codex-wake"))
        .args([
            "--db",
            db.to_str().unwrap(),
            "--codex",
            codex.to_str().unwrap(),
        ])
        .args(args)
        .env("XDG_STATE_HOME", root)
        .env("CODEX_HOME", root.join("codex-home"))
        .env_remove("CODEX_WAKE_PLUGIN_BASE")
        .env_remove("CODEX_WAKE_PLUGIN_ROOT")
        .output()
        .unwrap()
}

fn request(
    addr: std::net::SocketAddr,
    method: &str,
    body: &[u8],
    event: Option<&str>,
    signature: Option<&str>,
) -> u16 {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} /hooks/codex-wake HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
    )
    .unwrap();
    if method == "POST" {
        write!(
            stream,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
        .unwrap();
        if let Some(event) = event {
            write!(stream, "X-GitHub-Event: {event}\r\n").unwrap();
        }
        if let Some(signature) = signature {
            write!(stream, "X-Hub-Signature-256: {signature}\r\n").unwrap();
        }
    }
    stream.write_all(b"\r\n").unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let line = response.split(|b| *b == b'\n').next().unwrap();
    String::from_utf8_lossy(line)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn signed(body: &[u8], secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(body);
    format!(
        "sha256={}",
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn payload(action: &str, sha: &str, status: &str) -> Vec<u8> {
    let conclusion = (status == "completed").then_some("success");
    serde_json::to_vec(&json!({"action":action,"repository":{"full_name":"owner/repo"},
        "workflow_run":{"id":123,"run_attempt":1,"head_sha":sha,"status":status,"conclusion":conclusion}})).unwrap()
}

fn receiver_path() -> Option<PathBuf> {
    env::var_os("CODEX_WAKE_WEBHOOK")
        .map(PathBuf::from)
        .or_else(|| {
            let local = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(".tools/webhook-linux-amd64/webhook");
            local.is_file().then_some(local)
        })
}

fn start_receiver(
    temp: &TempDir,
    db: &Path,
    codex: &Path,
    defer: bool,
) -> (Receiver, std::net::SocketAddr) {
    let webhook = receiver_path().expect(
        "set CODEX_WAKE_WEBHOOK to a verified webhook executable or install the verified local binary",
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let log = temp.path().join("receiver.log");
    let logfile = fs::File::create(&log).unwrap();
    let mut command = Command::new(webhook);
    command
        .args([
            "-ip",
            "127.0.0.1",
            "-port",
            &addr.port().to_string(),
            "-template",
            "-hooks",
            "hooks.json.tmpl",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("CODEX_WAKE_EXECUTABLE", env!("CARGO_BIN_EXE_codex-wake"))
        .env("CODEX_WAKE_DB", db)
        .env("CODEX_WAKE_CODEX", codex)
        .env("CAPTURE", temp.path().join("codex-calls"))
        .env("GITHUB_WEBHOOK_SECRET", SECRET)
        .env("CODEX_WAKE_DEFER", if defer { "1" } else { "0" })
        .env("XDG_STATE_HOME", temp.path())
        .env("CODEX_HOME", temp.path().join("codex-home"))
        .env_remove("CODEX_WAKE_PLUGIN_BASE")
        .env_remove("CODEX_WAKE_PLUGIN_ROOT")
        .stdout(Stdio::from(logfile.try_clone().unwrap()))
        .stderr(Stdio::from(logfile));
    #[cfg(unix)]
    command.process_group(0);
    let child = command.spawn().unwrap();
    let mut receiver = Receiver {
        child,
        log: log.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = receiver.child.try_wait().unwrap() {
            panic!(
                "webhook exited {status}: {}",
                fs::read_to_string(&log).unwrap_or_default()
            );
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "webhook did not become ready: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(40));
    }
    (receiver, addr)
}

#[test]
#[ignore = "requires verified webhook binary; run with CODEX_WAKE_WEBHOOK and --include-ignored"]
fn real_webhook_authenticates_and_dispatches_once() {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let db = temp.path().join("state.sqlite3");
    let codex = temp.path().join("fake-codex");
    let capture = temp.path().join("codex-calls");
    fs::write(&codex, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CAPTURE\"\n").unwrap();
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();
    let registered = cli(
        &db,
        &codex,
        &[
            "register",
            "--repo",
            "owner/repo",
            "--run",
            "123",
            "--attempt",
            "1",
            "--thread",
            THREAD,
            "--sha",
            SHA,
        ],
    );
    assert!(
        registered.status.success(),
        "{}",
        String::from_utf8_lossy(&registered.stderr)
    );

    let (_receiver, addr) = start_receiver(&temp, &db, &codex, false);

    let body = payload("completed", SHA, "completed");
    let signature = signed(&body, SECRET.as_bytes());
    assert_eq!(
        request(addr, "POST", &body, Some("workflow_run"), Some(&signature)),
        200
    );
    assert_eq!(
        request(addr, "POST", &body, Some("workflow_run"), Some(&signature)),
        200
    );
    assert_eq!(
        fs::read_to_string(&capture).unwrap().lines().count(),
        1,
        "duplicate dispatched twice"
    );
    let status = cli(&db, &codex, &["status"]);
    let records: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(records[0]["state"], "queued");

    let bad_sig_body = payload("completed", SHA, "completed");
    assert!(
        request(
            addr,
            "POST",
            &bad_sig_body,
            Some("workflow_run"),
            Some(&signed(&bad_sig_body, b"wrong"))
        ) >= 400
    );
    assert_eq!(
        request(addr, "POST", &body, Some("issues"), Some(&signature)),
        403
    );
    let mismatch = payload("completed", &"b".repeat(40), "completed");
    assert_eq!(
        request(
            addr,
            "POST",
            &mismatch,
            Some("workflow_run"),
            Some(&signed(&mismatch, SECRET.as_bytes()))
        ),
        500
    );
    let incomplete = payload("in_progress", SHA, "in_progress");
    assert_eq!(
        request(
            addr,
            "POST",
            &incomplete,
            Some("workflow_run"),
            Some(&signed(&incomplete, SECRET.as_bytes()))
        ),
        403
    );
    assert!(
        request(addr, "GET", b"", None, None) >= 400,
        "unsigned health-style GET unexpectedly accepted"
    );
    assert_eq!(
        fs::read_to_string(capture).unwrap().lines().count(),
        1,
        "rejected or non-completed delivery dispatched"
    );
}

#[test]
#[ignore = "requires verified webhook binary; run with CODEX_WAKE_WEBHOOK and --include-ignored"]
fn real_webhook_routes_comment_and_custom_events_without_dispatching() {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let db = temp.path().join("state.sqlite3");
    let codex = temp.path().join("fake-codex");
    let capture = temp.path().join("codex-calls");
    fs::write(&codex, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CAPTURE\"\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();

    let rule_file = temp.path().join("rule.json");
    fs::write(
        &rule_file,
        serde_json::to_vec(&json!({
            "repo":"owner/repo", "pr":123, "author":"bot[bot]", "author_type":"Bot",
            "contains":"marker", "match_mode":"all", "prompt":"Review matching comment",
            "target_thread":THREAD
        }))
        .unwrap(),
    )
    .unwrap();
    let configured = cli(
        &db,
        &codex,
        &["configure-rule", "--file", rule_file.to_str().unwrap()],
    );
    assert!(
        configured.status.success(),
        "{}",
        String::from_utf8_lossy(&configured.stderr)
    );
    let subscribed = cli(
        &db,
        &codex,
        &[
            "subscribe",
            "--kind",
            "artifact",
            "--resource",
            "pkg",
            "--event",
            "available",
            "--thread",
            THREAD,
            "--message-template",
            "Artifact {{source.digest}}",
        ],
    );
    assert!(
        subscribed.status.success(),
        "{}",
        String::from_utf8_lossy(&subscribed.stderr)
    );

    let (_receiver, addr) = start_receiver(&temp, &db, &codex, true);
    let comment = serde_json::to_vec(&json!({
        "action":"created", "repository":{"full_name":"owner/repo"},
        "issue":{"number":123,"pull_request":{"url":"https://example.invalid/pull/123"}},
        "comment":{"id":1,"user":{"login":"bot[bot]","type":"Bot"},"body":"marker"}
    }))
    .unwrap();
    let signature = signed(&comment, SECRET.as_bytes());
    assert_eq!(
        request(
            addr,
            "POST",
            &comment,
            Some("issue_comment"),
            Some(&signature)
        ),
        200
    );
    assert_eq!(
        request(
            addr,
            "POST",
            &comment,
            Some("issue_comment"),
            Some(&signature)
        ),
        200
    );

    let custom = serde_json::to_vec(&json!({
        "kind":"artifact", "repo":"", "resource":"pkg", "event":"available",
        "outcome":"available", "digest":"abc"
    }))
    .unwrap();
    let signature = signed(&custom, SECRET.as_bytes());
    assert_eq!(
        request(addr, "POST", &custom, Some("codex_wake"), Some(&signature)),
        200
    );
    assert_eq!(
        request(addr, "POST", &custom, Some("codex_wake"), Some(&signature)),
        200
    );

    let db = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let (rule_count, rule_state): (i64, String) = db
        .query_row(
            "SELECT COUNT(*), MIN(state) FROM rule_deliveries WHERE event_header='issue_comment' AND comment_id='1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((rule_count, rule_state.as_str()), (1_i64, "ready"));
    let (subscription_count, subscription_state, source): (i64, String, String) = db
        .query_row(
            "SELECT COUNT(*), MIN(state), MIN(source_json) FROM subscriptions WHERE kind='artifact' AND repo='' AND resource='pkg' AND event='available'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (subscription_count, subscription_state.as_str()),
        (1_i64, "ready")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&source).unwrap()["digest"],
        "abc"
    );
    assert!(
        !capture.exists(),
        "deferred delivery invoked the Codex executable"
    );
}
