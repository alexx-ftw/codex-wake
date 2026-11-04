//! Real background service loop with a local source and a fake queue executable.
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Controller {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn controller(listener: UnixListener) -> Controller {
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let worker = thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            let Ok((stream, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let Ok(mut ws) = tungstenite::accept(stream) else {
                continue;
            };
            while let Ok(message) = ws.read() {
                let tungstenite::Message::Text(raw) = message else {
                    break;
                };
                let request: Value = serde_json::from_str(&raw).unwrap();
                let Some(id) = request.get("id") else {
                    continue;
                };
                let result = match request["method"].as_str().unwrap() {
                    "initialize" => json!({"userAgent":"fixture"}),
                    "thread/loaded/list" => json!({"data":[]}),
                    other => panic!("unexpected controller method: {other}"),
                };
                ws.send(tungstenite::Message::Text(
                    json!({"id":id,"result":result}).to_string().into(),
                ))
                .unwrap();
            }
        }
    });
    Controller {
        stop,
        worker: Some(worker),
    }
}

#[test]
fn background_file_observation_queues_once_without_http_receiver_or_model() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("owner.sock");
    let _owner = controller(UnixListener::bind(&socket).unwrap());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let queue = temp.path().join("queue");
    let codex = temp.path().join("codex");
    fs::write(&codex, format!("#!/bin/sh\n[ \"$1\" = queue ] || exit 9\nprintf '%s\\n' \"$@\" >> '{}'\nprintf '%s\\n' 'Queued message 22222222-2222-4222-8222-222222222222 for thread 11111111-1111-4111-8111-111111111111.'\n", queue.display())).unwrap();
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();
    let db = temp.path().join("state.sqlite3");
    let artifact = temp.path().join("package.tar");
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_codex-wake"));
        command
            .args([
                "--db",
                db.to_str().unwrap(),
                "--codex",
                codex.to_str().unwrap(),
            ])
            .env("HOME", temp.path())
            .env("XDG_STATE_HOME", temp.path())
            .env("XDG_CONFIG_HOME", temp.path())
            .env("XDG_DATA_HOME", temp.path())
            .env("XDG_CACHE_HOME", temp.path())
            .env("CODEX_HOME", temp.path().join("codex-home"))
            .env("CODEX_WAKE_RPC_SOCKET", &socket)
            .env("CODEX_WAKE_ENABLE_WEBHOOKS", "0")
            .env("CODEX_WAKE_WEBHOOK", "/nonexistent/webhook")
            .env_remove("CODEX_WAKE_PLUGIN_BASE")
            .env_remove("CODEX_WAKE_PLUGIN_ROOT");
        command
    };
    let output = command()
        .args([
            "subscribe",
            "--kind",
            "artifact",
            "--repo",
            "build",
            "--resource",
            "package",
            "--event",
            "available",
            "--thread",
            "11111111-1111-4111-8111-111111111111",
            "--observe",
            &json!({"type":"file","path":artifact}).to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = result["subscription_id"].as_str().unwrap();
    fs::write(&artifact, b"published atomically for this test").unwrap();
    let mut service = Service(
        command()
            .arg("receiver")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            service.0.try_wait().unwrap().is_none(),
            "service exited before delivery"
        );
        let reader = rusqlite::Connection::open(&db).unwrap();
        reader.busy_timeout(Duration::from_secs(2)).unwrap();
        let state: String = reader
            .query_row("SELECT state FROM subscriptions WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .unwrap();
        if state == "queued" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "delivery was not queued: {state}"
        );
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_secs(2));
    let args = fs::read_to_string(&queue).unwrap();
    assert_eq!(args.lines().filter(|line| *line == "queue").count(), 1);
    assert!(!temp.path().join("codex-wake/runtime/webhook").exists());
}

#[test]
#[ignore = "reads GitHub through the current gh login; no workflow or model is started"]
fn real_github_completion_requires_the_registered_attempt_and_sha() {
    let output = Command::new("gh")
        .args([
            "api",
            "repos/alexx-ftw/codex-wake/actions/runs?status=completed&per_page=1",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let runs: Value = serde_json::from_slice(&output.stdout).unwrap();
    let run = &runs["workflow_runs"][0];
    assert_eq!(run["status"], "completed");
    let run_id = run["id"].as_u64().unwrap().to_string();
    let current_attempt = run["run_attempt"].as_u64().unwrap();
    for (attempt, matches_sha) in [
        (current_attempt, true),
        (current_attempt, false),
        (current_attempt + 1, true),
    ] {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let db = temp.path().join("state.sqlite3");
        let command = || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_codex-wake"));
            command
                .args(["--db", db.to_str().unwrap()])
                .env("XDG_STATE_HOME", temp.path())
                .env_remove("CODEX_WAKE_PLUGIN_BASE")
                .env_remove("CODEX_WAKE_PLUGIN_ROOT");
            command
        };
        let sha = if matches_sha {
            run["head_sha"].as_str().unwrap().to_owned()
        } else {
            "b".repeat(40)
        };
        let attempt = attempt.to_string();
        let expected = if attempt == current_attempt.to_string() && matches_sha {
            "ready"
        } else {
            "waiting"
        };
        let output = command()
            .args([
                "register",
                "--repo",
                "alexx-ftw/codex-wake",
                "--run",
                &run_id,
                "--attempt",
                &attempt,
                "--sha",
                &sha,
                "--thread",
                "11111111-1111-4111-8111-111111111111",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = command().arg("poll").output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let read = || {
            rusqlite::Connection::open(&db)
                .unwrap()
                .query_row("SELECT state FROM waits", [], |row| row.get::<_, String>(0))
                .unwrap()
        };
        assert_eq!(read(), expected);
        let output = command().arg("poll").output().unwrap();
        assert!(output.status.success());
        assert_eq!(read(), expected);
    }
}
