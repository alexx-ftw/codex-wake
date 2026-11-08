#![cfg(unix)]

use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixListener,
    path::Path,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tungstenite::Message;

fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn cli(root: &Path, socket: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_codex-wake"))
        .args(args)
        .env("HOME", root)
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("CODEX_HOME", root.join("codex"))
        .env("CODEX_WAKE_DB", root.join("state.sqlite3"))
        .env("CODEX_WAKE_RPC_SOCKET", socket)
        .env("CODEX_WAKE_CODEX", "/bin/true")
        .env("CODEX_WAKE_GH", "/bin/true")
        .env_remove("CODEX_WAKE_DEFER")
        .env_remove("CODEX_WAKE_PLUGIN_ROOT")
        .env_remove("CODEX_WAKE_PLUGIN_BASE")
        .output()
        .unwrap()
}

fn exercise(
    fail_set: bool,
    initial_active: bool,
    missing_goal: bool,
    fail_queue: bool,
    pause_after_queue: bool,
    omit_timestamp: bool,
) {
    let temp = private_tempdir();
    let socket = temp.path().join("app.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let methods = Arc::new(Mutex::new(Vec::<String>::new()));
    let server_done = done.clone();
    let server_methods = methods.clone();
    let db_path = temp.path().join("state.sqlite3");
    let server = thread::spawn(move || {
        let mut active = initial_active;
        let mut updated = 100;
        while !server_done.load(Ordering::SeqCst) {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            let initialize: Value =
                serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
            ws.send(Message::Text(
                json!({"id":initialize["id"],"result":{}})
                    .to_string()
                    .into(),
            ))
            .unwrap();
            let _ = ws.read().unwrap();
            let request: Value =
                serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
            let method = request["method"].as_str().unwrap();
            assert_eq!(
                request["params"]["threadId"],
                "11111111-1111-4111-8111-111111111111"
            );
            if method == "thread/queue/add" {
                assert_eq!(
                    request["params"]["input"][0]["text"],
                    "Artifact build is ready"
                );
            }
            if method == "thread/goal/set" {
                assert_eq!(request["params"]["status"], "active");
                let db = rusqlite::Connection::open(&db_path).unwrap();
                let stage: String = db
                    .query_row("SELECT goal_stage FROM subscriptions", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(stage, "activating");
            }
            server_methods.lock().unwrap().push(method.to_string());
            let result = match method {
                "thread/goal/get" if missing_goal => json!({"goal":null}),
                "thread/goal/get" => {
                    json!({"goal":{"status":if active {"active"} else {"paused"},"updatedAt":if omit_timestamp {None} else {Some(updated)}}})
                }
                "thread/queue/add" if !fail_queue => {
                    if pause_after_queue {
                        active = false;
                        updated += 1;
                    }
                    json!({"queuedSubmission":{"id":"queued-1"}})
                }
                "thread/queue/add" => {
                    drop(ws);
                    continue;
                }
                "thread/goal/set" if !fail_set => {
                    active = true;
                    json!({})
                }
                "thread/goal/set" => {
                    ws.send(Message::Text(json!({"id":request["id"],"error":{"code":-32000,"message":"fixture failure"}}).to_string().into())).unwrap();
                    continue;
                }
                _ => panic!("unexpected method {method}"),
            };
            ws.send(Message::Text(
                json!({"id":request["id"],"result":result})
                    .to_string()
                    .into(),
            ))
            .unwrap();
        }
    });
    let target = "11111111-1111-4111-8111-111111111111";
    let registered = cli(
        temp.path(),
        &socket,
        &[
            "subscribe",
            "--kind",
            "artifact",
            "--repo",
            "ci",
            "--resource",
            "build",
            "--event",
            "available",
            "--thread",
            target,
            "--resume-goal",
            "true",
            "--message-template",
            "Artifact {{event.resource}} is ready",
        ],
    );
    assert!(
        registered.status.success(),
        "{}",
        String::from_utf8_lossy(&registered.stderr)
    );
    let publish = || {
        cli(
            temp.path(),
            &socket,
            &[
                "publish",
                "--kind",
                "artifact",
                "--repo",
                "ci",
                "--resource",
                "build",
                "--outcome",
                "available",
            ],
        )
    };
    assert!(publish().status.success());
    assert!(publish().status.success());
    done.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let calls = methods.lock().unwrap();
    let expected = if missing_goal {
        vec!["thread/goal/get"]
    } else if fail_queue {
        vec!["thread/goal/get", "thread/queue/add"]
    } else if initial_active || pause_after_queue || omit_timestamp {
        vec!["thread/goal/get", "thread/queue/add", "thread/goal/get"]
    } else if fail_set {
        vec![
            "thread/goal/get",
            "thread/queue/add",
            "thread/goal/get",
            "thread/goal/get",
            "thread/goal/set",
        ]
    } else {
        vec![
            "thread/goal/get",
            "thread/queue/add",
            "thread/goal/get",
            "thread/goal/get",
            "thread/goal/set",
            "thread/goal/get",
        ]
    };
    assert_eq!(*calls, expected);
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    let (state, reason, stage): (String, String, String) = db
        .query_row(
            "SELECT state,reason,goal_stage FROM subscriptions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        state,
        if fail_set || missing_goal || fail_queue || pause_after_queue || omit_timestamp {
            "needs_attention"
        } else {
            "queued"
        }
    );
    assert_eq!(
        reason,
        if missing_goal {
            "goal_missing_before_queue"
        } else if fail_queue {
            "native_queue_outcome_unknown"
        } else if pause_after_queue {
            "goal_changed_after_queue_input_queued: native_queue_accepted"
        } else if omit_timestamp {
            "goal_version_unavailable_after_queue_input_queued: native_queue_accepted"
        } else if fail_set {
            "goal_resume_unconfirmed_input_queued: native_queue_accepted"
        } else {
            "goal_active_input_queued: native_queue_accepted"
        }
    );
    assert_eq!(
        stage,
        if missing_goal || fail_queue {
            "preparing"
        } else if pause_after_queue || omit_timestamp {
            "activation_blocked"
        } else if fail_set {
            "activation_unconfirmed"
        } else {
            "active"
        }
    );
}

#[test]
fn event_queues_before_activating_goal_and_never_replays_uncertain_input() {
    exercise(false, false, false, false, false, false);
    exercise(true, false, false, false, false, false);
    exercise(false, true, false, false, false, false);
    exercise(false, false, true, false, false, false);
    exercise(false, false, false, true, false, false);
    exercise(false, true, false, false, true, false);
    exercise(false, false, false, false, true, false);
    exercise(false, false, false, false, false, true);
}

#[test]
fn unavailable_server_before_queue_keeps_event_ready_for_retry() {
    let temp = private_tempdir();
    let socket = temp.path().join("missing.sock");
    let registered = cli(
        temp.path(),
        &socket,
        &[
            "subscribe",
            "--kind",
            "artifact",
            "--repo",
            "ci",
            "--resource",
            "build",
            "--event",
            "available",
            "--thread",
            "11111111-1111-4111-8111-111111111111",
            "--resume-goal",
            "true",
        ],
    );
    assert!(
        registered.status.success(),
        "{}",
        String::from_utf8_lossy(&registered.stderr)
    );
    let published = cli(
        temp.path(),
        &socket,
        &[
            "publish",
            "--kind",
            "artifact",
            "--repo",
            "ci",
            "--resource",
            "build",
            "--outcome",
            "available",
        ],
    );
    assert!(published.status.success());
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    let (state, reason): (String, String) = db
        .query_row("SELECT state,reason FROM subscriptions", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(state, "ready");
    assert_eq!(reason, "target_unavailable_before_send");
    db.execute("UPDATE subscriptions SET updated='1970-01-01 00:00:00'", [])
        .unwrap();
    drop(db);
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let expected = [
            "thread/goal/get",
            "thread/queue/add",
            "thread/goal/get",
            "thread/goal/get",
            "thread/goal/set",
            "thread/goal/get",
        ];
        let deadline = Instant::now() + Duration::from_secs(10);
        for (index, method) in expected.into_iter().enumerate() {
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing RPC {method}");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            let init: Value = serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
            ws.send(Message::Text(
                json!({"id":init["id"],"result":{}}).to_string().into(),
            ))
            .unwrap();
            let _ = ws.read().unwrap();
            let request: Value =
                serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(request["method"], method);
            let result = match method {
                "thread/goal/get" => {
                    json!({"goal":{"status":if index == 5 {"active"} else {"paused"},"updatedAt":100}})
                }
                "thread/queue/add" => json!({"queuedSubmission":{"id":"queued-1"}}),
                _ => json!({}),
            };
            ws.send(Message::Text(
                json!({"id":request["id"],"result":result})
                    .to_string()
                    .into(),
            ))
            .unwrap();
        }
    });
    let recovered = cli(temp.path(), &socket, &["recover"]);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    server.join().unwrap();
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    let (state, stage): (String, String) = db
        .query_row("SELECT state,goal_stage FROM subscriptions", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!((state.as_str(), stage.as_str()), ("queued", "active"));
}

fn exercise_recover_accepted_input(changed: bool) {
    let temp = private_tempdir();
    let socket = temp.path().join("app.sock");
    let registered = cli(
        temp.path(),
        &socket,
        &[
            "subscribe",
            "--kind",
            "artifact",
            "--repo",
            "ci",
            "--resource",
            "build",
            "--event",
            "available",
            "--thread",
            "11111111-1111-4111-8111-111111111111",
            "--resume-goal",
            "true",
        ],
    );
    assert!(
        registered.status.success(),
        "{}",
        String::from_utf8_lossy(&registered.stderr)
    );
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute("UPDATE subscriptions SET state='sending',goal_stage='input_queued',reason='native_queue_accepted',goal_before_status='paused',goal_before_updated=100", []).unwrap();
    drop(db);
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "missing goal RPC");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut ws = tungstenite::accept(stream).unwrap();
        let init: Value = serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
        ws.send(Message::Text(
            json!({"id":init["id"],"result":{}}).to_string().into(),
        ))
        .unwrap();
        let _ = ws.read().unwrap();
        let request: Value = serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(request["method"], "thread/goal/get");
        ws.send(Message::Text(
            json!({"id":request["id"],"result":{"goal":{"status":if changed {"paused"} else {"active"},"updatedAt":101}}})
                .to_string()
                .into(),
        ))
        .unwrap();
    });
    let recovered = cli(temp.path(), &socket, &["recover"]);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    server.join().unwrap();
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    let (state, stage): (String, String) = db
        .query_row("SELECT state,goal_stage FROM subscriptions", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(
        (state.as_str(), stage.as_str()),
        if changed {
            ("needs_attention", "activation_blocked")
        } else {
            ("queued", "active")
        }
    );
    drop(db);
    let again = cli(temp.path(), &socket, &["recover"]);
    assert!(again.status.success());
    let result: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(result["attempted"], 0);
}

#[test]
fn recover_accepted_input_without_queuing_it_again() {
    exercise_recover_accepted_input(false);
    exercise_recover_accepted_input(true);
}

#[test]
fn condition_group_publishes_once_after_both_events() {
    let temp = private_tempdir();
    let socket = temp.path().join("app.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let initialized = cli(temp.path(), &socket, &["poll"]);
    assert!(initialized.status.success());
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    let group = "11111111-1111-4111-8111-111111111111";
    let target = "22222222-2222-4222-8222-222222222222";
    db.execute("INSERT INTO condition_groups(id,mode,target_thread,message_template) VALUES(?1,'and',?2,'Both artifacts are ready')", [group, target]).unwrap();
    for resource in ["first", "second"] {
        db.execute("INSERT INTO condition_members(group_id,kind,repo,resource,event) VALUES(?1,'artifact','ci',?2,'available')", [group, resource]).unwrap();
    }
    let server = thread::spawn(move || {
        for expected in ["thread/queue/add", "thread/read"] {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            let init: Value = serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
            ws.send(Message::Text(
                json!({"id":init["id"],"result":{}}).to_string().into(),
            ))
            .unwrap();
            let _ = ws.read().unwrap();
            let request: Value =
                serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(request["method"], expected);
            assert_eq!(request["params"]["threadId"], target);
            let result = if expected == "thread/queue/add" {
                assert_eq!(request["params"]["clientUserMessageId"], group);
                assert_eq!(
                    request["params"]["input"][0]["text"],
                    "Both artifacts are ready"
                );
                json!({"queuedSubmission":{"id":"queued-1"}})
            } else {
                json!({"thread":{"status":{"type":"idle"}}})
            };
            ws.send(Message::Text(
                json!({"id":request["id"],"result":result})
                    .to_string()
                    .into(),
            ))
            .unwrap();
        }
    });
    for (resource, expected) in [("first", 0), ("second", 1)] {
        let output = cli(
            temp.path(),
            &socket,
            &[
                "publish",
                "--kind",
                "artifact",
                "--repo",
                "ci",
                "--resource",
                resource,
                "--outcome",
                "available",
                "--event-id",
                resource,
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["attempted"], expected);
    }
    server.join().unwrap();
    let state: String = db
        .query_row(
            "SELECT state FROM condition_groups WHERE id=?1",
            [group],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "accepted");
    let output = cli(temp.path(), &socket, &["recover"]);
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["attempted"], 0);
}
