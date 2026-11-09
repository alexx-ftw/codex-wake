//! Actual isolated CLI/MCP entry points; no user service or Codex process.
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};
use wait_timeout::ChildExt;

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

const OWNER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const THREAD: &str = "11111111-1111-4111-8111-111111111111";
const FIRST: &str = "22222222-2222-4222-8222-222222222222";
const SECOND: &str = "33333333-3333-4333-8333-333333333333";

fn command(root: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_codex-wake"));
    cmd.args(args)
        .env_clear()
        .env("PATH", root.join("bin"))
        .env("HOME", root)
        .env("CODEX_HOME", root.join("codex"))
        .env("XDG_STATE_HOME", root.join("state-root"))
        .env("CODEX_WAKE_DB", root.join("state/state.sqlite3"))
        .env("CODEX_WAKE_CODEX", "/bin/false")
        .env("CODEX_WAKE_GH", "/bin/false")
        .env("CODEX_WAKE_GATE_OWNER", OWNER)
        .env("CODEX_WAKE_GATE_GENERATION", "1")
        .env("FAKE_SYSTEMCTL_MARKER", root.join("service-touched"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    cmd
}

fn gate(root: &Path, action: &str, generation: bool) {
    let mut args = vec!["cooperative-gate", action, "--owner", OWNER];
    if generation {
        args.extend(["--generation", "1"]);
    }
    assert!(command(root, &args).status().unwrap().success());
}

fn direct(root: &Path, payload: &Value, generation: &str) -> (bool, Option<Value>) {
    let mut child = command(root, &["queue-direct"])
        .env("CODEX_WAKE_GATE_GENERATION", generation)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    write!(child.stdin.take().unwrap(), "{payload}").unwrap();
    if child
        .wait_timeout(Duration::from_secs(15))
        .unwrap()
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("direct CLI timed out");
    }
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).ok(),
    )
}

#[test]
fn cli_and_mcp_share_durable_ids_without_starting_service() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("bin")).unwrap();
    let fake = root.join("bin/systemctl");
    fs::write(
        &fake,
        "#!/bin/sh\nprintf touched > \"$FAKE_SYSTEMCTL_MARKER\"\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    gate(root, "init", false);
    let mut premature = KillOnDrop(command(root, &["mcp"]).spawn().unwrap());
    assert!(
        !premature
            .0
            .wait_timeout(Duration::from_secs(15))
            .unwrap()
            .expect("premature MCP timed out")
            .success()
    );
    assert!(!root.join("service-touched").exists());
    gate(root, "arm", true);
    let mut stale_mcp = KillOnDrop(
        command(root, &["mcp"])
            .env("CODEX_WAKE_GATE_GENERATION", "2")
            .spawn()
            .unwrap(),
    );
    assert!(
        !stale_mcp
            .0
            .wait_timeout(Duration::from_secs(15))
            .unwrap()
            .expect("stale MCP timed out")
            .success()
    );
    assert!(!root.join("service-touched").exists());
    let payload = json!({"thread":THREAD,"message_template":"fixture","request_id":FIRST});
    let (ok, first) = direct(root, &payload, "1");
    assert!(ok);
    assert_eq!(first.unwrap()["state"], "pending");
    let (ok, again) = direct(root, &payload, "1");
    assert!(ok);
    assert_eq!(again.unwrap()["replayed"], true);
    let changed = json!({"thread":THREAD,"message_template":"different","request_id":FIRST});
    assert!(!direct(root, &changed, "1").0);
    let no_key = json!({"thread":THREAD,"message_template":"no-key"});
    let (ok, generated_cli) = direct(root, &no_key, "1");
    assert!(ok);
    let generated_cli = generated_cli.unwrap();
    assert_eq!(generated_cli["state"], "pending");
    assert_eq!(generated_cli["request_id_generated"], true);
    assert_eq!(generated_cli["retry_safe_if_response_lost"], false);
    let stale = json!({"thread":THREAD,"message_template":"stale","request_id":SECOND});
    assert!(!direct(root, &stale, "2").0);

    let mut mcp = KillOnDrop(
        command(root, &["mcp"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = mcp.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                break;
            };
            if tx.send(value).is_err() {
                break;
            }
        }
    });
    let mut input = mcp.0.stdin.take().unwrap();
    let mut send = |value: Value| {
        writeln!(input, "{value}").unwrap();
    };
    let receive = |id: i64| -> Value {
        loop {
            let response = rx
                .recv_timeout(Duration::from_secs(15))
                .expect("MCP response timeout");
            if response["id"] == id {
                return response;
            }
        }
    };
    send(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"isolated-test","version":"1"}}}),
    );
    assert!(receive(1).get("error").is_none());
    send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    send(
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"queue_thread","arguments":payload}}),
    );
    let replay = receive(2);
    assert_eq!(replay["result"]["structuredContent"]["state"], "pending");
    assert_eq!(replay["result"]["structuredContent"]["replayed"], true);
    send(
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"queue_thread","arguments":{"thread":THREAD,"message_template":"no-key"}}}),
    );
    let no_key = receive(3);
    assert_eq!(no_key["result"]["structuredContent"]["state"], "pending");
    assert_eq!(
        no_key["result"]["structuredContent"]["request_id_generated"],
        true
    );
    assert_eq!(
        no_key["result"]["structuredContent"]["retry_safe_if_response_lost"],
        false
    );
    send(
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"queue_thread","arguments":{"thread":THREAD,"message_template":"second","request_id":SECOND}}}),
    );
    assert_eq!(
        receive(4)["result"]["structuredContent"]["state"],
        "pending"
    );
    let steer_id = "44444444-4444-4444-8444-444444444444";
    for id in [5, 6] {
        send(
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"queue_thread","arguments":{"thread":THREAD,"message_template":"steer-fixture","steer":true,"request_id":steer_id}}}),
        );
        let response = receive(id);
        let result = &response["result"]["structuredContent"];
        assert_eq!(result["state"], "pending");
        assert_eq!(result["steer_id"], steer_id);
        assert_eq!(result["replayed"], id == 6);
    }
    send(
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"queue_thread","arguments":{"thread":THREAD,"message_template":"steer-fixture","steer":true}}}),
    );
    let generated = receive(7);
    assert_eq!(generated["result"]["structuredContent"]["state"], "pending");
    assert_eq!(
        generated["result"]["structuredContent"]["request_id_generated"],
        true
    );
    assert_eq!(
        generated["result"]["structuredContent"]["retry_safe_if_response_lost"],
        false
    );
    let cases = [
        (
            "create_goal",
            json!({"thread": THREAD, "objective":"first", "message_template":"input", "request_id":"55555555-5555-4555-8555-555555555555"}),
        ),
        (
            "edit_goal",
            json!({"thread": THREAD, "objective":"second", "message_template":"input", "request_id":"66666666-6666-4666-8666-666666666666"}),
        ),
        (
            "resume_goal",
            json!({"thread": THREAD, "message_template":"input", "request_id":"77777777-7777-4777-8777-777777777777"}),
        ),
    ];
    for (n, (name, arguments)) in cases.iter().enumerate() {
        for repeat in 0..2 {
            let id = 10 + n as i64 * 2 + repeat;
            send(
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}}),
            );
            let response = receive(id);
            let result = &response["result"]["structuredContent"];
            assert_eq!(result["state"], "pending", "{name}: {response}");
            assert_eq!(result["replayed"], repeat == 1);
            assert_eq!(result["retry_safe_if_response_lost"], true);
        }
    }
    send(
        json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"create_goal","arguments":{"thread":THREAD,"objective":"different","message_template":"input","request_id":"55555555-5555-4555-8555-555555555555"}}}),
    );
    assert_eq!(receive(19)["result"]["isError"], true);
    let mut generated_ids = Vec::new();
    for id in [20, 21] {
        send(
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"resume_goal","arguments":{"thread":THREAD,"message_template":"same"}}}),
        );
        let response = receive(id);
        let result = &response["result"]["structuredContent"];
        assert_eq!(result["state"], "pending");
        assert_eq!(result["retry_safe_if_response_lost"], false);
        generated_ids.push(result["request_id"].clone());
    }
    assert_ne!(generated_ids[0], generated_ids[1]);
    // Keep this MCP process on generation 1 across the actual transfer.
    assert!(
        command(
            root,
            &[
                "cooperative-gate",
                "transfer",
                "--owner",
                OWNER,
                "--generation",
                "1",
                "--next-owner",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            ]
        )
        .status()
        .unwrap()
        .success()
    );
    for (n, (name, arguments)) in cases.iter().enumerate() {
        let id = 30 + n as i64;
        send(
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}}),
        );
        let response = receive(id);
        assert_eq!(
            response["result"]["structuredContent"]["state"], "pending",
            "{name}: {response}"
        );
        assert_eq!(response["result"]["structuredContent"]["replayed"], true);
    }
    send(
        json!({"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"queue_thread","arguments":{"thread":THREAD,"message_template":"steer-fixture","steer":true,"request_id":steer_id}}}),
    );
    let replay = receive(34);
    assert_eq!(replay["result"]["structuredContent"]["state"], "pending");
    assert_eq!(replay["result"]["structuredContent"]["replayed"], true);
    send(
        json!({"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":"resume_goal","arguments":{"thread":THREAD,"message_template":"new","request_id":"88888888-8888-4888-8888-888888888888"}}}),
    );
    assert_eq!(receive(35)["result"]["isError"], true);
    send(
        json!({"jsonrpc":"2.0","id":36,"method":"tools/call","params":{"name":"queue_thread","arguments":{"thread":THREAD,"message_template":"new","steer":true,"request_id":"99999999-9999-4999-8999-999999999999"}}}),
    );
    assert_eq!(receive(36)["result"]["isError"], true);
    send(
        json!({"jsonrpc":"2.0","id":37,"method":"tools/call","params":{"name":"resume_goal","arguments":{"thread":THREAD,"message_template":"different","request_id":"77777777-7777-4777-8777-777777777777"}}}),
    );
    assert_eq!(receive(37)["result"]["isError"], true);
    drop(input);
    assert!(
        mcp.0
            .wait_timeout(Duration::from_secs(15))
            .unwrap()
            .expect("MCP did not exit")
            .success()
    );
    assert!(!root.join("service-touched").exists());
    let db_path = root.join("state/state.sqlite3");
    assert_eq!(
        fs::metadata(&db_path).unwrap().permissions().mode() & 0o077,
        0
    );
    let db = rusqlite::Connection::open(db_path).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM cooperative_direct_pending",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 11);
    let steers: i64 = db
        .query_row("SELECT count(*) FROM steers", [], |row| row.get(0))
        .unwrap();
    assert_eq!(steers, 0);
}

#[test]
fn deferred_webhook_handler_retains_events_after_owner_transfer() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("bin")).unwrap();
    let codex = root.join("bin/codex");
    fs::write(
        &codex,
        "#!/bin/sh\nprintf touched > \"$FAKE_CONTROLLER_MARKER\"\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();
    gate(root, "init", false);
    let db_path = root.join("state/state.sqlite3");
    let db = rusqlite::Connection::open(&db_path).unwrap();
    let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for id in [122, 123, 124] {
        db.execute("INSERT INTO waits(repo,run_id,attempt,thread,sha,state) VALUES('owner/repo',?1,1,?2,?3,'waiting')", rusqlite::params![id,THREAD,sha]).unwrap();
    }
    drop(db);
    let handle = |id: i64, conclusion: &str, defer: bool| {
        let payload = json!({"action":"completed","repository":{"full_name":"owner/repo"},"workflow_run":{"id":id,"run_attempt":1,"head_sha":sha,"status":"completed","conclusion":conclusion}});
        let mut child = command(root, &["handle"])
            .env("CODEX_WAKE_DEFER", if defer { "1" } else { "0" })
            .env("CODEX_WAKE_CODEX", &codex)
            .env("FAKE_CONTROLLER_MARKER", root.join("controller-touched"))
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        write!(child.stdin.take().unwrap(), "{payload}").unwrap();
        if child
            .wait_timeout(Duration::from_secs(15))
            .unwrap()
            .is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
            panic!("handler timed out");
        }
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "handler failed");
        serde_json::from_slice::<Value>(&result.stdout).unwrap()
    };
    // Keep claims possible here: a closed or process-bound gate would mask a
    // handler that incorrectly calls recover despite DEFER.
    gate(root, "open", true);
    assert_eq!(handle(122, "success", true)["result"], "recorded");
    let db = rusqlite::Connection::open(&db_path).unwrap();
    let deferred: String = db
        .query_row("SELECT state FROM waits WHERE run_id=122", [], |r| r.get(0))
        .unwrap();
    assert_eq!(deferred, "ready");
    assert!(!root.join("controller-touched").exists());
    drop(db);

    // Positive control: the same ready work and open gate must reach the fake
    // controller when DEFER is disabled. No real controller or service is used.
    assert_eq!(handle(122, "success", false)["result"], "recorded");
    assert_eq!(
        fs::read_to_string(root.join("controller-touched")).unwrap(),
        "touched"
    );
    fs::remove_file(root.join("controller-touched")).unwrap();
    gate(root, "close", true);
    gate(root, "arm", true);

    assert_eq!(handle(123, "success", true)["result"], "recorded");
    assert!(
        command(
            root,
            &[
                "cooperative-gate",
                "transfer",
                "--owner",
                OWNER,
                "--generation",
                "1",
                "--next-owner",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            ]
        )
        .status()
        .unwrap()
        .success()
    );
    // The persistent webhook still launches the old owner/generation environment.
    assert_eq!(handle(124, "failure", true)["result"], "recorded");
    assert_eq!(handle(124, "success", true)["result"], "recorded");
    let db = rusqlite::Connection::open(db_path).unwrap();
    let first: (String, String) = db
        .query_row(
            "SELECT state,conclusion FROM waits WHERE run_id=123",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let second: (String, String) = db
        .query_row(
            "SELECT state,conclusion FROM waits WHERE run_id=124",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(first, ("ready".into(), "success".into()));
    assert_eq!(second, ("ready".into(), "failure".into()));
    assert!(!root.join("controller-touched").exists());
    assert!(!root.join("service-touched").exists());
}

#[test]
fn stable_producer_retains_inputs_across_transfer_without_claim_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("bin")).unwrap();
    gate(root, "init", false);
    let producer = "44444444-4444-4444-8444-444444444444";
    let setup = || {
        command(
            root,
            &[
                "cooperative-gate",
                "producer",
                "--owner",
                OWNER,
                "--generation",
                "1",
                "--producer-id",
                producer,
            ],
        )
        .output()
        .unwrap()
    };
    // An owned but unarmed gate is rejected without adding the producer column.
    assert!(!setup().status.success());
    let path = root.join("state/state.sqlite3");
    let db = rusqlite::Connection::open(&path).unwrap();
    let count: i64 = db.query_row("SELECT count(*) FROM pragma_table_info('wake_delivery_claim_gate') WHERE name='producer_id'", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 0);
    drop(db);
    gate(root, "arm", true);
    assert!(setup().status.success());
    let repeated = setup();
    assert!(repeated.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&repeated.stdout).unwrap()["replayed"],
        true
    );
    let submit = |id: &str, message: &str, identity: &str| {
        let mut child = command(root, &["queue-direct"])
            .env_remove("CODEX_WAKE_GATE_OWNER")
            .env_remove("CODEX_WAKE_GATE_GENERATION")
            .env("CODEX_WAKE_PRODUCER_ID", identity)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        write!(
            child.stdin.take().unwrap(),
            "{}",
            json!({"thread":THREAD,"message_template":message,"request_id":id})
        )
        .unwrap();
        if child
            .wait_timeout(Duration::from_secs(15))
            .unwrap()
            .is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
            panic!("producer CLI timed out");
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.success(),
            serde_json::from_slice::<Value>(&output.stdout).ok(),
        )
    };
    let mut mcp = KillOnDrop(
        command(root, &["mcp"])
            .env_remove("CODEX_WAKE_GATE_OWNER")
            .env_remove("CODEX_WAKE_GATE_GENERATION")
            .env("CODEX_WAKE_PRODUCER_ID", producer)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = mcp.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                break;
            };
            if tx.send(value).is_err() {
                break;
            }
        }
    });
    let mut mcp_input = mcp.0.stdin.take().unwrap();
    writeln!(mcp_input, "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"isolated-producer-test","version":"1"}}})).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(15)).unwrap()["id"], 1);
    writeln!(
        mcp_input,
        "{}",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    {
        let mut mcp_call = |id: i64, name: &str, arguments: Value| -> Value {
            writeln!(mcp_input, "{}", json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})).unwrap();
            loop {
                let value = rx
                    .recv_timeout(Duration::from_secs(15))
                    .expect("producer MCP timeout");
                if value["id"] == id {
                    return value;
                }
            }
        };
        let created = mcp_call(
            2,
            "create_goal",
            json!({"thread":THREAD,"objective":"fixture","request_id":"77777777-7777-4777-8777-777777777777"}),
        );
        assert_eq!(created["result"]["structuredContent"]["state"], "pending");
        let first = submit(FIRST, "before-transfer", producer);
        assert!(first.0);
        assert_eq!(first.1.unwrap()["state"], "pending");
        assert!(
            command(
                root,
                &[
                    "cooperative-gate",
                    "transfer",
                    "--owner",
                    OWNER,
                    "--generation",
                    "1",
                    "--next-owner",
                    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                ]
            )
            .status()
            .unwrap()
            .success()
        );
        let resumed = mcp_call(
            3,
            "resume_goal",
            json!({"thread":THREAD,"message_template":"fixture","request_id":"88888888-8888-4888-8888-888888888888"}),
        );
        assert_eq!(resumed["result"]["structuredContent"]["state"], "pending");
        let steer = mcp_call(
            4,
            "queue_thread",
            json!({"thread":THREAD,"message_template":"fixture","steer":true,"request_id":"99999999-9999-4999-8999-999999999999"}),
        );
        assert_eq!(steer["result"]["structuredContent"]["state"], "pending");
    }
    // Interrupt the MCP process after commit, without consuming this reply.
    let interrupted_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    writeln!(mcp_input, "{}", json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"queue_thread","arguments":{"thread":THREAD,"message_template":"interrupted","request_id":interrupted_id}}})).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let db = rusqlite::Connection::open(&path).unwrap();
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cooperative_direct_pending WHERE request_id=?1)",
                [interrupted_id],
                |r| r.get(0),
            )
            .unwrap();
        if exists {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "interrupted request was not committed"
        );
        thread::sleep(Duration::from_millis(5));
    }
    mcp.0.kill().unwrap();
    mcp.0.wait().unwrap();
    drop(mcp_input);
    let recovered = submit(interrupted_id, "interrupted", producer);
    assert!(recovered.0);
    assert_eq!(recovered.1.unwrap()["replayed"], true);
    let second = submit(SECOND, "after-transfer", producer);
    assert!(second.0);
    assert_eq!(second.1.unwrap()["state"], "pending");
    let replay = submit(FIRST, "before-transfer", producer);
    assert!(replay.0);
    assert_eq!(replay.1.unwrap()["replayed"], true);
    assert!(!submit(FIRST, "different", producer).0);
    assert!(
        !submit(
            "55555555-5555-4555-8555-555555555555",
            "wrong",
            "66666666-6666-4666-8666-666666666666"
        )
        .0
    );
    let db = rusqlite::Connection::open(path).unwrap();
    let count: i64 = db
        .query_row("SELECT count(*) FROM cooperative_direct_pending", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 6);
    let open: bool = db
        .query_row(
            "SELECT is_open FROM wake_delivery_claim_gate WHERE id=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!open);
    assert!(!root.join("service-touched").exists());
}

#[test]
fn producer_configuration_refuses_legacy_database_without_modification() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("bin")).unwrap();
    fs::create_dir(root.join("state")).unwrap();
    fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("state/state.sqlite3");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "application_id", 0x43574b45)
        .unwrap();
    db.execute_batch("CREATE TABLE waits(repo TEXT)").unwrap();
    drop(db);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(&path).unwrap();
    let output = command(
        root,
        &[
            "cooperative-gate",
            "producer",
            "--owner",
            OWNER,
            "--generation",
            "1",
            "--producer-id",
            FIRST,
        ],
    )
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!root.join("service-touched").exists());
}
