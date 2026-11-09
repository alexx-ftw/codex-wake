//! CLI wiring only; ownership, stale claims and partial schemas are covered by unit tests.
use serde_json::{Value, json};
use std::{
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

#[test]
fn cooperative_gate_cli_routes_actions_and_rejects_bad_arguments() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("db/state.sqlite3");
    let a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let run = |args: &[&str]| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_codex-wake"))
            .arg("--db")
            .arg(&path)
            .arg("cooperative-gate")
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", root.path())
            .env("CODEX_HOME", root.path().join("codex"))
            .env("XDG_STATE_HOME", root.path().join("state"))
            .env("XDG_CONFIG_HOME", root.path().join("config"))
            .env("XDG_DATA_HOME", root.path().join("data"))
            .env("CODEX_WAKE_CODEX", "/bin/false")
            .env("CODEX_WAKE_GH", "/bin/false")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let timed_out = child
            .wait_timeout(Duration::from_secs(15))
            .unwrap()
            .is_none();
        if timed_out {
            let _ = child.kill();
        }
        let output = child.wait_with_output().unwrap();
        assert!(!timed_out, "cooperative-gate timed out: {args:?}");
        output
    };
    let success = |args: &[&str]| -> Value {
        let output = run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };
    assert_eq!(
        success(&["init", "--owner", a]),
        json!({"owner":a,"generation":1,"open":false})
    );
    assert_eq!(
        success(&["open", "--owner", a, "--generation", "1"]),
        json!({"owner":a,"generation":1,"open":true})
    );
    assert_eq!(
        success(&["close", "--owner", a, "--generation", "1"]),
        json!({"owner":a,"generation":1,"open":false})
    );
    assert_eq!(
        success(&[
            "transfer",
            "--owner",
            a,
            "--generation",
            "1",
            "--next-owner",
            b
        ]),
        json!({"owner":b,"generation":2,"open":false})
    );
    assert_eq!(
        success(&["open", "--owner", b, "--generation", "2"]),
        json!({"owner":b,"generation":2,"open":true})
    );

    let snapshot = || {
        rusqlite::Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT owner,generation,is_open FROM wake_delivery_claim_gate WHERE id=1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .unwrap()
    };
    let before = snapshot();
    let invalid: &[&[&str]] = &[
        &[],
        &["open"],
        &["open", "--owner", b, "--generation", "not-a-number"],
        &["open", "--owner", b, "--generation", "2", "--unexpected"],
        &["unknown", "--owner", b, "--generation", "2"],
    ];
    for args in invalid {
        let output = run(args);
        assert!(
            !output.status.success(),
            "invalid arguments accepted: {args:?}"
        );
        assert_eq!(
            snapshot(),
            before,
            "invalid arguments changed the gate: {args:?}"
        );
    }
}
