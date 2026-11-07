use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn hook(dir: &std::path::Path, payload: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_codex-wake"))
        .args([
            "--db",
            dir.join("state.sqlite3").to_str().unwrap(),
            "--codex",
            "/nonexistent/codex-wake-test-codex",
            "hook",
        ])
        .env("XDG_STATE_HOME", dir)
        .env_remove("CODEX_WAKE_PLUGIN_BASE")
        .env_remove("CODEX_WAKE_PLUGIN_ROOT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn stop_reminds_only_the_owner_and_does_not_resolve_validation() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = "11111111-1111-4111-8111-111111111111";
    let other = "22222222-2222-4222-8222-222222222222";
    let stop = |thread| json!({"hook_event_name":"Stop", "session_id":thread, "turn_id":"turn1"});
    hook(dir.path(), stop(owner));
    let db = rusqlite::Connection::open(dir.path().join("state.sqlite3")).unwrap();
    db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('one',?1,'validation','','one','','Check migration')", [owner]).unwrap();
    assert!(hook(dir.path(), stop(other)).get("decision").is_none());
    let output = hook(dir.path(), stop(owner));
    assert_eq!(output["decision"], "block");
    assert!(output["reason"].as_str().unwrap().contains("validation"));
    let resolved: i64 = db
        .query_row(
            "SELECT resolved FROM obligations WHERE id='one'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(resolved, 0);
    let active = hook(
        dir.path(),
        json!({"hook_event_name":"Stop", "session_id":owner, "turn_id":"turn1", "stop_hook_active":true}),
    );
    assert!(active.get("decision").is_none());
}
