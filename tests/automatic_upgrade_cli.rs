//! Real CLI, private environment and a manager fixture that rejects every mutation.
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
fn command(root: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_codex-wake"));
    cmd.env_clear()
        .env("HOME", root)
        .env("PATH", root.join("bin"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("CODEX_HOME", root.join("codex"))
        .env("CODEX_WAKE_CODEX", "/bin/false")
        .env("CODEX_WAKE_GH", "/bin/false")
        .env("CODEX_WAKE_RPC_SOCKET", root.join("external.sock"))
        .env("CODEX_WAKE_COOPERATIVE_RECEIVER", "1")
        .env("MANAGER_MARKER", root.join("mutated"));
    cmd
}
fn setup() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("bin")).unwrap();
    let script = temp.path().join("bin/systemctl");
    fs::write(&script,"#!/bin/sh\nif [ \"$2\" = show ]; then printf 'LoadState=loaded\\nActiveState=active\\nMainPID=123\\n'; else printf touched > \"$MANAGER_MARKER\"; exit 1; fi\n").unwrap();
    fs::set_permissions(script, fs::Permissions::from_mode(0o700)).unwrap();
    temp
}
#[test]
fn legacy_installation_is_rejected_before_database_or_unit_changes() {
    let temp = setup();
    let root = temp.path();
    fs::create_dir_all(root.join("state/codex-wake")).unwrap();
    let db = root.join("state/codex-wake/state.sqlite3");
    fs::write(&db, b"legacy fixture bytes").unwrap();
    let output = command(root).arg("ensure").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("alpha.2"));
    assert_eq!(fs::read(db).unwrap(), b"legacy fixture bytes");
    assert!(!root.join("mutated").exists());
    assert!(!root.join("data/codex-wake/runtime").exists());
    assert!(
        !root
            .join("state/codex-wake/cooperative-upgrade.json")
            .exists()
    );
}
#[test]
fn interrupted_outcome_is_closed_without_resuming_or_replaying() {
    let temp = setup();
    let root = temp.path();
    let owner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    assert!(
        command(root)
            .args(["cooperative-gate", "init", "--owner", owner])
            .output()
            .unwrap()
            .status
            .success()
    );
    let db = rusqlite::Connection::open(root.join("state/codex-wake/state.sqlite3")).unwrap();
    db.execute_batch("UPDATE wake_delivery_claim_gate SET is_open=1; INSERT INTO waits(repo,run_id,attempt,thread,sha,state) VALUES('fixture/repo',1,1,'11111111-1111-4111-8111-111111111111','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sending');").unwrap();
    let journal = root.join("state/codex-wake/cooperative-upgrade.json");
    let bytes = serde_json::to_vec(&json!({"phase":"pending","spec":{"protocol":1,"owner":owner,"generation":2,"executable":"/no/candidate","binary":"fixture","unit":"fixture"}})).unwrap();
    fs::write(&journal, &bytes).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    for _ in 0..2 {
        let output = command(root).arg("ensure").output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("do not retry automatically"));
        assert_eq!(fs::read(&journal).unwrap(), bytes);
        assert!(
            !db.query_row("SELECT is_open FROM wake_delivery_claim_gate", [], |r| r
                .get::<_, bool>(
                0
            ))
            .unwrap()
        );
        assert_eq!(
            db.query_row("SELECT state FROM waits WHERE run_id=1", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "sending"
        );
    }
    assert!(!root.join("mutated").exists());
}
