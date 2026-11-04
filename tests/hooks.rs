use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn invoke(payload: Value) -> std::process::Output {
    let temp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_codex-wake"))
        .args([
            "--db",
            temp.path().join("state.sqlite3").to_str().unwrap(),
            "--codex",
            "/nonexistent/codex-wake-test-codex",
            "hook",
        ])
        .env("XDG_STATE_HOME", temp.path())
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
    child.wait_with_output().unwrap()
}

#[test]
fn lifecycle_cli_emits_one_json_object_without_plain_text_or_control_fields() {
    for event in ["Stop", "SubagentStop"] {
        let output = invoke(
            json!({"hook_event_name":event,"session_id":"11111111-1111-4111-8111-111111111111","agent_id":"22222222-2222-4222-8222-222222222222"}),
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!({})
        );
    }
}

#[test]
fn failed_hook_emits_supported_warning_and_failing_exit_code() {
    let output = invoke(json!({"hook_event_name":"Stop"}));
    assert!(!output.status.success());
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        parsed["systemMessage"]
            .as_str()
            .unwrap()
            .contains("delivery is not confirmed")
    );
    assert_eq!(parsed.as_object().unwrap().len(), 1);
    assert!(!output.stderr.is_empty());
}
