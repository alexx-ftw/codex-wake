use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

fn invoke(root: &Path, args: &[&str], input: Option<&str>) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_codex-wake"))
        .args(args)
        .env("HOME", root)
        .env("CODEX_HOME", root.join("codex-home"))
        .env("XDG_STATE_HOME", root)
        .env_remove("CODEX_WAKE_DB")
        .env_remove("CODEX_WAKE_PLUGIN_BASE")
        .env_remove("CODEX_WAKE_PLUGIN_ROOT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}

#[test]
fn records_success_rejection_and_failure_across_processes_without_payloads() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("codex-wake");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let payload=json!({"hook_event_name":"Stop","session_id":"11111111-1111-4111-8111-111111111111","last_assistant_message":"SECRET_PROMPT_NEVER_LOG"}).to_string();
    assert!(
        invoke(root.path(), &["hook"], Some(&payload))
            .status
            .success()
    );
    assert!(
        !invoke(root.path(), &["hook"], Some("{SECRET_INVALID_JSON"))
            .status
            .success()
    );
    assert!(
        !invoke(root.path(), &["SECRET_UNKNOWN_COMMAND"], None)
            .status
            .success()
    );
    let output = invoke(root.path(), &["diagnostics", "--days", "42"], None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["enabled"], true);
    let groups = report["daily_groups"].as_array().unwrap();
    assert!(
        groups
            .iter()
            .any(|g| g["operation"] == "hook.stop" && g["outcome"] == "ok")
    );
    assert!(
        groups
            .iter()
            .any(|g| g["operation"] == "cli.hook" && g["reason"] == "invalid_json")
    );
    assert!(
        groups
            .iter()
            .any(|g| g["operation"] == "cli.unknown_command" && g["outcome"] == "error")
    );
    assert_eq!(report["telemetry_write_failures_this_process"], 0);
    let bytes = fs::read(state.join("telemetry.sqlite3")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("SECRET_"));
    assert!(!String::from_utf8_lossy(&bytes).contains("11111111-1111-4111-8111-111111111111"));
    assert_eq!(
        fs::metadata(state.join("telemetry.sqlite3"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn diagnostics_is_read_only_and_bad_logging_does_not_stop_operations() {
    let root = tempfile::tempdir().unwrap();
    let output = invoke(root.path(), &["diagnostics"], None);
    assert!(output.status.success());
    assert!(!root.path().join("codex-wake").exists());
    assert!(
        !invoke(root.path(), &["diagnostics", "--days", "0"], None)
            .status
            .success()
    );
    let state = root.path().join("codex-wake");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(state.join("telemetry.sqlite3"), b"foreign invalid database").unwrap();
    fs::set_permissions(
        state.join("telemetry.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let payload =
        json!({"hook_event_name":"Stop","session_id":"11111111-1111-4111-8111-111111111111"})
            .to_string();
    let output = invoke(root.path(), &["hook"], Some(&payload));
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({})
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("telemetry_write_failed"));
    assert_eq!(
        fs::read(state.join("telemetry.sqlite3")).unwrap(),
        b"foreign invalid database"
    );
}

#[test]
fn concurrent_cli_processes_keep_all_operation_results() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("codex-wake");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let root = root.path();
                scope.spawn(move || {
                    let output = invoke(root, &["hook"], Some("{INVALID_JSON"));
                    assert!(!output.status.success());
                    assert!(
                        !String::from_utf8_lossy(&output.stderr).contains("telemetry_write_failed")
                    );
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    let output = invoke(root.path(), &["diagnostics"], None);
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let groups = report["daily_groups"].as_array().unwrap();
    let errors: i64 = groups
        .iter()
        .filter(|g| g["operation"] == "cli.hook" && g["outcome"] == "error")
        .map(|g| g["calls"].as_i64().unwrap())
        .sum();
    assert_eq!(errors, 8);
}
