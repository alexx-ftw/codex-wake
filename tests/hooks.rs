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

#[test]
fn launcher_does_not_execute_another_plugins_cached_binary() {
    let temp = tempfile::tempdir().unwrap();
    let cache = temp.path().join("shared cache");
    let roots = [temp.path().join("copy a"), temp.path().join("copy b")];
    for (root, marker) in roots.iter().zip(["A", "B"]) {
        std::fs::create_dir_all(root.join("scripts")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("scripts/run-mcp.sh"),
            include_str!("../scripts/run-mcp.sh"),
        )
        .unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"codex-wake\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"codex-wake\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.rs"),
            format!("fn main() {{ println!(\"{marker}\"); }}\n"),
        )
        .unwrap();
    }
    for (index, expected) in [(0, "A"), (1, "B"), (0, "A")] {
        let output = Command::new("sh")
            .arg(roots[index].join("scripts/run-mcp.sh"))
            .arg("probe")
            .env("XDG_CACHE_HOME", &cache)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
    }
}
