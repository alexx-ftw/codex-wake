//! Explicit local-service qualification; never queues a real chat.
mod support;
use serde_json::json;
use std::{process::Command, time::Duration};
use support::Client;

fn pid() -> String {
    let result = Command::new("systemctl")
        .args([
            "--user",
            "show",
            "codex-wake.service",
            "--property=MainPID",
            "--value",
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    let pid = String::from_utf8(result.stdout).unwrap().trim().to_owned();
    assert_ne!(pid, "0");
    pid
}

#[test]
#[ignore = "uses the real shared user service; run explicitly"]
fn mcp_environment_can_reuse_the_installed_service() {
    let initial_pid = pid();
    let output = Command::new(env!("CARGO_BIN_EXE_codex-wake"))
        .arg("ensure")
        .env("PATH", "/usr/bin:/bin")
        .env_remove("CODEX_WAKE_CODEX")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(pid(), initial_pid);
}

#[test]
#[ignore = "creates/reuses the real shared user service; run explicitly"]
fn concurrent_mcp_sessions_share_receiver_and_closing_them_preserves_it() {
    // Start both OS processes before either handshake: their startup paths contend.
    let mut first = Client::start();
    let mut second = Client::start();
    first.initialize();
    second.initialize();
    let initial_pid = pid();
    for client in [&mut first, &mut second] {
        client.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}));
        let reply = client.response(2, Duration::from_secs(100));
        let tools = reply["result"]["tools"].as_array().unwrap();
        assert!(tools.len() >= 16);
        assert!(tools.iter().any(|t| t["name"] == "register_wait"));
        for name in [
            "register_circular_wait",
            "resolve_circular_wait",
            "register_obligation",
            "register_coordinator",
            "list_obligations",
            "resolve_obligation",
            "propose_obligation_transfer",
            "list_obligation_transfers",
            "accept_obligation_transfer",
            "register_validation",
            "resolve_validation",
        ] {
            assert!(tools.iter().any(|t| t["name"] == name));
        }
        let reply = json!({"result":{"structuredContent":client.call("get_status", json!({}))}});
        assert_eq!(
            reply["result"]["structuredContent"]["receiver"]["local_ready"], true,
            "{reply}"
        );
        client.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"register_wait","arguments":{
            "repo":"owner/repo","run_id":true,"attempt":1,"sha":"a".repeat(40),"thread":"11111111-1111-4111-8111-111111111111"}}}));
        let reply = client.response(4, Duration::from_secs(100));
        assert!(
            reply.get("error").is_some() || reply["result"]["isError"] == true,
            "{reply}"
        );
    }
    first.close();
    assert_eq!(pid(), initial_pid);
    second.close();
    assert_eq!(pid(), initial_pid);
    let mut third = Client::start();
    third.initialize();
    assert_eq!(pid(), initial_pid);
    third.close();
}
