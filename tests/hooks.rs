use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[cfg(unix)]
fn executable(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn invoke(payload: Value) -> std::process::Output {
    let temp = tempfile::tempdir().unwrap();
    invoke_at(payload, temp.path())
}

fn invoke_at(payload: Value, temp: &std::path::Path) -> std::process::Output {
    invoke_with_codex(payload, temp, "/nonexistent/codex-wake-test-codex")
}

fn invoke_with_codex(payload: Value, temp: &std::path::Path, codex: &str) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(temp, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_codex-wake"))
        .args([
            "--db",
            temp.join("state.sqlite3").to_str().unwrap(),
            "--codex",
            codex,
            "hook",
        ])
        .env("XDG_STATE_HOME", temp)
        .env("WAKE_TEST_CALLS", temp.join("codex-calls"))
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
fn stop_notifies_only_the_explicit_coordinator_once_with_obligation_and_last_info() {
    let temp = tempfile::tempdir().unwrap();
    let responsible = "11111111-1111-4111-8111-111111111111";
    let coordinator = "22222222-2222-4222-8222-222222222222";
    let codex = temp.path().join("codex");
    executable(
        &codex,
        "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$WAKE_TEST_CALLS\"\n",
    );
    let initial = json!({"hook_event_name":"Stop","session_id":responsible,"turn_id":"turn-1"});
    assert!(
        invoke_with_codex(initial.clone(), temp.path(), codex.to_str().unwrap())
            .status
            .success()
    );
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('one',?1,'artifact','repo','release','available','Publish signed release notes')", [responsible]).unwrap();
    db.execute(
        "INSERT INTO coordinators(responsible,coordinator) VALUES(?1,?2)",
        [responsible, coordinator],
    )
    .unwrap();

    for ignored in [
        json!({"hook_event_name":"SubagentStop","session_id":responsible,"agent_id":"33333333-3333-4333-8333-333333333333","turn_id":"turn-1"}),
        json!({"hook_event_name":"Stop","session_id":responsible,"turn_id":"turn-1","stop_hook_active":true}),
    ] {
        let result = invoke_with_codex(ignored, temp.path(), codex.to_str().unwrap());
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!temp.path().join("codex-calls").exists());
    }

    let payload = json!({"hook_event_name":"Stop","session_id":responsible,"turn_id":"turn-1","last_assistant_message":"Release notes are still waiting on signing."});
    let first = invoke_with_codex(payload.clone(), temp.path(), codex.to_str().unwrap());
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let output: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert!(
        output["systemMessage"]
            .as_str()
            .unwrap()
            .contains(coordinator)
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("codex-calls")).unwrap(),
        "queue\n"
    );

    let again = invoke_with_codex(payload, temp.path(), codex.to_str().unwrap());
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("codex-calls")).unwrap(),
        "queue\n"
    );
    let (message, state): (String, String) = db
        .query_row("SELECT message,state FROM coordinator_alerts WHERE reason IS NOT 'compatibility_guard_not_delivery'", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert!(message.contains("Publish signed release notes"));
    assert!(message.contains("Release notes are still waiting on signing."));
    assert!(message.contains("not establish task completion or abandonment"));
    assert_eq!(state, "queued");
}

#[test]
fn concurrent_hook_processes_emit_one_context_and_never_replay_it() {
    let temp = tempfile::tempdir().unwrap();
    let payload = json!({"hook_event_name":"PostToolUse","session_id":"11111111-1111-4111-8111-111111111111","turn_id":"turn1","tool_use_id":"tool1"});
    assert!(invoke_at(payload.clone(), temp.path()).status.success());
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO steers(id,thread,message) VALUES('one',?1,'Process the authorized result')",
        [payload["session_id"].as_str().unwrap()],
    )
    .unwrap();
    let workers = (0..2)
        .map(|_| {
            let path = temp.path().to_path_buf();
            let payload = payload.clone();
            std::thread::spawn(move || {
                let output = invoke_at(payload, &path);
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                serde_json::from_slice::<Value>(&output.stdout).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let outputs = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    let contexts = outputs
        .iter()
        .filter(|output| output.get("hookSpecificOutput").is_some())
        .collect::<Vec<_>>();
    assert_eq!(contexts.len(), 1);
    assert!(
        contexts[0]["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .contains("Process the authorized result")
    );
    assert!(
        outputs
            .iter()
            .all(|output| output.get("decision").is_none())
    );
    assert_eq!(
        db.query_row("SELECT state FROM steers WHERE id='one'", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "claimed"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&invoke_at(payload, temp.path()).stdout).unwrap(),
        json!({})
    );
}

#[test]
fn stop_combines_steer_and_pending_publication_without_resolving_it() {
    let temp = tempfile::tempdir().unwrap();
    let thread = "11111111-1111-4111-8111-111111111111";
    let payload = json!({"hook_event_name":"Stop","session_id":thread,"turn_id":"turn1"});
    assert!(invoke_at(payload.clone(), temp.path()).status.success());
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('one',?1,'artifact','repo','artifact1','available','report ready')", [thread]).unwrap();
    db.execute(
        "INSERT INTO steers(id,thread,message) VALUES('steer1',?1,'review input')",
        [thread],
    )
    .unwrap();
    db.execute("INSERT INTO subscriptions(id,kind,repo,resource,event,thread,state) VALUES('sub','thread','',?1,'turn_completed','22222222-2222-4222-8222-222222222222','waiting')", [thread]).unwrap();
    let result = invoke_at(payload.clone(), temp.path());
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(output["decision"], "block");
    let reason = output["reason"].as_str().unwrap();
    assert!(reason.contains("review input") && reason.contains("list_obligations"));
    assert!(
        output["systemMessage"]
            .as_str()
            .unwrap()
            .contains("deferred to the receiver")
    );
    assert_eq!(
        db.query_row(
            "SELECT state FROM subscriptions WHERE id='sub'",
            [],
            |row| row.get::<_, String>(0)
        )
        .unwrap(),
        "ready"
    );
    assert_eq!(
        db.query_row(
            "SELECT resolved FROM obligations WHERE id='one'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    db.execute("DELETE FROM subscriptions WHERE id='sub'", [])
        .unwrap();
    let again = invoke_at(
        json!({"hook_event_name":"Stop","session_id":thread,"turn_id":"turn1","stop_hook_active":true}),
        temp.path(),
    );
    assert!(again.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&again.stdout).unwrap(),
        json!({})
    );
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
            .env("CODEX_WAKE_BUILD_FROM_SOURCE", "1")
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

#[cfg(unix)]
fn release_fixture(temp: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = temp.path().join("plugin");
    let tools = temp.path().join("tools");
    let source = temp.path().join("release");
    std::fs::create_dir_all(root.join("scripts")).unwrap();
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::create_dir_all(source.join("codex-wake-0.2.0-alpha.1/bin")).unwrap();
    std::fs::create_dir_all(source.join("codex-wake-0.2.0-alpha.1/src")).unwrap();
    std::fs::write(
        root.join("scripts/run-mcp.sh"),
        include_str!("../scripts/run-mcp.sh"),
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"codex-wake\"\nversion = \"0.2.0-alpha.1\"\n",
    )
    .unwrap();
    let binary = source.join("codex-wake-0.2.0-alpha.1/bin/codex-wake");
    executable(
        &binary,
        "#!/bin/sh\nif [ -n \"${HOLD_MARKER:-}\" ]; then : > \"$HOLD_MARKER\"; sleep 3; fi\nprintf '%s|%s\\n' \"$CODEX_WAKE_PLUGIN_ROOT\" \"$*\"\n",
    );
    let output = Command::new("sha256sum")
        .arg("codex-wake")
        .current_dir(binary.parent().unwrap())
        .output()
        .unwrap();
    let inner = String::from_utf8(output.stdout).unwrap();
    std::fs::write(binary.parent().unwrap().join("codex-wake.sha256"), inner).unwrap();
    std::fs::write(
        source.join("codex-wake-0.2.0-alpha.1/src/main.rs"),
        "packaged source\n",
    )
    .unwrap();
    let archive_name = "codex-wake-0.2.0-alpha.1-linux-x86_64.tar.gz";
    let archive = temp.path().join(archive_name);
    assert!(
        Command::new("tar")
            .args(["-czf"])
            .arg(&archive)
            .arg("codex-wake-0.2.0-alpha.1")
            .current_dir(&source)
            .status()
            .unwrap()
            .success()
    );
    let digest = Command::new("sha256sum").arg(&archive).output().unwrap();
    std::fs::write(
        temp.path().join("SHA256SUMS"),
        format!(
            "{}  {archive_name}\n",
            String::from_utf8(digest.stdout)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
        ),
    )
    .unwrap();
    let calls = temp.path().join("curl.calls");
    executable(
        &tools.join("curl"),
        &format!(
            "#!/bin/sh\nurl= out=\nwhile [ $# -gt 0 ]; do case \"$1\" in https://*) url=$1 ;; -o) shift; out=$1 ;; esac; shift; done\nprintf '%s\\n' \"$url\" >> '{}'\ncase \"$url\" in *SHA256SUMS) cp '{}' \"$out\" ;; *) cp '{}' \"$out\" ;; esac\n",
            calls.display(),
            temp.path().join("SHA256SUMS").display(),
            archive.display()
        ),
    );
    (root, tools)
}

#[cfg(unix)]
#[test]
fn launcher_downloads_once_concurrently_and_uses_private_verified_cache() {
    let temp = tempfile::tempdir().unwrap();
    let (root, tools) = release_fixture(&temp);
    let cache = temp.path().join("cache");
    let script = root.join("scripts/run-mcp.sh");
    let path = format!("{}:/usr/bin:/bin", tools.display());
    let cache_for_run = cache.clone();
    let cache_for_second = cache.clone();
    let script_for_run = script.clone();
    let path_for_run = path.clone();
    let a = std::thread::spawn(move || {
        Command::new("sh")
            .arg(script_for_run)
            .arg("probe")
            .env("PATH", path_for_run)
            .env("XDG_CACHE_HOME", cache_for_run)
            .output()
            .unwrap()
    });
    let b = std::thread::spawn(move || {
        Command::new("sh")
            .arg(script)
            .arg("probe")
            .env("PATH", path)
            .env("XDG_CACHE_HOME", cache_for_second)
            .output()
            .unwrap()
    });
    for output in [a.join().unwrap(), b.join().unwrap()] {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8(output.stdout).unwrap().contains("|probe"));
    }
    assert!(
        Command::new("sh")
            .arg(root.join("scripts/run-mcp.sh"))
            .arg("probe")
            .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
            .env("XDG_CACHE_HOME", &cache)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("curl.calls"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    let installed = cache.join("codex-wake/releases/0.2.0-alpha.1/linux-x86_64/bin/codex-wake");
    assert!(installed.is_file());
    assert!(!root.join("bin/codex-wake").exists());
}

#[cfg(unix)]
#[test]
fn launcher_prefers_verified_bundled_binary_without_cargo_or_network() {
    let temp = tempfile::tempdir().unwrap();
    let (root, tools) = release_fixture(&temp);
    std::fs::create_dir_all(root.join("bin")).unwrap();
    let binary = root.join("bin/codex-wake");
    executable(
        &binary,
        "#!/bin/sh\nprintf 'bundled:%s:%s\\n' \"$CODEX_WAKE_PLUGIN_ROOT\" \"$*\"\n",
    );
    let digest = Command::new("sha256sum")
        .arg("codex-wake")
        .current_dir(root.join("bin"))
        .output()
        .unwrap();
    std::fs::write(root.join("bin/codex-wake.sha256"), digest.stdout).unwrap();
    executable(&tools.join("cargo"), "#!/bin/sh\nexit 90\n");
    executable(&tools.join("curl"), "#!/bin/sh\nexit 91\n");
    let output = Command::new("sh")
        .arg(root.join("scripts/run-mcp.sh"))
        .arg("probe")
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .env("XDG_CACHE_HOME", temp.path().join("cache"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("bundled:")
    );
    let checksum = root.join("bin/codex-wake.sha256");
    let original = std::fs::read_to_string(&checksum).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&checksum)
        .unwrap()
        .write_all(original.as_bytes())
        .unwrap();
    let duplicate = Command::new("sh")
        .arg(root.join("scripts/run-mcp.sh"))
        .arg("probe")
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .env("XDG_CACHE_HOME", temp.path().join("cache"))
        .output()
        .unwrap();
    assert!(
        !duplicate.status.success(),
        "duplicate checksum rows must be rejected"
    );
}

#[cfg(unix)]
#[test]
fn launcher_releases_cache_lock_before_long_lived_binary_exec() {
    let temp = tempfile::tempdir().unwrap();
    let (root, tools) = release_fixture(&temp);
    let cache = temp.path().join("cache");
    let script = root.join("scripts/run-mcp.sh");
    let path = format!("{}:/usr/bin:/bin", tools.display());
    let prime = Command::new("sh")
        .arg(&script)
        .env("PATH", &path)
        .env("XDG_CACHE_HOME", &cache)
        .output()
        .unwrap();
    assert!(
        prime.status.success(),
        "{}",
        String::from_utf8_lossy(&prime.stderr)
    );

    let marker = temp.path().join("first-running");
    let mut first = Command::new("sh")
        .arg(&script)
        .env("PATH", &path)
        .env("XDG_CACHE_HOME", &cache)
        .env("HOLD_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(marker.exists(), "first cached process did not start");
    assert!(
        !std::path::Path::new(&format!("/proc/{}/fd/9", first.id())).exists(),
        "cache lock descriptor 9 must be closed in the live MCP process"
    );

    let mut second = Command::new("sh")
        .arg(&script)
        .env("PATH", &path)
        .env("XDG_CACHE_HOME", &cache)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut completed = false;
    for _ in 0..100 {
        if second.try_wait().unwrap().is_some() {
            completed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !completed {
        let _ = second.kill();
    }
    assert!(
        completed,
        "second launch waited for first MCP process to exit"
    );
    let second_output = second.wait_with_output().unwrap();
    assert!(
        second_output.status.success(),
        "{}",
        String::from_utf8_lossy(&second_output.stderr)
    );
    assert!(first.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn launcher_rejects_bad_checksum_without_executing_or_installing() {
    let temp = tempfile::tempdir().unwrap();
    let (root, tools) = release_fixture(&temp);
    std::fs::write(
        temp.path().join("SHA256SUMS"),
        format!(
            "{}  codex-wake-0.2.0-alpha.1-linux-x86_64.tar.gz\n",
            "0".repeat(64)
        ),
    )
    .unwrap();
    let output = Command::new("sh")
        .arg(root.join("scripts/run-mcp.sh"))
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .env("XDG_CACHE_HOME", temp.path().join("cache"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        !temp
            .path()
            .join("cache/codex-wake/releases/0.2.0-alpha.1/linux-x86_64/bin/codex-wake")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn launcher_rejects_unsupported_platform_before_download() {
    let temp = tempfile::tempdir().unwrap();
    let (root, tools) = release_fixture(&temp);
    executable(
        &tools.join("uname"),
        "#!/bin/sh\ncase \"$1\" in -s) echo Darwin ;; *) echo arm64 ;; esac\n",
    );
    executable(&tools.join("curl"), "#!/bin/sh\nexit 92\n");
    let output = Command::new("sh")
        .arg(root.join("scripts/run-mcp.sh"))
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .env("XDG_CACHE_HOME", temp.path().join("cache"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Linux x86_64 only"));
}

#[test]
fn full_fingerprint_detects_ninth_change_and_never_replays_uncertain_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let owner = "11111111-1111-4111-8111-111111111111";
    let coordinator = "22222222-2222-4222-8222-222222222222";
    let codex = temp.path().join("codex");
    executable(
        &codex,
        "#!/bin/sh\nprintf 'attempt\\n' >> \"$WAKE_TEST_CALLS\"\nexit 1\n",
    );
    let payload = json!({"hook_event_name":"Stop","session_id":owner,"turn_id":"turn-1"});
    assert!(
        invoke_with_codex(payload.clone(), temp.path(), codex.to_str().unwrap())
            .status
            .success()
    );
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO coordinators(responsible,coordinator) VALUES(?1,?2)",
        [owner, coordinator],
    )
    .unwrap();
    for n in 0..8 {
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES(?1,?2,'artifact','repo','release','available','Pending')", rusqlite::params![format!("fixture-{n}"), owner]).unwrap();
    }
    for _ in 0..2 {
        assert!(
            invoke_with_codex(payload.clone(), temp.path(), codex.to_str().unwrap())
                .status
                .success()
        );
    }
    db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('fixture-8',?1,'artifact','repo','release','available','Ninth')", [owner]).unwrap();
    for _ in 0..2 {
        assert!(
            invoke_with_codex(payload.clone(), temp.path(), codex.to_str().unwrap())
                .status
                .success()
        );
    }
    db.execute(
        "UPDATE obligations SET description='Ninth modified' WHERE id='fixture-8'",
        [],
    )
    .unwrap();
    assert!(
        invoke_with_codex(payload.clone(), temp.path(), codex.to_str().unwrap())
            .status
            .success()
    );
    db.execute("UPDATE obligations SET resolved=1 WHERE id='fixture-8'", [])
        .unwrap();
    assert!(
        invoke_with_codex(payload, temp.path(), codex.to_str().unwrap())
            .status
            .success()
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("codex-calls")).unwrap(),
        "attempt\nattempt\nattempt\n"
    );
    let states: Vec<String> = db
        .prepare("SELECT state FROM coordinator_alerts WHERE reason IS NOT 'compatibility_guard_not_delivery' ORDER BY rowid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(states, vec!["needs_attention"; 3]);
    let messages: Vec<String> = db
        .prepare("SELECT message FROM coordinator_alerts WHERE reason IS NOT 'compatibility_guard_not_delivery' ORDER BY rowid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(messages[1].contains("1 more pending item(s)"));
    assert!(!messages[1].contains("Ninth modified"));
}

#[test]
fn existing_legacy_uncertain_alert_is_not_replayed() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let owner = "11111111-1111-4111-8111-111111111111";
    let coordinator = "22222222-2222-4222-8222-222222222222";
    let codex = temp.path().join("codex");
    executable(
        &codex,
        "#!/bin/sh\nprintf 'attempt\\n' >> \"$WAKE_TEST_CALLS\"\n",
    );
    let payload = json!({"hook_event_name":"Stop","session_id":owner,"turn_id":"turn-1"});
    assert!(
        invoke_with_codex(payload.clone(), temp.path(), codex.to_str().unwrap())
            .status
            .success()
    );
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('one',?1,'artifact','repo','release','available','Pending')", [owner]).unwrap();
    db.execute(
        "INSERT INTO coordinators(responsible,coordinator) VALUES(?1,?2)",
        [owner, coordinator],
    )
    .unwrap();
    let legacy = json!({"source":owner,"turn":"turn-1","pending_ids":["one"]}).to_string();
    let id = format!(
        "{:x}",
        Sha256::digest(format!("{owner}:{coordinator}:{legacy}").as_bytes())
    );
    db.execute("INSERT INTO coordinator_alerts(id,responsible,coordinator,message,state,reason) VALUES(?1,?2,?3,'old','needs_attention','delivery_unknown')", rusqlite::params![id,owner,coordinator]).unwrap();
    assert!(
        invoke_with_codex(payload, temp.path(), codex.to_str().unwrap())
            .status
            .success()
    );
    assert!(!temp.path().join("codex-calls").exists());
    let count: i64 = db
        .query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn concurrent_identical_stops_claim_one_uncertain_alert() {
    use std::sync::{Arc, Barrier};
    let temp = tempfile::tempdir().unwrap();
    let owner = "11111111-1111-4111-8111-111111111111";
    let coordinator = "22222222-2222-4222-8222-222222222222";
    let codex = temp.path().join("codex");
    executable(
        &codex,
        "#!/bin/sh\nprintf 'attempt\\n' >> \"$WAKE_TEST_CALLS\"\nexit 1\n",
    );
    let payload = json!({"hook_event_name":"Stop","session_id":owner,"turn_id":"turn-1"});
    assert!(
        invoke_with_codex(payload.clone(), temp.path(), codex.to_str().unwrap())
            .status
            .success()
    );
    let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
    db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('one',?1,'artifact','repo','release','available','Pending')", [owner]).unwrap();
    db.execute(
        "INSERT INTO coordinators(responsible,coordinator) VALUES(?1,?2)",
        [owner, coordinator],
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let barrier = barrier.clone();
            let path = temp.path().to_path_buf();
            let codex = codex.clone();
            let payload = payload.clone();
            std::thread::spawn(move || {
                barrier.wait();
                invoke_with_codex(payload, &path, codex.to_str().unwrap())
            })
        })
        .collect();
    for task in tasks {
        assert!(task.join().unwrap().status.success());
    }
    assert_eq!(
        std::fs::read_to_string(temp.path().join("codex-calls")).unwrap(),
        "attempt\n"
    );
    let (count, state): (i64, String) = db
        .query_row(
            "SELECT count(*),min(state) FROM coordinator_alerts WHERE reason IS NOT 'compatibility_guard_not_delivery'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((count, state.as_str()), (1, "needs_attention"));
}

#[test]
fn legacy_collision_with_ninth_is_durable_visible_and_never_sent() {
    use sha2::{Digest, Sha256};
    for has_turn in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let owner = "11111111-1111-4111-8111-111111111111";
        let coordinator = "22222222-2222-4222-8222-222222222222";
        let codex = temp.path().join("codex");
        executable(
            &codex,
            "#!/bin/sh\nprintf 'attempt\\n' >> \"$WAKE_TEST_CALLS\"\n",
        );
        let init = json!({"hook_event_name":"Stop","session_id":owner,"turn_id":"init"});
        assert!(
            invoke_with_codex(init, temp.path(), codex.to_str().unwrap())
                .status
                .success()
        );
        let db = rusqlite::Connection::open(temp.path().join("state.sqlite3")).unwrap();
        db.execute(
            "INSERT INTO coordinators(responsible,coordinator) VALUES(?1,?2)",
            [owner, coordinator],
        )
        .unwrap();
        let mut ids = Vec::new();
        for n in 0..8 {
            let id = format!("fixture-{n}");
            db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES(?1,?2,'artifact','repo','release','available','Pending')", rusqlite::params![id, owner]).unwrap();
            ids.push(id);
        }
        let legacy = if has_turn {
            json!({"source":owner,"turn":"turn-1","pending_ids":ids})
        } else {
            json!({"source":owner,"turn":"no_turn_id","pending_ids":ids,"last_assistant_message":"same message"})
        };
        let legacy_id = format!(
            "{:x}",
            Sha256::digest(format!("{owner}:{coordinator}:{legacy}").as_bytes())
        );
        db.execute("INSERT INTO coordinator_alerts(id,responsible,coordinator,message,state,reason) VALUES(?1,?2,?3,'old','needs_attention','delivery_unknown')", rusqlite::params![legacy_id,owner,coordinator]).unwrap();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('fixture-8',?1,'artifact','repo','release','available','Ninth')", [owner]).unwrap();
        let payload = if has_turn {
            json!({"hook_event_name":"Stop","session_id":owner,"turn_id":"turn-1","last_assistant_message":"same message"})
        } else {
            json!({"hook_event_name":"Stop","session_id":owner,"last_assistant_message":"same message"})
        };
        for _ in 0..2 {
            let output = invoke_with_codex(payload.clone(), temp.path(), codex.to_str().unwrap());
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            let text = value["systemMessage"].as_str().unwrap();
            assert!(text.contains("Delivery of this snapshot is not confirmed"));
            assert!(text.contains("no automatic send was attempted"));
        }
        assert!(!temp.path().join("codex-calls").exists());
        let (alert_id, reason, state, old_id): (String,String,String,String) = db.query_row("SELECT a.id,a.reason,a.state,c.legacy_alert_id FROM coordinator_alerts a JOIN coordinator_alert_legacy_collisions c ON c.alert_id=a.id", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(
            (reason.as_str(), state.as_str(), old_id.as_str()),
            (
                "legacy_collision_delivery_unknown",
                "needs_attention",
                legacy_id.as_str()
            )
        );
        let count: i64 = db
            .query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        let observations: i64 = db
            .query_row(
                "SELECT observations FROM coordinator_alert_legacy_collisions WHERE alert_id=?1",
                [&alert_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(observations, 2);
        db.execute(
            "UPDATE obligations SET resolved=1,description='Changed later' WHERE id='fixture-8'",
            [],
        )
        .unwrap();
        let description: String = db.query_row("SELECT description FROM coordinator_alert_collision_items WHERE alert_id=?1 AND id='fixture-8'", [&alert_id], |r| r.get(0)).unwrap();
        assert_eq!(description, "Ninth");
    }
}
