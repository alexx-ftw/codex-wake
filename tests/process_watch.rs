#![cfg(unix)]

use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

fn isolated(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_codex-wake"));
    command
        .args(args)
        .env("HOME", root)
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("CODEX_HOME", root.join("codex"))
        .env("CODEX_WAKE_DB", root.join("watch.sqlite"))
        .env("CODEX_WAKE_CODEX", "/bin/true")
        .env("CODEX_WAKE_GH", "/bin/true")
        .env_remove("CODEX_WAKE_PLUGIN_ROOT")
        .env_remove("CODEX_WAKE_PLUGIN_BASE")
        .env_remove("CODEX_WAKE_ENABLE_WEBHOOKS");
    command
}

fn private_tempdir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn subscribe(root: &Path) -> String {
    let resource = format!("process-watch-{}", std::process::id());
    let output = isolated(
        root,
        &[
            "--db",
            root.join("watch.sqlite").to_str().unwrap(),
            "subscribe",
            "--kind",
            "job",
            "--repo",
            "local",
            "--resource",
            &resource,
            "--event",
            "completed",
            "--thread",
            "11111111-1111-4111-8111-111111111111",
            "--message-template",
            "Process watch: {{source.watch.reason}}",
        ],
    )
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["subscription_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn spawn_watch(root: &Path, id: &str, script: &str, timeout: &str) -> (Child, Value) {
    spawn_watch_with_args(root, id, script, timeout, &[])
}

fn spawn_watch_with_args(
    root: &Path,
    id: &str,
    script: &str,
    timeout: &str,
    child_args: &[&str],
) -> (Child, Value) {
    spawn_watch_pattern(root, id, "READY", script, timeout, child_args)
}

fn spawn_watch_pattern(
    root: &Path,
    id: &str,
    regex: &str,
    script: &str,
    timeout: &str,
    child_args: &[&str],
) -> (Child, Value) {
    let db = root.join("watch.sqlite");
    let mut command = isolated(root, &[]);
    command
        .arg("--db")
        .arg(db)
        .args([
            "watch-process",
            "--subscription-id",
            id,
            "--regex",
            regex,
            "--timeout-seconds",
            timeout,
            "--",
            "sh",
            "-c",
            script,
        ])
        .args(child_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.process_group(0);
    let mut child = command.spawn().unwrap();
    let mut startup = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut startup)
        .unwrap();
    assert!(!startup.is_empty(), "watch supervisor exited before launch");
    let startup: Value = serde_json::from_str(startup.trim_end()).unwrap();
    assert_eq!(startup["ready"], true);
    (child, startup)
}

fn wait_for(root: &Path, marker: &Path, id: &str) -> Value {
    let db_path = root.join("watch.sqlite");
    let db = rusqlite::Connection::open(db_path).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let status: String = db
            .query_row(
                "SELECT state FROM process_watches WHERE subscription_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        if status == "published" && marker.exists() {
            let selected: String = db
                .query_row(
                    "SELECT selection_json FROM process_watches WHERE subscription_id=?1",
                    [id],
                    |row| row.get(0),
                )
                .unwrap();
            return serde_json::from_str(&selected).unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "watch did not publish (state={status})"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn recover(root: &Path) -> Output {
    isolated(
        root,
        &[
            "--db",
            root.join("watch.sqlite").to_str().unwrap(),
            "recover-process-watches",
        ],
    )
    .output()
    .unwrap()
}

#[test]
fn detached_supervisor_continues_after_parent_drops_child_handle() {
    let root = private_tempdir();
    let id = subscribe(root.path());
    let marker = root.path().join("finished");
    let script = format!(
        "sleep .2; printf READY; sleep .1; touch '{}'",
        marker.display()
    );
    let (child, startup) = spawn_watch(root.path(), &id, &script, "5");
    assert!(startup["pid"].as_u64().is_some());
    drop(child);
    let selected = wait_for(root.path(), &marker, &id);
    assert_eq!(selected["reason"], "match");
    let stdout_path = Path::new(startup["stdout_retained_path"].as_str().unwrap());
    assert!(
        fs::read(stdout_path)
            .unwrap()
            .windows(5)
            .any(|bytes| bytes == b"READY")
    );
}

#[test]
fn canceling_subscription_keeps_child_alive_and_marks_delivery_attention() {
    struct ReleaseChild(PathBuf);
    impl Drop for ReleaseChild {
        fn drop(&mut self) {
            let _ = fs::write(&self.0, []);
        }
    }

    let root = private_tempdir();
    let id = subscribe(root.path());
    let started = root.path().join("child-started");
    let release = root.path().join("release-child");
    let _release_child = ReleaseChild(release.clone());
    let finished = root.path().join("child-finished");
    let script = format!(
        "touch '{}'; while [ ! -e '{}' ]; do sleep .01; done; printf READY; sleep .1; touch '{}'",
        started.display(),
        release.display(),
        finished.display()
    );
    let (mut supervisor, _) = spawn_watch(root.path(), &id, &script, "5");
    let deadline = Instant::now() + Duration::from_secs(3);
    while !started.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(started.exists(), "child did not reach its wait point");

    let cancelled = isolated(
        root.path(),
        &[
            "--db",
            root.path().join("watch.sqlite").to_str().unwrap(),
            "cancel-subscription",
            "--subscription-id",
            &id,
        ],
    )
    .output()
    .unwrap();
    assert!(
        cancelled.status.success(),
        "{}",
        String::from_utf8_lossy(&cancelled.stderr)
    );
    fs::write(&release, []).unwrap();

    let db = rusqlite::Connection::open(root.path().join("watch.sqlite")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (state, retention, selected, diagnostic, child_pid): (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<u32>,
        ) = db
            .query_row(
                "SELECT state,retention_state,selection_json,retention_diagnostic,child_pid FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        if finished.exists() && state == "needs_attention" && retention == "complete" {
            assert_eq!(
                serde_json::from_str::<Value>(selected.as_deref().unwrap()).unwrap()["reason"],
                "match"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child/retention did not finish after cancellation (state={state}, retention={retention}, finished={}, child_pid={child_pid:?}, diagnostic={diagnostic:?}, group={})",
            finished.exists(),
            child_pid
                .map(|pid| {
                    let group = pid.to_string();
                    Command::new("ps")
                        .args(["-eo", "pid,ppid,pgid,state,comm"])
                        .output()
                        .ok()
                        .map(|output| {
                            String::from_utf8_lossy(&output.stdout)
                                .lines()
                                .filter(|line| {
                                    let fields = line.split_whitespace().collect::<Vec<_>>();
                                    fields.first() == Some(&group.as_str())
                                        || fields.get(2) == Some(&group.as_str())
                                })
                                .collect::<Vec<_>>()
                                .join(";")
                        })
                        .unwrap_or_default()
                })
                .unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(10));
    }
    let subscription_exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE id=?1)",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !subscription_exists,
        "cancellation deletes the waiting subscription"
    );
    assert!(finished.exists(), "cancellation must not stop the child");
    assert!(!supervisor.wait().unwrap().success());
}

#[test]
fn output_is_bounded_after_match_while_inherited_child_fd_keeps_writing() {
    let root = private_tempdir();
    let id = subscribe(root.path());
    let marker = root.path().join("group-writer-started");
    let script = format!(
        "printf READY; (i=0; while [ \"$i\" -lt 250 ]; do head -c 8192 /dev/zero; i=$((i+1)); sleep .01; done) & touch '{}'",
        marker.display()
    );
    let (mut supervisor, startup) = spawn_watch(root.path(), &id, &script, "8");
    let selected = wait_for(root.path(), &marker, &id);
    assert_eq!(selected["reason"], "match");

    let active = Path::new(startup["stdout_path"].as_str().unwrap());
    let retained = Path::new(startup["stdout_retained_path"].as_str().unwrap());
    let match_context = active.with_file_name(format!(
        "{}.match",
        active.file_name().unwrap().to_string_lossy()
    ));
    let mut largest_active = 0;
    let deadline = Instant::now() + Duration::from_secs(8);
    while supervisor.try_wait().unwrap().is_none() {
        largest_active = largest_active.max(fs::metadata(active).unwrap().len());
        assert!(
            Instant::now() < deadline,
            "reaper did not finish with the child group"
        );
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        largest_active < 1024 * 1024,
        "active inode grew to {largest_active} bytes"
    );
    assert!(fs::metadata(active).unwrap().len() < 1024 * 1024);
    assert!(fs::metadata(retained).unwrap().len() <= 1024 * 1024);
    assert!(
        fs::read(match_context)
            .unwrap()
            .windows(5)
            .any(|bytes| bytes == b"READY"),
        "the bytes that caused selection must remain available"
    );
    let states: (String, String) = rusqlite::Connection::open(root.path().join("watch.sqlite"))
        .unwrap()
        .query_row(
            "SELECT state,retention_state FROM process_watches WHERE subscription_id=?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(states, ("published".into(), "complete".into()));
    for _ in 0..2 {
        let recovery = recover(root.path());
        assert!(recovery.status.success());
        let report: Value = serde_json::from_slice(&recovery.stdout).unwrap();
        assert!(
            report["scheduled"].as_array().unwrap().is_empty(),
            "published delivery with completed retention must not relaunch"
        );
    }
}

#[test]
fn recovery_restarts_post_selection_retention_after_supervisor_crash() {
    let root = private_tempdir();
    let id = subscribe(root.path());
    let marker = root.path().join("group-writer-started-before-recovery");
    let script = format!(
        "printf READY; (i=0; while [ \"$i\" -lt 250 ]; do head -c 8192 /dev/zero; i=$((i+1)); sleep .01; done) & touch '{}'",
        marker.display()
    );
    let (mut supervisor, startup) = spawn_watch(root.path(), &id, &script, "8");
    assert_eq!(wait_for(root.path(), &marker, &id)["reason"], "match");
    let child_pid = startup["pid"].as_u64().unwrap() as i32;
    assert_eq!(
        unsafe { libc::kill(supervisor.id() as i32, libc::SIGKILL) },
        0
    );
    let _ = supervisor.wait();

    let recovery = recover(root.path());
    assert!(
        recovery.status.success(),
        "{}",
        String::from_utf8_lossy(&recovery.stderr)
    );
    let report: Value = serde_json::from_slice(&recovery.stdout).unwrap();
    let recovered_pid = report["scheduled"][0]["supervisor_pid"].as_u64().unwrap() as u32;
    let duplicate_recovery = recover(root.path());
    let duplicate_report: Value = serde_json::from_slice(&duplicate_recovery.stdout).unwrap();
    assert!(
        duplicate_report["scheduled"].as_array().unwrap().is_empty(),
        "a live recovery supervisor must not be spawned again"
    );
    let active = Path::new(startup["stdout_path"].as_str().unwrap());
    let retained = Path::new(startup["stdout_retained_path"].as_str().unwrap());
    let mut largest_active = 0;
    let deadline = Instant::now() + Duration::from_secs(8);
    let db_path = root.path().join("watch.sqlite");
    loop {
        let owner: u32 = rusqlite::Connection::open(&db_path)
            .unwrap()
            .query_row(
                "SELECT supervisor_pid FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        if owner == recovered_pid {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "recovery did not take over the watch"
        );
        thread::sleep(Duration::from_millis(10));
    }
    while unsafe { libc::kill(-child_pid, 0) } == 0 {
        largest_active = largest_active.max(fs::metadata(active).unwrap().len());
        assert!(Instant::now() < deadline, "recovered reaper did not finish");
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        largest_active < 1024 * 1024,
        "active inode grew to {largest_active} bytes"
    );
    assert!(fs::metadata(retained).unwrap().len() <= 1024 * 1024);
}

#[test]
fn crashed_supervisor_can_resume_from_durable_output_without_stopping_child() {
    let root = private_tempdir();
    let id = subscribe(root.path());
    let marker = root.path().join("finished-after-crash");
    let script = format!(
        "sleep 1; head -c 65536 /dev/zero; printf READY; touch '{}'",
        marker.display()
    );
    let (mut supervisor, startup) = spawn_watch(root.path(), &id, &script, "5");
    let child_pid = startup["pid"].as_u64().unwrap() as u32;
    let supervisor_pid = supervisor.id();
    assert_eq!(
        unsafe { libc::kill(supervisor_pid as i32, libc::SIGKILL) },
        0
    );
    let _ = supervisor.wait();
    assert_eq!(
        unsafe { libc::kill(child_pid as i32, 0) },
        0,
        "crashing the watcher must not kill the command"
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    while !marker.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        marker.exists(),
        "child should finish while its supervisor is down"
    );

    let output = recover(root.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["scheduled"].as_array().unwrap().len(), 1);
    assert_ne!(response["scheduled"][0]["supervisor_pid"], supervisor_pid);
    let scheduled_pid = response["scheduled"][0]["supervisor_pid"].as_u64().unwrap();
    let selected = wait_for(root.path(), &marker, &id);
    assert_eq!(selected["reason"], "recovery_ambiguous");
    let candidates = selected["candidates"].as_array().unwrap();
    assert!(candidates.iter().any(|candidate| candidate == "match"));
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate == "process_exit")
    );
    let db = rusqlite::Connection::open(root.path().join("watch.sqlite")).unwrap();
    let (state, owner_pid): (String, u32) = db
        .query_row(
            "SELECT state,supervisor_pid FROM process_watches WHERE subscription_id=?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        state, "published",
        "scheduled recovery must eventually durably handle the crashed watch"
    );
    assert_eq!(owner_pid as u64, scheduled_pid);
    let source: String = db
        .query_row(
            "SELECT source_json FROM subscriptions WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(source.contains("process-watch:"));
}

#[test]
fn resume_flag_after_separator_is_passed_to_child() {
    let root = private_tempdir();
    let id = subscribe(root.path());
    let marker = root.path().join("received-resume-argument");
    let script = format!(
        "test \"$0\" = --resume && printf READY && touch '{}'",
        marker.display()
    );
    let (mut supervisor, startup) =
        spawn_watch_with_args(root.path(), &id, &script, "5", &["--resume"]);
    let selected = wait_for(root.path(), &marker, &id);
    assert_eq!(selected["reason"], "match");
    assert!(marker.exists());
    let _ = supervisor.wait();
    assert!(Path::new(startup["stdout_path"].as_str().unwrap()).exists());
}

#[test]
fn resume_flag_used_as_regex_value_is_not_treated_as_resume_mode() {
    let root = private_tempdir();
    let id = subscribe(root.path());
    let marker = root.path().join("matched-resume-regex");
    let script = format!("printf '%s' --resume; touch '{}'", marker.display());
    let (mut supervisor, _) = spawn_watch_pattern(root.path(), &id, "--resume", &script, "5", &[]);
    let selected = wait_for(root.path(), &marker, &id);
    assert_eq!(selected["reason"], "match");
    let _ = supervisor.wait();
}

#[test]
fn regex_values_that_look_like_global_options_or_separator_are_preserved() {
    for (index, pattern) in ["--db", "--"].into_iter().enumerate() {
        let root = private_tempdir();
        let id = subscribe(root.path());
        let marker = root.path().join(format!("regex-{index}-finished"));
        let script = format!("printf '%s' '{pattern}'; touch '{}'", marker.display());
        let (mut supervisor, _) = spawn_watch_pattern(root.path(), &id, pattern, &script, "5", &[]);
        let selected = wait_for(root.path(), &marker, &id);
        assert_eq!(selected["reason"], "match", "pattern={pattern}");
        let _ = supervisor.wait();
    }
}

#[test]
fn status_keeps_legacy_trailing_database_option() {
    let root = private_tempdir();
    let override_db = root.path().join("trailing-option.sqlite");
    let output = isolated(
        root.path(),
        &["status", "--db", override_db.to_str().unwrap()],
    )
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(override_db.exists());
    assert!(!root.path().join("watch.sqlite").exists());
}
