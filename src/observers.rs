use anyhow::{Context, Result, bail, ensure};
use rmcp::schemars::{self, JsonSchema};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::{Command, Output},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const POLL_SECONDS: i64 = 60;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    File { path: String },
    Http { url: String },
    FileLock { path: String },
    Systemd { unit: String, invocation_id: String },
}

pub fn validate(kind: &str, event: &str, observation: &Observation) -> Result<()> {
    match (kind, event, observation) {
        ("artifact", "available", Observation::File { path })
        | ("resource", "released", Observation::FileLock { path }) => {
            ensure!(valid_path(path), "Invalid observation path");
        }
        ("dependency", "recovered", Observation::Http { url }) => {
            ensure!(valid_http_url(url), "Invalid HTTP observation URL");
        }
        (
            "job",
            "success" | "failure" | "completed",
            Observation::Systemd {
                unit,
                invocation_id,
            },
        ) => {
            ensure!(
                valid_unit(unit),
                "Systemd observation requires a fixed .service unit name"
            );
            ensure!(
                is_hex_id(invocation_id),
                "Systemd invocation_id must be exactly 32 hexadecimal characters"
            );
        }
        (_, "cancelled", Observation::Systemd { .. }) => {
            bail!("Systemd status cannot prove that a job was cancelled");
        }
        _ => bail!("Observation does not match the subscription kind and event"),
    }
    Ok(())
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.as_bytes().contains(&0)
        && Path::new(path).is_absolute()
        && !path.split('/').any(|part| matches!(part, "." | ".."))
}

fn valid_http_url(url: &str) -> bool {
    if url.is_empty()
        || url.len() > 8192
        || url.contains('#')
        || url.contains('\\')
        || url.chars().any(char::is_control)
    {
        return false;
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty() && !authority.contains('@') && !url.chars().any(char::is_whitespace)
}

fn valid_unit(unit: &str) -> bool {
    unit.len() <= 255
        && unit.ends_with(".service")
        && !unit.starts_with('-')
        && !unit.starts_with('.')
        && unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b))
}

fn is_hex_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS observers (
            subscription_id TEXT PRIMARY KEY NOT NULL,
            config TEXT NOT NULL,
            next_poll INTEGER NOT NULL DEFAULT 0,
            last_check INTEGER,
            last_reason TEXT,
            last_outcome TEXT
        );
        CREATE INDEX IF NOT EXISTS observers_due ON observers(next_poll);",
    )?;
    Ok(())
}

pub fn attach(db: &Connection, id: &str, observation: &Observation) -> Result<()> {
    initialize(db)?;
    db.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<()> {
        let subscription = db
            .query_row(
                "SELECT kind,event,state FROM subscriptions WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .context("Subscription not found")?;
        validate(&subscription.0, &subscription.1, observation)?;
        let existing: Option<String> = db
            .query_row(
                "SELECT config FROM observers WHERE subscription_id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        let config = serde_json::to_string(observation)?;
        if let Some(existing) = existing {
            let existing: Observation = serde_json::from_str(&existing)
                .context("Stored observer configuration is invalid")?;
            ensure!(
                existing == *observation,
                "Observer configuration is immutable"
            );
            return Ok(());
        }
        ensure!(
            subscription.2 == "waiting",
            "Cannot attach an observer to a consumed subscription"
        );
        db.execute(
            "INSERT INTO observers(subscription_id,config) VALUES(?1,?2)",
            params![id, config],
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            db.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

pub fn status(db: &Connection) -> Result<Value> {
    initialize(db)?;
    let mut statement = db.prepare(
        "SELECT o.subscription_id,o.config,o.next_poll,o.last_check,o.last_reason,o.last_outcome,
                s.kind,s.event,s.resource,s.state
         FROM observers o JOIN subscriptions s ON s.id=o.subscription_id
         ORDER BY o.subscription_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Value::Array(rows.into_iter().map(|r| json!({
        "subscription_id":r.0,"config":serde_json::from_str::<Value>(&r.1).unwrap_or(Value::Null),
        "next_poll":r.2,"last_check":r.3,"last_error":r.4,"last_outcome":r.5,
        "kind":r.6,"event":r.7,"resource":r.8,"state":r.9
    })).collect()))
}

#[derive(Clone)]
struct DueObserver {
    id: String,
    config: String,
}

#[derive(Clone)]
struct Subscription {
    kind: String,
    repo: String,
    resource: String,
    event: String,
}

enum Probe {
    Pending(&'static str),
    Ready {
        outcome: &'static str,
        evidence: Value,
    },
}

fn claim_due(db: &Connection, now: i64) -> Result<Vec<DueObserver>> {
    db.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<Vec<DueObserver>> {
        let due = {
            let mut statement = db.prepare(
                "SELECT o.subscription_id,o.config FROM observers o
                 JOIN subscriptions s ON s.id=o.subscription_id
                 WHERE s.state='waiting' AND o.next_poll<=?1
                 ORDER BY o.next_poll,o.subscription_id",
            )?;
            statement
                .query_map([now], |row| {
                    Ok(DueObserver {
                        id: row.get(0)?,
                        config: row.get(1)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for observer in &due {
            db.execute(
                "UPDATE observers SET next_poll=?2 WHERE subscription_id=?1",
                params![observer.id, now.saturating_add(POLL_SECONDS)],
            )?;
        }
        Ok(due)
    })();
    match result {
        Ok(due) => {
            db.execute_batch("COMMIT")?;
            Ok(due)
        }
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn waiting_subscription(db: &Connection, id: &str) -> Result<Option<Subscription>> {
    Ok(db
        .query_row(
            "SELECT kind,repo,resource,event FROM subscriptions WHERE id=?1 AND state='waiting'",
            [id],
            |row| {
                Ok(Subscription {
                    kind: row.get(0)?,
                    repo: row.get(1)?,
                    resource: row.get(2)?,
                    event: row.get(3)?,
                })
            },
        )
        .optional()?)
}

fn record_check(
    db: &Connection,
    id: &str,
    now: i64,
    reason: &'static str,
    outcome: Option<&str>,
) -> Result<()> {
    db.execute(
        "UPDATE observers SET last_check=?2,last_reason=?3,last_outcome=COALESCE(?4,last_outcome) WHERE subscription_id=?1",
        params![id, now, reason, outcome],
    )?;
    Ok(())
}

pub fn tick(db: &Connection, codex: &Path) -> Result<Value> {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .context("Current time is outside the supported range")?;
    tick_at(db, codex, now, |observation, event, codex| {
        probe_observation(observation, event, codex, &mut |command, timeout| {
            crate::manager::run(command, timeout)
        })
    })
}

fn tick_at(
    db: &Connection,
    codex: &Path,
    now: i64,
    mut probe: impl FnMut(&Observation, &str, &Path) -> Probe,
) -> Result<Value> {
    initialize(db)?;
    let due = claim_due(db, now)?;
    let (mut checked, mut published, mut pending, mut errors) = (0u64, 0u64, 0u64, 0u64);
    for item in due {
        let Some(subscription) = waiting_subscription(db, &item.id)? else {
            continue;
        };
        let observation: Observation = match serde_json::from_str(&item.config) {
            Ok(value) => value,
            Err(_) => {
                record_check(db, &item.id, now, "invalid_configuration", None)?;
                crate::observability::emit(
                    "poll.observer.configuration",
                    "error",
                    "invalid_configuration",
                    None,
                    Duration::ZERO,
                    1,
                );
                errors += 1;
                continue;
            }
        };
        if validate(&subscription.kind, &subscription.event, &observation).is_err() {
            record_check(db, &item.id, now, "invalid_configuration", None)?;
            crate::observability::emit(
                "poll.observer.configuration",
                "error",
                "invalid_configuration",
                None,
                Duration::ZERO,
                1,
            );
            errors += 1;
            continue;
        }
        let started = Instant::now();
        checked += 1;
        let result = probe(&observation, &subscription.event, codex);
        let operation = operation(&observation);
        match result {
            Probe::Pending(reason) => {
                record_check(db, &item.id, now, reason, None)?;
                crate::observability::emit(
                    operation,
                    "pending",
                    reason,
                    None,
                    started.elapsed(),
                    1,
                );
                pending += 1;
            }
            Probe::Ready { outcome, evidence } => {
                let source = source_json(&observation, &subscription, outcome, evidence)?;
                match crate::subscriptions::publish_observation(db, &item.id, outcome, &source) {
                    Ok(count) if count > 0 => {
                        record_check(db, &item.id, now, "published", Some(outcome))?;
                        crate::observability::emit(
                            operation,
                            "published",
                            "",
                            None,
                            started.elapsed(),
                            count as u64,
                        );
                        published += count as u64;
                    }
                    Ok(_) => {
                        record_check(db, &item.id, now, "already_consumed", None)?;
                        crate::observability::emit(
                            operation,
                            "skipped",
                            "already_consumed",
                            None,
                            started.elapsed(),
                            0,
                        );
                        pending += 1;
                    }
                    Err(_) => {
                        record_check(db, &item.id, now, "publish_error", None)?;
                        crate::observability::emit(
                            operation,
                            "error",
                            "publish_error",
                            None,
                            started.elapsed(),
                            1,
                        );
                        errors += 1;
                    }
                }
            }
        }
    }
    Ok(json!({"checked":checked,"published":published,"pending":pending,"errors":errors}))
}

fn source_json(
    observation: &Observation,
    subscription: &Subscription,
    outcome: &str,
    evidence: Value,
) -> Result<Value> {
    let config = serde_json::to_value(observation)?;
    let mut source = config
        .as_object()
        .context("Observer config must serialize as an object")?
        .clone();
    source.insert("kind".into(), json!(subscription.kind));
    source.insert("repo".into(), json!(subscription.repo));
    source.insert("resource".into(), json!(subscription.resource));
    source.insert("event".into(), json!(subscription.event));
    source.insert("outcome".into(), json!(outcome));
    source.insert("observation".into(), config);
    source.insert("evidence".into(), evidence);
    Ok(Value::Object(source))
}

fn operation(observation: &Observation) -> &'static str {
    match observation {
        Observation::File { .. } => "poll.observer.file",
        Observation::Http { .. } => "poll.observer.http",
        Observation::FileLock { .. } => "poll.observer.file_lock",
        Observation::Systemd { .. } => "poll.observer.systemd",
    }
}

fn probe_observation(
    observation: &Observation,
    event: &str,
    codex: &Path,
    runner: &mut dyn FnMut(&mut Command, Duration) -> Result<Output>,
) -> Probe {
    match observation {
        Observation::File { path } => match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => Probe::Ready {
                outcome: "available",
                evidence: json!({"regular_file":true,"size_bytes":metadata.len()}),
            },
            Ok(_) => Probe::Pending("not_regular_file"),
            Err(error) => Probe::Pending(io_reason(&error, "metadata_error")),
        },
        Observation::Http { url } => probe_http(url, runner),
        Observation::FileLock { path } => probe_file_lock(Path::new(path)),
        Observation::Systemd {
            unit,
            invocation_id,
        } => probe_systemd(unit, invocation_id, event, codex, runner),
    }
}

fn probe_http(
    url: &str,
    runner: &mut dyn FnMut(&mut Command, Duration) -> Result<Output>,
) -> Probe {
    let mut command = Command::new("curl");
    command.args([
        "-q",
        "--silent",
        "--proto",
        "=http,https",
        "--connect-timeout",
        "5",
        "--max-time",
        "10",
        "--max-filesize",
        "1048576",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--",
        url,
    ]);
    let output = match runner(&mut command, Duration::from_secs(12)) {
        Ok(output) => output,
        Err(error) => {
            return Probe::Pending(if timed_out(&error) {
                "http_timeout"
            } else {
                "http_request_error"
            });
        }
    };
    if !output.status.success() {
        return Probe::Pending("http_request_error");
    }
    let status = std::str::from_utf8(&output.stdout).ok().and_then(|raw| {
        (raw.len() == 3 && raw.bytes().all(|b| b.is_ascii_digit()))
            .then(|| raw.parse::<u16>().ok())
            .flatten()
    });
    match status {
        Some(status @ 200..=299) => Probe::Ready {
            outcome: "recovered",
            evidence: json!({"http_status":status}),
        },
        Some(_) => Probe::Pending("http_status_not_success"),
        None => Probe::Pending("http_response_invalid"),
    }
}

fn probe_file_lock(path: &Path) -> Probe {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return Probe::Pending(io_reason(&error, "metadata_error")),
    };
    if before.file_type().is_symlink() || !before.is_file() {
        return Probe::Pending("unsafe_file");
    }
    if before.uid() != unsafe { libc::geteuid() } {
        return Probe::Pending("owner_mismatch");
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => return Probe::Pending(io_reason(&error, "open_error")),
    };
    let opened = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return Probe::Pending("metadata_error"),
    };
    if !opened.is_file()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
    {
        return Probe::Pending("unsafe_file");
    }
    let fd = file.as_raw_fd();
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        return Probe::Pending(if error.kind() == std::io::ErrorKind::WouldBlock {
            "lock_held"
        } else {
            "lock_error"
        });
    }
    if unsafe { libc::flock(fd, libc::LOCK_UN) } != 0 {
        return Probe::Pending("unlock_error");
    }
    Probe::Ready {
        outcome: "released",
        evidence: json!({"exclusive_lock_acquired_and_released":true}),
    }
}

fn probe_systemd(
    unit: &str,
    expected_id: &str,
    event: &str,
    _codex: &Path,
    runner: &mut dyn FnMut(&mut Command, Duration) -> Result<Output>,
) -> Probe {
    let mut command = Command::new("systemctl");
    command.args([
        "--user",
        "show",
        "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,InvocationID",
        unit,
    ]);
    let output = match runner(&mut command, Duration::from_secs(10)) {
        Ok(output) => output,
        Err(error) => {
            return Probe::Pending(if timed_out(&error) {
                "systemd_timeout"
            } else {
                "systemd_query_error"
            });
        }
    };
    if !output.status.success() || output.stdout.len() > 4096 {
        return Probe::Pending("systemd_query_error");
    }
    let Some(raw) = std::str::from_utf8(&output.stdout).ok() else {
        return Probe::Pending("systemd_response_invalid");
    };
    let mut properties: [Option<&str>; 6] = [None; 6];
    for line in raw.lines() {
        let Some((key, value)) = line.strip_suffix('\r').unwrap_or(line).split_once('=') else {
            return Probe::Pending("systemd_response_invalid");
        };
        let slot = match key {
            "ActiveState" => &mut properties[0],
            "SubState" => &mut properties[1],
            "Result" => &mut properties[2],
            "ExecMainCode" => &mut properties[3],
            "ExecMainStatus" => &mut properties[4],
            "InvocationID" => &mut properties[5],
            _ => return Probe::Pending("systemd_response_invalid"),
        };
        if slot.replace(value).is_some() {
            return Probe::Pending("systemd_response_invalid");
        }
    }
    if properties.iter().any(Option::is_none) {
        return Probe::Pending("systemd_response_invalid");
    }
    let (active, sub, result, code, status, invocation) = (
        properties[0].unwrap(),
        properties[1].unwrap(),
        properties[2].unwrap(),
        properties[3].unwrap().parse::<i32>().ok(),
        properties[4].unwrap().parse::<i32>().ok(),
        properties[5].unwrap(),
    );
    if !is_hex_id(invocation) || !invocation.eq_ignore_ascii_case(expected_id) {
        return Probe::Pending("generation_mismatch");
    }
    if !["active", "inactive", "failed"].contains(&active)
        || sub.is_empty()
        || sub.len() > 64
        || !sub
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        || result.is_empty()
        || result.len() > 64
        || !result
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Probe::Pending("systemd_response_invalid");
    }
    let (Some(code), Some(status)) = (code, status) else {
        return Probe::Pending("systemd_response_invalid");
    };
    let exited = code == libc::CLD_EXITED;
    let success = result == "success"
        && exited
        && status == 0
        && ((active == "inactive" && matches!(sub, "dead" | "exited"))
            || (active == "active" && sub == "exited"));
    let failed = active == "failed" && sub == "failed" && result != "success";
    let completed = success || (active == "failed" && sub == "failed" && result != "success");
    let outcome = match event {
        "success" if success => Some("success"),
        "failure" if failed => Some("failure"),
        "completed" if completed => Some("completed"),
        _ => None,
    };
    let Some(outcome) = outcome else {
        return Probe::Pending(if success || failed || completed {
            "outcome_mismatch"
        } else {
            "not_terminal"
        });
    };
    Probe::Ready {
        outcome,
        evidence: json!({
            "active_state":active,"sub_state":sub,"result":result,
            "exec_main_code":code,"exec_main_status":status,"invocation_id":invocation
        }),
    }
}

fn io_reason(error: &std::io::Error, fallback: &'static str) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        _ if error.raw_os_error() == Some(libc::ELOOP) => "unsafe_file",
        _ => fallback,
    }
}

fn timed_out(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string() == "Command timed out; inspect state before retrying")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscriptions::{self, DeliveryConfig};
    use std::os::unix::{fs::symlink, io::AsRawFd, process::ExitStatusExt};

    const THREAD: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    fn output(code: u8, stdout: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(i32::from(code) << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: b"sensitive child diagnostic".to_vec(),
        }
    }

    #[test]
    fn observation_json_is_tagged_snake_case_and_rejects_unknown_fields() {
        let observation: Observation =
            serde_json::from_str(r#"{"type":"file","path":"/tmp/artifact"}"#).unwrap();
        assert_eq!(
            observation,
            Observation::File {
                path: "/tmp/artifact".into()
            }
        );
        assert_eq!(
            serde_json::to_value(&observation).unwrap(),
            json!({"type":"file","path":"/tmp/artifact"})
        );
        assert!(
            serde_json::from_str::<Observation>(r#"{"type":"file","path":"/tmp/a","extra":1}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<Observation>(r#"{"type":"file_lock","path":"/tmp/a"}"#).is_ok()
        );
    }

    #[test]
    fn validate_binds_each_observer_to_its_exact_event_and_safe_shape() {
        assert!(
            validate(
                "artifact",
                "available",
                &Observation::File {
                    path: "/tmp/a".into()
                }
            )
            .is_ok()
        );
        assert!(
            validate(
                "artifact",
                "available",
                &Observation::File {
                    path: "relative/a".into()
                }
            )
            .is_err()
        );
        assert!(
            validate(
                "artifact",
                "available",
                &Observation::File {
                    path: "/tmp/../a".into()
                }
            )
            .is_err()
        );
        assert!(
            validate(
                "artifact",
                "available",
                &Observation::File {
                    path: "/tmp/./a".into()
                }
            )
            .is_err()
        );
        for url in [
            "https://user:pass@example.test/",
            "https://example.test/#fragment",
            "file:///tmp/a",
        ] {
            assert!(
                validate(
                    "dependency",
                    "recovered",
                    &Observation::Http { url: url.into() }
                )
                .is_err()
            );
        }
        assert!(
            validate(
                "dependency",
                "recovered",
                &Observation::Http {
                    url: "https://example.test/health".into()
                }
            )
            .is_ok()
        );
        assert!(
            validate(
                "job",
                "cancelled",
                &Observation::Systemd {
                    unit: "task.service".into(),
                    invocation_id: "a".repeat(32)
                }
            )
            .is_err()
        );
        assert!(
            validate(
                "job",
                "success",
                &Observation::Systemd {
                    unit: "task.service".into(),
                    invocation_id: "a".repeat(32)
                }
            )
            .is_ok()
        );
        assert!(
            validate(
                "job",
                "success",
                &Observation::Systemd {
                    unit: "--user.service".into(),
                    invocation_id: "a".repeat(32)
                }
            )
            .is_err()
        );
    }

    #[test]
    fn file_observer_accepts_only_a_regular_nonsymlink_path_without_reading_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        fs::write(&path, b"contents are not inspected").unwrap();
        assert!(matches!(
            probe_observation(
                &Observation::File {
                    path: path.to_string_lossy().into_owned()
                },
                "available",
                Path::new("/codex"),
                &mut |_, _| unreachable!(),
            ),
            Probe::Ready {
                outcome: "available",
                ..
            }
        ));
        assert!(matches!(
            probe_observation(
                &Observation::File {
                    path: dir.path().to_string_lossy().into_owned()
                },
                "available",
                Path::new("/codex"),
                &mut |_, _| unreachable!(),
            ),
            Probe::Pending("not_regular_file")
        ));
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(matches!(
            probe_observation(
                &Observation::File {
                    path: link.to_string_lossy().into_owned()
                },
                "available",
                Path::new("/codex"),
                &mut |_, _| unreachable!(),
            ),
            Probe::Pending("not_regular_file")
        ));
    }

    #[test]
    fn file_lock_probe_never_creates_or_follows_links_and_reports_real_flock_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        fs::write(&path, b"").unwrap();
        assert!(matches!(
            probe_file_lock(&path),
            Probe::Ready {
                outcome: "released",
                ..
            }
        ));
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(matches!(
            probe_file_lock(&path),
            Probe::Pending("lock_held")
        ));
        unsafe {
            libc::flock(held.as_raw_fd(), libc::LOCK_UN);
        }
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(matches!(
            probe_file_lock(&link),
            Probe::Pending("unsafe_file")
        ));
        assert!(!dir.path().join("missing").exists());
        assert!(matches!(
            probe_file_lock(&dir.path().join("missing")),
            Probe::Pending("not_found")
        ));
        assert!(!dir.path().join("missing").exists());
    }

    #[test]
    fn systemd_properties_are_keyed_and_invocation_generation_must_match() {
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let observation = Observation::Systemd {
            unit: "task.service".into(),
            invocation_id: id.into(),
        };
        let permuted = "ExecMainStatus=0\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nResult=success\nActiveState=inactive\nExecMainCode=1\nSubState=dead\n";
        let mut runner = |command: &mut Command, timeout: Duration| {
            assert_eq!(command.get_program(), "systemctl");
            assert_eq!(timeout, Duration::from_secs(10));
            let args: Vec<_> = command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            assert!(args.contains(&"--user".into()));
            assert!(!args.contains(&"--value".into()));
            Ok(output(0, permuted))
        };
        assert!(matches!(
            probe_observation(&observation, "success", Path::new("/codex"), &mut runner),
            Probe::Ready {
                outcome: "success",
                ..
            }
        ));

        let mismatch = permuted.replace(id, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let mut runner = |_: &mut Command, _| Ok(output(0, &mismatch));
        assert!(matches!(
            probe_observation(&observation, "success", Path::new("/codex"), &mut runner),
            Probe::Pending("generation_mismatch")
        ));
    }

    #[test]
    fn systemd_failure_uses_authoritative_failed_result_for_signal_and_timeout() {
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let observation = Observation::Systemd {
            unit: "task.service".into(),
            invocation_id: id.into(),
        };
        for (result, code, status) in [("signal", 2, 15), ("timeout", 2, 9)] {
            let response = format!(
                "ActiveState=failed\nSubState=failed\nResult={result}\nExecMainCode={code}\nExecMainStatus={status}\nInvocationID={id}\n"
            );
            let mut runner = |_: &mut Command, _| Ok(output(0, &response));
            assert!(matches!(
                probe_observation(&observation, "failure", Path::new("/codex"), &mut runner),
                Probe::Ready {
                    outcome: "failure",
                    ..
                }
            ));
        }
        assert!(validate("job", "cancelled", &observation).is_err());
    }

    #[test]
    fn http_network_failure_retries_at_interval_then_publishes_once_and_stops_polling() {
        let db = Connection::open_in_memory().unwrap();
        subscriptions::initialize(&db).unwrap();
        initialize(&db).unwrap();
        let required = vec![
            "evidence.http_status".to_string(),
            "evidence.missing".to_string(),
        ];
        let id = subscriptions::subscribe_with_delivery(
            &db,
            "dependency",
            "provider",
            "dep-1",
            "recovered",
            THREAD,
            DeliveryConfig {
                message_template: Some("{{source.url}}"),
                execution: None,
                required_source: Some(&required),
                progress_timeout_secs: None,
                ..Default::default()
            },
        )
        .unwrap();
        let observation = Observation::Http {
            url: "https://example.test/health".into(),
        };
        attach(&db, &id, &observation).unwrap();
        attach(&db, &id, &observation).unwrap();
        assert!(
            attach(
                &db,
                &id,
                &Observation::Http {
                    url: "https://other.test/".into()
                }
            )
            .is_err()
        );

        let mut calls = 0;
        let mut poll = |db: &Connection, at| {
            tick_at(db, Path::new("/codex"), at, |obs, event, codex| {
                probe_observation(obs, event, codex, &mut |command, timeout| {
                    calls += 1;
                    assert_eq!(command.get_program(), "curl");
                    assert_eq!(timeout, Duration::from_secs(12));
                    let args: Vec<_> = command
                        .get_args()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect();
                    assert_eq!(args[0], "-q");
                    assert!(
                        args.windows(2)
                            .any(|pair| pair[0] == "--connect-timeout" && pair[1] == "5")
                    );
                    assert!(
                        args.windows(2)
                            .any(|pair| pair[0] == "--max-filesize" && pair[1] == "1048576")
                    );
                    assert!(
                        args.windows(2)
                            .any(|pair| pair[0] == "--max-time" && pair[1] == "10")
                    );
                    assert!(!args.iter().any(|arg| arg == "--location" || arg == "-L"));
                    match calls {
                        1 => Ok(output(7, "")),
                        2 => Ok(output(0, "503")),
                        _ => Ok(output(0, "204")),
                    }
                })
            })
        };
        assert_eq!(poll(&db, 100).unwrap()["pending"], 1);
        assert_eq!(poll(&db, 159).unwrap()["checked"], 0);
        assert_eq!(poll(&db, 160).unwrap()["pending"], 1);
        assert_eq!(poll(&db, 220).unwrap()["published"], 1);
        assert_eq!(poll(&db, 280).unwrap()["checked"], 0);
        assert_eq!(calls, 3);
        let row = subscriptions::status(&db).unwrap();
        assert_eq!(row[0]["state"], "ready");
        assert_eq!(row[0]["outcome"], "recovered");
        assert_eq!(row[0]["missing_source"], json!(["evidence.missing"]));
        let source: Value = db
            .query_row(
                "SELECT source_json FROM subscriptions WHERE id=?1",
                [&id],
                |row| row.get::<_, String>(0),
            )
            .map(|raw| serde_json::from_str(&raw).unwrap())
            .unwrap();
        assert_eq!(source["url"], "https://example.test/health");
        assert_eq!(source["observation"]["type"], "http");
        assert_eq!(source["evidence"]["http_status"], 204);
        let observer = status(&db).unwrap();
        assert_eq!(observer[0]["last_check"], 220);
        assert_eq!(observer[0]["last_error"], "published");
        assert_eq!(observer[0]["last_outcome"], "recovered");
    }
}
