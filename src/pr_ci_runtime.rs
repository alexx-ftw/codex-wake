//! Bounded `gh` transport and durable PR-CI polling/dispatch adapter.
//!
//! The host application supplies its existing delivery function so this
//! module does not create a second chat-send path or alter exact-run waits.

use crate::pr_ci::{self, ApiResponse, Delivery, PollReport};
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use std::{error::Error, fmt, io::Read};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "pr_ci_legacy.rs"]
mod legacy;

const GH_TIMEOUT: Duration = Duration::from_secs(20);
const GH_OUTPUT_LIMIT: u64 = 1_048_576;
const GH_STDERR_LIMIT: u64 = 65_536;
const DISPATCH_BATCH: usize = 1;
// Each recovery may make a bounded read and resume RPC (15 s each). Process
// one destination per pass so a backlog cannot overrun a worker's deadline.
const WAKE_RETRY_BATCH: i64 = 1;
const WAKE_RETRY_MAX_MS: i64 = 900_000;
/// Longer than Wake's normal delivery command timeout; expiry means uncertain.
const DELIVERY_LEASE: Duration = Duration::from_secs(180);
/// The lease exceeds the bounded queue RPC; the kernel lock also fences a
/// suspended writer whose RPC outlives that deadline.
pub const NATIVE_WAKE_INTENT_LEASE_MS: i64 = 180_000;

/// Acquire one of a fixed set of database-local locks. Locks are never unlinked:
/// removing a held lock could allow a second process to lock a different inode.
pub fn try_native_wake_lock(db: &Connection, client_id: &str) -> Result<Option<std::fs::File>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let id = uuid::Uuid::parse_str(client_id)?;
    let path = match db.path() {
        Some(path) if !path.is_empty() => {
            let mut path = std::fs::canonicalize(path)?.into_os_string();
            path.push(format!(".native-wake-lock-{:02x}", id.as_bytes()[0] % 32));
            PathBuf::from(path)
        }
        _ => std::env::temp_dir().join(format!(
            "codex-wake-memory-lock-{}-{}-{:02x}",
            std::process::id(),
            memory_lock_namespace(db)?,
            id.as_bytes()[0] % 32
        )),
    };
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error.into());
    }
    Ok(Some(lock))
}

fn memory_lock_namespace(db: &Connection) -> Result<String> {
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let namespace = memory_lock_namespace(&tx)?;
        tx.commit()?;
        return Ok(namespace);
    }
    db.execute_batch("CREATE TABLE IF NOT EXISTS pr_ci_schema_migrations(name TEXT PRIMARY KEY)")?;
    let existing: Option<String> = db.query_row(
        "SELECT name FROM pr_ci_schema_migrations WHERE name LIKE 'memory_lock_namespace:%' LIMIT 1",
        [], |row| row.get(0),
    ).optional()?;
    let name = match existing {
        Some(name) => name,
        None => {
            let name = format!("memory_lock_namespace:{}", uuid::Uuid::new_v4());
            db.execute(
                "INSERT INTO pr_ci_schema_migrations(name) VALUES(?1)",
                [&name],
            )?;
            name
        }
    };
    let namespace = name
        .strip_prefix("memory_lock_namespace:")
        .context("Invalid memory lock namespace")?;
    Ok(uuid::Uuid::parse_str(namespace)?.to_string())
}

#[derive(Debug)]
struct BeforeSendFailure {
    error: anyhow::Error,
    intent_token: Option<String>,
}

#[derive(Debug)]
struct ExistingNativeWakeIntent;

impl fmt::Display for ExistingNativeWakeIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("A previous native delivery remains uncertain")
    }
}
impl Error for ExistingNativeWakeIntent {}

pub fn native_wake_intent_exists(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ExistingNativeWakeIntent>().is_some()
}

impl fmt::Display for BeforeSendFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Delivery preparation failed before queue submission: {}",
            self.error
        )
    }
}

impl Error for BeforeSendFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.error.as_ref())
    }
}

/// Mark an error from delivery preparation that occurs before any queue request.
pub fn before_send_failure(error: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(BeforeSendFailure {
        error,
        intent_token: None,
    })
}

pub fn before_send_failure_with_intent(error: anyhow::Error, token: &str) -> anyhow::Error {
    anyhow::Error::new(BeforeSendFailure {
        error,
        intent_token: Some(token.to_owned()),
    })
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DispatchReport {
    pub claimed: usize,
    pub accepted: usize,
    pub retried_before_send: usize,
    pub uncertain: usize,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct NativeWakeIds {
    client_ids: Vec<String>,
    unattributed: bool,
    generation: String,
    #[serde(default)]
    intents: Vec<NativeWakeIntent>,
}

/// Exact origin of a native queue request whose acceptance may be uncertain.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind")]
pub enum NativeWakeOrigin {
    Pr {
        id: String,
    },
    Ci {
        id: i64,
    },
    Rule {
        rule_id: String,
        event_header: String,
        comment_id: String,
    },
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct NativeWakeIntent {
    client_id: String,
    token: String,
    lease_until_ms: i64,
    origin: NativeWakeOrigin,
}

fn native_wake_ids(raw: Option<&str>) -> Result<NativeWakeIds> {
    let ids: NativeWakeIds = match raw {
        Some(raw) => serde_json::from_str(raw)?,
        None => NativeWakeIds {
            unattributed: true,
            ..NativeWakeIds::default()
        },
    };
    if raw.is_some() {
        uuid::Uuid::parse_str(&ids.generation)?;
    }
    for id in &ids.client_ids {
        ensure!(
            uuid::Uuid::parse_str(id)?.to_string() == *id,
            "Invalid stored native recovery message identity"
        );
    }
    for intent in &ids.intents {
        ensure!(
            uuid::Uuid::parse_str(&intent.client_id)?.to_string() == intent.client_id,
            "Invalid pending native message identity"
        );
        uuid::Uuid::parse_str(&intent.token)?;
    }
    Ok(ids)
}

/// Persist the intent before invoking the queue. Recovery may inspect it only
/// after its lease; absence from the queue is never evidence of rejection.
pub fn begin_native_wake_intent(
    db: &Connection,
    thread: &str,
    client_id: &str,
    origin: NativeWakeOrigin,
    lease_until_ms: i64,
) -> Result<String> {
    let thread = uuid::Uuid::parse_str(thread)?.to_string();
    let client_id = uuid::Uuid::parse_str(client_id)?.to_string();
    initialize_native_wake_recovery(db)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let token = begin_native_wake_intent(&tx, &thread, &client_id, origin, lease_until_ms)?;
        tx.commit()?;
        return Ok(token);
    }
    let raw: Option<Option<String>> = db
        .query_row(
            "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
            [&thread],
            |row| row.get(0),
        )
        .optional()?;
    let mut ids = match raw {
        Some(raw) => native_wake_ids(raw.as_deref())?,
        None => NativeWakeIds::default(),
    };
    if ids
        .intents
        .iter()
        .any(|intent| intent.client_id == client_id)
    {
        return Err(ExistingNativeWakeIntent.into());
    }
    let token = uuid::Uuid::new_v4().to_string();
    ids.intents.push(NativeWakeIntent {
        client_id,
        token: token.clone(),
        lease_until_ms,
        origin,
    });
    ids.generation = uuid::Uuid::new_v4().to_string();
    let raw = serde_json::to_string(&ids)?;
    db.execute("INSERT INTO native_wake_recovery(thread,reason,next_attempt_ms,backoff_ms,revision,client_ids_json)
        VALUES(?1,'native_queue_resume_warning',?2,1000,1,?3)
        ON CONFLICT(thread) DO UPDATE SET next_attempt_ms=min(next_attempt_ms,excluded.next_attempt_ms),
          revision=revision+1,client_ids_json=excluded.client_ids_json",
        rusqlite::params![thread, lease_until_ms, raw])?;
    Ok(token)
}

/// Remove a completed or definitively unsent intent using its original token.
pub fn finish_native_wake_intent(db: &Connection, thread: &str, token: &str) -> Result<()> {
    initialize_native_wake_recovery(db)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        finish_native_wake_intent(&tx, thread, token)?;
        tx.commit()?;
        return Ok(());
    }
    let raw: Option<Option<String>> = db
        .query_row(
            "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
            [thread],
            |row| row.get(0),
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(());
    };
    let mut ids = native_wake_ids(raw.as_deref())?;
    ids.intents.retain(|intent| intent.token != token);
    if ids.intents.is_empty() && ids.client_ids.is_empty() && !ids.unattributed {
        db.execute("DELETE FROM native_wake_recovery WHERE thread=?1", [thread])?;
    } else {
        ids.generation = uuid::Uuid::new_v4().to_string();
        db.execute("UPDATE native_wake_recovery SET client_ids_json=?2,revision=revision+1 WHERE thread=?1",
            rusqlite::params![thread, serde_json::to_string(&ids)?])?;
    }
    Ok(())
}

/// Persist the exact accepted message identity, never its input. Multiple warnings
/// accumulate obligations; an unattributed legacy warning cannot be cleared implicitly.
pub fn record_native_wake_recovery(
    db: &Connection,
    thread: &str,
    reason: &str,
    client_id: &str,
) -> Result<bool> {
    record_native_wake_recovery_with_id(db, thread, reason, Some(client_id))
}

/// Retain a warning from a delivery path that cannot provide a verified message ID.
/// Known IDs on the same row can still be started, but cannot resolve this warning.
pub fn record_unattributed_native_wake_recovery(
    db: &Connection,
    thread: &str,
    reason: &str,
) -> Result<bool> {
    record_native_wake_recovery_with_id(db, thread, reason, None)
}

fn record_native_wake_recovery_with_id(
    db: &Connection,
    thread: &str,
    reason: &str,
    client_id: Option<&str>,
) -> Result<bool> {
    ensure!(
        reason == "native_queue_resume_warning",
        "Unsupported native wake recovery reason"
    );
    let thread = uuid::Uuid::parse_str(thread)?.to_string();
    let client_id = client_id
        .map(|id| uuid::Uuid::parse_str(id).map(|id| id.to_string()))
        .transpose()?;
    initialize_native_wake_recovery(db)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let recorded = record_native_wake_recovery_in(&tx, &thread, reason, client_id.as_deref())?;
        tx.commit()?;
        Ok(recorded)
    } else {
        record_native_wake_recovery_in(db, &thread, reason, client_id.as_deref())
    }
}

fn record_native_wake_recovery_in(
    db: &Connection,
    thread: &str,
    reason: &str,
    client_id: Option<&str>,
) -> Result<bool> {
    let existing: Option<Option<String>> = db
        .query_row(
            "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
            [thread],
            |row| row.get(0),
        )
        .optional()?;
    let mut ids = match existing {
        Some(raw) => native_wake_ids(raw.as_deref())?,
        None => NativeWakeIds::default(),
    };
    if let Some(client_id) = client_id {
        ids.client_ids.push(client_id.to_owned());
    } else {
        ids.unattributed = true;
    }
    ids.client_ids.sort();
    ids.client_ids.dedup();
    ids.generation = uuid::Uuid::new_v4().to_string();
    let raw = serde_json::to_string(&ids)?;
    Ok(db.execute(
        "INSERT INTO native_wake_recovery
         (thread,reason,next_attempt_ms,backoff_ms,revision,client_ids_json)
         VALUES(?1,?2,0,1000,1,?3)
         ON CONFLICT(thread) DO UPDATE SET reason=excluded.reason,next_attempt_ms=0,
             backoff_ms=1000,revision=native_wake_recovery.revision+1,
             client_ids_json=excluded.client_ids_json",
        rusqlite::params![thread, reason, raw],
    )? != 0)
}

/// Retry only the native wake operation for accepted queue entries. Failed
/// wakes remain durable and use bounded backoff. The callback must confirm every
/// supplied ID without resending input; unattributed legacy warnings stay durable.
pub fn recover_native_wake_retries<F>(db: &Connection, now_ms: i64, mut wake: F) -> Result<usize>
where
    F: FnMut(&str, &[String]) -> Result<()>,
{
    initialize_native_wake_recovery(db)?;
    let tx = rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
    let due = {
        let mut statement = tx.prepare(
            "SELECT thread,client_ids_json,revision,backoff_ms FROM native_wake_recovery
             WHERE next_attempt_ms<=?1 ORDER BY next_attempt_ms,thread",
        )?;
        statement
            .query_map([now_ms], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|row| match native_wake_ids(row.1.as_deref()) {
                Ok(ids)
                    if ids
                        .client_ids
                        .iter()
                        .any(|id| !ids.intents.iter().any(|intent| &intent.client_id == id)) =>
                {
                    Some(Ok(row))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .take(WAKE_RETRY_BATCH as usize)
            .collect::<Result<Vec<_>>>()?
    };
    for (thread, _, revision, backoff) in &due {
        tx.execute(
            "UPDATE native_wake_recovery SET next_attempt_ms=?1,backoff_ms=?2
             WHERE thread=?3 AND revision=?4",
            rusqlite::params![
                now_ms.saturating_add(*backoff),
                backoff.saturating_mul(2).min(WAKE_RETRY_MAX_MS),
                thread,
                revision
            ],
        )?;
    }
    tx.commit()?;

    let mut recovered = 0;
    for (thread, raw, revision, _) in due {
        let mut ids = native_wake_ids(raw.as_deref())?;
        let eligible: Vec<String> = ids
            .client_ids
            .iter()
            .filter(|id| !ids.intents.iter().any(|intent| &intent.client_id == *id))
            .cloned()
            .collect();
        if !eligible.is_empty() && wake(&thread, &eligible).is_ok() {
            ids.client_ids.retain(|id| !eligible.contains(id));
            if ids.client_ids.is_empty() && ids.intents.is_empty() && !ids.unattributed {
                let changed = db.execute(
                    "DELETE FROM native_wake_recovery WHERE thread=?1 AND revision=?2 AND client_ids_json=?3",
                    rusqlite::params![thread, revision, raw],
                )?;
                if !ids.unattributed {
                    recovered += changed;
                }
            } else {
                ids.generation = uuid::Uuid::new_v4().to_string();
                let changed = db.execute(
                    "UPDATE native_wake_recovery SET client_ids_json=?4,revision=revision+1
                     WHERE thread=?1 AND revision=?2 AND client_ids_json=?3",
                    rusqlite::params![thread, revision, raw, serde_json::to_string(&ids)?],
                )?;
                if !ids.unattributed {
                    recovered += changed;
                }
            }
        }
    }
    Ok(recovered)
}

/// Reconcile expired pre-send intents using exact queue or execution evidence.
/// A missing identity is never treated as a rejection and is not resent.
pub fn recover_native_wake_intents<F>(db: &Connection, now_ms: i64, mut wake: F) -> Result<usize>
where
    F: FnMut(&str, &[String]) -> Result<()>,
{
    initialize_native_wake_recovery(db)?;
    let rows: Vec<(String, Option<String>)> = db.prepare(
        "SELECT thread,client_ids_json FROM native_wake_recovery ORDER BY next_attempt_ms,thread"
    )?.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
    let mut due = Vec::new();
    for (thread, raw) in rows {
        let ids = native_wake_ids(raw.as_deref())?;
        due.extend(
            ids.intents
                .into_iter()
                .filter(|intent| intent.lease_until_ms <= now_ms)
                .map(|intent| (thread.clone(), intent)),
        );
    }
    due.sort_by_key(|(_, intent)| intent.lease_until_ms);
    for (thread, intent) in due.into_iter().take(2) {
        let Some(_lock) = try_native_wake_lock(db, &intent.client_id)? else {
            defer_native_wake_intent(db, &thread, &intent.token, now_ms.saturating_add(1_000))?;
            continue;
        };
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let current: Option<Option<String>> = tx
            .query_row(
                "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
                [&thread],
                |row| row.get(0),
            )
            .optional()?;
        let Some(current) = current else {
            tx.commit()?;
            continue;
        };
        let mut ids = native_wake_ids(current.as_deref())?;
        let Some(entry) = ids
            .intents
            .iter_mut()
            .find(|entry| entry.token == intent.token && entry.lease_until_ms <= now_ms)
        else {
            tx.commit()?;
            continue;
        };
        let claimed_until = now_ms.saturating_add(NATIVE_WAKE_INTENT_LEASE_MS);
        entry.lease_until_ms = claimed_until;
        ids.generation = uuid::Uuid::new_v4().to_string();
        tx.execute("UPDATE native_wake_recovery SET client_ids_json=?2,revision=revision+1 WHERE thread=?1",
            rusqlite::params![thread, serde_json::to_string(&ids)?])?;
        tx.commit()?;
        if wake(&thread, std::slice::from_ref(&intent.client_id)).is_err() {
            continue;
        }
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let current: Option<Option<String>> = tx
            .query_row(
                "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
                [&thread],
                |row| row.get(0),
            )
            .optional()?;
        let Some(current) = current else {
            tx.commit()?;
            continue;
        };
        let mut ids = native_wake_ids(current.as_deref())?;
        if !ids
            .intents
            .iter()
            .any(|entry| entry.token == intent.token && entry.lease_until_ms == claimed_until)
        {
            tx.commit()?;
            continue;
        }
        let reconciled = match &intent.origin {
            NativeWakeOrigin::Pr { id } => {
                tx.execute("UPDATE automatic_pr_notifications SET state='queued' WHERE id=?1 AND thread=?2 AND state IN ('pending','sending','needs_attention')", rusqlite::params![id,thread])? != 0
                    || tx.query_row("SELECT EXISTS(SELECT 1 FROM automatic_pr_notifications WHERE id=?1 AND thread=?2 AND state='queued')", rusqlite::params![id,thread], |row| row.get(0))?
            }
            NativeWakeOrigin::Ci { id } => {
                tx.execute("UPDATE pr_ci_deliveries SET state='delivered',lease_until_ms=NULL WHERE id=?1 AND thread=?2 AND state IN ('pending','claimed','needs_attention')", rusqlite::params![id,thread])? != 0
                    || tx.query_row("SELECT EXISTS(SELECT 1 FROM pr_ci_deliveries WHERE id=?1 AND thread=?2 AND state='delivered')", rusqlite::params![id,thread], |row| row.get(0))?
            }
            NativeWakeOrigin::Rule {
                rule_id,
                event_header,
                comment_id,
            } => {
                tx.execute("UPDATE rule_deliveries SET state='queued',reason=NULL,updated=CURRENT_TIMESTAMP WHERE rule_id=?1 AND event_header=?2 AND comment_id=?3 AND thread_id=?4 AND state IN ('ready','creating','needs_attention')", rusqlite::params![rule_id,event_header,comment_id,thread])? != 0
                    || tx.query_row("SELECT EXISTS(SELECT 1 FROM rule_deliveries WHERE rule_id=?1 AND event_header=?2 AND comment_id=?3 AND thread_id=?4 AND state='queued')", rusqlite::params![rule_id,event_header,comment_id,thread], |row| row.get(0))?
            }
        };
        if !reconciled {
            tx.commit()?;
            continue;
        }
        ids.intents.retain(|entry| entry.token != intent.token);
        if ids.intents.is_empty() && ids.client_ids.is_empty() && !ids.unattributed {
            tx.execute(
                "DELETE FROM native_wake_recovery WHERE thread=?1",
                [&thread],
            )?;
        } else {
            ids.generation = uuid::Uuid::new_v4().to_string();
            tx.execute("UPDATE native_wake_recovery SET client_ids_json=?2,revision=revision+1 WHERE thread=?1",
                rusqlite::params![thread, serde_json::to_string(&ids)?])?;
        }
        tx.commit()?;
        return Ok(1);
    }
    Ok(0)
}

fn defer_native_wake_intent(db: &Connection, thread: &str, token: &str, until: i64) -> Result<()> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let raw: Option<Option<String>> = tx
        .query_row(
            "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
            [thread],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(raw) = raw {
        let mut ids = native_wake_ids(raw.as_deref())?;
        if let Some(intent) = ids.intents.iter_mut().find(|intent| intent.token == token) {
            intent.lease_until_ms = intent.lease_until_ms.max(until);
            ids.generation = uuid::Uuid::new_v4().to_string();
            tx.execute("UPDATE native_wake_recovery SET client_ids_json=?2,revision=revision+1 WHERE thread=?1",
                rusqlite::params![thread, serde_json::to_string(&ids)?])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn initialize_native_wake_recovery(db: &Connection) -> Result<()> {
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        initialize_native_wake_recovery_in(&tx)?;
        tx.commit()?;
        Ok(())
    } else {
        initialize_native_wake_recovery_in(db)
    }
}

fn initialize_native_wake_recovery_in(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS native_wake_recovery (
            thread TEXT PRIMARY KEY, reason TEXT NOT NULL,
            next_attempt_ms INTEGER NOT NULL DEFAULT 0,
            backoff_ms INTEGER NOT NULL DEFAULT 1000,
            revision INTEGER NOT NULL DEFAULT 1,
            client_ids_json TEXT
        );",
    )?;
    let columns = {
        let mut statement = db.prepare("PRAGMA table_info(native_wake_recovery)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if !columns.iter().any(|column| column == "client_ids_json") {
        db.execute_batch("ALTER TABLE native_wake_recovery ADD COLUMN client_ids_json TEXT")?;
    }
    Ok(())
}

/// Authenticated, read-only GitHub REST transport using the user's `gh` auth.
/// Only the GET route forms generated by `pr_ci::poll` are accepted. Execution,
/// output size and captured diagnostics are bounded; no token is read or logged.
/// On Unix, timeout cleanup kills the `gh` process group. Descendants that call
/// `setsid` (or otherwise leave that group) may continue running, but nonblocking
/// pipe readers observe cancellation, so they cannot keep this call blocked
/// indefinitely after the deadline; cleanup can add brief latency.
pub fn gh_api(gh_executable: &Path, route: &str) -> Result<ApiResponse> {
    gh_api_with_timeout(gh_executable, route, GH_TIMEOUT)
}

fn gh_response_filter(route: &str) -> Result<&'static str> {
    let mut segments = route
        .strip_prefix("/repos/")
        .context("Unsupported GitHub API route")?
        .splitn(3, '/');
    let owner = segments.next().unwrap_or_default();
    let repo = segments.next().unwrap_or_default();
    let endpoint = segments.next().context("Missing GitHub API endpoint")?;
    ensure!(
        !owner.is_empty() && !repo.is_empty(),
        "Invalid repository path"
    );
    let filter = if endpoint.starts_with("pulls/") {
        ". as $pr | {number, state, closed_at, base:{repo:{full_name:$pr.base.repo.full_name}}, head:{sha:$pr.head.sha, repo:{full_name:$pr.head.repo.full_name}}}"
    } else if endpoint.starts_with("actions/runs?") {
        ". as $r | {total_count:$r.total_count, workflow_runs:[$r.workflow_runs[] | {id, run_attempt, head_sha, event, status, conclusion, head_repository:(.head_repository | if . == null then null else {id,name,full_name,html_url} end), pull_requests:[.pull_requests[]? | {id, number, url, html_url, title, head:{sha:.head.sha, ref:.head.ref, repo:(.head.repo | if . == null then null else {id,name,url} end)}}]}]}"
    } else if endpoint.starts_with("actions/runs/") && endpoint.contains("/attempts/") {
        ". as $r | {id, run_attempt, head_sha, event, status, conclusion, head_repository:(.head_repository | if . == null then null else {id,name,full_name,html_url} end), pull_requests:[.pull_requests[]? | {id, number, url, html_url, title, head:{sha:.head.sha, ref:.head.ref, repo:(.head.repo | if . == null then null else {id,name,url} end)}}]}"
    } else {
        bail!("Unsupported GitHub API route")
    };
    Ok(filter)
}

fn gh_api_with_timeout(
    gh_executable: &Path,
    route: &str,
    timeout: Duration,
) -> Result<ApiResponse> {
    gh_api_with_probe(gh_executable, route, timeout, false)
}

fn gh_api_with_probe(
    gh_executable: &Path,
    route: &str,
    timeout: Duration,
    deny_group: bool,
) -> Result<ApiResponse> {
    let deadline = Instant::now() + timeout;
    let filter = gh_response_filter(route)?;
    ensure!(
        route.starts_with("/repos/")
            && !route.contains("..")
            && !route.contains('#')
            && !route.contains(' '),
        "Invalid GitHub API route"
    );

    let mut command = Command::new(gh_executable);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(target_os = "linux")]
    command
        .arg("api")
        .arg("--jq")
        .arg(filter)
        .arg(route)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let started = spawn_with_group_handle(
        &mut command,
        false,
        deny_group,
        deadline.saturating_duration_since(Instant::now()),
    );
    let (mut child, group_handle) = match started {
        Ok(started) => started,
        Err(error) => {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if error
                .get_ref()
                .is_some_and(|inner| inner.is::<GroupProbeUnsupported>())
            {
                return legacy::gh_api(gh_executable, route, filter, deadline);
            }
            #[cfg(target_os = "linux")]
            if error
                .get_ref()
                .is_some_and(|inner| inner.is::<GroupProbeCleanupUncertain>())
            {
                return Err(error.into());
            }
            return Err(error)
                .with_context(|| format!("Start {} with safe cleanup", gh_executable.display()));
        }
    };

    let exceeded = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().context("Capture gh stdout")?;
    let stderr = child.stderr.take().context("Capture gh stderr")?;
    #[cfg(unix)]
    if let Err(error) = set_pipe_nonblocking(&stdout).and_then(|()| set_pipe_nonblocking(&stderr)) {
        let cleanup = terminate_process_group(&mut child, &group_handle);
        if cleanup.is_err() {
            return Err(
                anyhow::Error::new(crate::pr_ci::ProcessCleanupUncertain).context(format!(
                    "Set GitHub CLI pipes nonblocking: {error}; cleanup: {cleanup:?}"
                )),
            );
        }
        return Err(error).context(format!(
            "Set GitHub CLI pipes nonblocking; cleanup: {cleanup:?}"
        ));
    }
    let stdout_exceeded = Arc::clone(&exceeded);
    let stderr_exceeded = Arc::clone(&exceeded);
    let stdout_cancelled = Arc::clone(&cancelled);
    let stderr_cancelled = Arc::clone(&cancelled);
    let mut stdout_reader = Some(thread::spawn(move || {
        read_pipe(stdout, GH_OUTPUT_LIMIT, stdout_exceeded, stdout_cancelled)
    }));
    let mut stderr_reader = Some(thread::spawn(move || {
        read_pipe(stderr, GH_STDERR_LIMIT, stderr_exceeded, stderr_cancelled)
    }));
    let mut output = None;
    let mut diagnostics = None;
    let mut status = None;
    let mut timed_out = false;
    let mut cleanup_error = None;
    loop {
        if stdout_reader
            .as_ref()
            .is_some_and(|reader| reader.is_finished())
        {
            output = Some(stdout_reader.take().unwrap().join());
        }
        if stderr_reader
            .as_ref()
            .is_some_and(|reader| reader.is_finished())
        {
            diagnostics = Some(stderr_reader.take().unwrap().join());
        }
        if exceeded.load(Ordering::Relaxed) {
            break;
        }
        // Join both readers before reaping, so their output-limit decisions are final.
        if output.is_some() && diagnostics.is_some() {
            match child.try_wait() {
                Ok(Some(exit)) => {
                    status = Some(exit);
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    cancelled.store(true, Ordering::Relaxed);
                    let cleanup = terminate_process_group(&mut child, &group_handle);
                    if cleanup.is_err() {
                        return Err(anyhow::Error::new(crate::pr_ci::ProcessCleanupUncertain)
                            .context(format!(
                                "Check gh process: {error}; process group cleanup: {cleanup:?}"
                            )));
                    }
                    bail!("Check gh process: {error}; process group cleanup: {cleanup:?}");
                }
            }
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if timed_out || exceeded.load(Ordering::Relaxed) {
        cancelled.store(true, Ordering::Relaxed);
        cleanup_error = terminate_process_group(&mut child, &group_handle).err();
    }
    let output = output.unwrap_or_else(|| stdout_reader.unwrap().join());
    let diagnostics = diagnostics.unwrap_or_else(|| stderr_reader.unwrap().join());
    let (output, diagnostics) = finish_pipe_reads(output, diagnostics, cleanup_error, timed_out)?;
    if timed_out {
        bail!("GitHub CLI request timed out")
    }
    ensure!(
        !exceeded.load(Ordering::Relaxed),
        "GitHub CLI output exceeded its size limit"
    );
    let status = status.context("GitHub CLI exited without a status")?;
    if !status.success() {
        let message = String::from_utf8_lossy(&diagnostics);
        bail!("GitHub CLI request failed: {}", message.trim());
    }
    let body: Value = serde_json::from_slice(&output).context("Decode GitHub API response")?;
    Ok(ApiResponse { status: 200, body })
}

fn finish_pipe_reads(
    output: thread::Result<Result<Vec<u8>>>,
    diagnostics: thread::Result<Result<Vec<u8>>>,
    cleanup_error: Option<std::io::Error>,
    timed_out: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if let Some(error) = cleanup_error {
        let reason = if timed_out {
            "timed out"
        } else {
            "output exceeded its size limit"
        };
        return Err(
            anyhow::Error::new(crate::pr_ci::ProcessCleanupUncertain).context(format!(
                "GitHub CLI request {reason}; process group cleanup incomplete: {error}"
            )),
        );
    }
    let output = output.map_err(|_| anyhow::anyhow!("gh stdout reader panicked"))??;
    let diagnostics = diagnostics.map_err(|_| anyhow::anyhow!("gh stderr reader panicked"))??;
    Ok((output, diagnostics))
}

#[cfg(target_os = "linux")]
type GroupHandle = Option<std::os::fd::OwnedFd>;
#[cfg(not(target_os = "linux"))]
type GroupHandle = ();

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct GroupProbeUnsupported;

#[cfg(target_os = "linux")]
impl fmt::Display for GroupProbeUnsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pidfd process-group signaling is unavailable")
    }
}

#[cfg(target_os = "linux")]
impl Error for GroupProbeUnsupported {}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct GroupProbeCleanupUncertain(String);

#[cfg(target_os = "linux")]
impl fmt::Display for GroupProbeCleanupUncertain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(target_os = "linux")]
impl Error for GroupProbeCleanupUncertain {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&crate::pr_ci::ProcessCleanupUncertain)
    }
}

#[cfg(target_os = "linux")]
enum GroupReceipt {
    Handle(std::os::fd::OwnedFd),
    ProbeUnsupported(std::os::fd::OwnedFd),
    ProbeTimedOut(std::os::fd::OwnedFd),
    ProbeTransferFailed(std::os::fd::OwnedFd, libc::c_int),
    Invalid,
}

#[cfg(target_os = "linux")]
const UNSUPPORTED_GROUP_PROBE: u8 = 0xa5;
#[cfg(target_os = "linux")]
const PROBE_REQUEST: i32 = 1;
#[cfg(target_os = "linux")]
const PROBE_OPENED: i32 = 2;
#[cfg(target_os = "linux")]
const PROBE_CONFIRMED: i32 = 3;
#[cfg(target_os = "linux")]
const PROBE_ACCEPTED: i32 = 4;
#[cfg(target_os = "linux")]
const PROBE_ABANDONED: i32 = 5;

#[cfg(target_os = "linux")]
struct ProbeShared {
    phase: std::sync::atomic::AtomicI32,
    pid: std::sync::atomic::AtomicI32,
    error: std::sync::atomic::AtomicI32,
    spawn_finished: AtomicBool,
}

#[cfg(target_os = "linux")]
struct ProbeMapping(usize);

#[cfg(target_os = "linux")]
impl ProbeMapping {
    fn new() -> std::io::Result<Arc<Self>> {
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<ProbeShared>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        unsafe {
            address.cast::<ProbeShared>().write(ProbeShared {
                phase: std::sync::atomic::AtomicI32::new(0),
                pid: std::sync::atomic::AtomicI32::new(0),
                error: std::sync::atomic::AtomicI32::new(0),
                spawn_finished: AtomicBool::new(true),
            });
        }
        Ok(Arc::new(Self(address as usize)))
    }

    fn state(&self) -> &ProbeShared {
        // The Arc owns this mapping until both the receiver and Command release it.
        unsafe { &*(self.0 as *const ProbeShared) }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProbeMapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.0 as *mut libc::c_void,
                std::mem::size_of::<ProbeShared>(),
            )
        };
    }
}

#[cfg(target_os = "linux")]
struct SpawnFinished(Arc<ProbeMapping>);

#[cfg(target_os = "linux")]
impl Drop for SpawnFinished {
    fn drop(&mut self) {
        self.0.state().spawn_finished.store(true, Ordering::Release);
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
static REAP_GROUP_PROBE_IN_TEST: AtomicBool = AtomicBool::new(false);

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
static TRUNCATE_GROUP_PROBE_IN_TEST: AtomicBool = AtomicBool::new(false);

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
static PAUSE_AFTER_EMPTY_PROBE_POLL: AtomicBool = AtomicBool::new(false);

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
static DELAY_GROUP_PROBE_IN_TEST: AtomicBool = AtomicBool::new(false);

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
static TRACK_RECEIVER_IN_TEST: AtomicBool = AtomicBool::new(false);
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
static RECEIVER_STARTED_IN_TEST: AtomicBool = AtomicBool::new(false);
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
static RECEIVER_FINISHED_IN_TEST: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
unsafe fn exit_unsupported_group_probe(
    socket: libc::c_int,
    pidfd: libc::c_int,
    handshake_ms: libc::c_int,
    shared: &ProbeShared,
) -> ! {
    // Do not return an error through Command's pre-exec pipe: its internal
    // wait can panic if an embedder has already reaped the child. Transfer the
    // exact pidfd instead, then let the parent use waitid(P_PIDFD).
    unsafe {
        #[cfg(all(test, target_arch = "x86_64"))]
        if DELAY_GROUP_PROBE_IN_TEST.load(Ordering::Relaxed) {
            libc::poll(std::ptr::null_mut(), 0, 100);
        }
        let mut marker = UNSUPPORTED_GROUP_PROBE;
        let mut iov = libc::iovec {
            iov_base: (&mut marker as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0_usize; 8];
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), pidfd);
        let sent = libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL);
        let send_error = if sent == 1 {
            0
        } else if sent < 0 {
            *libc::__errno_location()
        } else {
            libc::EIO
        };
        shared.pid.store(libc::getpid(), Ordering::Relaxed);
        shared.error.store(send_error, Ordering::Relaxed);
        if shared
            .phase
            .compare_exchange(0, PROBE_REQUEST, Ordering::Release, Ordering::Acquire)
            .is_ok()
        {
            let mut start: libc::timespec = std::mem::zeroed();
            if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut start) == 0 {
                let end_ms = i128::from(start.tv_sec) * 1000
                    + i128::from(start.tv_nsec) / 1_000_000
                    + i128::from(handshake_ms);
                loop {
                    let phase = shared.phase.load(Ordering::Acquire);
                    if phase == PROBE_OPENED {
                        let _ = shared.phase.compare_exchange(
                            PROBE_OPENED,
                            PROBE_CONFIRMED,
                            Ordering::Release,
                            Ordering::Acquire,
                        );
                        break;
                    }
                    if phase == PROBE_ACCEPTED || phase == PROBE_ABANDONED {
                        break;
                    }
                    let mut now: libc::timespec = std::mem::zeroed();
                    if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) != 0
                        || i128::from(now.tv_sec) * 1000 + i128::from(now.tv_nsec) / 1_000_000
                            >= end_ms
                    {
                        break;
                    }
                    libc::poll(std::ptr::null_mut(), 0, 2);
                }
            }
        }
        libc::close(pidfd);
        libc::_exit(0)
    }
}

#[cfg(target_os = "linux")]
unsafe fn discard_received_rights(message: &libc::msghdr) {
    // recvmsg installs every descriptor that fits, even when MSG_CTRUNC is set.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let base = u64::from(libc::CMSG_LEN(0));
                let length = (*header).cmsg_len as u64;
                if length >= base {
                    let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                    for index in 0..(length - base) / std::mem::size_of::<libc::c_int>() as u64 {
                        libc::close(std::ptr::read_unaligned(data.add(index as usize)));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
}

// The child opens its own pidfd before exec, so even an external reaper cannot
// race its acquisition. SCM_RIGHTS keeps that exact descriptor alive in transit.
#[cfg(target_os = "linux")]
fn prepare_group_handle(
    command: &mut Command,
    deny_pidfd: bool,
    deny_group: bool,
    handshake_ms: libc::c_int,
) -> Option<(
    std::os::fd::OwnedFd,
    std::os::fd::OwnedFd,
    Arc<ProbeMapping>,
)> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    let shared = ProbeMapping::new().ok()?;
    let child_shared = Arc::clone(&shared);
    let mut sockets = [-1; 2];
    // SAFETY: sockets is writable and a successful socketpair returns two owned descriptors.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            sockets.as_mut_ptr(),
        )
    } != 0
    {
        return None;
    }
    // Command may replace descriptors 0..=2 when configuring stdio.
    for index in 0..2 {
        if sockets[index] <= 2 {
            let duplicate = unsafe { libc::fcntl(sockets[index], libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                unsafe {
                    libc::close(sockets[0]);
                    libc::close(sockets[1]);
                }
                return None;
            }
            unsafe {
                libc::close(sockets[index]);
            }
            sockets[index] = duplicate;
        }
    }
    let (receiver, sender) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(sockets[0]),
            std::os::fd::OwnedFd::from_raw_fd(sockets[1]),
        )
    };
    let (receive_fd, send_fd) = (receiver.as_raw_fd(), sender.as_raw_fd());
    // SAFETY: this closure uses only async-signal-safe syscalls after fork and no heap allocations.
    unsafe {
        command.pre_exec(move || {
            libc::close(receive_fd);
            if deny_pidfd {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            let pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as libc::c_int;
            if pidfd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setpgid(0, 0) != 0 {
                let error = std::io::Error::last_os_error();
                libc::close(pidfd);
                return Err(error);
            }
            if deny_group {
                exit_unsupported_group_probe(send_fd, pidfd, handshake_ms, child_shared.state());
            }
            if libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                0,
                std::ptr::null::<libc::siginfo_t>(),
                1_u32 << 2,
            ) != 0
            {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINVAL) {
                    exit_unsupported_group_probe(
                        send_fd,
                        pidfd,
                        handshake_ms,
                        child_shared.state(),
                    );
                }
                libc::close(pidfd);
                return Err(error);
            }
            {
                let mut byte = 0_u8;
                let mut iov = libc::iovec {
                    iov_base: (&mut byte as *mut u8).cast(),
                    iov_len: 1,
                };
                let mut control = [0_usize; 8];
                let mut message: libc::msghdr = std::mem::zeroed();
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen =
                    libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&message);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), pidfd);
                let sent = libc::sendmsg(send_fd, &message, libc::MSG_NOSIGNAL);
                libc::close(pidfd);
                if sent != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut pollfd = libc::pollfd {
                    fd: send_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                if libc::poll(&mut pollfd, 1, handshake_ms) != 1 {
                    return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
                }
                if libc::recv(send_fd, (&mut byte as *mut u8).cast(), 1, 0) != 1 || byte != 1 {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
            }
            Ok(())
        });
    }
    Some((receiver, sender, shared))
}

#[cfg(target_os = "linux")]
fn receive_group_handle(
    receiver: std::os::fd::OwnedFd,
    handshake_ms: libc::c_int,
    shared: Arc<ProbeMapping>,
) -> GroupReceipt {
    use std::os::fd::{AsRawFd, FromRawFd};
    #[cfg(all(test, target_arch = "x86_64"))]
    struct ReceiverFinished(bool);
    #[cfg(all(test, target_arch = "x86_64"))]
    impl Drop for ReceiverFinished {
        fn drop(&mut self) {
            if self.0 {
                RECEIVER_FINISHED_IN_TEST.store(true, Ordering::Release);
            }
        }
    }
    #[cfg(all(test, target_arch = "x86_64"))]
    let _finished = {
        let tracked = TRACK_RECEIVER_IN_TEST.load(Ordering::Acquire);
        if tracked {
            RECEIVER_STARTED_IN_TEST.store(true, Ordering::Release);
        }
        ReceiverFinished(tracked)
    };
    let deadline = Instant::now() + Duration::from_millis(handshake_ms.max(0) as u64);
    let state = shared.state();
    let mut invalid_message = false;
    loop {
        // Inspect a queued SCM_RIGHTS message before using shared recovery.
        let mut pollfd = libc::pollfd {
            fd: receiver.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 0) };
        #[cfg(all(test, target_arch = "x86_64"))]
        if ready == 0 && PAUSE_AFTER_EMPTY_PROBE_POLL.swap(false, Ordering::AcqRel) {
            while state.phase.load(Ordering::Acquire) != PROBE_REQUEST && Instant::now() < deadline
            {
                thread::yield_now();
            }
        }
        if ready == 1 && pollfd.revents & libc::POLLIN != 0 {
            let mut byte = 0_u8;
            let mut iov = libc::iovec {
                iov_base: (&mut byte as *mut u8).cast(),
                iov_len: 1,
            };
            let mut control = [0_usize; 8];
            unsafe {
                let mut message: libc::msghdr = std::mem::zeroed();
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = std::mem::size_of_val(&control) as _;
                #[cfg(target_arch = "x86_64")]
                #[cfg(test)]
                if TRUNCATE_GROUP_PROBE_IN_TEST.load(Ordering::Relaxed) {
                    message.msg_controllen = 0;
                }
                let received =
                    libc::recvmsg(receiver.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC);
                if received >= 0 {
                    let cmsg = libc::CMSG_FIRSTHDR(&message);
                    let valid = received == 1
                        && message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0
                        && !cmsg.is_null()
                        && (byte == 0 || byte == UNSUPPORTED_GROUP_PROBE)
                        && (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                        && (*cmsg).cmsg_len as u64
                            == u64::from(libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32))
                        && libc::CMSG_NXTHDR(&message, cmsg).is_null();
                    if valid {
                        let fd = std::os::fd::OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                            libc::CMSG_DATA(cmsg).cast::<libc::c_int>(),
                        ));
                        if byte == UNSUPPORTED_GROUP_PROBE {
                            state.phase.store(PROBE_ACCEPTED, Ordering::Release);
                            return if Instant::now() >= deadline {
                                GroupReceipt::ProbeTimedOut(fd)
                            } else {
                                GroupReceipt::ProbeUnsupported(fd)
                            };
                        }
                        let ack = 1_u8;
                        if libc::send(
                            receiver.as_raw_fd(),
                            (&ack as *const u8).cast(),
                            1,
                            libc::MSG_NOSIGNAL,
                        ) == 1
                        {
                            return GroupReceipt::Handle(fd);
                        }
                        state.phase.store(PROBE_ABANDONED, Ordering::Release);
                        return GroupReceipt::Invalid;
                    }
                    discard_received_rights(&message);
                    invalid_message = true;
                } else {
                    let error = std::io::Error::last_os_error();
                    if !matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) || Instant::now() >= deadline
                    {
                        // A queued datagram cannot be consumed (for example,
                        // recvmsg is denied by policy). Recover using the
                        // child's separately confirmed pidfd instead.
                        invalid_message = true;
                    } else {
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        if state.phase.load(Ordering::Acquire) == PROBE_REQUEST {
            let pid = state.pid.load(Ordering::Relaxed);
            let send_error = state.error.load(Ordering::Relaxed);
            // The sender can enqueue SCM_RIGHTS immediately after the empty
            // poll above. A successful send must be read before recovery is
            // interpreted as a transfer failure.
            if send_error == 0 && !invalid_message {
                continue;
            }
            if pid <= 0 || send_error < 0 {
                state.phase.store(PROBE_ABANDONED, Ordering::Release);
                return GroupReceipt::Invalid;
            }
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as libc::c_int };
            if raw < 0 {
                state.phase.store(PROBE_ABANDONED, Ordering::Release);
                return GroupReceipt::Invalid;
            }
            // Opening by PID is only provisional: the child must confirm after
            // this open, while still alive, before the descriptor is used.
            let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            let recovery_deadline = deadline.max(Instant::now() + Duration::from_millis(100));
            if state
                .phase
                .compare_exchange(
                    PROBE_REQUEST,
                    PROBE_OPENED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return GroupReceipt::Invalid;
            }
            loop {
                let phase = state.phase.load(Ordering::Acquire);
                if phase == PROBE_CONFIRMED {
                    return GroupReceipt::ProbeTransferFailed(
                        fd,
                        if send_error == 0 {
                            libc::EIO
                        } else {
                            send_error
                        },
                    );
                }
                if Instant::now() >= recovery_deadline {
                    let previous = state.phase.swap(PROBE_ABANDONED, Ordering::AcqRel);
                    if previous == PROBE_CONFIRMED {
                        return GroupReceipt::ProbeTransferFailed(
                            fd,
                            if send_error == 0 {
                                libc::EIO
                            } else {
                                send_error
                            },
                        );
                    }
                    return GroupReceipt::Invalid;
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() && state.spawn_finished.load(Ordering::Acquire) {
            // The child may have sent its final message after the poll above
            // but before Command::spawn returned; drain it before giving up.
            if state.phase.load(Ordering::Acquire) == PROBE_REQUEST
                || !invalid_message
                    && unsafe { libc::poll(&mut pollfd, 1, 0) } == 1
                    && pollfd.revents & libc::POLLIN != 0
            {
                continue;
            }
            state.phase.store(PROBE_ABANDONED, Ordering::Release);
            return GroupReceipt::Invalid;
        }
        let wait = if remaining.is_zero() {
            Duration::from_millis(5)
        } else {
            remaining.min(Duration::from_millis(5))
        };
        unsafe { libc::poll(&mut pollfd, 1, wait.as_millis().max(1) as libc::c_int) };
    }
}

#[cfg(target_os = "linux")]
fn reap_group_probe(fd: &std::os::fd::OwnedFd, deadline: Instant) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                fd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG,
            )
        };
        if result == 0 && info.si_signo == libc::SIGCHLD {
            return Ok(());
        }
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(std::io::Error::other(GroupProbeCleanupUncertain(format!(
                    "probe waitid failed: {error}; process cleanup uncertain"
                ))));
            }
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(GroupProbeCleanupUncertain(
                "probe waitid timed out; process cleanup uncertain".into(),
            )));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(target_os = "linux")]
fn spawn_with_group_handle(
    command: &mut Command,
    deny_pidfd: bool,
    deny_group: bool,
    remaining: Duration,
) -> std::io::Result<(std::process::Child, GroupHandle)> {
    if remaining.is_zero() {
        return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
    }
    let deadline = Instant::now() + remaining;
    let handshake_ms = remaining.as_millis().clamp(1, 1000) as libc::c_int;
    let (receiver, sender, shared) =
        prepare_group_handle(command, deny_pidfd, deny_group, handshake_ms)
            .ok_or_else(|| std::io::Error::other("cannot prepare safe process cleanup"))?;
    shared
        .state()
        .spawn_finished
        .store(false, Ordering::Release);
    let spawn_finished = SpawnFinished(Arc::clone(&shared));
    let receiver_shared = Arc::clone(&shared);
    let receiver_thread = thread::Builder::new()
        .spawn(move || receive_group_handle(receiver, handshake_ms, receiver_shared))?;
    let child = command.spawn();
    drop(sender);
    drop(spawn_finished);
    let handle = receiver_thread.join().map_err(|_| {
        std::io::Error::other(GroupProbeCleanupUncertain(
            "pidfd receiver panicked; process cleanup uncertain".into(),
        ))
    })?;
    let child = child?;
    match handle {
        GroupReceipt::Handle(handle) => Ok((child, Some(handle))),
        GroupReceipt::ProbeUnsupported(handle) => {
            #[cfg(all(test, target_arch = "x86_64"))]
            if REAP_GROUP_PROBE_IN_TEST.load(Ordering::Relaxed) {
                let mut status = 0;
                unsafe { libc::waitpid(child.id() as libc::pid_t, &mut status, 0) };
            }
            let result = reap_group_probe(&handle, deadline);
            drop(child);
            result?;
            if cfg!(target_arch = "x86_64") {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    GroupProbeUnsupported,
                ))
            } else {
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        }
        GroupReceipt::ProbeTimedOut(handle) => {
            #[cfg(all(test, target_arch = "x86_64"))]
            if REAP_GROUP_PROBE_IN_TEST.load(Ordering::Relaxed) {
                let mut status = 0;
                unsafe { libc::waitpid(child.id() as libc::pid_t, &mut status, 0) };
            }
            let result = reap_group_probe(&handle, Instant::now() + Duration::from_millis(100));
            drop(child);
            result?;
            Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT))
        }
        GroupReceipt::ProbeTransferFailed(handle, send_error) => {
            #[cfg(all(test, target_arch = "x86_64"))]
            if REAP_GROUP_PROBE_IN_TEST.load(Ordering::Relaxed) {
                let mut status = 0;
                unsafe { libc::waitpid(child.id() as libc::pid_t, &mut status, 0) };
            }
            let result = reap_group_probe(
                &handle,
                deadline.max(Instant::now() + Duration::from_millis(100)),
            );
            drop(child);
            result?;
            Err(std::io::Error::from_raw_os_error(send_error))
        }
        GroupReceipt::Invalid => Err(std::io::Error::other(GroupProbeCleanupUncertain(
            "pidfd transfer failed; probe child may remain unreaped; process cleanup uncertain"
                .into(),
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
fn spawn_with_group_handle(
    _: &mut Command,
    _: bool,
    _: bool,
    _: Duration,
) -> std::io::Result<(std::process::Child, GroupHandle)> {
    Err(std::io::Error::other(
        "safe process cleanup unavailable on this platform",
    ))
}

fn terminate_process_group(
    child: &mut std::process::Child,
    handle: &GroupHandle,
) -> std::io::Result<()> {
    terminate_process_group_with(child, handle, false)
}

fn terminate_process_group_with(
    child: &mut std::process::Child,
    handle: &GroupHandle,
    reject_group_signal: bool,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = handle
            .as_ref()
            .ok_or_else(|| std::io::Error::other("process group pidfd unavailable"))?;
        // SAFETY: the descriptor was opened by the child before exec and held by the parent.
        let group_error = if reject_group_signal {
            Some(std::io::Error::from_raw_os_error(libc::EINVAL))
        } else if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                1_u32 << 2,
            )
        } != 0
        {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        if let Some(ref group_error) = group_error {
            // A failed group signal must still address the exact leader, never
            // its reusable numeric PID. Group cleanup remains uncertain.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err(std::io::Error::other(format!(
                    "group signal failed: {}; leader signal failed: {}",
                    group_error,
                    std::io::Error::last_os_error()
                )));
            }
        }
        // SIGKILL is asynchronous and an uninterruptible child may not exit.
        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return match group_error {
                        Some(error) => Err(error),
                        None => Ok(()),
                    };
                }
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                    return match group_error {
                        Some(error) => Err(error),
                        None => Ok(()),
                    };
                }
                Err(error) => return Err(error),
                Ok(None) if Instant::now() >= deadline => {
                    return Err(std::io::Error::other(
                        "child did not exit after group signal",
                    ));
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (child, handle, reject_group_signal);
        Err(std::io::Error::other(
            "safe process group cleanup unavailable",
        ))
    }
}

#[cfg(unix)]
fn set_pipe_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let descriptor = pipe.as_raw_fd();
    // SAFETY: fcntl reads/updates flags on the live child pipe descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same live descriptor; preserve its flags and add O_NONBLOCK.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn read_pipe<R: Read>(
    mut reader: R,
    limit: u64,
    exceeded: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024) as usize);
    let mut chunk = [0_u8; 8192];
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Ok(bytes);
        }
        let count = match reader.read(&mut chunk) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() as u64 + count as u64 > limit {
            exceeded.store(true, Ordering::Relaxed);
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

/// Advance one due tracker through the bounded `gh` transport. Call from a
/// dedicated background worker, not Wake's synchronous poll/dispatch cycle.
pub fn poll_one_with_gh(db: &Connection, gh_executable: &Path, now_ms: i64) -> Result<PollReport> {
    pr_ci::poll(db, now_ms, |route| gh_api(gh_executable, route))
}

/// Start one bounded tracker step on Tokio's blocking pool with its own
/// database connection. Dropping the returned handle detaches the step; keep
/// it when the caller needs the outcome. The database must be file-backed.
pub fn spawn_poll_one_with_gh(
    database_path: PathBuf,
    gh_executable: PathBuf,
    now_ms: i64,
) -> tokio::task::JoinHandle<Result<PollReport>> {
    tokio::task::spawn_blocking(move || {
        let db = open_database(database_path)?;
        poll_one_with_gh(&db, &gh_executable, now_ms)
    })
}

/// Adapter for an already-authenticated GitHub transport. This lets the host
/// reuse its established transport without coupling CI state to exact waits.
pub fn poll_one_with_transport<F>(db: &Connection, now_ms: i64, fetch: F) -> Result<PollReport>
where
    F: FnMut(&str) -> Result<ApiResponse>,
{
    pr_ci::poll(db, now_ms, fetch)
}

/// Background variant for a transport supplied by the host. It can reuse the
/// existing authenticated GitHub client while keeping network waits off Wake's
/// current poll and dispatch threads.
pub fn spawn_poll_one_with_transport<F>(
    database_path: PathBuf,
    now_ms: i64,
    fetch: F,
) -> tokio::task::JoinHandle<Result<PollReport>>
where
    F: FnMut(&str) -> Result<ApiResponse> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let db = open_database(database_path)?;
        poll_one_with_transport(&db, now_ms, fetch)
    })
}

/// Dispatch already durable CI outbox rows without polling GitHub. Schedule it
/// in the CI worker, independently of Wake's existing dispatcher.
/// The delivery callback must persist an exact-ID wake recovery before returning
/// `queued` with a wake warning; only the caller knows the identity it submitted.
pub fn dispatch<D>(db: &mut Connection, now_ms: i64, deliver: D) -> Result<DispatchReport>
where
    D: FnMut(&Connection, &Delivery, &str) -> Result<(String, Option<String>)>,
{
    let started = Instant::now();
    dispatch_with_clock(db, now_ms, deliver, || {
        now_ms.saturating_add(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX))
    })
}

fn dispatch_with_clock<D, C>(
    db: &mut Connection,
    now_ms: i64,
    mut deliver: D,
    mut now: C,
) -> Result<DispatchReport>
where
    D: FnMut(&Connection, &Delivery, &str) -> Result<(String, Option<String>)>,
    C: FnMut() -> i64,
{
    let deliveries = pr_ci::claim_deliveries(db, now_ms, DISPATCH_BATCH, DELIVERY_LEASE)?;
    let mut report = DispatchReport {
        claimed: deliveries.len(),
        ..DispatchReport::default()
    };
    for delivery in deliveries {
        let message = notification(&delivery);
        match deliver(db, &delivery, &message) {
            Ok((state, _)) if state == "queued" => {
                if pr_ci::ack_delivery(db, delivery.id)? {
                    report.accepted += 1;
                } else {
                    report.uncertain += 1;
                }
            }
            Ok((state, _)) if state == "ready" => {
                if retry_ci_before_send(db, &delivery, now(), None)? {
                    report.retried_before_send += 1;
                } else {
                    report.uncertain += 1;
                }
            }
            Err(error) if known_before_send_failure(&error) => {
                let token = error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<BeforeSendFailure>())
                    .and_then(|failure| failure.intent_token.as_deref());
                if retry_ci_before_send(db, &delivery, now(), token)? {
                    report.retried_before_send += 1;
                } else {
                    report.uncertain += 1;
                }
            }
            Ok(_) | Err(_) => {
                pr_ci::mark_delivery_uncertain(db, delivery.id)?;
                report.uncertain += 1;
            }
        }
    }
    Ok(report)
}

fn retry_ci_before_send(
    db: &Connection,
    delivery: &Delivery,
    now: i64,
    token: Option<&str>,
) -> Result<bool> {
    initialize_native_wake_recovery(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let changed = pr_ci::retry_delivery(&tx, delivery.id, now)?;
    let raw: Option<Option<String>> = tx
        .query_row(
            "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
            [&delivery.thread],
            |row| row.get(0),
        )
        .optional()?;
    if changed && let Some(raw) = raw {
        let ids = native_wake_ids(raw.as_deref())?;
        for intent in ids.intents {
            if token == Some(intent.token.as_str())
                && matches!(intent.origin, NativeWakeOrigin::Ci { id } if id == delivery.id)
            {
                finish_native_wake_intent(&tx, &delivery.thread, &intent.token)?;
            }
        }
    }
    tx.commit()?;
    Ok(changed)
}

fn known_before_send_failure(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<BeforeSendFailure>().is_some())
}

/// Dispatch from an independent worker and independent database connection.
/// The callback is normally a closure around the binary's existing
/// `execution::deliver` function; no send outcome is inferred by this wrapper.
pub fn spawn_dispatch<D>(
    database_path: PathBuf,
    now_ms: i64,
    deliver: D,
) -> tokio::task::JoinHandle<Result<DispatchReport>>
where
    D: FnMut(&Connection, &Delivery, &str) -> Result<(String, Option<String>)> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut db = open_database(database_path)?;
        dispatch(&mut db, now_ms, deliver)
    })
}

fn open_database(path: PathBuf) -> Result<Connection> {
    let db = Connection::open(path).context("Open CI tracking database")?;
    db.busy_timeout(Duration::from_secs(5))?;
    Ok(db)
}

fn notification(delivery: &Delivery) -> String {
    format!(
        "CI de {}/PR #{}: ejecución {} (intento {}) para `{}` terminó con `{}`.",
        delivery.repo,
        delivery.pull_request,
        delivery.run_id,
        delivery.attempt,
        delivery.sha,
        delivery.conclusion
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_failure_does_not_hide_cleanup_uncertainty_in_tracker_status() {
        for (timed_out, stdout_fails, panics) in [
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (false, false, false),
        ] {
            let mut db = Connection::open_in_memory().unwrap();
            crate::pr_ci::register(
                &mut db,
                "owner/repo",
                "7",
                "11111111-1111-4111-8111-111111111111",
            )
            .unwrap();
            let report = crate::pr_ci::poll(&db, 1, |_| {
                let failure: thread::Result<Result<Vec<u8>>> = if panics {
                    Err(Box::new("private reader panic"))
                } else {
                    Ok(Err(anyhow::anyhow!("private reader error")))
                };
                let ok = Ok(Ok(Vec::new()));
                let (stdout, stderr) = if stdout_fails {
                    (failure, ok)
                } else {
                    (ok, failure)
                };
                finish_pipe_reads(
                    stdout,
                    stderr,
                    Some(std::io::Error::other("private cleanup error")),
                    timed_out,
                )
                .map(|_| ApiResponse {
                    status: 200,
                    body: serde_json::json!({}),
                })
            })
            .unwrap();
            assert_eq!(report.cleanup_uncertain, 1);
            assert_eq!(report.errors, ["owner/repo#7: process_cleanup_uncertain"]);
            let (error, marker_count): (String, i64) = db
                .query_row(
                    "SELECT error,(SELECT count(*) FROM pr_ci_cleanup_uncertainties) FROM pr_ci_trackers",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(error, "process_cleanup_uncertain");
            assert_eq!(marker_count, 1);
        }
    }

    #[test]
    fn pipe_failure_with_confirmed_cleanup_keeps_reader_error() {
        let error = finish_pipe_reads(
            Ok(Err(anyhow::anyhow!("reader failed"))),
            Ok(Ok(Vec::new())),
            None,
            true,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "reader failed");
        assert!(
            !error
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>())
        );
    }
    use rusqlite::params;

    #[test]
    fn intent_waits_for_writer_and_requires_exact_evidence() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE automatic_pr_notifications(id TEXT PRIMARY KEY,thread TEXT,state TEXT);
            INSERT INTO automatic_pr_notifications VALUES('11111111-1111-4111-8111-111111111112',
            '11111111-1111-4111-8111-111111111111','sending');",
        )
        .unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let id = "11111111-1111-4111-8111-111111111112";
        let lock = try_native_wake_lock(&db, id).unwrap().unwrap();
        begin_native_wake_intent(&db, thread, id, NativeWakeOrigin::Pr { id: id.into() }, 100)
            .unwrap();
        assert_eq!(
            recover_native_wake_intents(&db, 101, |_, _| panic!("writer still owns lock")).unwrap(),
            0
        );
        drop(lock);
        assert_eq!(
            recover_native_wake_intents(&db, 101, |_, _| anyhow::bail!("identity absent")).unwrap(),
            0
        );
        let state: String = db
            .query_row(
                "SELECT state FROM automatic_pr_notifications WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "sending");
        assert_eq!(
            recover_native_wake_intents(
                &db,
                101 + NATIVE_WAKE_INTENT_LEASE_MS,
                |destination, ids| {
                    assert_eq!(destination, thread);
                    assert_eq!(ids, &[id.to_owned()]);
                    Ok(())
                }
            )
            .unwrap(),
            1
        );
        let state: String = db
            .query_row(
                "SELECT state FROM automatic_pr_notifications WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "queued");
    }

    #[test]
    fn memory_locks_are_per_database_and_shared_across_connections() {
        let first = Connection::open_in_memory().unwrap();
        let second = Connection::open_in_memory().unwrap();
        let id = "11111111-1111-4111-8111-111111111112";
        let first_lock = try_native_wake_lock(&first, id).unwrap().unwrap();
        let second_lock = try_native_wake_lock(&second, id).unwrap().unwrap();
        assert!(try_native_wake_lock(&first, id).unwrap().is_none());
        drop((first_lock, second_lock));
        let uri = format!("file:{}?mode=memory&cache=shared", uuid::Uuid::new_v4());
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            | rusqlite::OpenFlags::SQLITE_OPEN_URI;
        let shared_a = Connection::open_with_flags(&uri, flags).unwrap();
        let shared_b = Connection::open_with_flags(&uri, flags).unwrap();
        let lock = try_native_wake_lock(&shared_a, id).unwrap().unwrap();
        assert!(try_native_wake_lock(&shared_b, id).unwrap().is_none());
        drop(lock);
        assert!(try_native_wake_lock(&shared_b, id).unwrap().is_some());
    }

    #[test]
    fn before_send_retry_cannot_clear_a_previous_uncertain_intent() {
        let mut db = Connection::open_in_memory().unwrap();
        crate::pr_ci::initialize(&db).unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let id = "11111111-1111-4111-8111-111111111112";
        db.execute("INSERT INTO pr_ci_deliveries(repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json)
            VALUES('owner/repo',7,'sha',1,1,?1,'success','{}')", [thread]).unwrap();
        let delivery = crate::pr_ci::claim_deliveries(&mut db, 1, 1, Duration::from_secs(180))
            .unwrap()
            .remove(0);
        let token = begin_native_wake_intent(
            &db,
            thread,
            id,
            NativeWakeOrigin::Ci { id: delivery.id },
            100,
        )
        .unwrap();
        assert!(retry_ci_before_send(&db, &delivery, 2, None).unwrap());
        let raw: String = db
            .query_row(
                "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
                [thread],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(native_wake_ids(Some(&raw)).unwrap().intents[0].token, token);
    }

    #[test]
    fn ci_retry_and_own_intent_cleanup_are_atomic() {
        let mut db = Connection::open_in_memory().unwrap();
        crate::pr_ci::initialize(&db).unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let id = "11111111-1111-4111-8111-111111111112";
        db.execute("INSERT INTO pr_ci_deliveries(repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json)
            VALUES('owner/repo',7,'sha',1,1,?1,'success','{}')", [thread]).unwrap();
        let delivery = crate::pr_ci::claim_deliveries(&mut db, 1, 1, Duration::from_secs(180))
            .unwrap()
            .remove(0);
        let token = begin_native_wake_intent(
            &db,
            thread,
            id,
            NativeWakeOrigin::Ci { id: delivery.id },
            100,
        )
        .unwrap();
        db.execute_batch("CREATE TRIGGER fail_finish BEFORE DELETE ON native_wake_recovery BEGIN SELECT RAISE(ABORT,'db error'); END;").unwrap();
        assert!(retry_ci_before_send(&db, &delivery, 2, Some(&token)).is_err());
        let state: String = db
            .query_row(
                "SELECT state FROM pr_ci_deliveries WHERE id=?1",
                [delivery.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "claimed");
        db.execute_batch("DROP TRIGGER fail_finish").unwrap();
        assert!(retry_ci_before_send(&db, &delivery, 3, Some(&token)).unwrap());
        let (state, remaining): (String, i64) = db.query_row("SELECT state,(SELECT count(*) FROM native_wake_recovery) FROM pr_ci_deliveries WHERE id=?1", [delivery.id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!((state.as_str(), remaining), ("pending", 0));
    }

    #[test]
    fn uncertain_intent_does_not_block_another_accepted_message() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let uncertain = "11111111-1111-4111-8111-111111111112";
        let accepted = "11111111-1111-4111-8111-111111111113";
        begin_native_wake_intent(
            &db,
            thread,
            uncertain,
            NativeWakeOrigin::Pr {
                id: uncertain.into(),
            },
            500,
        )
        .unwrap();
        record_native_wake_recovery(&db, thread, "native_queue_resume_warning", accepted).unwrap();
        assert_eq!(
            recover_native_wake_retries(&db, 1, |target, ids| {
                assert_eq!(target, thread);
                assert_eq!(ids, &[accepted.to_owned()]);
                Ok(())
            })
            .unwrap(),
            1
        );
        let raw: String = db
            .query_row(
                "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
                [thread],
                |row| row.get(0),
            )
            .unwrap();
        let remaining = native_wake_ids(Some(&raw)).unwrap();
        assert!(remaining.client_ids.is_empty());
        assert_eq!(remaining.intents.len(), 1);
        assert_eq!(remaining.intents[0].client_id, uncertain);
    }

    #[test]
    fn missing_intent_does_not_block_another_recovery() {
        for same_thread in [true, false] {
            let db = Connection::open_in_memory().unwrap();
            db.execute_batch("CREATE TABLE automatic_pr_notifications(id TEXT PRIMARY KEY,thread TEXT,state TEXT)").unwrap();
            let first = "11111111-1111-4111-8111-111111111111";
            let second = if same_thread {
                first
            } else {
                "22222222-2222-4222-8222-222222222222"
            };
            let absent = "11111111-1111-4111-8111-111111111112";
            let accepted = "22222222-2222-4222-8222-222222222223";
            for (thread, id) in [(first, absent), (second, accepted)] {
                db.execute(
                    "INSERT INTO automatic_pr_notifications VALUES(?1,?2,'sending')",
                    params![id, thread],
                )
                .unwrap();
                begin_native_wake_intent(
                    &db,
                    thread,
                    id,
                    NativeWakeOrigin::Pr { id: id.into() },
                    1,
                )
                .unwrap();
            }
            let mut checked = Vec::new();
            assert_eq!(
                recover_native_wake_intents(&db, 2, |_, ids| {
                    checked.push(ids[0].clone());
                    if ids[0] == absent {
                        anyhow::bail!("not found")
                    } else {
                        Ok(())
                    }
                })
                .unwrap(),
                1
            );
            assert_eq!(checked, vec![absent, accepted]);
            let states: Vec<String> = db
                .prepare("SELECT state FROM automatic_pr_notifications ORDER BY id")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(states, vec!["sending", "queued"]);
        }
    }

    #[test]
    fn locked_intents_do_not_starve_a_third_destination() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE automatic_pr_notifications(id TEXT PRIMARY KEY,thread TEXT,state TEXT)",
        )
        .unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let ids = [
            "11111111-1111-4111-8111-111111111112",
            "22222222-2222-4222-8222-222222222223",
            "33333333-3333-4333-8333-333333333334",
        ];
        for id in ids {
            db.execute(
                "INSERT INTO automatic_pr_notifications VALUES(?1,?2,'sending')",
                params![id, thread],
            )
            .unwrap();
            begin_native_wake_intent(&db, thread, id, NativeWakeOrigin::Pr { id: id.into() }, 1)
                .unwrap();
        }
        let first = try_native_wake_lock(&db, ids[0]).unwrap().unwrap();
        let second = try_native_wake_lock(&db, ids[1]).unwrap().unwrap();
        assert_eq!(
            recover_native_wake_intents(&db, 2, |_, _| panic!("locks held")).unwrap(),
            0
        );
        assert_eq!(
            recover_native_wake_intents(&db, 1_002, |_, found| {
                assert_eq!(found, &[ids[2]]);
                Ok(())
            })
            .unwrap(),
            1
        );
        drop((first, second));
    }

    #[test]
    fn unattributed_recovery_does_not_starve_other_threads() {
        let db = Connection::open_in_memory().unwrap();
        let first = "11111111-1111-4111-8111-111111111111";
        let second = "22222222-2222-4222-8222-222222222222";
        let id1 = "11111111-1111-4111-8111-111111111112";
        let id2 = "22222222-2222-4222-8222-222222222223";
        record_unattributed_native_wake_recovery(&db, first, "native_queue_resume_warning")
            .unwrap();
        record_native_wake_recovery(&db, first, "native_queue_resume_warning", id1).unwrap();
        record_native_wake_recovery(&db, second, "native_queue_resume_warning", id2).unwrap();
        assert_eq!(
            recover_native_wake_retries(&db, 1, |thread, ids| {
                assert_eq!(thread, first);
                assert_eq!(ids, &[id1]);
                Ok(())
            })
            .unwrap(),
            0
        );
        assert_eq!(
            recover_native_wake_retries(&db, 2, |thread, ids| {
                assert_eq!(thread, second);
                assert_eq!(ids, &[id2]);
                Ok(())
            })
            .unwrap(),
            1
        );
        let raw: String = db
            .query_row(
                "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
                [first],
                |row| row.get(0),
            )
            .unwrap();
        let remaining = native_wake_ids(Some(&raw)).unwrap();
        assert!(remaining.unattributed);
        assert!(remaining.client_ids.is_empty());
    }

    #[test]
    fn github_response_filter_uses_endpoint_after_owner_and_repository() {
        for (ordinary, named_pulls) in [
            ("/repos/acme/widget/pulls/7", "/repos/pulls/pulls/pulls/7"),
            (
                "/repos/acme/widget/actions/runs?head_sha=abc&per_page=100&page=1",
                "/repos/pulls/pulls/actions/runs?head_sha=abc&per_page=100&page=1",
            ),
            (
                "/repos/acme/widget/actions/runs/42/attempts/2",
                "/repos/pulls/pulls/actions/runs/42/attempts/2",
            ),
        ] {
            assert_eq!(
                gh_response_filter(ordinary).unwrap(),
                gh_response_filter(named_pulls).unwrap()
            );
        }
        assert!(gh_response_filter("/repos/acme/pulls/issues/7").is_err());
        assert!(gh_response_filter("/repos/acme//pulls/7").is_err());
        assert_ne!(
            gh_response_filter("/repos/acme/pulls/pulls/7").unwrap(),
            gh_response_filter("/repos/acme/pulls/actions/runs?per_page=100").unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gh_pull_filter_preserves_close_identity_for_ci_sweep() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let wrapper = directory.path().join("gh");
        std::fs::write(&wrapper, r##"#!/bin/sh
case "$4" in
  */pulls/7) case "$3" in *closed_at*) ;; *) exit 2;; esac
    printf '%s' '{"number":7,"state":"closed","closed_at":"2026-01-01T00:00:00Z","base":{"repo":{"full_name":"owner/project"}},"head":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"full_name":"owner/project"}}}' ;;
  *) printf '%s' '{"total_count":0,"workflow_runs":[]}' ;;
esac
"##).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut db = Connection::open_in_memory().unwrap();
        crate::pr_ci::register(
            &mut db,
            "owner/project",
            "7",
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        let snapshot = gh_api_with_timeout(
            &wrapper,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(5),
        )
        .unwrap()
        .body;
        crate::pr_ci::observe_pull_request_snapshot_in(&db, "owner/project", "7", &snapshot, 1)
            .unwrap();
        let report = crate::pr_ci::poll(&db, 2, |route| {
            gh_api_with_timeout(&wrapper, route, Duration::from_secs(5))
        })
        .unwrap();
        assert!(report.errors.is_empty());
        let certificate: Option<i64> = db
            .query_row(
                "SELECT closed_sweep_generation FROM pr_ci_tracker_generations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(certificate.is_some());
    }

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        pr_ci::initialize(&db).unwrap();
        db.execute(
            "INSERT INTO pr_ci_deliveries(repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json)
             VALUES('acme/widget',7,?1,101,1,?2,'success','{}')",
            params!["a".repeat(40), "00000000-0000-4000-8000-000000000001"],
        )
        .unwrap();
        db
    }

    fn dispatch_at<D>(db: &mut Connection, now_ms: i64, deliver: D) -> Result<DispatchReport>
    where
        D: FnMut(&Connection, &Delivery, &str) -> Result<(String, Option<String>)>,
    {
        dispatch_with_clock(db, now_ms, deliver, || now_ms)
    }

    #[test]
    fn accepted_queue_delivery_is_acknowledged() {
        let mut db = database();
        let report = dispatch(&mut db, 1_000, |_, _, _| Ok(("queued".into(), None))).unwrap();
        assert_eq!(report.accepted, 1);
        assert_eq!(pr_ci::uncertain_deliveries(&db).unwrap().len(), 0);
    }

    #[test]
    fn uncertain_send_is_not_requeued_automatically() {
        let mut db = database();
        let report = dispatch(&mut db, 1_000, |_, _, _| Err(anyhow::anyhow!("ambiguous"))).unwrap();
        assert_eq!(report.uncertain, 1);
        assert_eq!(pr_ci::uncertain_deliveries(&db).unwrap().len(), 1);
        assert_eq!(
            pr_ci::claim_deliveries(&mut db, 2_000, 10, DELIVERY_LEASE)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn definitely_pre_send_result_returns_to_queue() {
        let mut db = database();
        let report = dispatch_at(&mut db, 1_000, |_, _, _| Ok(("ready".into(), None))).unwrap();
        assert_eq!(report.retried_before_send, 1);
        assert_eq!(
            pr_ci::claim_deliveries(&mut db, 6_000, 10, DELIVERY_LEASE)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn known_before_send_errors_retry_but_unknown_errors_stay_uncertain() {
        for marker in [
            "Target unavailable during preparation; input was not sent",
            "Target thread has an active writer; input was not sent",
        ] {
            let mut db = database();
            let report = dispatch_at(&mut db, 1_000, |_, _, _| {
                Err(before_send_failure(anyhow::anyhow!(marker)))
            })
            .unwrap();
            assert_eq!((report.retried_before_send, report.uncertain), (1, 0));
            assert_eq!(
                pr_ci::claim_deliveries(&mut db, 6_000, 10, DELIVERY_LEASE)
                    .unwrap()
                    .len(),
                1
            );
        }

        let mut evidence_db = database();
        let report = dispatch_at(&mut evidence_db, 2_000, |_, _, _| {
            Err(before_send_failure(anyhow::anyhow!(
                "could not open delivery evidence database"
            )))
        })
        .unwrap();
        assert_eq!((report.retried_before_send, report.uncertain), (1, 0));
        assert_eq!(pr_ci::uncertain_deliveries(&evidence_db).unwrap().len(), 0);

        let mut uncertain_db = database();
        let report = dispatch(&mut uncertain_db, 3_000, |_, _, _| {
            Err(anyhow::anyhow!("unknown send state"))
        })
        .unwrap();
        assert_eq!((report.retried_before_send, report.uncertain), (0, 1));
        assert_eq!(pr_ci::uncertain_deliveries(&uncertain_db).unwrap().len(), 1);

        let mut misleading_db = database();
        let report = dispatch(&mut misleading_db, 3_000, |_, _, _| {
            Err(anyhow::anyhow!(
                "Target unavailable during preparation; input was not sent"
            ))
        })
        .unwrap();
        assert_eq!((report.retried_before_send, report.uncertain), (0, 1));
        assert!(
            pr_ci::claim_deliveries(&mut misleading_db, 10_000, 10, DELIVERY_LEASE)
                .unwrap()
                .is_empty()
        );

        let mut unknown_state_db = database();
        let report = dispatch(&mut unknown_state_db, 4_000, |_, _, _| {
            Ok(("unknown".into(), None))
        })
        .unwrap();
        assert_eq!((report.retried_before_send, report.uncertain), (0, 1));
        assert_eq!(
            pr_ci::uncertain_deliveries(&unknown_state_db)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn dispatch_claims_one_row_so_unattempted_rows_remain_pending() {
        use std::cell::Cell;

        let mut db = database();
        for run_id in [102, 103] {
            db.execute(
                "INSERT INTO pr_ci_deliveries(repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json)
                 VALUES('acme/widget',7,?1,?2,1,'00000000-0000-4000-8000-000000000001','success','{}')",
                params!["b".repeat(40), run_id],
            )
            .unwrap();
        }
        let calls = Cell::new(0);
        let report = dispatch(&mut db, 1_000, |_, _, _| {
            calls.set(calls.get() + 1);
            Err(anyhow::anyhow!("ambiguous send"))
        })
        .unwrap();
        let pending: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_deliveries WHERE state='pending'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            (report.claimed, report.uncertain, calls.get(), pending),
            (1, 1, 1, 2)
        );
    }

    #[test]
    fn busy_delivery_defers_its_retry_so_other_chats_can_run() {
        let mut db = database();
        db.execute(
            "INSERT INTO pr_ci_deliveries(repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json)
             VALUES('acme/widget',7,?1,102,1,'00000000-0000-4000-8000-000000000002','success','{}')",
            params!["b".repeat(40)],
        )
        .unwrap();

        let first = dispatch_at(&mut db, 1_000, |_, delivery, _| {
            assert_eq!(delivery.run_id, 101);
            Err(before_send_failure(anyhow::anyhow!(
                "Target thread has an active writer; input was not sent"
            )))
        })
        .unwrap();
        assert_eq!(first.retried_before_send, 1);

        let second = dispatch_at(&mut db, 1_000, |_, delivery, _| {
            assert_eq!(delivery.run_id, 102);
            Ok(("queued".into(), None))
        })
        .unwrap();
        assert_eq!(second.accepted, 1);

        let retry = dispatch_at(&mut db, 6_000, |_, delivery, _| {
            assert_eq!(delivery.run_id, 101);
            Ok(("queued".into(), None))
        })
        .unwrap();
        assert_eq!(retry.accepted, 1);
    }

    #[test]
    fn slow_pre_send_failure_starts_retry_delay_when_callback_finishes() {
        use std::cell::Cell;

        let mut db = database();
        let clock = Cell::new(1_000);
        let failed = dispatch_with_clock(
            &mut db,
            1_000,
            |_, _, _| {
                clock.set(8_000);
                Err(before_send_failure(anyhow::anyhow!(
                    "Target thread has an active writer; input was not sent"
                )))
            },
            || clock.get(),
        )
        .unwrap();
        assert_eq!(failed.retried_before_send, 1);

        assert_eq!(
            dispatch(&mut db, 12_999, |_, _, _| panic!("retry ran early"))
                .unwrap()
                .claimed,
            0
        );
        assert_eq!(
            dispatch(&mut db, 13_000, |_, _, _| Ok(("queued".into(), None)))
                .unwrap()
                .accepted,
            1
        );
    }

    #[test]
    fn accepted_input_resume_warning_survives_restart_without_resending() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("wake.sqlite");
        {
            let mut db = Connection::open(&database_path).unwrap();
            pr_ci::initialize(&db).unwrap();
            db.execute(
                "INSERT INTO pr_ci_deliveries(repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json)
                 VALUES('acme/widget',7,?1,101,1,'00000000-0000-4000-8000-000000000001','success','{}')",
                params!["a".repeat(40)],
            )
            .unwrap();
            let report = dispatch(&mut db, 1_000, |writer, delivery, _| {
                record_native_wake_recovery(
                    writer,
                    &delivery.thread,
                    "native_queue_resume_warning",
                    "10000000-0000-4000-8000-000000000001",
                )?;
                Ok(("queued".into(), Some("native_queue_resume_warning".into())))
            })
            .unwrap();
            assert_eq!(report.accepted, 1);
            let delivered: String = db
                .query_row(
                    "SELECT state FROM pr_ci_deliveries WHERE run_id=101",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(delivered, "delivered");
        }

        let db = Connection::open(&database_path).unwrap();
        let mut woken = Vec::new();
        assert_eq!(
            recover_native_wake_retries(&db, 1_001, |thread, ids| {
                assert_eq!(ids, &["10000000-0000-4000-8000-000000000001"]);
                woken.push(thread.to_owned());
                Ok(())
            })
            .unwrap(),
            1
        );
        assert_eq!(woken, vec!["00000000-0000-4000-8000-000000000001"]);
        let pending: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_deliveries WHERE state='pending'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0);
    }

    #[test]
    fn concurrent_wake_writer_is_preserved_without_resending_accepted_input() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("wake-writer.sqlite");
        let mut db = Connection::open(&database_path).unwrap();
        pr_ci::initialize(&db).unwrap();
        db.execute(
            "INSERT INTO pr_ci_deliveries(repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json)
             VALUES('acme/widget',7,?1,101,1,'00000000-0000-4000-8000-000000000001','success','{}')",
            params!["a".repeat(40)],
        )
        .unwrap();
        let report = dispatch(&mut db, 1_000, |writer, delivery, _| {
            record_native_wake_recovery(
                writer,
                &delivery.thread,
                "native_queue_resume_warning",
                "10000000-0000-4000-8000-000000000001",
            )?;
            Ok(("queued".into(), Some("native_queue_resume_warning".into())))
        })
        .unwrap();
        assert_eq!(report.accepted, 1);

        let writer_path = database_path.clone();
        assert_eq!(
            recover_native_wake_retries(&db, 1_001, |thread, ids| {
                assert_eq!(ids, &["10000000-0000-4000-8000-000000000001"]);
                let writer = Connection::open(&writer_path).unwrap();
                assert!(record_native_wake_recovery(
                    &writer,
                    thread,
                    "native_queue_resume_warning",
                    "10000000-0000-4000-8000-000000000002"
                )?);
                Ok(())
            })
            .unwrap(),
            0,
            "stale recovery completion must not erase the concurrent write"
        );
        let remaining: i64 = db
            .query_row("SELECT count(*) FROM native_wake_recovery", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 1);
        let mut recovered_ids = Vec::new();
        assert_eq!(
            recover_native_wake_retries(&db, 2_002, |_, ids| {
                recovered_ids = ids.to_vec();
                Ok(())
            })
            .unwrap(),
            1
        );
        assert_eq!(
            recovered_ids,
            vec![
                "10000000-0000-4000-8000-000000000001",
                "10000000-0000-4000-8000-000000000002"
            ]
        );
        let state: String = db
            .query_row(
                "SELECT state FROM pr_ci_deliveries WHERE run_id=101",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "delivered");
        assert_eq!(
            dispatch(&mut db, 2_000, |_, _, _| panic!("accepted input resent"))
                .unwrap()
                .claimed,
            0
        );
    }

    #[test]
    fn wake_recovery_accumulates_exact_ids_and_retains_them_after_failure() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "00000000-0000-4000-8000-000000000001";
        let first = "10000000-0000-4000-8000-000000000001";
        let second = "10000000-0000-4000-8000-000000000002";
        for id in [second, first, second] {
            record_native_wake_recovery(&db, thread, "native_queue_resume_warning", id).unwrap();
        }
        let mut attempts = 0;
        assert_eq!(
            recover_native_wake_retries(&db, 1_000, |destination, ids| {
                assert_eq!(destination, thread);
                assert_eq!(ids, &[first, second]);
                attempts += 1;
                bail!("exact message is not yet observable")
            })
            .unwrap(),
            0
        );
        assert_eq!(attempts, 1);
        assert_eq!(
            recover_native_wake_retries(&db, 1_999, |_, _| panic!("retry before deadline"))
                .unwrap(),
            0
        );
        assert_eq!(
            recover_native_wake_retries(&db, 2_000, |_, ids| {
                assert_eq!(ids, &[first, second]);
                Ok(())
            })
            .unwrap(),
            1
        );
    }

    #[test]
    fn wake_recovery_migration_preserves_unattributed_legacy_and_new_obligations() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "00000000-0000-4000-8000-000000000001";
        let id = "10000000-0000-4000-8000-000000000001";
        db.execute_batch(
            "CREATE TABLE native_wake_recovery (
                 thread TEXT PRIMARY KEY,reason TEXT NOT NULL,
                 next_attempt_ms INTEGER NOT NULL DEFAULT 0,
                 backoff_ms INTEGER NOT NULL DEFAULT 1000,
                 revision INTEGER NOT NULL DEFAULT 1
             );",
        )
        .unwrap();
        db.execute(
            "INSERT INTO native_wake_recovery(thread,reason)
             VALUES(?1,'native_queue_resume_warning')",
            [thread],
        )
        .unwrap();
        assert_eq!(
            recover_native_wake_retries(&db, 1_000, |_, _| panic!("legacy identity was guessed"))
                .unwrap(),
            0
        );
        record_native_wake_recovery(&db, thread, "native_queue_resume_warning", id).unwrap();
        let mut attempts = 0;
        assert_eq!(
            recover_native_wake_retries(&db, 1_001, |_, ids| {
                assert_eq!(ids, &[id]);
                attempts += 1;
                Ok(())
            })
            .unwrap(),
            0,
            "executing a new message must not resolve the unattributed legacy warning"
        );
        assert_eq!(attempts, 1);
        let raw: String = db
            .query_row(
                "SELECT client_ids_json FROM native_wake_recovery WHERE thread=?1",
                [thread],
                |row| row.get(0),
            )
            .unwrap();
        let ids = native_wake_ids(Some(&raw)).unwrap();
        assert!(ids.unattributed);
        assert!(ids.client_ids.is_empty());
    }

    #[test]
    fn unattributed_warning_preserves_known_ids_without_becoming_resolvable() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "00000000-0000-4000-8000-000000000001";
        let id = "10000000-0000-4000-8000-000000000001";
        record_native_wake_recovery(&db, thread, "native_queue_resume_warning", id).unwrap();
        record_unattributed_native_wake_recovery(&db, thread, "native_queue_resume_warning")
            .unwrap();
        let mut attempts = 0;
        assert_eq!(
            recover_native_wake_retries(&db, 1_000, |_, ids| {
                assert_eq!(ids, &[id]);
                attempts += 1;
                Ok(())
            })
            .unwrap(),
            0
        );
        assert_eq!(attempts, 1);
        let rows: i64 = db
            .query_row("SELECT count(*) FROM native_wake_recovery", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn wake_recovery_ignores_unrelated_uncertainty_after_crash_before_ack() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wake-crash.sqlite");
        let thread = "00000000-0000-4000-8000-000000000001";
        let id = "10000000-0000-4000-8000-000000000002";
        {
            let mut db = Connection::open(&path).unwrap();
            pr_ci::initialize(&db).unwrap();
            for (run, state) in [(100, "needs_attention"), (101, "pending")] {
                db.execute(
                    "INSERT INTO pr_ci_deliveries
                     (repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json,state)
                     VALUES('acme/widget',7,?1,?2,1,?3,'success','{}',?4)",
                    params!["a".repeat(40), run, thread, state],
                )
                .unwrap();
            }
            let claimed =
                pr_ci::claim_deliveries(&mut db, 1_000, 1, Duration::from_secs(1)).unwrap();
            assert_eq!(claimed.len(), 1);
            assert_eq!(claimed[0].run_id, 101);
            record_native_wake_recovery(&db, thread, "native_queue_resume_warning", id).unwrap();
            // The accepted input was persisted, but the process stopped before ack_delivery.
        }
        let mut db = Connection::open(&path).unwrap();
        assert!(
            pr_ci::claim_deliveries(&mut db, 2_001, 1, Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            recover_native_wake_retries(&db, 2_001, |destination, ids| {
                assert_eq!(destination, thread);
                assert_eq!(ids, &[id]);
                Ok(())
            })
            .unwrap(),
            1
        );
        let uncertain: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_deliveries WHERE state='needs_attention'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            uncertain, 2,
            "wake recovery must not change uncertain send outcomes"
        );
    }

    #[test]
    fn stale_wake_recovery_cannot_delete_a_recreated_generation_with_the_same_id() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "00000000-0000-4000-8000-000000000001";
        let first = "10000000-0000-4000-8000-000000000001";
        record_native_wake_recovery(&db, thread, "native_queue_resume_warning", first).unwrap();
        assert_eq!(
            recover_native_wake_retries(&db, 1_000, |_, ids| {
                assert_eq!(ids, &[first]);
                assert_eq!(recover_native_wake_retries(&db, 2_001, |_, _| Ok(()))?, 1);
                record_native_wake_recovery(&db, thread, "native_queue_resume_warning", first)?;
                Ok(())
            })
            .unwrap(),
            0
        );
        assert_eq!(
            recover_native_wake_retries(&db, 2_002, |_, ids| {
                assert_eq!(ids, &[first]);
                Ok(())
            })
            .unwrap(),
            1
        );
    }

    #[test]
    fn wake_recovery_respects_the_callers_transaction_and_rejects_invalid_ids() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "00000000-0000-4000-8000-000000000001";
        initialize_native_wake_recovery(&db).unwrap();
        let tx = Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        record_native_wake_recovery(
            &tx,
            thread,
            "native_queue_resume_warning",
            "10000000-0000-4000-8000-000000000001",
        )
        .unwrap();
        tx.rollback().unwrap();
        assert!(
            record_native_wake_recovery(&db, thread, "native_queue_resume_warning", "not-an-id")
                .is_err()
        );
        let rows: i64 = db
            .query_row("SELECT count(*) FROM native_wake_recovery", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gh_external_reap_still_cleans_process_group() {
        use std::fs;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let wrapper = directory.path().join("gh-wrapper");
        let leader_file = directory.path().join("leader");
        let descendant_file = directory.path().join("descendant");
        let release_file = directory.path().join("release");
        fs::write(&wrapper, format!("#!/bin/sh\necho $$ > '{}'; sh -c 'echo $$ > \"$1\"; while [ ! -e \"$2\" ]; do sleep 0.01; done; exec >/dev/null 2>&1; exec sleep 10' sh '{}' '{}' &\nwhile [ ! -s '{}' ]; do sleep 0.01; done\nprintf '{{}}'\n", leader_file.display(), descendant_file.display(), release_file.display(), descendant_file.display())).unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let worker = thread::spawn(move || {
            gh_api_with_timeout(
                &wrapper,
                "/repos/owner/project/pulls/7",
                Duration::from_secs(3),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while (!leader_file.exists() || !descendant_file.exists()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let leader: libc::pid_t = fs::read_to_string(leader_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let descendant: libc::pid_t = fs::read_to_string(descendant_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, descendant, 0) as libc::c_int };
        assert!(fd >= 0);
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        assert_eq!(
            unsafe { libc::waitpid(leader, std::ptr::null_mut(), 0) },
            leader
        );
        fs::write(release_file, "release").unwrap();
        let error = worker.join().unwrap().unwrap_err().to_string();
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let exited = unsafe { libc::poll(&mut pollfd, 1, 1000) } == 1;
        if !exited {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        assert!(error.contains("Check gh process"), "{error}");
        assert!(exited || error.contains("cleanup: Err"), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn group_pidfd_survives_external_reap() {
        use std::io::BufRead;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::process::CommandExt;
        let mut command = Command::new("sh");
        command
            .process_group(0)
            .arg("-c")
            .arg("sleep 10 & echo $!; exit")
            .stdout(Stdio::piped());
        let (mut child, handle) =
            spawn_with_group_handle(&mut command, false, false, Duration::from_secs(2)).unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let descendant: libc::pid_t = line.trim().parse().unwrap();
        // The fixture has just started its sleep child; retain an individual
        // pidfd for verification and safe cleanup if group signalling fails.
        let desc_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, descendant, 0) as libc::c_int };
        assert!(desc_fd >= 0);
        let desc_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(desc_fd) };
        let leader = child.id() as libc::pid_t;
        let reaped =
            thread::spawn(move || unsafe { libc::waitpid(leader, std::ptr::null_mut(), 0) })
                .join()
                .unwrap();
        assert_eq!(reaped, leader);
        let result = terminate_process_group(&mut child, &handle);
        if result.is_err() {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    desc_fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        let mut pollfd = libc::pollfd {
            fd: desc_fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 2000) }, 1);
        if let Err(error) = result {
            // Older kernels or sandbox policies may not support the feature.
            assert!(
                matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
                ) || handle.is_none(),
                "unexpected cleanup error: {error}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_group_handle_reports_incomplete_cleanup() {
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();
        let error = terminate_process_group(&mut child, &None).unwrap_err();
        assert!(error.to_string().contains("unavailable"));
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn denied_pidfd_or_group_probe_never_executes_command() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("executed");
        for (deny_pidfd, deny_group) in [(true, false), (false, true)] {
            let mut command = Command::new("sh");
            command.arg("-c").arg("touch \"$1\"").arg("sh").arg(&marker);
            let started = Instant::now();
            assert!(
                spawn_with_group_handle(
                    &mut command,
                    deny_pidfd,
                    deny_group,
                    Duration::from_millis(40)
                )
                .is_err()
            );
            assert!(started.elapsed() < Duration::from_millis(500));
            assert!(!marker.exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unrelated_einval_is_not_a_group_probe_failure() {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("true");
        unsafe {
            command.pre_exec(|| Err(std::io::Error::from_raw_os_error(libc::EINVAL)));
        }
        let error = spawn_with_group_handle(&mut command, false, false, Duration::from_millis(50))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn group_probe_marker_is_distinct_from_other_errors() {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        if pidfd < 0 {
            let error = std::io::Error::last_os_error();
            assert!(matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EPERM | libc::EACCES)
            ));
            return;
        }
        unsafe { libc::close(pidfd as libc::c_int) };
        let mut command = Command::new("true");
        let error = spawn_with_group_handle(&mut command, false, true, Duration::from_millis(200))
            .unwrap_err();
        assert!(
            error
                .get_ref()
                .is_some_and(|error| error.is::<GroupProbeUnsupported>())
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn delayed_probe_fixture(
        test_name: &str,
        external_reaper: bool,
        deny_sendmsg: bool,
        deny_recvmsg: Option<i32>,
    ) {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "CODEX_WAKE_TEST_DELAYED_PROBE";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("pr_ci_runtime::tests::{test_name}"),
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        DELAY_GROUP_PROBE_IN_TEST.store(true, Ordering::Relaxed);
        REAP_GROUP_PROBE_IN_TEST.store(external_reaper, Ordering::Relaxed);
        if deny_sendmsg {
            deny_test_syscall(libc::SYS_sendmsg);
        }
        if let Some(errno) = deny_recvmsg {
            deny_test_syscall_with_errno(libc::SYS_recvmsg, errno);
        }
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("gh");
        let marker = dir.path().join("executed");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = Command::new(executable);
        let error = spawn_with_group_handle(&mut command, false, true, Duration::from_millis(20))
            .unwrap_err();
        if external_reaper {
            assert!(error.to_string().contains("cleanup uncertain"));
        } else if deny_sendmsg {
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        } else if deny_recvmsg.is_some() {
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
        } else {
            assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
        }
        let typed = anyhow::Error::new(error);
        assert_eq!(
            typed
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>()),
            external_reaper
        );
        assert!(!marker.exists());
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn timed_out_probe_is_reaped() {
        delayed_probe_fixture("timed_out_probe_is_reaped", false, false, None);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn timed_out_probe_reaped_externally_is_uncertain() {
        delayed_probe_fixture(
            "timed_out_probe_reaped_externally_is_uncertain",
            true,
            false,
            None,
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn timed_out_probe_with_failed_transfer_is_reaped() {
        delayed_probe_fixture(
            "timed_out_probe_with_failed_transfer_is_reaped",
            false,
            true,
            None,
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn timed_out_probe_with_recvmsg_denied_is_reaped() {
        delayed_probe_fixture(
            "timed_out_probe_with_recvmsg_denied_is_reaped",
            false,
            false,
            Some(libc::EPERM),
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn timed_out_probe_with_recvmsg_eagain_is_reaped() {
        delayed_probe_fixture(
            "timed_out_probe_with_recvmsg_eagain_is_reaped",
            false,
            false,
            Some(libc::EAGAIN),
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn probe_receiver_finishes_if_spawn_unwinds() {
        const CHILD: &str = "CODEX_WAKE_TEST_PROBE_SPAWN_UNWIND";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "pr_ci_runtime::tests::probe_receiver_finishes_if_spawn_unwinds",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
        TRACK_RECEIVER_IN_TEST.store(true, Ordering::Release);
        let result = std::panic::catch_unwind(|| {
            spawn_with_group_handle(
                &mut Command::new("true"),
                true,
                false,
                Duration::from_millis(20),
            )
        });
        assert!(!matches!(result, Ok(Ok(_))));
        let deadline = Instant::now() + Duration::from_secs(2);
        while (!RECEIVER_STARTED_IN_TEST.load(Ordering::Acquire)
            || !RECEIVER_FINISHED_IN_TEST.load(Ordering::Acquire))
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(RECEIVER_STARTED_IN_TEST.load(Ordering::Acquire));
        assert!(RECEIVER_FINISHED_IN_TEST.load(Ordering::Acquire));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn group_probe_marker_rejects_truncated_datagrams() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram;

        let (sender, receiver) = UnixDatagram::pair().unwrap();
        sender.send(&[UNSUPPORTED_GROUP_PROBE, 0]).unwrap();
        assert!(matches!(
            receive_group_handle(OwnedFd::from(receiver), 200, ProbeMapping::new().unwrap()),
            GroupReceipt::Invalid
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn probe_sent_after_empty_poll_is_not_treated_as_failed() {
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::net::UnixDatagram;

        const CHILD: &str = "CODEX_WAKE_TEST_PROBE_POLL_RACE";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "pr_ci_runtime::tests::probe_sent_after_empty_poll_is_not_treated_as_failed",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let shared = ProbeMapping::new().unwrap();
        PAUSE_AFTER_EMPTY_PROBE_POLL.store(true, Ordering::Release);
        let receiver_shared = Arc::clone(&shared);
        let receiver_thread = thread::spawn(move || {
            receive_group_handle(OwnedFd::from(receiver), 1000, receiver_shared)
        });
        while PAUSE_AFTER_EMPTY_PROBE_POLL.load(Ordering::Acquire) {
            thread::yield_now();
        }
        let file = std::fs::File::open("/dev/null").unwrap();
        let mut byte = UNSUPPORTED_GROUP_PROBE;
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0_usize; 8];
        unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(
                libc::CMSG_DATA(header).cast::<libc::c_int>(),
                file.as_raw_fd(),
            );
            assert_eq!(libc::sendmsg(sender.as_raw_fd(), &message, 0), 1);
        }
        shared
            .state()
            .pid
            .store(std::process::id() as i32, Ordering::Relaxed);
        shared.state().error.store(0, Ordering::Relaxed);
        shared.state().phase.store(PROBE_REQUEST, Ordering::Release);
        assert!(matches!(
            receiver_thread.join().unwrap(),
            GroupReceipt::ProbeUnsupported(_)
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_group_probe_runs_gh_once_with_real_arguments() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("gh");
        let args_file = directory.path().join("args");
        let calls_file = directory.path().join("calls");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf 'x' >> '{}'\nprintf '{{\"number\":7}}'\n",
                args_file.display(), calls_file.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let route = "/repos/owner/project/pulls/7";
        let result = gh_api_with_probe(&program, route, Duration::from_secs(3), true).unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.body["number"], 7);
        assert_eq!(std::fs::read_to_string(calls_file).unwrap(), "x");
        assert_eq!(
            std::fs::read_to_string(args_file).unwrap(),
            format!(
                "api\n--jq\n{}\n{route}\n",
                gh_response_filter(route).unwrap()
            )
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn automatic_group_probe_runs_gh() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("gh");
        std::fs::write(&program, "#!/bin/sh\nprintf '{\"number\":7}'\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = gh_api_with_timeout(
            &program,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(result.body["number"], 7);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_group_probe_preserves_timeout_and_uncertainty() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("gh");
        std::fs::write(&program, "#!/bin/sh\nsleep 10\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let started = Instant::now();
        let error = gh_api_with_probe(
            &program,
            "/repos/owner/project/pulls/7",
            Duration::from_millis(100),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(error.to_string().contains("cleanup uncertain"));
        assert!(
            error
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>())
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn legacy_deadline_before_spawn_has_no_cleanup_uncertainty() {
        let error = legacy::gh_api(
            Path::new("/nonexistent-gh"),
            "/repos/owner/project/pulls/7",
            ".",
            Instant::now(),
        )
        .unwrap_err();
        assert!(
            !error
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>())
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn legacy_missing_executable_with_confirmed_cleanup_is_not_uncertain() {
        let error = gh_api_with_probe(
            Path::new("/codex-wake-nonexistent-gh"),
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("Start gh failed"));
        assert!(
            !error
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>())
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_group_probe_preserves_output_limit() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("gh");
        std::fs::write(&program, "#!/bin/sh\nhead -c 1048577 /dev/zero\nsleep 10\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = gh_api_with_probe(
            &program,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("output exceeded"));
        assert!(error.to_string().contains("cleanup uncertain"));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn deny_test_syscall(number: libc::c_long) {
        deny_test_syscall_with_errno(number, libc::EPERM);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn deny_test_syscall_with_errno(number: libc::c_long, errno: i32) {
        let filter = [
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: number as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | errno as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_group_probe_reports_denied_waitid() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "CODEX_WAKE_TEST_DENIED_WAITID_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("pr_ci_runtime::tests::unsupported_group_probe_reports_denied_waitid")
                .arg("--test-threads=1")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "denied-waitid fixture failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains(
                "test pr_ci_runtime::tests::unsupported_group_probe_reports_denied_waitid ... ok"
            ));
            return;
        }
        deny_test_syscall(libc::SYS_waitid);
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("gh");
        std::fs::write(&executable, "#!/bin/sh\nprintf '{\"number\":7}'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = gh_api_with_probe(
            &executable,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cleanup uncertain"));
        assert!(error.to_string().contains("waitid"));
        assert!(
            error
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>())
        );
        let mut db = Connection::open_in_memory().unwrap();
        crate::pr_ci::register(
            &mut db,
            "owner/repo",
            "7",
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        let report = crate::pr_ci::poll(&db, 1, |route| {
            gh_api_with_probe(&executable, route, Duration::from_secs(3), true)
        })
        .unwrap();
        assert_eq!(report.errors, ["owner/repo#7: process_cleanup_uncertain"]);
        let stored: String = db
            .query_row("SELECT error FROM pr_ci_trackers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored, "process_cleanup_uncertain");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_group_probe_reports_external_reaping() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "CODEX_WAKE_TEST_EXTERNAL_REAP_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("pr_ci_runtime::tests::unsupported_group_probe_reports_external_reaping")
                .arg("--test-threads=1")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "external-reaper fixture failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains(
                "test pr_ci_runtime::tests::unsupported_group_probe_reports_external_reaping ... ok"
            ));
            return;
        }
        assert_ne!(
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) },
            libc::SIG_ERR
        );
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("gh");
        std::fs::write(&executable, "#!/bin/sh\nprintf '{\"number\":7}'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = gh_api_with_probe(
            &executable,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cleanup uncertain"));
        assert!(error.to_string().contains("waitid"));
        assert!(
            error
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>())
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_group_probe_reports_concurrent_reaping() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "CODEX_WAKE_TEST_CONCURRENT_REAP_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("pr_ci_runtime::tests::unsupported_group_probe_reports_concurrent_reaping")
                .arg("--test-threads=1")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success());
            assert!(String::from_utf8_lossy(&output.stdout).contains(
                "test pr_ci_runtime::tests::unsupported_group_probe_reports_concurrent_reaping ... ok"
            ));
            return;
        }
        REAP_GROUP_PROBE_IN_TEST.store(true, Ordering::Relaxed);
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("gh");
        let marker = directory.path().join("executed");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = gh_api_with_probe(
            &executable,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cleanup uncertain"));
        assert!(error.to_string().contains("waitid"));
        assert!(!marker.exists());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn sendmsg_failure_fixture(test_name: &str, external_reaper: bool, deny_sendto: bool) {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "CODEX_WAKE_TEST_SENDMSG_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let full_name = format!("pr_ci_runtime::tests::{test_name}");
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(&full_name)
                .arg("--test-threads=1")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "sendmsg fixture failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains(&format!("test {full_name} ... ok"))
            );
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("gh");
        let marker = directory.path().join("executed");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        if external_reaper {
            REAP_GROUP_PROBE_IN_TEST.store(true, Ordering::Relaxed);
        }
        deny_test_syscall(libc::SYS_sendmsg);
        if deny_sendto {
            deny_test_syscall(libc::SYS_sendto);
        }
        let error = gh_api_with_probe(
            &executable,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        if external_reaper {
            assert!(error.to_string().contains("cleanup uncertain"));
            assert!(error.to_string().contains("waitid"));
        } else {
            assert!(error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error)
                    == Some(libc::EPERM)
            }));
        }
        assert!(!marker.exists());
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result =
            unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG) };
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn failed_probe_sendmsg_is_reaped_without_running_gh() {
        sendmsg_failure_fixture(
            "failed_probe_sendmsg_is_reaped_without_running_gh",
            false,
            false,
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn failed_probe_sendmsg_after_external_reaping_is_uncertain() {
        sendmsg_failure_fixture(
            "failed_probe_sendmsg_after_external_reaping_is_uncertain",
            true,
            false,
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn failed_probe_sends_are_reaped_without_running_gh() {
        sendmsg_failure_fixture(
            "failed_probe_sends_are_reaped_without_running_gh",
            false,
            true,
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn failed_probe_sends_after_external_reaping_are_uncertain() {
        sendmsg_failure_fixture(
            "failed_probe_sends_after_external_reaping_are_uncertain",
            true,
            true,
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn truncated_probe_transfer_is_reaped_without_running_gh() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "CODEX_WAKE_TEST_TRUNCATED_PROBE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("pr_ci_runtime::tests::truncated_probe_transfer_is_reaped_without_running_gh")
                .arg("--test-threads=1")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains(
                "test pr_ci_runtime::tests::truncated_probe_transfer_is_reaped_without_running_gh ... ok"
            ));
            return;
        }
        TRUNCATE_GROUP_PROBE_IN_TEST.store(true, Ordering::Relaxed);
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("gh");
        let marker = directory.path().join("executed");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = gh_api_with_probe(
            &executable,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error)
                == Some(libc::EIO)
        }));
        assert!(!marker.exists());
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_group_probe_reports_failed_guardian_after_release() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD: &str = "CODEX_WAKE_TEST_FAILED_GUARD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("pr_ci_runtime::tests::unsupported_group_probe_reports_failed_guardian_after_release")
                .arg("--test-threads=1")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success());
            assert!(String::from_utf8_lossy(&output.stdout).contains(
                "test pr_ci_runtime::tests::unsupported_group_probe_reports_failed_guardian_after_release ... ok"
            ));
            return;
        }
        legacy::fail_guard_after_release_for_test();
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("gh");
        std::fs::write(&executable, "#!/bin/sh\nprintf '{\"number\":7}'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = gh_api_with_probe(
            &executable,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cleanup uncertain"));
        assert!(
            error
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>())
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_group_probe_distinguishes_gh_exit_120() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("gh");
        std::fs::write(&executable, "#!/bin/sh\nprintf 'gh exit' >&2\nexit 120\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = gh_api_with_probe(
            &executable,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(3),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("gh exit"));
        assert!(!error.to_string().contains("cleanup uncertain"));
        assert!(
            !error
                .chain()
                .any(|cause| cause.is::<crate::pr_ci::ProcessCleanupUncertain>())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn truncated_group_rights_are_closed() {
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::net::UnixDatagram;

        const CHILD: &str = "CODEX_WAKE_TEST_TRUNCATED_RIGHTS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("pr_ci_runtime::tests::truncated_group_rights_are_closed")
                .arg("--test-threads=1")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(
                    "test pr_ci_runtime::tests::truncated_group_rights_are_closed ... ok"
                )
            );
            return;
        }

        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let count = || {
            (3..1024)
                .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
                .count()
        };
        let before = count();
        let descriptors = [file.as_raw_fd(); 24];
        let mut control = [0_usize; 32];
        let mut byte = 0_u8;
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                libc::CMSG_SPACE(std::mem::size_of_val(&descriptors) as u32) as _;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(&descriptors) as u32) as _;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr(),
                libc::CMSG_DATA(header).cast(),
                descriptors.len(),
            );
            assert_eq!(libc::sendmsg(sender.as_raw_fd(), &message, 0), 1);
        }
        assert!(matches!(
            receive_group_handle(OwnedFd::from(receiver), 200, ProbeMapping::new().unwrap()),
            GroupReceipt::Invalid
        ));
        assert_eq!(count() + 1, before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejected_group_signal_stops_exact_leader_and_reports_incomplete() {
        let mut command = Command::new("sleep");
        command.arg("10");
        let (mut child, handle) =
            spawn_with_group_handle(&mut command, false, false, Duration::from_secs(2)).unwrap();
        let error = terminate_process_group_with(&mut child, &handle, true).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gh_output_limit_stops_process_group() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let wrapper = directory.path().join("gh-wrapper");
        fs::write(&wrapper, "#!/bin/sh\nhead -c 1048577 /dev/zero\nsleep 10\n").unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let started = Instant::now();
        let error = gh_api_with_timeout(
            &wrapper,
            "/repos/owner/project/pulls/7",
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(error.to_string().contains("output exceeded"));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gh_keeps_exited_group_leader_until_pipe_cleanup() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let wrapper = directory.path().join("gh-wrapper");
        let leader_file = directory.path().join("leader.pid");
        let escaped_file = directory.path().join("escaped.pid");
        let release_file = directory.path().join("release");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nsetsid sh -c 'echo $$ > \"$1\"; i=0; while [ ! -e \"$2\" ] && [ \"$i\" -lt 240 ]; do i=$((i+1)); sleep 0.05; done' sh '{}' '{}' &\nwhile [ ! -s '{}' ]; do sleep 0.01; done\nprintf '{{}}'\nexit 0\n",
                leader_file.display(), escaped_file.display(), release_file.display(), escaped_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let worker = thread::spawn(move || {
            gh_api_with_timeout(
                &wrapper,
                "/repos/owner/project/pulls/7",
                Duration::from_secs(10),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut reserved = false;
        let mut last_stat = None;
        while Instant::now() < deadline {
            if let Ok(pid) = fs::read_to_string(&leader_file)
                && let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
            {
                reserved = stat
                    .split_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with("Z "));
                last_stat = Some(stat);
                if reserved {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        fs::write(release_file, "release").unwrap();
        let result = worker.join().unwrap();
        let escaped = fs::read_to_string(escaped_file);
        assert!(
            reserved,
            "exited leader must remain unreaped until cleanup; worker={result:?}; leader={:?}; escaped={escaped:?}; last_stat={last_stat:?}",
            fs::read_to_string(leader_file),
        );
        assert!(
            result.is_ok(),
            "worker should finish after release: {result:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gh_deadline_cancels_readers_held_open_by_setsid_descendant() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let wrapper = directory.path().join("gh-wrapper");
        let pid_file = directory.path().join("escaped-child.pid");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nsetsid sh -c 'echo $$ > {}; exec sleep 10' &\nwhile [ ! -s '{}' ]; do sleep 0.01; done\nexit 0\n",
                pid_file.display(),
                pid_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();

        let started = Instant::now();
        let result = gh_api_with_timeout(
            &wrapper,
            "/repos/owner/project/pulls/7",
            Duration::from_millis(100),
        );
        let elapsed = started.elapsed();
        if let Ok(pid) = fs::read_to_string(pid_file) {
            let _ = Command::new("kill").arg("-KILL").arg(pid.trim()).status();
        }
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(elapsed < Duration::from_secs(2));
    }
}
