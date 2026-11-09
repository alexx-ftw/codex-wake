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

#[derive(Debug)]
struct BeforeSendFailure(anyhow::Error);

impl fmt::Display for BeforeSendFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Delivery preparation failed before queue submission: {}",
            self.0
        )
    }
}

impl Error for BeforeSendFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Mark an error from delivery preparation that occurs before any queue request.
pub fn before_send_failure(error: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(BeforeSendFailure(error))
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
    Ok(ids)
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
             WHERE next_attempt_ms<=?1 ORDER BY next_attempt_ms,thread LIMIT ?2",
        )?;
        statement
            .query_map([now_ms, WAKE_RETRY_BATCH], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
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
        let ids = native_wake_ids(raw.as_deref())?;
        if !ids.client_ids.is_empty() && wake(&thread, &ids.client_ids).is_ok() && !ids.unattributed
        {
            recovered += db.execute(
                "DELETE FROM native_wake_recovery
                 WHERE thread=?1 AND revision=?2 AND client_ids_json=?3",
                rusqlite::params![thread, revision, raw],
            )?;
        }
    }
    Ok(recovered)
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
        ". as $pr | {number, state, base:{repo:{full_name:$pr.base.repo.full_name}}, head:{sha:$pr.head.sha, repo:{full_name:$pr.head.repo.full_name}}}"
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
    let mut child = command
        .arg("api")
        .arg("--jq")
        .arg(filter)
        .arg(route)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Start {}", gh_executable.display()))?;

    let exceeded = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().context("Capture gh stdout")?;
    let stderr = child.stderr.take().context("Capture gh stderr")?;
    #[cfg(unix)]
    if let Err(error) = set_pipe_nonblocking(&stdout).and_then(|()| set_pipe_nonblocking(&stderr)) {
        terminate_process_group(&mut child);
        return Err(error).context("Set GitHub CLI pipes nonblocking");
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
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut timed_out = false;
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
        if output.is_some()
            && diagnostics.is_some()
            && let Some(exit) = child.try_wait().context("Check gh process")?
        {
            status = Some(exit);
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if timed_out || exceeded.load(Ordering::Relaxed) {
        cancelled.store(true, Ordering::Relaxed);
        terminate_process_group(&mut child);
    }
    let output = output
        .unwrap_or_else(|| stdout_reader.unwrap().join())
        .map_err(|_| anyhow::anyhow!("gh stdout reader panicked"))??;
    let diagnostics = diagnostics
        .unwrap_or_else(|| stderr_reader.unwrap().join())
        .map_err(|_| anyhow::anyhow!("gh stderr reader panicked"))??;
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

fn terminate_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        let process_group = child.id() as libc::pid_t;
        libc::kill(-process_group, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
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
                if pr_ci::retry_delivery(db, delivery.id, now())? {
                    report.retried_before_send += 1;
                } else {
                    report.uncertain += 1;
                }
            }
            Err(error) if known_before_send_failure(&error) => {
                if pr_ci::retry_delivery(db, delivery.id, now())? {
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

fn known_before_send_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<BeforeSendFailure>().is_some()
            || matches!(
                cause.to_string().as_str(),
                "Target unavailable during preparation; input was not sent"
                    | "Target thread has an active writer; input was not sent"
            )
    })
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
    use rusqlite::params;

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
        use std::{error::Error, fmt};

        #[derive(Clone, Copy, Debug)]
        enum BeforeSend {
            Unavailable,
            Busy,
        }

        impl fmt::Display for BeforeSend {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    Self::Unavailable => {
                        "Target unavailable during preparation; input was not sent"
                    }
                    Self::Busy => "Target thread has an active writer; input was not sent",
                })
            }
        }

        impl Error for BeforeSend {}

        for marker in [BeforeSend::Unavailable, BeforeSend::Busy] {
            let mut db = database();
            let report = dispatch_at(&mut db, 1_000, |_, _, _| {
                Err(anyhow::anyhow!("preparation failed").context(marker))
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
            Err(anyhow::anyhow!(
                "Target thread has an active writer; input was not sent"
            ))
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
                Err(anyhow::anyhow!(
                    "Target thread has an active writer; input was not sent"
                ))
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
        assert_eq!(ids.client_ids, vec![id]);
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
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nsetsid sh -c 'echo $$ > {}; exec sleep 10' &\nwhile [ ! -s '{}' ]; do sleep 0.01; done\nexit 0\n",
                leader_file.display(), escaped_file.display(), escaped_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let worker = thread::spawn(move || {
            gh_api_with_timeout(
                &wrapper,
                "/repos/owner/project/pulls/7",
                Duration::from_secs(2),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut reserved = false;
        while Instant::now() < deadline {
            if let Ok(pid) = fs::read_to_string(&leader_file)
                && let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
                && stat
                    .split_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with("Z "))
            {
                reserved = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let result = worker.join().unwrap();
        if let Ok(pid) = fs::read_to_string(escaped_file) {
            let _ = Command::new("kill").arg("-KILL").arg(pid.trim()).status();
        }
        assert!(reserved, "exited leader must remain unreaped until cleanup");
        assert!(result.unwrap_err().to_string().contains("timed out"));
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
