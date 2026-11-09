//! Durable, Actions-only CI tracking for a pull request.
//!
//! A caller registers the PR, periodically calls [`poll`] with its GitHub REST
//! transport, then delivers rows claimed by [`claim_deliveries`]. This state
//! is independent of the exact-run `waits` table.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};
use uuid::Uuid;

const POLL_MS: i64 = 60_000;
const MAX_BACKOFF_MS: i64 = 3_600_000;
// Each invocation atomically claims and advances one registration.
const RUNS_PER_PAGE: usize = 100;
const MAX_RUN_PAGES: usize = 10;
const MAX_RECORDED_ATTEMPT_GAP: i64 = 50;
const DELIVERY_RETRY_DELAY_MS: i64 = 5_000;
const TRACKERS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS pr_ci_trackers (
    repo TEXT NOT NULL, pull_number INTEGER NOT NULL, thread TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    head_sha TEXT, next_poll_ms INTEGER NOT NULL DEFAULT 0,
    backoff_ms INTEGER NOT NULL DEFAULT 60000, error TEXT,
    updated_at_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(repo,pull_number,thread)
);";
const DELIVERIES_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS pr_ci_deliveries (
    id INTEGER PRIMARY KEY, repo TEXT NOT NULL, pull_number INTEGER NOT NULL,
    sha TEXT NOT NULL, run_id INTEGER NOT NULL, attempt INTEGER NOT NULL,
    thread TEXT NOT NULL, conclusion TEXT NOT NULL, source_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK(state IN ('pending','claimed','delivered','needs_attention')),
    lease_until_ms INTEGER,
    UNIQUE(repo,pull_number,sha,run_id,attempt,thread)
);";
const CLOSED_TRACKERS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS pr_ci_auto_closed_trackers (
    repo TEXT NOT NULL, pull_number INTEGER NOT NULL, thread TEXT NOT NULL,
    PRIMARY KEY(repo,pull_number,thread)
);";
const REOPEN_EVENTS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS pr_ci_reopen_events (
    notification_id TEXT PRIMARY KEY, consumed_at_ms INTEGER NOT NULL
);";
const PR_OBSERVATIONS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS pr_ci_pr_observations (
    repo TEXT NOT NULL, pull_number INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open','closed')),
    observed_at_ms INTEGER NOT NULL,
    PRIMARY KEY(repo,pull_number)
);";
const TRACKER_GENERATIONS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS pr_ci_tracker_generations (
    repo TEXT NOT NULL, pull_number INTEGER NOT NULL, thread TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0, closed_sweep_generation INTEGER,
    PRIMARY KEY(repo,pull_number,thread)
);";
const PR_CI_MIGRATIONS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS pr_ci_schema_migrations (
    name TEXT PRIMARY KEY
);";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Delivery {
    pub id: i64,
    pub thread: String,
    pub repo: String,
    pub pull_request: i64,
    pub sha: String,
    pub run_id: i64,
    pub attempt: i64,
    pub conclusion: String,
    pub source: Value,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PollReport {
    pub checked: usize,
    pub discovered: usize,
    pub queued: usize,
    /// Runs matching this PR's head SHA that GitHub did not link to a PR.
    /// They are intentionally not attributed or delivered.
    pub unlinked_runs: usize,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryResolution {
    Accepted,
    DefinitelyNotAccepted,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UncertainDelivery {
    pub delivery: Delivery,
    pub lease_expired_at_ms: i64,
}

/// A read-only response from the caller's GitHub REST transport.
#[derive(Clone, Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Value,
}

#[derive(Clone, Copy)]
struct RunPollIdentity<'a> {
    repo: &'a str,
    pull_request: i64,
    sha: &'a str,
}

/// Create the isolated PR tracking schema. Safe to call on each connection.
pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(TRACKERS_SCHEMA)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS pr_ci_runs (
            repo TEXT NOT NULL, pull_number INTEGER NOT NULL, sha TEXT NOT NULL,
            run_id INTEGER NOT NULL, attempt INTEGER NOT NULL,
            status TEXT NOT NULL, conclusion TEXT, source_json TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            PRIMARY KEY(repo,pull_number,sha,run_id,attempt)
        );",
    )?;
    db.execute_batch(DELIVERIES_SCHEMA)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS pr_ci_delivery_retry_after (
            delivery_id INTEGER PRIMARY KEY,
            available_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS pr_ci_delivery_retry_due
            ON pr_ci_delivery_retry_after(available_at_ms,delivery_id);",
    )?;
    db.execute_batch(CLOSED_TRACKERS_SCHEMA)?;
    db.execute_batch(REOPEN_EVENTS_SCHEMA)?;
    db.execute_batch(PR_OBSERVATIONS_SCHEMA)?;
    db.execute_batch(TRACKER_GENERATIONS_SCHEMA)?;
    db.execute_batch(PR_CI_MIGRATIONS_SCHEMA)?;
    backfill_tracker_generations_once(db)?;
    db.execute_batch(
        "CREATE INDEX IF NOT EXISTS pr_ci_due ON pr_ci_trackers(active,next_poll_ms);
         CREATE INDEX IF NOT EXISTS pr_ci_delivery_queue ON pr_ci_deliveries(state,id);
         CREATE INDEX IF NOT EXISTS pr_ci_delivery_lease ON pr_ci_deliveries(state,lease_until_ms);",
    )?;
    Ok(())
}

fn backfill_tracker_generations_once(db: &Connection) -> Result<()> {
    let complete: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pr_ci_schema_migrations
         WHERE name='tracker_generations_v1')",
        [],
        |row| row.get(0),
    )?;
    if complete {
        return Ok(());
    }
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        backfill_tracker_generations_in(&tx)?;
        tx.commit()?;
    } else {
        backfill_tracker_generations_in(db)?;
    }
    Ok(())
}

fn backfill_tracker_generations_in(db: &Connection) -> Result<()> {
    let complete: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pr_ci_schema_migrations
         WHERE name='tracker_generations_v1')",
        [],
        |row| row.get(0),
    )?;
    if !complete {
        db.execute(
            "INSERT OR IGNORE INTO pr_ci_tracker_generations(repo,pull_number,thread)
             SELECT repo,pull_number,thread FROM pr_ci_trackers",
            [],
        )?;
        db.execute(
            "INSERT INTO pr_ci_schema_migrations(name) VALUES('tracker_generations_v1')",
            [],
        )?;
    }
    Ok(())
}

/// Subscribe one chat to a PR's CI. Registration is idempotent per chat and
/// supports fanout without changing other subscribers' polling state.
pub fn register(db: &mut Connection, repo: &str, number: &str, thread: &str) -> Result<bool> {
    parse_number(number)?;
    ensure!(valid_repo(repo), "Invalid repository");
    let thread = Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string();
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let inserted = register_in(&tx, repo, number, &thread)?;
    tx.commit()?;
    Ok(inserted)
}

/// Register a PR inside a caller-owned transaction, for atomic integration
/// with PR subscriptions and comment rules.
pub fn register_in(db: &Connection, repo: &str, number: &str, thread: &str) -> Result<bool> {
    let number = parse_number(number)?;
    initialize(db)?;
    ensure!(valid_repo(repo), "Invalid repository");
    let repo = repo.to_ascii_lowercase();
    let thread = Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string();
    let inserted = db.execute(
        "INSERT OR IGNORE INTO pr_ci_trackers(repo,pull_number,thread) VALUES(?1,?2,?3)",
        params![repo, number, thread],
    )? != 0;
    db.execute(
        "UPDATE pr_ci_trackers SET active=1 WHERE repo=?1 AND pull_number=?2 AND thread=?3",
        params![repo, number, thread],
    )?;
    db.execute(
        "DELETE FROM pr_ci_auto_closed_trackers
         WHERE repo=?1 AND pull_number=?2 AND thread=?3",
        params![repo, number, thread],
    )?;
    db.execute(
        "INSERT OR IGNORE INTO pr_ci_tracker_generations(repo,pull_number,thread)
         VALUES(?1,?2,?3)",
        params![repo, number, thread],
    )?;
    db.execute(
        "UPDATE pr_ci_tracker_generations SET generation=generation+1,
             closed_sweep_generation=NULL
         WHERE repo=?1 AND pull_number=?2 AND thread=?3",
        params![repo, number, thread],
    )?;
    Ok(inserted)
}

/// Stop tracking without deleting run history or unclaimed deliveries.
pub fn unregister(db: &Connection, repo: &str, number: &str, thread: &str) -> Result<bool> {
    initialize(db)?;
    let number = parse_number(number)?;
    ensure!(valid_repo(repo), "Invalid repository");
    let repo = repo.to_ascii_lowercase();
    let thread = Uuid::parse_str(thread)?.to_string();
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE pr_ci_trackers SET active=0 WHERE repo=?1 AND pull_number=?2 AND thread=?3",
        params![repo, number, thread],
    )?;
    let cleared_auto_close = tx.execute(
        "DELETE FROM pr_ci_auto_closed_trackers
         WHERE repo=?1 AND pull_number=?2 AND thread=?3",
        params![repo, number, thread],
    )?;
    tx.execute(
        "UPDATE pr_ci_tracker_generations SET generation=generation+1,
             closed_sweep_generation=NULL
         WHERE repo=?1 AND pull_number=?2 AND thread=?3",
        params![repo, number, thread],
    )?;
    tx.commit()?;
    Ok(changed != 0 || cleared_auto_close != 0)
}

/// Apply the latest validated PR state from the ordinary PR poller.
/// `observed_at_ms` orders concurrent responses so a late stale `closed`
/// snapshot cannot overwrite a newer `open` observation. This PR-poller-owned
/// reconciliation pauses a closed PR only after CI records a successful sweep
/// for the current tracker generation and no observed run remains nonterminal.
pub fn observe_pull_request_state_in(
    db: &Connection,
    repo: &str,
    number: &str,
    state: &str,
    observed_at_ms: i64,
) -> Result<bool> {
    initialize(db)?;
    ensure!(
        matches!(state, "open" | "closed"),
        "Invalid pull request state"
    );
    let number = parse_number(number)?;
    ensure!(valid_repo(repo), "Invalid repository");
    let repo = repo.to_ascii_lowercase();
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let changed = observe_pull_request_state_tx(&tx, &repo, number, state, observed_at_ms)?;
        tx.commit()?;
        Ok(changed)
    } else {
        observe_pull_request_state_tx(db, &repo, number, state, observed_at_ms)
    }
}

fn observe_pull_request_state_tx(
    db: &Connection,
    repo: &str,
    number: i64,
    state: &str,
    observed_at_ms: i64,
) -> Result<bool> {
    let previous_state: Option<String> = db
        .query_row(
            "SELECT state FROM pr_ci_pr_observations WHERE repo=?1 AND pull_number=?2",
            params![repo, number],
            |row| row.get(0),
        )
        .optional()?;
    let observed = db.execute(
        "INSERT INTO pr_ci_pr_observations(repo,pull_number,state,observed_at_ms)
         VALUES(?1,?2,?3,?4)
         ON CONFLICT(repo,pull_number) DO UPDATE SET
             state=excluded.state,observed_at_ms=excluded.observed_at_ms
         WHERE excluded.observed_at_ms>pr_ci_pr_observations.observed_at_ms
            OR (excluded.observed_at_ms=pr_ci_pr_observations.observed_at_ms
                AND excluded.state='open' AND pr_ci_pr_observations.state='closed')",
        params![repo, number, state, observed_at_ms],
    )?;
    if observed == 0 {
        let current_state: Option<String> = db
            .query_row(
                "SELECT state FROM pr_ci_pr_observations WHERE repo=?1 AND pull_number=?2",
                params![repo, number],
                |row| row.get(0),
            )
            .optional()?;
        if current_state.as_deref() != Some(state) {
            return Ok(false);
        }
    }
    if previous_state.as_deref() != Some(state) && observed != 0 {
        db.execute(
            "UPDATE pr_ci_tracker_generations SET generation=generation+1,
                 closed_sweep_generation=NULL
             WHERE repo=?1 AND pull_number=?2",
            params![repo, number],
        )?;
    }
    if state == "open" {
        if previous_state.as_deref() == Some("closed") && observed != 0 {
            db.execute(
                "UPDATE pr_ci_trackers SET next_poll_ms=0,backoff_ms=60000,
                     error=NULL,updated_at_ms=?1
                 WHERE repo=?2 AND pull_number=?3 AND active=1",
                params![observed_at_ms, repo, number],
            )?;
        }
        db.execute(
            "UPDATE pr_ci_trackers SET active=1,next_poll_ms=0,backoff_ms=60000,
                 error=NULL,updated_at_ms=?1
             WHERE repo=?2 AND pull_number=?3 AND active=0 AND EXISTS(
                 SELECT 1 FROM pr_ci_auto_closed_trackers AS closed
                 WHERE closed.repo=pr_ci_trackers.repo
                   AND closed.pull_number=pr_ci_trackers.pull_number
                   AND closed.thread=pr_ci_trackers.thread)",
            params![observed_at_ms, repo, number],
        )?;
        db.execute(
            "DELETE FROM pr_ci_auto_closed_trackers WHERE repo=?1 AND pull_number=?2",
            params![repo, number],
        )?;
    } else {
        let pending_runs: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pr_ci_runs
             WHERE repo=?1 AND pull_number=?2 AND status!='completed')",
            params![repo, number],
            |row| row.get(0),
        )?;
        if !pending_runs {
            db.execute(
                "INSERT OR IGNORE INTO pr_ci_auto_closed_trackers(repo,pull_number,thread)
                 SELECT tracker.repo,tracker.pull_number,tracker.thread
                 FROM pr_ci_trackers AS tracker
                 JOIN pr_ci_tracker_generations AS generation
                   USING(repo,pull_number,thread)
                 WHERE tracker.repo=?1 AND tracker.pull_number=?2 AND tracker.active=1
                   AND generation.closed_sweep_generation=generation.generation",
                params![repo, number],
            )?;
            db.execute(
                "UPDATE pr_ci_tracker_generations SET generation=generation+1,
                     closed_sweep_generation=NULL
                 WHERE repo=?1 AND pull_number=?2 AND EXISTS(
                   SELECT 1 FROM pr_ci_auto_closed_trackers AS closed
                   WHERE closed.repo=pr_ci_tracker_generations.repo
                     AND closed.pull_number=pr_ci_tracker_generations.pull_number
                     AND closed.thread=pr_ci_tracker_generations.thread)
                   AND EXISTS(SELECT 1 FROM pr_ci_trackers AS tracker
                     WHERE tracker.repo=pr_ci_tracker_generations.repo
                       AND tracker.pull_number=pr_ci_tracker_generations.pull_number
                       AND tracker.thread=pr_ci_tracker_generations.thread
                       AND tracker.active=1)",
                params![repo, number],
            )?;
            db.execute(
                "UPDATE pr_ci_trackers SET active=0,error=NULL,updated_at_ms=?1
                 WHERE repo=?2 AND pull_number=?3 AND active=1 AND EXISTS(
                   SELECT 1 FROM pr_ci_auto_closed_trackers AS closed
                   WHERE closed.repo=pr_ci_trackers.repo
                     AND closed.pull_number=pr_ci_trackers.pull_number
                     AND closed.thread=pr_ci_trackers.thread)",
                params![observed_at_ms, repo, number],
            )?;
        }
    }
    Ok(observed != 0)
}

/// Consume a durable `reopened` notification by its ID after inserting it into
/// `automatic_pr_notifications`. Call this from the same transaction as the
/// notification insert when possible. Explicitly unregistered trackers remain
/// inactive because `observe_pull_request_state_in` only resumes auto-closed
/// trackers.
pub fn consume_reopened_notification_in(
    db: &Connection,
    notification_id: &str,
    observed_at_ms: i64,
) -> Result<bool> {
    initialize(db)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let consumed = consume_reopened_notification_tx(&tx, notification_id, observed_at_ms)?;
        tx.commit()?;
        Ok(consumed)
    } else {
        consume_reopened_notification_tx(db, notification_id, observed_at_ms)
    }
}

fn consume_reopened_notification_tx(
    db: &Connection,
    notification_id: &str,
    observed_at_ms: i64,
) -> Result<bool> {
    let Some((repo, number)) = db
        .query_row(
            "SELECT repo,pr FROM automatic_pr_notifications
             WHERE id=?1 AND kind='pull_request' AND event='reopened'",
            [notification_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    else {
        return Ok(false);
    };
    let repo = repo.to_ascii_lowercase();
    let number = parse_number(&number)?;
    if db.execute(
        "INSERT OR IGNORE INTO pr_ci_reopen_events(notification_id,consumed_at_ms)
         VALUES(?1,?2)",
        params![notification_id, observed_at_ms],
    )? == 0
    {
        return Ok(false);
    }
    observe_pull_request_state_tx(db, &repo, number, "open", observed_at_ms)?;
    Ok(true)
}

/// Poll due PRs. The transport receives GitHub REST paths (including query
/// strings) and must return the decoded JSON body and HTTP status. Calls and
/// retries are durable; transport failures use bounded exponential backoff.
///
/// The caller should supply the same authenticated, read-only GitHub transport
/// used by Wake's existing poller.
pub fn poll<F>(db: &Connection, now_ms: i64, mut fetch: F) -> Result<PollReport>
where
    F: FnMut(&str) -> Result<ApiResponse>,
{
    let poll_started = Instant::now();
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let mut stmt = tx.prepare(
        "UPDATE pr_ci_trackers SET next_poll_ms=?1
         WHERE repo=(SELECT repo FROM pr_ci_trackers WHERE active=1 AND next_poll_ms<=?2 ORDER BY next_poll_ms,repo,pull_number,thread LIMIT 1)
           AND pull_number=(SELECT pull_number FROM pr_ci_trackers WHERE active=1 AND next_poll_ms<=?2 ORDER BY next_poll_ms,repo,pull_number,thread LIMIT 1)
           AND thread=(SELECT thread FROM pr_ci_trackers WHERE active=1 AND next_poll_ms<=?2 ORDER BY next_poll_ms,repo,pull_number,thread LIMIT 1)
           AND active=1 AND next_poll_ms<=?2
         RETURNING repo,pull_number,thread,head_sha,backoff_ms",
    )?;
    let trackers = stmt
        .query_map(params![now_ms.saturating_add(POLL_MS), now_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let mut trackers_with_generation = Vec::with_capacity(trackers.len());
    for (repo, number, thread, old_sha, backoff) in trackers {
        tx.execute(
            "UPDATE pr_ci_tracker_generations SET generation=generation+1,
                 closed_sweep_generation=NULL
             WHERE repo=?1 AND pull_number=?2 AND thread=?3",
            params![repo, number, thread],
        )?;
        let generation: i64 = tx.query_row(
            "SELECT generation FROM pr_ci_tracker_generations
             WHERE repo=?1 AND pull_number=?2 AND thread=?3",
            params![repo, number, thread],
            |row| row.get(0),
        )?;
        trackers_with_generation.push((repo, number, thread, old_sha, backoff, generation));
    }
    tx.commit()?;
    let mut report = PollReport::default();
    for (repo, number, thread, old_sha, backoff, expected_generation) in trackers_with_generation {
        report.checked += 1;
        let poll_result = poll_one(
            db,
            now_ms,
            &repo,
            number,
            &thread,
            old_sha.as_deref(),
            &mut fetch,
        );
        let elapsed_ms = i64::try_from(poll_started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let finished_ms = now_ms.saturating_add(elapsed_ms);
        match poll_result {
            Ok((discovered, queued, unlinked, is_closed)) => {
                report.discovered += discovered;
                report.queued += queued;
                report.unlinked_runs += unlinked;
                let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
                let tracker_current: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pr_ci_trackers AS tracker
                     JOIN pr_ci_tracker_generations AS generation USING(repo,pull_number,thread)
                     WHERE tracker.repo=?1 AND tracker.pull_number=?2 AND tracker.thread=?3
                       AND tracker.active=1 AND generation.generation=?4)",
                    params![repo, number, thread, expected_generation],
                    |row| row.get(0),
                )?;
                let observed_closed: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pr_ci_pr_observations
                     WHERE repo=?1 AND pull_number=?2 AND state='closed')",
                    params![repo, number],
                    |row| row.get(0),
                )?;
                let pending_runs: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pr_ci_runs
                     WHERE repo=?1 AND pull_number=?2 AND status!='completed')",
                    params![repo, number],
                    |row| row.get(0),
                )?;
                if tracker_current && is_closed && observed_closed && !pending_runs {
                    tx.execute(
                        "UPDATE pr_ci_tracker_generations SET closed_sweep_generation=?1
                         WHERE repo=?2 AND pull_number=?3 AND thread=?4 AND generation=?1",
                        params![expected_generation, repo, number, thread],
                    )?;
                }
                tx.execute(
                    "UPDATE pr_ci_trackers SET next_poll_ms=?1,backoff_ms=60000,error=NULL,
                     updated_at_ms=?2 WHERE repo=?3 AND pull_number=?4 AND thread=?5
                       AND active=1 AND EXISTS(
                         SELECT 1 FROM pr_ci_tracker_generations AS generation
                         WHERE generation.repo=pr_ci_trackers.repo
                           AND generation.pull_number=pr_ci_trackers.pull_number
                           AND generation.thread=pr_ci_trackers.thread
                           AND generation.generation=?6)",
                    params![
                        schedule_after_completion_ms(now_ms, elapsed_ms, POLL_MS),
                        finished_ms,
                        repo,
                        number,
                        thread,
                        expected_generation
                    ],
                )?;
                tx.commit()?;
            }
            Err(_) => {
                let delay = backoff.clamp(60_000, MAX_BACKOFF_MS);
                let next = delay.saturating_mul(2).min(MAX_BACKOFF_MS);
                db.execute(
                    "UPDATE pr_ci_trackers SET next_poll_ms=?1,backoff_ms=?2,error=?3,
                     updated_at_ms=?4 WHERE repo=?5 AND pull_number=?6 AND thread=?7
                       AND active=1 AND EXISTS(
                         SELECT 1 FROM pr_ci_tracker_generations AS generation
                         WHERE generation.repo=pr_ci_trackers.repo
                           AND generation.pull_number=pr_ci_trackers.pull_number
                           AND generation.thread=pr_ci_trackers.thread
                           AND generation.generation=?8)",
                    params![
                        schedule_after_completion_ms(now_ms, elapsed_ms, delay),
                        next,
                        "poll_failed",
                        finished_ms,
                        repo,
                        number,
                        thread,
                        expected_generation
                    ],
                )?;
                report
                    .errors
                    .push(format!("{repo}#{number}: tracking poll failed"));
            }
        }
    }
    Ok(report)
}

fn schedule_after_completion_ms(started_ms: i64, elapsed_ms: i64, delay_ms: i64) -> i64 {
    started_ms
        .saturating_add(elapsed_ms.max(0))
        .saturating_add(delay_ms)
}

fn poll_one<F>(
    db: &Connection,
    now: i64,
    repo: &str,
    number: i64,
    thread: &str,
    old_sha: Option<&str>,
    fetch: &mut F,
) -> Result<(usize, usize, usize, bool)>
where
    F: FnMut(&str) -> Result<ApiResponse>,
{
    let pull = successful(fetch(&format!("/repos/{repo}/pulls/{number}"))?)?;
    ensure!(
        pull["number"].as_i64() == Some(number),
        "PR number mismatch"
    );
    ensure!(
        same_repo(
            pull.pointer("/base/repo/full_name").and_then(Value::as_str),
            repo
        ),
        "PR base repository mismatch"
    );
    ensure!(
        matches!(pull["state"].as_str(), Some("open" | "closed")),
        "Unexpected PR state"
    );
    let sha = pull
        .pointer("/head/sha")
        .and_then(Value::as_str)
        .filter(|sha| valid_sha(sha))
        .context("Invalid PR head SHA")?
        .to_ascii_lowercase();
    match pull.pointer("/head/repo") {
        Some(Value::Null) | None => {}
        Some(Value::Object(head_repo)) => {
            if let Some(full_name) = head_repo.get("full_name")
                && !full_name.is_null()
            {
                let full_name = full_name.as_str().context("Invalid PR head repository")?;
                ensure!(valid_repo(full_name), "Invalid PR head repository");
            }
        }
        Some(_) => bail!("Invalid PR head repository"),
    }
    if old_sha.is_none_or(|old| !same_sha(old, &sha)) {
        db.execute(
            "UPDATE pr_ci_trackers SET head_sha=?1 WHERE repo=?2 AND pull_number=?3",
            params![sha, repo, number],
        )?;
    }

    // Continue checking nonterminal runs from earlier PR heads as well as the
    // current head. Old completed runs remain history but cost no API calls.
    let mut shas = vec![sha.clone()];
    {
        let mut stmt = db.prepare(
            "SELECT sha FROM pr_ci_runs
             WHERE repo=?1 AND pull_number=?2 AND status!='completed'
             GROUP BY sha ORDER BY min(updated_at_ms),sha LIMIT 20",
        )?;
        for pending_sha in stmt
            .query_map(params![repo, number], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
        {
            if !shas.iter().any(|existing| same_sha(existing, &pending_sha)) {
                shas.push(pending_sha);
            }
        }
    }
    let mut runs = Vec::new();
    for query_sha in shas {
        runs.extend(
            fetch_runs_for_sha(repo, &query_sha, fetch)?
                .into_iter()
                .map(|run| (query_sha.clone(), run)),
        );
        db.execute(
            "UPDATE pr_ci_runs SET updated_at_ms=?1
             WHERE repo=?2 AND pull_number=?3 AND sha=?4 AND status!='completed'",
            params![now, repo, number, query_sha],
        )?;
    }
    let confirmed = successful(fetch(&format!("/repos/{repo}/pulls/{number}"))?)?;
    ensure!(
        confirmed["number"].as_i64() == Some(number)
            && confirmed["state"] == pull["state"]
            && same_repo(
                confirmed
                    .pointer("/base/repo/full_name")
                    .and_then(Value::as_str),
                repo
            )
            && confirmed
                .pointer("/head/sha")
                .and_then(Value::as_str)
                .is_some_and(|confirmed_sha| same_sha(confirmed_sha, &sha)),
        "PR head changed during CI discovery"
    );
    let still_active: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pr_ci_trackers
         WHERE repo=?1 AND pull_number=?2 AND thread=?3 AND active=1)",
        params![repo, number, thread],
        |row| row.get(0),
    )?;
    if !still_active {
        return Ok((0, 0, 0, false));
    }
    let mut discovered = 0;
    let mut queued = 0;
    let mut unlinked = 0;
    for (queried_sha, run) in &runs {
        let Some(run_sha) = run["head_sha"]
            .as_str()
            .filter(|run_sha| valid_sha(run_sha))
            .map(str::to_ascii_lowercase)
        else {
            continue;
        };
        if !same_sha(&run_sha, queried_sha) {
            continue;
        }
        let pr_event = matches!(
            run["event"].as_str(),
            Some("pull_request" | "pull_request_target")
        );
        let Some(prs) = run["pull_requests"].as_array() else {
            unlinked += usize::from(pr_event);
            continue;
        };
        if prs.is_empty() {
            unlinked += usize::from(pr_event);
            continue;
        }
        if !run_links_pr(run, number, &run_sha) {
            continue;
        }
        let run_id = positive_id(&run["id"]).context("Invalid workflow run ID")?;
        let attempt = positive_id(&run["run_attempt"]).context("Invalid workflow attempt")?;
        let identity = RunPollIdentity {
            repo,
            pull_request: number,
            sha: &run_sha,
        };
        let known_attempts = known_attempts(db, repo, number, &run_sha, run_id)?;
        let mut attempt_runs = Vec::new();
        for (known_attempt, known_status) in &known_attempts {
            if *known_status != "completed" && *known_attempt < attempt {
                let mut attempt_run = fetch_attempt(repo, run_id, *known_attempt, fetch)?;
                ensure!(
                    positive_id(&attempt_run["id"]) == Some(run_id)
                        && positive_id(&attempt_run["run_attempt"]) == Some(*known_attempt)
                        && attempt_run["head_sha"]
                            .as_str()
                            .is_some_and(|value| same_sha(value, &run_sha)),
                    "Workflow attempt identity mismatch"
                );
                if attempt_run["pull_requests"]
                    .as_array()
                    .is_none_or(Vec::is_empty)
                {
                    // The attempt endpoint can omit the PR association. The list
                    // response for this same run ID and SHA is the exact link.
                    attempt_run["pull_requests"] = run["pull_requests"].clone();
                }
                process_run_attempt(db, now, identity, attempt_run, &mut discovered, &mut queued)?;
            }
        }
        let max_known = known_attempts
            .iter()
            .map(|(known_attempt, _)| *known_attempt)
            .max()
            .unwrap_or(0);
        let missing_start = max_known.saturating_add(1).max(1);
        let gap_end = attempt.saturating_sub(1);
        ensure!(
            gap_end < missing_start || gap_end - missing_start < MAX_RECORDED_ATTEMPT_GAP,
            "Workflow run attempt gap exceeds bounded recovery limit"
        );
        for missing in missing_start..=gap_end {
            let mut attempt_run = fetch_attempt(repo, run_id, missing, fetch)?;
            ensure!(
                positive_id(&attempt_run["id"]) == Some(run_id)
                    && positive_id(&attempt_run["run_attempt"]) == Some(missing)
                    && attempt_run["head_sha"]
                        .as_str()
                        .is_some_and(|value| same_sha(value, &run_sha)),
                "Workflow attempt identity mismatch"
            );
            if attempt_run["pull_requests"]
                .as_array()
                .is_none_or(Vec::is_empty)
            {
                attempt_run["pull_requests"] = run["pull_requests"].clone();
            }
            attempt_runs.push(attempt_run);
        }
        attempt_runs.push(run.clone());
        for attempt_run in attempt_runs {
            process_run_attempt(db, now, identity, attempt_run, &mut discovered, &mut queued)?;
        }
    }
    Ok((discovered, queued, unlinked, pull["state"] == "closed"))
}

fn fetch_runs_for_sha<F>(repo: &str, sha: &str, fetch: &mut F) -> Result<Vec<Value>>
where
    F: FnMut(&str) -> Result<ApiResponse>,
{
    let mut runs = Vec::new();
    for page in 1..=MAX_RUN_PAGES {
        let route = format!(
            "/repos/{repo}/actions/runs?head_sha={sha}&per_page={RUNS_PER_PAGE}&page={page}"
        );
        let response = successful(fetch(&route)?)?;
        let page_runs = response["workflow_runs"]
            .as_array()
            .context("Missing workflow_runs array")?;
        let total_count = response["total_count"]
            .as_u64()
            .context("Missing workflow run total_count")?;
        ensure!(
            total_count <= (RUNS_PER_PAGE * MAX_RUN_PAGES) as u64,
            "GitHub Actions search exceeds its 1,000-run result cap"
        );
        let count = page_runs.len();
        runs.extend(page_runs.iter().cloned());
        if count < RUNS_PER_PAGE {
            break;
        }
    }
    Ok(runs)
}

fn known_attempts(
    db: &Connection,
    repo: &str,
    number: i64,
    sha: &str,
    run_id: i64,
) -> Result<Vec<(i64, String)>> {
    let mut stmt = db.prepare(
        "SELECT attempt,status FROM pr_ci_runs
         WHERE repo=?1 AND pull_number=?2 AND sha=?3 AND run_id=?4 ORDER BY attempt",
    )?;
    Ok(stmt
        .query_map(params![repo, number, sha, run_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn fetch_attempt<F>(repo: &str, run_id: i64, attempt: i64, fetch: &mut F) -> Result<Value>
where
    F: FnMut(&str) -> Result<ApiResponse>,
{
    successful(fetch(&format!(
        "/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}"
    ))?)
}

fn process_run_attempt(
    db: &Connection,
    now: i64,
    identity: RunPollIdentity<'_>,
    run: Value,
    discovered: &mut usize,
    queued: &mut usize,
) -> Result<()> {
    let run_sha = run["head_sha"]
        .as_str()
        .filter(|sha| valid_sha(sha))
        .map(str::to_ascii_lowercase)
        .context("Invalid workflow run head SHA")?;
    ensure!(
        same_sha(&run_sha, identity.sha),
        "Workflow attempt SHA mismatch"
    );
    if !run_links_pr(&run, identity.pull_request, &run_sha) {
        return Ok(());
    }
    let run_id = positive_id(&run["id"]).context("Invalid workflow run ID")?;
    let attempt = positive_id(&run["run_attempt"]).context("Invalid workflow attempt")?;
    let status = run["status"].as_str().context("Missing workflow status")?;
    ensure!(
        matches!(
            status,
            "queued" | "in_progress" | "waiting" | "pending" | "requested" | "completed"
        ),
        "Unknown workflow status"
    );
    let conclusion = if status == "completed" {
        let value = run["conclusion"]
            .as_str()
            .context("Completed run has no conclusion")?;
        ensure!(valid_conclusion(value), "Unknown workflow conclusion");
        Some(value)
    } else {
        None
    };
    let source = serde_json::to_string(&run)?;
    let tx = db.unchecked_transaction()?;
    let inserted = tx.execute(
            "INSERT INTO pr_ci_runs(repo,pull_number,sha,run_id,attempt,status,conclusion,source_json,updated_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(repo,pull_number,sha,run_id,attempt) DO NOTHING",
            params![identity.repo, identity.pull_request, run_sha, run_id, attempt, status, conclusion, source, now],
        )?;
    tx.execute(
        "UPDATE pr_ci_runs SET
             status=CASE WHEN status='completed' THEN status ELSE ?1 END,
             conclusion=coalesce(conclusion,?2),
             source_json=CASE WHEN status='completed' THEN source_json ELSE ?3 END,
             updated_at_ms=?4
             WHERE repo=?5 AND pull_number=?6 AND sha=?7 AND run_id=?8 AND attempt=?9",
        params![
            status,
            conclusion,
            source,
            now,
            identity.repo,
            identity.pull_request,
            run_sha,
            run_id,
            attempt
        ],
    )?;
    // A unique outbox key ensures webhook/poll redelivery and reruns do not collide.
    if let Some(conclusion) = conclusion {
        let inserted_delivery = tx.execute(
                "INSERT OR IGNORE INTO pr_ci_deliveries(repo,pull_number,sha,run_id,attempt,thread,conclusion,source_json)
                 SELECT ?1,?2,?3,?4,?5,thread,?6,?7 FROM pr_ci_trackers
                 WHERE repo=?1 AND pull_number=?2 AND active=1",
                params![identity.repo, identity.pull_request, run_sha, run_id, attempt, conclusion, source],
            )?;
        *queued += inserted_delivery;
    }
    tx.commit()?;
    *discovered += usize::from(inserted != 0);
    Ok(())
}

/// Claim pending deliveries for an external queue. An expired claim is
/// uncertain and moves to `needs_attention`; it is never retried implicitly.
pub fn claim_deliveries(
    db: &mut Connection,
    now_ms: i64,
    limit: usize,
    lease: Duration,
) -> Result<Vec<Delivery>> {
    initialize(db)?;
    ensure!(limit > 0 && limit <= 1000, "Invalid delivery claim limit");
    let lease_ms = i64::try_from(lease.as_millis())?.clamp(1_000, 3_600_000);
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE pr_ci_deliveries SET state='needs_attention'
         WHERE state='claimed' AND lease_until_ms<=?1",
        [now_ms],
    )?;
    let ids = {
        let mut stmt = tx.prepare(
            "SELECT delivery.id FROM pr_ci_deliveries AS delivery
             WHERE delivery.state='pending' AND NOT EXISTS(
                 SELECT 1 FROM pr_ci_delivery_retry_after AS retry
                 WHERE retry.delivery_id=delivery.id AND retry.available_at_ms>?1)
             ORDER BY delivery.id LIMIT ?2",
        )?;
        stmt.query_map(params![now_ms, limit as i64], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut deliveries = Vec::with_capacity(ids.len());
    for id in ids {
        let row: (String, String, i64, String, i64, i64, String, String) = tx.query_row(
            "SELECT thread,repo,pull_number,sha,run_id,attempt,conclusion,source_json
             FROM pr_ci_deliveries WHERE id=?1 AND state='pending'",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )?;
        let changed = tx.execute(
            "UPDATE pr_ci_deliveries SET state='claimed',lease_until_ms=?1 WHERE id=?2 AND state='pending'",
            params![now_ms.saturating_add(lease_ms), id],
        )?;
        if changed != 1 {
            continue;
        }
        tx.execute(
            "DELETE FROM pr_ci_delivery_retry_after WHERE delivery_id=?1",
            [id],
        )?;
        deliveries.push(Delivery {
            id,
            thread: row.0,
            repo: row.1,
            pull_request: row.2,
            sha: row.3,
            run_id: row.4,
            attempt: row.5,
            conclusion: row.6,
            source: serde_json::from_str(&row.7)?,
        });
    }
    tx.commit()?;
    Ok(deliveries)
}

/// Mark an accepted external delivery complete. Queue acceptance is not proof
/// that the target chat executed the message.
pub fn ack_delivery(db: &Connection, id: i64) -> Result<bool> {
    initialize(db)?;
    Ok(db.execute(
        "UPDATE pr_ci_deliveries SET state='delivered',lease_until_ms=NULL
         WHERE id=?1 AND state='claimed'",
        [id],
    )? == 1)
}

/// Return an unaccepted claim to the durable queue immediately.
pub fn retry_delivery(db: &Connection, id: i64, now_ms: i64) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE pr_ci_deliveries SET state='pending',lease_until_ms=NULL
         WHERE id=?1 AND state='claimed'",
        [id],
    )?;
    if changed == 1 {
        tx.execute(
            "INSERT INTO pr_ci_delivery_retry_after(delivery_id,available_at_ms)
             VALUES(?1,?2)
             ON CONFLICT(delivery_id) DO UPDATE SET available_at_ms=excluded.available_at_ms",
            params![id, now_ms.saturating_add(DELIVERY_RETRY_DELAY_MS)],
        )?;
    }
    tx.commit()?;
    Ok(changed == 1)
}

/// Keep a claimed delivery out of automatic retries when its send outcome is
/// unknown. A later operator or authoritative queue inspection can resolve it.
pub fn mark_delivery_uncertain(db: &Connection, id: i64) -> Result<bool> {
    initialize(db)?;
    Ok(db.execute(
        "UPDATE pr_ci_deliveries SET state='needs_attention'
         WHERE id=?1 AND state='claimed'",
        [id],
    )? == 1)
}

/// Resolve a lease-expired delivery only after checking the external queue's
/// outcome. `DefinitelyNotAccepted` is the only path that makes it claimable.
pub fn resolve_delivery_uncertainty(
    db: &Connection,
    id: i64,
    resolution: DeliveryResolution,
) -> Result<bool> {
    initialize(db)?;
    let state = match resolution {
        DeliveryResolution::Accepted => "delivered",
        DeliveryResolution::DefinitelyNotAccepted => "pending",
    };
    Ok(db.execute(
        "UPDATE pr_ci_deliveries SET state=?1,lease_until_ms=NULL
         WHERE id=?2 AND state='needs_attention'",
        params![state, id],
    )? == 1)
}

/// Inspect deliveries whose send outcome became uncertain after lease expiry.
pub fn uncertain_deliveries(db: &Connection) -> Result<Vec<UncertainDelivery>> {
    initialize(db)?;
    let mut stmt = db.prepare(
        "SELECT id,thread,repo,pull_number,sha,run_id,attempt,conclusion,source_json,
                coalesce(lease_until_ms,0)
         FROM pr_ci_deliveries WHERE state='needs_attention' ORDER BY id",
    )?;
    Ok(stmt
        .query_map([], |row| {
            let source: String = row.get(8)?;
            Ok(UncertainDelivery {
                delivery: Delivery {
                    id: row.get(0)?,
                    thread: row.get(1)?,
                    repo: row.get(2)?,
                    pull_request: row.get(3)?,
                    sha: row.get(4)?,
                    run_id: row.get(5)?,
                    attempt: row.get(6)?,
                    conclusion: row.get(7)?,
                    source: serde_json::from_str(&source).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            8,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                },
                lease_expired_at_ms: row.get(9)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn successful(response: ApiResponse) -> Result<Value> {
    ensure!(
        response.status == 200,
        "GitHub REST returned HTTP {}",
        response.status
    );
    Ok(response.body)
}

fn run_links_pr(run: &Value, number: i64, sha: &str) -> bool {
    run["pull_requests"].as_array().is_some_and(|prs| {
        prs.iter().any(|pr| {
            pr["number"].as_i64() == Some(number)
                && pr
                    .pointer("/head/sha")
                    .and_then(Value::as_str)
                    .is_some_and(|candidate| same_sha(candidate, sha))
        })
    })
}

fn positive_id(value: &Value) -> Option<i64> {
    value.as_i64().filter(|number| *number > 0)
}

fn parse_number(value: &str) -> Result<i64> {
    let number = value
        .parse::<i64>()
        .ok()
        .filter(|number| *number > 0)
        .context("Pull request number must be a positive integer")?;
    ensure!(
        number.to_string() == value,
        "Pull request number is not canonical"
    );
    Ok(number)
}

fn valid_repo(repo: &str) -> bool {
    let mut parts = repo.split('/');
    let valid = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    };
    parts.next().is_some_and(valid) && parts.next().is_some_and(valid) && parts.next().is_none()
}

fn same_repo(actual: Option<&str>, expected: &str) -> bool {
    actual.is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
}

fn same_sha(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

fn valid_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_conclusion(value: &str) -> bool {
    matches!(
        value,
        "success"
            | "failure"
            | "neutral"
            | "cancelled"
            | "skipped"
            | "timed_out"
            | "action_required"
            | "stale"
            | "startup_failure"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const THREAD: &str = "11111111-1111-4111-8111-111111111111";
    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEAD_REPO: &str = "fork/project";

    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        db
    }

    fn pull(number: i64, state: &str, sha: &str) -> Value {
        json!({"number":number,"state":state,"base":{"repo":{"full_name":"owner/project"}},
            "head":{"sha":sha,"repo":{"full_name":HEAD_REPO}}})
    }

    fn run(number: i64, sha: &str, id: i64, attempt: i64, conclusion: &str) -> Value {
        json!({"id":id,"run_attempt":attempt,"head_sha":sha,"status":"completed",
        "conclusion":conclusion,"event":"pull_request",
        "head_repository":{"id":777,"name":"project","full_name":HEAD_REPO,
            "html_url":"https://github.com/fork/project"},"pull_requests":[
            {"id":9000+number,"number":number,
             "url":format!("https://api.github.com/repos/owner/project/pulls/{number}"),
             "html_url":format!("https://github.com/owner/project/pull/{number}"),
             "title":"sample PR",
             "head":{"sha":sha,"ref":"feature",
                "repo":{"id":777,"name":"project",
                    "url":"https://api.github.com/repos/fork/project"}}}
        ]})
    }

    #[test]
    fn registration_is_idempotent_per_chat_and_supports_fanout() {
        let mut db = db();
        assert!(register(&mut db, "owner/project", "7", THREAD).unwrap());
        assert!(!register(&mut db, "owner/project", "7", THREAD).unwrap());
        let second_thread = "22222222-2222-4222-8222-222222222222";
        assert!(register(&mut db, "owner/project", "7", second_thread).unwrap());
        assert!(!register(&mut db, "OWNER/PROJECT", "7", second_thread).unwrap());
        let subscribers: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_trackers WHERE repo='owner/project' AND pull_number=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(subscribers, 2);
        assert!(register(&mut db, "owner/project", "07", THREAD).is_err());
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(register_in(&tx, "owner/project", "8", THREAD).unwrap());
        tx.rollback().unwrap();
        let rolled_back: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_trackers WHERE pull_number=8",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rolled_back, 0);
        let waits: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='waits'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(waits, 0);
    }

    #[test]
    fn tracker_generation_backfill_runs_once_and_registration_still_creates_rows() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(TRACKERS_SCHEMA).unwrap();
        db.execute(
            "INSERT INTO pr_ci_trackers(repo,pull_number,thread,active)
             VALUES('owner/project',7,?1,0)",
            [THREAD],
        )
        .unwrap();

        initialize(&db).unwrap();
        let migrated: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_tracker_generations
                 WHERE repo='owner/project' AND pull_number=7 AND thread=?1",
                [THREAD],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migrated, 1);

        db.execute(
            "DELETE FROM pr_ci_tracker_generations
             WHERE repo='owner/project' AND pull_number=7 AND thread=?1",
            [THREAD],
        )
        .unwrap();
        initialize(&db).unwrap();
        let repeated_backfill: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_tracker_generations
                 WHERE repo='owner/project' AND pull_number=7 AND thread=?1",
                [THREAD],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(repeated_backfill, 0, "initialize must not rescan trackers");

        register_in(&db, "owner/project", "7", THREAD).unwrap();
        let registered: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_tracker_generations
                 WHERE repo='owner/project' AND pull_number=7 AND thread=?1",
                [THREAD],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            registered, 1,
            "registration still creates its generation row"
        );
    }

    #[test]
    fn poll_selects_oldest_due_tracker_first() {
        use std::cell::Cell;

        let mut db = db();
        for number in [7, 8, 9] {
            register(&mut db, "owner/project", &number.to_string(), THREAD).unwrap();
        }
        db.execute(
            "UPDATE pr_ci_trackers SET next_poll_ms=CASE pull_number
                WHEN 7 THEN 300 WHEN 8 THEN 100 WHEN 9 THEN 200 END",
            [],
        )
        .unwrap();

        let first_pr = Cell::new(None);
        let mut response = |route: &str| -> Result<ApiResponse> {
            let number = route
                .split("/pulls/")
                .nth(1)
                .and_then(|tail| tail.split('/').next())
                .and_then(|value| value.parse::<i64>().ok());
            if let Some(number) = number {
                first_pr.set(first_pr.get().or(Some(number)));
                Ok(ApiResponse {
                    status: 200,
                    body: pull(number, "open", SHA),
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":0,"workflow_runs":[]}),
                })
            }
        };

        let report = poll(&db, 1_000, &mut response).unwrap();
        assert_eq!(report.checked, 1);
        assert_eq!(first_pr.get(), Some(8));
    }

    #[test]
    fn next_poll_delay_is_added_after_elapsed_poll_time() {
        assert_eq!(
            schedule_after_completion_ms(1_000, 95_000, POLL_MS),
            156_000
        );
    }

    #[test]
    fn each_chat_gets_one_deduplicated_delivery_for_the_same_run() {
        let mut db = db();
        let other = "22222222-2222-4222-8222-222222222222";
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        register(&mut db, "owner/project", "7", other).unwrap();
        let mut response = |route: &str| -> Result<ApiResponse> {
            let body = if route.contains("/pulls/") {
                pull(7, "open", SHA)
            } else {
                json!({"total_count":1,"workflow_runs":[run(7,SHA,81,1,"success")]})
            };
            Ok(ApiResponse { status: 200, body })
        };
        assert_eq!(poll(&db, 1, &mut response).unwrap().queued, 2);
        assert_eq!(poll(&db, 1, &mut response).unwrap().queued, 0);
        let deliveries: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_deliveries WHERE run_id=81 AND attempt=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let distinct_threads: i64 = db
            .query_row(
                "SELECT count(DISTINCT thread) FROM pr_ci_deliveries WHERE run_id=81 AND attempt=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((deliveries, distinct_threads), (2, 2));
    }

    #[test]
    fn poll_requires_exact_pr_fork_sha_and_attempt_and_deduplicates_delivery() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "open", SHA),
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":4,"workflow_runs":[
                        run(7,SHA,21,1,"failure"),
                        run(8,SHA,22,1,"success"),
                        {"id":23,"run_attempt":1,"head_sha":SHA,"status":"completed","conclusion":"success","event":"pull_request","pull_requests":[]},
                        run(7,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",24,1,"success")
                    ]}),
                })
            }
        };
        let first = poll(&db, 1, response).unwrap();
        assert_eq!(first.queued, 1);
        assert_eq!(first.unlinked_runs, 1);
        let mismatched_sha: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_runs WHERE run_id=24",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mismatched_sha, 0);
        let source: String = db
            .query_row(
                "SELECT source_json FROM pr_ci_runs WHERE run_id=21 AND attempt=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let source: Value = serde_json::from_str(&source).unwrap();
        assert_eq!(source["pull_requests"][0]["id"].as_i64(), Some(9007));
        assert_eq!(
            source["pull_requests"][0]["head"]["repo"]["id"].as_i64(),
            Some(777)
        );
        assert_eq!(
            source["pull_requests"][0]["head"]["repo"]["name"],
            "project"
        );
        assert_eq!(
            source["pull_requests"][0]["head"]["repo"]["url"],
            "https://api.github.com/repos/fork/project"
        );
        assert_eq!(source["head_repository"]["id"].as_i64(), Some(777));
        db.execute("UPDATE pr_ci_trackers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(poll(&db, 2, response).unwrap().queued, 0);
        let claimed = claim_deliveries(&mut db, 3, 10, Duration::from_secs(10)).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            (
                claimed[0].run_id,
                claimed[0].attempt,
                claimed[0].conclusion.as_str()
            ),
            (21, 1, "failure")
        );
        assert!(ack_delivery(&db, claimed[0].id).unwrap());
        assert!(
            claim_deliveries(&mut db, 4, 10, Duration::from_secs(10))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn poll_reads_all_pages_and_keeps_pending_statuses_nonterminal() {
        use std::cell::RefCell;

        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        let pages = RefCell::new(Vec::new());
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                return Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "open", SHA),
                });
            }
            let page = if route.ends_with("page=1") { 1 } else { 2 };
            pages.borrow_mut().push(page);
            let runs = if page == 1 {
                (0..100)
                    .map(|n| {
                        let status = match n {
                            0 => "waiting",
                            1 => "pending",
                            2 => "requested",
                            _ => "queued",
                        };
                        json!({"id":n+1,"run_attempt":1,"head_sha":SHA,"status":status,
                            "event":"pull_request","pull_requests":[{"id":9007,"number":7,
                                "url":"https://api.github.com/repos/owner/project/pulls/7",
                                "html_url":"https://github.com/owner/project/pull/7",
                                "title":"sample PR","head":{"sha":SHA,"repo":{"id":777,
                                "name":"project","url":"https://api.github.com/repos/fork/project"}}}]})
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![
                    json!({"id":101,"run_attempt":1,"head_sha":SHA,"status":"in_progress",
                    "event":"pull_request","pull_requests":[{"id":9007,"number":7,
                        "url":"https://api.github.com/repos/owner/project/pulls/7",
                        "html_url":"https://github.com/owner/project/pull/7",
                        "title":"sample PR","head":{"sha":SHA,"repo":{"id":777,
                        "name":"project","url":"https://api.github.com/repos/fork/project"}}}]}),
                ]
            };
            Ok(ApiResponse {
                status: 200,
                body: json!({"total_count":101,"workflow_runs":runs}),
            })
        };
        let report = poll(&db, 1, response).unwrap();
        assert_eq!(report.discovered, 101);
        assert_eq!(report.queued, 0);
        assert_eq!(*pages.borrow(), vec![1, 2]);
        let saved: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_runs WHERE status IN ('waiting','pending','requested')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved, 3);
        let deliveries: i64 = db
            .query_row("SELECT count(*) FROM pr_ci_deliveries", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(deliveries, 0);
    }

    #[test]
    fn poll_refuses_a_search_above_githubs_result_cap_without_partial_delivery() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        let response = |route: &str| -> Result<ApiResponse> {
            let body = if route.contains("/pulls/") {
                pull(7, "open", SHA)
            } else {
                json!({"total_count":1001,"workflow_runs":[run(7,SHA,1,1,"success")]})
            };
            Ok(ApiResponse { status: 200, body })
        };
        let report = poll(&db, 1, response).unwrap();
        assert_eq!(report.errors.len(), 1);
        let (runs, deliveries): (i64, i64) = db
            .query_row(
                "SELECT (SELECT count(*) FROM pr_ci_runs),(SELECT count(*) FROM pr_ci_deliveries)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((runs, deliveries), (0, 0));
    }

    #[test]
    fn pending_run_on_previous_head_is_still_polled() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        let old_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        db.execute(
            "INSERT INTO pr_ci_runs(repo,pull_number,sha,run_id,attempt,status,source_json,updated_at_ms)
             VALUES('owner/project',7,?1,31,1,'in_progress','{}',0)",
            [old_sha],
        )
        .unwrap();
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                return Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "open", SHA),
                });
            }
            let listed = if route.contains(old_sha) {
                vec![run(7, old_sha, 31, 1, "success")]
            } else {
                vec![]
            };
            Ok(ApiResponse {
                status: 200,
                body: json!({"total_count":listed.len(),"workflow_runs":listed}),
            })
        };
        let report = poll(&db, 1, response).unwrap();
        assert_eq!(report.queued, 1);
        let saved: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_runs WHERE sha=?1 AND status='completed'",
                [old_sha],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved, 1);
    }

    #[test]
    fn closed_pr_remains_tracked_and_picks_up_ci_after_reopen() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 1).unwrap());
        let mut response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                return Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "closed", SHA),
                });
            }
            Ok(ApiResponse {
                status: 200,
                body: json!({"total_count":1,"workflow_runs":[run(7,SHA,52,1,"success")]}),
            })
        };
        let mut pending_run = run(7, SHA, 52, 1, "success");
        pending_run["status"] = json!("in_progress");
        pending_run["conclusion"] = Value::Null;
        let pending_response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "closed", SHA),
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":1,"workflow_runs":[pending_run.clone()]}),
                })
            }
        };

        assert_eq!(poll(&db, 2, pending_response).unwrap().queued, 0);
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 10).unwrap());
        let active_with_pending: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_ci_trackers WHERE active=1 AND repo='owner/project' AND pull_number=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active_with_pending, 1);

        db.execute("UPDATE pr_ci_trackers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(poll(&db, 3, &mut response).unwrap().queued, 1);
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 20).unwrap());
        let (active_after_close, deliveries): (i64, i64) = db
            .query_row(
                "SELECT (SELECT count(*) FROM pr_ci_trackers WHERE active=1),
                        (SELECT count(*) FROM pr_ci_deliveries WHERE run_id=52)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((active_after_close, deliveries), (0, 1));

        db.execute_batch(
            "CREATE TABLE automatic_pr_notifications(
                id TEXT PRIMARY KEY, kind TEXT, repo TEXT, pr TEXT, thread TEXT, event TEXT
             );
             INSERT INTO automatic_pr_notifications
                VALUES('reopened-7','pull_request','owner/project','7',
                       '11111111-1111-4111-8111-111111111111','reopened');",
        )
        .unwrap();
        assert!(consume_reopened_notification_in(&db, "reopened-7", 30).unwrap());
        assert!(!consume_reopened_notification_in(&db, "reopened-7", 31).unwrap());
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "open", 31).unwrap());
        let open_response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "open", SHA),
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":2,"workflow_runs":[
                        run(7,SHA,52,1,"success"),run(7,SHA,53,1,"success")
                    ]}),
                })
            }
        };
        assert_eq!(poll(&db, 3, open_response).unwrap().queued, 1);
        let (active, reopened_deliveries): (i64, i64) = db
            .query_row(
                "SELECT (SELECT count(*) FROM pr_ci_trackers WHERE active=1),
                        (SELECT count(*) FROM pr_ci_deliveries WHERE run_id=53)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((active, reopened_deliveries), (1, 1));
    }

    #[test]
    fn reopening_resets_backoff_for_active_tracker_without_reactivation() {
        let db = db();
        register_in(&db, "owner/project", "7", THREAD).unwrap();
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 10).unwrap());
        db.execute(
            "UPDATE pr_ci_trackers SET next_poll_ms=3600000,backoff_ms=?1,error='temporary failure'
             WHERE repo='owner/project' AND pull_number=7 AND thread=?2",
            params![MAX_BACKOFF_MS, THREAD],
        )
        .unwrap();

        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "open", 20).unwrap());
        let tracker: (i64, i64, i64, Option<String>) = db
            .query_row(
                "SELECT active,next_poll_ms,backoff_ms,error FROM pr_ci_trackers
                 WHERE repo='owner/project' AND pull_number=7 AND thread=?1",
                [THREAD],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(tracker, (1, 0, 60_000, None));
    }

    #[test]
    fn closed_pr_is_paused_only_after_successful_ci_scan_discovers_runs() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 10).unwrap());
        let mut pending = run(7, SHA, 88, 1, "success");
        pending["status"] = json!("in_progress");
        pending["conclusion"] = Value::Null;
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "closed", SHA),
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":1,"workflow_runs":[pending.clone()]}),
                })
            }
        };

        assert_eq!(poll(&db, 20, response).unwrap().queued, 0);
        let (active, runs): (i64, i64) = db
            .query_row(
                "SELECT (SELECT active FROM pr_ci_trackers WHERE repo='owner/project' AND pull_number=7),
                        (SELECT count(*) FROM pr_ci_runs WHERE run_id=88 AND status='in_progress')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((active, runs), (1, 1));
    }

    #[test]
    fn new_closed_poll_invalidates_old_sweep_before_pr_poller_reconciles() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 10).unwrap());
        db.execute(
            "UPDATE pr_ci_tracker_generations SET closed_sweep_generation=generation
             WHERE repo='owner/project' AND pull_number=7",
            [],
        )
        .unwrap();

        let mut observed_during_fetch = false;
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                if !observed_during_fetch {
                    observed_during_fetch = true;
                    // The PR poller observes the close before this CI scan has
                    // discovered and persisted the newly pending run.
                    observe_pull_request_state_in(&db, "owner/project", "7", "closed", 11)?;
                }
                Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "closed", SHA),
                })
            } else {
                let mut pending = run(7, SHA, 89, 1, "success");
                pending["status"] = json!("in_progress");
                pending["conclusion"] = Value::Null;
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":1,"workflow_runs":[pending]}),
                })
            }
        };

        assert_eq!(poll(&db, 20, response).unwrap().queued, 0);
        let (active, runs, certificate): (i64, i64, Option<i64>) = db
            .query_row(
                "SELECT tracker.active,
                        (SELECT count(*) FROM pr_ci_runs WHERE run_id=89 AND status='in_progress'),
                        generation.closed_sweep_generation
                 FROM pr_ci_trackers AS tracker
                 JOIN pr_ci_tracker_generations AS generation USING(repo,pull_number,thread)
                 WHERE tracker.repo='owner/project' AND tracker.pull_number=7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((active, runs, certificate), (1, 1, None));
    }

    #[test]
    fn equal_time_close_and_reopen_invalidate_an_in_flight_poll() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 100).unwrap());
        db.execute(
            "UPDATE pr_ci_tracker_generations SET closed_sweep_generation=generation
             WHERE repo='owner/project' AND pull_number=7",
            [],
        )
        .unwrap();
        let mut reopened = false;
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                if !reopened {
                    reopened = true;
                    observe_pull_request_state_in(&db, "owner/project", "7", "closed", 200)?;
                    observe_pull_request_state_in(&db, "owner/project", "7", "open", 200)?;
                }
                Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "closed", SHA),
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":0,"workflow_runs":[]}),
                })
            }
        };

        assert_eq!(poll(&db, 100, response).unwrap().checked, 1);
        let (active, next_poll): (i64, i64) = db
            .query_row(
                "SELECT active,next_poll_ms FROM pr_ci_trackers
                 WHERE repo='owner/project' AND pull_number=7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((active, next_poll), (1, 60_100));
    }

    #[test]
    fn older_overlapping_poll_cannot_certify_newer_claim() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 10).unwrap());
        let mut nested_started = false;
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") && !nested_started {
                nested_started = true;
                let nested = poll(&db, 60_020, |_| anyhow::bail!("temporary poll failure"))?;
                assert_eq!(nested.errors.len(), 1);
            }
            if route.contains("/pulls/") {
                Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "closed", SHA),
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":0,"workflow_runs":[]}),
                })
            }
        };

        assert_eq!(poll(&db, 20, response).unwrap().checked, 1);
        let (active, certificate, generation): (i64, Option<i64>, i64) = db
            .query_row(
                "SELECT tracker.active,generation.closed_sweep_generation,generation.generation
                 FROM pr_ci_trackers AS tracker
                 JOIN pr_ci_tracker_generations AS generation USING(repo,pull_number,thread)
                 WHERE tracker.repo='owner/project' AND tracker.pull_number=7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(active, 1);
        assert_eq!(certificate, None);
        assert!(generation >= 3);
    }

    #[test]
    fn unregister_after_auto_pause_stays_inactive_when_pr_reopens() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 10).unwrap());
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                Ok(ApiResponse {
                    status: 200,
                    body: pull(7, "closed", SHA),
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":0,"workflow_runs":[]}),
                })
            }
        };
        poll(&db, 20, response).unwrap();
        let active_before_pr_reconciliation: i64 = db
            .query_row(
                "SELECT active FROM pr_ci_trackers WHERE repo='owner/project' AND pull_number=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active_before_pr_reconciliation, 1);
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 21).unwrap());
        let active: i64 = db
            .query_row(
                "SELECT active FROM pr_ci_trackers WHERE repo='owner/project' AND pull_number=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 0);
        assert!(unregister(&db, "owner/project", "7", THREAD).unwrap());
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "open", 30).unwrap());
        let active: i64 = db
            .query_row(
                "SELECT active FROM pr_ci_trackers WHERE repo='owner/project' AND pull_number=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 0);
    }

    #[test]
    fn reopen_observation_does_not_restore_explicit_unregister() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        assert!(unregister(&db, "owner/project", "7", THREAD).unwrap());
        db.execute_batch(
            "CREATE TABLE automatic_pr_notifications(
                id TEXT PRIMARY KEY, kind TEXT, repo TEXT, pr TEXT, thread TEXT, event TEXT
             );
             INSERT INTO automatic_pr_notifications
                VALUES('reopened-unregistered','pull_request','owner/project','7',
                       '11111111-1111-4111-8111-111111111111','reopened');",
        )
        .unwrap();
        assert!(consume_reopened_notification_in(&db, "reopened-unregistered", 10).unwrap());
        let active: i64 = db
            .query_row(
                "SELECT active FROM pr_ci_trackers WHERE repo='owner/project' AND pull_number=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 0);
    }

    #[test]
    fn stale_closed_observation_cannot_pause_a_newer_open_pr() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "closed", 100).unwrap());
        assert!(observe_pull_request_state_in(&db, "owner/project", "7", "open", 200).unwrap());
        assert!(!observe_pull_request_state_in(&db, "owner/project", "7", "closed", 150).unwrap());
        let active: i64 = db
            .query_row(
                "SELECT active FROM pr_ci_trackers WHERE repo='owner/project' AND pull_number=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 1);
    }

    #[test]
    fn attempt_jump_fetches_the_intermediate_attempt_and_sha_case_deduplicates() {
        let mut db = db();
        register(&mut db, "OWNER/PROJECT", "7", THREAD).unwrap();
        for attempt in [1, 3] {
            db.execute("UPDATE pr_ci_trackers SET next_poll_ms=0", [])
                .unwrap();
            let response = |route: &str| -> Result<ApiResponse> {
                if route.contains("/pulls/") {
                    return Ok(ApiResponse {
                        status: 200,
                        body: pull(7, "open", SHA),
                    });
                }
                if route.contains("/attempts/2") {
                    return Ok(ApiResponse {
                        status: 200,
                        body: run(7, SHA, 41, 2, "failure"),
                    });
                }
                let run_sha = if attempt == 3 {
                    SHA.to_ascii_uppercase()
                } else {
                    SHA.to_owned()
                };
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":1,"workflow_runs":[
                        run(7,&run_sha,41,attempt,"success")
                    ]}),
                })
            };
            poll(&db, attempt * 10, response).unwrap();
        }
        let (runs, deliveries): (i64, i64) = db
            .query_row(
                "SELECT (SELECT count(*) FROM pr_ci_runs WHERE run_id=41),
                        (SELECT count(*) FROM pr_ci_deliveries WHERE run_id=41)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((runs, deliveries), (3, 3));
    }

    #[test]
    fn rerun_attempt_is_distinct_and_expired_claim_stays_uncertain() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        for attempt in [1, 2] {
            db.execute("UPDATE pr_ci_trackers SET next_poll_ms=0", [])
                .unwrap();
            let response = |route: &str| -> Result<ApiResponse> {
                if route.contains("/pulls/") {
                    Ok(ApiResponse {
                        status: 200,
                        body: pull(7, "open", SHA),
                    })
                } else {
                    Ok(ApiResponse {
                        status: 200,
                        body: json!({"total_count":1,"workflow_runs":[run(7,SHA,21,attempt,"success")]}),
                    })
                }
            };
            poll(&db, attempt * 10, response).unwrap();
        }
        let first = claim_deliveries(&mut db, 100, 1, Duration::from_secs(1)).unwrap();
        assert_eq!(first[0].attempt, 1);
        let pending = claim_deliveries(&mut db, 2_000, 10, Duration::from_secs(30)).unwrap();
        assert_eq!(
            pending.iter().map(|row| row.attempt).collect::<Vec<_>>(),
            vec![2]
        );
        let uncertain = uncertain_deliveries(&db).unwrap();
        assert_eq!(uncertain.len(), 1);
        assert_eq!(uncertain[0].delivery.attempt, 1);
        assert!(
            resolve_delivery_uncertainty(
                &db,
                uncertain[0].delivery.id,
                DeliveryResolution::Accepted,
            )
            .unwrap()
        );
        assert!(uncertain_deliveries(&db).unwrap().is_empty());
        assert!(
            claim_deliveries(&mut db, 2_001, 10, Duration::from_secs(30))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn poll_persists_backoff_on_api_error() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        let started = Instant::now();
        let report = poll(&db, 100, |_| anyhow::bail!("offline")).unwrap();
        assert_eq!(report.errors.len(), 1);
        let (next, backoff): (i64, i64) = db.query_row(
            "SELECT next_poll_ms,backoff_ms FROM pr_ci_trackers WHERE repo='owner/project' AND pull_number=7",
            [], |r| Ok((r.get(0)?,r.get(1)?)),
        ).unwrap();
        let elapsed = i64::try_from(started.elapsed().as_millis()).unwrap();
        assert!((60_100..=60_100 + elapsed).contains(&next));
        assert_eq!(backoff, 120_000);
    }

    #[test]
    fn missing_fork_repository_name_does_not_block_sha_verified_run_polling() {
        let mut db = db();
        register(&mut db, "owner/project", "7", THREAD).unwrap();
        let response = |route: &str| -> Result<ApiResponse> {
            if route.contains("/pulls/") {
                let mut pr = pull(7, "open", SHA);
                pr["head"]["repo"] = Value::Null;
                Ok(ApiResponse {
                    status: 200,
                    body: pr,
                })
            } else {
                Ok(ApiResponse {
                    status: 200,
                    body: json!({"total_count":1,"workflow_runs":[run(7,SHA,95,1,"success")]}),
                })
            }
        };

        let report = poll(&db, 1_000, response).unwrap();
        assert_eq!((report.errors.len(), report.queued), (0, 1));
        let source_repo: Option<String> = db
            .query_row(
                "SELECT json_extract(source_json,'$.head_repository.full_name')
                 FROM pr_ci_runs WHERE run_id=95",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source_repo.as_deref(), Some(HEAD_REPO));
    }
}
