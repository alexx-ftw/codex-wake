//! Durable, repeatable notifications for automatic PR and review listeners.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
use std::collections::HashSet;
use uuid::Uuid;

const MAX_EVENT_KEY: usize = 512;
const MAX_SOURCE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Notification {
    pub id: String,
    pub kind: String,
    pub repo: String,
    pub pr: String,
    pub thread: String,
    pub event: String,
    pub event_key: String,
    pub source: Value,
    pub state: String,
}

struct PrLifecycleState {
    epoch: i64,
    state: String,
    closed_at_sec: i64,
    webhook_reopen_source_id: Option<String>,
    poll_reopen_source_id: Option<String>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct PendingReopen {
    source_kind: String,
    source_id: String,
    event_at_sec: i64,
    event_at: String,
}

pub(crate) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS automatic_pr_notification_listeners (
            kind TEXT NOT NULL CHECK(kind IN ('pull_request','review')),
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            thread TEXT NOT NULL,
            registered_at_sec INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
            PRIMARY KEY(kind,repo,pr,thread));
        CREATE TABLE IF NOT EXISTS automatic_pr_notifications (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL CHECK(kind IN ('pull_request','review')),
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            thread TEXT NOT NULL,
            event TEXT NOT NULL,
            event_key TEXT NOT NULL,
            source TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending'
                CHECK(state IN ('pending','sending','queued','needs_attention')),
            available_at_ms INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(kind,repo,pr,thread,event_key));
        CREATE TABLE IF NOT EXISTS automatic_pr_event_journal (
            kind TEXT NOT NULL CHECK(kind IN ('pull_request','review')),
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            event TEXT NOT NULL,
            event_key TEXT NOT NULL,
            event_at_sec INTEGER NOT NULL,
            event_at TEXT NOT NULL,
            source TEXT NOT NULL,
            PRIMARY KEY(kind,repo,pr,event_key));
        CREATE TABLE IF NOT EXISTS automatic_pr_lifecycle (
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('closed','reopened')),
            closed_at_sec INTEGER NOT NULL,
            reopened_at_sec INTEGER,
            webhook_reopen_source_id TEXT,
            poll_reopen_source_id TEXT,
            PRIMARY KEY(repo,pr));
        CREATE TABLE IF NOT EXISTS automatic_pr_closed_cycles (
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            closed_at_sec INTEGER NOT NULL,
            PRIMARY KEY(repo,pr,closed_at_sec));
        CREATE TABLE IF NOT EXISTS automatic_pr_pending_reopens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            source_kind TEXT NOT NULL CHECK(source_kind IN ('webhook','poll')),
            source_id TEXT NOT NULL,
            event_at_sec INTEGER NOT NULL,
            event_at TEXT NOT NULL,
            source TEXT NOT NULL,
            timeline_scanned INTEGER NOT NULL DEFAULT 0 CHECK(timeline_scanned IN (0,1)),
            UNIQUE(repo,pr,source_kind,source_id));",
    )?;
    for (table, column, migration) in [
        (
            "automatic_pr_notifications",
            "available_at_ms",
            "ALTER TABLE automatic_pr_notifications ADD COLUMN available_at_ms INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "automatic_pr_pending_reopens",
            "timeline_scanned",
            "ALTER TABLE automatic_pr_pending_reopens ADD COLUMN timeline_scanned INTEGER NOT NULL DEFAULT 0 CHECK(timeline_scanned IN (0,1))",
        ),
    ] {
        let has_column = || -> Result<bool> {
            let mut statement = db.prepare(&format!("PRAGMA table_info({table})"))?;
            let names = statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(names.iter().any(|name| name == column))
        };
        if !has_column()?
            && let Err(error) = db.execute_batch(migration)
            && !has_column()?
        {
            return Err(error.into());
        }
    }
    Ok(())
}

/// Idempotently enable repeat notifications for one PR or review stream and destination.
#[cfg(test)]
pub(crate) fn register(
    db: &Connection,
    kind: &str,
    repo: &str,
    pr: &str,
    thread: &str,
) -> Result<bool> {
    register_in(db, kind, repo, pr, thread)
}

/// Register inside the caller's transaction; create an immediate transaction only when
/// the connection is otherwise in autocommit mode.
pub(crate) fn register_in(
    db: &Connection,
    kind: &str,
    repo: &str,
    pr: &str,
    thread: &str,
) -> Result<bool> {
    register_in_with_boundary(db, kind, repo, pr, thread, None)
}

/// Register with the per-listener event-time boundary captured when PR creation was observed.
pub(crate) fn register_in_since(
    db: &Connection,
    kind: &str,
    repo: &str,
    pr: &str,
    thread: &str,
    registered_at_sec: i64,
) -> Result<bool> {
    register_in_with_boundary(db, kind, repo, pr, thread, Some(registered_at_sec))
}

fn register_in_with_boundary(
    db: &Connection,
    kind: &str,
    repo: &str,
    pr: &str,
    thread: &str,
    registered_at_sec: Option<i64>,
) -> Result<bool> {
    let validation_event = match kind {
        "pull_request" => "closed",
        "review" => "submitted",
        _ => anyhow::bail!("Unsupported automatic PR notification kind"),
    };
    let (thread, pr) =
        crate::subscriptions::validate_source(kind, repo, pr, validation_event, thread)?;
    initialize(db)?;
    let repo = repo.to_ascii_lowercase();
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let inserted = insert_listener(&tx, kind, &repo, &pr, &thread, registered_at_sec)?;
        tx.commit()?;
        Ok(inserted)
    } else {
        insert_listener(db, kind, &repo, &pr, &thread, registered_at_sec)
    }
}

fn insert_listener(
    db: &Connection,
    kind: &str,
    repo: &str,
    pr: &str,
    thread: &str,
    registered_at_sec: Option<i64>,
) -> Result<bool> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM automatic_pr_notification_listeners
         WHERE kind=?1 AND repo=?2 COLLATE NOCASE AND pr=?3 AND thread=?4)",
        params![kind, repo, pr, thread],
        |row| row.get(0),
    )?;
    let inserted = if exists {
        0
    } else {
        match registered_at_sec {
            Some(registered_at_sec) => db.execute(
                "INSERT OR IGNORE INTO automatic_pr_notification_listeners
                 (kind,repo,pr,thread,registered_at_sec) VALUES(?1,?2,?3,?4,?5)",
                params![kind, repo, pr, thread, registered_at_sec],
            )?,
            None => db.execute(
                "INSERT OR IGNORE INTO automatic_pr_notification_listeners(kind,repo,pr,thread)
                 VALUES(?1,?2,?3,?4)",
                params![kind, repo, pr, thread],
            )?,
        }
    };
    if inserted == 0
        && let Some(registered_at_sec) = registered_at_sec
    {
        db.execute(
            "UPDATE automatic_pr_notification_listeners
             SET registered_at_sec=MIN(registered_at_sec,?5)
             WHERE kind=?1 AND repo=?2 COLLATE NOCASE AND pr=?3 AND thread=?4",
            params![kind, repo, pr, thread, registered_at_sec],
        )?;
    }
    if registered_at_sec.is_some() {
        replay_listener_events_in(db, kind, repo, pr, thread)?;
    }
    Ok(inserted != 0)
}

/// Replay journaled events into a newly registered destination, preserving provider identity.
pub(crate) fn replay_listener_events_in(
    db: &Connection,
    kind: &str,
    repo: &str,
    pr: &str,
    thread: &str,
) -> Result<usize> {
    let registered_at_sec: i64 = db.query_row(
        "SELECT registered_at_sec FROM automatic_pr_notification_listeners
         WHERE kind=?1 AND repo=?2 COLLATE NOCASE AND pr=?3 AND thread=?4",
        params![kind, repo, pr, thread],
        |row| row.get(0),
    )?;
    let replayable_events: &[&str] = if kind == "pull_request" {
        &[
            "closed",
            "merged",
            "reopened",
            "synchronize",
            "base_changed",
        ]
    } else {
        &["submitted", "approved", "changes_requested"]
    };
    let placeholders = replayable_events
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT event,event_key,source FROM automatic_pr_event_journal
         WHERE kind=?1 AND repo=?2 COLLATE NOCASE AND pr=?3 AND event_at_sec>=?4
           AND event IN ({placeholders}) ORDER BY event_at_sec,event_key"
    );
    let rows: Vec<(String, String, String)> = {
        let mut statement = db.prepare(&sql)?;
        let mut values = vec![
            rusqlite::types::Value::Text(kind.to_owned()),
            rusqlite::types::Value::Text(repo.to_owned()),
            rusqlite::types::Value::Text(pr.to_owned()),
            rusqlite::types::Value::Integer(registered_at_sec),
        ];
        values.extend(
            replayable_events
                .iter()
                .map(|event| rusqlite::types::Value::Text((*event).to_owned())),
        );
        statement
            .query_map(rusqlite::params_from_iter(values), |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut inserted = 0;
    for (event, event_key, source) in rows {
        let already_delivered: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM automatic_pr_notifications
             WHERE kind=?1 AND repo=?2 COLLATE NOCASE AND pr=?3 AND thread=?4 AND event_key=?5)",
            params![kind, repo, pr, thread, event_key],
            |row| row.get(0),
        )?;
        if already_delivered {
            continue;
        }
        inserted += db.execute(
            "INSERT OR IGNORE INTO automatic_pr_notifications
             (id,kind,repo,pr,thread,event,event_key,source)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                Uuid::new_v4().to_string(),
                kind,
                repo,
                pr,
                thread,
                event,
                event_key,
                source
            ],
        )?;
    }
    Ok(inserted)
}

/// Record one provider event for every registered destination. `event_key` must be the
/// stable identity of this provider event; replaying it returns no new notifications.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_event(
    db: &Connection,
    kind: &str,
    repo: &str,
    pr: &str,
    event: &str,
    event_at: &str,
    event_key: &str,
    source: &Value,
) -> Result<Vec<Notification>> {
    initialize(db)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let notifications =
            record_event_in(&tx, kind, repo, pr, event, event_at, event_key, source)?;
        tx.commit()?;
        Ok(notifications)
    } else {
        record_event_in(db, kind, repo, pr, event, event_at, event_key, source)
    }
}

/// Record a provider event in a caller-owned transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_event_in(
    db: &Connection,
    kind: &str,
    repo: &str,
    pr: &str,
    event: &str,
    event_at: &str,
    event_key: &str,
    source: &Value,
) -> Result<Vec<Notification>> {
    initialize(db)?;
    let repo = repo.to_ascii_lowercase();
    // `reopened` is an internal durable notification, not a subscription rule event.
    let validation_event = if kind == "pull_request" && event == "reopened" {
        "closed"
    } else {
        event
    };
    let (_, pr) = crate::subscriptions::validate_source(
        kind,
        &repo,
        pr,
        validation_event,
        "11111111-1111-4111-8111-111111111111",
    )?;
    ensure!(
        !event_key.is_empty()
            && event_key.len() <= MAX_EVENT_KEY
            && event_key.bytes().all(|byte| byte.is_ascii_graphic()),
        "Invalid provider event identity"
    );
    ensure!(
        !event_at.is_empty() && event_at.len() <= 64,
        "Invalid event timestamp"
    );
    ensure!(
        serde_json::to_vec(source)?.len() <= MAX_SOURCE_BYTES,
        "Provider event exceeds 1 MiB"
    );
    let event_at_sec: Option<i64> = db.query_row(
        "SELECT CAST(strftime('%s',?1) AS INTEGER)",
        [event_at],
        |row| row.get(0),
    )?;
    let event_at_sec = event_at_sec.context("Invalid event timestamp")?;
    let source = serde_json::to_string(source)?;
    let mut delivery_at_sec = event_at_sec;
    let mut delivery_source = source.clone();
    let journalable = (kind == "pull_request"
        && matches!(
            event,
            "closed" | "merged" | "reopened" | "synchronize" | "base_changed"
        ))
        || (kind == "review" && matches!(event, "submitted" | "approved" | "changes_requested"));
    if journalable {
        let journal_row: Option<(String, i64, String, String)> = db
            .query_row(
                "SELECT event,event_at_sec,event_at,source FROM automatic_pr_event_journal
                 WHERE kind=?1 AND repo=?2 COLLATE NOCASE AND pr=?3 AND event_key=?4 LIMIT 1",
                params![kind, repo, pr, event_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let journal_event =
            if let Some((existing, original_at_sec, _, original_source)) = journal_row {
                delivery_at_sec = original_at_sec;
                delivery_source = original_source;
                existing
            } else {
                db.execute(
                    "INSERT OR IGNORE INTO automatic_pr_event_journal
                 (kind,repo,pr,event,event_key,event_at_sec,event_at,source)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        kind,
                        repo,
                        pr,
                        event,
                        event_key,
                        event_at_sec,
                        event_at,
                        source
                    ],
                )?;
                event.to_owned()
            };
        ensure!(
            journal_event == event,
            "Provider event identity was reused for another event type"
        );
    }
    let listeners = {
        let mut statement = db.prepare(
            "SELECT thread FROM automatic_pr_notification_listeners
             WHERE kind=?1 AND repo=?2 COLLATE NOCASE AND pr=?3 AND registered_at_sec<=?4 ORDER BY thread",
        )?;
        statement
            .query_map(params![kind, repo, pr, delivery_at_sec], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut notifications = Vec::new();
    for thread in listeners {
        let existing: Option<String> = db
            .query_row(
                "SELECT event FROM automatic_pr_notifications
                 WHERE kind=?1 AND repo=?2 COLLATE NOCASE AND pr=?3 AND thread=?4 AND event_key=?5
                 LIMIT 1",
                params![kind, repo, pr, thread, event_key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_event) = existing {
            ensure!(
                existing_event == event,
                "Provider event identity changed event type"
            );
            continue;
        }
        let id = Uuid::new_v4().to_string();
        let inserted = db.execute(
            "INSERT OR IGNORE INTO automatic_pr_notifications
             (id,kind,repo,pr,thread,event,event_key,source)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                id,
                kind,
                repo,
                pr,
                thread,
                event,
                event_key,
                delivery_source
            ],
        )?;
        if inserted != 0 {
            notifications.push(Notification {
                id,
                kind: kind.to_owned(),
                repo: repo.to_owned(),
                pr: pr.clone(),
                thread,
                event: event.to_owned(),
                event_key: event_key.to_owned(),
                source: serde_json::from_str(&delivery_source)?,
                state: "pending".into(),
            });
        } else {
            let existing_event: String = db.query_row(
                "SELECT event FROM automatic_pr_notifications
                 WHERE kind=?1 AND repo=?2 AND pr=?3 AND thread=?4 AND event_key=?5",
                params![kind, repo, pr, thread, event_key],
                |row| row.get(0),
            )?;
            ensure!(
                existing_event == event,
                "Provider event identity changed event type"
            );
        }
    }
    Ok(notifications)
}

// A snapshot and a webhook have no shared transition ID. Keep a possible
// cross-source duplicate in the journal, outside replay and the delivery queue.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_change_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    event: &str,
    event_at: &str,
    event_key: &str,
    source: &Value,
    webhook: bool,
    force_pending: bool,
    candidate_floor: Option<i64>,
) -> Result<usize> {
    initialize(db)?;
    let repo = repo.to_ascii_lowercase();
    let (_, pr) = crate::subscriptions::validate_source(
        "pull_request",
        &repo,
        pr,
        event,
        "11111111-1111-4111-8111-111111111111",
    )?;
    ensure!(
        !event_key.is_empty()
            && event_key.len() <= MAX_EVENT_KEY
            && event_key.bytes().all(|byte| byte.is_ascii_graphic()),
        "Invalid provider event identity"
    );
    ensure!(
        !event_at.is_empty() && event_at.len() <= 64,
        "Invalid event timestamp"
    );
    ensure!(
        serde_json::to_vec(source)?.len() <= MAX_SOURCE_BYTES,
        "Provider event exceeds 1 MiB"
    );
    let pending_event = format!("pending_{event}");
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM automatic_pr_event_journal
         WHERE kind='pull_request' AND repo=?1 COLLATE NOCASE AND pr=?2 AND event_key=?3)",
        params![repo, pr, event_key],
        |row| row.get(0),
    )?;
    if exists {
        return Ok(0);
    }
    let path = if event == "synchronize" {
        "$.pull_request.head.sha"
    } else {
        "$.pull_request.base.ref"
    };
    let target = if event == "synchronize" {
        source.pointer("/pull_request/head/sha")
    } else {
        source.pointer("/pull_request/base/ref")
    }
    .and_then(Value::as_str)
    .context("Change is missing its target")?;
    let current_second = timestamp_second(db, event_at)?;
    let ambiguous: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM automatic_pr_event_journal
         WHERE kind='pull_request' AND repo=?1 COLLATE NOCASE AND pr=?2
           AND event IN (?3,?4) AND json_extract(source,?5)=?6
           AND COALESCE(json_extract(source,'$._wake_change_origin'),'poll') != ?7
           AND (?8 IS NULL OR event_at_sec>=?8)
           AND (?7!='poll' OR event_at_sec<=?9)
           AND (?7!='webhook' OR json_extract(source,'$._wake_change_lower_sec') IS NULL
                OR json_extract(source,'$._wake_change_lower_sec')<=?9))",
        params![
            repo,
            pr,
            event,
            pending_event,
            path,
            target,
            if webhook { "webhook" } else { "poll" },
            candidate_floor,
            current_second
        ],
        |row| row.get(0),
    )?;
    if force_pending || ambiguous {
        db.execute(
            "INSERT INTO automatic_pr_event_journal
             (kind,repo,pr,event,event_key,event_at_sec,event_at,source)
             VALUES('pull_request',?1,?2,?3,?4,?5,?6,?7)",
            params![
                repo,
                pr,
                pending_event,
                event_key,
                current_second,
                event_at,
                serde_json::to_string(source)?
            ],
        )?;
        return Ok(0);
    }
    Ok(record_event_in(
        db,
        "pull_request",
        &repo,
        &pr,
        event,
        event_at,
        event_key,
        source,
    )?
    .len())
}

pub(crate) fn record_closed_event(
    db: &Connection,
    repo: &str,
    pr: &str,
    event: &str,
    event_at: &str,
    event_key: &str,
    source: &Value,
) -> Result<Vec<Notification>> {
    initialize(db)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let notifications =
            record_closed_event_in(&tx, repo, pr, event, event_at, event_key, source)?;
        tx.commit()?;
        Ok(notifications)
    } else {
        record_closed_event_in(db, repo, pr, event, event_at, event_key, source)
    }
}

pub(crate) fn record_closed_event_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    event: &str,
    event_at: &str,
    event_key: &str,
    source: &Value,
) -> Result<Vec<Notification>> {
    initialize(db)?;
    let repo = repo.to_ascii_lowercase();
    let event_at_sec = timestamp_second(db, event_at)?;
    let mut notifications = ensure_closed_cycle_in(db, &repo, pr, event_at_sec)?;
    notifications.extend(record_event_in(
        db,
        "pull_request",
        &repo,
        pr,
        event,
        event_at,
        event_key,
        source,
    )?);
    Ok(notifications)
}

pub(crate) fn ensure_closed_cycle(
    db: &Connection,
    repo: &str,
    pr: &str,
    closed_at: &str,
) -> Result<Vec<Notification>> {
    initialize(db)?;
    let closed_at_sec = timestamp_second(db, closed_at)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let notifications = ensure_closed_cycle_in(&tx, repo, pr, closed_at_sec)?;
        tx.commit()?;
        Ok(notifications)
    } else {
        ensure_closed_cycle_in(db, repo, pr, closed_at_sec)
    }
}

pub(crate) fn ensure_closed_cycle_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    closed_at_sec: i64,
) -> Result<Vec<Notification>> {
    let repo = repo.to_ascii_lowercase();
    let inserted = db.execute(
        "INSERT OR IGNORE INTO automatic_pr_closed_cycles(repo,pr,closed_at_sec)
         SELECT ?1,?2,?3 WHERE NOT EXISTS(
             SELECT 1 FROM automatic_pr_closed_cycles
             WHERE repo=?1 COLLATE NOCASE AND pr=?2 AND closed_at_sec=?3)",
        params![repo, pr, closed_at_sec],
    )?;
    if inserted != 0 {
        // A newly observed close can disambiguate retained reopen evidence.
        db.execute(
            "UPDATE automatic_pr_pending_reopens SET timeline_scanned=0
             WHERE repo=?1 COLLATE NOCASE AND pr=?2",
            params![repo, pr],
        )?;
    }
    let current: Option<(i64, String, i64, Option<i64>)> = db
        .query_row(
            "SELECT epoch,state,closed_at_sec,reopened_at_sec
             FROM automatic_pr_lifecycle WHERE repo=?1 AND pr=?2",
            params![repo, pr],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if let Some((_, _, known_closed_at, _)) = current.as_ref()
        && closed_at_sec < *known_closed_at
    {
        return reconcile_pending_reopens_in(db, &repo, pr);
    }
    let (epoch, begin_cycle) = match current.as_ref() {
        None => (1, true),
        Some((epoch, state, closed_at, _)) if state == "closed" => {
            if closed_at_sec == *closed_at {
                (*epoch, false)
            } else if closed_at_sec > *closed_at {
                (epoch.saturating_add(1), true)
            } else {
                (*epoch, false)
            }
        }
        Some((epoch, _, _, Some(reopened_at))) if closed_at_sec > *reopened_at => {
            (epoch.saturating_add(1), true)
        }
        Some((epoch, _, _, _)) => (*epoch, false),
    };
    if begin_cycle {
        let changed = db.execute(
            "UPDATE automatic_pr_lifecycle SET epoch=?3,state='closed',closed_at_sec=?4,
                 reopened_at_sec=NULL,webhook_reopen_source_id=NULL,poll_reopen_source_id=NULL
             WHERE repo=?1 AND pr=?2",
            params![repo, pr, epoch, closed_at_sec],
        )?;
        if changed == 0 {
            db.execute(
                "INSERT INTO automatic_pr_lifecycle
                 (repo,pr,epoch,state,closed_at_sec,reopened_at_sec,
                  webhook_reopen_source_id,poll_reopen_source_id)
                 VALUES(?1,?2,?3,'closed',?4,NULL,NULL,NULL)",
                params![repo, pr, epoch, closed_at_sec],
            )?;
        }
    }
    reconcile_pending_reopens_in(db, &repo, pr)
}

fn reconcile_pending_reopens_in(
    db: &Connection,
    repo: &str,
    pr: &str,
) -> Result<Vec<Notification>> {
    let closed_at: Vec<i64> = {
        let mut statement = db.prepare(
            "SELECT closed_at_sec FROM automatic_pr_closed_cycles
             WHERE repo=?1 COLLATE NOCASE AND pr=?2 ORDER BY closed_at_sec",
        )?;
        statement
            .query_map(params![repo, pr], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut notifications = Vec::new();
    for pair in closed_at.windows(2) {
        notifications.extend(resolve_pending_reopen_interval_in(
            db,
            repo,
            pr,
            pair[0],
            Some(pair[1]),
        )?);
    }
    Ok(notifications)
}

pub(crate) fn record_reopened_event_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    source_kind: &str,
    event_at: &str,
    source_id: &str,
) -> Result<Vec<Notification>> {
    ensure!(
        matches!(source_kind, "webhook" | "poll"),
        "Invalid PR reopen source"
    );
    ensure!(
        !source_id.trim().is_empty(),
        "Missing PR reopen event identity"
    );
    initialize(db)?;
    let repo = repo.to_ascii_lowercase();
    let event_at_sec = timestamp_second(db, event_at)?;
    let current: Option<PrLifecycleState> = db
        .query_row(
            "SELECT epoch,state,closed_at_sec,webhook_reopen_source_id,poll_reopen_source_id
             FROM automatic_pr_lifecycle WHERE repo=?1 AND pr=?2",
            params![repo, pr],
            |row| {
                Ok(PrLifecycleState {
                    epoch: row.get(0)?,
                    state: row.get(1)?,
                    closed_at_sec: row.get(2)?,
                    webhook_reopen_source_id: row.get(3)?,
                    poll_reopen_source_id: row.get(4)?,
                })
            },
        )
        .optional()?;

    let Some(current) = current else {
        store_pending_reopen_in(
            db,
            &repo,
            pr,
            source_kind,
            source_id,
            event_at_sec,
            event_at,
        )?;
        return reconcile_pending_reopens_in(db, &repo, pr);
    };
    let same_cycle = if source_kind == "webhook" && current.state == "reopened" {
        current.webhook_reopen_source_id.as_deref() == Some(source_id)
    } else if source_kind == "webhook" {
        // `pull_request.updated_at` is not the lifecycle event timestamp. Keep new
        // webhook evidence pending until the REST timeline identifies its cycle.
        false
    } else if current.state == "closed" {
        event_at_sec > current.closed_at_sec
    } else {
        let seen_id = if source_kind == "webhook" {
            current.webhook_reopen_source_id.as_deref()
        } else {
            current.poll_reopen_source_id.as_deref()
        };
        seen_id == Some(source_id)
    };
    if !same_cycle {
        store_pending_reopen_in(
            db,
            &repo,
            pr,
            source_kind,
            source_id,
            event_at_sec,
            event_at,
        )?;
        return reconcile_pending_reopens_in(db, &repo, pr);
    }

    let event_key = format!("reopened:{}", current.closed_at_sec);
    let notifications = record_event_in(
        db,
        "pull_request",
        &repo,
        pr,
        "reopened",
        event_at,
        &event_key,
        &minimal_reopen_source(&repo, pr, event_at),
    )?;
    if current.state == "closed" {
        db.execute(
            "UPDATE automatic_pr_lifecycle SET state='reopened',reopened_at_sec=?3,
                 webhook_reopen_source_id=?4,poll_reopen_source_id=?5
             WHERE repo=?1 AND pr=?2 AND epoch=?6 AND state='closed'",
            params![
                repo,
                pr,
                event_at_sec,
                (source_kind == "webhook").then_some(source_id),
                (source_kind == "poll").then_some(source_id),
                current.epoch
            ],
        )?;
    }
    Ok(notifications)
}

#[cfg(test)]
pub(crate) fn record_reopened_event(
    db: &Connection,
    repo: &str,
    pr: &str,
    source_kind: &str,
    event_at: &str,
) -> Result<usize> {
    let source_id = format!("unidentified:{}", Uuid::new_v4());
    record_reopened_event_with_id(db, repo, pr, source_kind, event_at, &source_id)
}

pub(crate) fn record_reopened_event_with_id(
    db: &Connection,
    repo: &str,
    pr: &str,
    source_kind: &str,
    event_at: &str,
    source_id: &str,
) -> Result<usize> {
    initialize(db)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let notifications =
            record_reopened_event_in(&tx, repo, pr, source_kind, event_at, source_id)?.len();
        tx.commit()?;
        Ok(notifications)
    } else {
        Ok(record_reopened_event_in(db, repo, pr, source_kind, event_at, source_id)?.len())
    }
}

fn store_pending_reopen_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    source_kind: &str,
    source_id: &str,
    event_at_sec: i64,
    event_at: &str,
) -> Result<()> {
    let inserted = db.execute(
        "INSERT OR IGNORE INTO automatic_pr_pending_reopens
         (repo,pr,source_kind,source_id,event_at_sec,event_at,source)
         SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE NOT EXISTS(
             SELECT 1 FROM automatic_pr_pending_reopens
             WHERE repo=?1 COLLATE NOCASE AND pr=?2 AND source_kind=?3 AND source_id=?4)",
        params![
            repo,
            pr,
            source_kind,
            source_id,
            event_at_sec,
            event_at,
            serde_json::to_string(&minimal_reopen_source(repo, pr, event_at))?
        ],
    )?;
    if inserted != 0 && source_kind == "webhook" {
        let has_poll_state: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='github_poll_state')",
            [], |row| row.get(0),
        )?;
        if has_poll_state {
            // Fresh evidence should not inherit a long ambiguity backoff. An
            // HTTP failure or rate limit retains its existing retry deadline.
            let route = format!("/repos/{repo}/issues/{pr}/timeline");
            db.execute(
                "UPDATE github_poll_state SET next_poll_ms=0,backoff_ms=?2
                 WHERE endpoint=?1 COLLATE NOCASE AND page=0 AND error_category IS NULL
                   AND NOT EXISTS(SELECT 1 FROM github_poll_state AS failed
                       WHERE failed.endpoint=?1 COLLATE NOCASE AND failed.page=0
                         AND failed.error_category IS NOT NULL)",
                params![route, super::INTERVAL_MS],
            )?;
        }
    }
    Ok(())
}

fn minimal_reopen_source(repo: &str, pr: &str, event_at: &str) -> Value {
    serde_json::json!({
        "action":"reopened",
        "number":pr.parse::<i64>().ok(),
        "repository":{"full_name":repo},
        "pull_request":{"number":pr.parse::<i64>().ok(),"updated_at":event_at}
    })
}

fn resolve_pending_reopen_interval_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    after_sec: i64,
    closed_at_sec: Option<i64>,
) -> Result<Vec<Notification>> {
    // A single timeline event identifies this interval. A webhook timestamp
    // alone cannot prove that it describes this same transition.
    let mut candidates: Vec<PendingReopen> = {
        let mut statement = db.prepare(
            "SELECT source_kind,source_id,event_at_sec,event_at
             FROM automatic_pr_pending_reopens
             WHERE repo=?1 COLLATE NOCASE AND pr=?2 AND event_at_sec>?3
               AND (?4 IS NULL OR event_at_sec<?4)
             ORDER BY event_at_sec,source_kind",
        )?;
        statement
            .query_map(params![repo, pr, after_sec, closed_at_sec], |row| {
                Ok(PendingReopen {
                    source_kind: row.get(0)?,
                    source_id: row.get(1)?,
                    event_at_sec: row.get(2)?,
                    event_at: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    candidates.sort();
    candidates.dedup();
    let polls: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.source_kind == "poll")
        .collect();
    let [candidate] = polls.as_slice() else {
        return Ok(Vec::new());
    };
    let source = minimal_reopen_source(repo, pr, &candidate.event_at);
    let event_key = format!("reopened:{after_sec}");
    let notifications = record_event_in(
        db,
        "pull_request",
        repo,
        pr,
        "reopened",
        &candidate.event_at,
        &event_key,
        &source,
    )?;
    db.execute(
        "UPDATE automatic_pr_lifecycle SET state='reopened',reopened_at_sec=?3,
             webhook_reopen_source_id=NULL,poll_reopen_source_id=?4
         WHERE repo=?1 AND pr=?2 AND closed_at_sec=?5 AND state='closed'",
        params![
            repo,
            pr,
            candidate.event_at_sec,
            candidate.source_id,
            after_sec
        ],
    )?;
    db.execute(
        "DELETE FROM automatic_pr_pending_reopens
         WHERE repo=?1 COLLATE NOCASE AND pr=?2 AND source_kind=?3 AND source_id=?4",
        params![repo, pr, candidate.source_kind, candidate.source_id],
    )?;
    Ok(notifications)
}

pub(crate) fn mark_pending_reopens_timeline_scanned_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    through_id: i64,
) -> Result<()> {
    db.execute(
        "UPDATE automatic_pr_pending_reopens SET timeline_scanned=1
         WHERE repo=?1 COLLATE NOCASE AND pr=?2 AND id<=?3",
        params![repo, pr, through_id],
    )?;
    Ok(())
}

pub(crate) fn reopen_timeline_floor(
    db: &Connection,
    repo: &str,
    pr: &str,
) -> Result<(Option<i64>, bool)> {
    initialize(db)?;
    let repo = repo.to_ascii_lowercase();
    let closed_floor: Option<i64> = db.query_row(
        "SELECT MIN(cycle.closed_at_sec) FROM automatic_pr_closed_cycles AS cycle
         JOIN automatic_pr_lifecycle AS lifecycle
           ON cycle.repo=lifecycle.repo COLLATE NOCASE AND cycle.pr=lifecycle.pr
         WHERE cycle.repo=?1 COLLATE NOCASE AND cycle.pr=?2
           AND cycle.repo=lifecycle.repo COLLATE NOCASE AND cycle.pr=lifecycle.pr
           AND lifecycle.repo=?1 AND lifecycle.state='closed'",
        params![repo, pr],
        |row| row.get(0),
    )?;
    let pending_floor: Option<i64> = db.query_row(
        "SELECT MIN(event_at_sec) FROM automatic_pr_pending_reopens
         WHERE repo=?1 COLLATE NOCASE AND pr=?2",
        params![repo, pr],
        |row| row.get(0),
    )?;
    let registration_floor: Option<i64> = db.query_row(
        "SELECT MIN(registered_at_sec) FROM automatic_pr_notification_listeners
         WHERE repo=?1 COLLATE NOCASE AND pr=?2",
        params![repo, pr],
        |row| row.get(0),
    )?;
    let needs_timeline: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM automatic_pr_pending_reopens
         WHERE repo=?1 COLLATE NOCASE AND pr=?2 AND (timeline_scanned=0 OR source_kind='webhook'))",
        params![repo, pr],
        |row| row.get(0),
    )?;
    Ok((
        [closed_floor, pending_floor, registration_floor]
            .into_iter()
            .flatten()
            .min(),
        needs_timeline,
    ))
}

pub(crate) fn timestamp_second(db: &Connection, timestamp: &str) -> Result<i64> {
    db.query_row(
        "SELECT CAST(strftime('%s',?1) AS INTEGER)",
        [timestamp],
        |row| row.get(0),
    )
    .context("Invalid PR lifecycle timestamp")
}

/// Store a PR/review event received through the HMAC-verified GitHub webhook route.
/// The caller must verify the signature over the raw request body before calling this.
/// Polling and webhook ingestion use the same event key, so provider retries and either
/// arrival order create at most one automatic notification per destination.
pub(crate) fn accept_authenticated_webhook(
    db: &Connection,
    event: &str,
    payload: &Value,
) -> Result<usize> {
    accept_authenticated_webhook_inner(db, event, None, payload)
}

/// Accept a webhook only after the caller verifies HMAC over the raw request body.
/// `delivery_id` is GitHub's X-GitHub-Delivery value, used to deduplicate pending replays.
pub(crate) fn accept_authenticated_webhook_with_delivery_id(
    db: &Connection,
    event: &str,
    delivery_id: &str,
    payload: &Value,
) -> Result<usize> {
    ensure!(!delivery_id.trim().is_empty(), "Empty webhook delivery ID");
    accept_authenticated_webhook_inner(db, event, Some(delivery_id), payload)
}

fn accept_authenticated_webhook_inner(
    db: &Connection,
    event: &str,
    delivery_id: Option<&str>,
    payload: &Value,
) -> Result<usize> {
    let repo = payload["repository"]["full_name"]
        .as_str()
        .filter(|value| !value.is_empty())
        .context("Webhook is missing repository.full_name")?;
    let pr_value = payload["pull_request"]["number"]
        .as_i64()
        .or_else(|| payload["number"].as_i64())
        .filter(|number| *number > 0)
        .context("Webhook is missing a valid pull request number")?;
    let pr = pr_value.to_string();

    match event {
        "pull_request" => {
            let action = payload["action"].as_str().unwrap_or_default();
            let change = match action {
                "synchronize" => Some("synchronize"),
                "edited"
                    if payload
                        .pointer("/changes/base/ref/from")
                        .and_then(Value::as_str)
                        .is_some() =>
                {
                    Some("base_changed")
                }
                _ => None,
            };
            if let Some(change) = change {
                ensure!(
                    serde_json::to_vec(payload)?.len() <= MAX_SOURCE_BYTES,
                    "Provider event exceeds 1 MiB"
                );
                let event_at = payload["pull_request"]["updated_at"]
                    .as_str()
                    .context("Changed pull request webhook is missing updated_at")?;
                let identity = delivery_id
                    .map(str::to_owned)
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                let key = super::stable_source_key(
                    "pull_request",
                    &repo.to_ascii_lowercase(),
                    &pr,
                    change,
                    "",
                    &["webhook", &identity],
                );
                let mut source = payload.clone();
                source["_wake_change_origin"] = Value::String("webhook".into());
                if change == "base_changed" {
                    source["changes"]["base"]["ref"] =
                        payload["changes"]["base"]["ref"]["from"].clone();
                }
                initialize(db)?;
                let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
                let count = record_change_in(
                    &tx,
                    repo,
                    &pr,
                    change,
                    event_at,
                    &key,
                    &source,
                    true,
                    delivery_id.is_none(),
                    Some(timestamp_second(&tx, event_at)?),
                )?;
                tx.commit()?;
                return Ok(count);
            }
            if action == "reopened" {
                let event_at = payload["pull_request"]["updated_at"]
                    .as_str()
                    .context("Reopened pull request webhook is missing updated_at")?;
                if let Some(delivery_id) = delivery_id {
                    let source_id = format!("webhook:{delivery_id}");
                    return record_reopened_event_with_id(
                        db, repo, &pr, "webhook", event_at, &source_id,
                    );
                }
                let source = serde_json::to_string(payload)?;
                let source_id = super::stable_source_key(
                    "pull_request",
                    &repo.to_ascii_lowercase(),
                    &pr,
                    "webhook_reopened",
                    "",
                    &[&source],
                );
                return record_reopened_event_with_id(
                    db, repo, &pr, "webhook", event_at, &source_id,
                );
            }
            if action != "closed" {
                return Ok(0);
            }
            let pull = &payload["pull_request"];
            let merged = pull["merged"].as_bool().unwrap_or(false);
            let event_name = if merged { "merged" } else { "closed" };
            let event_at = if merged {
                pull["merged_at"].as_str()
            } else {
                pull["closed_at"].as_str()
            }
            .context("Closed pull request webhook is missing its event timestamp")?;
            let key = super::stable_source_key(
                "pull_request",
                &repo.to_ascii_lowercase(),
                &pr,
                event_name,
                "",
                &[event_at],
            );
            Ok(record_closed_event(db, repo, &pr, event_name, event_at, &key, payload)?.len())
        }
        "pull_request_review" => {
            if payload["action"].as_str() != Some("submitted") {
                return Ok(0);
            }
            let review = &payload["review"];
            let review_id = review["id"]
                .as_u64()
                .filter(|id| *id > 0)
                .context("Submitted review webhook is missing its review ID")?
                .to_string();
            let submitted_at = review["submitted_at"]
                .as_str()
                .filter(|value| !value.is_empty())
                .context("Submitted review webhook is missing its timestamp")?;
            let state = match review["state"].as_str().unwrap_or_default() {
                "APPROVED" | "approved" => "approved",
                "CHANGES_REQUESTED" | "changes_requested" => "changes_requested",
                "COMMENTED" | "commented" => "commented",
                _ => return Ok(0),
            };
            let notification_event = match state {
                "approved" | "changes_requested" => state,
                _ => "submitted",
            };
            let identity = [review_id.as_str(), submitted_at];
            let key = super::stable_source_key(
                "review",
                &repo.to_ascii_lowercase(),
                &pr,
                notification_event,
                state,
                &identity,
            );
            let mut normalized = payload.clone();
            normalized["review"]["state"] = Value::String(state.to_owned());
            Ok(record_event(
                db,
                "review",
                repo,
                &pr,
                notification_event,
                submitted_at,
                &key,
                &normalized,
            )?
            .len())
        }
        _ => Ok(0),
    }
}

/// List durable notifications not yet accepted by the downstream queue.
#[cfg(test)]
pub(crate) fn pending(db: &Connection) -> Result<Vec<Notification>> {
    initialize(db)?;
    let mut statement = db.prepare(
        "SELECT id,kind,repo,pr,thread,event,event_key,source,state
         FROM automatic_pr_notifications WHERE state='pending' ORDER BY created_at,rowid",
    )?;
    statement
        .query_map([], |row| {
            let source: String = row.get(7)?;
            Ok(Notification {
                id: row.get(0)?,
                kind: row.get(1)?,
                repo: row.get(2)?,
                pr: row.get(3)?,
                thread: row.get(4)?,
                event: row.get(5)?,
                event_key: row.get(6)?,
                state: row.get(8)?,
                source: serde_json::from_str(&source).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("Could not read pending automatic PR notifications")
}

/// Claim before calling the downstream queue. Claims are never retried automatically.
#[cfg(test)]
pub(crate) fn claim(db: &Connection, id: &str) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let claimed = tx.execute(
        "UPDATE automatic_pr_notifications SET state='sending'
         WHERE id=?1 AND state='pending'",
        [id],
    )? != 0;
    tx.commit()?;
    Ok(claimed)
}

/// Mark queued only after downstream queue acceptance is confirmed.
pub(crate) fn mark_queued(db: &Connection, id: &str) -> Result<bool> {
    initialize(db)?;
    Ok(db.execute(
        "UPDATE automatic_pr_notifications SET state='queued'
         WHERE id=?1 AND state='sending'",
        [id],
    )? != 0)
}

/// Keep an ambiguous or interrupted send out of the automatic retry queue.
pub(crate) fn mark_uncertain(db: &Connection, id: &str) -> Result<bool> {
    initialize(db)?;
    Ok(db.execute(
        "UPDATE automatic_pr_notifications SET state='needs_attention'
         WHERE id=?1 AND state='sending'",
        [id],
    )? != 0)
}

/// Return to pending only when the caller proves the downstream send was never attempted.
fn release_before_send_at(db: &Connection, id: &str, available_at_ms: i64) -> Result<bool> {
    initialize(db)?;
    Ok(db.execute(
        "UPDATE automatic_pr_notifications SET state='pending',available_at_ms=?2
         WHERE id=?1 AND state='sending'",
        params![id, available_at_ms],
    )? != 0)
}

/// Surface interrupted and uncertain sends for explicit reconciliation, never retry them.
pub(crate) fn attention_details(db: &Connection) -> Result<(i64, Vec<Value>)> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='automatic_pr_notifications')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok((0, Vec::new()));
    }
    let mut statement = db.prepare(
        "SELECT id,kind,repo,pr,thread,event,event_key,state,count(*) OVER ()
         FROM automatic_pr_notifications
         WHERE state IN ('sending','needs_attention') ORDER BY created_at,id LIMIT 50",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(8)?,
            serde_json::json!({
                "queue_identity": row.get::<_, String>(0)?,
                "kind": row.get::<_, String>(1)?,
                "repo": row.get::<_, String>(2)?,
                "pr": row.get::<_, String>(3)?,
                "thread": row.get::<_, String>(4)?,
                "event": row.get::<_, String>(5)?,
                "event_key": row.get::<_, String>(6)?,
                "state": row.get::<_, String>(7)?,
            }),
        ))
    })?;
    let rows = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("Could not read uncertain automatic PR notifications")?;
    let count = rows.first().map_or(0, |row| row.0);
    Ok((count, rows.into_iter().map(|row| row.1).collect()))
}

/// Read one live page without loading event payloads or modifying deliveries.
pub(crate) fn attention_page(db: &Connection, cursor: Option<&str>) -> Result<Value> {
    let after: Option<(String, String)> = cursor
        .map(|cursor| -> Result<(String, String)> {
            ensure!(cursor.len() <= 256, "Invalid attention cursor");
            let (created, id): (String, String) =
                serde_json::from_str(cursor).context("Invalid attention cursor")?;
            ensure!(
                !created.is_empty() && created.len() <= 64 && !id.is_empty() && id.len() <= 128,
                "Invalid attention cursor"
            );
            Ok((created, id))
        })
        .transpose()?;
    let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='automatic_pr_notifications')", [], |row| row.get(0))?;
    if !exists {
        return Ok(serde_json::json!({"items":[],"has_more":false,"next_cursor":null}));
    }
    let mut statement = db.prepare(
        "SELECT id,kind,repo,pr,thread,event,event_key,state,created_at
         FROM automatic_pr_notifications WHERE state IN ('sending','needs_attention')
         AND (?1 IS NULL OR (created_at,id)>(?1,?2)) ORDER BY created_at,id LIMIT 51",
    )?;
    let mut rows = statement.query_map(params![after.as_ref().map(|v| &v.0), after.as_ref().map(|v| &v.1)], |row| {
        let id: String = row.get(0)?;
        let created: String = row.get(8)?;
        let item = serde_json::json!({"queue_identity":id.clone(),"kind":row.get::<_,String>(1)?,
            "repo":row.get::<_,String>(2)?,"pr":row.get::<_,String>(3)?,
            "thread":row.get::<_,String>(4)?,"event":row.get::<_,String>(5)?,
            "event_key":row.get::<_,String>(6)?,"state":row.get::<_,String>(7)?});
        Ok((created,id,item))
    })?.collect::<rusqlite::Result<Vec<_>>>()?;
    let has_more = rows.len() > 50;
    if has_more {
        rows.pop();
    }
    let next_cursor = if has_more {
        rows.last()
            .map(|row| serde_json::to_string(&(&row.0, &row.1)))
            .transpose()?
    } else {
        None
    };
    Ok(
        serde_json::json!({"items":rows.into_iter().map(|row| row.2).collect::<Vec<_>>(),
        "has_more":has_more,"next_cursor":next_cursor}),
    )
}

#[cfg(test)]
pub(crate) fn needs_attention(db: &Connection) -> Result<Vec<Notification>> {
    initialize(db)?;
    let mut statement = db.prepare(
        "SELECT id,kind,repo,pr,thread,event,event_key,source,state
         FROM automatic_pr_notifications
         WHERE state IN ('sending','needs_attention') ORDER BY created_at,id",
    )?;
    statement
        .query_map([], |row| {
            let source: String = row.get(7)?;
            Ok(Notification {
                id: row.get(0)?,
                kind: row.get(1)?,
                repo: row.get(2)?,
                pr: row.get(3)?,
                thread: row.get(4)?,
                event: row.get(5)?,
                event_key: row.get(6)?,
                source: serde_json::from_str(&source).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                state: row.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("Could not read automatic PR notifications needing attention")
}

/// Queue bounded batches of notifications. Ambiguous outcomes are retained for review.
pub(crate) fn dispatch(
    db: &mut Connection,
    codex: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<usize> {
    dispatch_with(db, |thread, message, id, resume| {
        crate::execution::queue_with_identity(codex, thread, message, id, resume, timeout)
    })
}

fn dispatch_with(
    db: &mut Connection,
    queue: impl FnMut(&str, &str, &str, bool) -> Result<(String, Option<String>)>,
) -> Result<usize> {
    dispatch_with_clock(db, queue, super::now_ms)
}

fn dispatch_with_clock(
    db: &mut Connection,
    mut queue: impl FnMut(&str, &str, &str, bool) -> Result<(String, Option<String>)>,
    mut now: impl FnMut() -> i64,
) -> Result<usize> {
    const BATCH: usize = 16;
    const BEFORE_SEND_RETRY_MS: i64 = 5_000;
    let mut attempted = 0;
    let mut attempted_ids = HashSet::new();
    for _ in 0..BATCH {
        let claim_time = now();
        let Some(notification) = claim_next(db, claim_time, &attempted_ids)? else {
            break;
        };
        attempted_ids.insert(notification.id.clone());
        let lock = codex_wake::pr_ci_runtime::try_native_wake_lock(db, &notification.id);
        let Ok(Some(_lock)) = lock else {
            release_before_send_at(
                db,
                &notification.id,
                claim_time.saturating_add(BEFORE_SEND_RETRY_MS),
            )?;
            attempted += 1;
            continue;
        };
        let intent = match codex_wake::pr_ci_runtime::begin_native_wake_intent(
            db,
            &notification.thread,
            &notification.id,
            codex_wake::pr_ci_runtime::NativeWakeOrigin::Pr {
                id: notification.id.clone(),
            },
            claim_time.saturating_add(codex_wake::pr_ci_runtime::NATIVE_WAKE_INTENT_LEASE_MS),
        ) {
            Ok(token) => token,
            Err(error) => {
                if codex_wake::pr_ci_runtime::native_wake_intent_exists(&error) {
                    mark_uncertain(db, &notification.id)?;
                } else {
                    release_before_send_at(
                        db,
                        &notification.id,
                        now().saturating_add(BEFORE_SEND_RETRY_MS),
                    )?;
                }
                attempted += 1;
                continue;
            }
        };
        let message = format!(
            "Automatic GitHub PR notification: {}#{} {}. Review: https://github.com/{}/pull/{}",
            notification.repo,
            notification.pr,
            notification.event,
            notification.repo,
            notification.pr,
        );
        match queue(&notification.thread, &message, &notification.id, true) {
            Ok((state, reason)) if state == "queued" => {
                let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
                if let Some(reason @ "native_queue_resume_warning") = reason.as_deref() {
                    codex_wake::pr_ci_runtime::record_native_wake_recovery(
                        &tx,
                        &notification.thread,
                        reason,
                        &notification.id,
                    )?;
                }
                ensure!(
                    mark_queued(&tx, &notification.id)?,
                    "Lost notification claim after queue acceptance"
                );
                codex_wake::pr_ci_runtime::finish_native_wake_intent(
                    &tx,
                    &notification.thread,
                    &intent,
                )?;
                tx.commit()?;
            }
            Err(error) if crate::execution::before_send_retry_reason(&error).is_some() => {
                let retry_after = now().saturating_add(BEFORE_SEND_RETRY_MS);
                let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
                ensure!(
                    release_before_send_at(&tx, &notification.id, retry_after)?,
                    "Lost notification claim before send"
                );
                codex_wake::pr_ci_runtime::finish_native_wake_intent(
                    &tx,
                    &notification.thread,
                    &intent,
                )?;
                tx.commit()?;
            }
            _ => {
                ensure!(
                    mark_uncertain(db, &notification.id)?,
                    "Lost notification claim with uncertain send outcome"
                );
            }
        }
        attempted += 1;
    }
    Ok(attempted)
}

fn claim_next(
    db: &Connection,
    now_ms: i64,
    excluded_ids: &HashSet<String>,
) -> Result<Option<Notification>> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let exclusion = if excluded_ids.is_empty() {
        String::new()
    } else {
        format!(
            " AND id NOT IN ({})",
            (2..=excluded_ids.len() + 1)
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let sql = format!(
            "SELECT id,kind,repo,pr,thread,event,event_key,source FROM automatic_pr_notifications
             WHERE state='pending' AND available_at_ms<=?1{exclusion}
             ORDER BY MAX(available_at_ms,COALESCE(CAST(ROUND((julianday(created_at)-2440587.5)*86400000) AS INTEGER),0)),rowid LIMIT 1"
        );
    let mut values = Vec::with_capacity(excluded_ids.len() + 1);
    values.push(rusqlite::types::Value::Integer(now_ms));
    values.extend(
        excluded_ids
            .iter()
            .cloned()
            .map(rusqlite::types::Value::Text),
    );
    let row = tx
        .query_row(&sql, rusqlite::params_from_iter(values), |row| {
            let source: String = row.get(7)?;
            Ok(Notification {
                id: row.get(0)?,
                kind: row.get(1)?,
                repo: row.get(2)?,
                pr: row.get(3)?,
                thread: row.get(4)?,
                event: row.get(5)?,
                event_key: row.get(6)?,
                source: serde_json::from_str(&source).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                state: "sending".into(),
            })
        })
        .optional()?;
    let Some(notification) = row else {
        tx.commit()?;
        return Ok(None);
    };
    let changed = tx.execute(
        "UPDATE automatic_pr_notifications SET state='sending'
         WHERE id=?1 AND state='pending'",
        [&notification.id],
    )?;
    ensure!(changed == 1, "Could not claim pending PR notification");
    tx.commit()?;
    Ok(Some(notification))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_notification_columns_are_added_without_losing_rows() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        db.execute_batch(
            "INSERT INTO automatic_pr_notifications
             (id,kind,repo,pr,thread,event,event_key,source,state)
             VALUES('existing','pull_request','owner/repo','7','thread','closed','key','{}','needs_attention');
             INSERT INTO automatic_pr_pending_reopens
             (repo,pr,source_kind,source_id,event_at_sec,event_at,source)
             VALUES('owner/repo','7','webhook','source',1,'1970-01-01T00:00:01Z','{}');
             ALTER TABLE automatic_pr_notifications DROP COLUMN available_at_ms;
             ALTER TABLE automatic_pr_pending_reopens DROP COLUMN timeline_scanned;",
        )
        .unwrap();
        initialize(&db).unwrap();
        let notification: (String, String, i64) = db
            .query_row(
                "SELECT id,state,available_at_ms FROM automatic_pr_notifications",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let reopen: (String, i64) = db
            .query_row(
                "SELECT source_id,timeline_scanned FROM automatic_pr_pending_reopens",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            notification,
            ("existing".into(), "needs_attention".into(), 0)
        );
        assert_eq!(reopen, ("source".into(), 0));
        initialize(&db).unwrap();
    }

    #[test]
    fn same_second_notifications_keep_insertion_order() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        for (id, event) in [("z", "closed"), ("a", "reopened")] {
            db.execute(
                "INSERT INTO automatic_pr_notifications
                 (id,kind,repo,pr,thread,event,event_key,source,created_at)
                 VALUES(?1,'pull_request','owner/repo','7','thread',?2,?2,'{}','2025-01-01 00:00:00')",
                params![id, event],
            )
            .unwrap();
        }
        assert_eq!(pending(&db).unwrap()[0].event, "closed");
        assert_eq!(
            claim_next(&db, 0, &HashSet::new()).unwrap().unwrap().event,
            "closed"
        );
    }

    #[test]
    fn late_registration_dispatches_journal_in_event_order() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        for (event, key, time) in [
            ("closed", "close-1", 1_735_689_601_i64),
            ("reopened", "reopen-1", 1_735_689_602),
            ("closed", "close-2", 1_735_689_603),
        ] {
            db.execute(
                "INSERT INTO automatic_pr_event_journal
                 (kind,repo,pr,event,event_key,event_at_sec,event_at,source)
                 VALUES('pull_request','owner/repo','7',?1,?2,?3,'2025-01-01T00:00:00Z','{}')",
                params![event, key, time],
            )
            .unwrap();
        }
        register_in_since(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "11111111-1111-4111-8111-111111111111",
            1_735_689_600,
        )
        .unwrap();
        for (key, id) in [("close-1", "z"), ("reopen-1", "y"), ("close-2", "x")] {
            db.execute(
                "UPDATE automatic_pr_notifications SET id=?2,created_at='2025-01-01 00:00:00' WHERE event_key=?1",
                params![key, id],
            )
            .unwrap();
        }
        for expected in ["closed", "reopened", "closed"] {
            let notice = claim_next(&db, 0, &HashSet::new()).unwrap().unwrap();
            assert_eq!(notice.event, expected);
        }
    }
    use serde_json::json;

    fn reopen_key(db: &Connection, closed_at: &str) -> String {
        format!("reopened:{}", timestamp_second(db, closed_at).unwrap())
    }

    #[test]
    fn distinct_events_fan_out_once_and_preserve_old_subscription_delivery() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE waits(repo TEXT,run_id INTEGER,attempt INTEGER,sha TEXT,state TEXT)",
        )
        .unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        crate::conditions::initialize(&db).unwrap();
        crate::polling::initialize(&db).unwrap();
        db.execute(
            "INSERT INTO github_poll_state(endpoint,page,cursor,next_poll_ms,backoff_ms,calls)
             VALUES('/repos/owner/repo/pulls/7',0,'old-global-cursor',0,60000,1)",
            [],
        )
        .unwrap();
        let first = "11111111-1111-4111-8111-111111111111";
        let second = "22222222-2222-4222-8222-222222222222";
        let old =
            crate::subscriptions::subscribe(&db, "review", "owner/repo", "7", "submitted", first)
                .unwrap();
        db.execute(
            "UPDATE subscriptions SET state='queued',reason='old_delivery' WHERE id=?1",
            [&old],
        )
        .unwrap();

        assert!(register(&db, "pull_request", "owner/repo", "7", first).unwrap());
        assert!(!register(&db, "pull_request", "owner/repo", "7", first).unwrap());
        register(&db, "pull_request", "owner/repo", "7", second).unwrap();
        register(&db, "review", "owner/repo", "7", first).unwrap();
        register(&db, "review", "owner/repo", "7", second).unwrap();

        let targets = super::super::targets(&db, true).unwrap();
        assert!(
            targets
                .pull_requests
                .iter()
                .any(|r| r.repo == "owner/repo" && r.resource == "7")
        );
        assert!(
            targets
                .reviews
                .iter()
                .any(|r| r.repo == "owner/repo" && r.resource == "7")
        );

        let pr_source = json!({"pull_request":{"number":7,"head":{"sha":"abc"}}});
        let review_source = json!({"review":{"id":91,"state":"approved"}});
        assert!(
            record_event(
                &db,
                "review",
                "owner/repo",
                "7",
                "approved",
                "2020-01-01T00:00:00Z",
                "historical-review",
                &review_source,
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "synchronize",
                "2020-01-01T00:00:00Z",
                "historical-pr-event",
                &pr_source,
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "synchronize",
                "2099-01-01T00:00:00Z",
                "pr-event-1",
                &pr_source,
            )
            .unwrap()
            .len(),
            2
        );
        assert_eq!(
            record_event(
                &db,
                "review",
                "owner/repo",
                "7",
                "approved",
                "2099-01-01T00:00:01Z",
                "review-event-1",
                &review_source,
            )
            .unwrap()
            .len(),
            2
        );
        assert!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "synchronize",
                "2099-01-01T00:00:00Z",
                "pr-event-1",
                &pr_source,
            )
            .unwrap()
            .is_empty()
        );

        let initial_pending = pending(&db).unwrap();
        assert_eq!(initial_pending.len(), 4);
        assert_eq!(
            crate::polling::status(&db).unwrap()["automatic_pr_notifications"]["pending"],
            4
        );
        assert_eq!(
            initial_pending
                .iter()
                .filter(|notification| notification.event_key == "pr-event-1")
                .count(),
            2
        );
        assert!(claim(&db, &initial_pending[0].id).unwrap());
        assert!(mark_uncertain(&db, &initial_pending[0].id).unwrap());
        assert!(!claim(&db, &initial_pending[0].id).unwrap());
        assert_eq!(pending(&db).unwrap().len(), 3);
        assert_eq!(needs_attention(&db).unwrap()[0].state, "needs_attention");
        let status = crate::polling::status(&db).unwrap();
        assert_eq!(status["automatic_pr_notifications"]["pending"], 3);
        assert_eq!(status["automatic_pr_notifications"]["needs_attention"], 1);
        let detail = &status["automatic_pr_notifications"]["attention_details"][0];
        assert_eq!(detail["queue_identity"], initial_pending[0].id);
        assert_eq!(detail["thread"], initial_pending[0].thread);
        assert_eq!(detail["repo"], "owner/repo");
        assert_eq!(detail["pr"], "7");
        assert_eq!(detail["event"], initial_pending[0].event);
        assert_eq!(detail["state"], "needs_attention");
        assert!(detail.get("source").is_none());
        assert!(!mark_queued(&db, &initial_pending[0].id).unwrap());
        let old_delivery: (String, Option<String>) = db
            .query_row(
                "SELECT state,reason FROM subscriptions WHERE id=?1",
                [&old],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(old_delivery, ("queued".into(), Some("old_delivery".into())));
    }

    #[test]
    fn status_limits_uncertain_details_without_exposing_source_or_changing_delivery() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        crate::polling::initialize(&db).unwrap();
        for index in 0..52 {
            db.execute(
                "INSERT INTO automatic_pr_notifications
                (id,kind,repo,pr,thread,event,event_key,source,state,created_at)
                VALUES(?1,'pull_request','owner/repo','7','thread','closed',?1,
                '{\"private\":\"secret-payload\"}',?2,'2000-01-01 00:00:00')",
                params![
                    format!("id-{index:02}"),
                    if index == 51 {
                        "pending"
                    } else if index == 49 {
                        "sending"
                    } else {
                        "needs_attention"
                    }
                ],
            )
            .unwrap();
        }
        let before = db.total_changes();
        let status = crate::polling::status(&db).unwrap();
        assert_eq!(db.total_changes(), before);
        let notifications = &status["automatic_pr_notifications"];
        assert_eq!(notifications["needs_attention"], 51);
        assert_eq!(
            notifications["attention_details"].as_array().unwrap().len(),
            50
        );
        assert_eq!(notifications["attention_details_truncated"], true);
        assert_eq!(
            notifications["attention_details"][0]["queue_identity"],
            "id-00"
        );
        assert_eq!(notifications["attention_details"][49]["state"], "sending");
        assert!(!status.to_string().contains("secret-payload"));
        db.execute_batch("PRAGMA query_only=ON").unwrap();
        let first = attention_page(&db, None).unwrap();
        assert_eq!(first["items"].as_array().unwrap().len(), 50);
        assert_eq!(first["has_more"], true);
        let cursor = first["next_cursor"].as_str().unwrap();
        let second = attention_page(&db, Some(cursor)).unwrap();
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert_eq!(second["items"][0]["queue_identity"], "id-50");
        assert_eq!(second["has_more"], false);
        assert!(second["next_cursor"].is_null());
        assert!(!first.to_string().contains("secret-payload"));
        assert!(!second.to_string().contains("secret-payload"));
        assert!(attention_page(&db, Some("invalid")).is_err());
        assert_eq!(db.total_changes(), before);
    }

    #[test]
    fn authenticated_webhooks_share_poll_event_ids_and_deduplicate_redelivery() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        register(&db, "review", "owner/repo", "7", thread).unwrap();

        let closed = json!({
            "action":"closed",
            "number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"merged":false,
                "closed_at":"2099-01-01T00:00:00Z"}
        });
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request", &closed).unwrap(),
            1
        );
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request", &closed).unwrap(),
            0
        );
        let closed_key = super::super::stable_source_key(
            "pull_request",
            "owner/repo",
            "7",
            "closed",
            "",
            &["2099-01-01T00:00:00Z"],
        );
        assert!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "closed",
                "2099-01-01T00:00:00Z",
                &closed_key,
                &closed,
            )
            .unwrap()
            .is_empty()
        );

        let review = json!({
            "action":"submitted",
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7},
            "review":{"id":99,"state":"APPROVED",
                "submitted_at":"2099-01-01T00:00:01Z"}
        });
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request_review", &review).unwrap(),
            1
        );
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request_review", &review).unwrap(),
            0
        );
        let review_key = super::super::stable_source_key(
            "review",
            "owner/repo",
            "7",
            "approved",
            "approved",
            &["99", "2099-01-01T00:00:01Z"],
        );
        assert!(
            record_event(
                &db,
                "review",
                "owner/repo",
                "7",
                "approved",
                "2099-01-01T00:00:01Z",
                &review_key,
                &review,
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(pending(&db).unwrap().len(), 2);
    }

    #[test]
    fn listener_registration_replays_durable_lifecycle_events_once() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let closed = json!({
            "action":"closed","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"merged":false,
                "closed_at":"2099-01-01T00:00:10Z"}
        });
        let closed_key = "provider-close:91";
        assert!(
            record_closed_event(
                &db,
                "owner/repo",
                "7",
                "closed",
                "2099-01-01T00:00:10Z",
                closed_key,
                &closed,
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            record_reopened_event_with_id(
                &db,
                "owner/repo",
                "7",
                "webhook",
                "2099-01-01T00:00:20Z",
                "provider-reopen:92",
            )
            .unwrap(),
            0
        );
        assert_eq!(
            record_reopened_event_with_id(
                &db,
                "owner/repo",
                "7",
                "poll",
                "2099-01-01T00:00:20Z",
                "timeline:92",
            )
            .unwrap(),
            0,
            "REST evidence should finalize the pending webhook before listener replay"
        );

        let thread = "11111111-1111-4111-8111-111111111111";
        let boundary = timestamp_second(&db, "2099-01-01T00:00:00Z").unwrap();
        register_in_since(&db, "pull_request", "owner/repo", "7", thread, boundary).unwrap();
        assert_eq!(pending(&db).unwrap().len(), 2);
        assert_eq!(
            replay_listener_events_in(&db, "pull_request", "owner/repo", "7", thread).unwrap(),
            0
        );
        let close = pending(&db)
            .unwrap()
            .into_iter()
            .find(|notice| notice.event == "closed")
            .unwrap();
        assert_eq!(close.event_key, closed_key);
        assert_eq!(close.source, closed);
    }

    #[test]
    fn webhook_only_changes_replay_each_delivery_once() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let payload = |action: &str, head: &str, base: &str, from: &str| {
            json!({
                "action":action,"number":7,"repository":{"full_name":"Owner/Repo"},
                "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:00Z",
                    "head":{"sha":head},"base":{"ref":base}},
                "changes":{"base":{"ref":{"from":from}}}
            })
        };
        let events = [
            ("h1", payload("synchronize", "b", "main", "main")),
            ("h2", payload("synchronize", "a", "main", "main")),
            ("b1", payload("edited", "a", "release", "main")),
            ("b2", payload("edited", "a", "main", "release")),
        ];
        for (id, event) in &events {
            assert_eq!(
                accept_authenticated_webhook_with_delivery_id(&db, "pull_request", id, event)
                    .unwrap(),
                0
            );
            assert_eq!(
                accept_authenticated_webhook_with_delivery_id(&db, "pull_request", id, event)
                    .unwrap(),
                0
            );
        }
        let boundary = timestamp_second(&db, "2099-01-01T00:00:00Z").unwrap();
        register_in_since(&db, "pull_request", "owner/repo", "7", thread, boundary).unwrap();
        assert_eq!(pending(&db).unwrap().len(), 4);
        assert_eq!(
            replay_listener_events_in(&db, "pull_request", "owner/repo", "7", thread).unwrap(),
            0
        );
    }

    #[test]
    fn unidentified_webhook_stays_pending_and_failed_journal_rolls_back() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        let payload = json!({"action":"synchronize","number":7,"repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:00Z","head":{"sha":"b"}}});
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request", &payload).unwrap(),
            0
        );
        assert!(pending(&db).unwrap().is_empty());
        let uncertain: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_event_journal WHERE event='pending_synchronize'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(uncertain, 1);
        db.execute_batch("CREATE TRIGGER reject_change BEFORE INSERT ON automatic_pr_event_journal BEGIN SELECT RAISE(ABORT, 'stop'); END;").unwrap();
        assert!(
            accept_authenticated_webhook_with_delivery_id(
                &db,
                "pull_request",
                "delivery",
                &payload
            )
            .is_err()
        );
        db.execute_batch("DROP TRIGGER reject_change").unwrap();
        assert_eq!(
            accept_authenticated_webhook_with_delivery_id(
                &db,
                "pull_request",
                "delivery",
                &payload
            )
            .unwrap(),
            1
        );
        assert_eq!(pending(&db).unwrap().len(), 1);
    }

    #[test]
    fn listener_registration_replays_journaled_head_and_base_transitions() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let head_source = json!({
            "action":"synchronize","repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"head":{"sha":"b".repeat(40)}}
        });
        let base_source = json!({
            "action":"edited","repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"base":{"ref":"release"}},
            "changes":{"base":{"ref":"main"}}
        });
        assert!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "synchronize",
                "2099-01-01T00:00:20Z",
                "head-transition:1",
                &head_source,
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "base_changed",
                "2099-01-01T00:00:30Z",
                "base-transition:1",
                &base_source,
            )
            .unwrap()
            .is_empty()
        );

        let thread = "11111111-1111-4111-8111-111111111111";
        register_in_since(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            thread,
            timestamp_second(&db, "2099-01-01T00:00:10Z").unwrap(),
        )
        .unwrap();
        let notices = pending(&db).unwrap();
        assert_eq!(notices.len(), 2);
        assert_eq!(
            notices
                .iter()
                .find(|notice| notice.event == "synchronize")
                .unwrap()
                .source,
            head_source
        );
        let base = notices
            .iter()
            .find(|notice| notice.event == "base_changed")
            .unwrap();
        assert_eq!(base.source, base_source);
        assert_eq!(base.source["changes"]["base"]["ref"], "main");
        assert_eq!(base.source["pull_request"]["base"]["ref"], "release");
    }

    #[test]
    fn journal_retry_keeps_original_time_and_source_for_listener_boundary() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register_in_since(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            thread,
            timestamp_second(&db, "2099-01-03T00:00:00Z").unwrap(),
        )
        .unwrap();
        let original_source = json!({
            "action":"synchronize","repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-02T00:00:00Z",
                "head":{"sha":"b".repeat(40)}}
        });
        assert!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "synchronize",
                "2099-01-02T00:00:00Z",
                "transition-stable-key",
                &original_source,
            )
            .unwrap()
            .is_empty()
        );
        let retry_source = json!({
            "action":"synchronize","repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-04T00:00:00Z",
                "head":{"sha":"b".repeat(40)}}
        });
        assert!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "synchronize",
                "2099-01-04T00:00:00Z",
                "transition-stable-key",
                &retry_source,
            )
            .unwrap()
            .is_empty()
        );
        let (event_at, source): (String, String) = db
            .query_row(
                "SELECT event_at,source FROM automatic_pr_event_journal
                 WHERE event_key='transition-stable-key'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(event_at, "2099-01-02T00:00:00Z");
        assert_eq!(
            serde_json::from_str::<Value>(&source).unwrap(),
            original_source
        );
        assert!(pending(&db).unwrap().is_empty());
    }

    #[test]
    fn reopen_without_a_known_cycle_stays_pending_until_close_arrives() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let registration_floor = timestamp_second(&db, "2098-12-31T23:58:00Z").unwrap();
        register_in_since(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            thread,
            registration_floor,
        )
        .unwrap();
        let reopen = json!({
            "action":"reopened","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:00Z"}
        });
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request", &reopen).unwrap(),
            0
        );
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request", &reopen).unwrap(),
            0,
            "an identical webhook redelivery must not create another pending source"
        );
        assert_eq!(
            reopen_timeline_floor(&db, "owner/repo", "7").unwrap(),
            (Some(registration_floor), true),
            "an unresolved webhook reopen must trigger timeline recovery even while the PR snapshot is open"
        );
        assert_eq!(pending(&db).unwrap().len(), 0);
        let unresolved: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unresolved, 1);

        let close = json!({
            "action":"closed","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"merged":false,
                "closed_at":"2098-12-31T23:59:00Z"}
        });
        accept_authenticated_webhook(&db, "pull_request", &close).unwrap();
        assert!(
            pending(&db)
                .unwrap()
                .iter()
                .all(|notification| notification.event != "reopened"),
            "a webhook timestamp alone cannot finalize an open-ended cycle"
        );
        assert_eq!(
            record_reopened_event_with_id(
                &db,
                "owner/repo",
                "7",
                "poll",
                "2099-01-01T00:00:00Z",
                "timeline:7001",
            )
            .unwrap(),
            1
        );
        let reopened: Vec<_> = pending(&db)
            .unwrap()
            .into_iter()
            .filter(|notification| notification.event == "reopened")
            .collect();
        assert_eq!(reopened.len(), 1);
        assert_eq!(
            reopened[0].event_key,
            reopen_key(&db, "2098-12-31T23:59:00Z")
        );
        let unresolved: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            unresolved, 1,
            "unattributed webhook evidence remains pending"
        );
    }

    #[test]
    fn late_close_splits_pending_reopens_into_their_actual_intervals() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();

        let close = |at: &str| {
            let payload = json!({"action":"closed","number":7,
                "repository":{"full_name":"owner/repo"},
                "pull_request":{"number":7,"merged":false,"closed_at":at}});
            accept_authenticated_webhook(&db, "pull_request", &payload).unwrap();
        };
        let reopen = |at: &str| {
            let payload = json!({"action":"reopened","number":7,
                "repository":{"full_name":"owner/repo"},
                "pull_request":{"number":7,"updated_at":at}});
            accept_authenticated_webhook(&db, "pull_request", &payload).unwrap();
        };

        reopen("2099-01-01T00:00:20Z");
        reopen("2099-01-01T00:00:40Z");
        close("2099-01-01T00:00:10Z");
        let unresolved: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unresolved, 2);

        close("2099-01-01T00:00:30Z");
        assert!(
            pending(&db)
                .unwrap()
                .iter()
                .all(|notification| notification.event != "reopened")
        );
        for (id, at) in [
            ("timeline:20", "2099-01-01T00:00:20Z"),
            ("timeline:40", "2099-01-01T00:00:40Z"),
        ] {
            record_reopened_event_with_id(&db, "owner/repo", "7", "poll", at, id).unwrap();
        }
        let mut reopened: Vec<_> = pending(&db)
            .unwrap()
            .into_iter()
            .filter(|notification| notification.event == "reopened")
            .map(|notification| notification.event_key)
            .collect();
        reopened.sort();
        assert_eq!(
            reopened,
            [
                reopen_key(&db, "2099-01-01T00:00:10Z"),
                reopen_key(&db, "2099-01-01T00:00:30Z")
            ]
        );
        let unresolved: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            unresolved, 2,
            "unattributed webhook evidence remains pending"
        );
    }

    #[test]
    fn reopen_after_two_closes_is_reconciled_to_the_intervening_cycle() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();

        for closed_at in ["2099-01-01T00:00:10Z", "2099-01-01T00:00:30Z"] {
            let close = json!({"action":"closed","number":7,
                "repository":{"full_name":"owner/repo"},
                "pull_request":{"number":7,"merged":false,"closed_at":closed_at}});
            accept_authenticated_webhook(&db, "pull_request", &close).unwrap();
        }
        let reopen = json!({"action":"reopened","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:20Z"}});
        accept_authenticated_webhook(&db, "pull_request", &reopen).unwrap();
        assert!(
            pending(&db)
                .unwrap()
                .iter()
                .all(|notification| notification.event != "reopened")
        );
        record_reopened_event_with_id(
            &db,
            "owner/repo",
            "7",
            "poll",
            "2099-01-01T00:00:20Z",
            "timeline:20",
        )
        .unwrap();

        let notices = pending(&db).unwrap();
        let reopened: Vec<_> = notices
            .iter()
            .filter(|notification| notification.event == "reopened")
            .collect();
        assert_eq!(reopened.len(), 1);
        assert_eq!(
            reopened[0].event_key,
            reopen_key(&db, "2099-01-01T00:00:10Z")
        );
        let unresolved: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            unresolved, 1,
            "unattributed webhook evidence remains pending"
        );
    }

    #[test]
    fn new_webhook_advances_only_successful_timeline_backoff() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        db.execute_batch("CREATE TABLE github_poll_state(endpoint TEXT,page INTEGER,next_poll_ms INTEGER,backoff_ms INTEGER,error_category TEXT);
            INSERT INTO github_poll_state VALUES('/repos/owner/repo/issues/7/timeline',0,999999,3600000,NULL);").unwrap();
        let insert = |id: &str| {
            store_pending_reopen_in(
                &db,
                "owner/repo",
                "7",
                "webhook",
                id,
                20,
                "1970-01-01T00:00:20Z",
            )
            .unwrap()
        };
        db.execute_batch("SAVEPOINT webhook").unwrap();
        insert("first");
        let next = || -> i64 {
            db.query_row("SELECT next_poll_ms FROM github_poll_state", [], |row| {
                row.get(0)
            })
            .unwrap()
        };
        assert_eq!(next(), 0);
        db.execute_batch("ROLLBACK TO webhook; RELEASE webhook")
            .unwrap();
        assert_eq!(
            next(),
            999999,
            "the reschedule rolls back with webhook evidence"
        );
        insert("first");
        db.execute("UPDATE github_poll_state SET next_poll_ms=12345", [])
            .unwrap();
        insert("first");
        assert_eq!(next(), 12345, "redelivery must not reschedule");
        db.execute(
            "UPDATE github_poll_state SET error_category='rate_limited'",
            [],
        )
        .unwrap();
        insert("second");
        assert_eq!(next(), 12345, "rate-limit deadline must be retained");
        db.execute("UPDATE github_poll_state SET error_category=NULL", [])
            .unwrap();
        insert("third");
        assert_eq!(next(), 0, "new evidence bypasses old ambiguity backoff");
        db.execute("UPDATE github_poll_state SET next_poll_ms=12345", [])
            .unwrap();
        db.execute("INSERT INTO github_poll_state VALUES('/repos/Owner/Repo/issues/7/timeline',0,999999,3600000,'server_error')", []).unwrap();
        insert("fourth");
        let healthy: i64 = db.query_row("SELECT next_poll_ms FROM github_poll_state WHERE endpoint='/repos/owner/repo/issues/7/timeline'", [], |row| row.get(0)).unwrap();
        assert_eq!(
            healthy, 12345,
            "a case variant with an error must retain backoff"
        );
    }

    #[test]
    fn timeline_reopen_survives_an_unmatched_webhook_in_the_same_interval() {
        for webhook_first in [true, false] {
            let db = Connection::open_in_memory().unwrap();
            register(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "11111111-1111-4111-8111-111111111111",
            )
            .unwrap();
            for closed_at in ["2099-01-01T00:00:10Z", "2099-01-01T00:00:30Z"] {
                let close = json!({"action":"closed","number":7,
                    "repository":{"full_name":"owner/repo"},
                    "pull_request":{"number":7,"merged":false,"closed_at":closed_at}});
                accept_authenticated_webhook(&db, "pull_request", &close).unwrap();
            }
            let webhook = json!({"action":"reopened","number":7,
                "repository":{"full_name":"owner/repo"},
                "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:25Z"}});
            let record_webhook = || {
                accept_authenticated_webhook_with_delivery_id(
                    &db,
                    "pull_request",
                    "ambiguous",
                    &webhook,
                )
                .unwrap();
            };
            let record_timeline = || {
                record_reopened_event_with_id(
                    &db,
                    "owner/repo",
                    "7",
                    "poll",
                    "2099-01-01T00:00:20Z",
                    "timeline:20",
                )
                .unwrap();
            };
            if webhook_first {
                record_webhook();
                record_timeline();
            } else {
                record_timeline();
                record_webhook();
            }
            record_timeline();
            record_webhook();

            let reopened: Vec<_> = pending(&db)
                .unwrap()
                .into_iter()
                .filter(|notice| notice.event == "reopened")
                .collect();
            assert_eq!(reopened.len(), 1);
            assert_eq!(
                reopened[0].event_key,
                reopen_key(&db, "2099-01-01T00:00:10Z")
            );
            let unresolved: i64 = db
                .query_row(
                    "SELECT count(*) FROM automatic_pr_pending_reopens
                     WHERE source_kind='webhook' AND source_id='webhook:ambiguous'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(unresolved, 1, "unmatched webhook identity remains pending");
        }
    }

    #[test]
    fn reconciliation_counts_only_new_notifications_for_every_listener() {
        for reopen_last in [false, true] {
            let db = Connection::open_in_memory().unwrap();
            for thread in [
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
            ] {
                register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
            }
            let close = |at: &str| {
                json!({"action":"closed","number":7,
                "repository":{"full_name":"owner/repo"},
                "pull_request":{"number":7,"merged":false,"closed_at":at}})
            };
            let c1 = close("2099-01-01T00:00:10Z");
            let c2 = close("2099-01-01T00:00:30Z");
            assert_eq!(
                accept_authenticated_webhook(&db, "pull_request", &c2).unwrap(),
                2
            );
            let reopen = || {
                record_reopened_event_with_id(
                    &db,
                    "owner/repo",
                    "7",
                    "poll",
                    "2099-01-01T00:00:20Z",
                    "timeline:20",
                )
                .unwrap()
            };
            if reopen_last {
                assert_eq!(
                    accept_authenticated_webhook(&db, "pull_request", &c1).unwrap(),
                    2
                );
                assert_eq!(reopen(), 2);
            } else {
                assert_eq!(reopen(), 0);
                db.execute_batch(
                    "CREATE TRIGGER fail_close_count BEFORE INSERT ON automatic_pr_notifications
                    WHEN NEW.event='closed' BEGIN SELECT RAISE(ABORT,'stop'); END;",
                )
                .unwrap();
                assert!(accept_authenticated_webhook(&db, "pull_request", &c1).is_err());
                assert_eq!(pending(&db).unwrap().len(), 2);
                db.execute_batch("DROP TRIGGER fail_close_count").unwrap();
                assert_eq!(
                    accept_authenticated_webhook(&db, "pull_request", &c1).unwrap(),
                    4
                );
            }
            assert_eq!(
                accept_authenticated_webhook(&db, "pull_request", &c1).unwrap(),
                0
            );
            assert_eq!(reopen(), 0);
            let notices = pending(&db).unwrap();
            assert_eq!(notices.len(), 6);
            assert_eq!(
                notices
                    .iter()
                    .filter(|notice| notice.event == "reopened")
                    .count(),
                2
            );
        }
    }

    #[test]
    fn multiple_timeline_reopens_in_one_interval_remain_pending() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        register(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        for at in ["2099-01-01T00:00:10Z", "2099-01-01T00:00:30Z"] {
            ensure_closed_cycle(&db, "owner/repo", "7", at).unwrap();
        }
        for (id, at) in [
            ("timeline:20", "2099-01-01T00:00:20Z"),
            ("timeline:21", "2099-01-01T00:00:21Z"),
        ] {
            store_pending_reopen_in(
                &db,
                "owner/repo",
                "7",
                "poll",
                id,
                timestamp_second(&db, at).unwrap(),
                at,
            )
            .unwrap();
        }
        reconcile_pending_reopens_in(&db, "owner/repo", "7").unwrap();
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
        assert!(pending(&db).unwrap().is_empty());
    }

    #[test]
    fn reopen_after_observed_cycle_waits_for_late_intervening_close() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        let close = |at: &str| {
            let payload = json!({"action":"closed","number":7,
                "repository":{"full_name":"owner/repo"},
                "pull_request":{"number":7,"merged":false,"closed_at":at}});
            accept_authenticated_webhook(&db, "pull_request", &payload).unwrap();
        };
        close("2099-01-01T00:00:10Z");
        assert_eq!(
            record_reopened_event(&db, "owner/repo", "7", "poll", "2099-01-01T00:00:20Z",).unwrap(),
            1
        );
        let later_webhook = json!({"action":"reopened","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:40Z"}});
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request", &later_webhook).unwrap(),
            0
        );
        close("2099-01-01T00:00:30Z");
        assert_eq!(
            pending(&db)
                .unwrap()
                .iter()
                .filter(|notification| notification.event == "reopened")
                .count(),
            1,
            "the delayed second webhook must remain unassigned until timeline evidence"
        );
        record_reopened_event_with_id(
            &db,
            "owner/repo",
            "7",
            "poll",
            "2099-01-01T00:00:40Z",
            "timeline:40",
        )
        .unwrap();

        let mut reopened: Vec<_> = pending(&db)
            .unwrap()
            .into_iter()
            .filter(|notification| notification.event == "reopened")
            .map(|notification| notification.event_key)
            .collect();
        reopened.sort();
        assert_eq!(
            reopened,
            [
                reopen_key(&db, "2099-01-01T00:00:10Z"),
                reopen_key(&db, "2099-01-01T00:00:30Z")
            ]
        );
        let unresolved: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            unresolved, 1,
            "unattributed webhook evidence remains pending"
        );
    }

    #[test]
    fn same_second_reopen_remains_ambiguous_and_retained() {
        let db = Connection::open_in_memory().unwrap();
        let close = json!({"action":"closed","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"merged":false,
                "closed_at":"2099-01-01T00:00:10Z"}});
        accept_authenticated_webhook(&db, "pull_request", &close).unwrap();
        let reopen = json!({"action":"reopened","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:10Z"}});
        accept_authenticated_webhook(&db, "pull_request", &reopen).unwrap();
        let later_close = json!({"action":"closed","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"merged":false,
                "closed_at":"2099-01-01T00:00:20Z"}});
        accept_authenticated_webhook(&db, "pull_request", &later_close).unwrap();
        let unresolved: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unresolved, 1);
    }

    #[test]
    fn inverted_close_arrival_keeps_each_reopen_on_its_close_timestamp() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        for (delivery, at) in [
            ("reopen-1", "2099-01-01T00:00:20Z"),
            ("reopen-2", "2099-01-01T00:00:40Z"),
        ] {
            let payload = json!({"action":"reopened","number":7,
                "repository":{"full_name":"owner/repo"},
                "pull_request":{"number":7,"updated_at":at}});
            accept_authenticated_webhook_with_delivery_id(&db, "pull_request", delivery, &payload)
                .unwrap();
        }
        for at in ["2099-01-01T00:00:30Z", "2099-01-01T00:00:10Z"] {
            let payload = json!({"action":"closed","number":7,
                "repository":{"full_name":"owner/repo"},
                "pull_request":{"number":7,"merged":false,"closed_at":at}});
            accept_authenticated_webhook_with_delivery_id(
                &db,
                "pull_request",
                "unique-close-id",
                &payload,
            )
            .unwrap();
        }
        assert!(
            pending(&db)
                .unwrap()
                .iter()
                .all(|notification| notification.event != "reopened")
        );
        for (id, at) in [
            ("timeline:20", "2099-01-01T00:00:20Z"),
            ("timeline:40", "2099-01-01T00:00:40Z"),
        ] {
            record_reopened_event_with_id(&db, "owner/repo", "7", "poll", at, id).unwrap();
        }
        let mut keys: Vec<_> = pending(&db)
            .unwrap()
            .into_iter()
            .filter(|notification| notification.event == "reopened")
            .map(|notification| notification.event_key)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                reopen_key(&db, "2099-01-01T00:00:10Z"),
                reopen_key(&db, "2099-01-01T00:00:30Z")
            ]
        );
    }

    #[test]
    fn pending_delivery_ids_deduplicate_replays_without_collapsing_same_second_events() {
        let db = Connection::open_in_memory().unwrap();
        let payload = json!({"action":"reopened","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:20Z"}});
        for delivery in ["delivery-a", "delivery-a", "delivery-b"] {
            accept_authenticated_webhook_with_delivery_id(&db, "pull_request", delivery, &payload)
                .unwrap();
        }
        let rows: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_pending_reopens",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
    }

    #[test]
    fn repository_case_variants_share_listener_and_event_identity() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "Owner/Repo", "7", thread).unwrap();
        let first = record_event(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "closed",
            "2099-01-01T00:00:00Z",
            "same-provider-event",
            &json!({"action":"closed"}),
        )
        .unwrap();
        let replay = record_event(
            &db,
            "pull_request",
            "OWNER/REPO",
            "7",
            "closed",
            "2099-01-01T00:00:00Z",
            "same-provider-event",
            &json!({"action":"closed"}),
        )
        .unwrap();

        assert_eq!(first.len(), 1);
        assert!(replay.is_empty());
        assert_eq!(pending(&db).unwrap().len(), 1);
        let stored_repo: String = db
            .query_row(
                "SELECT repo FROM automatic_pr_notification_listeners",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_repo, "owner/repo");
    }

    #[test]
    fn dispatch_uses_claimed_identity_and_never_retries_ambiguous_send() {
        let mut db = Connection::open_in_memory().unwrap();
        register(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        record_event(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "synchronize",
            "2099-01-01T00:00:00Z",
            "pr-event-1",
            &serde_json::json!({"updated_at":"2026-11-09T00:00:00Z"}),
        )
        .unwrap();
        let mut sent_id = String::new();
        assert_eq!(
            dispatch_with(&mut db, |thread, message, id, resume| {
                assert_eq!(thread, "11111111-1111-4111-8111-111111111111");
                assert!(message.contains("owner/repo#7 synchronize"));
                assert!(resume, "PR notices must wake unloaded chats");
                sent_id = id.to_owned();
                anyhow::bail!("RPC response lost after send")
            })
            .unwrap(),
            1
        );
        assert_eq!(needs_attention(&db).unwrap()[0].id, sent_id);
        let mut resend_count = 0;
        assert_eq!(
            dispatch_with(&mut db, |_, _, _, _| {
                resend_count += 1;
                Ok(("queued".into(), None))
            })
            .unwrap(),
            0
        );
        assert_eq!(resend_count, 0);
    }

    #[test]
    fn accepted_notification_survives_failed_ack_without_resend() {
        let mut db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        record_event(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "closed",
            "2099-01-01T00:00:00Z",
            "close-ack-failure",
            &json!({"action":"closed"}),
        )
        .unwrap();
        db.execute_batch(
            "CREATE TRIGGER reject_queued BEFORE UPDATE OF state ON automatic_pr_notifications
            WHEN NEW.state='queued' BEGIN SELECT RAISE(ABORT,'ack failed'); END;",
        )
        .unwrap();
        let mut sent = Vec::new();
        let result = dispatch_with_clock(
            &mut db,
            |_, _, id, _| {
                sent.push(id.to_owned());
                Ok(("queued".into(), Some("native_queue_resume_warning".into())))
            },
            || 1_000,
        );
        assert!(result.is_err());
        assert_eq!(sent.len(), 1);
        db.execute_batch("DROP TRIGGER reject_queued").unwrap();
        assert_eq!(
            codex_wake::pr_ci_runtime::recover_native_wake_intents(
                &db,
                1_000 + codex_wake::pr_ci_runtime::NATIVE_WAKE_INTENT_LEASE_MS,
                |destination, ids| {
                    assert_eq!(destination, thread);
                    assert_eq!(ids, sent.as_slice());
                    Ok(())
                }
            )
            .unwrap(),
            1
        );
        let state: String = db
            .query_row(
                "SELECT state FROM automatic_pr_notifications WHERE id=?1",
                [&sent[0]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "queued");
        assert_eq!(
            dispatch_with(&mut db, |_, _, _, _| panic!("must not resend")).unwrap(),
            0
        );
    }

    #[test]
    fn failed_intent_before_send_retries_without_sending() {
        let mut db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        record_event(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "closed",
            "2099-01-01T00:00:00Z",
            "close-pre-intent",
            &json!({"action":"closed"}),
        )
        .unwrap();
        codex_wake::pr_ci_runtime::record_native_wake_recovery(
            &db,
            thread,
            "native_queue_resume_warning",
            "11111111-1111-4111-8111-111111111112",
        )
        .unwrap();
        db.execute("DELETE FROM native_wake_recovery", []).unwrap();
        db.execute_batch(
            "CREATE TRIGGER reject_intent BEFORE INSERT ON native_wake_recovery
            BEGIN SELECT RAISE(ABORT,'db unavailable'); END;",
        )
        .unwrap();
        assert_eq!(
            dispatch_with_clock(&mut db, |_, _, _, _| panic!("must not send"), || 1_000).unwrap(),
            1
        );
        let (state, next): (String, i64) = db
            .query_row(
                "SELECT state,available_at_ms FROM automatic_pr_notifications",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((state.as_str(), next), ("pending", 6_000));
        db.execute_batch("DROP TRIGGER reject_intent").unwrap();
        assert_eq!(
            dispatch_with_clock(&mut db, |_, _, _, _| Ok(("queued".into(), None)), || 6_000)
                .unwrap(),
            1
        );
    }

    #[test]
    fn slow_before_send_failure_defers_only_that_destination() {
        let mut db = Connection::open_in_memory().unwrap();
        let failed_thread = "11111111-1111-4111-8111-111111111111";
        let healthy_thread = "22222222-2222-4222-8222-222222222222";
        register(&db, "pull_request", "owner/repo", "7", failed_thread).unwrap();
        register(&db, "pull_request", "owner/repo", "7", healthy_thread).unwrap();
        record_event(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "closed",
            "2099-01-01T00:00:00Z",
            "close-destinations",
            &json!({"action":"closed"}),
        )
        .unwrap();
        db.execute(
            "UPDATE automatic_pr_notifications SET created_at=CASE thread
                WHEN ?1 THEN '2000-01-01 00:00:00' ELSE '2000-01-01 00:00:01' END",
            params![failed_thread],
        )
        .unwrap();

        let clock = std::cell::Cell::new(10_000);
        let mut attempts = Vec::new();
        assert_eq!(
            dispatch_with_clock(
                &mut db,
                |thread, _, _, _| {
                    attempts.push(thread.to_owned());
                    if thread == failed_thread {
                        clock.set(25_000);
                        Err(crate::execution::TargetUnavailableBeforeSend.into())
                    } else {
                        Ok(("queued".into(), None))
                    }
                },
                || clock.get(),
            )
            .unwrap(),
            2
        );
        assert_eq!(attempts, [failed_thread, healthy_thread]);

        let states: Vec<(String, String, i64)> = {
            let mut statement = db
                .prepare(
                    "SELECT thread,state,available_at_ms FROM automatic_pr_notifications
                     ORDER BY thread",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(states[0], (failed_thread.into(), "pending".into(), 30_000));
        assert_eq!(states[1], (healthy_thread.into(), "queued".into(), 0));

        let mut retried = false;
        assert_eq!(
            dispatch_with_clock(
                &mut db,
                |thread, _, _, _| {
                    assert_eq!(thread, failed_thread);
                    retried = true;
                    Ok(("queued".into(), None))
                },
                || 30_000,
            )
            .unwrap(),
            1
        );
        assert!(retried);
    }

    #[test]
    fn claim_order_uses_fractional_creation_time_and_respects_retry_gate() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        for key in ["later", "earlier"] {
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "closed",
                "2099-01-01T00:00:00Z",
                key,
                &json!({"action":"closed"}),
            )
            .unwrap();
        }
        db.execute_batch(
            "UPDATE automatic_pr_notifications SET created_at=CASE event_key
            WHEN 'later' THEN '2000-01-01 00:00:00.750' ELSE '2000-01-01 00:00:00.250' END;",
        )
        .unwrap();
        let selected = claim_next(&db, 946_684_801_000, &HashSet::new())
            .unwrap()
            .unwrap();
        assert_eq!(selected.event_key, "earlier");
        db.execute("UPDATE automatic_pr_notifications SET created_at='invalid',available_at_ms=946684802000 WHERE event_key='later'", []).unwrap();
        assert!(
            claim_next(&db, 946_684_801_999, &HashSet::new())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            claim_next(&db, 946_684_802_000, &HashSet::new())
                .unwrap()
                .unwrap()
                .event_key,
            "later"
        );
    }

    #[test]
    fn slow_retries_do_not_starve_a_newer_notification() {
        let mut db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        for index in 0..17 {
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "closed",
                "2099-01-01T00:00:00Z",
                &format!("event-{index:02}"),
                &json!({"action":"closed"}),
            )
            .unwrap();
        }
        db.execute_batch("UPDATE automatic_pr_notifications SET created_at='2000-01-01 00:00:00.250';
            UPDATE automatic_pr_notifications SET created_at='2000-01-01 00:00:00.750' WHERE event_key='event-16';").unwrap();
        let healthy: String = db
            .query_row(
                "SELECT id FROM automatic_pr_notifications WHERE event_key='event-16'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let clock = std::cell::Cell::new(946_684_801_000_i64);
        let mut attempts = Vec::new();
        let mut queue = |_: &str, _: &str, id: &str, _: bool| {
            attempts.push(id.to_owned());
            if id == healthy {
                Ok(("queued".into(), None))
            } else {
                clock.set(clock.get() + 6_000);
                Err(crate::execution::TargetUnavailableBeforeSend.into())
            }
        };
        assert_eq!(
            dispatch_with_clock(&mut db, &mut queue, || clock.get()).unwrap(),
            16
        );
        assert_eq!(
            dispatch_with_clock(&mut db, &mut queue, || clock.get()).unwrap(),
            16
        );
        assert!(!attempts[..16].contains(&healthy));
        assert_eq!(attempts[16], healthy);
        assert_eq!(
            attempts
                .iter()
                .filter(|id| id.as_str() == healthy.as_str())
                .count(),
            1
        );
        let state: String = db
            .query_row(
                "SELECT state FROM automatic_pr_notifications WHERE id=?1",
                [&healthy],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "queued");
    }

    #[test]
    fn before_send_retry_is_not_retried_again_in_same_batch() {
        let mut db = Connection::open_in_memory().unwrap();
        let failed_thread = "11111111-1111-4111-8111-111111111111";
        let healthy_thread = "22222222-2222-4222-8222-222222222222";
        register(&db, "pull_request", "owner/repo", "7", failed_thread).unwrap();
        register(&db, "pull_request", "owner/repo", "7", healthy_thread).unwrap();
        record_event(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "closed",
            "2099-01-01T00:00:00Z",
            "close-retry-batch",
            &json!({"action":"closed"}),
        )
        .unwrap();
        db.execute(
            "UPDATE automatic_pr_notifications SET created_at=CASE thread
                WHEN ?1 THEN '2000-01-01 00:00:00' ELSE '2000-01-01 00:00:01' END",
            params![failed_thread],
        )
        .unwrap();

        let now_calls = std::cell::Cell::new(0);
        let mut fail_once = true;
        let mut attempts = Vec::new();
        assert_eq!(
            dispatch_with_clock(
                &mut db,
                |thread, _, _, _| {
                    attempts.push(thread.to_owned());
                    if thread == failed_thread && fail_once {
                        fail_once = false;
                        Err(crate::execution::TargetUnavailableBeforeSend.into())
                    } else {
                        Ok(("queued".into(), None))
                    }
                },
                || {
                    let call = now_calls.get();
                    now_calls.set(call + 1);
                    match call {
                        0 | 1 => 10_000,
                        _ => 30_000,
                    }
                },
            )
            .unwrap(),
            2
        );
        assert_eq!(attempts, [failed_thread, healthy_thread]);
    }

    #[test]
    fn accepted_queue_resume_warning_is_persisted_without_redelivery() {
        let mut db = Connection::open_in_memory().unwrap();
        register(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        record_event(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "synchronize",
            "2099-01-01T00:00:00Z",
            "pr-event-wake-warning",
            &serde_json::json!({"updated_at":"2026-11-09T00:00:00Z"}),
        )
        .unwrap();

        let mut accepted_id = None;
        assert_eq!(
            dispatch_with(&mut db, |_, _, id, _| {
                accepted_id = Some(id.to_owned());
                Ok(("queued".into(), Some("native_queue_resume_warning".into())))
            })
            .unwrap(),
            1
        );
        let (state, recovery_reason, recovery_json): (String, Option<String>, Option<String>) = db
            .query_row(
                "SELECT notification.state,recovery.reason,recovery.client_ids_json
                 FROM automatic_pr_notifications AS notification
                 LEFT JOIN native_wake_recovery AS recovery
                   ON recovery.thread=notification.thread
                 WHERE notification.event_key='pr-event-wake-warning'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "queued");
        assert_eq!(
            recovery_reason.as_deref(),
            Some("native_queue_resume_warning")
        );
        let recovery_payload: serde_json::Value =
            serde_json::from_str(recovery_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            recovery_payload["client_ids"],
            json!([accepted_id.unwrap()])
        );
        assert_eq!(recovery_payload["unattributed"], json!(false));
        assert_eq!(
            dispatch_with(&mut db, |_, _, _, _| unreachable!()).unwrap(),
            0
        );
    }

    #[test]
    fn register_in_uses_and_does_not_commit_the_callers_transaction() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let tx = db.unchecked_transaction().unwrap();
        assert!(
            register_in(
                &tx,
                "pull_request",
                "owner/repo",
                "7",
                "11111111-1111-4111-8111-111111111111",
            )
            .unwrap()
        );
        assert!(!tx.is_autocommit());
        tx.rollback().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM automatic_pr_notification_listeners",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn first_poll_suppresses_history_but_captures_events_since_registration() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE waits(repo TEXT,run_id INTEGER,attempt INTEGER,sha TEXT,state TEXT)",
        )
        .unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        crate::conditions::initialize(&db).unwrap();
        crate::polling::initialize(&db).unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        register(&db, "review", "owner/repo", "7", thread).unwrap();
        db.execute(
            "INSERT INTO github_poll_state(endpoint,page,cursor,next_poll_ms,backoff_ms,calls)
             VALUES('/repos/owner/repo/pulls/7',0,?1,0,60000,1),
                   ('/repos/owner/repo/pulls/7/reviews',0,'{}',0,60000,1)",
            [
                json!({"head":"a".repeat(40),"base":"main","state":"open","poll_seq":1})
                    .to_string(),
            ],
        )
        .unwrap();

        let review =
            |id, submitted_at, state| json!({"id":id,"submitted_at":submitted_at,"state":state});
        let pull_request = |head: &str, updated_at: &str| {
            json!({"number":7,"state":"open","updated_at":updated_at,
                "head":{"sha":head},"base":{"ref":"main"}})
        };
        let response = |body: Value| super::super::HttpResponse {
            status: 200,
            headers: Default::default(),
            body: serde_json::to_vec(&body).unwrap(),
        };
        let old_review = review(10, "2020-01-01T00:00:00Z", "APPROVED");
        let raced_review = review(11, "2099-01-01T00:00:00Z", "APPROVED");
        let initial_pr = pull_request(&"b".repeat(40), "2026-01-01T00:00:00Z");
        super::super::tick_with(&db, 1, |route, _| match route {
            "/repos/owner/repo/pulls/7" => Ok(response(initial_pr.clone())),
            "/repos/owner/repo/issues/7/timeline?per_page=100&page=1" => Ok(response(json!([]))),
            route if route.starts_with("/repos/owner/repo/pulls/7/reviews") => {
                Ok(response(json!([old_review.clone(), raced_review.clone()])))
            }
            _ => panic!("unexpected route {route}"),
        })
        .unwrap();
        let after_first_read = pending(&db).unwrap();
        assert_eq!(after_first_read.len(), 1);
        assert_eq!(after_first_read[0].event, "approved");
        assert_eq!(after_first_read[0].source["review"]["id"], 11);

        let next_pr = pull_request(&"c".repeat(40), "2099-01-01T00:00:00Z");
        let new_review = review(12, "2099-01-01T00:00:00Z", "CHANGES_REQUESTED");
        let mut fetch = |route: &str, _etag: Option<&str>| match route {
            "/repos/owner/repo/pulls/7" => Ok(response(next_pr.clone())),
            "/repos/owner/repo/issues/7/timeline?per_page=100&page=1" => Ok(response(json!([]))),
            route if route.starts_with("/repos/owner/repo/pulls/7/reviews") => {
                Ok(response(json!([
                    old_review.clone(),
                    raced_review.clone(),
                    new_review.clone()
                ])))
            }
            _ => panic!("unexpected route {route}"),
        };
        super::super::tick_with(&db, super::super::INTERVAL_MS + 1, &mut fetch).unwrap();
        let pending_after_events = pending(&db).unwrap();
        assert_eq!(pending_after_events.len(), 3);
        assert!(
            pending_after_events
                .iter()
                .any(|notice| notice.event == "synchronize")
        );
        assert!(
            pending_after_events
                .iter()
                .any(|notice| notice.event == "changes_requested")
        );

        super::super::tick_with(&db, super::super::INTERVAL_MS * 2 + 1, &mut fetch).unwrap();
        assert_eq!(pending(&db).unwrap().len(), 3);
    }

    #[test]
    fn event_in_listener_registration_second_is_included() {
        let db = Connection::open_in_memory().unwrap();
        register(
            &db,
            "review",
            "owner/repo",
            "7",
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        let registered_second: i64 = db
            .query_row(
                "SELECT registered_at_sec FROM automatic_pr_notification_listeners",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let same_second: String = db
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%SZ',?1,'unixepoch')",
                [registered_second],
                |row| row.get(0),
            )
            .unwrap();
        let notifications = record_event(
            &db,
            "review",
            "owner/repo",
            "7",
            "approved",
            &same_second,
            "review-created-in-registration-second",
            &json!({"review":{"id":91}}),
        )
        .unwrap();
        assert_eq!(notifications.len(), 1);
    }
}
