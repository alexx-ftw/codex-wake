//! Durable, repeatable notifications for automatic PR and review listeners.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
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

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct PendingReopen {
    source_kind: String,
    source_id: String,
    event_at_sec: i64,
    event_at: String,
}

struct PendingReopenSourceRow {
    id: i64,
    repo: String,
    pr: String,
    event_at: String,
    source: String,
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
        CREATE TABLE IF NOT EXISTS automatic_pr_schema_migrations (
            name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS automatic_pr_pending_reopens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            source_kind TEXT NOT NULL CHECK(source_kind IN ('webhook','poll')),
            source_id TEXT NOT NULL,
            event_at_sec INTEGER NOT NULL,
            event_at TEXT NOT NULL,
            source TEXT NOT NULL,
            UNIQUE(repo,pr,source_kind,source_id));",
    )?;
    db.execute(
        "INSERT OR IGNORE INTO automatic_pr_closed_cycles(repo,pr,closed_at_sec)
         SELECT repo,pr,closed_at_sec FROM automatic_pr_lifecycle",
        [],
    )?;
    migrate_pending_reopens(db)?;
    sanitize_pending_reopen_sources(db)?;
    let lifecycle_columns = {
        let mut statement = db.prepare("PRAGMA table_info(automatic_pr_lifecycle)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for column in ["webhook_reopen_source_id", "poll_reopen_source_id"] {
        if !lifecycle_columns.iter().any(|existing| existing == column) {
            db.execute_batch(&format!(
                "ALTER TABLE automatic_pr_lifecycle ADD COLUMN {column} TEXT;"
            ))?;
        }
    }
    let has_available_at = {
        let mut statement = db.prepare("PRAGMA table_info(automatic_pr_notifications)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|column| column == "available_at_ms")
    };
    if !has_available_at {
        db.execute_batch(
            "ALTER TABLE automatic_pr_notifications
             ADD COLUMN available_at_ms INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    let has_registration_time = {
        let mut statement = db.prepare("PRAGMA table_info(automatic_pr_notification_listeners)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|column| column == "registered_at_sec")
    };
    if !has_registration_time {
        db.execute_batch(
            "ALTER TABLE automatic_pr_notification_listeners
             ADD COLUMN registered_at_sec INTEGER NOT NULL DEFAULT 0;
             UPDATE automatic_pr_notification_listeners
             SET registered_at_sec=CAST(strftime('%s','now') AS INTEGER)
             WHERE registered_at_sec=0;",
        )?;
    }
    migrate_reopen_notification_identity(db)?;
    Ok(())
}

fn migrate_reopen_notification_identity(db: &Connection) -> Result<()> {
    struct LegacyNotification {
        id: String,
        kind: String,
        repo: String,
        pr: String,
        thread: String,
        state: String,
        available_at_ms: i64,
        closed_at_sec: i64,
    }
    db.execute_batch("SAVEPOINT reopen_notification_identity_v1")?;
    let migration = (|| -> Result<()> {
        let rows: Vec<LegacyNotification> = {
            let mut statement = db.prepare(
                "SELECT notification.id,notification.kind,notification.repo,
                        notification.pr,notification.thread,notification.state,
                        notification.available_at_ms,lifecycle.closed_at_sec
                 FROM automatic_pr_notifications AS notification
                 JOIN automatic_pr_lifecycle AS lifecycle
                   ON lifecycle.repo=notification.repo AND lifecycle.pr=notification.pr
                 WHERE notification.event='reopened'
                   AND lifecycle.state='closed'
                   AND notification.event_key='reopened:' || lifecycle.epoch",
            )?;
            statement
                .query_map([], |row| {
                    Ok(LegacyNotification {
                        id: row.get(0)?,
                        kind: row.get(1)?,
                        repo: row.get(2)?,
                        pr: row.get(3)?,
                        thread: row.get(4)?,
                        state: row.get(5)?,
                        available_at_ms: row.get(6)?,
                        closed_at_sec: row.get(7)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?
        };
        for row in rows {
            let new_key = format!("reopened:{}", row.closed_at_sec);
            let duplicate: Option<String> = db
                .query_row(
                    "SELECT id FROM automatic_pr_notifications
                 WHERE kind=?1 AND repo=?2 AND pr=?3 AND thread=?4 AND event='reopened'
                   AND event_key=?5",
                    params![row.kind, row.repo, row.pr, row.thread, new_key],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(target_id) = duplicate {
                db.execute(
                    "UPDATE automatic_pr_notifications SET
                        state=CASE
                            WHEN CASE state
                                WHEN 'queued' THEN 4 WHEN 'needs_attention' THEN 3
                                WHEN 'sending' THEN 2 ELSE 1 END >= CASE ?2
                                WHEN 'queued' THEN 4 WHEN 'needs_attention' THEN 3
                                WHEN 'sending' THEN 2 ELSE 1 END
                            THEN state ELSE ?2 END,
                        available_at_ms=MAX(available_at_ms,?3)
                     WHERE id=?1",
                    params![target_id, row.state, row.available_at_ms],
                )?;
                db.execute(
                    "DELETE FROM automatic_pr_notifications WHERE id=?1",
                    [row.id],
                )?;
            } else {
                db.execute(
                    "UPDATE automatic_pr_notifications SET event_key=?2 WHERE id=?1",
                    params![row.id, new_key],
                )?;
            }
        }
        Ok(())
    })();
    if let Err(error) = migration {
        let _ = db.execute_batch(
            "ROLLBACK TO reopen_notification_identity_v1;
             RELEASE reopen_notification_identity_v1;",
        );
        return Err(error);
    }
    db.execute_batch("RELEASE reopen_notification_identity_v1")?;
    Ok(())
}

fn migrate_pending_reopens(db: &Connection) -> Result<()> {
    let columns = {
        let mut statement = db.prepare("PRAGMA table_info(automatic_pr_pending_reopens)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if columns.iter().any(|column| column == "source_id") {
        return Ok(());
    }

    db.execute_batch("SAVEPOINT pending_reopens_migration")?;
    let id_column = if columns.iter().any(|column| column == "id") {
        "id"
    } else {
        "rowid"
    };
    let migration = (|| -> rusqlite::Result<()> {
        db.execute_batch(
            "ALTER TABLE automatic_pr_pending_reopens RENAME TO automatic_pr_pending_reopens_old;
             CREATE TABLE automatic_pr_pending_reopens (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 repo TEXT NOT NULL,
                 pr TEXT NOT NULL,
                 source_kind TEXT NOT NULL CHECK(source_kind IN ('webhook','poll')),
                 source_id TEXT NOT NULL,
                 event_at_sec INTEGER NOT NULL,
                 event_at TEXT NOT NULL,
                 source TEXT NOT NULL,
                 UNIQUE(repo,pr,source_kind,source_id));",
        )?;
        let rows = {
            let mut statement = db.prepare(&format!(
                "SELECT {id_column},repo,pr,source_kind,event_at_sec,event_at
                 FROM automatic_pr_pending_reopens_old ORDER BY {id_column}"
            ))?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (id, repo, pr, source_kind, event_at_sec, event_at) in rows {
            let number = pr.parse::<i64>().ok();
            let source = serde_json::json!({
                "action":"reopened",
                "number":number,
                "repository":{"full_name":repo.as_str()},
                "pull_request":{"number":number,"updated_at":event_at.as_str()}
            });
            let source = serde_json::to_string(&source)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            db.execute(
                "INSERT INTO automatic_pr_pending_reopens
                 (id,repo,pr,source_kind,source_id,event_at_sec,event_at,source)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    id,
                    repo,
                    pr,
                    source_kind,
                    format!("legacy:{id}"),
                    event_at_sec,
                    event_at,
                    source
                ],
            )?;
        }
        db.execute_batch("DROP TABLE automatic_pr_pending_reopens_old;")?;
        Ok(())
    })();
    if let Err(error) = migration {
        let _ = db.execute_batch(
            "ROLLBACK TO pending_reopens_migration; RELEASE pending_reopens_migration;",
        );
        return Err(error.into());
    }
    db.execute_batch("RELEASE pending_reopens_migration")?;
    Ok(())
}

fn sanitize_pending_reopen_sources(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS automatic_pr_schema_migrations(name TEXT PRIMARY KEY);",
    )?;
    let done: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM automatic_pr_schema_migrations
         WHERE name='pending_reopen_payload_v1')",
        [],
        |row| row.get(0),
    )?;
    if done {
        return Ok(());
    }
    db.execute_batch("SAVEPOINT pending_reopen_payload_migration")?;
    let migration = (|| -> Result<()> {
        let rows: Vec<PendingReopenSourceRow> = {
            let mut statement = db.prepare(
                "SELECT id,repo,pr,event_at,source FROM automatic_pr_pending_reopens ORDER BY id",
            )?;
            statement
                .query_map([], |row| {
                    Ok(PendingReopenSourceRow {
                        id: row.get(0)?,
                        repo: row.get(1)?,
                        pr: row.get(2)?,
                        event_at: row.get(3)?,
                        source: row.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?
        };
        for row in rows {
            let source =
                serde_json::to_string(&minimal_reopen_source(&row.repo, &row.pr, &row.event_at))?;
            if source != row.source {
                db.execute(
                    "UPDATE automatic_pr_pending_reopens SET source=?2 WHERE id=?1",
                    params![row.id, source],
                )?;
            }
        }
        db.execute(
            "INSERT OR IGNORE INTO automatic_pr_schema_migrations(name)
             VALUES('pending_reopen_payload_v1')",
            [],
        )?;
        Ok(())
    })();
    if let Err(error) = migration {
        let _ = db.execute_batch(
            "ROLLBACK TO pending_reopen_payload_migration;
             RELEASE pending_reopen_payload_migration;",
        );
        return Err(error);
    }
    db.execute_batch("RELEASE pending_reopen_payload_migration")?;
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
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let inserted = insert_listener(&tx, kind, repo, &pr, &thread, registered_at_sec)?;
        tx.commit()?;
        Ok(inserted)
    } else {
        insert_listener(db, kind, repo, &pr, &thread, registered_at_sec)
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
    let inserted = match registered_at_sec {
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
    };
    if inserted == 0
        && let Some(registered_at_sec) = registered_at_sec
    {
        db.execute(
            "UPDATE automatic_pr_notification_listeners
             SET registered_at_sec=MIN(registered_at_sec,?5)
             WHERE kind=?1 AND repo=?2 AND pr=?3 AND thread=?4",
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
         WHERE kind=?1 AND repo=?2 AND pr=?3 AND thread=?4",
        params![kind, repo, pr, thread],
        |row| row.get(0),
    )?;
    let replayable_events: &[&str] = if kind == "pull_request" {
        &["closed", "merged", "reopened"]
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
         WHERE kind=?1 AND repo=?2 AND pr=?3 AND event_at_sec>=?4
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
    // `reopened` is an internal durable notification, not a subscription rule event.
    let validation_event = if kind == "pull_request" && event == "reopened" {
        "closed"
    } else {
        event
    };
    let (_, pr) = crate::subscriptions::validate_source(
        kind,
        repo,
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
    initialize(db)?;
    let event_at_sec: Option<i64> = db.query_row(
        "SELECT CAST(strftime('%s',?1) AS INTEGER)",
        [event_at],
        |row| row.get(0),
    )?;
    let event_at_sec = event_at_sec.context("Invalid event timestamp")?;
    let source = serde_json::to_string(source)?;
    let journalable = (kind == "pull_request" && matches!(event, "closed" | "merged" | "reopened"))
        || (kind == "review" && matches!(event, "submitted" | "approved" | "changes_requested"));
    if journalable {
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
        let journal_event: String = db.query_row(
            "SELECT event FROM automatic_pr_event_journal
             WHERE kind=?1 AND repo=?2 AND pr=?3 AND event_key=?4",
            params![kind, repo, pr, event_key],
            |row| row.get(0),
        )?;
        ensure!(
            journal_event == event,
            "Provider event identity was reused for another event type"
        );
    }
    let listeners = {
        let mut statement = db.prepare(
            "SELECT thread FROM automatic_pr_notification_listeners
             WHERE kind=?1 AND repo=?2 AND pr=?3 AND registered_at_sec<=?4 ORDER BY thread",
        )?;
        statement
            .query_map(params![kind, repo, pr, event_at_sec], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut notifications = Vec::new();
    for thread in listeners {
        let id = Uuid::new_v4().to_string();
        let inserted = db.execute(
            "INSERT OR IGNORE INTO automatic_pr_notifications
             (id,kind,repo,pr,thread,event,event_key,source)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, kind, repo, pr, thread, event, event_key, source],
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
                source: serde_json::from_str(&source)?,
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
    let event_at_sec = timestamp_second(db, event_at)?;
    ensure_closed_cycle_in(db, repo, pr, event_at_sec)?;
    let notifications = record_event_in(
        db,
        "pull_request",
        repo,
        pr,
        event,
        event_at,
        event_key,
        source,
    )?;
    Ok(notifications)
}

pub(crate) fn ensure_closed_cycle(
    db: &Connection,
    repo: &str,
    pr: &str,
    closed_at: &str,
) -> Result<()> {
    initialize(db)?;
    let closed_at_sec = timestamp_second(db, closed_at)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        ensure_closed_cycle_in(&tx, repo, pr, closed_at_sec)?;
        tx.commit()?;
    } else {
        ensure_closed_cycle_in(db, repo, pr, closed_at_sec)?;
    }
    Ok(())
}

pub(crate) fn ensure_closed_cycle_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    closed_at_sec: i64,
) -> Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO automatic_pr_closed_cycles(repo,pr,closed_at_sec)
         VALUES(?1,?2,?3)",
        params![repo, pr, closed_at_sec],
    )?;
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
        reconcile_pending_reopens_in(db, repo, pr)?;
        return Ok(());
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
        db.execute(
            "INSERT INTO automatic_pr_lifecycle
             (repo,pr,epoch,state,closed_at_sec,reopened_at_sec,
              webhook_reopen_source_id,poll_reopen_source_id)
             VALUES(?1,?2,?3,'closed',?4,NULL,NULL,NULL)
             ON CONFLICT(repo,pr) DO UPDATE SET epoch=excluded.epoch,state='closed',
                closed_at_sec=excluded.closed_at_sec,reopened_at_sec=NULL,
                webhook_reopen_source_id=NULL,poll_reopen_source_id=NULL",
            params![repo, pr, epoch, closed_at_sec],
        )?;
    }
    reconcile_pending_reopens_in(db, repo, pr)?;
    Ok(())
}

fn reconcile_pending_reopens_in(db: &Connection, repo: &str, pr: &str) -> Result<()> {
    let closed_at: Vec<i64> = {
        let mut statement = db.prepare(
            "SELECT closed_at_sec FROM automatic_pr_closed_cycles
             WHERE repo=?1 AND pr=?2 ORDER BY closed_at_sec",
        )?;
        statement
            .query_map(params![repo, pr], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    for pair in closed_at.windows(2) {
        resolve_pending_reopen_interval_in(db, repo, pr, pair[0], Some(pair[1]))?;
    }
    if let Some(latest) = closed_at.last() {
        let current_closed: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM automatic_pr_lifecycle
             WHERE repo=?1 AND pr=?2 AND state='closed' AND closed_at_sec=?3)",
            params![repo, pr, latest],
            |row| row.get(0),
        )?;
        if current_closed {
            resolve_pending_reopen_interval_in(db, repo, pr, *latest, None)?;
        }
    }
    Ok(())
}

pub(crate) fn record_reopened_event_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    source_kind: &str,
    event_at: &str,
    source_id: &str,
) -> Result<Option<(String, Vec<Notification>)>> {
    ensure!(
        matches!(source_kind, "webhook" | "poll"),
        "Invalid PR reopen source"
    );
    ensure!(
        !source_id.trim().is_empty(),
        "Missing PR reopen event identity"
    );
    initialize(db)?;
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
        store_pending_reopen_in(db, repo, pr, source_kind, source_id, event_at_sec, event_at)?;
        reconcile_pending_reopens_in(db, repo, pr)?;
        return Ok(None);
    };
    let same_cycle = if current.state == "closed" {
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
        store_pending_reopen_in(db, repo, pr, source_kind, source_id, event_at_sec, event_at)?;
        reconcile_pending_reopens_in(db, repo, pr)?;
        return Ok(None);
    }

    let event_key = format!("reopened:{}", current.closed_at_sec);
    let notifications = record_event_in(
        db,
        "pull_request",
        repo,
        pr,
        "reopened",
        event_at,
        &event_key,
        &minimal_reopen_source(repo, pr, event_at),
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
    Ok(Some((event_key, notifications)))
}

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
            record_reopened_event_in(&tx, repo, pr, source_kind, event_at, source_id)?
                .map_or(0, |(_, notifications)| notifications.len());
        tx.commit()?;
        Ok(notifications)
    } else {
        Ok(
            record_reopened_event_in(db, repo, pr, source_kind, event_at, source_id)?
                .map_or(0, |(_, notifications)| notifications.len()),
        )
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
    db.execute(
        "INSERT OR IGNORE INTO automatic_pr_pending_reopens
         (repo,pr,source_kind,source_id,event_at_sec,event_at,source)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
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
) -> Result<()> {
    // Remove rows only when one observation fits the interval. Equal-second events and
    // multiple candidates stay pending; retained payloads contain only routing and time.
    let mut candidates: Vec<PendingReopen> = {
        let mut statement = db.prepare(
            "SELECT source_kind,source_id,event_at_sec,event_at
             FROM automatic_pr_pending_reopens
             WHERE repo=?1 AND pr=?2 AND event_at_sec>?3
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
    if candidates.len() != 1 {
        return Ok(());
    }
    let candidate = &candidates[0];
    let source = minimal_reopen_source(repo, pr, &candidate.event_at);
    let event_key = format!("reopened:{after_sec}");
    record_event_in(
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
             webhook_reopen_source_id=?4,poll_reopen_source_id=?5
         WHERE repo=?1 AND pr=?2 AND closed_at_sec=?6 AND state='closed'",
        params![
            repo,
            pr,
            candidate.event_at_sec,
            (candidate.source_kind == "webhook").then_some(candidate.source_id.as_str()),
            (candidate.source_kind == "poll").then_some(candidate.source_id.as_str()),
            after_sec
        ],
    )?;
    db.execute(
        "DELETE FROM automatic_pr_pending_reopens
         WHERE repo=?1 AND pr=?2 AND source_kind=?3 AND source_id=?4",
        params![repo, pr, candidate.source_kind, candidate.source_id],
    )?;
    Ok(())
}

pub(crate) fn reopen_timeline_floor(db: &Connection, repo: &str, pr: &str) -> Result<Option<i64>> {
    initialize(db)?;
    Ok(db.query_row(
        "SELECT MIN(cycle.closed_at_sec) FROM automatic_pr_closed_cycles AS cycle
         JOIN automatic_pr_lifecycle AS lifecycle USING(repo,pr)
         WHERE cycle.repo=?1 AND cycle.pr=?2 AND lifecycle.state='closed'",
        params![repo, pr],
        |row| row.get(0),
    )?)
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
                return record_reopened_event(db, repo, &pr, "webhook", event_at);
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
            let key =
                super::stable_source_key("pull_request", repo, &pr, event_name, "", &[event_at]);
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
            let key = super::stable_source_key(
                "review",
                repo,
                &pr,
                notification_event,
                state,
                &[&review_id, submitted_at],
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
         FROM automatic_pr_notifications WHERE state='pending' ORDER BY created_at,id",
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
    for _ in 0..BATCH {
        let Some(notification) = claim_next(db, now())? else {
            break;
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
                if let Some(reason @ "native_queue_resume_warning") = reason.as_deref() {
                    codex_wake::pr_ci_runtime::record_native_wake_recovery(
                        db,
                        &notification.thread,
                        reason,
                    )?;
                }
                ensure!(
                    mark_queued(db, &notification.id)?,
                    "Lost notification claim after queue acceptance"
                );
            }
            Err(error) if crate::execution::before_send_retry_reason(&error).is_some() => {
                let retry_after = now().saturating_add(BEFORE_SEND_RETRY_MS);
                ensure!(
                    release_before_send_at(db, &notification.id, retry_after)?,
                    "Lost notification claim before send"
                );
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

fn claim_next(db: &Connection, now_ms: i64) -> Result<Option<Notification>> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let row = tx
        .query_row(
            "SELECT id,kind,repo,pr,thread,event,event_key,source FROM automatic_pr_notifications
             WHERE state='pending' AND available_at_ms<=?1 ORDER BY created_at,id LIMIT 1",
            [now_ms],
            |row| {
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
            },
        )
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

        let targets = super::super::targets(&db).unwrap();
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
    fn reopen_without_a_known_cycle_stays_pending_until_close_arrives() {
        let db = Connection::open_in_memory().unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        let reopen = json!({
            "action":"reopened","number":7,
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":7,"updated_at":"2099-01-01T00:00:00Z"}
        });
        assert_eq!(
            accept_authenticated_webhook(&db, "pull_request", &reopen).unwrap(),
            0
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
        assert_eq!(unresolved, 0);
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
        assert_eq!(unresolved, 0);
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
        assert_eq!(unresolved, 0);
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
        assert_eq!(unresolved, 0);
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
    fn pending_reopen_schema_migration_rolls_back_and_can_resume() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE automatic_pr_pending_reopens (
                repo TEXT NOT NULL, pr TEXT NOT NULL,
                source_kind TEXT NOT NULL CHECK(source_kind IN ('webhook','poll')),
                event_at_sec INTEGER NOT NULL, event_at TEXT NOT NULL, source TEXT NOT NULL,
                PRIMARY KEY(repo,pr,source_kind,event_at_sec));
             PRAGMA ignore_check_constraints=ON;
             INSERT INTO automatic_pr_pending_reopens
            VALUES('owner/repo','7','invalid',1,'2099-01-01T00:00:01Z','discard-me-payload');
             PRAGMA ignore_check_constraints=OFF;",
        )
        .unwrap();
        assert!(migrate_pending_reopens(&db).is_err());
        let old_columns = {
            let mut statement = db
                .prepare("PRAGMA table_info(automatic_pr_pending_reopens)")
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert!(!old_columns.iter().any(|column| column == "source_id"));
        db.execute(
            "UPDATE automatic_pr_pending_reopens SET source_kind='webhook'",
            [],
        )
        .unwrap();
        migrate_pending_reopens(&db).unwrap();
        let (source_id, source_json, rows): (String, String, i64) = db
            .query_row(
                "SELECT source_id,source,(SELECT count(*) FROM automatic_pr_pending_reopens)
                 FROM automatic_pr_pending_reopens",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(source_id, "legacy:1");
        let migrated: Value = serde_json::from_str(&source_json).unwrap();
        assert_eq!(migrated["action"], "reopened");
        assert_eq!(migrated["repository"]["full_name"], "owner/repo");
        assert_eq!(
            migrated["pull_request"]["updated_at"],
            "2099-01-01T00:00:01Z"
        );
        assert!(migrated.get("huge").is_none());
        assert_eq!(rows, 1);
    }

    #[test]
    fn legacy_reopen_migration_does_not_infer_epochs_from_close_order() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        register(&db, "pull_request", "owner/repo", "7", thread).unwrap();
        db.execute_batch(
            "INSERT INTO automatic_pr_closed_cycles(repo,pr,closed_at_sec) VALUES
                ('owner/repo','7',10),('owner/repo','7',30),('owner/repo','7',20);
             INSERT INTO automatic_pr_lifecycle
                (repo,pr,epoch,state,closed_at_sec,reopened_at_sec)
                VALUES('owner/repo','7',2,'closed',30,NULL);",
        )
        .unwrap();
        for (id, epoch, state) in [("n1", 1, "queued"), ("n2", 2, "pending")] {
            db.execute(
                "INSERT INTO automatic_pr_notifications
                (id,kind,repo,pr,thread,event,event_key,source,state)
                 VALUES(?1,'pull_request','owner/repo','7',?2,'reopened',?3,'{}',?4)",
                params![id, thread, format!("reopened:{epoch}"), state],
            )
            .unwrap();
        }

        migrate_reopen_notification_identity(&db).unwrap();
        let migrated: Vec<(String, String)> = {
            let mut statement = db
                .prepare("SELECT event_key,state FROM automatic_pr_notifications ORDER BY id")
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(
            migrated,
            [
                ("reopened:1".into(), "queued".into()),
                ("reopened:30".into(), "pending".into())
            ]
        );
        assert!(
            record_event(
                &db,
                "pull_request",
                "owner/repo",
                "7",
                "reopened",
                "1970-01-01T00:05:00Z",
                "reopened:30",
                &json!({"action":"reopened"}),
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn pending_reopen_payloads_are_sanitized_when_source_id_already_exists() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE automatic_pr_pending_reopens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT NOT NULL, pr TEXT NOT NULL,
                source_kind TEXT NOT NULL CHECK(source_kind IN ('webhook','poll')),
                source_id TEXT NOT NULL,
                event_at_sec INTEGER NOT NULL, event_at TEXT NOT NULL, source TEXT NOT NULL,
                UNIQUE(repo,pr,source_kind,source_id));",
        )
        .unwrap();
        db.execute(
            "INSERT INTO automatic_pr_pending_reopens
             (repo,pr,source_kind,source_id,event_at_sec,event_at,source)
             VALUES('owner/repo','7','webhook','delivery-1',1,?1,?2)",
            params![
                "2099-01-01T00:00:01Z",
                r#"{"action":"reopened","secret":"remove-me"}"#
            ],
        )
        .unwrap();

        sanitize_pending_reopen_sources(&db).unwrap();
        let (source_id, event_at, source): (String, String, String) = db
            .query_row(
                "SELECT source_id,event_at,source FROM automatic_pr_pending_reopens",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(source_id, "delivery-1");
        assert_eq!(event_at, "2099-01-01T00:00:01Z");
        let source: Value = serde_json::from_str(&source).unwrap();
        assert_eq!(source["repository"]["full_name"], "owner/repo");
        assert_eq!(source["pull_request"]["updated_at"], event_at);
        assert!(source.get("secret").is_none());
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

        assert_eq!(
            dispatch_with(&mut db, |_, _, _, _| {
                Ok(("queued".into(), Some("native_queue_resume_warning".into())))
            })
            .unwrap(),
            1
        );
        let (state, recovery_reason): (String, Option<String>) = db
            .query_row(
                "SELECT notification.state,recovery.reason
                 FROM automatic_pr_notifications AS notification
                 LEFT JOIN native_wake_recovery AS recovery
                   ON recovery.thread=notification.thread
                 WHERE notification.event_key='pr-event-wake-warning'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "queued");
        assert_eq!(
            recovery_reason.as_deref(),
            Some("native_queue_resume_warning")
        );
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
