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
        CREATE TABLE IF NOT EXISTS automatic_pr_lifecycle (
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('closed','reopened')),
            closed_at_sec INTEGER NOT NULL,
            reopened_at_sec INTEGER,
            webhook_reopen_at_sec INTEGER,
            poll_reopen_at_sec INTEGER,
            PRIMARY KEY(repo,pr));
        CREATE TABLE IF NOT EXISTS automatic_pr_pending_reopens (
            repo TEXT NOT NULL,
            pr TEXT NOT NULL,
            source_kind TEXT NOT NULL CHECK(source_kind IN ('webhook','poll')),
            event_at_sec INTEGER NOT NULL,
            event_at TEXT NOT NULL,
            source TEXT NOT NULL,
            PRIMARY KEY(repo,pr,source_kind,event_at_sec));",
    )?;
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
    Ok(inserted != 0)
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
    let source = serde_json::to_string(source)?;
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

fn record_closed_event_in(
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

fn ensure_closed_cycle_in(db: &Connection, repo: &str, pr: &str, closed_at_sec: i64) -> Result<()> {
    let current: Option<(i64, String, i64, Option<i64>)> = db
        .query_row(
            "SELECT epoch,state,closed_at_sec,reopened_at_sec
             FROM automatic_pr_lifecycle WHERE repo=?1 AND pr=?2",
            params![repo, pr],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (epoch, begin_cycle) = match current {
        None => (1, true),
        Some((epoch, state, closed_at, reopened_at)) if state == "closed" => {
            if closed_at_sec == closed_at {
                (epoch, false)
            } else if closed_at_sec > closed_at {
                (epoch.saturating_add(1), true)
            } else {
                (epoch, false)
            }
        }
        Some((epoch, _, _, Some(reopened_at))) if closed_at_sec > reopened_at => {
            (epoch.saturating_add(1), true)
        }
        Some((epoch, _, _, _)) => (epoch, false),
    };
    if begin_cycle {
        db.execute(
            "INSERT INTO automatic_pr_lifecycle
             (repo,pr,epoch,state,closed_at_sec,reopened_at_sec,
              webhook_reopen_at_sec,poll_reopen_at_sec)
             VALUES(?1,?2,?3,'closed',?4,NULL,NULL,NULL)
             ON CONFLICT(repo,pr) DO UPDATE SET epoch=excluded.epoch,state='closed',
                closed_at_sec=excluded.closed_at_sec,reopened_at_sec=NULL,
                webhook_reopen_at_sec=NULL,poll_reopen_at_sec=NULL",
            params![repo, pr, epoch, closed_at_sec],
        )?;
    }
    let current_closed_at: Option<i64> = db
        .query_row(
            "SELECT closed_at_sec FROM automatic_pr_lifecycle
             WHERE repo=?1 AND pr=?2 AND state='closed'",
            params![repo, pr],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(closed_at_sec) = current_closed_at {
        resolve_one_pending_reopen_in(db, repo, pr, closed_at_sec)?;
    }
    Ok(())
}

pub(crate) fn record_reopened_event_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    source_kind: &str,
    event_at: &str,
    source: &Value,
) -> Result<Option<(String, Vec<Notification>)>> {
    ensure!(
        matches!(source_kind, "webhook" | "poll"),
        "Invalid PR reopen source"
    );
    initialize(db)?;
    let event_at_sec = timestamp_second(db, event_at)?;
    let current: Option<(i64, String, i64, Option<i64>, Option<i64>, Option<i64>)> = db
        .query_row(
            "SELECT epoch,state,closed_at_sec,reopened_at_sec,
                    webhook_reopen_at_sec,poll_reopen_at_sec
             FROM automatic_pr_lifecycle WHERE repo=?1 AND pr=?2",
            params![repo, pr],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;

    let Some((epoch, state, closed_at, reopened_at, webhook_at, poll_at)) = current else {
        store_pending_reopen_in(db, repo, pr, source_kind, event_at_sec, event_at, source)?;
        return Ok(None);
    };
    let (same_cycle, source_seen_at) = if state == "closed" {
        (event_at_sec > closed_at, None)
    } else {
        let seen_at = if source_kind == "webhook" {
            webhook_at
        } else {
            poll_at
        };
        // The other source may report a later PR edit than the timeline reopen time.
        let within_cycle = reopened_at.is_some() && event_at_sec > closed_at;
        (
            within_cycle && (seen_at == Some(event_at_sec) || seen_at.is_none()),
            seen_at,
        )
    };
    if !same_cycle {
        store_pending_reopen_in(db, repo, pr, source_kind, event_at_sec, event_at, source)?;
        return Ok(None);
    }

    let event_key = format!("reopened:{epoch}");
    let notifications = record_event_in(
        db,
        "pull_request",
        repo,
        pr,
        "reopened",
        event_at,
        &event_key,
        source,
    )?;
    if state == "closed" {
        let webhook_reopen_at = (source_kind == "webhook").then_some(event_at_sec);
        let poll_reopen_at = (source_kind == "poll").then_some(event_at_sec);
        db.execute(
            "UPDATE automatic_pr_lifecycle SET state='reopened',reopened_at_sec=?3,
                 webhook_reopen_at_sec=?4,poll_reopen_at_sec=?5
             WHERE repo=?1 AND pr=?2 AND epoch=?6 AND state='closed'",
            params![
                repo,
                pr,
                event_at_sec,
                webhook_reopen_at,
                poll_reopen_at,
                epoch
            ],
        )?;
    } else if source_seen_at.is_none() {
        let column = if source_kind == "webhook" {
            "webhook_reopen_at_sec"
        } else {
            "poll_reopen_at_sec"
        };
        db.execute(
            &format!(
                "UPDATE automatic_pr_lifecycle SET {column}=?3
                 WHERE repo=?1 AND pr=?2 AND epoch=?4 AND state='reopened'"
            ),
            params![repo, pr, event_at_sec, epoch],
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
    source: &Value,
) -> Result<usize> {
    initialize(db)?;
    if db.is_autocommit() {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let notifications = record_reopened_event_in(&tx, repo, pr, source_kind, event_at, source)?
            .map_or(0, |(_, notifications)| notifications.len());
        tx.commit()?;
        Ok(notifications)
    } else {
        Ok(
            record_reopened_event_in(db, repo, pr, source_kind, event_at, source)?
                .map_or(0, |(_, notifications)| notifications.len()),
        )
    }
}

fn store_pending_reopen_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    source_kind: &str,
    event_at_sec: i64,
    event_at: &str,
    source: &Value,
) -> Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO automatic_pr_pending_reopens
         (repo,pr,source_kind,event_at_sec,event_at,source) VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            repo,
            pr,
            source_kind,
            event_at_sec,
            event_at,
            serde_json::to_string(source)?
        ],
    )?;
    Ok(())
}

fn resolve_one_pending_reopen_in(
    db: &Connection,
    repo: &str,
    pr: &str,
    closed_at_sec: i64,
) -> Result<()> {
    // Timestamps have second precision; leave zero or multiple possible cycles pending.
    let candidates: Vec<(String, i64, String, String)> = {
        let mut statement = db.prepare(
            "SELECT source_kind,event_at_sec,event_at,source
             FROM automatic_pr_pending_reopens
             WHERE repo=?1 AND pr=?2 AND event_at_sec>?3
             ORDER BY event_at_sec,source_kind",
        )?;
        statement
            .query_map(params![repo, pr, closed_at_sec], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if candidates.len() != 1 {
        return Ok(());
    }
    let Some((source_kind, event_at_sec, event_at, source)) = candidates.into_iter().next() else {
        return Ok(());
    };
    let source: Value = serde_json::from_str(&source)?;
    let epoch: i64 = db.query_row(
        "SELECT epoch FROM automatic_pr_lifecycle WHERE repo=?1 AND pr=?2 AND state='closed'",
        params![repo, pr],
        |row| row.get(0),
    )?;
    let event_key = format!("reopened:{epoch}");
    record_event_in(
        db,
        "pull_request",
        repo,
        pr,
        "reopened",
        &event_at,
        &event_key,
        &source,
    )?;
    db.execute(
        "UPDATE automatic_pr_lifecycle SET state='reopened',reopened_at_sec=?3,
             webhook_reopen_at_sec=?4,poll_reopen_at_sec=?5
         WHERE repo=?1 AND pr=?2 AND epoch=?6 AND state='closed'",
        params![
            repo,
            pr,
            event_at_sec,
            (source_kind == "webhook").then_some(event_at_sec),
            (source_kind == "poll").then_some(event_at_sec),
            epoch
        ],
    )?;
    db.execute(
        "DELETE FROM automatic_pr_pending_reopens
         WHERE repo=?1 AND pr=?2 AND source_kind=?3 AND event_at_sec=?4",
        params![repo, pr, source_kind, event_at_sec],
    )?;
    Ok(())
}

fn timestamp_second(db: &Connection, timestamp: &str) -> Result<i64> {
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
                return record_reopened_event(db, repo, &pr, "webhook", event_at, payload);
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
        assert_eq!(reopened[0].event_key, "reopened:1");
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
