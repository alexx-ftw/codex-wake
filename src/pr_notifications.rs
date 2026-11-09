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
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(kind,repo,pr,thread,event_key));",
    )?;
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
pub(crate) fn release_before_send(db: &Connection, id: &str) -> Result<bool> {
    initialize(db)?;
    Ok(db.execute(
        "UPDATE automatic_pr_notifications SET state='pending'
         WHERE id=?1 AND state='sending'",
        [id],
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
    mut queue: impl FnMut(&str, &str, &str, bool) -> Result<(String, Option<String>)>,
) -> Result<usize> {
    const BATCH: usize = 16;
    let mut attempted = 0;
    for _ in 0..BATCH {
        let Some(notification) = claim_next(db)? else {
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
            Ok((state, _)) if state == "queued" => {
                ensure!(
                    mark_queued(db, &notification.id)?,
                    "Lost notification claim after queue acceptance"
                );
            }
            Err(error) if crate::execution::before_send_retry_reason(&error).is_some() => {
                ensure!(
                    release_before_send(db, &notification.id)?,
                    "Lost notification claim before send"
                );
                break;
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

fn claim_next(db: &Connection) -> Result<Option<Notification>> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let row = tx
        .query_row(
            "SELECT id,kind,repo,pr,thread,event,event_key,source FROM automatic_pr_notifications
             WHERE state='pending' ORDER BY created_at,id LIMIT 1",
            [],
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
