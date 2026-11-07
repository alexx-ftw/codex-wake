//! Durable notices for condition members whose event ordering is ambiguous.
use crate::conditions::{SenderIdentity, current_sender_identity, sender_confirmed_gone};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{path::Path, time::Duration};
use uuid::Uuid;

const CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS condition_alerts (
    id TEXT PRIMARY KEY,
    ambiguity TEXT NOT NULL CHECK(ambiguity IN (
        'ci_order_uncertain','pr_baseline_order_uncertain','native_baseline_order_uncertain')),
    group_id TEXT NOT NULL,
    target_thread TEXT NOT NULL,
    kind TEXT NOT NULL,
    repo TEXT NOT NULL,
    resource TEXT NOT NULL,
    event TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ambiguous_cursor TEXT,
    ci_repo TEXT NOT NULL DEFAULT '',
    ci_run_id INTEGER NOT NULL DEFAULT 0,
    ci_attempt INTEGER NOT NULL DEFAULT 0,
    ci_sha TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'ready'
        CHECK(state IN ('ready','sending','queued','uncertain','send_failed','cancelled')),
    reason TEXT,
    retry_at TEXT,
    sender_pid INTEGER,
    sender_start INTEGER,
    sender_boot TEXT,
    sender_namespace TEXT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(group_id,kind,repo,resource,event,outcome,ci_repo,ci_run_id,ci_attempt,ci_sha)
)";

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(CREATE_TABLE)?;
    db.execute_batch(
        "CREATE INDEX IF NOT EXISTS condition_alerts_thread
            ON condition_alerts(target_thread,created,id);",
    )?;
    Ok(())
}

#[derive(Debug)]
struct Alert {
    ambiguity: String,
    group_id: String,
    target_thread: String,
    kind: String,
    repo: String,
    resource: String,
    event: String,
    outcome: String,
    ambiguous_cursor: Option<String>,
    ci_repo: String,
    ci_run_id: i64,
    ci_attempt: i64,
    ci_sha: String,
}

fn record_uncertainty(tx: &Transaction<'_>) -> Result<()> {
    let alerts = {
        let mut statement = tx.prepare(
            "SELECT CASE WHEN m.kind='pull_request' THEN 'pr_baseline_order_uncertain'
                         ELSE 'ci_order_uncertain' END,
                    g.id,g.target_thread,m.kind,m.repo,m.resource,m.event,
                    m.outcome,m.ambiguous_cursor,m.ci_repo,m.ci_run_id,m.ci_attempt,m.ci_sha
             FROM condition_members m JOIN condition_groups g ON g.id=m.group_id
             WHERE m.order_uncertain=1 AND g.state='pending'
               AND m.kind IN ('job','pull_request')
             UNION ALL
             SELECT 'native_baseline_order_uncertain',g.id,g.target_thread,m.kind,m.repo,m.resource,
                    m.event,m.outcome,o.baseline_turn_id,m.ci_repo,m.ci_run_id,m.ci_attempt,m.ci_sha
             FROM native_condition_observers o
             JOIN condition_groups g ON g.id=o.group_id
             JOIN condition_members m ON m.group_id=o.group_id AND m.kind=o.kind
                AND m.repo=o.repo AND m.resource=o.resource AND m.event=o.event AND m.outcome=o.outcome
             WHERE o.baseline_order_uncertain=1 AND g.state='pending'
             ORDER BY 2,4,5,6,7,8,1",
        )?;
        statement
            .query_map([], |row| {
                Ok(Alert {
                    ambiguity: row.get(0)?,
                    group_id: row.get(1)?,
                    target_thread: row.get(2)?,
                    kind: row.get(3)?,
                    repo: row.get(4)?,
                    resource: row.get(5)?,
                    event: row.get(6)?,
                    outcome: row.get(7)?,
                    ambiguous_cursor: row.get(8)?,
                    ci_repo: row.get(9)?,
                    ci_run_id: row.get(10)?,
                    ci_attempt: row.get(11)?,
                    ci_sha: row.get(12)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for alert in alerts {
        tx.execute(
            "INSERT OR IGNORE INTO condition_alerts
             (id,ambiguity,group_id,target_thread,kind,repo,resource,event,outcome,ambiguous_cursor,
              ci_repo,ci_run_id,ci_attempt,ci_sha)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                Uuid::new_v4().to_string(),
                alert.ambiguity,
                alert.group_id,
                alert.target_thread,
                alert.kind,
                alert.repo,
                alert.resource,
                alert.event,
                alert.outcome,
                alert.ambiguous_cursor,
                alert.ci_repo,
                alert.ci_run_id,
                alert.ci_attempt,
                alert.ci_sha,
            ],
        )?;
    }
    tx.execute(
        "UPDATE condition_alerts AS a SET state='cancelled',
             reason=CASE WHEN EXISTS(SELECT 1 FROM condition_groups g
                                    WHERE g.id=a.group_id AND g.state<>'pending')
                         THEN 'condition_no_longer_pending' ELSE 'uncertainty_resolved' END,
             retry_at=NULL,updated=CURRENT_TIMESTAMP
         WHERE a.state IN ('ready','send_failed') AND (
             EXISTS(SELECT 1 FROM condition_groups g
                    WHERE g.id=a.group_id AND g.state<>'pending') OR
             (a.ambiguity IN ('ci_order_uncertain','pr_baseline_order_uncertain') AND EXISTS (
                 SELECT 1 FROM condition_members m WHERE m.group_id=a.group_id
                   AND m.kind=a.kind AND m.repo=a.repo AND m.resource=a.resource
                   AND m.event=a.event AND m.outcome=a.outcome AND m.ci_repo=a.ci_repo
                   AND m.ci_run_id=a.ci_run_id AND m.ci_attempt=a.ci_attempt AND m.ci_sha=a.ci_sha
                   AND m.order_uncertain=0
             )) OR
             (a.ambiguity='native_baseline_order_uncertain' AND EXISTS (
                 SELECT 1 FROM native_condition_observers o WHERE o.group_id=a.group_id
                   AND o.kind=a.kind AND o.repo=a.repo AND o.resource=a.resource
                   AND o.event=a.event AND o.outcome=a.outcome
                   AND o.baseline_order_uncertain=0
             ))
         )",
        [],
    )?;
    Ok(())
}

fn reconcile_orphaned_senders(tx: &Transaction<'_>) -> Result<usize> {
    let owners = {
        let mut statement = tx.prepare(
            "SELECT id,sender_pid,sender_start,sender_boot,sender_namespace
             FROM condition_alerts WHERE state='sending'",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut count = 0;
    for (id, pid, start, boot, namespace) in owners {
        let (Some(pid), Some(start), Some(boot), Some(namespace)) = (pid, start, boot, namespace)
        else {
            continue;
        };
        if sender_confirmed_gone(&SenderIdentity {
            pid,
            start,
            boot,
            namespace,
        }) {
            count += tx.execute(
                "UPDATE condition_alerts SET state='uncertain',reason='sender_exit_confirmed',
                     updated=CURRENT_TIMESTAMP WHERE id=?1 AND state='sending'",
                [&id],
            )?;
        }
    }
    Ok(count)
}

pub(crate) fn reconcile(db: &Connection) -> Result<usize> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let count = reconcile_orphaned_senders(&tx)?;
    tx.commit()?;
    Ok(count)
}

fn claim_ready(db: &Connection) -> Result<Option<(String, Alert)>> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    record_uncertainty(&tx)?;
    let row: Option<(String, Alert)> = tx
        .query_row(
            "SELECT id,ambiguity,group_id,target_thread,kind,repo,resource,event,outcome,
                    ambiguous_cursor,ci_repo,ci_run_id,ci_attempt,ci_sha
             FROM condition_alerts
             WHERE state='ready' OR (state='send_failed'
               AND reason IN ('target_busy_before_send','target_unavailable_before_send')
               AND retry_at<=CURRENT_TIMESTAMP)
             ORDER BY created,id LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    Alert {
                        ambiguity: row.get(1)?,
                        group_id: row.get(2)?,
                        target_thread: row.get(3)?,
                        kind: row.get(4)?,
                        repo: row.get(5)?,
                        resource: row.get(6)?,
                        event: row.get(7)?,
                        outcome: row.get(8)?,
                        ambiguous_cursor: row.get(9)?,
                        ci_repo: row.get(10)?,
                        ci_run_id: row.get(11)?,
                        ci_attempt: row.get(12)?,
                        ci_sha: row.get(13)?,
                    },
                ))
            },
        )
        .optional()?;
    let Some((id, alert)) = row else {
        tx.commit()?;
        return Ok(None);
    };
    let sender = current_sender_identity()?;
    ensure!(
        tx.execute(
            "UPDATE condition_alerts SET state='sending',reason=NULL,retry_at=NULL,
                 sender_pid=?2,sender_start=?3,sender_boot=?4,sender_namespace=?5,
                 updated=CURRENT_TIMESTAMP WHERE id=?1 AND state IN ('ready','send_failed')",
            params![id, sender.pid, sender.start, sender.boot, sender.namespace],
        )? == 1,
        "Ready condition alert changed while being claimed"
    );
    tx.commit()?;
    Ok(Some((id, alert)))
}

fn message(alert: &Alert) -> String {
    let resource = if alert.repo.is_empty() {
        alert.resource.clone()
    } else {
        format!("{}/{}", alert.repo, alert.resource)
    };
    let ambiguity = match alert.ambiguity.as_str() {
        "ci_order_uncertain" => format!(
            "CI event ordering is uncertain for condition group {}: resource {}/{}; event {}; outcome {}",
            alert.group_id, alert.kind, resource, alert.event, alert.outcome
        ),
        "pr_baseline_order_uncertain" => format!(
            "The cached pull request baseline is missing its prior state, so event ordering is uncertain for condition group {}: pull request {}/{}; event {}; outcome {}; candidate PR event time {}",
            alert.group_id,
            alert.repo,
            alert.resource,
            alert.event,
            alert.outcome,
            alert.ambiguous_cursor.as_deref().unwrap_or("unavailable")
        ),
        _ => format!(
            "Native baseline ordering is uncertain for condition group {}: resource {}/{}; event {}; outcome {}; baseline turn {}",
            alert.group_id,
            alert.kind,
            resource,
            alert.event,
            alert.outcome,
            alert.ambiguous_cursor.as_deref().unwrap_or("unavailable")
        ),
    };
    let ci_cursor = if alert.ambiguity == "ci_order_uncertain" {
        format!(
            "; ambiguous cursor {}",
            alert.ambiguous_cursor.as_deref().unwrap_or("unavailable")
        )
    } else {
        String::new()
    };
    let ci = if alert.ci_run_id > 0 {
        format!(
            "; CI run {}/{} attempt {} SHA {}",
            alert.ci_repo, alert.ci_run_id, alert.ci_attempt, alert.ci_sha
        )
    } else {
        String::new()
    };
    let investigation = if alert.ambiguity == "pr_baseline_order_uncertain" {
        "Investigate the prior cached pull request state and event timeline before treating this member as satisfied."
    } else {
        "Investigate the source ordering evidence before treating this member as satisfied."
    };
    format!(
        "{ambiguity}{ci}{ci_cursor}. This event was not recorded as a condition match. {investigation}"
    )
}

/// Send each persisted ambiguity notice at most once after an uncertain result.
/// Only a failure classified by execution as pre-send is eligible for retry.
fn dispatch(
    db: &Connection,
    mut send: impl FnMut(&str, &str, &str) -> Result<(String, Option<String>)>,
) -> Result<usize> {
    initialize(db)?;
    let mut attempted = 0;
    loop {
        let Some((id, alert)) = claim_ready(db)? else {
            return Ok(attempted);
        };
        let (state, reason) = match send(&alert.target_thread, &message(&alert), &id) {
            Ok((state, _)) if state == "queued" => ("queued", None),
            Ok((state, Some(reason)))
                if state == "ready"
                    && matches!(
                        reason.as_str(),
                        "target_busy_before_send" | "target_unavailable_before_send"
                    ) =>
            {
                ("send_failed", Some(reason))
            }
            Err(error) => match crate::execution::before_send_retry_reason(&error) {
                Some(reason) => ("send_failed", Some(reason.to_owned())),
                None => ("uncertain", Some("send_outcome_unknown".to_owned())),
            },
            _ => ("uncertain", Some("send_outcome_unknown".to_owned())),
        };
        let retry = state == "send_failed";
        ensure!(
            db.execute(
                "UPDATE condition_alerts SET state=?1,reason=?2,
                     retry_at=CASE WHEN ?3 THEN datetime('now','+15 seconds') ELSE NULL END,
                     sender_pid=NULL,sender_start=NULL,sender_boot=NULL,sender_namespace=NULL,
                     updated=CURRENT_TIMESTAMP
                 WHERE id=?4 AND state='sending'",
                params![state, reason, retry, id],
            )? == 1,
            "Could not persist condition alert delivery result"
        );
        attempted += 1;
    }
}

pub fn dispatch_with_timeout(db: &Connection, codex: &Path, timeout: Duration) -> Result<usize> {
    dispatch(db, |thread, text, id| {
        crate::execution::queue_with_identity(codex, thread, text, id, true, timeout)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conditions::{CiRunIdentity, MemberRegistration, Mode, Selector};

    const TARGET: &str = "11111111-1111-4111-8111-111111111111";
    const SOURCE: &str = "22222222-2222-4222-8222-222222222222";

    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        crate::conditions::initialize(&db).unwrap();
        crate::native_poll::initialize(&db).unwrap();
        initialize(&db).unwrap();
        db
    }

    fn ci_member(db: &Connection) -> String {
        let member = MemberRegistration::polling(
            Selector {
                kind: "job".into(),
                repo: "owner/repo".into(),
                resource: "build".into(),
                event: "completed".into(),
                outcome: Some("success".into()),
            },
            Some(CiRunIdentity {
                repo: "owner/repo".into(),
                run_id: 42,
                attempt: 1,
                sha: "a".repeat(40),
            }),
        );
        let group = crate::conditions::register_group_with_members(
            db,
            Mode::And,
            &[member],
            TARGET,
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_members SET order_uncertain=1,ambiguous_cursor='ci-cursor'
             WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        group
    }

    #[test]
    fn ci_and_native_uncertainty_create_one_concrete_notice_each() {
        let db = db();
        let ci = ci_member(&db);
        let native = crate::conditions::register_group_with_members(
            &db,
            Mode::And,
            &[MemberRegistration::polling(
                Selector {
                    kind: "thread".into(),
                    repo: String::new(),
                    resource: SOURCE.into(),
                    event: "turn_completed".into(),
                    outcome: Some("turn_completed".into()),
                },
                None,
            )],
            TARGET,
            None,
            None,
        )
        .unwrap();
        db.execute(
            "INSERT INTO native_condition_observers
             (group_id,kind,repo,resource,event,outcome,baseline_turn_id,baseline_status,
              baseline_order_uncertain,next_poll_ms)
             VALUES(?1,'thread','',?2,'turn_completed','turn_completed','baseline-7',
                    'completed',1,0)",
            params![native, SOURCE],
        )
        .unwrap();
        let mut sent = Vec::new();
        assert_eq!(
            dispatch(&db, |thread, text, id| {
                assert_eq!(thread, TARGET);
                assert!(text.contains("not recorded as a condition match"));
                assert!(text.contains("Investigate the source ordering evidence"));
                assert!(!text.contains("conditions are satisfied"));
                sent.push((text.to_owned(), id.to_owned()));
                Ok(("queued".into(), None))
            })
            .unwrap(),
            2
        );
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().any(|(text, _)| text.contains(&ci)));
        assert!(sent.iter().any(|(text, _)| text.contains(&native)));
        assert_eq!(
            dispatch(&db, |_, _, _| panic!("accepted alert must not replay")).unwrap(),
            0
        );
        let count: i64 = db
            .query_row("SELECT count(*) FROM condition_alerts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn pull_request_legacy_baseline_gets_a_distinct_investigation_notice() {
        let db = db();
        let group = crate::conditions::register_group_with_members(
            &db,
            Mode::And,
            &[MemberRegistration::polling(
                Selector {
                    kind: "pull_request".into(),
                    repo: "owner/repo".into(),
                    resource: "42".into(),
                    event: "merged".into(),
                    outcome: None,
                },
                None,
            )],
            TARGET,
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_members SET order_uncertain=1,ambiguous_cursor='legacy-cursor'
             WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        let mut sent = String::new();
        assert_eq!(
            dispatch(&db, |thread, text, _| {
                assert_eq!(thread, TARGET);
                sent = text.to_owned();
                Ok(("queued".into(), None))
            })
            .unwrap(),
            1
        );
        assert!(sent.contains("cached pull request baseline is missing its prior state"));
        assert!(sent.contains("pull request owner/repo/42"));
        assert!(sent.contains("candidate PR event time legacy-cursor"));
        assert!(sent.contains("not recorded as a condition match"));
        assert!(sent.contains("prior cached pull request state and event timeline"));
        assert!(!sent.contains("CI event ordering"));
        let ambiguity: String = db
            .query_row("SELECT ambiguity FROM condition_alerts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(ambiguity, "pr_baseline_order_uncertain");
        let cursor: Option<String> = db
            .query_row("SELECT ambiguous_cursor FROM condition_alerts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(cursor.as_deref(), Some("legacy-cursor"));
    }

    #[test]
    fn resolved_pull_request_baseline_cancels_unclaimed_notice() {
        let db = db();
        let group = crate::conditions::register_group_with_members(
            &db,
            Mode::And,
            &[MemberRegistration::polling(
                Selector {
                    kind: "pull_request".into(),
                    repo: "owner/repo".into(),
                    resource: "42".into(),
                    event: "merged".into(),
                    outcome: None,
                },
                None,
            )],
            TARGET,
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_members SET order_uncertain=1,ambiguous_cursor='legacy-cursor'
             WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        let tx = Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        record_uncertainty(&tx).unwrap();
        tx.commit().unwrap();
        db.execute(
            "UPDATE condition_members SET order_uncertain=0,ambiguous_cursor=NULL
             WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        assert_eq!(
            dispatch(&db, |_, _, _| panic!("resolved PR notice must not send")).unwrap(),
            0
        );
        let state: String = db
            .query_row("SELECT state FROM condition_alerts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state, "cancelled");
    }

    #[test]
    fn resolved_ready_alert_is_cancelled_without_replay() {
        let db = db();
        let group = ci_member(&db);
        let tx = Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        record_uncertainty(&tx).unwrap();
        tx.commit().unwrap();
        db.execute(
            "UPDATE condition_members SET order_uncertain=0 WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        assert_eq!(
            dispatch(&db, |_, _, _| panic!("resolved notice must not send")).unwrap(),
            0
        );
        let state: String = db
            .query_row("SELECT state FROM condition_alerts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state, "cancelled");
    }

    #[test]
    fn resolved_or_group_cancels_unclaimed_alert_after_normal_delivery() {
        let db = db();
        let other = Selector {
            kind: "artifact".into(),
            repo: "owner/repo".into(),
            resource: "release".into(),
            event: "available".into(),
            outcome: None,
        };
        let group = crate::conditions::register_group_with_members(
            &db,
            Mode::Or,
            &[
                MemberRegistration::polling(
                    Selector {
                        kind: "job".into(),
                        repo: "owner/repo".into(),
                        resource: "build".into(),
                        event: "completed".into(),
                        outcome: Some("success".into()),
                    },
                    Some(CiRunIdentity {
                        repo: "owner/repo".into(),
                        run_id: 42,
                        attempt: 1,
                        sha: "a".repeat(40),
                    }),
                ),
                MemberRegistration::explicit(other.clone()),
            ],
            TARGET,
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_members SET order_uncertain=1,ambiguous_cursor='ci-cursor'
             WHERE group_id=?1 AND kind='job'",
            [&group],
        )
        .unwrap();
        let tx = Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        record_uncertainty(&tx).unwrap();
        tx.commit().unwrap();

        crate::conditions::record_published_event(
            &db,
            &crate::conditions::PublishedEvent {
                selector: other,
                source_event_key: "release-event".into(),
                cursor: None,
                ci: None,
                source: serde_json::json!({}),
            },
        )
        .unwrap();
        let delivery = crate::conditions::claim_ready(&db).unwrap().unwrap();
        assert_eq!(delivery.group_id, group);
        crate::conditions::record_delivery_accepted(&db, &group).unwrap();

        assert_eq!(
            dispatch(&db, |_, _, _| panic!("resolved OR notice must not send")).unwrap(),
            0
        );
        let state: String = db
            .query_row("SELECT state FROM condition_alerts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state, "cancelled");
        let group_state: String = db
            .query_row(
                "SELECT state FROM condition_groups WHERE id=?1",
                [&group],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(group_state, "accepted");
    }

    #[test]
    fn uncertain_and_crash_claims_are_never_replayed() {
        let db = db();
        ci_member(&db);
        assert_eq!(
            dispatch(&db, |_, _, _| Ok((
                "needs_attention".into(),
                Some("queue_unknown".into())
            )))
            .unwrap(),
            1
        );
        assert_eq!(
            dispatch(&db, |_, _, _| panic!("uncertain notice must not replay")).unwrap(),
            0
        );
    }

    #[test]
    fn live_sending_claim_is_not_marked_uncertain_or_replayed() {
        let db = db();
        ci_member(&db);
        assert!(claim_ready(&db).unwrap().is_some());
        assert_eq!(reconcile(&db).unwrap(), 0);
        assert_eq!(
            dispatch(&db, |_, _, _| panic!("live claim must not replay")).unwrap(),
            0
        );
        let (state, reason): (String, Option<String>) = db
            .query_row("SELECT state,reason FROM condition_alerts", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(state, "sending");
        assert_eq!(reason, None);
    }

    #[test]
    fn orphaned_sending_claim_becomes_uncertain_without_replay() {
        let db = db();
        ci_member(&db);
        let (id, _) = claim_ready(&db).unwrap().unwrap();
        let mut owner = current_sender_identity().unwrap();
        owner.pid = std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .unwrap()
            .trim()
            .parse::<i64>()
            .unwrap()
            + 1;
        assert!(owner.pid < i64::from(i32::MAX));
        owner.start = 1;
        db.execute(
            "UPDATE condition_alerts SET sender_pid=?1,sender_start=?2,sender_boot=?3,
                 sender_namespace=?4 WHERE id=?5",
            params![owner.pid, owner.start, owner.boot, owner.namespace, id],
        )
        .unwrap();
        assert_eq!(reconcile(&db).unwrap(), 1);
        let (state, reason): (String, Option<String>) = db
            .query_row("SELECT state,reason FROM condition_alerts", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(state, "uncertain");
        assert_eq!(reason.as_deref(), Some("sender_exit_confirmed"));
        assert_eq!(
            dispatch(&db, |_, _, _| panic!("orphaned claim must not replay")).unwrap(),
            0
        );
        assert_eq!(
            dispatch(&db, |_, _, _| panic!("uncertain orphan must not replay")).unwrap(),
            0
        );
    }

    #[test]
    fn restart_makes_alert_claim_uncertain_without_replay_but_namespace_mismatch_stays_sending() {
        let db = db();
        ci_member(&db);
        let (id, _) = claim_ready(&db).unwrap().unwrap();
        let mut owner = current_sender_identity().unwrap();
        owner.namespace.push_str("-other");
        db.execute(
            "UPDATE condition_alerts SET sender_boot=?1,sender_namespace=?2 WHERE id=?3",
            params![owner.boot, owner.namespace, id],
        )
        .unwrap();

        assert_eq!(reconcile(&db).unwrap(), 0);
        let state: String = db
            .query_row("SELECT state FROM condition_alerts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state, "sending");

        db.execute(
            "UPDATE condition_alerts SET sender_boot='previous-boot' WHERE id=?1",
            [&id],
        )
        .unwrap();
        assert_eq!(reconcile(&db).unwrap(), 1);
        let (state, reason): (String, Option<String>) = db
            .query_row("SELECT state,reason FROM condition_alerts", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(state, "uncertain");
        assert_eq!(reason.as_deref(), Some("sender_exit_confirmed"));
        assert_eq!(
            dispatch(&db, |_, _, _| panic!("restarted alert must not replay")).unwrap(),
            0
        );
    }

    #[test]
    fn receiver_dispatch_reconciles_orphaned_alert_without_database_open() {
        let db = db();
        ci_member(&db);
        let (id, _) = claim_ready(&db).unwrap().unwrap();
        let mut owner = current_sender_identity().unwrap();
        owner.pid = std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .unwrap()
            .trim()
            .parse::<i64>()
            .unwrap()
            + 1;
        assert!(owner.pid < i64::from(i32::MAX));
        owner.start = 1;
        db.execute(
            "UPDATE condition_alerts SET sender_pid=?1,sender_start=?2,sender_boot=?3,
                 sender_namespace=?4 WHERE id=?5",
            params![owner.pid, owner.start, owner.boot, owner.namespace, id],
        )
        .unwrap();

        // The receiver calls this dispatcher after opening bridge::connect directly.
        // This path must reconcile without going through main::database or MCP.
        assert_eq!(
            crate::dispatch_conditions(&db, std::path::Path::new("/unused-codex")).unwrap(),
            0
        );
        let (state, reason): (String, Option<String>) = db
            .query_row("SELECT state,reason FROM condition_alerts", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(state, "uncertain");
        assert_eq!(reason.as_deref(), Some("sender_exit_confirmed"));
    }

    #[test]
    fn only_proven_pre_send_failure_retries_with_the_same_identity() {
        let db = db();
        ci_member(&db);
        let mut first_id = String::new();
        assert_eq!(
            dispatch(&db, |_, _, id| {
                first_id = id.to_owned();
                Err(crate::execution::TargetUnavailableBeforeSend.into())
            })
            .unwrap(),
            1
        );
        db.execute(
            "UPDATE condition_alerts SET retry_at='2000-01-01 00:00:00'",
            [],
        )
        .unwrap();
        let mut retry_id = String::new();
        assert_eq!(
            dispatch(&db, |_, _, id| {
                retry_id = id.to_owned();
                Ok(("queued".into(), None))
            })
            .unwrap(),
            1
        );
        assert_eq!(retry_id, first_id);
    }
}
