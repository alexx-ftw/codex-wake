//! Persistent obligations, independent of notification delivery state.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use uuid::Uuid;

const MAX_DESCRIPTION_BYTES: usize = 2048;
const LEGACY_GUARD_REASON: &str = "compatibility_guard_not_delivery";

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Obligation {
    pub id: String,
    pub thread: String,
    pub kind: String,
    pub repo: String,
    pub resource: String,
    pub outcome: String,
    pub description: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Transfer {
    pub id: String,
    pub obligation: Obligation,
    pub source_thread: String,
    pub target_thread: String,
    pub goal: String,
    pub status: String,
    pub tests: String,
    pub next_step: String,
    pub state: String,
    pub notification_state: String,
    pub notification_reason: Option<String>,
    #[serde(skip)]
    pub confirmation_code: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct NotificationStatus {
    pub state: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CoordinatorAlert {
    pub id: String,
    pub responsible: String,
    pub coordinator: String,
    pub state: String,
    pub reason: Option<String>,
    pub created: String,
}

pub fn initialize(db: &Connection) -> Result<()> {
    crate::steer::initialize(db)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS obligations (
            id TEXT PRIMARY KEY,
            thread TEXT NOT NULL,
            kind TEXT NOT NULL,
            repo TEXT NOT NULL,
            resource TEXT NOT NULL,
            outcome TEXT NOT NULL,
            description TEXT NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0 CHECK(resolved IN (0, 1))
        );
        CREATE INDEX IF NOT EXISTS obligations_pending ON obligations(thread, resolved);
        CREATE INDEX IF NOT EXISTS obligations_publication
            ON obligations(kind, repo, resource, outcome, resolved);
        CREATE TABLE IF NOT EXISTS coordinators (
            responsible TEXT PRIMARY KEY,
            coordinator TEXT NOT NULL,
            CHECK(responsible != coordinator)
        );
        CREATE TABLE IF NOT EXISTS coordinator_alerts (
            id TEXT PRIMARY KEY,
            responsible TEXT NOT NULL,
            coordinator TEXT NOT NULL,
            message TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('sending','queued','ready','needs_attention')),
            reason TEXT,
            created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            sender_pid INTEGER,
            sender_start INTEGER
        );
        CREATE TABLE IF NOT EXISTS coordinator_alert_legacy_collisions (
            alert_id TEXT PRIMARY KEY, legacy_alert_id TEXT NOT NULL,
            claim_id TEXT NOT NULL, observations INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS coordinator_alert_collision_items (
            alert_id TEXT NOT NULL, id TEXT NOT NULL, thread TEXT NOT NULL,
            kind TEXT NOT NULL, repo TEXT NOT NULL, resource TEXT NOT NULL,
            outcome TEXT NOT NULL, description TEXT NOT NULL,
            PRIMARY KEY(alert_id, id)
        );
        CREATE TABLE IF NOT EXISTS obligation_transfers (
            id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL,
            source_thread TEXT NOT NULL,
            target_thread TEXT NOT NULL,
            goal TEXT NOT NULL,
            status TEXT NOT NULL,
            tests TEXT NOT NULL,
            next_step TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending', 'accepted')),
            confirmation_code_hash TEXT,
            notification_message TEXT,
            notification_state TEXT NOT NULL DEFAULT 'ready'
                CHECK(notification_state IN ('ready', 'sending', 'queued', 'needs_attention')),
            notification_reason TEXT,
            notification_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            accepted_at TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS obligation_transfers_pending
            ON obligation_transfers(obligation_id) WHERE state='pending';
        CREATE INDEX IF NOT EXISTS obligation_transfers_target
            ON obligation_transfers(target_thread, state);",
    )?;
    let collision_columns = {
        let mut stmt = db.prepare("PRAGMA table_info(coordinator_alert_legacy_collisions)")?;
        stmt.query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if !collision_columns.iter().any(|column| column == "claim_id") {
        // Recheck after taking the write lock: another startup may have migrated it.
        let tx = rusqlite::Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let current = {
            let mut stmt = tx.prepare("PRAGMA table_info(coordinator_alert_legacy_collisions)")?;
            stmt.query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        if !current.iter().any(|column| column == "claim_id") {
            tx.execute_batch(
                "ALTER TABLE coordinator_alert_legacy_collisions ADD COLUMN claim_id TEXT",
            )?;
        }
        tx.execute("UPDATE coordinator_alert_legacy_collisions SET claim_id=alert_id WHERE claim_id IS NULL", [])?;
        tx.commit()?;
    }
    db.execute_batch("CREATE INDEX IF NOT EXISTS coordinator_collision_claim ON coordinator_alert_legacy_collisions(claim_id)")?;
    // Complete a partially applied migration from an earlier interrupted startup.
    let incomplete: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM coordinator_alert_legacy_collisions WHERE claim_id IS NULL)",
        [],
        |r| r.get(0),
    )?;
    if incomplete {
        db.execute("UPDATE coordinator_alert_legacy_collisions SET claim_id=alert_id WHERE claim_id IS NULL", [])?;
    }
    let columns = {
        let mut statement = db.prepare("PRAGMA table_info(coordinator_alerts)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if !columns.iter().any(|column| column == "sender_pid") {
        db.execute_batch("ALTER TABLE coordinator_alerts ADD COLUMN sender_pid INTEGER")?;
    }
    if !columns.iter().any(|column| column == "sender_start") {
        db.execute_batch("ALTER TABLE coordinator_alerts ADD COLUMN sender_start INTEGER")?;
    }

    let has_code_hash = {
        let mut statement = db.prepare("PRAGMA table_info(obligation_transfers)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|column| column == "confirmation_code_hash")
    };
    if !has_code_hash {
        db.execute(
            "ALTER TABLE obligation_transfers ADD COLUMN confirmation_code_hash TEXT",
            [],
        )?;
    }
    let columns = {
        let mut statement = db.prepare("PRAGMA table_info(obligation_transfers)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if !columns
        .iter()
        .any(|column| column == "notification_message")
    {
        db.execute(
            "ALTER TABLE obligation_transfers ADD COLUMN notification_message TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "notification_state") {
        db.execute(
            "ALTER TABLE obligation_transfers ADD COLUMN notification_state TEXT NOT NULL DEFAULT 'ready'",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "notification_reason") {
        db.execute(
            "ALTER TABLE obligation_transfers ADD COLUMN notification_reason TEXT",
            [],
        )?;
    }
    if !columns
        .iter()
        .any(|column| column == "notification_updated_at")
    {
        db.execute(
            "ALTER TABLE obligation_transfers ADD COLUMN notification_updated_at TEXT",
            [],
        )?;
        db.execute(
            "UPDATE obligation_transfers SET notification_updated_at=CURRENT_TIMESTAMP
             WHERE notification_updated_at IS NULL",
            [],
        )?;
    }
    db.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS obligation_transfers_confirmation_code
            ON obligation_transfers(confirmation_code_hash)
            WHERE confirmation_code_hash IS NOT NULL;",
    )?;

    // Backfill durable notices for pending proposals created before code confirmation existed.
    let tx = db.unchecked_transaction()?;
    let old_pending = {
        let mut statement = tx.prepare(
            "SELECT id, target_thread, confirmation_code_hash FROM obligation_transfers
             WHERE state='pending' AND notification_state='ready'
               AND notification_message IS NULL ORDER BY rowid",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if old_pending.is_empty() {
        tx.rollback()?;
        return Ok(());
    }
    for (transfer_id, target_thread, code_hash) in old_pending {
        if code_hash.is_some() {
            let old_notice = tx
                .query_row(
                    "SELECT id, message, state FROM steers
                     WHERE thread=?1 AND message LIKE ?2 ORDER BY rowid DESC LIMIT 1",
                    params![
                        target_thread,
                        format!("Wake: nueva propuesta de traspaso {transfer_id}. Código de confirmación: %")
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?;
            let (message, reason, pending_notice_id) = match old_notice {
                Some((notice_id, message, state)) if state == "pending" => {
                    (Some(message), None, Some(notice_id))
                }
                Some((_, message, _)) => (
                    Some(message),
                    Some("prior_hook_notice_claimed_outcome_unknown"),
                    None,
                ),
                None => (None, Some("prior_notice_missing_outcome_unknown"), None),
            };
            if let Some(notice_id) = pending_notice_id {
                tx.execute(
                    "UPDATE obligation_transfers SET notification_message=?1
                     WHERE id=?2 AND state='pending' AND notification_message IS NULL",
                    params![message, transfer_id],
                )?;
                tx.execute(
                    "DELETE FROM steers WHERE id=?1 AND state='pending'",
                    [notice_id],
                )?;
                continue;
            }
            tx.execute(
                "UPDATE obligation_transfers SET notification_message=?1,
                    notification_state='needs_attention', notification_reason=?2
                 WHERE id=?3 AND state='pending' AND notification_message IS NULL",
                params![message, reason, transfer_id],
            )?;
            continue;
        }
        let code = new_confirmation_code();
        let notice = transfer_notice(&transfer_id, &code);
        tx.execute(
            "UPDATE obligation_transfers SET confirmation_code_hash=?1, notification_message=?2
             WHERE id=?3 AND state='pending' AND notification_message IS NULL",
            params![confirmation_code_hash(&code), notice, transfer_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

pub fn register_coordinator(db: &Connection, responsible: &str, coordinator: &str) -> Result<()> {
    let responsible = Uuid::parse_str(responsible)?.to_string();
    let coordinator = Uuid::parse_str(coordinator)?.to_string();
    ensure!(
        responsible != coordinator,
        "A chat cannot coordinate itself"
    );
    db.execute(
        "INSERT INTO coordinators(responsible, coordinator) VALUES (?1, ?2)
         ON CONFLICT(responsible) DO UPDATE SET coordinator=excluded.coordinator",
        params![responsible, coordinator],
    )?;
    Ok(())
}

/// Hash every pending obligation in canonical ID order without retaining the whole set.
/// Run inside the same transaction as the alert claim.
pub fn pending_digest(db: &Connection, thread: &str) -> Result<(i64, String)> {
    let mut stmt = db.prepare(
        "SELECT id,kind,repo,resource,outcome,description FROM obligations \
         WHERE thread=?1 AND resolved=0 ORDER BY id COLLATE BINARY",
    )?;
    let mut rows = stmt.query([thread])?;
    let mut hash = Sha256::new();
    let mut count = 0_i64;
    while let Some(row) = rows.next()? {
        for index in 0..6 {
            let value: String = row.get(index)?;
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        count += 1;
    }
    Ok((count, format!("{:x}", hash.finalize())))
}

/// Persist before sending. Existing event IDs are never sent again, including after an uncertain result.
#[cfg(test)]
pub fn claim_coordinator_alert(
    db: &Connection,
    responsible: &str,
    fingerprint: &str,
    message: &str,
) -> Result<Option<(String, String)>> {
    Ok(
        claim_coordinator_alert_with_legacy(db, responsible, fingerprint, message, None)?
            .and_then(|(id, coordinator, collision)| (!collision).then_some((id, coordinator))),
    )
}

/// Caller holds an immediate transaction covering the snapshot and this claim.
pub fn claim_coordinator_alert_with_legacy(
    db: &Connection,
    responsible: &str,
    fingerprint: &str,
    message: &str,
    legacy_fingerprint: Option<&str>,
) -> Result<Option<(String, String, bool)>> {
    let responsible = Uuid::parse_str(responsible)?.to_string();
    let Some(coordinator) = db
        .query_row(
            "SELECT coordinator FROM coordinators WHERE responsible=?1",
            [&responsible],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let id = format!(
        "{:x}",
        Sha256::digest(format!("{responsible}:{coordinator}:{fingerprint}").as_bytes())
    );
    if let Some(legacy) = legacy_fingerprint {
        let old_id = format!(
            "{:x}",
            Sha256::digest(format!("{responsible}:{coordinator}:{legacy}").as_bytes())
        );
        let old_reason: Option<Option<String>> = db
            .query_row(
                "SELECT reason FROM coordinator_alerts WHERE id=?1",
                [&old_id],
                |row| row.get(0),
            )
            .optional()?;
        if old_reason.is_some()
            && old_reason.as_ref().and_then(|value| value.as_deref()) != Some(LEGACY_GUARD_REASON)
        {
            let existing: Option<String> = db.query_row(
                "SELECT alert_id FROM coordinator_alert_legacy_collisions WHERE claim_id=?1 AND legacy_alert_id=?2 LIMIT 1",
                params![id, old_id], |row| row.get(0),
            ).optional()?;
            let diagnostic_id = existing.unwrap_or_else(|| {
                format!(
                    "{:x}",
                    Sha256::digest(format!("legacy-collision:{id}:{old_id}").as_bytes())
                )
            });
            let inserted = db.execute(
                "INSERT OR IGNORE INTO coordinator_alerts(id,responsible,coordinator,message,state,reason)
                 VALUES (?1,?2,?3,?4,'needs_attention','legacy_collision_delivery_unknown')",
                params![diagnostic_id, responsible, coordinator, message],
            )?;
            if inserted == 1 {
                db.execute(
                    "INSERT INTO coordinator_alert_legacy_collisions(alert_id,legacy_alert_id,claim_id) VALUES (?1,?2,?3)",
                    params![diagnostic_id, old_id, id],
                )?;
                db.execute(
                    "INSERT INTO coordinator_alert_collision_items(alert_id,id,thread,kind,repo,resource,outcome,description)
                     SELECT ?1,id,thread,kind,repo,resource,outcome,description FROM obligations
                     WHERE thread=?2 AND resolved=0",
                    params![diagnostic_id, responsible],
                )?;
            } else {
                let recorded: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM coordinator_alert_legacy_collisions WHERE alert_id=?1 AND claim_id=?2 AND legacy_alert_id=?3)",
                    params![diagnostic_id,id,old_id], |row| row.get(0),
                )?;
                ensure!(
                    recorded,
                    "Collision diagnostic ID already belongs to another alert"
                );
                record_collision_observation(db, &diagnostic_id)?;
            }
            return Ok(Some((diagnostic_id, coordinator, true)));
        }
    }
    // A legacy executable claims only its own key. Reserve that key in the same
    // transaction as the full claim; this row is a guard, not a delivery.
    if let Some(legacy) = legacy_fingerprint {
        let old_id = format!(
            "{:x}",
            Sha256::digest(format!("{responsible}:{coordinator}:{legacy}").as_bytes())
        );
        db.execute(
            "INSERT OR IGNORE INTO coordinator_alerts(id,responsible,coordinator,message,state,reason)
             VALUES (?1,?2,?3,'Compatibility guard; no delivery was attempted.','needs_attention',?4)",
            params![old_id,responsible,coordinator,LEGACY_GUARD_REASON],
        )?;
    }
    let prior_collision: Option<String> = db
        .query_row(
            "SELECT alert_id FROM coordinator_alert_legacy_collisions WHERE claim_id=?1 LIMIT 1",
            [&id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(diagnostic_id) = prior_collision {
        record_collision_observation(db, &diagnostic_id)?;
        return Ok(Some((diagnostic_id, coordinator, true)));
    }
    let sender_pid = i64::from(std::process::id());
    let sender_start =
        process_start_time(std::process::id()).and_then(|started| i64::try_from(started).ok());
    let inserted = db.execute(
        "INSERT OR IGNORE INTO coordinator_alerts
            (id,responsible,coordinator,message,state,sender_pid,sender_start)
         VALUES (?1,?2,?3,?4,'sending',?5,?6)",
        params![
            id,
            responsible,
            coordinator,
            message,
            sender_pid,
            sender_start
        ],
    )?;
    Ok((inserted == 1).then_some((id, coordinator, false)))
}

fn record_collision_observation(db: &Connection, id: &str) -> Result<()> {
    db.execute("UPDATE coordinator_alert_legacy_collisions SET observations=observations+1 WHERE alert_id=?1", [id])?;
    db.execute(
        "UPDATE coordinator_alerts SET updated=CURRENT_TIMESTAMP WHERE id=?1",
        [id],
    )?;
    Ok(())
}

pub fn finish_coordinator_alert(
    db: &Connection,
    id: &str,
    state: &str,
    reason: Option<&str>,
) -> Result<()> {
    ensure!(
        matches!(state, "queued" | "ready" | "needs_attention"),
        "Invalid coordinator alert state"
    );
    db.execute(
        "UPDATE coordinator_alerts SET state=?1,reason=?2,updated=CURRENT_TIMESTAMP,
         sender_pid=NULL,sender_start=NULL WHERE id=?3 AND state='sending'",
        params![state, reason, id],
    )?;
    Ok(())
}

/// Guards reserve legacy IDs; they are never evidence of delivery.
pub fn coordinator_guard_count(db: &Connection) -> Result<i64> {
    Ok(db.query_row(
        "SELECT count(*) FROM coordinator_alerts WHERE reason=?1",
        [LEGACY_GUARD_REASON],
        |r| r.get(0),
    )?)
}

pub fn coordinator_alerts_status(db: &Connection) -> Result<Vec<CoordinatorAlert>> {
    let mut statement = db.prepare(
        "SELECT id,responsible,coordinator,state,reason,created,sender_pid,sender_start
         FROM coordinator_alerts WHERE reason IS NOT 'compatibility_guard_not_delivery' ORDER BY rowid DESC LIMIT 25",
    )?;
    let rows = statement.query_map([], |row| {
        let mut alert = CoordinatorAlert {
            id: row.get(0)?,
            responsible: row.get(1)?,
            coordinator: row.get(2)?,
            state: row.get(3)?,
            reason: row.get(4)?,
            created: row.get(5)?,
        };
        if alert.state == "sending" {
            let pid = row.get::<_, Option<i64>>(6)?;
            let started = row.get::<_, Option<i64>>(7)?;
            let sender_is_live = match (pid, started) {
                (Some(pid), Some(started)) if u32::try_from(pid).is_ok() && started >= 0 => {
                    process_start_time(pid as u32) == Some(started as u64)
                }
                _ => false,
            };
            if sender_is_live {
                alert.reason.get_or_insert_with(|| {
                    "A sender process is still alive; its delivery result is not recorded yet."
                        .into()
                });
            } else {
                alert.state = "uncertain".into();
                alert.reason = Some("The sender process is not verifiably alive; delivery may have been abandoned. Receipt is unknown, and Wake will not resend it automatically.".into());
            }
        }
        Ok(alert)
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Page through durable legacy-collision diagnostics, newest first.
pub fn coordinator_collisions(
    db: &Connection,
    after: Option<&str>,
) -> Result<(Vec<serde_json::Value>, Option<String>)> {
    let before = match after {
        Some(id) => db.query_row(
            "SELECT a.rowid FROM coordinator_alerts a JOIN coordinator_alert_legacy_collisions c ON c.alert_id=a.id WHERE a.id=?1",
            [id], |row| row.get::<_, i64>(0),
        )?,
        None => i64::MAX,
    };
    let mut stmt = db.prepare(
        "SELECT a.id,a.responsible,a.coordinator,a.message,a.state,a.reason,a.created,c.legacy_alert_id,c.observations,a.updated,old.state,old.reason,old.message,prior.state,prior.reason,prior.message,c.claim_id
         FROM coordinator_alerts a JOIN coordinator_alert_legacy_collisions c ON c.alert_id=a.id
         LEFT JOIN coordinator_alerts old ON old.id=c.legacy_alert_id
         LEFT JOIN coordinator_alerts prior ON prior.id=c.claim_id
         WHERE a.rowid<?1 ORDER BY a.rowid DESC LIMIT 11",
    )?;
    let mut rows = stmt
        .query_map([before], |r| {
            Ok(serde_json::json!({
                "alert_id":r.get::<_,String>(0)?,"responsible":r.get::<_,String>(1)?,
                "coordinator":r.get::<_,String>(2)?,"message":r.get::<_,String>(3)?,
                "state":r.get::<_,String>(4)?,"reason":r.get::<_,String>(5)?,
                "created":r.get::<_,String>(6)?,"legacy_alert_id":r.get::<_,String>(7)?,
                "observations":r.get::<_,i64>(8)?,"last_observed":r.get::<_,String>(9)?,
                "legacy_persisted_state":r.get::<_,Option<String>>(10)?,
                "legacy_reason":r.get::<_,Option<String>>(11)?,
                "legacy_message":r.get::<_,Option<String>>(12)?,
                    "prior_claim_persisted_state":r.get::<_,Option<String>>(13)?,
                    "prior_claim_reason":r.get::<_,Option<String>>(14)?,
                    "prior_claim_message":r.get::<_,Option<String>>(15)?,
                    "prior_claim_id":r.get::<_,String>(16)?
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let next = if rows.len() > 10 {
        rows.truncate(10);
        rows.last()
            .and_then(|x| x["alert_id"].as_str())
            .map(str::to_owned)
    } else {
        None
    };
    Ok((rows, next))
}

/// Page the exact pending snapshot captured when the collision was diagnosed.
pub fn coordinator_collision_items(
    db: &Connection,
    alert_id: &str,
    after: Option<&str>,
) -> Result<(Vec<Obligation>, Option<String>)> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM coordinator_alert_legacy_collisions WHERE alert_id=?1)",
        [alert_id],
        |r| r.get(0),
    )?;
    ensure!(exists, "Unknown collision alert");
    let mut stmt = db.prepare("SELECT id,thread,kind,repo,resource,outcome,description FROM coordinator_alert_collision_items WHERE alert_id=?1 AND id COLLATE BINARY>?2 ORDER BY id COLLATE BINARY LIMIT 21")?;
    let mut rows = stmt
        .query_map(params![alert_id, after.unwrap_or("")], |r| {
            Ok(Obligation {
                id: r.get(0)?,
                thread: r.get(1)?,
                kind: r.get(2)?,
                repo: r.get(3)?,
                resource: r.get(4)?,
                outcome: r.get(5)?,
                description: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let next = if rows.len() > 20 {
        rows.truncate(20);
        rows.last().map(|x| x.id.clone())
    } else {
        None
    };
    Ok((rows, next))
}

fn new_confirmation_code() -> String {
    Uuid::new_v4().simple().to_string()[..16].to_ascii_uppercase()
}

fn confirmation_code_hash(code: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hash = String::with_capacity(64);
    for byte in Sha256::digest(code.as_bytes()) {
        hash.push(HEX[(byte >> 4) as usize] as char);
        hash.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hash
}

fn transfer_notice(transfer_id: &str, code: &str) -> String {
    format!(
        "Wake: nueva propuesta de traspaso {transfer_id}. Código de confirmación: {code}. Consulta list_obligation_transfers(target_thread) para ver objetivo, estado, pruebas y siguiente paso. Acepta con accept_obligation_transfer(transfer_id, recipient_thread, confirmation_code)."
    )
}

pub fn notification_status(db: &Connection, transfer_id: &str) -> Result<NotificationStatus> {
    let transfer_id = Uuid::parse_str(transfer_id)?.to_string();
    let (state, reason) = db.query_row(
        "SELECT notification_state, notification_reason FROM obligation_transfers WHERE id=?1",
        [transfer_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
    )?;
    Ok(NotificationStatus { state, reason })
}

fn dispatch_with(
    db: &mut Connection,
    transfer_id: Option<&str>,
    send: &mut impl FnMut(&str, &str, bool) -> Result<(String, Option<String>)>,
) -> Result<usize> {
    let mut attempted = 0;
    loop {
        let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT id, target_thread, notification_message FROM obligation_transfers
                 WHERE (?1 IS NULL OR id=?1) AND state='pending' AND notification_state='ready'
                   AND (notification_reason IS NULL OR notification_reason NOT IN
                       ('executable_not_found', 'target_busy_before_send', 'target_unavailable_before_send')
                       OR notification_updated_at<=datetime('now','-15 seconds'))
                 ORDER BY rowid LIMIT 1",
                [transfer_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some((id, _, _)) = &row {
            ensure!(
                transaction.execute(
                    "UPDATE obligation_transfers SET notification_state='sending',
                        notification_reason=NULL, notification_updated_at=CURRENT_TIMESTAMP
                     WHERE id=?1 AND state='pending' AND notification_state='ready'",
                    [id],
                )? == 1,
                "Transfer notification was claimed concurrently"
            );
        }
        transaction.commit()?;
        let Some((id, thread, message)) = row else {
            return Ok(attempted);
        };

        let (state, reason) = match send(&thread, &message, true) {
            Ok((state, Some(reason)))
                if state == "queued" && reason == "resume_daemon_unavailable" =>
            {
                (
                    "needs_attention".to_owned(),
                    Some("queued_but_recipient_not_resumed".to_owned()),
                )
            }
            Ok((state, reason))
                if matches!(state.as_str(), "queued" | "ready" | "needs_attention") =>
            {
                (state, reason)
            }
            Ok(_) => (
                "needs_attention".to_owned(),
                Some("invalid_send_classification".to_owned()),
            ),
            Err(error) => match crate::execution::before_send_retry_reason(&error) {
                Some(reason) => ("ready".to_owned(), Some(reason.to_owned())),
                None => (
                    "needs_attention".to_owned(),
                    Some("send_outcome_unknown".to_owned()),
                ),
            },
        };
        db.execute(
            "UPDATE obligation_transfers SET notification_state=?1, notification_reason=?2,
                notification_updated_at=CURRENT_TIMESTAMP,
                notification_message=CASE WHEN ?1='queued' THEN NULL ELSE notification_message END
             WHERE id=?3 AND notification_state='sending'",
            params![state, reason, id],
        )?;
        crate::observability::emit(
            "obligation_transfer.notify",
            match state.as_str() {
                "queued" => "queued",
                "ready" => "ready",
                _ => "needs_attention",
            },
            reason.as_deref().unwrap_or(""),
            Some(&id),
            Duration::ZERO,
            1,
        );
        attempted += 1;
        if state == "ready" {
            return Ok(attempted);
        }
    }
}

/// Claim each durable notice once and resume the recipient; ambiguous sends are never replayed.
pub fn dispatch(db: &mut Connection, codex: &Path, timeout: Duration) -> Result<usize> {
    dispatch_with(db, None, &mut |thread, message, resume| {
        crate::bridge::send_mode(codex, timeout, thread, message, resume)
    })
}

pub fn dispatch_transfer(
    db: &mut Connection,
    transfer_id: &str,
    codex: &Path,
    timeout: Duration,
) -> Result<usize> {
    let transfer_id = Uuid::parse_str(transfer_id)?.to_string();
    dispatch_with(db, Some(&transfer_id), &mut |thread, message, resume| {
        crate::bridge::send_mode(codex, timeout, thread, message, resume)
    })
}

pub fn validate_publication_identity(kind: &str, repo: &str, resource: &str) -> Result<()> {
    ensure!(
        ["job", "chat", "dependency", "resource", "artifact"].contains(&kind),
        "Unsupported publication kind"
    );
    ensure!(
        repo.len() <= 255
            && repo
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b)),
        "Invalid namespace"
    );
    ensure!(
        !resource.is_empty()
            && resource.len() <= 255
            && resource.bytes().all(|b| b.is_ascii_graphic()),
        "Invalid resource identifier"
    );
    if kind == "chat" {
        Uuid::parse_str(resource).context("Invalid source UUID")?;
    }
    Ok(())
}

/// Create a durable proposal while leaving the obligation owned by its source chat.
#[allow(clippy::too_many_arguments)]
pub fn propose_transfer(
    db: &mut Connection,
    obligation_id: &str,
    source_thread: &str,
    target_thread: &str,
    goal: &str,
    status: &str,
    tests: &str,
    next_step: &str,
) -> Result<Transfer> {
    let obligation_id = Uuid::parse_str(obligation_id)
        .context("Invalid obligation UUID")?
        .to_string();
    let target_thread = Uuid::parse_str(target_thread)
        .context("Invalid target thread UUID")?
        .to_string();
    let source_thread = Uuid::parse_str(source_thread)
        .context("Invalid source thread UUID")?
        .to_string();
    for (label, value) in [
        ("Goal", goal),
        ("Status", status),
        ("Tests", tests),
        ("Next step", next_step),
    ] {
        ensure!(!value.trim().is_empty(), "{label} is empty");
        ensure!(
            value.len() <= MAX_DESCRIPTION_BYTES,
            "{label} exceeds 2048 bytes"
        );
    }

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let obligation = tx.query_row(
        "SELECT id, thread, kind, repo, resource, outcome, description
         FROM obligations WHERE id=?1 AND resolved=0",
        [&obligation_id],
        |row| {
            Ok(Obligation {
                id: row.get(0)?,
                thread: row.get(1)?,
                kind: row.get(2)?,
                repo: row.get(3)?,
                resource: row.get(4)?,
                outcome: row.get(5)?,
                description: row.get(6)?,
            })
        },
    )?;
    ensure!(
        obligation.thread == source_thread,
        "Only the current owner can propose a transfer"
    );
    ensure!(
        obligation.thread != target_thread,
        "Target already owns this obligation"
    );
    let id = Uuid::new_v4().to_string();
    let confirmation_code = new_confirmation_code();
    let notification_message = transfer_notice(&id, &confirmation_code);
    tx.execute(
        "INSERT INTO obligation_transfers
            (id, obligation_id, source_thread, target_thread, goal, status, tests, next_step,
             confirmation_code_hash, notification_message)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            id,
            obligation.id,
            obligation.thread,
            target_thread,
            goal,
            status,
            tests,
            next_step,
            confirmation_code_hash(&confirmation_code),
            notification_message
        ],
    )?;
    tx.commit()?;
    Ok(Transfer {
        id,
        source_thread: obligation.thread.clone(),
        target_thread,
        goal: goal.to_owned(),
        status: status.to_owned(),
        tests: tests.to_owned(),
        next_step: next_step.to_owned(),
        state: "pending".into(),
        notification_state: "ready".into(),
        notification_reason: None,
        confirmation_code,
        obligation,
    })
}

/// List proposals for the recipient; only that thread may accept them.
pub fn pending_transfers(db: &Connection, target_thread: &str) -> Result<Vec<Transfer>> {
    let target_thread = Uuid::parse_str(target_thread)
        .context("Invalid target thread UUID")?
        .to_string();
    let mut statement = db.prepare(
        "SELECT t.id, t.source_thread, t.target_thread, t.goal, t.status, t.tests,
                t.next_step, t.state, t.notification_state, t.notification_reason,
                o.id, o.thread, o.kind, o.repo, o.resource,
                o.outcome, o.description
         FROM obligation_transfers t JOIN obligations o ON o.id=t.obligation_id
         WHERE t.target_thread=?1 AND t.state='pending' AND o.resolved=0 ORDER BY t.rowid",
    )?;
    let rows = statement.query_map([target_thread], |row| {
        Ok(Transfer {
            id: row.get(0)?,
            source_thread: row.get(1)?,
            target_thread: row.get(2)?,
            goal: row.get(3)?,
            status: row.get(4)?,
            tests: row.get(5)?,
            next_step: row.get(6)?,
            state: row.get(7)?,
            notification_state: row.get(8)?,
            notification_reason: row.get(9)?,
            confirmation_code: String::new(),
            obligation: Obligation {
                id: row.get(10)?,
                thread: row.get(11)?,
                kind: row.get(12)?,
                repo: row.get(13)?,
                resource: row.get(14)?,
                outcome: row.get(15)?,
                description: row.get(16)?,
            },
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Atomically move responsibility after explicit acceptance by the proposed recipient.
pub fn accept_transfer(
    db: &mut Connection,
    transfer_id: &str,
    recipient_thread: &str,
    confirmation_code: &str,
) -> Result<Transfer> {
    let transfer_id = Uuid::parse_str(transfer_id)
        .context("Invalid transfer UUID")?
        .to_string();
    let recipient_thread = Uuid::parse_str(recipient_thread)
        .context("Invalid recipient thread UUID")?
        .to_string();
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        confirmation_code.len() == 16
            && confirmation_code
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "Invalid confirmation code"
    );
    let (
        obligation_id,
        source_thread,
        target_thread,
        goal,
        status,
        tests,
        next_step,
        notification_state,
        notification_reason,
        code_hash,
    ) = tx.query_row(
        "SELECT obligation_id, source_thread, target_thread, goal, status, tests, next_step,
                    notification_state, notification_reason, confirmation_code_hash
         FROM obligation_transfers WHERE id=?1 AND state='pending'",
        [&transfer_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        },
    )?;
    ensure!(
        target_thread == recipient_thread,
        "Only the proposed recipient can accept"
    );
    let supplied_code_hash = confirmation_code_hash(confirmation_code);
    ensure!(
        code_hash.as_deref() == Some(supplied_code_hash.as_str()),
        "Invalid confirmation code"
    );
    ensure!(
        tx.execute(
            "UPDATE obligations SET thread=?1 WHERE id=?2 AND thread=?3 AND resolved=0",
            params![target_thread, obligation_id, source_thread],
        )? == 1,
        "Obligation is no longer pending with its original owner"
    );
    tx.execute(
        "UPDATE obligation_transfers SET state='accepted', accepted_at=CURRENT_TIMESTAMP,
             notification_message=NULL
         WHERE id=?1 AND state='pending'",
        [&transfer_id],
    )?;
    let obligation = tx.query_row(
        "SELECT id, thread, kind, repo, resource, outcome, description FROM obligations WHERE id=?1",
        [&obligation_id],
        |row| Ok(Obligation {
            id: row.get(0)?, thread: row.get(1)?, kind: row.get(2)?, repo: row.get(3)?,
            resource: row.get(4)?, outcome: row.get(5)?, description: row.get(6)?,
        }),
    )?;
    tx.commit()?;
    Ok(Transfer {
        id: transfer_id,
        obligation,
        source_thread,
        target_thread,
        goal,
        status,
        tests,
        next_step,
        state: "accepted".into(),
        notification_state,
        notification_reason,
        confirmation_code: String::new(),
    })
}

fn publication_resource(kind: &str, repo: &str, resource: &str, outcome: &str) -> Result<String> {
    let valid_outcome = match kind {
        "job" => matches!(outcome, "success" | "failure" | "cancelled" | "completed"),
        "chat" => matches!(outcome, "completed" | "blocked" | "failed"),
        "dependency" => outcome == "recovered",
        "resource" => outcome == "released",
        "artifact" => outcome == "available",
        _ => false,
    };
    ensure!(valid_outcome, "Unsupported publication kind or outcome");
    validate_publication_identity(kind, repo, resource)?;
    if kind == "chat" {
        Ok(Uuid::parse_str(resource)
            .context("Invalid source UUID")?
            .to_string())
    } else {
        Ok(resource.to_owned())
    }
}

/// Register one obligation; each call creates a distinct ID.
pub fn register(
    db: &Connection,
    thread: &str,
    kind: &str,
    repo: &str,
    resource: &str,
    outcome: &str,
    description: &str,
) -> Result<String> {
    let thread = Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string();
    let resource = publication_resource(kind, repo, resource, outcome)?;
    ensure!(!description.trim().is_empty(), "Description is empty");
    ensure!(
        serde_json::to_vec(description)?.len() <= MAX_DESCRIPTION_BYTES,
        "JSON-encoded description exceeds 2048 bytes"
    );
    let id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO obligations(id, thread, kind, repo, resource, outcome, description)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, thread, kind, repo, resource, outcome, description],
    )?;
    crate::observability::emit(
        "obligation.register",
        "pending",
        "",
        Some(&id),
        std::time::Duration::ZERO,
        1,
    );
    Ok(id)
}

/// List unresolved obligations belonging to the canonical thread UUID.
pub fn pending_page(
    db: &Connection,
    thread: &str,
    after: Option<&str>,
) -> Result<(Vec<Obligation>, Option<String>)> {
    let thread = Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string();
    let cursor = if let Some(after) = after {
        let id = Uuid::parse_str(after)
            .context("Invalid cursor")?
            .to_string();
        db.query_row(
            "SELECT rowid FROM obligations WHERE id=?1 AND thread=?2",
            params![id, thread],
            |row| row.get::<_, i64>(0),
        )?
    } else {
        0
    };
    let mut statement = db.prepare(
        "SELECT id, thread, kind, repo, resource, outcome, description
         FROM obligations WHERE thread=?1 AND resolved=0 AND rowid>?2 ORDER BY rowid LIMIT 9",
    )?;
    let mut rows = statement
        .query_map(params![thread, cursor], |row| {
            Ok(Obligation {
                id: row.get(0)?,
                thread: row.get(1)?,
                kind: row.get(2)?,
                repo: row.get(3)?,
                resource: row.get(4)?,
                outcome: row.get(5)?,
                description: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let next = if rows.len() > 8 {
        rows.truncate(8);
        rows.last().map(|row| row.id.clone())
    } else {
        None
    };
    Ok((rows, next))
}

#[cfg(test)]
pub fn pending(db: &Connection, thread: &str) -> Result<Vec<Obligation>> {
    Ok(pending_page(db, thread, None)?.0)
}

pub fn pending_count(db: &Connection, thread: &str) -> Result<i64> {
    let thread = Uuid::parse_str(thread)?.to_string();
    Ok(db.query_row(
        "SELECT count(*) FROM obligations WHERE thread=?1 AND resolved=0",
        [thread],
        |row| row.get(0),
    )?)
}

/// Call only for an explicit agent publication; notification delivery does not resolve obligations.
pub fn resolve_publication(
    db: &Connection,
    kind: &str,
    repo: &str,
    resource: &str,
    outcome: &str,
) -> Result<usize> {
    let resource = publication_resource(kind, repo, resource, outcome)?;
    Ok(db.execute(
        "UPDATE obligations SET resolved=1
         WHERE kind=?1 AND repo=?2 AND resource=?3 AND resolved=0
           AND (outcome=?4 OR (?1='job' AND ?4 IN ('success','failure','cancelled') AND outcome='completed'))",
        params![kind, repo, resource, outcome],
    )?)
}

/// An agent can explicitly resolve an obligation that no longer needs publication.
pub fn resolve(db: &Connection, id: &str) -> Result<bool> {
    let id = Uuid::parse_str(id)
        .context("Invalid obligation UUID")?
        .to_string();
    let changed = db.execute(
        "UPDATE obligations SET resolved=1 WHERE id=?1 AND kind!='validation' AND resolved=0",
        [&id],
    )? == 1;
    crate::observability::emit(
        "obligation.resolve",
        if changed { "resolved" } else { "not_pending" },
        "explicit",
        Some(&id),
        std::time::Duration::ZERO,
        if changed { 1 } else { 0 },
    );
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREAD: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const OTHER: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    fn transfer_input(db: &mut Connection) -> (String, String, String) {
        let obligation = register(
            db,
            THREAD,
            "artifact",
            "ci",
            "result",
            "available",
            "Publish the report",
        )
        .unwrap();
        let transfer = propose_transfer(
            db,
            &obligation,
            THREAD,
            OTHER,
            "Finish report",
            "In progress",
            "Unit checks pending",
            "Run the focused checks",
        )
        .unwrap();
        assert!(
            !serde_json::to_string(&transfer)
                .unwrap()
                .contains(&transfer.confirmation_code)
        );
        let stored_code_hash: String = db
            .query_row(
                "SELECT confirmation_code_hash FROM obligation_transfers WHERE id=?1",
                [&transfer.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            stored_code_hash,
            confirmation_code_hash(&transfer.confirmation_code)
        );
        (obligation, transfer.id, transfer.confirmation_code)
    }

    fn notice_code(db: &Connection, thread: &str) -> String {
        let message: String = db
            .query_row(
                "SELECT notification_message FROM obligation_transfers
                 WHERE target_thread=?1 AND state='pending' ORDER BY rowid DESC LIMIT 1",
                [thread],
                |row| row.get(0),
            )
            .unwrap();
        message
            .split_once("Código de confirmación: ")
            .unwrap()
            .1
            .split('.')
            .next()
            .unwrap()
            .to_owned()
    }

    fn insert_intermediate_transfer(db: &Connection, steer_state: &str) -> (String, String) {
        let obligation_id = register(
            db,
            THREAD,
            "artifact",
            "ci",
            "legacy-result",
            "available",
            "Publish the report",
        )
        .unwrap();
        let transfer_id = Uuid::new_v4().to_string();
        let code = new_confirmation_code();
        db.execute(
            "INSERT INTO obligation_transfers
                (id, obligation_id, source_thread, target_thread, goal, status, tests,
                 next_step, confirmation_code_hash)
             VALUES (?1, ?2, ?3, ?4, 'Finish report', 'In progress', 'Checks pending',
                     'Run focused checks', ?5)",
            params![
                transfer_id,
                obligation_id,
                THREAD,
                OTHER,
                confirmation_code_hash(&code)
            ],
        )
        .unwrap();
        let notice = transfer_notice(&transfer_id, &code);
        let queued = crate::steer::enqueue(db, OTHER, &notice).unwrap();
        if steer_state != "pending" {
            db.execute(
                "UPDATE steers SET state=?1 WHERE id=?2",
                params![steer_state, queued["steer_id"].as_str().unwrap()],
            )
            .unwrap();
        }
        (transfer_id, code)
    }

    #[test]
    fn pagination_reaches_every_pending_obligation() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        for n in 0..12 {
            register(
                &db,
                THREAD,
                "artifact",
                "ci",
                &format!("item-{n}"),
                "available",
                "result",
            )
            .unwrap();
        }
        let (first, cursor) = pending_page(&db, THREAD, None).unwrap();
        assert_eq!(first.len(), 8);
        resolve(&db, cursor.as_deref().unwrap()).unwrap();
        let (last, next) = pending_page(&db, THREAD, cursor.as_deref()).unwrap();
        assert_eq!(last.len(), 4);
        assert!(next.is_none());
        assert!(pending_page(&db, OTHER, cursor.as_deref()).is_err());
    }

    #[test]
    fn persists_and_resolves_only_exact_publications() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        initialize(&db).unwrap();
        let id = register(
            &db,
            &THREAD.to_uppercase(),
            "job",
            "a/b",
            "run",
            "success",
            "first",
        )
        .unwrap();
        register(&db, OTHER, "job", "a/b", "run", "success", "second").unwrap();
        register(
            &db,
            THREAD,
            "job",
            "a/b",
            "run",
            "failure",
            "different outcome",
        )
        .unwrap();
        register(
            &db,
            THREAD,
            "job",
            "a/b",
            "other",
            "success",
            "different resource",
        )
        .unwrap();
        register(
            &db,
            THREAD,
            "job",
            "c/d",
            "run",
            "success",
            "different repo",
        )
        .unwrap();
        register(
            &db,
            THREAD,
            "artifact",
            "a/b",
            "run",
            "available",
            "different kind",
        )
        .unwrap();
        assert_eq!(pending(&db, THREAD).unwrap()[0].id, id);
        drop(db);
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            resolve_publication(&db, "job", "a/b", "run", "success").unwrap(),
            2
        );
        assert_eq!(
            resolve_publication(&db, "job", "a/b", "run", "success").unwrap(),
            0
        );
        assert_eq!(pending(&db, THREAD).unwrap().len(), 4);
        assert!(pending(&db, OTHER).unwrap().is_empty());
    }

    #[test]
    fn canonicalizes_source_and_destination_uuids() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        register(
            &db,
            &THREAD.to_uppercase(),
            "chat",
            "",
            &OTHER.to_uppercase(),
            "completed",
            "result",
        )
        .unwrap();
        let record = pending(&db, THREAD).unwrap().remove(0);
        assert_eq!(record.thread, THREAD);
        assert_eq!(record.resource, OTHER);
        assert_eq!(
            resolve_publication(&db, "chat", "", OTHER, "completed").unwrap(),
            1
        );
    }

    #[test]
    fn rejects_invalid_input_without_changing_obligations() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        for (thread, kind, repo, resource, outcome, description) in [
            ("invalid", "job", "", "r", "success", "ok"),
            (THREAD, "unknown", "", "r", "success", "ok"),
            (THREAD, "job", "bad repo", "r", "success", "ok"),
            (THREAD, "job", "", "", "success", "ok"),
            (THREAD, "chat", "", "invalid", "completed", "ok"),
            (THREAD, "job", "", "r", "unknown", "ok"),
            (THREAD, "job", "", "r", "success", "  "),
        ] {
            assert!(register(&db, thread, kind, repo, resource, outcome, description).is_err());
        }
        assert!(register(&db, THREAD, "job", "", "r", "success", &"é".repeat(1025)).is_err());
        assert!(pending(&db, "invalid").is_err());
        assert!(resolve_publication(&db, "job", "", "r", "invalid").is_err());
        assert!(pending(&db, THREAD).unwrap().is_empty());
    }

    #[test]
    fn delivery_state_does_not_resolve_obligations() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        db.execute_batch(
            "CREATE TABLE deliveries (state TEXT); INSERT INTO deliveries VALUES ('queued');",
        )
        .unwrap();
        register(
            &db,
            THREAD,
            "resource",
            "",
            "lock",
            "released",
            "release lock",
        )
        .unwrap();
        db.execute("UPDATE deliveries SET state='needs_attention'", [])
            .unwrap();
        assert_eq!(pending(&db, THREAD).unwrap().len(), 1);
        assert_eq!(
            resolve_publication(&db, "resource", "", "lock", "released").unwrap(),
            1
        );
        let state: String = db
            .query_row("SELECT state FROM deliveries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state, "needs_attention");
    }

    #[test]
    fn proposal_keeps_original_owner_until_recipient_accepts_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let mut db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        let (obligation_id, transfer_id, confirmation_code) = transfer_input(&mut db);
        assert_eq!(pending(&db, THREAD).unwrap()[0].id, obligation_id);
        assert!(pending(&db, OTHER).unwrap().is_empty());
        assert_eq!(pending_transfers(&db, OTHER).unwrap()[0].id, transfer_id);
        assert_eq!(notice_code(&db, OTHER), confirmation_code);
        assert!(accept_transfer(&mut db, &transfer_id, OTHER, "BADBADBADBADBADB").is_err());
        assert_eq!(pending(&db, THREAD).unwrap()[0].id, obligation_id);
        assert!(
            propose_transfer(
                &mut db,
                &obligation_id,
                OTHER,
                THREAD,
                "Wrong owner",
                "In progress",
                "Not run",
                "Continue",
            )
            .is_err()
        );
        assert!(accept_transfer(&mut db, &transfer_id, THREAD, &confirmation_code).is_err());
        drop(db);

        let mut db = Connection::open(path).unwrap();
        initialize(&db).unwrap();
        assert_eq!(notice_code(&db, OTHER), confirmation_code);
        let accepted = accept_transfer(&mut db, &transfer_id, OTHER, &confirmation_code).unwrap();
        assert_eq!(accepted.state, "accepted");
        assert_eq!(accepted.goal, "Finish report");
        assert_eq!(accepted.status, "In progress");
        assert_eq!(accepted.tests, "Unit checks pending");
        assert_eq!(accepted.next_step, "Run the focused checks");
        assert!(pending(&db, THREAD).unwrap().is_empty());
        assert_eq!(pending(&db, OTHER).unwrap()[0].id, obligation_id);
        assert!(pending_transfers(&db, OTHER).unwrap().is_empty());
        assert!(accept_transfer(&mut db, &transfer_id, OTHER, &confirmation_code).is_err());
    }

    #[test]
    fn upgrading_legacy_pending_transfer_adds_code_notice_without_changing_owner() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE obligations (
                id TEXT PRIMARY KEY, thread TEXT NOT NULL, kind TEXT NOT NULL,
                repo TEXT NOT NULL, resource TEXT NOT NULL, outcome TEXT NOT NULL,
                description TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO obligations VALUES
                ('cccccccc-cccc-4ccc-8ccc-cccccccccccc',
                 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'artifact', 'ci', 'result',
                 'available', 'Publish the report', 0);
            CREATE TABLE obligation_transfers (
                id TEXT PRIMARY KEY, obligation_id TEXT NOT NULL,
                source_thread TEXT NOT NULL, target_thread TEXT NOT NULL,
                goal TEXT NOT NULL, status TEXT NOT NULL, tests TEXT NOT NULL,
                next_step TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, accepted_at TEXT
            );
            INSERT INTO obligation_transfers
                (id, obligation_id, source_thread, target_thread, goal, status, tests, next_step)
            VALUES
                ('dddddddd-dddd-4ddd-8ddd-dddddddddddd',
                 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
                 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
                 'Finish report', 'In progress', 'Checks pending', 'Run focused checks');",
        )
        .unwrap();

        initialize(&db).unwrap();
        initialize(&db).unwrap();
        let code = notice_code(&db, OTHER);
        let notice_count: i64 = db
            .query_row(
                "SELECT count(*) FROM obligation_transfers
                 WHERE target_thread=?1 AND state='pending' AND notification_message IS NOT NULL",
                [OTHER],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(notice_count, 1);
        assert_eq!(
            notification_status(&db, "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
                .unwrap()
                .state,
            "ready"
        );
        assert_eq!(
            pending(&db, THREAD).unwrap()[0].id,
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        );
        assert_eq!(pending_transfers(&db, OTHER).unwrap().len(), 1);
        let accepted = accept_transfer(
            &mut db,
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            OTHER,
            &code,
        )
        .unwrap();
        assert_eq!(accepted.state, "accepted");
        assert_eq!(
            pending(&db, OTHER).unwrap()[0].id,
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        );
    }

    #[test]
    fn failed_transfer_insert_preserves_original_owner() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let obligation_id = register(
            &db,
            THREAD,
            "artifact",
            "ci",
            "result",
            "available",
            "Publish the report",
        )
        .unwrap();
        db.execute_batch(
            "CREATE TRIGGER reject_transfer_insert BEFORE INSERT ON obligation_transfers
             BEGIN SELECT RAISE(ABORT, 'transfer insert rejected'); END;",
        )
        .unwrap();
        assert!(
            propose_transfer(
                &mut db,
                &obligation_id,
                THREAD,
                OTHER,
                "Finish report",
                "In progress",
                "Checks pending",
                "Run focused checks",
            )
            .is_err()
        );
        assert_eq!(pending(&db, THREAD).unwrap()[0].id, obligation_id);
        assert!(pending_transfers(&db, OTHER).unwrap().is_empty());
    }

    #[test]
    fn durable_notification_resumes_idle_recipient_and_is_not_repeated_after_queue_ack() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let (obligation_id, transfer_id, confirmation_code) = transfer_input(&mut db);
        let mut calls = 0;
        let attempted = dispatch_with(&mut db, None, &mut |thread, message, resume| {
            calls += 1;
            assert_eq!(thread, OTHER);
            assert!(resume, "idle and notLoaded recipients must be resumed");
            assert!(message.contains(&confirmation_code));
            Ok(("queued".into(), Some("native_queue_accepted".into())))
        })
        .unwrap();
        assert_eq!(attempted, 1);
        assert_eq!(calls, 1);
        assert_eq!(
            notification_status(&db, &transfer_id).unwrap().state,
            "queued"
        );
        let message: Option<String> = db
            .query_row(
                "SELECT notification_message FROM obligation_transfers WHERE id=?1",
                [&transfer_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(message.is_none());
        assert_eq!(pending(&db, THREAD).unwrap()[0].id, obligation_id);
        initialize(&db).unwrap();
        assert_eq!(
            notification_status(&db, &transfer_id).unwrap().state,
            "queued"
        );
        assert_eq!(
            dispatch_with(&mut db, None, &mut |_, _, _| panic!("must not resend")).unwrap(),
            0
        );
    }

    #[test]
    fn uncertain_notification_is_needs_attention_and_never_retried() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let (obligation_id, transfer_id, _) = transfer_input(&mut db);
        assert_eq!(
            dispatch_with(&mut db, None, &mut |_, _, _| {
                Ok((
                    "needs_attention".into(),
                    Some("timeout_delivery_unknown".into()),
                ))
            })
            .unwrap(),
            1
        );
        assert_eq!(
            notification_status(&db, &transfer_id).unwrap().state,
            "needs_attention"
        );
        assert_eq!(pending(&db, THREAD).unwrap()[0].id, obligation_id);
        assert_eq!(
            dispatch_with(&mut db, None, &mut |_, _, _| panic!("must not resend")).unwrap(),
            0
        );
    }

    #[test]
    fn accepted_queue_without_resume_is_visible_and_not_sent_again() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let (obligation_id, transfer_id, _) = transfer_input(&mut db);
        assert_eq!(
            dispatch_with(&mut db, None, &mut |_, _, resume| {
                assert!(resume);
                Ok(("queued".into(), Some("resume_daemon_unavailable".into())))
            })
            .unwrap(),
            1
        );
        assert_eq!(
            notification_status(&db, &transfer_id).unwrap(),
            NotificationStatus {
                state: "needs_attention".into(),
                reason: Some("queued_but_recipient_not_resumed".into()),
            }
        );
        assert_eq!(pending(&db, THREAD).unwrap()[0].id, obligation_id);
        assert_eq!(
            dispatch_with(&mut db, None, &mut |_, _, _| panic!("must not resend")).unwrap(),
            0
        );
    }

    #[test]
    fn interrupted_sending_notice_is_not_retried() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let (_, transfer_id, _) = transfer_input(&mut db);
        db.execute(
            "UPDATE obligation_transfers SET notification_state='sending'
             WHERE id=?1",
            [&transfer_id],
        )
        .unwrap();
        assert_eq!(
            dispatch_with(&mut db, None, &mut |_, _, _| panic!("must not resend")).unwrap(),
            0
        );
        assert_eq!(
            notification_status(&db, &transfer_id).unwrap().state,
            "sending"
        );
    }

    #[test]
    fn pending_hook_notice_migrates_to_resuming_delivery_without_duplicate() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let (transfer_id, code) = insert_intermediate_transfer(&db, "pending");
        initialize(&db).unwrap();
        assert_eq!(
            notification_status(&db, &transfer_id).unwrap().state,
            "ready"
        );
        let old_pending: i64 = db
            .query_row(
                "SELECT count(*) FROM steers WHERE thread=?1 AND state='pending'",
                [OTHER],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_pending, 0);
        assert_eq!(notice_code(&db, OTHER), code);
        assert_eq!(
            dispatch_with(&mut db, None, &mut |thread, message, resume| {
                assert_eq!(thread, OTHER);
                assert!(resume);
                assert!(message.contains(&code));
                Ok(("queued".into(), None))
            })
            .unwrap(),
            1
        );
    }

    #[test]
    fn claimed_legacy_hook_notice_is_not_sent_again() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let (transfer_id, _) = insert_intermediate_transfer(&db, "claimed");
        initialize(&db).unwrap();
        assert_eq!(
            notification_status(&db, &transfer_id).unwrap().state,
            "needs_attention"
        );
        assert_eq!(
            dispatch_with(&mut db, None, &mut |_, _, _| panic!("must not resend")).unwrap(),
            0
        );
    }

    #[test]
    fn concurrent_acceptance_transfers_responsibility_once() {
        use std::{
            sync::{Arc, Barrier},
            thread,
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let mut db = Connection::open(&path).unwrap();
        db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        initialize(&db).unwrap();
        let (obligation_id, transfer_id, confirmation_code) = transfer_input(&mut db);
        drop(db);

        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let transfer_id = transfer_id.clone();
                let confirmation_code = confirmation_code.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut db = Connection::open(path).unwrap();
                    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                    barrier.wait();
                    accept_transfer(&mut db, &transfer_id, OTHER, &confirmation_code).is_ok()
                })
            })
            .collect();
        let accepted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(accepted, 1);

        let db = Connection::open(path).unwrap();
        assert!(pending(&db, THREAD).unwrap().is_empty());
        assert_eq!(pending(&db, OTHER).unwrap()[0].id, obligation_id);
        assert_eq!(pending_transfers(&db, OTHER).unwrap().len(), 0);
    }

    #[test]
    fn coordinator_alert_is_persisted_and_never_reclaimed_after_uncertain_send() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        register_coordinator(&db, THREAD, OTHER).unwrap();
        let claimed = claim_coordinator_alert(&db, THREAD, "turn-1", "pending check: smoke")
            .unwrap()
            .unwrap();
        assert_eq!(claimed.1, OTHER);
        finish_coordinator_alert(&db, &claimed.0, "needs_attention", Some("timeout")).unwrap();
        drop(db);

        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        assert!(
            claim_coordinator_alert(&db, THREAD, "turn-1", "pending check: smoke")
                .unwrap()
                .is_none()
        );
        let saved: (String, String, String) = db
            .query_row(
                "SELECT message,state,reason FROM coordinator_alerts WHERE id=?1",
                [&claimed.0],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            saved,
            (
                "pending check: smoke".into(),
                "needs_attention".into(),
                "timeout".into()
            )
        );
    }

    #[test]
    fn coordinator_registration_is_explicit_idempotent_and_cannot_self_target() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        assert!(
            claim_coordinator_alert(&db, THREAD, "turn-1", "alert")
                .unwrap()
                .is_none()
        );
        assert!(register_coordinator(&db, THREAD, THREAD).is_err());
        register_coordinator(&db, THREAD, OTHER).unwrap();
        register_coordinator(&db, &THREAD.to_uppercase(), &OTHER.to_uppercase()).unwrap();
        assert_eq!(
            claim_coordinator_alert(&db, THREAD, "turn-1", "alert")
                .unwrap()
                .unwrap()
                .1,
            OTHER
        );
    }

    #[test]
    fn abandoned_sending_alert_is_reported_uncertain_without_mutation_or_replay() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        register_coordinator(&db, THREAD, OTHER).unwrap();
        let (id, _) = claim_coordinator_alert(&db, THREAD, "turn-uncertain", "pending check")
            .unwrap()
            .unwrap();

        let live = coordinator_alerts_status(&db).unwrap();
        assert_eq!(live[0].state, "sending");

        db.execute(
            "UPDATE coordinator_alerts SET sender_pid=?1,sender_start=?2 WHERE id=?3",
            params![i64::MAX, 0, id],
        )
        .unwrap();
        let uncertain = coordinator_alerts_status(&db).unwrap();
        assert_eq!(uncertain[0].state, "uncertain");
        assert!(
            uncertain[0]
                .reason
                .as_deref()
                .unwrap()
                .contains("may have been abandoned")
        );
        assert!(
            uncertain[0]
                .reason
                .as_deref()
                .unwrap()
                .contains("will not resend")
        );
        assert!(
            claim_coordinator_alert(&db, THREAD, "turn-uncertain", "pending check")
                .unwrap()
                .is_none()
        );

        let persisted: (String, Option<String>) = db
            .query_row(
                "SELECT state,reason FROM coordinator_alerts WHERE id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(persisted, ("sending".into(), None));
    }

    #[test]
    fn pre_identity_sending_rows_migrate_to_read_only_uncertain_status() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE coordinator_alerts (
                id TEXT PRIMARY KEY,responsible TEXT NOT NULL,coordinator TEXT NOT NULL,
                message TEXT NOT NULL,state TEXT NOT NULL,reason TEXT,
                created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO coordinator_alerts(id,responsible,coordinator,message,state)
            VALUES ('legacy','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','pending','sending');",
        )
        .unwrap();

        initialize(&db).unwrap();
        let alerts = coordinator_alerts_status(&db).unwrap();
        assert_eq!(alerts[0].state, "uncertain");
        assert!(
            alerts[0]
                .reason
                .as_deref()
                .unwrap()
                .contains("delivery may have been abandoned")
        );
        let persisted: String = db
            .query_row(
                "SELECT state FROM coordinator_alerts WHERE id='legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, "sending");
    }
}

#[cfg(test)]
mod full_snapshot_tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    const OWNER: &str = "11111111-1111-4111-8111-111111111111";
    const COORDINATOR: &str = "22222222-2222-4222-8222-222222222222";

    #[test]
    fn digest_is_independent_of_insert_order_and_includes_changed_content() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let insert = |id: &str| {
            db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES(?1,?2,'artifact','repo','resource','available','pending')", params![id, OWNER]).unwrap()
        };
        insert("b");
        insert("a");
        let before = pending_digest(&db, OWNER).unwrap();
        db.execute("DELETE FROM obligations", []).unwrap();
        insert("a");
        insert("b");
        assert_eq!(before, pending_digest(&db, OWNER).unwrap());
        db.execute(
            "UPDATE obligations SET description='changed' WHERE id='b'",
            [],
        )
        .unwrap();
        assert_ne!(before, pending_digest(&db, OWNER).unwrap());
        db.execute("UPDATE obligations SET resolved=1 WHERE id='b'", [])
            .unwrap();
        assert_eq!(pending_digest(&db, OWNER).unwrap().0, 1);
    }

    #[test]
    fn snapshot_and_claim_serialize_with_modification_and_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let db = Connection::open(&path).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        initialize(&db).unwrap();
        register_coordinator(&db, OWNER, COORDINATOR).unwrap();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('a',?1,'artifact','repo','resource','available','pending')", [OWNER]).unwrap();
        for sql in [
            "UPDATE obligations SET description='changed' WHERE id='a'",
            "UPDATE obligations SET resolved=1 WHERE id='a'",
        ] {
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            let before = pending_digest(&tx, OWNER).unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let path = path.clone();
            let worker = thread::spawn(move || {
                let other = Connection::open(path).unwrap();
                other.busy_timeout(Duration::from_secs(5)).unwrap();
                started_tx.send(()).unwrap();
                other.execute(sql, []).unwrap();
                done_tx.send(()).unwrap();
            });
            started_rx.recv().unwrap();
            assert!(matches!(
                done_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            assert_eq!(before, pending_digest(&tx, OWNER).unwrap());
            let fingerprint = format!("snapshot-{}", before.1);
            assert!(
                claim_coordinator_alert_with_legacy(&tx, OWNER, &fingerprint, "snapshot", None)
                    .unwrap()
                    .is_some()
            );
            tx.commit().unwrap();
            done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            worker.join().unwrap();
            assert_ne!(before, pending_digest(&db, OWNER).unwrap());
        }
        assert_eq!(pending_digest(&db, OWNER).unwrap().0, 0);
    }
}

#[cfg(test)]
mod legacy_collision_tests {
    use super::*;
    const OWNER: &str = "11111111-1111-4111-8111-111111111111";
    const COORDINATOR: &str = "22222222-2222-4222-8222-222222222222";

    fn fixture() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        register_coordinator(&db, OWNER, COORDINATOR).unwrap();
        claim_coordinator_alert(&db, OWNER, "legacy", "old")
            .unwrap()
            .unwrap();
        db
    }

    #[test]
    fn collisions_and_snapshots_are_discoverable_beyond_status_limit() {
        let db = fixture();
        for n in 0..25 {
            db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES(?1,?2,'artifact','repo','resource','available','pending')", params![format!("item-{n:02}"), OWNER]).unwrap();
        }
        for n in 0..26 {
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            let result = claim_coordinator_alert_with_legacy(
                &tx,
                OWNER,
                &format!("new-{n}"),
                "snapshot",
                Some("legacy"),
            )
            .unwrap()
            .unwrap();
            assert!(result.2);
            tx.commit().unwrap();
        }
        let mut cursor = None;
        let mut found = Vec::new();
        loop {
            let (rows, next) = coordinator_collisions(&db, cursor.as_deref()).unwrap();
            found.extend(rows);
            if next.is_none() {
                break;
            }
            cursor = next;
        }
        assert_eq!(found.len(), 26);
        let id = found[0]["alert_id"].as_str().unwrap();
        let (first, next) = coordinator_collision_items(&db, id, None).unwrap();
        let (second, end) = coordinator_collision_items(&db, id, next.as_deref()).unwrap();
        assert_eq!((first.len(), second.len()), (20, 5));
        assert!(end.is_none());
        assert!(coordinator_collision_items(&db, "unknown", None).is_err());
    }

    #[test]
    fn failed_snapshot_insert_rolls_back_collision_record() {
        let db = fixture();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('item',?1,'artifact','repo','resource','available','pending')", [OWNER]).unwrap();
        db.execute_batch("CREATE TRIGGER fail_collision BEFORE INSERT ON coordinator_alert_collision_items BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").unwrap();
        {
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            assert!(
                claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                    .is_err()
            );
        }
        let count: i64 = db
            .query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r.get(0))
            .unwrap();
        let collisions: i64 = db
            .query_row(
                "SELECT count(*) FROM coordinator_alert_legacy_collisions",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!((count, collisions), (1, 0));
    }
}

#[cfg(test)]
mod mixed_alert_version_tests {
    use super::*;
    const OWNER: &str = "11111111-1111-4111-8111-111111111111";
    const COORDINATOR: &str = "22222222-2222-4222-8222-222222222222";

    #[test]
    fn existing_new_claim_does_not_hide_collision_or_change_send_state() {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        register_coordinator(&db, OWNER, COORDINATOR).unwrap();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('item',?1,'artifact','repo','resource','available','pending')", [OWNER]).unwrap();
        let (new_id, _) = claim_coordinator_alert(&db, OWNER, "new", "new message")
            .unwrap()
            .unwrap();
        finish_coordinator_alert(&db, &new_id, "queued", None).unwrap();
        let (old_id, _) = claim_coordinator_alert(&db, OWNER, "legacy", "old message")
            .unwrap()
            .unwrap();
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        let (diagnostic_id, _, collision) =
            claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                .unwrap()
                .unwrap();
        assert!(collision);
        assert_ne!(diagnostic_id, new_id);
        tx.commit().unwrap();
        let state: String = db
            .query_row(
                "SELECT state FROM coordinator_alerts WHERE id=?1",
                [&new_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "queued");
        let (rows, _) = coordinator_collisions(&db, None).unwrap();
        assert_eq!(rows[0]["prior_claim_persisted_state"], "queued");
        assert_eq!(rows[0]["prior_claim_message"], "new message");
        db.execute("DELETE FROM coordinator_alerts WHERE id=?1", [&old_id])
            .unwrap();
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        let (again, _, collision) =
            claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                .unwrap()
                .unwrap();
        assert!(collision);
        assert_eq!(again, diagnostic_id);
        tx.commit().unwrap();
        let observations: i64 = db
            .query_row(
                "SELECT observations FROM coordinator_alert_legacy_collisions WHERE alert_id=?1",
                [&diagnostic_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(observations, 2);
    }

    #[test]
    fn initial_collision_schema_migrates_existing_claim_identity() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE coordinator_alert_legacy_collisions(alert_id TEXT PRIMARY KEY,legacy_alert_id TEXT NOT NULL,observations INTEGER NOT NULL DEFAULT 1); INSERT INTO coordinator_alert_legacy_collisions(alert_id,legacy_alert_id) VALUES('prior','old');").unwrap();
        initialize(&db).unwrap();
        let claim: String = db
            .query_row(
                "SELECT claim_id FROM coordinator_alert_legacy_collisions WHERE alert_id='prior'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(claim, "prior");
        db.execute(
            "UPDATE coordinator_alert_legacy_collisions SET claim_id=NULL WHERE alert_id='prior'",
            [],
        )
        .unwrap();
        initialize(&db).unwrap();
        let recovered: String = db
            .query_row(
                "SELECT claim_id FROM coordinator_alert_legacy_collisions WHERE alert_id='prior'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(recovered, "prior");
    }
    #[test]
    fn concurrent_startups_serialize_collision_schema_migration() {
        use std::sync::{Arc, Barrier};
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        db.execute_batch("DROP TABLE coordinator_alert_legacy_collisions; CREATE TABLE coordinator_alert_legacy_collisions(alert_id TEXT PRIMARY KEY,legacy_alert_id TEXT NOT NULL,observations INTEGER NOT NULL DEFAULT 1); INSERT INTO coordinator_alert_legacy_collisions(alert_id,legacy_alert_id) VALUES('prior','old');").unwrap();
        drop(db);
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let db = Connection::open(path).unwrap();
                    db.busy_timeout(Duration::from_secs(5)).unwrap();
                    barrier.wait();
                    initialize(&db)
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        let db = Connection::open(path).unwrap();
        let claim: String = db
            .query_row(
                "SELECT claim_id FROM coordinator_alert_legacy_collisions WHERE alert_id='prior'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(claim, "prior");
    }
}

#[cfg(test)]
mod legacy_guard_tests {
    use super::*;
    const OWNER: &str = "11111111-1111-4111-8111-111111111111";
    const COORDINATOR: &str = "22222222-2222-4222-8222-222222222222";

    fn fixture() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        register_coordinator(&db, OWNER, COORDINATOR).unwrap();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('one',?1,'artifact','repo','resource','available','pending')", [OWNER]).unwrap();
        db
    }
    fn legacy_id(fingerprint: &str) -> String {
        format!(
            "{:x}",
            Sha256::digest(format!("{OWNER}:{COORDINATOR}:{fingerprint}").as_bytes())
        )
    }
    fn old_claim(db: &Connection, fingerprint: &str) -> usize {
        db.execute("INSERT OR IGNORE INTO coordinator_alerts(id,responsible,coordinator,message,state) VALUES(?1,?2,?3,'old','sending')", params![legacy_id(fingerprint),OWNER,COORDINATOR]).unwrap()
    }
    #[test]
    fn guard_blocks_old_claim_and_new_snapshots_reuse_it() {
        let db = fixture();
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        let (new_id, _, collision) =
            claim_coordinator_alert_with_legacy(&tx, OWNER, "new-a", "snapshot", Some("legacy"))
                .unwrap()
                .unwrap();
        assert!(!collision);
        tx.commit().unwrap();
        assert_eq!(old_claim(&db, "legacy"), 0);
        let guard: (String, String, String) = db
            .query_row(
                "SELECT state,reason,message FROM coordinator_alerts WHERE id=?1",
                [legacy_id("legacy")],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(guard.0, "needs_attention");
        assert_eq!(guard.1, LEGACY_GUARD_REASON);
        assert!(guard.2.contains("no delivery was attempted"));
        assert_eq!(coordinator_guard_count(&db).unwrap(), 1);
        let status = coordinator_alerts_status(&db).unwrap();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].id, new_id);
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        let (_, _, collision) =
            claim_coordinator_alert_with_legacy(&tx, OWNER, "new-b", "changed", Some("legacy"))
                .unwrap()
                .unwrap();
        assert!(!collision);
        tx.commit().unwrap();
        assert_eq!(old_claim(&db, "legacy"), 0);
    }
    #[test]
    fn legacy_first_is_diagnostic_not_a_guard_or_send() {
        let db = fixture();
        assert_eq!(old_claim(&db, "legacy"), 1);
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        let (id, _, collision) =
            claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                .unwrap()
                .unwrap();
        assert!(collision);
        tx.commit().unwrap();
        assert_eq!(coordinator_guard_count(&db).unwrap(), 0);
        let state: String = db
            .query_row(
                "SELECT state FROM coordinator_alerts WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "needs_attention");
    }
    #[test]
    fn rollback_and_restart_never_turn_guard_into_a_verified_delivery() {
        let db = fixture();
        {
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                .unwrap()
                .unwrap();
        }
        assert_eq!(coordinator_guard_count(&db).unwrap(), 0);
        assert_eq!(
            db.query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        let (id, _, _) =
            claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                .unwrap()
                .unwrap();
        tx.commit().unwrap();
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        assert!(
            claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                .unwrap()
                .is_none()
        );
        tx.commit().unwrap();
        assert_eq!(old_claim(&db, "legacy"), 0);
        let state: String = db
            .query_row(
                "SELECT state FROM coordinator_alerts WHERE id=?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "sending");
    }
    #[test]
    fn failed_new_claim_rolls_back_legacy_guard() {
        let db = fixture();
        db.execute_batch("CREATE TRIGGER fail_new_claim BEFORE INSERT ON coordinator_alerts WHEN NEW.state='sending' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        {
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            assert!(
                claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                    .is_err()
            );
        }
        let rows: i64 = db
            .query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn stale_legacy_snapshot_can_still_claim_a_different_key() {
        let db = fixture();
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "new snapshot", Some("legacy-b"))
            .unwrap()
            .unwrap();
        tx.commit().unwrap();
        assert_eq!(old_claim(&db, "legacy-a"), 1);
    }
    #[test]
    fn simultaneous_claims_allow_only_one_sender_for_the_same_legacy_key() {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        register_coordinator(&db, OWNER, COORDINATOR).unwrap();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('one',?1,'artifact','repo','resource','available','pending')", [OWNER]).unwrap();
        drop(db);
        let barrier = Arc::new(Barrier::new(2));
        let old_path = path.clone();
        let old_barrier = barrier.clone();
        let old = std::thread::spawn(move || {
            let db = Connection::open(old_path).unwrap();
            db.busy_timeout(Duration::from_secs(5)).unwrap();
            old_barrier.wait();
            old_claim(&db, "legacy")
        });
        let new = std::thread::spawn(move || {
            let db = Connection::open(path).unwrap();
            db.busy_timeout(Duration::from_secs(5)).unwrap();
            barrier.wait();
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            let result =
                claim_coordinator_alert_with_legacy(&tx, OWNER, "new", "snapshot", Some("legacy"))
                    .unwrap()
                    .unwrap();
            tx.commit().unwrap();
            !result.2
        });
        let old_sent = old.join().unwrap();
        let new_sent = usize::from(new.join().unwrap());
        assert_eq!(old_sent + new_sent, 1);
    }
}
