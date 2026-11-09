//! Persistent obligations, independent of notification delivery state.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use uuid::Uuid;

const MAX_DESCRIPTION_BYTES: usize = 2048;
pub(crate) const COORDINATOR_ALERT_READY_REASON: &str = "interrupt_ready_v1";

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
        CREATE TABLE IF NOT EXISTS obligation_reviews (
            thread TEXT PRIMARY KEY,
            digest TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS obligation_review_events (
            fingerprint TEXT NOT NULL,
            obligation_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            repo TEXT NOT NULL,
            resource TEXT NOT NULL,
            outcome TEXT NOT NULL,
            scope TEXT,
            execution_id TEXT,
            attempt TEXT,
            PRIMARY KEY(fingerprint,obligation_id)
        );
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

pub(crate) fn process_start_time(pid: u32) -> Option<u64> {
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

/// Snapshot pending work and observable results for the responsible chat.
pub fn review_digest(db: &Connection, thread: &str) -> Result<(i64, String)> {
    let thread = Uuid::parse_str(thread)?.to_string();
    let (count, pending) = pending_digest(db, &thread)?;
    let mut hash = Sha256::new();
    hash.update(pending.as_bytes());
    let mut stmt = db.prepare(
        "SELECT s.id,coalesce(s.outcome,''),coalesce(s.source_event_key,''),CASE WHEN s.state='needs_attention' THEN coalesce(s.reason,'needs_attention') ELSE '' END FROM subscriptions s
         WHERE s.thread=?1 AND s.state!='waiting' AND EXISTS (
           SELECT 1 FROM obligations o LEFT JOIN validation_scope_links l ON l.obligation_id=o.id
           WHERE o.thread=s.thread AND o.resolved=0 AND
             ((o.kind=s.kind AND o.repo=s.repo AND o.resource=s.resource) OR
              (l.kind=s.kind AND l.repo=s.repo AND (l.resource=s.resource OR (l.kind='chat' AND l.resource COLLATE NOCASE=s.resource)))))
         ORDER BY s.id COLLATE BINARY",
    )?;
    let mut rows = stmt.query([&thread])?;
    while let Some(row) = rows.next()? {
        for i in 0..4 {
            let value: String = row.get(i)?;
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
    }
    let mut stmt = db.prepare(
        "SELECT w.repo,CAST(w.run_id AS TEXT),CAST(w.attempt AS TEXT),w.conclusion,
         CASE WHEN w.state='needs_attention' THEN coalesce(w.reason,'needs_attention') ELSE '' END FROM waits w
         WHERE w.thread=?1 AND w.conclusion IS NOT NULL AND EXISTS (
         SELECT 1 FROM obligations o LEFT JOIN validation_scope_links l ON l.obligation_id=o.id
         WHERE o.thread=w.thread AND o.resolved=0 AND
         ((o.kind='job' AND o.repo=w.repo AND o.resource=CAST(w.run_id AS TEXT)) OR
         (l.kind='job' AND l.repo=w.repo AND l.resource=CAST(w.run_id AS TEXT)) OR
         (o.kind='validation' AND l.obligation_id IS NULL)))
         ORDER BY w.repo,w.run_id,w.attempt",
    )?;
    let mut rows = stmt.query([&thread])?;
    while let Some(row) = rows.next()? {
        for i in 0..5 {
            let value: String = row.get(i)?;
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
    }
    let mut stmt = db.prepare(
        "SELECT l.obligation_id,l.kind,l.repo,l.resource,l.scope FROM validation_scope_links l
         JOIN obligations o ON o.id=l.obligation_id WHERE o.thread=?1 AND o.resolved=0
         ORDER BY l.obligation_id COLLATE BINARY",
    )?;
    let mut rows = stmt.query([&thread])?;
    while let Some(row) = rows.next()? {
        for i in 0..5 {
            let value: String = row.get(i)?;
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
    }
    let mut stmt = db.prepare(
        "SELECT e.fingerprint FROM obligation_review_events e
         JOIN obligations o ON o.id=e.obligation_id
         WHERE o.thread=?1 AND o.resolved=0
         ORDER BY e.fingerprint COLLATE BINARY",
    )?;
    let mut rows = stmt.query([&thread])?;
    while let Some(row) = rows.next()? {
        let fingerprint: String = row.get(0)?;
        hash.update(fingerprint.as_bytes());
    }
    Ok((count, format!("{:x}", hash.finalize())))
}

pub fn unreviewed_count(db: &Connection, thread: &str) -> Result<i64> {
    let thread = Uuid::parse_str(thread)?.to_string();
    let tx = rusqlite::Transaction::new_unchecked(db, TransactionBehavior::Deferred)?;
    let (count, digest) = review_digest(&tx, &thread)?;
    let reviewed: Option<String> = tx
        .query_row(
            "SELECT digest FROM obligation_reviews WHERE thread=?1",
            [&thread],
            |row| row.get(0),
        )
        .optional()?;
    tx.commit()?;
    Ok(if reviewed.as_deref() == Some(&digest) {
        0
    } else {
        count
    })
}

pub fn acknowledge_review(
    db: &Connection,
    thread: &str,
    digest: &str,
    ids: &[String],
) -> Result<()> {
    let thread = Uuid::parse_str(thread)?.to_string();
    let tx = rusqlite::Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let (count, current) = review_digest(&tx, &thread)?;
    ensure!(
        count > 0 && digest == current,
        "Obligations or results changed; list all pages again"
    );
    let mut supplied = ids.to_vec();
    supplied.sort_unstable();
    let mut stmt = tx.prepare(
        "SELECT id FROM obligations WHERE thread=?1 AND resolved=0 ORDER BY id COLLATE BINARY",
    )?;
    let expected = stmt
        .query_map([&thread], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    ensure!(
        supplied == expected,
        "Review must include every pending obligation exactly once"
    );
    tx.execute("INSERT INTO obligation_reviews(thread,digest) VALUES (?1,?2) ON CONFLICT(thread) DO UPDATE SET digest=excluded.digest", params![thread, digest])?;
    tx.commit()?;
    Ok(())
}

/// Reopen reviews for linked validations when a distinct result is published.
#[allow(clippy::too_many_arguments)]
pub fn note_result(
    db: &Connection,
    kind: &str,
    repo: &str,
    resource: &str,
    outcome: &str,
    source: &serde_json::Value,
    event_key: Option<&str>,
    scope: Option<&serde_json::Value>,
    identity: Option<(&str, u64)>,
) -> Result<()> {
    let initialized: bool = db.query_row(
        "SELECT count(*)=2 FROM sqlite_master WHERE type='table' AND name IN ('obligation_review_events','validation_scope_links')",
        [],
        |row| row.get(0),
    )?;
    if !initialized {
        return Ok(());
    }
    let mut hash = Sha256::new();
    let source_json = serde_json::to_string(source)?;
    for value in [
        kind,
        repo,
        resource,
        outcome,
        event_key.unwrap_or(&source_json),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    if let Some(scope) = scope {
        hash.update(serde_json::to_vec(scope)?);
    }
    let fingerprint = format!("{:x}", hash.finalize());
    db.execute(
        "INSERT OR IGNORE INTO obligation_review_events(fingerprint,kind,repo,resource,outcome,scope,obligation_id,execution_id,attempt)
         SELECT ?1,?2,?3,?4,?5,?6,o.id,?7,?8 FROM obligations o LEFT JOIN validation_scope_links l ON l.obligation_id=o.id
         WHERE o.resolved=0 AND ((o.kind=?2 AND o.repo=?3 AND o.resource=?4) OR
         (l.kind=?2 AND l.repo=?3 AND (l.resource=?4 OR (?2='chat' AND l.resource COLLATE NOCASE=?4))))",
        params![fingerprint, kind, repo, resource, outcome, scope.map(serde_json::to_string).transpose()?,
            identity.map(|x| x.0.to_owned()).or_else(|| crate::delivery_evidence::identity_component(source.pointer("/workflow_run/id")).or_else(|| crate::delivery_evidence::identity_component(source.get("execution_id")))),
            identity.map(|x| x.1.to_string()).or_else(|| crate::delivery_evidence::identity_component(source.pointer("/workflow_run/run_attempt")).or_else(|| crate::delivery_evidence::identity_component(source.get("attempt"))))],
    )?;
    Ok(())
}

pub fn linked_results(db: &Connection, obligation_id: &str) -> Result<Vec<serde_json::Value>> {
    let mut stmt = db.prepare(
        "SELECT e.kind,e.repo,e.resource,e.outcome,e.scope,e.execution_id,e.attempt FROM obligation_review_events e
         WHERE e.obligation_id=?1 ORDER BY e.rowid DESC",
    )?;
    let mut values = stmt
        .query_map([obligation_id], |row| {
            Ok(
                serde_json::json!({"kind":row.get::<_,String>(0)?,"repo":row.get::<_,String>(1)?,
            "resource":row.get::<_,String>(2)?,"outcome":row.get::<_,String>(3)?,"scope":row.get::<_,Option<String>>(4)?.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),"execution_id":row.get::<_,Option<String>>(5)?,"attempt":row.get::<_,Option<String>>(6)?}),
            )
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut stmt = db.prepare("SELECT w.repo,w.run_id,w.attempt,w.conclusion,CASE WHEN w.state='needs_attention' THEN coalesce(w.reason,'needs_attention') ELSE NULL END FROM waits w
        JOIN obligations o ON o.id=?1 AND o.thread=w.thread LEFT JOIN validation_scope_links l ON l.obligation_id=o.id
        WHERE w.conclusion IS NOT NULL AND ((o.kind='job' AND o.repo=w.repo AND o.resource=CAST(w.run_id AS TEXT)) OR
        (l.kind='job' AND l.repo=w.repo AND l.resource=CAST(w.run_id AS TEXT)) OR
        (o.kind='validation' AND l.obligation_id IS NULL)) ORDER BY w.repo,w.run_id,w.attempt")?;
    values.extend(stmt.query_map([obligation_id], |row| Ok(serde_json::json!({"kind":"job","repo":row.get::<_,String>(0)?,
        "resource":row.get::<_,i64>(1)?.to_string(),"attempt":row.get::<_,i64>(2)?,"outcome":row.get::<_,String>(3)?,
        "delivery_issue":row.get::<_,Option<String>>(4)?})))?.collect::<rusqlite::Result<Vec<_>>>()?);
    Ok(values)
}

const MAX_COLLISION_PREVIEW_BYTES: usize = 7 * 1024;
const MAX_COLLISION_RECORD_BYTES: usize = 16 * 1024;
const MAX_COLLISION_ITEMS: usize = 16;

fn clipped(value: String, max_chars: usize) -> (String, bool) {
    let shortened: String = value.chars().take(max_chars).collect();
    let was_clipped = shortened.len() < value.len();
    (shortened, was_clipped)
}

/// Capture a fixed-size observation preview; the digest is not reversible.
fn collision_preview(
    db: &Connection,
    source: &str,
    legacy_id: &str,
    claim_id: &str,
    digest: &str,
    count: i64,
) -> Result<String> {
    let mut statement = db.prepare(
        "SELECT id,kind,repo,resource,outcome,description FROM obligations WHERE thread=?1 AND resolved=0 ORDER BY rowid LIMIT 16",
    )?;
    let mut rows = statement.query([source])?;
    let mut items = Vec::new();
    let mut fields_clipped = false;
    while let Some(row) = rows.next()? {
        let mut item = serde_json::Map::new();
        let mut item_clipped = false;
        for (index, (key, limit)) in [
            ("id", 64),
            ("kind", 64),
            ("repo", 128),
            ("resource", 128),
            ("outcome", 64),
            ("description", 256),
        ]
        .iter()
        .enumerate()
        {
            let (value, cut) = clipped(row.get(index)?, *limit);
            item.insert((*key).into(), serde_json::json!(value));
            item_clipped |= cut;
        }
        items.push(serde_json::Value::Object(item));
        let candidate = serde_json::json!({"legacy_alert_id":legacy_id,"claim_id":claim_id,"snapshot_digest":digest,"pending_count":count,"preview":items,"omitted":count.saturating_sub(items.len() as i64),"fields_clipped":fields_clipped || item_clipped});
        if serde_json::to_vec(&candidate)?.len() > MAX_COLLISION_PREVIEW_BYTES {
            items.pop();
            break;
        }
        fields_clipped |= item_clipped;
    }
    debug_assert!(items.len() <= MAX_COLLISION_ITEMS);
    let snapshot = serde_json::json!({"legacy_alert_id":legacy_id,"claim_id":claim_id,"snapshot_digest":digest,"pending_count":count,"preview":items,"omitted":count.saturating_sub(items.len() as i64),"fields_clipped":fields_clipped});
    let encoded = serde_json::to_string(&snapshot)?;
    ensure!(
        encoded.len() <= MAX_COLLISION_PREVIEW_BYTES,
        "Collision preview exceeds limit"
    );
    Ok(encoded)
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
    legacy_fingerprint: Option<(&str, &str, i64)>,
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
    if let Some((legacy, digest, count)) = legacy_fingerprint {
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) && count >= 0,
            "Invalid collision snapshot summary"
        );
        let old_id = format!(
            "{:x}",
            Sha256::digest(format!("{responsible}:{coordinator}:{legacy}").as_bytes())
        );
        // One diagnostic per legacy key bounds repeated snapshots. Its immutable
        // previews retain the first and most recent observations only.
        let diagnostic_id = format!(
            "{:x}",
            Sha256::digest(format!("legacy-collision:{old_id}").as_bytes())
        );
        let diagnostic_exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM coordinator_alerts WHERE id=?1)",
            [&diagnostic_id],
            |r| r.get(0),
        )?;
        let legacy_exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM coordinator_alerts WHERE id=?1)",
            [&old_id],
            |r| r.get(0),
        )?;
        if diagnostic_exists || legacy_exists {
            let preview: serde_json::Value = serde_json::from_str(&collision_preview(
                db,
                &responsible,
                &old_id,
                &id,
                digest,
                count,
            )?)?;
            let record = if !diagnostic_exists {
                serde_json::json!({"first":preview,"latest":preview})
            } else {
                let (reason, saved): (Option<String>, String) = db.query_row(
                    "SELECT reason,message FROM coordinator_alerts WHERE id=?1",
                    [&diagnostic_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                ensure!(
                    reason.as_deref() == Some(format!("legacy_collision:{old_id}").as_str()),
                    "Collision diagnostic ID is already occupied"
                );
                let mut saved: serde_json::Value =
                    serde_json::from_str(&saved).context("Invalid saved collision diagnostic")?;
                ensure!(
                    saved["first"].is_object() && saved["latest"].is_object(),
                    "Invalid saved collision diagnostic"
                );
                saved["latest"] = preview;
                saved
            };
            let encoded = serde_json::to_string(&record)?;
            ensure!(
                encoded.len() <= MAX_COLLISION_RECORD_BYTES,
                "Collision diagnostic exceeds limit"
            );
            if diagnostic_exists {
                db.execute("UPDATE coordinator_alerts SET message=?1,updated=CURRENT_TIMESTAMP WHERE id=?2", params![encoded,diagnostic_id])?;
            } else {
                db.execute("INSERT INTO coordinator_alerts(id,responsible,coordinator,message,state,reason) VALUES (?1,?2,?3,?4,'needs_attention',?5)", params![diagnostic_id,responsible,coordinator,encoded,format!("legacy_collision:{old_id}")])?;
            }
            return Ok(Some((diagnostic_id, coordinator, true)));
        }
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

/// Only the versioned marker proves a new unattempted alert; legacy ready rows stay untouched.
fn dispatch_coordinator_alerts_with(
    db: &mut Connection,
    send: &mut impl FnMut(&str, &str) -> Result<(String, Option<String>)>,
) -> Result<usize> {
    let pid = i64::from(std::process::id());
    let started = process_start_time(std::process::id())
        .and_then(|started| i64::try_from(started).ok())
        .context("Could not verify coordinator alert sender identity")?;
    let mut attempted = 0;
    loop {
        let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT id,coordinator,message FROM coordinator_alerts
                 WHERE state='ready' AND reason=?1 ORDER BY rowid LIMIT 1",
                [COORDINATOR_ALERT_READY_REASON],
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
                    "UPDATE coordinator_alerts SET state='sending',reason=NULL,
                        updated=CURRENT_TIMESTAMP,sender_pid=?1,sender_start=?2
                     WHERE id=?3 AND state='ready'",
                    params![pid, started, id],
                )? == 1,
                "Coordinator alert was claimed concurrently"
            );
        }
        transaction.commit()?;
        let Some((id, coordinator, message)) = row else {
            return Ok(attempted);
        };

        let (state, reason) = match send(&coordinator, &message) {
            Ok((state, reason)) if state == "queued" => (state, reason),
            Ok((state, reason)) if state == "needs_attention" => (
                state,
                reason.or_else(|| Some("send_needs_attention".into())),
            ),
            Ok((_, reason)) => (
                "needs_attention".into(),
                reason.or_else(|| Some("invalid_send_classification".into())),
            ),
            Err(_) => (
                "needs_attention".into(),
                Some("send_error_outcome_unknown".into()),
            ),
        };
        ensure!(
            db.execute(
                "UPDATE coordinator_alerts SET state=?1,reason=?2,updated=CURRENT_TIMESTAMP,
                    sender_pid=NULL,sender_start=NULL
                 WHERE id=?3 AND state='sending' AND sender_pid=?4 AND sender_start=?5",
                params![state, reason, id, pid, started],
            )? == 1,
            "Coordinator alert claim is no longer owned by this sender"
        );
        attempted += 1;
    }
}

/// Claim ready alerts once, then queue each with the Codex CLI; uncertain sends are never replayed.
pub fn dispatch_coordinator_alerts(
    db: &mut Connection,
    codex: &Path,
    timeout: Duration,
) -> Result<usize> {
    dispatch_coordinator_alerts_with(db, &mut |coordinator, message| {
        crate::bridge::send_mode(codex, timeout, coordinator, message, false)
    })
}

pub fn coordinator_alerts_status(db: &Connection) -> Result<Vec<CoordinatorAlert>> {
    let mut statement = db.prepare(
        "SELECT id,responsible,coordinator,state,reason,created,sender_pid,sender_start
         FROM coordinator_alerts ORDER BY rowid DESC LIMIT 25",
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

/// Read bounded collision diagnostics; messages and previews are untrusted data.
pub fn inspect_legacy_collisions(
    db: &Connection,
    alert_id: Option<&str>,
    after: Option<&str>,
) -> Result<(Vec<serde_json::Value>, Option<String>)> {
    ensure!(
        alert_id.is_none() || after.is_none(),
        "Use alert_id or after, not both"
    );
    let before = match after {
        Some(id) => db.query_row(
            "SELECT rowid FROM coordinator_alerts WHERE id=?1 AND reason LIKE 'legacy_collision:%'",
            [id],
            |r| r.get::<_, i64>(0),
        )?,
        None => i64::MAX,
    };
    let mut statement = db.prepare(
        "SELECT a.id,a.responsible,a.coordinator,a.message,a.created,a.updated,a.state,a.reason,old.id,old.state,old.reason,old.message
         FROM coordinator_alerts a LEFT JOIN coordinator_alerts old ON old.id=substr(a.reason,18)
         WHERE a.reason LIKE 'legacy_collision:%' AND (?1 IS NULL OR a.id=?1) AND a.rowid<?2
         ORDER BY a.rowid DESC LIMIT 6",
    )?;
    let mut rows = statement.query_map(params![alert_id,before], |r| {
        let message: String = r.get(3)?;
        let preview = serde_json::from_str::<serde_json::Value>(&message);
        Ok(serde_json::json!({
            "alert_id":r.get::<_,String>(0)?,"responsible":r.get::<_,String>(1)?,
            "coordinator":r.get::<_,String>(2)?,"observations":preview.as_ref().ok(),"preview_invalid":preview.is_err(),
            "created":r.get::<_,String>(4)?,"last_observed":r.get::<_,String>(5)?,
            "state":r.get::<_,String>(6)?,"reason":r.get::<_,String>(7)?,
            "legacy_alert":{"id":r.get::<_,Option<String>>(8)?,"persisted_state":r.get::<_,Option<String>>(9)?,
                "reason":r.get::<_,Option<String>>(10)?,"message":r.get::<_,Option<String>>(11)?}
        }))
    })?.collect::<rusqlite::Result<Vec<_>>>()?;
    for item in &mut rows {
        let responsible = item["responsible"]
            .as_str()
            .context("Missing diagnostic responsible")?;
        let (count, digest) = pending_digest(db, responsible)?;
        item["current_pending"] = serde_json::json!({"count":count,"digest":digest});
        for (observation, output_key) in [("first", "first_claim"), ("latest", "latest_claim")] {
            let first_claim_id = item["observations"][observation]["claim_id"].as_str();
            let prior: Option<(String, Option<String>, String)> = match first_claim_id {
                Some(id) => db
                    .query_row(
                        "SELECT state,reason,message FROM coordinator_alerts WHERE id=?1",
                        [id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?,
                None => None,
            };
            item[output_key] = match prior {
                Some((state, reason, message)) => {
                    serde_json::json!({"persisted_state":state,"reason":reason,"message":message})
                }
                None => serde_json::Value::Null,
            };
        }
    }
    let next = if rows.len() > 5 {
        rows.truncate(5);
        rows.last()
            .and_then(|x| x["alert_id"].as_str())
            .map(str::to_owned)
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
        "DELETE FROM obligation_reviews WHERE thread IN (?1,?2)",
        params![source_thread, target_thread],
    )?;
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

    fn insert_coordinator_alert(
        db: &Connection,
        id: &str,
        state: &str,
        reason: Option<&str>,
        sender_pid: Option<i64>,
        sender_start: Option<i64>,
        message: &str,
    ) {
        db.execute(
            "INSERT INTO coordinator_alerts
                (id,responsible,coordinator,message,state,reason,sender_pid,sender_start)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                id,
                THREAD,
                OTHER,
                message,
                state,
                reason,
                sender_pid,
                sender_start
            ],
        )
        .unwrap();
    }

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
    fn coordinator_alert_dispatch_commits_live_claim_before_send() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let mut db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        insert_coordinator_alert(
            &db,
            "ready",
            "ready",
            Some(COORDINATOR_ALERT_READY_REASON),
            None,
            None,
            "alert",
        );
        let inspect_path = path.clone();
        let mut calls = 0;

        assert_eq!(
            dispatch_coordinator_alerts_with(&mut db, &mut |coordinator, message| {
                calls += 1;
                assert_eq!(coordinator, OTHER);
                assert_eq!(message, "alert");
                let observer = Connection::open(&inspect_path).unwrap();
                let (state, pid, started): (String, i64, i64) = observer
                    .query_row(
                        "SELECT state,sender_pid,sender_start FROM coordinator_alerts WHERE id='ready'",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .unwrap();
                assert_eq!(state, "sending");
                assert_eq!(pid, i64::from(std::process::id()));
                assert_eq!(
                    process_start_time(pid as u32),
                    u64::try_from(started).ok()
                );
                Ok(("queued".into(), None))
            })
            .unwrap(),
            1
        );
        assert_eq!(calls, 1);
        let saved: (String, Option<String>, Option<i64>, Option<i64>) = db
            .query_row(
                "SELECT state,reason,sender_pid,sender_start FROM coordinator_alerts WHERE id='ready'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(saved, ("queued".into(), None, None, None));
        assert_eq!(
            dispatch_coordinator_alerts_with(&mut db, &mut |_, _| panic!("must not resend"))
                .unwrap(),
            0
        );
    }

    #[test]
    fn concurrent_coordinator_alert_dispatchers_claim_only_once() {
        use std::{sync::mpsc, thread};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        insert_coordinator_alert(
            &db,
            "ready",
            "ready",
            Some(COORDINATOR_ALERT_READY_REASON),
            None,
            None,
            "alert",
        );
        drop(db);

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_path = path.clone();
        let worker = thread::spawn(move || {
            let mut db = Connection::open(worker_path).unwrap();
            db.busy_timeout(Duration::from_secs(5)).unwrap();
            let mut calls = 0;
            let count = dispatch_coordinator_alerts_with(&mut db, &mut |_, _| {
                calls += 1;
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(("queued".into(), None))
            })
            .unwrap();
            (count, calls)
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let mut competing_db = Connection::open(path).unwrap();
        competing_db.busy_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            dispatch_coordinator_alerts_with(&mut competing_db, &mut |_, _| {
                panic!("second dispatcher must not send")
            })
            .unwrap(),
            0
        );
        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), (1, 1));
    }

    #[test]
    fn coordinator_alert_dispatch_marks_uncertain_error_terminal() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        insert_coordinator_alert(
            &db,
            "ready",
            "ready",
            Some(COORDINATOR_ALERT_READY_REASON),
            None,
            None,
            "alert",
        );
        let mut calls = 0;
        assert_eq!(
            dispatch_coordinator_alerts_with(&mut db, &mut |_, _| {
                calls += 1;
                Err(anyhow::anyhow!("outcome unknown"))
            })
            .unwrap(),
            1
        );
        assert_eq!(calls, 1);
        let saved: (String, Option<String>) = db
            .query_row(
                "SELECT state,reason FROM coordinator_alerts WHERE id='ready'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            saved,
            (
                "needs_attention".into(),
                Some("send_error_outcome_unknown".into())
            )
        );
        assert_eq!(
            dispatch_coordinator_alerts_with(&mut db, &mut |_, _| panic!("must not retry"))
                .unwrap(),
            0
        );
    }

    #[test]
    fn coordinator_alert_dispatch_restart_sends_ready_but_never_reclaims_sending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        insert_coordinator_alert(
            &db,
            "ready",
            "ready",
            Some(COORDINATOR_ALERT_READY_REASON),
            None,
            None,
            "new alert",
        );
        insert_coordinator_alert(
            &db,
            "interrupted",
            "sending",
            None,
            Some(i64::MAX),
            Some(0),
            "uncertain alert",
        );
        drop(db);

        let mut db = Connection::open(path).unwrap();
        let mut calls = 0;
        assert_eq!(
            dispatch_coordinator_alerts_with(&mut db, &mut |_, message| {
                calls += 1;
                assert_eq!(message, "new alert");
                Ok(("queued".into(), None))
            })
            .unwrap(),
            1
        );
        assert_eq!(calls, 1);
        let state: String = db
            .query_row(
                "SELECT state FROM coordinator_alerts WHERE id='interrupted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "sending");
        assert_eq!(
            dispatch_coordinator_alerts_with(&mut db, &mut |_, _| panic!("must not replay"))
                .unwrap(),
            0
        );
    }

    #[test]
    fn coordinator_alert_dispatch_preserves_non_ready_states() {
        type SavedAlert = (
            String,
            String,
            Option<String>,
            Option<i64>,
            Option<i64>,
            String,
        );
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        for (id, state) in [
            ("sending", "sending"),
            ("queued", "queued"),
            ("attention", "needs_attention"),
        ] {
            insert_coordinator_alert(
                &db,
                id,
                state,
                Some("preserve me"),
                Some(123),
                Some(456),
                "existing alert",
            );
        }
        let before: Vec<SavedAlert> = db
            .prepare(
                "SELECT id,state,reason,sender_pid,sender_start,message
                 FROM coordinator_alerts ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();

        assert_eq!(
            dispatch_coordinator_alerts_with(&mut db, &mut |_, _| panic!("must not send")).unwrap(),
            0
        );
        let after: Vec<SavedAlert> = db
            .prepare(
                "SELECT id,state,reason,sender_pid,sender_start,message
                 FROM coordinator_alerts ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();
        assert_eq!(after, before);
    }

    #[test]
    fn coordinator_alert_dispatch_preserves_ready_rows_without_new_marker() {
        type LegacyAlert = (String, Option<String>, Option<i64>, Option<i64>, String);
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        insert_coordinator_alert(&db, "legacy_empty", "ready", None, None, None, "old alert");
        insert_coordinator_alert(
            &db,
            "legacy_reason",
            "ready",
            Some("send_outcome_unknown"),
            Some(123),
            Some(456),
            "possibly attempted",
        );
        insert_coordinator_alert(
            &db,
            "new_interrupt",
            "ready",
            Some(COORDINATOR_ALERT_READY_REASON),
            None,
            None,
            "new alert",
        );

        let legacy_before: Vec<LegacyAlert> = db
            .prepare(
                "SELECT id,reason,sender_pid,sender_start,message FROM coordinator_alerts
                 WHERE id LIKE 'legacy_%' ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();
        let mut calls = 0;
        assert_eq!(
            dispatch_coordinator_alerts_with(&mut db, &mut |_, message| {
                calls += 1;
                assert_eq!(message, "new alert");
                Ok(("queued".into(), None))
            })
            .unwrap(),
            1
        );
        assert_eq!(calls, 1);
        let legacy_after: Vec<LegacyAlert> = db
            .prepare(
                "SELECT id,reason,sender_pid,sender_start,message FROM coordinator_alerts
                 WHERE id LIKE 'legacy_%' ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();
        assert_eq!(legacy_after, legacy_before);
        let new_state: String = db
            .query_row(
                "SELECT state FROM coordinator_alerts WHERE id='new_interrupt'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_state, "queued");
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
mod bounded_collision_tests {
    use super::*;
    const OWNER: &str = "11111111-1111-4111-8111-111111111111";
    const COORDINATOR: &str = "22222222-2222-4222-8222-222222222222";
    fn fixture() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        register_coordinator(&db, OWNER, COORDINATOR).unwrap();
        db
    }
    #[test]
    fn preview_is_bounded_and_explicit_about_omitted_and_clipped_data() {
        let db = fixture();
        let text = "é\n".repeat(2048);
        for n in 0..40 {
            db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES(?1,?2,'artifact','repo','resource','available',?3)", params![format!("item-{n:02}"),OWNER,text]).unwrap();
        }
        let (count, digest) = pending_digest(&db, OWNER).unwrap();
        let preview =
            collision_preview(&db, OWNER, &"a".repeat(64), &"b".repeat(64), &digest, count)
                .unwrap();
        assert!(preview.len() <= MAX_COLLISION_PREVIEW_BYTES);
        let value: serde_json::Value = serde_json::from_str(&preview).unwrap();
        assert_eq!(value["pending_count"], 40);
        assert_eq!(value["fields_clipped"], true);
        assert!(value["omitted"].as_i64().unwrap() >= 24);
        assert!(value["preview"].as_array().unwrap().len() <= MAX_COLLISION_ITEMS);
        assert_eq!(value["snapshot_digest"], digest);
    }
    #[test]
    fn repeated_changing_collisions_keep_one_bounded_first_and_latest_record() {
        let db = fixture();
        for n in 0..40 {
            db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES(?1,?2,'artifact','repo','resource','available',?3)",params![format!("item-{n:02}"),OWNER,"é\n".repeat(1024)]).unwrap();
        }
        claim_coordinator_alert(&db, OWNER, "legacy", "old")
            .unwrap()
            .unwrap();
        let mut first_digest = String::new();
        let mut latest_digest = String::new();
        for n in 0..30 {
            db.execute(
                "UPDATE obligations SET description=?1 WHERE id='item-00'",
                [format!("version-{n}")],
            )
            .unwrap();
            let (count, digest) = pending_digest(&db, OWNER).unwrap();
            if n == 0 {
                first_digest = digest.clone();
            }
            latest_digest = digest.clone();
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            let (_, _, collision) = claim_coordinator_alert_with_legacy(
                &tx,
                OWNER,
                &format!("new-{n}"),
                "snapshot",
                Some(("legacy", &digest, count)),
            )
            .unwrap()
            .unwrap();
            assert!(collision);
            tx.commit().unwrap();
        }
        let (count,message): (i64,String)=db.query_row("SELECT count(*),min(message) FROM coordinator_alerts WHERE reason LIKE 'legacy_collision:%'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(count, 1);
        assert!(message.len() <= MAX_COLLISION_RECORD_BYTES);
        let record: serde_json::Value = serde_json::from_str(&message).unwrap();
        assert_eq!(record["first"]["snapshot_digest"], first_digest);
        assert_eq!(record["latest"]["snapshot_digest"], latest_digest);
        assert!(record["latest"]["omitted"].as_i64().unwrap() > 0);
    }

    #[test]
    fn diagnostics_are_paginated_and_link_the_prior_alert() {
        let db = fixture();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('item',?1,'artifact','repo','resource','available','pending')", [OWNER]).unwrap();
        let (count, digest) = pending_digest(&db, OWNER).unwrap();
        for n in 0..12 {
            let old = format!("old-{n}");
            claim_coordinator_alert(&db, OWNER, &old, "legacy context")
                .unwrap()
                .unwrap();
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            let (_, _, collision) = claim_coordinator_alert_with_legacy(
                &tx,
                OWNER,
                &format!("new-{n}"),
                "new context",
                Some((&old, &digest, count)),
            )
            .unwrap()
            .unwrap();
            assert!(collision);
            tx.commit().unwrap();
        }
        let mut cursor = None;
        let mut all = Vec::new();
        loop {
            let (rows, next) = inspect_legacy_collisions(&db, None, cursor.as_deref()).unwrap();
            all.extend(rows);
            if next.is_none() {
                break;
            }
            cursor = next;
        }
        assert_eq!(all.len(), 12);
        assert_eq!(all[0]["legacy_alert"]["persisted_state"], "sending");
        assert_eq!(all[0]["legacy_alert"]["message"], "legacy context");
        assert_eq!(all[0]["current_pending"]["digest"], digest);
        db.execute(
            "UPDATE obligations SET description='changed after observation' WHERE id='item'",
            [],
        )
        .unwrap();
        let (changed, _) =
            inspect_legacy_collisions(&db, all[0]["alert_id"].as_str(), None).unwrap();
        assert_ne!(changed[0]["current_pending"]["digest"], digest);
        assert_eq!(
            changed[0]["observations"]["latest"]["snapshot_digest"],
            digest
        );
        let id = all[0]["alert_id"].as_str().unwrap();
        assert_eq!(
            inspect_legacy_collisions(&db, Some(id), None)
                .unwrap()
                .0
                .len(),
            1
        );
        assert!(inspect_legacy_collisions(&db, Some(id), Some(id)).is_err());
    }
    #[test]
    fn prior_new_claim_is_preserved_and_visible_in_diagnostic() {
        let db = fixture();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('item',?1,'artifact','repo','resource','available','pending')", [OWNER]).unwrap();
        let (new_id, _) = claim_coordinator_alert(&db, OWNER, "new", "new context")
            .unwrap()
            .unwrap();
        finish_coordinator_alert(&db, &new_id, "queued", None).unwrap();
        claim_coordinator_alert(&db, OWNER, "legacy", "old context")
            .unwrap()
            .unwrap();
        let (count, digest) = pending_digest(&db, OWNER).unwrap();
        let tx = rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
        let (diag, _, collision) = claim_coordinator_alert_with_legacy(
            &tx,
            OWNER,
            "new",
            "snapshot",
            Some(("legacy", &digest, count)),
        )
        .unwrap()
        .unwrap();
        assert!(collision);
        assert_ne!(diag, new_id);
        tx.commit().unwrap();
        let state: String = db
            .query_row(
                "SELECT state FROM coordinator_alerts WHERE id=?1",
                [&new_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "queued");
        let (result, _) = inspect_legacy_collisions(&db, Some(&diag), None).unwrap();
        assert_eq!(result[0]["first_claim"]["persisted_state"], "queued");
        assert_eq!(result[0]["latest_claim"]["message"], "new context");
    }

    #[test]
    fn failed_diagnostic_insert_rolls_back_without_claiming_delivery() {
        let db = fixture();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('item',?1,'artifact','repo','resource','available','pending')", [OWNER]).unwrap();
        claim_coordinator_alert(&db, OWNER, "legacy", "old")
            .unwrap()
            .unwrap();
        db.execute_batch("CREATE TRIGGER reject_diagnostic BEFORE INSERT ON coordinator_alerts WHEN NEW.reason LIKE 'legacy_collision:%' BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
        let (count, digest) = pending_digest(&db, OWNER).unwrap();
        {
            let tx =
                rusqlite::Transaction::new_unchecked(&db, TransactionBehavior::Immediate).unwrap();
            assert!(
                claim_coordinator_alert_with_legacy(
                    &tx,
                    OWNER,
                    "new",
                    "snapshot",
                    Some(("legacy", &digest, count))
                )
                .is_err()
            );
        }
        let count: i64 = db
            .query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
