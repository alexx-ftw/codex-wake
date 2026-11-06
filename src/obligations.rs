//! Persistent obligations, independent of notification delivery state.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use uuid::Uuid;

const MAX_DESCRIPTION_BYTES: usize = 2048;

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

/// Persist before sending. Existing event IDs are never sent again, including after an uncertain result.
pub fn claim_coordinator_alert(
    db: &Connection,
    responsible: &str,
    fingerprint: &str,
    message: &str,
) -> Result<Option<(String, String)>> {
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
    Ok((inserted == 1).then_some((id, coordinator)))
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
    tx.execute(
        "INSERT INTO obligation_transfers
            (id, obligation_id, source_thread, target_thread, goal, status, tests, next_step)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            obligation.id,
            obligation.thread,
            target_thread,
            goal,
            status,
            tests,
            next_step
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
                t.next_step, t.state, o.id, o.thread, o.kind, o.repo, o.resource,
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
            obligation: Obligation {
                id: row.get(8)?,
                thread: row.get(9)?,
                kind: row.get(10)?,
                repo: row.get(11)?,
                resource: row.get(12)?,
                outcome: row.get(13)?,
                description: row.get(14)?,
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
) -> Result<Transfer> {
    let transfer_id = Uuid::parse_str(transfer_id)
        .context("Invalid transfer UUID")?
        .to_string();
    let recipient_thread = Uuid::parse_str(recipient_thread)
        .context("Invalid recipient thread UUID")?
        .to_string();
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (obligation_id, source_thread, target_thread, goal, status, tests, next_step) = tx
        .query_row(
            "SELECT obligation_id, source_thread, target_thread, goal, status, tests, next_step
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
                ))
            },
        )?;
    ensure!(
        target_thread == recipient_thread,
        "Only the proposed recipient can accept"
    );
    ensure!(
        tx.execute(
            "UPDATE obligations SET thread=?1 WHERE id=?2 AND thread=?3 AND resolved=0",
            params![target_thread, obligation_id, source_thread],
        )? == 1,
        "Obligation is no longer pending with its original owner"
    );
    tx.execute(
        "UPDATE obligation_transfers SET state='accepted', accepted_at=CURRENT_TIMESTAMP
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
         WHERE kind=?1 AND repo=?2 AND resource=?3 AND outcome=?4 AND resolved=0",
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

    fn transfer_input(db: &mut Connection) -> (String, String) {
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
        (obligation, transfer.id)
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
        let (obligation_id, transfer_id) = transfer_input(&mut db);
        assert_eq!(pending(&db, THREAD).unwrap()[0].id, obligation_id);
        assert!(pending(&db, OTHER).unwrap().is_empty());
        assert_eq!(pending_transfers(&db, OTHER).unwrap()[0].id, transfer_id);
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
        assert!(accept_transfer(&mut db, &transfer_id, THREAD).is_err());
        drop(db);

        let mut db = Connection::open(path).unwrap();
        initialize(&db).unwrap();
        let accepted = accept_transfer(&mut db, &transfer_id, OTHER).unwrap();
        assert_eq!(accepted.state, "accepted");
        assert_eq!(accepted.goal, "Finish report");
        assert_eq!(accepted.status, "In progress");
        assert_eq!(accepted.tests, "Unit checks pending");
        assert_eq!(accepted.next_step, "Run the focused checks");
        assert!(pending(&db, THREAD).unwrap().is_empty());
        assert_eq!(pending(&db, OTHER).unwrap()[0].id, obligation_id);
        assert!(pending_transfers(&db, OTHER).unwrap().is_empty());
        assert!(accept_transfer(&mut db, &transfer_id, OTHER).is_err());
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
        let (obligation_id, transfer_id) = transfer_input(&mut db);
        drop(db);

        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let transfer_id = transfer_id.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut db = Connection::open(path).unwrap();
                    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                    barrier.wait();
                    accept_transfer(&mut db, &transfer_id, OTHER).is_ok()
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
