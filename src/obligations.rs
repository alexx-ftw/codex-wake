//! Persistent obligations, independent of notification delivery state.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
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
            ON obligations(kind, repo, resource, outcome, resolved);",
    )?;
    Ok(())
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
        "UPDATE obligations SET resolved=1 WHERE id=?1 AND resolved=0",
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
}
