//! Explicit validation commitments, using Wake's existing obligation queue.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
use uuid::Uuid;

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS validation_evidence (
            obligation_id TEXT PRIMARY KEY REFERENCES obligations(id),
            evidence TEXT NOT NULL
        );",
    )?;
    Ok(())
}

pub fn register(db: &Connection, thread: &str, description: &str) -> Result<String> {
    let thread = Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string();
    ensure!(!description.trim().is_empty(), "Description is empty");
    ensure!(description.len() <= 2048, "Description exceeds 2048 bytes");
    let id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO obligations(id, thread, kind, repo, resource, outcome, description)
         VALUES (?1, ?2, 'validation', '', ?1, '', ?3)",
        params![id, thread, description],
    )?;
    Ok(id)
}

pub fn resolve(db: &mut Connection, id: &str, evidence: &str) -> Result<bool> {
    let id = Uuid::parse_str(id)
        .context("Invalid obligation UUID")?
        .to_string();
    ensure!(!evidence.trim().is_empty(), "Evidence is empty");
    ensure!(evidence.len() <= 2048, "Evidence exceeds 2048 bytes");
    let tx = db.transaction()?;
    let changed = tx.execute(
        "UPDATE obligations SET resolved=1 WHERE id=?1 AND kind='validation' AND resolved=0",
        [&id],
    )?;
    if changed == 1 {
        tx.execute(
            "INSERT INTO validation_evidence(obligation_id, evidence) VALUES (?1, ?2)",
            params![id, evidence],
        )?;
    }
    tx.commit()?;
    Ok(changed == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitments_and_evidence_survive_reopen_and_are_thread_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let owner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let db = Connection::open(&path).unwrap();
        crate::obligations::initialize(&db).unwrap();
        initialize(&db).unwrap();
        let id = register(&db, owner, "Check the migration").unwrap();
        drop(db);
        let mut db = Connection::open(&path).unwrap();
        assert_eq!(crate::obligations::pending(&db, owner).unwrap().len(), 1);
        assert!(crate::obligations::pending(&db, other).unwrap().is_empty());
        assert!(resolve(&mut db, &id, "migration test passed").unwrap());
        drop(db);
        let db = Connection::open(path).unwrap();
        assert!(crate::obligations::pending(&db, owner).unwrap().is_empty());
        let evidence: String = db
            .query_row(
                "SELECT evidence FROM validation_evidence WHERE obligation_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence, "migration test passed");
    }

    #[test]
    fn requires_evidence_and_preserves_it_atomically() {
        let mut db = Connection::open_in_memory().unwrap();
        crate::obligations::initialize(&db).unwrap();
        initialize(&db).unwrap();
        let thread = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        assert!(register(&db, thread, " ").is_err());
        assert!(register(&db, "invalid", "Check the migration").is_err());
        let id = register(&db, thread, "Check the migration").unwrap();
        let publication = crate::obligations::register(
            &db,
            thread,
            "artifact",
            "",
            "report",
            "available",
            "Publish report",
        )
        .unwrap();
        assert!(!resolve(&mut db, &publication, "not a validation").unwrap());
        assert!(crate::obligations::resolve(&db, &publication).unwrap());
        assert!(!crate::obligations::resolve(&db, &id).unwrap());
        assert_eq!(
            crate::obligations::resolve_publication(&db, "artifact", "", &id, "available").unwrap(),
            0
        );
        assert!(resolve(&mut db, &id, " ").is_err());
        assert_eq!(crate::obligations::pending(&db, thread).unwrap().len(), 1);
        db.execute_batch("CREATE TRIGGER reject_evidence BEFORE INSERT ON validation_evidence BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        assert!(resolve(&mut db, &id, "migration test passed").is_err());
        assert_eq!(crate::obligations::pending(&db, thread).unwrap().len(), 1);
        db.execute_batch("DROP TRIGGER reject_evidence").unwrap();
        assert!(resolve(&mut db, &id, "migration test passed").unwrap());
        assert!(!resolve(&mut db, &id, "replacement").unwrap());
        let evidence: String = db
            .query_row(
                "SELECT evidence FROM validation_evidence WHERE obligation_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence, "migration test passed");
        assert!(crate::obligations::pending(&db, thread).unwrap().is_empty());
    }
}
