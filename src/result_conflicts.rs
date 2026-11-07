use anyhow::{Result, ensure};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

pub fn validate_identity(execution: &str, attempt: u64) -> Result<()> {
    ensure!(
        !execution.is_empty()
            && execution.len() <= 255
            && execution.bytes().all(|b| b.is_ascii_graphic()),
        "Invalid execution identity"
    );
    ensure!(
        attempt > 0 && i64::try_from(attempt).is_ok(),
        "Invalid execution attempt"
    );
    Ok(())
}

/// Caller must use the same namespace and resource used for the publication.
/// Execution and attempt are explicit: an omitted identity must never be inferred.
pub fn record(
    db: &Connection,
    namespace: &str,
    resource: &str,
    execution: &str,
    attempt: u64,
    outcome: &str,
    evidence: &Value,
) -> Result<Vec<Value>> {
    validate_identity(execution, attempt)?;
    ensure!(
        matches!(outcome, "success" | "failure" | "cancelled"),
        "Unsupported conflict outcome"
    );
    let evidence = serde_json::to_string(evidence)?;
    ensure!(evidence.len() <= 1024 * 1024, "Payload exceeds 1 MiB");
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS result_reports (
        id INTEGER PRIMARY KEY,
        namespace TEXT NOT NULL,
        resource TEXT NOT NULL,
        execution TEXT NOT NULL,
        attempt INTEGER NOT NULL,
        outcome TEXT NOT NULL,
        evidence TEXT NOT NULL,
        reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(namespace, resource, execution, attempt, outcome, evidence)
    );",
    )?;
    db.execute(
        "INSERT OR IGNORE INTO result_reports(namespace,resource,execution,attempt,outcome,evidence) VALUES (?1,?2,?3,?4,?5,?6)",
        params![namespace, resource, execution, attempt as i64, outcome, evidence],
    )?;
    Ok(lookup_page(db, namespace, resource, execution, attempt, 0)?.1)
}

pub fn lookup_page(
    db: &Connection,
    namespace: &str,
    resource: &str,
    execution: &str,
    attempt: u64,
    after: i64,
) -> Result<(bool, Vec<Value>, Option<i64>)> {
    validate_identity(execution, attempt)?;
    ensure!(after >= 0, "Invalid cursor");
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='result_reports')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok((false, Vec::new(), None));
    }
    let conflict: bool = db.query_row(
        "SELECT count(DISTINCT outcome)>1 FROM result_reports WHERE namespace=?1 AND resource=?2 AND execution=?3 AND attempt=?4",
        params![namespace, resource, execution, attempt as i64], |row| row.get(0),
    )?;
    if !conflict {
        return Ok((false, Vec::new(), None));
    }
    let mut statement = db.prepare(
        "SELECT id,outcome,evidence,reported_at FROM result_reports WHERE namespace=?1 AND resource=?2 AND execution=?3 AND attempt=?4 AND id>?5 ORDER BY id LIMIT 11",
    )?;
    let rows = statement
        .query_map(
            params![namespace, resource, execution, attempt as i64, after],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let next = (rows.len() > 10).then(|| rows[9].0);
    let reports = rows.into_iter().take(10).map(|(_, outcome, evidence, reported_at)| {
        Ok(json!({"outcome": outcome, "evidence": serde_json::from_str::<Value>(&evidence)?, "reported_at": reported_at}))
    }).collect::<Result<Vec<_>>>()?;
    Ok((true, reports, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_exact_execution_and_attempt_and_preserves_all_evidence() {
        let db = Connection::open_in_memory().unwrap();
        let a = json!({"agent":"a", "proof":"first"});
        let b = json!({"agent":"b", "proof":"second"});
        assert!(!lookup_page(&db, "repo", "job", "run1", 1, 0).unwrap().0);
        assert!(
            record(&db, "repo", "job", "run1", 1, "success", &a)
                .unwrap()
                .is_empty()
        );
        assert!(
            record(&db, "repo", "job", "run1", 2, "failure", &b)
                .unwrap()
                .is_empty()
        );
        assert!(
            record(&db, "repo", "job", "run2", 1, "failure", &b)
                .unwrap()
                .is_empty()
        );
        assert!(
            record(&db, "other", "job", "run1", 1, "failure", &b)
                .unwrap()
                .is_empty()
        );
        assert!(
            record(&db, "repo", "other", "run1", 1, "failure", &b)
                .unwrap()
                .is_empty()
        );
        let conflict = record(&db, "repo", "job", "run1", 1, "failure", &b).unwrap();
        assert_eq!(conflict.len(), 2);
        assert_eq!(conflict[0]["evidence"], a);
        assert_eq!(conflict[1]["evidence"], b);
        assert_eq!(
            lookup_page(&db, "repo", "job", "run1", 1, 0).unwrap().1,
            conflict
        );
        assert_eq!(
            record(&db, "repo", "job", "run1", 1, "failure", &b)
                .unwrap()
                .len(),
            2
        );
        assert!(record(&db, "repo", "job", "", 1, "success", &a).is_err());
        assert!(record(&db, "repo", "job", "run1", 0, "success", &a).is_err());
        assert!(
            record(
                &db,
                "repo",
                "job",
                "run1",
                1,
                "success",
                &json!("x".repeat(1024 * 1024))
            )
            .is_err()
        );
        assert_eq!(
            record(
                &db,
                "repo",
                "job",
                "run1",
                1,
                "cancelled",
                &json!({"agent":"c"})
            )
            .unwrap()
            .len(),
            3
        );
    }

    #[test]
    fn reports_are_part_of_the_callers_transaction() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("BEGIN").unwrap();
        record(&db, "repo", "job", "run", 1, "success", &json!({})).unwrap();
        db.execute_batch("ROLLBACK").unwrap();
        assert!(
            record(&db, "repo", "job", "run", 1, "failure", &json!({}))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn conflict_evidence_is_paginated_without_crossing_identities() {
        let db = Connection::open_in_memory().unwrap();
        for index in 0..12 {
            record(
                &db,
                "repo",
                "job",
                "run",
                1,
                if index == 11 { "failure" } else { "success" },
                &json!({"index": index}),
            )
            .unwrap();
        }
        record(
            &db,
            "repo",
            "job",
            "run",
            2,
            "failure",
            &json!({"other": true}),
        )
        .unwrap();
        let (conflict, first, cursor) = lookup_page(&db, "repo", "job", "run", 1, 0).unwrap();
        assert!(conflict);
        assert_eq!(first.len(), 10);
        let (conflict, second, next) =
            lookup_page(&db, "repo", "job", "run", 1, cursor.unwrap()).unwrap();
        assert!(conflict);
        assert_eq!(second.len(), 2);
        assert_eq!(second[1]["outcome"], "failure");
        assert!(next.is_none());
        assert!(!lookup_page(&db, "repo", "job", "run", 2, 0).unwrap().0);
        assert!(lookup_page(&db, "repo", "job", "run", 1, -1).is_err());
    }
}
