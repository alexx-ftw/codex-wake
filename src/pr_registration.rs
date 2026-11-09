use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

/// Register PR listeners without changing pre-existing subscriptions or deliveries.
pub fn register(db: &mut Connection, repo: &str, number: &str, thread: &str) -> Result<()> {
    let (thread, number) =
        crate::subscriptions::validate_source("pull_request", repo, number, "closed", thread)?;
    crate::subscriptions::initialize(db)?;
    crate::rules::initialize(db)?;
    crate::polling::pr_notifications::initialize(db)?;
    codex_wake::pr_ci::initialize(db)?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS automatic_pr_rules (repo TEXT NOT NULL, pr TEXT NOT NULL, thread TEXT NOT NULL, rule_id TEXT NOT NULL, PRIMARY KEY(repo,pr,thread))")?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    codex_wake::pr_ci::register_in(&tx, repo, &number, &thread)?;
    for kind in ["pull_request", "review"] {
        crate::polling::pr_notifications::register_in(&tx, kind, repo, &number, &thread)?;
    }
    let existing: Option<String> = tx
        .query_row(
            "SELECT rule_id FROM automatic_pr_rules WHERE repo=?1 AND pr=?2 AND thread=?3",
            params![repo, number, thread],
            |row| row.get(0),
        )
        .optional()?;
    if existing.is_none() {
        let input: crate::rules::RuleInput = serde_json::from_value(serde_json::json!({
            "repo":repo, "pr":number.parse::<i64>()?, "target_thread":thread,
            "prompt":"Hay un comentario nuevo o editado en la PR {{event.repo}}#{{event.pr}}. Revísalo en GitHub y atiéndelo dentro del alcance autorizado."
        }))?;
        let id = crate::rules::configure(&tx, input)?;
        tx.execute(
            "INSERT INTO automatic_pr_rules(repo,pr,thread,rule_id) VALUES(?1,?2,?3,?4)",
            params![repo, number, thread, id],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub fn reconcile(db: &mut Connection, config: &crate::manager::Config, now: i64) -> Result<()> {
    let transport = crate::pr_observation::GhCliPullRequestGet::from_config(config);
    for candidate in crate::pr_observation::claim_due_retries(db, now, 60_000, 1)? {
        crate::pr_observation::retry_candidate(
            db,
            candidate.id,
            &transport,
            std::time::Duration::from_secs(20),
            3_600_000,
        )?;
    }
    for candidate in crate::pr_observation::claim_verified_pending(db, now, 60_000, 1)? {
        let pr = candidate
            .verified
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Verified PR evidence missing"))?;
        let thread = candidate
            .session_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("PR destination missing"))?;
        register(db, &pr.repository, &pr.number.to_string(), thread)?;
        let finished = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis(),
        )?;
        anyhow::ensure!(
            crate::pr_observation::mark_candidate_consumed(db, candidate.id, finished)?,
            "PR registration claim expired"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_is_idempotent_and_preserves_existing_deliveries() {
        let mut db = Connection::open_in_memory().unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let other = "22222222-2222-4222-8222-222222222222";
        crate::subscriptions::subscribe(&db, "review", "owner/repo", "7", "submitted", other)
            .unwrap();
        db.execute(
            "UPDATE subscriptions SET state='queued',reason='preserved'",
            [],
        )
        .unwrap();
        register(&mut db, "owner/repo", "7", thread).unwrap();
        register(&mut db, "owner/repo", "7", thread).unwrap();
        let counts: (i64,i64,i64) = db.query_row("SELECT (SELECT count(*) FROM automatic_pr_notification_listeners),(SELECT count(*) FROM rules),(SELECT count(*) FROM subscriptions WHERE thread=?1 AND state='queued' AND reason='preserved')", [other], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(counts, (2, 1, 1));
        assert_eq!(
            db.query_row("SELECT count(*) FROM pr_ci_trackers", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
