use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

/// Register PR listeners without changing pre-existing subscriptions or deliveries.
#[cfg(test)]
pub fn register(db: &mut Connection, repo: &str, number: &str, thread: &str) -> Result<()> {
    let (thread, number) =
        crate::subscriptions::validate_source("pull_request", repo, number, "closed", thread)?;
    initialize_registration(db)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    register_in(&tx, repo, &number, &thread, None)?;
    tx.commit()?;
    Ok(())
}

fn initialize_registration(db: &Connection) -> Result<()> {
    crate::subscriptions::initialize(db)?;
    crate::rules::initialize(db)?;
    crate::polling::pr_notifications::initialize(db)?;
    codex_wake::pr_ci::initialize(db)?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS automatic_pr_rules (repo TEXT NOT NULL, pr TEXT NOT NULL, thread TEXT NOT NULL, rule_id TEXT NOT NULL, PRIMARY KEY(repo,pr,thread))")?;
    Ok(())
}

fn register_in(
    db: &Connection,
    repo: &str,
    number: &str,
    thread: &str,
    registered_at_sec: Option<i64>,
) -> Result<()> {
    codex_wake::pr_ci::register_in(db, repo, number, thread)?;
    for kind in ["pull_request", "review"] {
        if let Some(registered_at_sec) = registered_at_sec {
            crate::polling::pr_notifications::register_in_since(
                db,
                kind,
                repo,
                number,
                thread,
                registered_at_sec,
            )?;
        } else {
            crate::polling::pr_notifications::register_in(db, kind, repo, number, thread)?;
        }
    }
    let existing: Option<String> = db
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
        let id = crate::rules::configure(db, input)?;
        db.execute(
            "INSERT INTO automatic_pr_rules(repo,pr,thread,rule_id) VALUES(?1,?2,?3,?4)",
            params![repo, number, thread, id],
        )?;
    }
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
        let claim_until = now
            .checked_add(60_000)
            .ok_or_else(|| anyhow::anyhow!("candidate claim lease overflow"))?;
        register_claimed_candidate(db, &candidate, claim_until)?;
    }
    Ok(())
}

fn register_claimed_candidate(
    db: &mut Connection,
    candidate: &crate::pr_observation::CandidateRecord,
    claim_until: i64,
) -> Result<bool> {
    let Some(pr) = candidate.verified.as_ref() else {
        return Ok(false);
    };
    let Some(thread) = candidate.session_id.as_deref() else {
        return Ok(false);
    };
    let (thread, number) = crate::subscriptions::validate_source(
        "pull_request",
        &pr.repository,
        &pr.number.to_string(),
        "closed",
        thread,
    )?;
    initialize_registration(db)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let now = current_time_ms()?;
    let eligible: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pr_hook_candidates
         WHERE id=?1 AND state='verified' AND consumed_at_ms IS NULL
           AND work_claim_until_ms=?2 AND work_claim_until_ms>?3)",
        params![candidate.id, claim_until, now],
        |row| row.get(0),
    )?;
    if !eligible {
        return Ok(false);
    }
    let observed_at_ms: i64 = tx.query_row(
        "SELECT created_at_ms FROM pr_hook_candidates WHERE id=?1",
        [candidate.id],
        |row| row.get(0),
    )?;
    register_in(
        &tx,
        &pr.repository,
        &number,
        &thread,
        Some(observed_at_ms.div_euclid(1000)),
    )?;
    let consumed = tx.execute(
        "UPDATE pr_hook_candidates SET consumed_at_ms=?1,work_claim_until_ms=NULL,updated_at_ms=?1
         WHERE id=?2 AND state='verified' AND consumed_at_ms IS NULL
           AND work_claim_until_ms=?3 AND work_claim_until_ms>?1",
        params![current_time_ms()?, candidate.id, claim_until],
    )? == 1;
    if !consumed {
        return Ok(false);
    }
    tx.commit()?;
    Ok(true)
}

fn current_time_ms() -> Result<i64> {
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct FixtureTransport {
        created_at: String,
    }

    impl crate::pr_observation::PullRequestGetTransport for FixtureTransport {
        fn get_pull_request(
            &self,
            _repository: &str,
            _number: u64,
            _timeout: Duration,
        ) -> std::result::Result<
            crate::pr_observation::GetPullRequestResponse,
            crate::pr_observation::TransportFailure,
        > {
            Ok(crate::pr_observation::GetPullRequestResponse {
                status: 200,
                observed_at_ms: unix_now_ms(),
                body: serde_json::json!({
                    "number": 42,
                    "html_url": "https://github.com/owner/repo/pull/42",
                    "created_at": self.created_at,
                    "base": {"ref": "main", "repo": {"full_name": "owner/repo"}},
                    "head": {"ref": "feature"},
                    "user": {"login": "alice"}
                }),
            })
        }
    }

    fn unix_now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    fn utc_timestamp(unix_ms: i64) -> String {
        let seconds = unix_ms.div_euclid(1000);
        let days = seconds.div_euclid(86_400);
        let day_seconds = seconds.rem_euclid(86_400);
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
        let day_of_era = z - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let mut year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_prime = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
        let month = month_prime + if month_prime < 10 { 3 } else { -9 };
        year += i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            day_seconds / 3_600,
            (day_seconds % 3_600) / 60,
            day_seconds % 60
        )
    }

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

    #[test]
    fn delayed_verification_keeps_events_since_creation_observation() {
        let mut db = Connection::open_in_memory().unwrap();
        let observed_at_ms = unix_now_ms() - 30_000;
        let session = "11111111-1111-4111-8111-111111111111";
        let turn = "turn-delayed";
        let call = "call-delayed";
        let command = "gh pr create --repo owner/repo --title delayed";
        let pre = serde_json::json!({
            "hook_event_name":"PreToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_use_id":call,
            "tool_name":"Bash",
            "tool_input":{"command":command}
        });
        crate::pr_observation::record_pre_tool_use(&mut db, &pre, observed_at_ms, 60_000).unwrap();
        let post = serde_json::json!({
            "hook_event_name":"PostToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_use_id":call,
            "tool_name":"Bash",
            "tool_input":{"command":command},
            "tool_response":"https://github.com/owner/repo/pull/42"
        });
        let transport = FixtureTransport {
            created_at: utc_timestamp(observed_at_ms + 1_000),
        };
        let result = crate::pr_observation::handle_post_tool_use(
            &mut db,
            &post,
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        let crate::pr_observation::HandleResult::Candidate { record, .. } = result else {
            panic!("expected verified PR candidate");
        };
        db.execute(
            "UPDATE pr_hook_candidates SET created_at_ms=?1 WHERE id=?2",
            params![observed_at_ms, record.id],
        )
        .unwrap();

        let claimed_at_ms = unix_now_ms();
        let claimed =
            crate::pr_observation::claim_verified_pending(&mut db, claimed_at_ms, 60_000, 1)
                .unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(register_claimed_candidate(&mut db, &claimed[0], claimed_at_ms + 60_000,).unwrap());

        let event_at = utc_timestamp(observed_at_ms + 10_000);
        let notices = crate::polling::pr_notifications::record_event(
            &db,
            "review",
            "owner/repo",
            "42",
            "approved",
            &event_at,
            "review-during-verification",
            &serde_json::json!({"review":{"id":73,"state":"approved"}}),
        )
        .unwrap();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].thread, session);
    }

    #[test]
    fn conflicting_post_after_claim_cannot_register_from_stale_candidate() {
        let mut db = Connection::open_in_memory().unwrap();
        let now = unix_now_ms();
        let session = "11111111-1111-4111-8111-111111111111";
        let turn = "turn-1";
        let call = "call-1";
        let original = "gh pr create --repo owner/repo --title original";
        let transport = FixtureTransport {
            created_at: utc_timestamp(now),
        };
        let pre = serde_json::json!({
            "hook_event_name":"PreToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_use_id":call,
            "tool_name":"Bash",
            "tool_input":{"command":original}
        });
        crate::pr_observation::record_pre_tool_use(&mut db, &pre, now, 60_000).unwrap();
        let post = |command: &str| {
            serde_json::json!({
                "hook_event_name":"PostToolUse",
                "session_id":session,
                "turn_id":turn,
                "tool_use_id":call,
                "tool_name":"Bash",
                "tool_input":{"command":command},
                "tool_response":"https://github.com/owner/repo/pull/42"
            })
        };
        let first = crate::pr_observation::handle_post_tool_use(
            &mut db,
            &post(original),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        let crate::pr_observation::HandleResult::Candidate { record, .. } = first else {
            panic!("expected verified PR candidate");
        };
        assert_eq!(
            record.state,
            crate::pr_observation::CandidateState::Verified
        );
        let claimed =
            crate::pr_observation::claim_verified_pending(&mut db, now, 60_000, 1).unwrap();
        let claim_until = now + 60_000;
        assert_eq!(claimed.len(), 1);

        let conflict = crate::pr_observation::handle_post_tool_use(
            &mut db,
            &post("gh pr create --repo owner/repo --title conflicting"),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        let crate::pr_observation::HandleResult::Candidate { record, .. } = conflict else {
            panic!("expected conflicting candidate result");
        };
        assert_eq!(
            record.state,
            crate::pr_observation::CandidateState::Ambiguous
        );

        assert!(!register_claimed_candidate(&mut db, &claimed[0], claim_until).unwrap());
        let counts: (i64, i64, i64, Option<i64>) = db
            .query_row(
                "SELECT
                    (SELECT count(*) FROM automatic_pr_notification_listeners),
                    (SELECT count(*) FROM pr_ci_trackers),
                    (SELECT count(*) FROM automatic_pr_rules),
                    consumed_at_ms
                 FROM pr_hook_candidates WHERE id=?1",
                [claimed[0].id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(counts, (0, 0, 0, None));
    }

    #[test]
    fn stale_worker_cannot_consume_a_later_workers_claim() {
        let mut db = Connection::open_in_memory().unwrap();
        let now = unix_now_ms();
        let session = "11111111-1111-4111-8111-111111111111";
        let turn = "turn-2";
        let call = "call-2";
        let original = "gh pr create --repo owner/repo --title current";
        let pre = serde_json::json!({
            "hook_event_name":"PreToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_use_id":call,
            "tool_name":"Bash",
            "tool_input":{"command":original}
        });
        crate::pr_observation::record_pre_tool_use(&mut db, &pre, now, 60_000).unwrap();
        let post = serde_json::json!({
            "hook_event_name":"PostToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_use_id":call,
            "tool_name":"Bash",
            "tool_input":{"command":original},
            "tool_response":"https://github.com/owner/repo/pull/42"
        });
        let transport = FixtureTransport {
            created_at: utc_timestamp(now),
        };
        crate::pr_observation::handle_post_tool_use(
            &mut db,
            &post,
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();

        let stale_claim_started = now - 60_001;
        let stale_claim =
            crate::pr_observation::claim_verified_pending(&mut db, stale_claim_started, 60_000, 1)
                .unwrap()
                .remove(0);
        let stale_lease_until = stale_claim_started + 60_000;
        assert!(!register_claimed_candidate(&mut db, &stale_claim, stale_lease_until).unwrap());

        let later_now = unix_now_ms();
        let later_claim =
            crate::pr_observation::claim_verified_pending(&mut db, later_now, 60_000, 1).unwrap();
        assert_eq!(later_claim.len(), 1);
        let later_lease_until = later_now + 60_000;
        assert!(!register_claimed_candidate(&mut db, &stale_claim, stale_lease_until).unwrap());
        let persisted_lease: i64 = db
            .query_row(
                "SELECT work_claim_until_ms FROM pr_hook_candidates WHERE id=?1",
                [stale_claim.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted_lease, later_lease_until);
    }
}
