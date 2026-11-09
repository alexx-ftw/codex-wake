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
        if let Some(registered_at_sec) = registered_at_sec {
            db.execute(
                "UPDATE rules SET updated=datetime(?1,'unixepoch') WHERE id=?2",
                params![registered_at_sec, id],
            )?;
        }
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
            candidate
                .work_claim_until_ms
                .ok_or_else(|| anyhow::anyhow!("retry candidate has no claim lease"))?,
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
    let claim_valid: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pr_hook_candidates
         WHERE id=?1 AND state='verified' AND consumed_at_ms IS NULL
           AND work_claim_until_ms=?2 AND work_claim_until_ms>?3)",
        params![candidate.id, claim_until, now],
        |row| row.get(0),
    )?;
    if !claim_valid {
        return Ok(false);
    }
    let pre_linked: bool = tx.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM pr_hook_candidates c
             JOIN pr_hook_pre_observations p ON p.id=c.pre_id
             WHERE c.id=?1 AND p.state='linked'
         )",
        [candidate.id],
        |row| row.get(0),
    )?;
    if !pre_linked {
        tx.execute(
            "UPDATE pr_hook_candidates SET state='ambiguous',
             reason='correlated PreToolUse is not in linked state',verified_json=NULL,
             work_claim_until_ms=NULL,updated_at_ms=?1
             WHERE id=?2 AND state='verified' AND consumed_at_ms IS NULL
               AND work_claim_until_ms=?3",
            params![now, candidate.id, claim_until],
        )?;
        tx.commit()?;
        return Ok(false);
    }
    let created_at_sec: i64 = tx.query_row(
        "SELECT CAST(strftime('%s', ?1) AS INTEGER)",
        [&pr.created_at],
        |row| row.get(0),
    )?;
    register_in(&tx, &pr.repository, &number, &thread, Some(created_at_sec))?;
    let consumed = tx.execute(
        "UPDATE pr_hook_candidates SET consumed_at_ms=?1,work_claim_until_ms=NULL,updated_at_ms=?1
         WHERE id=?2 AND state='verified' AND consumed_at_ms IS NULL
           AND work_claim_until_ms=?3 AND work_claim_until_ms>?1
           AND EXISTS(SELECT 1 FROM pr_hook_pre_observations p
                      WHERE p.id=pr_hook_candidates.pre_id AND p.state='linked')",
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
    fn registration_replays_lifecycle_events_recorded_before_listener_exists() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize_registration(&db).unwrap();
        let thread = "11111111-1111-4111-8111-111111111111";
        let closed_at = "2025-01-02T03:04:05Z";
        let reopened_at = "2025-01-03T04:05:06Z";

        assert!(
            crate::polling::pr_notifications::record_closed_event(
                &db,
                "owner/repo",
                "7",
                "closed",
                closed_at,
                "close-before-registration",
                &serde_json::json!({
                    "action":"closed",
                    "number":7,
                    "repository":{"full_name":"owner/repo"},
                    "pull_request":{"number":7,"merged":false,"closed_at":closed_at}
                }),
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            crate::polling::pr_notifications::record_reopened_event_with_id(
                &db,
                "owner/repo",
                "7",
                "webhook",
                reopened_at,
                "reopen-before-registration",
            )
            .unwrap(),
            0
        );

        let expected_events: Vec<(String, String)> = {
            let mut statement = db
                .prepare(
                    "SELECT event,event_key FROM automatic_pr_event_journal
                     WHERE kind='pull_request' AND repo='owner/repo' AND pr='7'
                     ORDER BY event_at_sec,event_key",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(expected_events.len(), 2);
        let registered_at_sec =
            crate::polling::pr_notifications::timestamp_second(&db, "2025-01-01T00:00:00Z")
                .unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        register_in(&tx, "owner/repo", "7", thread, Some(registered_at_sec)).unwrap();
        tx.commit().unwrap();

        let mut lifecycle: Vec<(String, String)> = crate::polling::pr_notifications::pending(&db)
            .unwrap()
            .into_iter()
            .filter(|notice| notice.thread == thread)
            .map(|notice| (notice.event, notice.event_key))
            .collect();
        assert_eq!(lifecycle.len(), 2, "close and reopen must be replayed");
        lifecycle.sort();
        assert_eq!(lifecycle, expected_events);
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        register_in(&tx, "owner/repo", "7", thread, Some(registered_at_sec)).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            crate::polling::pr_notifications::pending(&db)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn expired_verified_pre_survives_cleanup_until_reconcile_consumes_candidate() {
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
        assert_eq!(
            record.state,
            crate::pr_observation::CandidateState::Verified
        );

        db.execute(
            "UPDATE pr_hook_pre_observations SET expires_at_ms=0 WHERE tool_use_id=?1",
            [call],
        )
        .unwrap();
        assert_eq!(
            crate::pr_observation::cleanup_expired_pre(&db, unix_now_ms()).unwrap(),
            0,
            "an unconsumed verified candidate must retain its linked PreToolUse row"
        );

        let empty = std::path::PathBuf::new();
        let config = crate::manager::Config {
            state: empty.clone(),
            runtime: empty.clone(),
            config: empty.clone(),
            unit: empty.clone(),
            db: empty.clone(),
            codex: empty.clone(),
            gh: empty.clone(),
            webhooks_enabled: false,
            codex_home: empty.clone(),
            rpc_socket: empty.clone(),
            cache: empty,
            plugin_base: None,
        };
        reconcile(&mut db, &config, unix_now_ms()).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM automatic_pr_rules", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1,
            "reconcile must register the verified candidate after cleanup"
        );
        let consumed_at: Option<i64> = db
            .query_row(
                "SELECT consumed_at_ms FROM pr_hook_candidates WHERE id=?1",
                [record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(consumed_at.is_some());
        assert_eq!(
            crate::pr_observation::cleanup_expired_pre(&db, i64::MAX).unwrap(),
            1,
            "a consumed verified candidate must release its expired PreToolUse row"
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM pr_hook_pre_observations WHERE tool_use_id=?1",
                [call],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );

        let event_at = utc_timestamp(observed_at_ms + 10_000);
        let eligible_rules: i64 = db
            .query_row(
                "SELECT count(*) FROM rules WHERE datetime(updated)<=datetime(?1)",
                [&event_at],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            eligible_rules, 1,
            "creation boundary must admit earlier comments"
        );
        let stored_boundary: i64 = db
            .query_row(
                "SELECT CAST(strftime('%s', r.updated) AS INTEGER)
                 FROM automatic_pr_rules a JOIN rules r ON r.id=a.rule_id
                 WHERE a.repo='owner/repo' AND a.pr='42' AND a.thread=?1",
                [session],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_boundary, (observed_at_ms + 1_000).div_euclid(1000));
        register(&mut db, "owner/repo", "42", session).unwrap();
        let preserved_boundary: i64 = db
            .query_row(
                "SELECT CAST(strftime('%s', r.updated) AS INTEGER)
                 FROM automatic_pr_rules a JOIN rules r ON r.id=a.rule_id
                 WHERE a.repo='owner/repo' AND a.pr='42' AND a.thread=?1",
                [session],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved_boundary, stored_boundary);
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
    fn persisted_ambiguous_pre_blocks_pending_registration() {
        let mut db = Connection::open_in_memory().unwrap();
        let now = unix_now_ms();
        let session = "11111111-1111-4111-8111-111111111111";
        let command = "gh pr create --repo owner/repo --title verified";
        let pre = serde_json::json!({
            "hook_event_name":"PreToolUse",
            "session_id":session,
            "turn_id":"turn-ambiguous-pre",
            "tool_use_id":"call-ambiguous-pre",
            "tool_name":"Bash",
            "tool_input":{"command":command}
        });
        crate::pr_observation::record_pre_tool_use(&mut db, &pre, now, 60_000).unwrap();
        let post = serde_json::json!({
            "hook_event_name":"PostToolUse",
            "session_id":session,
            "turn_id":"turn-ambiguous-pre",
            "tool_use_id":"call-ambiguous-pre",
            "tool_name":"Bash",
            "tool_input":{"command":command},
            "tool_response":"https://github.com/owner/repo/pull/42"
        });
        let transport = FixtureTransport {
            created_at: utc_timestamp(now),
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
            panic!("expected verified candidate")
        };
        assert_eq!(
            record.state,
            crate::pr_observation::CandidateState::Verified
        );
        let claimed = crate::pr_observation::claim_verified_pending(&mut db, now, 60_000, 1)
            .unwrap()
            .remove(0);
        db.execute(
            "UPDATE pr_hook_pre_observations SET state='ambiguous'
             WHERE tool_use_id='call-ambiguous-pre'",
            [],
        )
        .unwrap();

        assert!(!register_claimed_candidate(&mut db, &claimed, now + 60_000).unwrap());
        let (candidate_state, verified, consumed, registrations): (
            String,
            Option<String>,
            Option<i64>,
            i64,
        ) = db
            .query_row(
                "SELECT c.state,c.verified_json,c.consumed_at_ms,
                        (SELECT count(*) FROM automatic_pr_rules)
                 FROM pr_hook_candidates c WHERE c.id=?1",
                [claimed.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(candidate_state, "ambiguous");
        assert!(verified.is_none());
        assert!(consumed.is_none());
        assert_eq!(registrations, 0);
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
