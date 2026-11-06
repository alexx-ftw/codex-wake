//! Durable evidence for native user-message receipts.
//!
//! Incoming event acceptance is deliberately not evidence here. A duplicate is
//! confirmed only by two distinct server-side userMessage item IDs for the
//! same deterministic event/destination client ID.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

/// Canonical key from source-provided identifiers such as repository, run ID,
/// and attempt. Every component must come from the event or its registration.
pub fn source_fields_identity(scope: &str, fields: &[&str]) -> Result<String> {
    ensure!(
        !scope.is_empty() && !fields.is_empty(),
        "Source identity fields are required"
    );
    ensure!(
        fields.iter().all(|field| !field.is_empty()),
        "Source identity field is empty"
    );
    let mut hash = Sha256::new();
    hash.update(b"codex-wake/source-fields/v1\0");
    hash.update(scope.as_bytes());
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    let digest = hash.finalize();
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{encoded}"))
}

/// A GitHub comment ID plus its action identifies the event independently of a webhook delivery ID.
pub fn github_comment_event_identity(event_header: &str, source: &Value) -> Result<Option<String>> {
    if !matches!(
        event_header,
        "issue_comment" | "pull_request_review_comment"
    ) {
        return Ok(None);
    }
    let Some(action) = source.get("action").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !matches!(action, "created" | "edited") {
        return Ok(None);
    }
    let (Some(repo), Some(pr), Some(comment_id)) = (
        source
            .pointer("/repository/full_name")
            .and_then(Value::as_str),
        source
            .pointer(if event_header == "issue_comment" {
                "/issue/number"
            } else {
                "/pull_request/number"
            })
            .and_then(Value::as_u64),
        source.pointer("/comment/id").and_then(Value::as_u64),
    ) else {
        return Ok(None);
    };
    if repo.is_empty() || repo.len() > 255 || !repo.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Ok(None);
    }
    let mut fields = vec![
        event_header.to_owned(),
        repo.to_owned(),
        pr.to_string(),
        comment_id.to_string(),
        action.to_owned(),
    ];
    if action == "edited" {
        let Some(updated_at) = source
            .pointer("/comment/updated_at")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 255
                    && value.bytes().all(|byte| byte.is_ascii_graphic())
            })
        else {
            return Ok(None);
        };
        fields.push(updated_at.to_owned());
    }
    let fields = fields.iter().map(String::as_str).collect::<Vec<_>>();
    Ok(Some(source_fields_identity(
        "codex-wake/github-comment-event/v1",
        &fields,
    )?))
}

fn identity_component(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let component = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.as_u64()?.to_string(),
        _ => return None,
    };
    (!component.is_empty()
        && component.len() <= 255
        && component.bytes().all(|byte| byte.is_ascii_graphic()))
    .then_some(component)
}

fn subscription_identity(
    kind: &str,
    repo: &str,
    resource: &str,
    event: &str,
    outcome: &str,
    identity_kind: &str,
    components: Vec<Option<String>>,
) -> Result<Option<String>> {
    let Some(components) = components.into_iter().collect::<Option<Vec<_>>>() else {
        return Ok(None);
    };
    let scope = format!("codex-wake/subscription/{kind}/{identity_kind}/v1");
    let mut fields = vec![
        format!("repo:{repo}"),
        format!("resource:{resource}"),
        format!("event:{event}"),
        format!("outcome:{outcome}"),
    ];
    fields.extend(components);
    let fields = fields.iter().map(String::as_str).collect::<Vec<_>>();
    Ok(Some(source_fields_identity(&scope, &fields)?))
}

/// Return an event key only when the source supplies an event-specific stable ID.
/// Payload hashes and provider delivery-attempt IDs are not used.
pub fn subscription_event_identity(
    kind: &str,
    repo: &str,
    resource: &str,
    event: &str,
    outcome: &str,
    source: &Value,
) -> Result<Option<String>> {
    let explicit_id = identity_component(source.get("event_id").or_else(|| source.get("eventId")));
    let (identity_kind, components) = match (kind, event) {
        ("pull_request", "merged") => (
            "pull-request-merged",
            vec![identity_component(
                source.pointer("/pull_request/merged_at"),
            )],
        ),
        ("pull_request", "closed") => (
            "pull-request-closed",
            vec![identity_component(
                source
                    .pointer("/pull_request/closed_at")
                    .or_else(|| source.pointer("/pull_request/updated_at")),
            )],
        ),
        ("review", _) => (
            "pull-request-review",
            vec![identity_component(source.pointer("/review/id"))],
        ),
        ("deployment", _) => (
            "deployment-status",
            vec![identity_component(source.pointer("/deployment_status/id"))],
        ),
        ("job", _) => {
            let run_id = identity_component(source.pointer("/workflow_run/id"))
                .or_else(|| identity_component(source.get("execution_id")));
            let attempt = identity_component(source.pointer("/workflow_run/run_attempt"))
                .or_else(|| identity_component(source.get("attempt")));
            if run_id.is_some() && attempt.is_some() {
                (
                    "job-execution",
                    vec![run_id, attempt, Some(outcome.to_owned())],
                )
            } else if explicit_id.is_some() {
                ("explicit-event", vec![explicit_id.clone()])
            } else {
                return Ok(None);
            }
        }
        ("chat" | "thread" | "subagent", _) => {
            let turn_id = identity_component(source.get("turnId"));
            if turn_id.is_some() {
                ("native-turn", vec![turn_id])
            } else if explicit_id.is_some() {
                ("explicit-event", vec![explicit_id.clone()])
            } else {
                return Ok(None);
            }
        }
        _ if explicit_id.is_some() => ("explicit-event", vec![explicit_id.clone()]),
        _ => return Ok(None),
    };
    if let Some(key) = subscription_identity(
        kind,
        repo,
        resource,
        event,
        outcome,
        identity_kind,
        components,
    )? {
        return Ok(Some(key));
    }
    match explicit_id {
        Some(id) if identity_kind != "explicit-event" => subscription_identity(
            kind,
            repo,
            resource,
            event,
            outcome,
            "explicit-event",
            vec![Some(id)],
        ),
        _ => Ok(None),
    }
}

/// Derive the app-server clientUserMessageId from a source event and target chat.
pub fn client_user_message_id(event_key: &str, thread: &str) -> Result<String> {
    let thread = Uuid::parse_str(thread)
        .context("Destination thread must be a UUID")?
        .to_string();
    let mut hash = Sha256::new();
    hash.update(b"codex-wake/event-destination/v1\0");
    hash.update(event_key.as_bytes());
    hash.update([0]);
    hash.update(thread.as_bytes());
    let mut bytes: [u8; 16] = hash.finalize()[..16]
        .try_into()
        .expect("fixed digest length");
    // Keep the identifier UUID-shaped and mark it as a deterministic v5-style ID.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes).to_string())
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS delivery_evidence (
            event_key TEXT NOT NULL,
            target_thread TEXT NOT NULL,
            client_user_message_id TEXT NOT NULL,
            coverage_state TEXT NOT NULL CHECK(coverage_state IN ('unknown','duplicate_confirmed')),
            identity_verified INTEGER NOT NULL DEFAULT 0 CHECK(identity_verified IN (0,1)),
            warning_state TEXT NOT NULL DEFAULT 'not_attempted' CHECK(warning_state IN ('not_attempted','claimed','accepted_unconfirmed','outcome_unknown')),
            updated_ms INTEGER NOT NULL,
            PRIMARY KEY(event_key,target_thread),
            UNIQUE(client_user_message_id)
        );
        CREATE TABLE IF NOT EXISTS user_message_observations (
            event_key TEXT NOT NULL,
            target_thread TEXT NOT NULL,
            client_user_message_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            turn_id TEXT NOT NULL,
            observed_ms INTEGER NOT NULL,
            PRIMARY KEY(event_key,target_thread,item_id),
            FOREIGN KEY(event_key,target_thread) REFERENCES delivery_evidence(event_key,target_thread) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS user_message_observations_identity
            ON user_message_observations(client_user_message_id,item_id);
        -- Fewer than two positive observations always means coverage is unknown.",
    )?;
    Ok(())
}

/// Persist the identity before attempting a native delivery.
pub fn begin(
    db: &Connection,
    event_key: &str,
    thread: &str,
    identity_verified: bool,
) -> Result<(String, bool)> {
    initialize(db)?;
    let thread = Uuid::parse_str(thread)
        .context("Destination thread must be a UUID")?
        .to_string();
    let client_id = client_user_message_id(event_key, &thread)?;
    let inserted = db.execute(
        "INSERT INTO delivery_evidence(event_key,target_thread,client_user_message_id,coverage_state,identity_verified,updated_ms)
         VALUES(?1,?2,?3,'unknown',?4,?5)
         ON CONFLICT(event_key,target_thread) DO NOTHING",
        params![event_key, thread, client_id, identity_verified, now_ms()],
    )? == 1;
    let stored: String = db.query_row(
        "SELECT client_user_message_id FROM delivery_evidence WHERE event_key=?1 AND target_thread=?2",
        params![event_key, thread],
        |row| row.get(0),
    )?;
    ensure!(
        stored == client_id,
        "Stored event identity does not match derived client ID"
    );
    Ok((client_id, inserted))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationResult {
    pub distinct_receipts: i64,
    pub duplicate_confirmed: bool,
    /// True exactly once, when this call atomically claims the warning attempt.
    pub should_warn: bool,
}

/// Record one live native `userMessage` signal. Repeated started/completed
/// notifications for the same item ID remain a single receipt.
pub fn observe_user_message(
    db: &mut Connection,
    event_key: &str,
    thread: &str,
    client_id: &str,
    item_id: &str,
    turn_id: &str,
) -> Result<ObservationResult> {
    initialize(db)?;
    let thread = Uuid::parse_str(thread)
        .context("Observed thread must be a UUID")?
        .to_string();
    ensure!(
        !item_id.is_empty() && !turn_id.is_empty(),
        "Message item and turn IDs are required"
    );
    let tx = db.transaction()?;
    let expected: Option<(String, bool)> = tx
        .query_row(
            "SELECT client_user_message_id,identity_verified FROM delivery_evidence WHERE event_key=?1 AND target_thread=?2",
            params![event_key, thread],
            |row| Ok((row.get(0)?,row.get(1)?)),
        )
        .optional()?;
    let Some((expected_client_id, identity_verified)) = expected else {
        anyhow::bail!("No persisted delivery identity for observed message")
    };
    ensure!(
        expected_client_id == client_id,
        "Observed client ID does not match event and destination"
    );
    tx.execute(
        "INSERT OR IGNORE INTO user_message_observations(event_key,target_thread,client_user_message_id,item_id,turn_id,observed_ms)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![event_key, thread, client_id, item_id, turn_id, now_ms()],
    )?;
    let distinct_receipts: i64 = tx.query_row(
        "SELECT count(*) FROM user_message_observations WHERE event_key=?1 AND target_thread=?2 AND client_user_message_id=?3",
        params![event_key, thread, client_id],
        |row| row.get(0),
    )?;
    let duplicate_confirmed = identity_verified && distinct_receipts >= 2;
    tx.execute(
        "UPDATE delivery_evidence SET coverage_state=?1,updated_ms=?2 WHERE event_key=?3 AND target_thread=?4",
        params![if duplicate_confirmed { "duplicate_confirmed" } else { "unknown" }, now_ms(), event_key, thread],
    )?;
    let should_warn = duplicate_confirmed
        && tx.execute(
            "UPDATE delivery_evidence SET warning_state='claimed',updated_ms=?1
             WHERE event_key=?2 AND target_thread=?3 AND warning_state='not_attempted'",
            params![now_ms(), event_key, thread],
        )? == 1;
    tx.commit()?;
    Ok(ObservationResult {
        distinct_receipts,
        duplicate_confirmed,
        should_warn,
    })
}

/// Record the warning RPC outcome. Acceptance is deliberately not called delivery confirmation.
pub fn warning_outcome(
    db: &Connection,
    event_key: &str,
    thread: &str,
    accepted: bool,
) -> Result<()> {
    let next = if accepted {
        "accepted_unconfirmed"
    } else {
        "outcome_unknown"
    };
    db.execute(
        "UPDATE delivery_evidence SET warning_state=?1,updated_ms=?2
         WHERE event_key=?3 AND target_thread=?4 AND warning_state='claimed' AND coverage_state='duplicate_confirmed'",
        params![next, now_ms(), event_key, Uuid::parse_str(thread)?.to_string()],
    )?;
    Ok(())
}

/// Persist only notifications whose native fields bind them to this exact
/// event ID and destination. `item/started` and `item/completed` share the
/// same item ID and are idempotent in the observations table.
pub fn record_notifications(
    db: &mut Connection,
    event_key: &str,
    thread: &str,
    client_id: &str,
    notifications: &[Value],
) -> Result<(u64, bool)> {
    let mut matching = 0;
    let mut should_warn = false;
    for notification in notifications {
        if !matches!(
            notification["method"].as_str(),
            Some("item/started" | "item/completed")
        ) || notification
            .pointer("/params/threadId")
            .and_then(Value::as_str)
            != Some(thread)
            || notification
                .pointer("/params/item/type")
                .and_then(Value::as_str)
                != Some("userMessage")
            || notification
                .pointer("/params/item/clientId")
                .and_then(Value::as_str)
                != Some(client_id)
        {
            continue;
        }
        let (Some(item_id), Some(turn_id)) = (
            notification
                .pointer("/params/item/id")
                .and_then(Value::as_str),
            notification
                .pointer("/params/turnId")
                .and_then(Value::as_str),
        ) else {
            continue;
        };
        matching += 1;
        let result = observe_user_message(db, event_key, thread, client_id, item_id, turn_id)?;
        should_warn |= result.should_warn;
    }
    if matching == 0 {
        mark_unknown(db, event_key, thread)?;
    }
    Ok((matching, should_warn))
}

/// Queue one warning after duplicate evidence is durably claimed. The original
/// event input is never resent, and queue acceptance remains unconfirmed.
pub fn warn_once(
    db: &Connection,
    codex: &std::path::Path,
    event_key: &str,
    thread: &str,
) -> Result<()> {
    let warning_id = Uuid::new_v4().to_string();
    let warning = format!(
        "Codex Wake detected two distinct native userMessage items for one verified event delivery to this chat (event ID fingerprint {}). The original input was not resent by this warning.",
        &event_key[event_key.len().saturating_sub(12)..]
    );
    let accepted = crate::goals::rpc(
        codex,
        "thread/queue/add",
        serde_json::json!({"threadId":thread,"clientUserMessageId":warning_id,"input":[{"type":"text","text":warning,"text_elements":[]}]}),
    ).is_ok();
    warning_outcome(db, event_key, thread, accepted)
}

/// Mark missing signals or an interrupted RPC as incomplete coverage.
pub fn mark_unknown(db: &Connection, event_key: &str, thread: &str) -> Result<()> {
    db.execute(
        "UPDATE delivery_evidence SET coverage_state='unknown',updated_ms=?1
         WHERE event_key=?2 AND target_thread=?3 AND coverage_state!='duplicate_confirmed'",
        params![now_ms(), event_key, Uuid::parse_str(thread)?.to_string()],
    )?;
    Ok(())
}

pub fn status(db: &Connection) -> Result<Value> {
    initialize(db)?;
    let mut statement = db.prepare(
        "SELECT e.event_key,e.target_thread,e.client_user_message_id,e.coverage_state,e.identity_verified,
           CASE WHEN e.warning_state='claimed' THEN 'outcome_unknown' ELSE e.warning_state END,
           (SELECT count(*) FROM user_message_observations o WHERE o.event_key=e.event_key AND o.target_thread=e.target_thread)
         FROM delivery_evidence e ORDER BY e.updated_ms,e.event_key,e.target_thread",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(serde_json::json!({
                "event_key": row.get::<_, String>(0)?,
                "target_thread": row.get::<_, String>(1)?,
                "client_user_message_id": row.get::<_, String>(2)?,
                "coverage": row.get::<_, String>(3)?,
                "event_identity_verified": row.get::<_, bool>(4)?,
                "warning": row.get::<_, String>(5)?,
                "distinct_user_message_items": row.get::<_, i64>(6)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(serde_json::json!({
        "deliveries":rows,
        "evidence_source":"live_native_userMessage_notifications",
        "coverage_limits":{
            "turn_start":"Only matching notifications read on the request socket are captured; absence is unknown.",
            "queue_add":"Unknown. clientUserMessageId-to-clientId is not qualified for queue/add; no duplicate conclusion is drawn.",
            "cli":"Unknown. CLI queue output does not expose native userMessage item identities.",
            "subscriptions":"Configured native turn/start sends are observed only when the source supplies a stable event ID. CLI sends and source events without such IDs remain unknown.",
            "polling":"Polling can supply stable source IDs to rules, waits, and subscription dispatch; it is not recipient receipt evidence. Only distinct native userMessage item IDs confirm a duplicate."
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREAD: &str = "22222222-2222-4222-8222-222222222222";

    fn db() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    fn comment_event_key(id: u64) -> String {
        let source = serde_json::json!({
            "action":"created",
            "repository":{"full_name":"owner/repo"},
            "issue":{"number":7},
            "comment":{"id":id}
        });
        github_comment_event_identity("issue_comment", &source)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn github_comment_identity_uses_comment_id_action_and_edit_time() {
        let mut created = serde_json::json!({
            "action":"created",
            "repository":{"full_name":"owner/repo"},
            "issue":{"number":7},
            "comment":{"id":42,"body":"first"}
        });
        let first = github_comment_event_identity("issue_comment", &created)
            .unwrap()
            .unwrap();
        created["comment"]["body"] = serde_json::json!("edited body content");
        assert_eq!(
            Some(first.as_str()),
            github_comment_event_identity("issue_comment", &created)
                .unwrap()
                .as_deref()
        );
        created["action"] = serde_json::json!("edited");
        assert!(
            github_comment_event_identity("issue_comment", &created)
                .unwrap()
                .is_none()
        );
        created["comment"]["updated_at"] = serde_json::json!("2026-11-06T16:00:00Z");
        let edited = github_comment_event_identity("issue_comment", &created)
            .unwrap()
            .unwrap();
        created["comment"]["updated_at"] = serde_json::json!("2026-11-06T16:01:00Z");
        assert_ne!(
            edited,
            github_comment_event_identity("issue_comment", &created)
                .unwrap()
                .unwrap()
        );
        assert_ne!(
            client_user_message_id(&first, THREAD).unwrap(),
            client_user_message_id(&first, "33333333-3333-4333-8333-333333333333").unwrap()
        );
    }

    #[test]
    fn subscription_identity_uses_stable_event_fields_not_payload_content() {
        let first = serde_json::json!({"review":{"id":42,"body":"first"}});
        let changed = serde_json::json!({"review":{"id":42,"body":"changed"}});
        let other = serde_json::json!({"review":{"id":43,"body":"first"}});
        let submitted = subscription_event_identity(
            "review",
            "owner/repo",
            "7",
            "submitted",
            "approved",
            &first,
        )
        .unwrap()
        .unwrap();
        let submitted_retry = subscription_event_identity(
            "review",
            "owner/repo",
            "7",
            "submitted",
            "approved",
            &changed,
        )
        .unwrap()
        .unwrap();
        let approved = subscription_event_identity(
            "review",
            "owner/repo",
            "7",
            "approved",
            "approved",
            &changed,
        )
        .unwrap()
        .unwrap();
        assert_eq!(submitted, submitted_retry);
        assert_eq!(
            client_user_message_id(&submitted, THREAD).unwrap(),
            client_user_message_id(&submitted_retry, THREAD).unwrap()
        );
        assert_ne!(submitted, approved);
        assert_ne!(
            client_user_message_id(&submitted, THREAD).unwrap(),
            client_user_message_id(&approved, THREAD).unwrap()
        );
        assert_ne!(
            Some(submitted.as_str()),
            subscription_event_identity(
                "review",
                "owner/repo",
                "7",
                "submitted",
                "approved",
                &other,
            )
            .unwrap()
            .as_deref()
        );
        assert_eq!(
            None,
            subscription_event_identity(
                "artifact",
                "ci",
                "pkg",
                "available",
                "available",
                &serde_json::json!({"delivery_id":"retry-1","message":"same content is not an event ID"}),
            )
            .unwrap()
        );
    }

    #[test]
    fn reusable_refs_and_commit_shas_do_not_verify_event_identity() {
        let base_change = serde_json::json!({
            "changes":{"base":{"from":"A","to":"B"}},
            "pull_request":{"base":{}}
        });
        assert_eq!(
            None,
            subscription_event_identity(
                "pull_request",
                "owner/repo",
                "7",
                "base_changed",
                "base_changed",
                &base_change,
            )
            .unwrap()
        );
        for (old, new) in [("A", "B"), ("B", "A"), ("A", "B"), ("B", "A")] {
            let base_change = serde_json::json!({
                "changes":{"base":{"ref":old}},
                "pull_request":{"base":{"ref":new}}
            });
            assert_eq!(
                None,
                subscription_event_identity(
                    "pull_request",
                    "owner/repo",
                    "7",
                    "base_changed",
                    "base_changed",
                    &base_change,
                )
                .unwrap()
            );
        }
        let identified_base_change = serde_json::json!({
            "event_id":"base-change-event-1",
            "changes":{"base":{"from":"A","to":"B"}},
            "pull_request":{"base":{}}
        });
        let identified = subscription_event_identity(
            "pull_request",
            "owner/repo",
            "7",
            "base_changed",
            "base_changed",
            &identified_base_change,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            Some(identified.as_str()),
            subscription_event_identity(
                "pull_request",
                "owner/repo",
                "7",
                "base_changed",
                "base_changed",
                &identified_base_change,
            )
            .unwrap()
            .as_deref()
        );
        assert_eq!(
            None,
            subscription_event_identity(
                "pull_request",
                "owner/repo",
                "7",
                "synchronize",
                "synchronize",
                &serde_json::json!({"pull_request":{"head":{"sha":"reused-sha"}}}),
            )
            .unwrap()
        );
        assert_eq!(
            None,
            subscription_event_identity(
                "git_ref",
                "owner/repo",
                "main",
                "updated",
                "updated",
                &serde_json::json!({"ref":"refs/heads/main","after":"reused-sha"}),
            )
            .unwrap()
        );

        let retry = serde_json::json!({"event_id":"push-event-1","after":"reused-sha"});
        let first = subscription_event_identity(
            "git_ref",
            "owner/repo",
            "main",
            "updated",
            "updated",
            &retry,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            Some(first.as_str()),
            subscription_event_identity(
                "git_ref",
                "owner/repo",
                "main",
                "updated",
                "updated",
                &retry,
            )
            .unwrap()
            .as_deref()
        );
        assert_ne!(
            Some(first.as_str()),
            subscription_event_identity(
                "git_ref",
                "owner/repo",
                "main",
                "updated",
                "updated",
                &serde_json::json!({"event_id":"push-event-2","after":"reused-sha"}),
            )
            .unwrap()
            .as_deref()
        );
    }

    #[test]
    fn native_poll_identity_binds_turn_and_destination() {
        let source = serde_json::json!({"turnId":"turn-123","status":"completed"});
        let event = subscription_event_identity(
            "thread",
            "",
            "11111111-1111-4111-8111-111111111111",
            "turn_completed",
            "turn_completed",
            &source,
        )
        .unwrap()
        .unwrap();
        assert_ne!(
            client_user_message_id(&event, "22222222-2222-4222-8222-222222222222").unwrap(),
            client_user_message_id(&event, "33333333-3333-4333-8333-333333333333").unwrap()
        );
        assert_ne!(
            event,
            subscription_event_identity(
                "thread",
                "",
                "11111111-1111-4111-8111-111111111111",
                "turn_completed",
                "turn_completed",
                &serde_json::json!({"turnId":"turn-124","status":"completed"}),
            )
            .unwrap()
            .unwrap()
        );
    }

    #[test]
    fn same_item_started_and_completed_counts_once_and_distinct_items_claim_one_warning() {
        let mut db = db();
        let event = comment_event_key(7);
        let (client, first) = begin(&db, &event, THREAD, true).unwrap();
        assert!(first);
        assert!(!begin(&db, &event, THREAD, true).unwrap().1);
        assert_eq!(
            observe_user_message(&mut db, &event, THREAD, &client, "item-1", "turn-1").unwrap(),
            ObservationResult {
                distinct_receipts: 1,
                duplicate_confirmed: false,
                should_warn: false
            }
        );
        assert_eq!(
            observe_user_message(&mut db, &event, THREAD, &client, "item-1", "turn-1")
                .unwrap()
                .distinct_receipts,
            1
        );
        assert_eq!(
            observe_user_message(&mut db, &event, THREAD, &client, "item-2", "turn-2").unwrap(),
            ObservationResult {
                distinct_receipts: 2,
                duplicate_confirmed: true,
                should_warn: true
            }
        );
        assert!(
            !observe_user_message(&mut db, &event, THREAD, &client, "item-2", "turn-2")
                .unwrap()
                .should_warn
        );
    }

    #[test]
    fn missing_coverage_is_unknown_but_two_positive_items_stay_confirmed() {
        let mut db = db();
        let event = comment_event_key(9);
        let (client, _) = begin(&db, &event, THREAD, true).unwrap();
        observe_user_message(&mut db, &event, THREAD, &client, "item-1", "turn-1").unwrap();
        assert_eq!(status(&db).unwrap()["deliveries"][0]["coverage"], "unknown");
        observe_user_message(&mut db, &event, THREAD, &client, "item-2", "turn-2").unwrap();
        assert_eq!(
            status(&db).unwrap()["deliveries"][0]["coverage"],
            "duplicate_confirmed"
        );
    }

    #[test]
    fn unverified_event_identity_never_confirms_a_duplicate() {
        let mut db = db();
        let event = comment_event_key(11);
        let (client, _) = begin(&db, &event, THREAD, false).unwrap();
        observe_user_message(&mut db, &event, THREAD, &client, "item-1", "turn-1").unwrap();
        let second =
            observe_user_message(&mut db, &event, THREAD, &client, "item-2", "turn-2").unwrap();
        assert_eq!(second.distinct_receipts, 2);
        assert!(!second.duplicate_confirmed);
        assert!(!second.should_warn);
        let status = status(&db).unwrap();
        assert_eq!(status["deliveries"][0]["coverage"], "unknown");
        assert_eq!(status["deliveries"][0]["event_identity_verified"], false);
    }
}
