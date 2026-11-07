//! Read-only, bounded coordination snapshot grouped by chat.
//!
//! This module intentionally selects only identifiers, state and small metadata. It never
//! returns prompts, message bodies, payloads, descriptions, evidence or execution options.
use anyhow::Result;
use rusqlite::{Connection, params};
use serde_json::{Value, json};

const CONDITION_SELECTOR_LIMIT: i64 = 32;

/// Return one page of chats and a bounded page of each coordination category per chat.
///
/// `offset` and `limit` paginate chats; `per_chat_limit` bounds every category within each
/// returned chat. Each category reports its total and whether rows were omitted.
pub fn by_chat(
    db: &Connection,
    offset: u32,
    limit: u32,
    per_chat_limit: u32,
    condition_groups_offset: u32,
    condition_selectors_offset: u32,
) -> Result<Value> {
    let limit = limit.clamp(1, 100);
    let per_chat_limit = per_chat_limit.clamp(1, 100);
    let chat_limit = i64::from(limit);
    let row_limit = i64::from(per_chat_limit) + 1;
    let offset = i64::from(offset);
    let condition_groups_offset = i64::from(condition_groups_offset);
    let condition_selectors_offset = i64::from(condition_selectors_offset);
    let selector_limit = i64::from(per_chat_limit).min(CONDITION_SELECTOR_LIMIT);
    // One deferred read transaction keeps the chat page, category totals and rows on one snapshot.
    let tx = db.unchecked_transaction()?;

    let total_chats: i64 = tx.query_row(
        "SELECT count(*) FROM (
            SELECT thread AS chat FROM waits
            UNION SELECT thread FROM subscriptions
            UNION SELECT thread FROM obligations
            UNION SELECT target_thread FROM condition_groups
            UNION SELECT responsible FROM coordinators
            UNION SELECT coordinator FROM coordinators
            UNION SELECT responsible FROM coordinator_alerts
            UNION SELECT coordinator FROM coordinator_alerts
            UNION SELECT thread FROM circular_waits
            UNION SELECT waits_for FROM circular_waits WHERE waits_for NOT LIKE 'resource:%'
            UNION SELECT source_thread FROM obligation_transfers
            UNION SELECT target_thread FROM obligation_transfers
            UNION SELECT target_thread FROM condition_alerts
        )",
        [],
        |row| row.get(0),
    )?;
    let mut statement = tx.prepare(
        "SELECT chat FROM (
            SELECT thread AS chat FROM waits
            UNION SELECT thread FROM subscriptions
            UNION SELECT thread FROM obligations
            UNION SELECT target_thread FROM condition_groups
            UNION SELECT responsible FROM coordinators
            UNION SELECT coordinator FROM coordinators
            UNION SELECT responsible FROM coordinator_alerts
            UNION SELECT coordinator FROM coordinator_alerts
            UNION SELECT thread FROM circular_waits
            UNION SELECT waits_for FROM circular_waits WHERE waits_for NOT LIKE 'resource:%'
            UNION SELECT source_thread FROM obligation_transfers
            UNION SELECT target_thread FROM obligation_transfers
            UNION SELECT target_thread FROM condition_alerts
        ) ORDER BY chat LIMIT ?1 OFFSET ?2",
    )?;
    let chats = statement
        .query_map(params![chat_limit, offset], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let page_chat_count = chats.len() as i64;
    let mut result = Vec::with_capacity(chats.len());
    for chat in chats {
        let mut conditions = category_page(
            &tx,
            "SELECT id,mode,state,depends_on,depends_on_mode,created,reason FROM condition_groups WHERE target_thread=?1 ORDER BY created DESC,id",
            &chat,
            i64::from(per_chat_limit),
            condition_groups_offset,
            |r| {
                let reason: Option<String> = r.get(6)?;
                Ok(
                    json!({"id":r.get::<_,String>(0)?,"mode":r.get::<_,String>(1)?,"state":r.get::<_,String>(2)?,"depends_on":r.get::<_,Option<String>>(3)?,"depends_on_mode":r.get::<_,Option<String>>(4)?,"created":r.get::<_,String>(5)?,"reason":safe_reason(reason.as_deref())}),
                )
            },
        )?;
        if let Some(groups) = conditions["items"].as_array_mut() {
            for group in groups {
                let id = group["id"].as_str().unwrap_or_default();
                group["selectors"] =
                    condition_selectors(&tx, id, selector_limit, condition_selectors_offset)?;
            }
        }
        result.push(json!({
            "chat": chat,
            "thread_ref": format!("codex://threads/{chat}"),
            "conditions": conditions,
            "condition_alerts": category(&tx, "SELECT id,ambiguity,group_id,kind,repo,resource,event,outcome,state,reason,created,updated,ambiguous_cursor FROM condition_alerts WHERE target_thread=?1 ORDER BY created DESC,id", &chat, row_limit, |r| { let state: String = r.get(8)?; let reason: Option<String> = r.get(9)?; Ok(json!({"id":r.get::<_,String>(0)?,"ambiguity":r.get::<_,String>(1)?,"group_id":r.get::<_,String>(2)?,"kind":r.get::<_,String>(3)?,"repo":r.get::<_,String>(4)?,"resource":r.get::<_,String>(5)?,"event":r.get::<_,String>(6)?,"outcome":r.get::<_,String>(7)?,"state":state,"delivery":delivery_state(&state),"reason":safe_reason(reason.as_deref()),"created":r.get::<_,String>(10)?,"updated":r.get::<_,String>(11)?,"ambiguous_cursor":r.get::<_,Option<String>>(12)?})) })?,
            "coordinators": category(&tx, "SELECT responsible,coordinator FROM coordinators WHERE responsible=?1 OR coordinator=?1 ORDER BY responsible,coordinator", &chat, row_limit, |r| Ok(json!({"responsible":r.get::<_,String>(0)?,"coordinator":r.get::<_,String>(1)?})))?,
            "waits": category(&tx, "SELECT repo,run_id,attempt,sha,state,conclusion,updated,reason FROM waits WHERE thread=?1 ORDER BY updated DESC,repo,run_id,attempt", &chat, row_limit, |r| { let state: String = r.get(4)?; let reason: Option<String> = r.get(7)?; Ok(json!({"repo":r.get::<_,String>(0)?,"run_id":r.get::<_,i64>(1)?,"attempt":r.get::<_,i64>(2)?,"sha":r.get::<_,String>(3)?,"state":state,"conclusion":r.get::<_,Option<String>>(5)?,"updated":r.get::<_,String>(6)?,"reason":safe_reason(reason.as_deref()),"delivery":delivery_state(&state)})) })?,
            "circular_waits": category(&tx, "SELECT id,thread,waits_for,continuation,continuation_ref,active FROM circular_waits WHERE thread=?1 OR waits_for=?1 ORDER BY rowid DESC", &chat, row_limit, |r| Ok(json!({"id":r.get::<_,String>(0)?,"thread":r.get::<_,String>(1)?,"waits_for":r.get::<_,String>(2)?,"continuation":r.get::<_,String>(3)?,"continuation_ref":r.get::<_,Option<String>>(4)?,"active":r.get::<_,i64>(5)? != 0})))?,
            "subscriptions": category(&tx, "SELECT id,kind,repo,resource,event,state,outcome,updated,reason,expires_at_ms,expiration_notice_state,expiration_notice_reason FROM subscriptions WHERE thread=?1 ORDER BY updated DESC,id", &chat, row_limit, |r| { let state: String = r.get(5)?; let reason: Option<String> = r.get(8)?; let notice_reason: Option<String> = r.get(11)?; Ok(json!({"id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"repo":r.get::<_,String>(2)?,"resource":r.get::<_,String>(3)?,"event":r.get::<_,String>(4)?,"state":state,"outcome":r.get::<_,Option<String>>(6)?,"updated":r.get::<_,String>(7)?,"reason":safe_reason(reason.as_deref()),"delivery":delivery_state(&state),"expires_at_ms":r.get::<_,Option<i64>>(9)?,"expiration_notice_state":r.get::<_,Option<String>>(10)?,"expiration_notice_reason":safe_reason(notice_reason.as_deref())})) })?,
            "obligations": category(&tx, "SELECT id,kind,repo,resource,outcome,resolved FROM obligations WHERE thread=?1 ORDER BY rowid DESC", &chat, row_limit, |r| Ok(json!({"id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"repo":r.get::<_,String>(2)?,"resource":r.get::<_,String>(3)?,"outcome":r.get::<_,String>(4)?,"resolved":r.get::<_,i64>(5)? != 0})))?,
            "transfers": category(&tx, "SELECT id,obligation_id,source_thread,target_thread,state,notification_state,notification_updated_at,created_at,accepted_at,notification_reason FROM obligation_transfers WHERE source_thread=?1 OR target_thread=?1 ORDER BY created_at DESC,id", &chat, row_limit, |r| { let state: String = r.get(4)?; let notification: String = r.get(5)?; let reason: Option<String> = r.get(9)?; Ok(json!({"id":r.get::<_,String>(0)?,"obligation_id":r.get::<_,String>(1)?,"source_thread":r.get::<_,String>(2)?,"target_thread":r.get::<_,String>(3)?,"state":state,"notification_state":notification,"notification_reason":safe_reason(reason.as_deref()),"notification_delivery":delivery_state(&notification),"notification_updated_at":r.get::<_,String>(6)?,"created_at":r.get::<_,String>(7)?,"accepted_at":r.get::<_,Option<String>>(8)?})) })?,
            "alerts": category(&tx, "SELECT id,responsible,coordinator,state,created,updated,reason FROM coordinator_alerts WHERE responsible=?1 OR coordinator=?1 ORDER BY created DESC,id", &chat, row_limit, |r| { let state: String = r.get(3)?; let reason: Option<String> = r.get(6)?; Ok(json!({"id":r.get::<_,String>(0)?,"responsible":r.get::<_,String>(1)?,"coordinator":r.get::<_,String>(2)?,"state":state,"reason":safe_reason(reason.as_deref()),"delivery":delivery_state(&state),"created":r.get::<_,String>(4)?,"updated":r.get::<_,String>(5)?})) })?
        }));
    }
    let next_offset = offset + page_chat_count;
    let result = json!({
        "chats": result,
        "page": {
            "offset": offset,
            "limit": limit,
            "total_chats": total_chats,
            "has_more": next_offset < total_chats,
            "next_offset": if next_offset < total_chats { Some(next_offset) } else { None::<i64> },
            "per_chat_limit": per_chat_limit,
            "condition_selector_limit": selector_limit
        }
    });
    tx.commit()?;
    Ok(result)
}

fn condition_selectors(db: &Connection, group_id: &str, limit: i64, offset: i64) -> Result<Value> {
    let total: i64 = db.query_row(
        "SELECT count(*) FROM condition_members WHERE group_id=?1",
        [group_id],
        |row| row.get(0),
    )?;
    let mut statement = db.prepare(
        "SELECT m.kind,m.repo,m.resource,m.event,m.outcome,m.matched,m.armed,m.buffer_overflow,m.buffer_overflow_count,COALESCE(o.baseline_order_uncertain,0),CASE WHEN o.baseline_order_uncertain=1 THEN o.baseline_turn_id ELSE NULL END,m.order_uncertain,m.ambiguous_cursor,m.ci_run_id,m.ci_attempt,m.ci_sha FROM condition_members m LEFT JOIN native_condition_observers o ON o.group_id=m.group_id AND o.kind=m.kind AND o.repo=m.repo AND o.resource=m.resource AND o.event=m.event AND o.outcome=m.outcome
         WHERE m.group_id=?1 ORDER BY m.kind,m.repo,m.resource,m.event,m.outcome LIMIT ?2 OFFSET ?3",
    )?;
    let mut items = statement
        .query_map(params![group_id, limit + 1, offset], |row| {
            let kind: String = row.get(0)?;
            let outcome: String = row.get(4)?;
            let baseline_uncertain = row.get::<_, i64>(9)? != 0;
            let order_uncertain = row.get::<_, i64>(11)? != 0;
            let ambiguous_cursor: Option<String> = row.get(12)?;
            let is_pull_request = kind == "pull_request";
            let is_ci = kind == "job";
            let uncertainty_type = if baseline_uncertain {
                Some("native_baseline_order_uncertain")
            } else if order_uncertain && is_pull_request {
                Some("pr_baseline_order_uncertain")
            } else if order_uncertain && is_ci {
                Some("ci_order_uncertain")
            } else if order_uncertain {
                Some("order_uncertain")
            } else {
                None
            };
            Ok(json!({
                "kind":kind,
                "repo":row.get::<_,String>(1)?,
                "resource":row.get::<_,String>(2)?,
                "event":row.get::<_,String>(3)?,
                "outcome":if outcome.is_empty() { Value::Null } else { json!(outcome) },
                "matched":row.get::<_,i64>(5)? != 0,
                "armed":row.get::<_,i64>(6)? != 0,
                "buffer_overflow":row.get::<_,i64>(7)? != 0,
                "buffer_overflow_count":row.get::<_,i64>(8)?,
                "baseline_order_uncertain":baseline_uncertain,
                "ambiguous_turn_id":row.get::<_,Option<String>>(10)?,
                "order_uncertain":order_uncertain || baseline_uncertain,
                "order_uncertainty_type":uncertainty_type,
                "ambiguous_cursor":if order_uncertain { ambiguous_cursor.clone() } else { None },
                "pr_order_uncertain":is_pull_request && order_uncertain,
                "ambiguous_pr_cursor":if is_pull_request && order_uncertain { ambiguous_cursor.clone() } else { None },
                "ci_order_uncertain":is_ci && order_uncertain,
                "ambiguous_ci_time":if is_ci { ambiguous_cursor } else { None },
                "ci":if row.get::<_,i64>(13)? > 0 { json!({"run_id":row.get::<_,i64>(13)?,"attempt":row.get::<_,i64>(14)?,"sha":row.get::<_,String>(15)?}) } else { Value::Null }
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let truncated = items.len() as i64 > limit;
    if truncated {
        items.pop();
    }
    let next_offset = offset + items.len() as i64;
    Ok(
        json!({"items":items,"total":total,"truncated":truncated,"offset":offset,"limit":limit,"has_more":next_offset < total,"next_offset":if next_offset < total { Some(next_offset) } else { None::<i64> }}),
    )
}

fn delivery_state(state: &str) -> &'static str {
    match state {
        "queued" => "queued_execution_unverified",
        "sending" => "sending_execution_unverified",
        "ready" => "ready_not_sent",
        "send_failed" => "retryable_pre_send_failure",
        "cancelled" => "cancelled_before_send",
        "needs_attention" | "uncertain" => "attention_delivery_or_execution_uncertain",
        _ => "not_applicable_or_not_verified",
    }
}

/// Map free-form persisted errors to a closed, non-sensitive diagnostic vocabulary.
fn safe_reason(reason: Option<&str>) -> Option<&'static str> {
    let reason = reason?;
    let code = reason.split_once(':').map_or(reason, |(code, _)| code);
    Some(match code {
        "template_error" => "template_error",
        "execution_options_error" => "execution_options_error",
        "send_outcome_unknown" => "send_outcome_unknown",
        "uncertainty_resolved" => "uncertainty_resolved",
        "condition_no_longer_pending" => "condition_no_longer_pending",
        "sender_exit_confirmed" => "sender_exit_confirmed",
        "target_busy_before_send" => "target_busy_before_send",
        "target_unavailable_before_send" => "target_unavailable_before_send",
        "executable_not_found" => "executable_not_found",
        "resume_owned_by_active_writer" => "resume_owned_by_active_writer",
        "resume_daemon_unavailable" => "resume_daemon_unavailable",
        "queued_but_recipient_not_resumed" => "queued_but_recipient_not_resumed",
        "cli_warning_or_nonzero_exit" => "cli_warning_or_nonzero_exit",
        "timeout_delivery_unknown" => "timeout_delivery_unknown",
        "os_error_delivery_unknown" => "os_error_delivery_unknown",
        "invalid_send_classification" => "invalid_send_classification",
        "expiration_notice_not_queued" => "expiration_notice_not_queued",
        "subscription_expired" => "subscription_expired",
        "send_needs_attention" => "send_needs_attention",
        "send_error_outcome_unknown" => "send_error_outcome_unknown",
        "timeout" => "timeout",
        "connection_refused" => "connection_refused",
        "invalid_native_baseline" => "invalid_native_baseline",
        "native_baseline_unavailable" => "native_baseline_unavailable",
        "native_poll_error" => "native_poll_error",
        "native_queue_error" => "native_queue_error",
        "queue_uncertain" => "queue_uncertain",
        "native_queue_accepted" => "native_queue_accepted",
        "goal_active_input_queued" => "goal_active_input_queued",
        "goal_changed_after_queue_input_queued" => "goal_changed_after_queue_input_queued",
        "goal_version_unavailable_after_queue_input_queued" => {
            "goal_version_unavailable_after_queue_input_queued"
        }
        "goal_reconcile_unavailable" => "goal_reconcile_unavailable",
        "goal_active_after_interrupted_activation" => "goal_active_after_interrupted_activation",
        "goal_activation_interrupted_input_queued" => "goal_activation_interrupted_input_queued",
        "legacy_collision" => "legacy_collision",
        "interrupt_ready_v1" => "interrupt_ready",
        _ => "other",
    })
}

fn category(
    db: &Connection,
    sql: &str,
    chat: &str,
    limit_plus_one: i64,
    map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
) -> Result<Value> {
    let count_sql = format!("SELECT count(*) FROM ({sql})");
    let total: i64 = db.query_row(&count_sql, [chat], |row| row.get(0))?;
    let page_sql = format!("{sql} LIMIT ?2");
    let mut statement = db.prepare(&page_sql)?;
    let mut rows = statement
        .query_map(params![chat, limit_plus_one], map)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let truncated = rows.len() as i64 > limit_plus_one - 1;
    if truncated {
        rows.pop();
    }
    Ok(json!({"items":rows,"total":total,"truncated":truncated}))
}

fn category_page(
    db: &Connection,
    sql: &str,
    chat: &str,
    limit: i64,
    offset: i64,
    map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
) -> Result<Value> {
    let count_sql = format!("SELECT count(*) FROM ({sql})");
    let total: i64 = db.query_row(&count_sql, [chat], |row| row.get(0))?;
    let page_sql = format!("{sql} LIMIT ?2 OFFSET ?3");
    let mut statement = db.prepare(&page_sql)?;
    let mut rows = statement
        .query_map(params![chat, limit + 1, offset], map)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() as i64 > limit {
        rows.pop();
    }
    let next_offset = offset + rows.len() as i64;
    Ok(
        json!({"items":rows,"total":total,"truncated":next_offset < total,"offset":offset,"limit":limit,"has_more":next_offset < total,"next_offset":if next_offset < total { Some(next_offset) } else { None::<i64> }}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = crate::bridge::connect(&dir.path().join("wake.sqlite")).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::conditions::initialize(&db).unwrap();
        crate::condition_alerts::initialize(&db).unwrap();
        crate::native_poll::initialize(&db).unwrap();
        crate::obligations::initialize(&db).unwrap();
        crate::circular_waits::initialize(&db).unwrap();
        (dir, db)
    }

    #[test]
    fn groups_safe_references_and_distinguishes_queued_from_execution() {
        let (_dir, db) = db();
        db.execute("INSERT INTO waits(repo,run_id,attempt,thread,sha,state,updated,reason,message_template,source_json,execution_json) VALUES('o/r',1,2,'chat-a','abc','queued','now','send_outcome_unknown: SECRET DETAIL','SECRET PROMPT','SECRET PAYLOAD','SECRET')", []).unwrap();
        db.execute("INSERT INTO subscriptions(id,kind,repo,resource,event,thread,state,outcome,updated,reason,message_template,source_json,execution_json) VALUES('sub','chat','o/r','17','completed','chat-a','queued','done','now','template_error: SECRET DETAIL','SECRET','SECRET','SECRET')", []).unwrap();
        db.execute("INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES('obl','chat-a','ci','o/r','17','passed','SECRET DESCRIPTION')", []).unwrap();
        db.execute("INSERT INTO coordinator_alerts(id,responsible,coordinator,message,state,reason) VALUES('alert','chat-a','chat-b','SECRET MESSAGE','queued','timeout: SECRET DETAIL')", []).unwrap();
        let view = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        assert_eq!(view["chats"].as_array().unwrap().len(), 2);
        let a = &view["chats"][0];
        assert_eq!(a["chat"], "chat-a");
        assert_eq!(
            a["waits"]["items"][0]["delivery"],
            "queued_execution_unverified"
        );
        assert_eq!(
            a["subscriptions"]["items"][0]["delivery"],
            "queued_execution_unverified"
        );
        assert_eq!(a["waits"]["items"][0]["reason"], "send_outcome_unknown");
        assert_eq!(a["subscriptions"]["items"][0]["reason"], "template_error");
        assert_eq!(a["coordinators"]["items"].as_array().unwrap().len(), 0);
        assert_eq!(a["alerts"]["items"][0]["reason"], "timeout");
        let encoded = view.to_string();
        for secret in [
            "SECRET PROMPT",
            "SECRET PAYLOAD",
            "SECRET DESCRIPTION",
            "SECRET MESSAGE",
        ] {
            assert!(!encoded.contains(secret));
        }
    }

    #[test]
    fn paginates_chats_and_marks_per_chat_truncation() {
        let (_dir, db) = db();
        for (chat, id) in [("a", "1"), ("a", "2"), ("b", "3")] {
            db.execute(
                "INSERT INTO obligations(id,thread,kind,repo,resource,outcome,description) VALUES(?1,?2,'kind','','','outcome','private')",
                params![id, chat],
            )
            .unwrap();
        }
        let first = by_chat(&db, 0, 1, 1, 0, 0).unwrap();
        assert_eq!(first["chats"].as_array().unwrap().len(), 1);
        assert_eq!(first["chats"][0]["obligations"]["total"], 2);
        assert_eq!(
            first["chats"][0]["obligations"]["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(first["chats"][0]["obligations"]["truncated"], true);
        assert_eq!(first["page"]["has_more"], true);
        let second = by_chat(&db, 1, 1, 1, 0, 0).unwrap();
        assert_eq!(second["chats"][0]["chat"], "b");
        assert_eq!(second["page"]["has_more"], false);
    }

    #[test]
    fn includes_coordinator_only_chats_and_relationships() {
        let (_dir, db) = db();
        db.execute(
            "INSERT INTO coordinators(responsible,coordinator) VALUES('responsible-only','coordinator-only')",
            [],
        )
        .unwrap();
        let view = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        assert_eq!(view["page"]["total_chats"], 2);
        assert_eq!(view["chats"][0]["chat"], "coordinator-only");
        assert_eq!(
            view["chats"][0]["coordinators"]["items"][0]["responsible"],
            "responsible-only"
        );
        assert_eq!(view["chats"][1]["chat"], "responsible-only");
        assert_eq!(
            view["chats"][1]["coordinators"]["items"][0]["coordinator"],
            "coordinator-only"
        );
    }

    #[test]
    fn circular_wait_rows_identify_the_dependent_chat() {
        let (_dir, db) = db();
        let dependent = "11111111-1111-4111-8111-111111111111";
        let waited_on = "22222222-2222-4222-8222-222222222222";
        db.execute(
            "INSERT INTO circular_waits(id,thread,waits_for,evidence) VALUES('wait-1',?1,?2,'evidence')",
            params![dependent, waited_on],
        )
        .unwrap();

        let view = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        let row = &view["chats"][1]["circular_waits"]["items"][0];
        assert_eq!(view["chats"][1]["chat"], waited_on);
        assert_eq!(row["thread"], dependent);
        assert_eq!(row["waits_for"], waited_on);
    }

    #[test]
    fn includes_condition_groups_in_their_destination_chat() {
        let (_dir, db) = db();
        let chat = "11111111-1111-4111-8111-111111111111";
        let id = crate::conditions::register_group(
            &db,
            crate::conditions::Mode::And,
            &[crate::conditions::Selector {
                kind: "artifact".into(),
                repo: "ci".into(),
                resource: "package".into(),
                event: "available".into(),
                outcome: None,
            }],
            chat,
            None,
            None,
        )
        .unwrap();
        let view = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        assert_eq!(view["chats"][0]["chat"], chat);
        assert_eq!(view["chats"][0]["conditions"]["items"][0]["id"], id);
        assert_eq!(
            view["chats"][0]["conditions"]["items"][0]["state"],
            "pending"
        );
        assert_eq!(
            view["chats"][0]["conditions"]["items"][0]["reason"],
            Value::Null
        );
        assert_eq!(
            view["chats"][0]["conditions"]["items"][0]["selectors"]["items"][0]["armed"],
            true
        );
    }

    #[test]
    fn condition_groups_can_continue_past_the_page_limit() {
        let (_dir, db) = db();
        let chat = "11111111-1111-4111-8111-111111111111";
        for index in 0..101 {
            db.execute(
                "INSERT INTO condition_groups(id,mode,target_thread,created) VALUES(?1,'and',?2,'2026-01-01T00:00:00Z')",
                params![format!("group-{index:03}"), chat],
            )
            .unwrap();
        }

        let first = by_chat(&db, 0, 10, 100, 0, 0).unwrap();
        let first_page = &first["chats"][0]["conditions"];
        assert_eq!(first_page["items"].as_array().unwrap().len(), 100);
        assert_eq!(first_page["total"], 101);
        assert_eq!(first_page["has_more"], true);
        assert_eq!(first_page["next_offset"], 100);

        let second = by_chat(&db, 0, 10, 100, 100, 0).unwrap();
        let second_page = &second["chats"][0]["conditions"];
        assert_eq!(second_page["items"].as_array().unwrap().len(), 1);
        assert_eq!(second_page["items"][0]["id"], "group-100");
        assert_eq!(second_page["has_more"], false);
        assert_eq!(second_page["next_offset"], Value::Null);
    }

    #[test]
    fn condition_selectors_can_continue_past_the_page_limit() {
        let (_dir, db) = db();
        let chat = "11111111-1111-4111-8111-111111111111";
        let selectors: Vec<_> = (0..33)
            .map(|index| crate::conditions::Selector {
                kind: "artifact".into(),
                repo: "ci".into(),
                resource: format!("selector-{index:02}"),
                event: "available".into(),
                outcome: None,
            })
            .collect();
        crate::conditions::register_group(
            &db,
            crate::conditions::Mode::And,
            &selectors,
            chat,
            None,
            None,
        )
        .unwrap();

        let first = by_chat(&db, 0, 10, 100, 0, 0).unwrap();
        let first_page = &first["chats"][0]["conditions"]["items"][0]["selectors"];
        assert_eq!(first_page["items"].as_array().unwrap().len(), 32);
        assert_eq!(first_page["total"], 33);
        assert_eq!(first_page["has_more"], true);
        assert_eq!(first_page["next_offset"], 32);

        let second = by_chat(&db, 0, 10, 100, 0, 32).unwrap();
        let second_page = &second["chats"][0]["conditions"]["items"][0]["selectors"];
        assert_eq!(second_page["items"].as_array().unwrap().len(), 1);
        assert_eq!(second_page["items"][0]["resource"], "selector-32");
        assert_eq!(second_page["has_more"], false);
        assert_eq!(second_page["next_offset"], Value::Null);
    }

    #[test]
    fn condition_alerts_are_exposed_with_delivery_state_under_the_destination_chat() {
        let (_dir, db) = db();
        let chat = "11111111-1111-4111-8111-111111111111";
        db.execute(
            "INSERT INTO condition_alerts
             (id,ambiguity,group_id,target_thread,kind,repo,resource,event,outcome,state,reason,
              ambiguous_cursor)
             VALUES('alert-1','ci_order_uncertain','group-1',?1,'job','owner/repo','build',
                    'completed','success','uncertain','send_outcome_unknown','ci-cursor')",
            [chat],
        )
        .unwrap();
        db.execute(
            "INSERT INTO condition_alerts
             (id,ambiguity,group_id,target_thread,kind,repo,resource,event,outcome,state,reason,
              ambiguous_cursor)
             VALUES('alert-pr','pr_baseline_order_uncertain','group-pr',?1,'pull_request',
                    'owner/repo','42','merged','','queued',NULL,'2026-11-08T10:00:00Z')",
            [chat],
        )
        .unwrap();
        let view = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        let alert = &view["chats"][0]["condition_alerts"]["items"][0];
        assert_eq!(view["chats"][0]["chat"], chat);
        assert_eq!(alert["ambiguity"], "ci_order_uncertain");
        assert_eq!(alert["group_id"], "group-1");
        assert_eq!(alert["resource"], "build");
        assert_eq!(alert["ambiguous_cursor"], "ci-cursor");
        assert_eq!(alert["state"], "uncertain");
        assert_eq!(
            alert["delivery"],
            "attention_delivery_or_execution_uncertain"
        );
        let pr_alert = view["chats"][0]["condition_alerts"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|alert| alert["id"] == "alert-pr")
            .unwrap();
        assert_eq!(pr_alert["ambiguity"], "pr_baseline_order_uncertain");
        assert_eq!(pr_alert["ambiguous_cursor"], "2026-11-08T10:00:00Z");
    }

    #[test]
    fn pull_request_order_uncertainty_keeps_ci_fields_compatible_and_exposes_cursor() {
        let (_dir, db) = db();
        let chat = "11111111-1111-4111-8111-111111111111";
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::And,
            &[crate::conditions::MemberRegistration::polling(
                crate::conditions::Selector {
                    kind: "pull_request".into(),
                    repo: "owner/repo".into(),
                    resource: "42".into(),
                    event: "merged".into(),
                    outcome: None,
                },
                None,
            )],
            chat,
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_members SET order_uncertain=1,ambiguous_cursor='2026-11-08T10:00:00Z'
             WHERE group_id=?1",
            [&group],
        )
        .unwrap();

        let view = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        let selector = &view["chats"][0]["conditions"]["items"][0]["selectors"]["items"][0];
        assert_eq!(selector["kind"], "pull_request");
        assert_eq!(selector["ci_order_uncertain"], false);
        assert_eq!(selector["ambiguous_ci_time"], Value::Null);
        assert_eq!(selector["order_uncertain"], true);
        assert_eq!(
            selector["order_uncertainty_type"],
            "pr_baseline_order_uncertain"
        );
        assert_eq!(selector["pr_order_uncertain"], true);
        assert_eq!(selector["ambiguous_cursor"], "2026-11-08T10:00:00Z");
        assert_eq!(selector["ambiguous_pr_cursor"], "2026-11-08T10:00:00Z");
    }

    #[test]
    fn condition_view_exposes_native_armed_state_and_only_sanitized_group_reason() {
        let (_dir, db) = db();
        let chat = "11111111-1111-4111-8111-111111111111";
        let selector = crate::conditions::Selector {
            kind: "thread".into(),
            repo: String::new(),
            resource: chat.into(),
            event: "turn_completed".into(),
            outcome: Some("turn_completed".into()),
        };
        let id = crate::conditions::register_group(
            &db,
            crate::conditions::Mode::And,
            std::slice::from_ref(&selector),
            chat,
            Some("SECRET TEMPLATE"),
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_groups SET reason=?1 WHERE id=?2",
            params!["connection_refused: SECRET DIAGNOSTIC", id],
        )
        .unwrap();

        let unarmed = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        let group = &unarmed["chats"][0]["conditions"]["items"][0];
        assert_eq!(group["reason"], "connection_refused");
        assert_eq!(group["selectors"]["items"][0]["armed"], false);
        assert!(!unarmed.to_string().contains("SECRET DIAGNOSTIC"));

        crate::conditions::arm_native_member(&db, &id, &selector, Some("SECRET_CURSOR")).unwrap();
        let armed = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        let group = &armed["chats"][0]["conditions"]["items"][0];
        assert_eq!(group["selectors"]["items"][0]["armed"], true);
        let encoded = armed.to_string();
        assert!(!encoded.contains("SECRET_CURSOR"));
        assert!(!encoded.contains("SECRET TEMPLATE"));

        db.execute(
            "UPDATE condition_groups SET reason=?1 WHERE id=?2",
            params!["internal details containing SECRET", id],
        )
        .unwrap();
        let unknown = by_chat(&db, 0, 10, 10, 0, 0).unwrap();
        assert_eq!(
            unknown["chats"][0]["conditions"]["items"][0]["reason"],
            "other"
        );
        assert!(!unknown.to_string().contains("SECRET"));
    }

    #[test]
    fn condition_selectors_show_match_state_without_source_or_template_and_are_bounded() {
        let (_dir, db) = db();
        let chat = "11111111-1111-4111-8111-111111111111";
        let selectors: Vec<_> = (0..33)
            .map(|index| crate::conditions::Selector {
                kind: "thread".into(),
                repo: String::new(),
                resource: format!("resource-{index}"),
                event: "turn_completed".into(),
                outcome: Some("turn_completed".into()),
            })
            .collect();
        let group = crate::conditions::register_group(
            &db,
            crate::conditions::Mode::And,
            &selectors,
            chat,
            Some("SECRET TEMPLATE"),
            None,
        )
        .unwrap();
        crate::conditions::arm_native_member(&db, &group, &selectors[0], Some("turn-0")).unwrap();
        crate::conditions::record_native_poll_event(
            &db,
            &group,
            &crate::conditions::PublishedEvent {
                selector: selectors[0].clone(),
                source_event_key: "native:source:turn-1".into(),
                cursor: Some("turn-1".into()),
                ci: None,
                source: json!({"private":"SECRET SOURCE"}),
            },
        )
        .unwrap();

        let view = by_chat(&db, 0, 10, 100, 0, 0).unwrap();
        let condition = &view["chats"][0]["conditions"]["items"][0];
        let selector_page = &condition["selectors"];
        assert_eq!(selector_page["total"], 33);
        assert_eq!(selector_page["items"].as_array().unwrap().len(), 32);
        assert_eq!(selector_page["truncated"], true);
        let first = selector_page["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|selector| selector["resource"] == "resource-0")
            .unwrap();
        assert_eq!(first["kind"], "thread");
        assert_eq!(first["repo"], "");
        assert_eq!(first["event"], "turn_completed");
        assert_eq!(first["outcome"], "turn_completed");
        assert_eq!(first["matched"], true);
        assert!(
            selector_page["items"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|selector| selector["resource"] != "resource-0")
                .all(|selector| selector["matched"] == false)
        );
        let encoded = view.to_string();
        assert!(!encoded.contains("SECRET SOURCE"));
        assert!(!encoded.contains("SECRET TEMPLATE"));
        assert!(!encoded.contains("source_json"));
        assert_eq!(view["page"]["condition_selector_limit"], 32);
    }
}
