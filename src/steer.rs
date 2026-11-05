//! Explicit, bounded inputs handed to the destination chat's own hooks.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use uuid::Uuid;

const MAX_INPUT_BYTES: usize = 2048;

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS steers (
        id TEXT PRIMARY KEY, thread TEXT NOT NULL, message TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending', hook_event TEXT, turn_id TEXT,
        created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );",
    )?;
    Ok(())
}

pub fn enqueue(db: &Connection, thread: &str, message: &str) -> Result<Value> {
    let thread = Uuid::parse_str(thread)?.to_string();
    ensure!(!message.trim().is_empty(), "Steer input is empty");
    ensure!(
        serde_json::to_string(message)?.len() <= MAX_INPUT_BYTES,
        "JSON-encoded steer input exceeds 2048 bytes"
    );
    let id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO steers(id,thread,message) VALUES(?1,?2,?3)",
        params![id, thread, message],
    )?;
    crate::observability::emit(
        "steer.enqueue",
        "pending",
        "",
        Some(&id),
        std::time::Duration::ZERO,
        1,
    );
    Ok(
        json!({"steer_id":id,"state":"pending","reason":"awaiting_destination_hook","turn_execution_verified":false}),
    )
}

/// Claim once before producing output. A crash or rejected hook output never causes replay.
pub fn take(db: &mut Connection, payload: &Value) -> Result<Value> {
    let event = payload["hook_event_name"].as_str().unwrap_or_default();
    ensure!(
        matches!(event, "PostToolUse" | "Stop"),
        "Unsupported steer hook"
    );
    if event == "Stop" && payload["stop_hook_active"] == true {
        return Ok(json!({}));
    }
    let thread = Uuid::parse_str(payload["session_id"].as_str().unwrap_or_default())?.to_string();
    // Subagent hooks carry the parent's session_id; never leak the parent's input to a child.
    if payload["agent_id"]
        .as_str()
        .is_some_and(|agent| agent != thread)
    {
        return Ok(json!({}));
    }
    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row = transaction.query_row(
        "SELECT id,message FROM steers WHERE thread=?1 AND state='pending' ORDER BY created,rowid LIMIT 1",
        [&thread], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    ).optional()?;
    let Some((id, message)) = row else {
        transaction.commit()?;
        return Ok(json!({}));
    };
    // Keep external values delimited; the event grants no additional authorization.
    let text = format!(
        "Wake input {id} (existing task authorization only):\n{}",
        serde_json::to_string(&json!({"input":message}))?
    );
    let output = if event == "PostToolUse" {
        json!({"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":text}})
    } else {
        json!({"decision":"block","reason":text})
    };
    transaction.execute("UPDATE steers SET state='claimed',hook_event=?1,turn_id=?2,updated=CURRENT_TIMESTAMP WHERE id=?3 AND state='pending'", params![event, payload["turn_id"].as_str(), id])?;
    transaction.commit()?;
    crate::observability::emit(
        "steer.claim",
        "claimed",
        "hook_output_unconfirmed",
        Some(&id),
        std::time::Duration::ZERO,
        1,
    );
    Ok(output)
}

pub fn status(db: &Connection) -> Result<Value> {
    let mut statement = db.prepare("SELECT id,thread,state,hook_event,turn_id,created,updated FROM steers ORDER BY created,rowid")?;
    let rows = statement
        .query_map([], |row| {
            Ok(json!({
                "id":row.get::<_,String>(0)?,"thread":row.get::<_,String>(1)?,
                "state":row.get::<_,String>(2)?,"hook_event":row.get::<_,Option<String>>(3)?,
                "turn_id":row.get::<_,Option<String>>(4)?,"created":row.get::<_,String>(5)?,
                "updated":row.get::<_,String>(6)?,"turn_execution_verified":false
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    const THREAD: &str = "11111111-1111-4111-8111-111111111111";
    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        db
    }
    fn payload(event: &str) -> Value {
        json!({"hook_event_name":event,"session_id":THREAD,"turn_id":"turn1"})
    }
    #[test]
    fn tool_hook_hands_off_each_input_once_in_order_without_blocking_tool() {
        let mut db = database();
        enqueue(&db, THREAD, "first {{literal}}\nα").unwrap();
        enqueue(&db, THREAD, "second").unwrap();
        let first = take(&mut db, &payload("PostToolUse")).unwrap();
        assert!(
            first["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap()
                .contains("first {{literal}}\\nα")
        );
        assert!(first.get("decision").is_none());
        assert!(take(&mut db, &payload("PostToolUse")).unwrap()["hookSpecificOutput"]["additionalContext"].as_str().unwrap().contains("second"));
        assert_eq!(take(&mut db, &payload("PostToolUse")).unwrap(), json!({}));
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM steers WHERE state='claimed'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        assert!(!status(&db).unwrap().to_string().contains("second"));
    }
    #[test]
    fn stop_fallback_does_not_loop_or_consume_other_threads() {
        let mut db = database();
        enqueue(&db, THREAD, "continue").unwrap();
        let mut other = payload("Stop");
        other["session_id"] = json!("22222222-2222-4222-8222-222222222222");
        assert_eq!(take(&mut db, &other).unwrap(), json!({}));
        let mut child = payload("PostToolUse");
        child["agent_id"] = json!("33333333-3333-4333-8333-333333333333");
        assert_eq!(take(&mut db, &child).unwrap(), json!({}));
        let mut continued = payload("Stop");
        continued["stop_hook_active"] = json!(true);
        assert_eq!(take(&mut db, &continued).unwrap(), json!({}));
        let output = take(&mut db, &payload("Stop")).unwrap();
        assert_eq!(output["decision"], "block");
        assert!(output["reason"].as_str().unwrap().contains("continue"));
        assert_eq!(take(&mut db, &payload("Stop")).unwrap(), json!({}));
    }
    #[test]
    fn invalid_or_large_input_and_invalid_hook_do_not_consume() {
        let mut db = database();
        for message in ["".to_string(), " ".to_string(), "a".repeat(2049)] {
            assert!(enqueue(&db, THREAD, &message).is_err());
        }
        assert!(enqueue(&db, "bad", "input").is_err());
        assert!(enqueue(&db, THREAD, &"\0".repeat(400)).is_err());
        enqueue(&db, THREAD, "valid").unwrap();
        assert!(take(&mut db, &payload("SessionStart")).is_err());
        let mut missing = payload("PostToolUse");
        missing["session_id"] = Value::Null;
        assert!(take(&mut db, &missing).is_err());
        assert_eq!(status(&db).unwrap()[0]["state"], "pending");
    }

    #[test]
    fn concurrent_hooks_claim_one_input_only_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite3");
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        enqueue(&db, THREAD, "once").unwrap();
        let workers = (0..2)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let mut db = Connection::open(path).unwrap();
                    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                    take(&mut db, &payload("PostToolUse")).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let outputs = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outputs
                .iter()
                .filter(|output| **output != json!({}))
                .count(),
            1
        );
    }
}
