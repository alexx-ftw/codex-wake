//! Metadata-only polling for registered Codex thread turn-completion observers.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const INTERVAL_MS: i64 = 5_000;
const CLAIM_MS: i64 = 180_000;
const PAGE_SIZE: i64 = 100;
const MAX_PAGES: usize = 10;
type Rpc<'a> = dyn FnMut(&str, Value) -> Result<Value> + 'a;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
struct Turn {
    id: String,
    status: String,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS native_observers (
        subscription_id TEXT PRIMARY KEY,
        resource TEXT NOT NULL,
        thread TEXT NOT NULL,
        baseline_turn_id TEXT,
        baseline_status TEXT,
        next_poll_ms INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('unknown','baseline','observed','error')),
        reason TEXT,
        updated_ms INTEGER NOT NULL
    ); CREATE INDEX IF NOT EXISTS native_observers_due ON native_observers(next_poll_ms);",
    )?;
    Ok(())
}

fn registration(db: &Connection, id: &str) -> Result<(String, String, String)> {
    let (kind, event, resource, thread): (String, String, String, String) = db
        .query_row(
            "SELECT kind,event,resource,thread FROM subscriptions WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .context("Native poll subscription not found")?;
    ensure!(
        (kind == "thread" && event == "turn_completed")
            || (kind == "subagent" && event == "completed"),
        "Native poll requires a thread or native subagent completion"
    );
    let resource = Uuid::parse_str(&resource)
        .context("Thread source must be a UUID")?
        .to_string();
    let thread = Uuid::parse_str(&thread)
        .context("Destination thread must be a UUID")?
        .to_string();
    Ok((kind, resource, thread))
}

fn source_parent(call: &mut Rpc, kind: &str, source: &str) -> Result<Option<String>> {
    if kind != "subagent" {
        return Ok(None);
    }
    let response = call(
        "thread/read",
        json!({"threadId":source,"includeTurns":false}),
    )?;
    ensure!(
        response["thread"]["id"] == source,
        "Subagent thread identity mismatch"
    );
    let parent = response
        .pointer("/thread/source/subAgent/thread_spawn/parent_thread_id")
        .and_then(Value::as_str)
        .context("Source is not an attributable native subagent thread")?;
    let parent = Uuid::parse_str(parent)?.to_string();
    ensure!(parent != source, "Subagent cannot be its own parent");
    Ok(Some(parent))
}

fn turns_page(
    call: &mut Rpc,
    thread: &str,
    cursor: Option<&str>,
) -> Result<(Vec<Turn>, Option<String>)> {
    let mut params =
        json!({"threadId":thread,"limit":PAGE_SIZE,"sortDirection":"desc","itemsView":"notLoaded"});
    if let Some(cursor) = cursor {
        params["cursor"] = json!(cursor);
    }
    let response = call("thread/turns/list", params)?;
    let data = response["data"]
        .as_array()
        .context("thread/turns/list response has no data page")?;
    ensure!(
        data.len() <= PAGE_SIZE as usize,
        "thread/turns/list exceeded requested page size"
    );
    let mut turns = Vec::with_capacity(data.len());
    for value in data {
        let id = value["id"].as_str().context("Turn has no id")?;
        ensure!(
            !id.is_empty() && id.len() <= 255 && id.bytes().all(|byte| byte.is_ascii_graphic()),
            "Invalid turn identifier"
        );
        let status = value["status"].as_str().context("Turn has no status")?;
        ensure!(
            matches!(
                status,
                "inProgress" | "completed" | "interrupted" | "failed"
            ),
            "Unsupported turn status"
        );
        turns.push(Turn {
            id: id.to_owned(),
            status: status.to_owned(),
        });
    }
    ensure!(
        response["nextCursor"].is_null() || response["nextCursor"].is_string(),
        "Invalid turn cursor"
    );
    Ok((turns, response["nextCursor"].as_str().map(str::to_owned)))
}

fn first_turn(call: &mut Rpc, thread: &str) -> Result<Option<Turn>> {
    Ok(turns_page(call, thread, None)?.0.into_iter().next())
}

fn record_unknown(
    db: &Connection,
    id: &str,
    resource: &str,
    thread: &str,
    now: i64,
) -> Result<bool> {
    Ok(db.execute("INSERT INTO native_observers(subscription_id,resource,thread,next_poll_ms,state,reason,updated_ms) VALUES(?1,?2,?3,?4,'unknown','baseline_unavailable',?5) ON CONFLICT(subscription_id) DO NOTHING", params![id,resource,thread,now+CLAIM_MS,now])? > 0)
}

/// Arm after inserting the subscription. RPC errors are retained as `unknown` state for retry.
pub fn arm(db: &Connection, id: &str, codex: &Path) -> Result<()> {
    arm_with(db, id, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
}

fn arm_with(db: &Connection, id: &str, call: &mut Rpc) -> Result<()> {
    initialize(db)?;
    let (kind, resource, thread) = registration(db, id)?;
    let now = now_ms();
    if !record_unknown(db, id, &resource, &thread, now)? {
        return Ok(());
    }
    match source_parent(call, &kind, &resource).and_then(|_| first_turn(call, &resource)) {
        Ok(turn) => {
            db.execute("UPDATE native_observers SET baseline_turn_id=?1,baseline_status=?2,next_poll_ms=?3,state='baseline',reason=NULL,updated_ms=?3 WHERE subscription_id=?4 AND state='unknown' AND reason='baseline_unavailable'", params![turn.as_ref().map(|t|t.id.as_str()),turn.as_ref().map(|t|t.status.as_str()),now+INTERVAL_MS,id])?;
            crate::observability::emit(
                "native_poll.arm",
                "ok",
                "baseline",
                None,
                Duration::ZERO,
                1,
            );
        }
        Err(_) => {
            db.execute("UPDATE native_observers SET next_poll_ms=?1,state='unknown',reason='rpc_error',updated_ms=?1 WHERE subscription_id=?2 AND state='unknown' AND reason='baseline_unavailable'", params![now+INTERVAL_MS,id])?;
            crate::observability::emit(
                "native_poll.arm",
                "error",
                "rpc_error",
                None,
                Duration::ZERO,
                1,
            );
        }
    }
    Ok(())
}

/// Poll due observers. Uses only metadata; never starts/resumes turns or reads items.
pub fn tick(db: &Connection, codex: &Path) -> Result<Value> {
    tick_with(db, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
}

fn tick_with(db: &Connection, call: &mut Rpc) -> Result<Value> {
    initialize(db)?;
    let now = now_ms();
    let due = {
        let mut statement = db.prepare("SELECT s.id,s.resource,s.thread,o.baseline_turn_id,o.baseline_status,o.state,s.kind FROM subscriptions s LEFT JOIN native_observers o ON o.subscription_id=s.id WHERE ((s.kind='thread' AND s.event='turn_completed') OR (s.kind='subagent' AND s.event='completed')) AND s.state='waiting' AND (o.subscription_id IS NULL OR o.next_poll_ms<=?1) ORDER BY s.id")?;
        statement
            .query_map([now], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut report = json!({"due":due.len(),"baselined":0,"published":0,"unchanged":0,"errors":0});
    for (id, resource, thread, base_id, base_status, state, kind) in due {
        let valid = Uuid::parse_str(&resource).is_ok_and(|u| u.to_string() == resource)
            && Uuid::parse_str(&thread).is_ok_and(|u| u.to_string() == thread);
        if !valid {
            let stamp = now_ms();
            db.execute("INSERT INTO native_observers(subscription_id,resource,thread,next_poll_ms,state,reason,updated_ms) VALUES(?1,?2,?3,?4,'error','invalid_thread_uuid',?4) ON CONFLICT(subscription_id) DO UPDATE SET next_poll_ms=excluded.next_poll_ms,state='error',reason=excluded.reason,updated_ms=excluded.updated_ms",params![id,resource,thread,stamp+INTERVAL_MS])?;
            report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
            crate::observability::emit(
                "native_poll.tick",
                "error",
                "invalid_thread_uuid",
                None,
                Duration::ZERO,
                1,
            );
            continue;
        }
        let stamp = now_ms();
        let inserted = record_unknown(db, &id, &resource, &thread, stamp)?;
        if !inserted && db.execute("UPDATE native_observers SET next_poll_ms=?1 WHERE subscription_id=?2 AND next_poll_ms<=?3",params![stamp+CLAIM_MS,id,now])? == 0 { continue; }
        let first: Result<_> = (|| {
            Ok((
                source_parent(call, &kind, &resource)?,
                turns_page(call, &resource, None)?,
            ))
        })();
        let (parent, (latest_page, next)) = match first {
            Ok(page) => page,
            Err(_) => {
                db.execute("UPDATE native_observers SET next_poll_ms=?1,state=CASE WHEN state='unknown' THEN 'unknown' ELSE 'error' END,reason='rpc_error',updated_ms=?1 WHERE subscription_id=?2",params![stamp+INTERVAL_MS,id])?;
                report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                crate::observability::emit(
                    "native_poll.tick",
                    "error",
                    "rpc_error",
                    None,
                    Duration::ZERO,
                    1,
                );
                continue;
            }
        };
        let latest = latest_page.first().cloned();
        if state.as_deref() == Some("unknown") || (state.is_none() && base_id.is_none()) {
            let observed = latest.as_ref();
            db.execute("UPDATE native_observers SET baseline_turn_id=?1,baseline_status=?2,next_poll_ms=?3,state='baseline',reason=NULL,updated_ms=?3 WHERE subscription_id=?4",params![observed.map(|t|t.id.as_str()),observed.map(|t|t.status.as_str()),stamp+INTERVAL_MS,id])?;
            report["baselined"] = json!(report["baselined"].as_u64().unwrap_or(0) + 1);
            crate::observability::emit(
                "native_poll.tick",
                "ok",
                "baseline",
                None,
                Duration::ZERO,
                1,
            );
            continue;
        }
        let chronological = if base_id.is_none() {
            latest_page.into_iter().rev().collect::<Vec<_>>()
        } else {
            let mut page = latest_page;
            let mut cursor = next;
            let mut found = false;
            let mut descending = Vec::new();
            for page_no in 0..MAX_PAGES {
                for turn in &page {
                    if turn.id == base_id.as_deref().unwrap_or_default() {
                        found = true;
                        break;
                    }
                }
                descending.extend(page);
                if found {
                    break;
                }
                let Some(next_cursor) = cursor else { break };
                if page_no + 1 == MAX_PAGES {
                    break;
                }
                match turns_page(call, &resource, Some(&next_cursor)) {
                    Ok((next_page, next_cursor)) => {
                        page = next_page;
                        cursor = next_cursor;
                    }
                    Err(_) => {
                        found = false;
                        break;
                    }
                }
            }
            if !found {
                db.execute("UPDATE native_observers SET next_poll_ms=?1,state='error',reason='baseline_cursor_not_found',updated_ms=?1 WHERE subscription_id=?2",params![stamp+INTERVAL_MS,id])?;
                report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                crate::observability::emit(
                    "native_poll.tick",
                    "error",
                    "baseline_cursor_not_found",
                    None,
                    Duration::ZERO,
                    1,
                );
                continue;
            }
            if let Some(base) = descending
                .iter()
                .position(|turn| Some(turn.id.as_str()) == base_id.as_deref())
            {
                descending.truncate(base + 1);
            }
            descending.into_iter().rev().collect()
        };
        let previous_id = base_id.clone();
        let mut previous_status = base_status.clone();
        let mut event_turn = None;
        for turn in chronological {
            let same = previous_id.as_deref() == Some(turn.id.as_str());
            // Another controller can reconstruct an unloaded live turn as interrupted.
            if turn.status == "completed"
                && (!same || previous_status.as_deref() != Some("completed"))
            {
                event_turn = Some(turn.clone());
                break;
            }
            previous_status = Some(turn.status);
        }
        if let Some(turn) = event_turn {
            let source = if kind == "subagent" {
                json!({"session_id":parent.context("Native subagent parent missing")?,"agent_id":resource,"turnId":turn.id,"status":turn.status})
            } else {
                json!({"session_id":resource,"turnId":turn.id,"status":turn.status})
            };
            let count = crate::subscriptions::publish_observation(
                db,
                &id,
                if kind == "subagent" {
                    "completed"
                } else {
                    "turn_completed"
                },
                &source,
            )?;
            report["published"] = json!(report["published"].as_u64().unwrap_or(0) + count as u64);
            crate::observability::emit(
                "native_poll.tick",
                "ok",
                "published",
                None,
                Duration::ZERO,
                count as u64,
            );
        } else {
            report["unchanged"] = json!(report["unchanged"].as_u64().unwrap_or(0) + 1);
            crate::observability::emit(
                "native_poll.tick",
                "ok",
                "unchanged",
                None,
                Duration::ZERO,
                1,
            );
        }
        let last_status = if latest.as_ref().map(|t| t.id.as_str()) == base_id.as_deref()
            && base_status.as_deref() == Some("completed")
        {
            Some("completed")
        } else {
            latest.as_ref().map(|t| t.status.as_str())
        };
        db.execute("UPDATE native_observers SET baseline_turn_id=?1,baseline_status=?2,next_poll_ms=?3,state='observed',reason=NULL,updated_ms=?3 WHERE subscription_id=?4",params![latest.as_ref().map(|t|t.id.as_str()),last_status,stamp+INTERVAL_MS,id])?;
    }
    Ok(report)
}

/// Read observer state only; never contacts the app-server or returns turn contents.
pub fn status(db: &Connection) -> Result<Value> {
    initialize(db)?;
    let mut statement=db.prepare("SELECT subscription_id,resource,thread,baseline_turn_id,baseline_status,state,reason,next_poll_ms,updated_ms FROM native_observers ORDER BY subscription_id")?;
    let rows=statement.query_map([],|r|Ok(json!({"subscription_id":r.get::<_,String>(0)?,"resource":r.get::<_,String>(1)?,"thread":r.get::<_,String>(2)?,"baseline_turn_id":r.get::<_,Option<String>>(3)?,"baseline_status":r.get::<_,Option<String>>(4)?,"state":r.get::<_,String>(5)?,"reason":r.get::<_,Option<String>>(6)?,"next_poll_ms":r.get::<_,i64>(7)?,"updated_ms":r.get::<_,i64>(8)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
    const TARGET: &str = "22222222-2222-4222-8222-222222222222";
    #[test]
    fn slow_arming_cannot_overwrite_a_newer_poll_baseline() {
        let db = db();
        let id = sub(&db);
        arm_with(&db,&id,&mut |_,_| {
            db.execute("UPDATE native_observers SET baseline_turn_id='newer',baseline_status='completed',state='observed',reason=NULL",[])?;
            Ok(json!({"data":[{"id":"older","status":"inProgress"}],"nextCursor":null}))
        }).unwrap();
        let cursor: String = db
            .query_row(
                "SELECT baseline_turn_id FROM native_observers WHERE subscription_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor, "newer");
    }
    #[test]
    fn subagent_poll_requires_verified_native_parent_and_child_identity() {
        let db = db();
        let id = crate::subscriptions::subscribe(&db, "subagent", "", SOURCE, "completed", TARGET)
            .unwrap();
        db.execute(
            "UPDATE subscriptions SET message_template='{{source.agent_id}}' WHERE id=?1",
            [&id],
        )
        .unwrap();
        let state = std::cell::Cell::new("inProgress");
        let mut rpc = |method: &str, params: Value| -> Result<Value> {
            assert_eq!(params["threadId"], SOURCE);
            Ok(if method == "thread/read" {
                assert_eq!(params["includeTurns"], false);
                json!({"thread":{"id":SOURCE,"source":{"subAgent":{"thread_spawn":{"parent_thread_id":TARGET,"depth":1}}}}})
            } else {
                assert_eq!(method, "thread/turns/list");
                json!({"data":[{"id":"child-turn","status":state.get()}],"nextCursor":null})
            })
        };
        arm_with(&db, &id, &mut rpc).unwrap();
        state.set("completed");
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(tick_with(&db, &mut rpc).unwrap()["published"], 1);
        let source: String = db
            .query_row(
                "SELECT source_json FROM subscriptions WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        let source: Value = serde_json::from_str(&source).unwrap();
        assert_eq!(source["agent_id"], SOURCE);
        assert_eq!(source["session_id"], TARGET);
        assert_eq!(tick_with(&db, &mut rpc).unwrap()["published"], 0);
    }

    #[test]
    fn ordinary_thread_cannot_impersonate_a_subagent() {
        let db = db();
        let id = crate::subscriptions::subscribe(&db, "subagent", "", SOURCE, "completed", TARGET)
            .unwrap();
        let mut rpc = |method: &str, _| -> Result<Value> {
            assert_eq!(method, "thread/read");
            Ok(json!({"thread":{"id":SOURCE,"source":"cli"}}))
        };
        arm_with(&db, &id, &mut rpc).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(tick_with(&db, &mut rpc).unwrap()["errors"], 1);
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
    }
    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        initialize(&db).unwrap();
        db
    }
    fn sub(db: &Connection) -> String {
        let id =
            crate::subscriptions::subscribe(db, "thread", "", SOURCE, "turn_completed", TARGET)
                .unwrap();
        db.execute(
            "UPDATE subscriptions SET message_template='{{source.turnId}}' WHERE id=?1",
            [&id],
        )
        .unwrap();
        id
    }
    fn page(expected_thread: &str, turns: Vec<Turn>) -> impl FnMut(&str, Value) -> Result<Value> {
        let expected_thread = expected_thread.to_owned();
        move |method, params| {
            assert_eq!(method, "thread/turns/list");
            assert_eq!(params["threadId"], expected_thread);
            assert_eq!(params["itemsView"], "notLoaded");
            Ok(json!({"data":turns.clone(),"nextCursor":null}))
        }
    }
    fn three_pages() -> impl FnMut(&str, Value) -> Result<Value> {
        let mut page_no = 0;
        move |method, params| {
            assert_eq!(method, "thread/turns/list");
            assert_eq!(params["threadId"], SOURCE);
            assert_eq!(params["itemsView"], "notLoaded");
            let (data, cursor) = match page_no {
                0 => {
                    assert!(params["cursor"].is_null());
                    (
                        vec![turn("t3", "completed"), turn("t2", "completed")],
                        Some("c1"),
                    )
                }
                1 => {
                    assert_eq!(params["cursor"], "c1");
                    (
                        vec![turn("t1", "completed"), turn("base", "failed")],
                        Some("c2"),
                    )
                }
                2 => {
                    assert_eq!(params["cursor"], "c2");
                    (vec![turn("baseline", "inProgress")], None)
                }
                _ => panic!("unexpected turns page"),
            };
            page_no += 1;
            Ok(json!({"data":data,"nextCursor":cursor}))
        }
    }
    fn turn(id: &str, status: &str) -> Turn {
        Turn {
            id: id.into(),
            status: status.into(),
        }
    }

    #[test]
    fn active_baseline_completion_publishes_once_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("poll.sqlite");
        let id = {
            let db = Connection::open(&path).unwrap();
            crate::subscriptions::initialize(&db).unwrap();
            let id = sub(&db);
            arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
            id
        };
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        let mut rpc = page(SOURCE, vec![turn("t1", "completed")]);
        assert_eq!(tick_with(&db, &mut rpc).unwrap()["published"], 1);
        let source: String = db
            .query_row(
                "SELECT source_json FROM subscriptions WHERE id=?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&source).unwrap(),
            json!({"session_id":SOURCE,"turnId":"t1","status":"completed"})
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "ready"
        );
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["due"],
            0
        );
    }

    #[test]
    fn independent_baselines_do_not_publish_to_later_registration() {
        let db = db();
        let early = sub(&db);
        arm_with(
            &db,
            &early,
            &mut page(SOURCE, vec![turn("t1", "inProgress")]),
        )
        .unwrap();
        let late = crate::subscriptions::subscribe(
            &db,
            "thread",
            "later-registration",
            SOURCE,
            "turn_completed",
            "33333333-3333-4333-8333-333333333333",
        )
        .unwrap();
        arm_with(&db, &late, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        let result = tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap();
        assert_eq!(result["published"], 1);
        for (id, expected) in [(&early, "ready"), (&late, "waiting")] {
            let state: String = db
                .query_row("SELECT state FROM subscriptions WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(state, expected);
        }
    }

    #[test]
    fn historical_completed_turn_is_only_a_baseline() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("old", "completed")])).unwrap();
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
    }

    #[test]
    fn completed_baseline_does_not_replay_after_reconstructed_interruption() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("old", "completed")])).unwrap();
        for observed in ["interrupted", "completed"] {
            db.execute("UPDATE native_observers SET next_poll_ms=0", [])
                .unwrap();
            assert_eq!(
                tick_with(&db, &mut page(SOURCE, vec![turn("old", observed)])).unwrap()["published"],
                0
            );
            assert_eq!(
                crate::subscriptions::status(&db).unwrap()[0]["state"],
                "waiting"
            );
            assert_eq!(status(&db).unwrap()[0]["baseline_status"], "completed");
        }
    }

    #[test]
    fn unarmed_first_poll_baselines_historical_completion() {
        let db = db();
        sub(&db);
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("old", "completed")])).unwrap()["baselined"],
            1
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
        assert_eq!(status(&db).unwrap()[0]["baseline_turn_id"], "old");
    }

    #[test]
    fn three_pages_use_source_uuid_and_find_new_turns_without_timestamp_fields() {
        let db = db();
        let id = sub(&db);
        arm_with(
            &db,
            &id,
            &mut page(SOURCE, vec![turn("baseline", "inProgress")]),
        )
        .unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(tick_with(&db, &mut three_pages()).unwrap()["published"], 1);
        let source: String = db
            .query_row(
                "SELECT source_json FROM subscriptions WHERE id=?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&source).unwrap(),
            json!({"session_id":SOURCE,"turnId":"t1","status":"completed"})
        );
    }

    #[test]
    fn arm_does_not_reset_existing_baseline_or_call_rpc_again() {
        let db = db();
        let id = sub(&db);
        arm_with(
            &db,
            &id,
            &mut page(SOURCE, vec![turn("active", "inProgress")]),
        )
        .unwrap();
        arm_with(&db, &id, &mut |_, _| {
            panic!("existing observer must not be re-armed")
        })
        .unwrap();
        assert_eq!(status(&db).unwrap()[0]["baseline_turn_id"], "active");
    }

    #[test]
    fn stop_and_native_completion_claim_once_in_either_order() {
        for hook_first in [true, false] {
            let db = db();
            let id = sub(&db);
            db.execute(
                "UPDATE subscriptions SET message_template=NULL WHERE id=?1",
                [&id],
            )
            .unwrap();
            arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
            db.execute(
                "UPDATE native_observers SET next_poll_ms=0 WHERE subscription_id=?1",
                [&id],
            )
            .unwrap();
            let hook = || {
                crate::subscriptions::publish_with_source(
                    &db,
                    "thread",
                    "",
                    SOURCE,
                    "turn_completed",
                    &json!({"session_id":SOURCE,"turn_id":"t1"}),
                )
                .unwrap()
            };
            let poll = || {
                tick_with(&db,&mut page(SOURCE,vec![turn("t1","completed")])).unwrap()["published"].as_u64().unwrap() as usize
            };
            let (first, second) = if hook_first {
                (hook(), poll())
            } else {
                (poll(), hook())
            };
            assert_eq!((first, second), (1, 0));
            let rows = crate::subscriptions::status(&db).unwrap();
            assert_eq!(rows.as_array().unwrap().len(), 1);
            assert_eq!(rows[0]["state"], "ready");
        }
    }

    #[test]
    fn stop_and_native_completion_race_claim_one_subscription() {
        use std::sync::{Arc, Barrier};
        let temp = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("state.sqlite3");
        let db = crate::bridge::connect(&path).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        let id = sub(&db);
        db.execute(
            "UPDATE subscriptions SET message_template=NULL WHERE id=?1",
            [&id],
        )
        .unwrap();
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
        db.execute(
            "UPDATE native_observers SET next_poll_ms=0 WHERE subscription_id=?1",
            [&id],
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let hook_path = path.clone();
        let hook_barrier = barrier.clone();
        let hook = std::thread::spawn(move || {
            let db = crate::bridge::connect(&hook_path).unwrap();
            hook_barrier.wait();
            crate::subscriptions::publish_with_source(
                &db,
                "thread",
                "",
                SOURCE,
                "turn_completed",
                &json!({"session_id":SOURCE,"turn_id":"t1"}),
            )
            .unwrap()
        });
        let poll_path = path.clone();
        let poll = std::thread::spawn(move || {
            let db = crate::bridge::connect(&poll_path).unwrap();
            barrier.wait();
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["published"]
                .as_u64()
                .unwrap() as usize
        });
        assert_eq!(hook.join().unwrap() + poll.join().unwrap(), 1);
        let row = crate::subscriptions::status(&db).unwrap();
        assert_eq!(row.as_array().unwrap().len(), 1);
        assert_eq!(row[0]["state"], "ready");
    }

    #[test]
    fn unloaded_interrupted_baseline_can_later_complete() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "interrupted")])).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "interrupted")])).unwrap()["published"],
            0
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["published"],
            1
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "ready"
        );
    }

    #[test]
    fn failed_turn_does_not_publish() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        tick_with(&db, &mut page(SOURCE, vec![turn("t1", "failed")])).unwrap();
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
    }

    #[test]
    fn rpc_error_preserves_active_cursor_for_later_completion() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut |_, _| anyhow::bail!("offline")).unwrap()["errors"],
            1
        );
        assert_eq!(status(&db).unwrap()[0]["baseline_turn_id"], "t1");
        assert_eq!(status(&db).unwrap()[0]["state"], "error");
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["published"],
            1
        );
    }

    #[test]
    fn rpc_failure_keeps_waiting_subscription_observable_unknown() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut |_, _| anyhow::bail!("offline")).unwrap();
        assert_eq!(status(&db).unwrap()[0]["state"], "unknown");
        assert_eq!(status(&db).unwrap()[0]["reason"], "rpc_error");
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
    }
}
