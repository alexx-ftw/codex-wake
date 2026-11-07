//! Bounded metadata-only visibility for responsible chats with pending obligations.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const BATCH: i64 = 8;
const LEASE_MS: i64 = 60_000;
const ACTIVE_MS: i64 = 30_000;
const IDLE_MS: i64 = 300_000;
const MAX_BACKOFF_MS: i64 = 900_000;

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS responsible_observations (
        responsible TEXT PRIMARY KEY, turn_id TEXT, turn_status TEXT, state TEXT NOT NULL, observed_at TEXT
    ); CREATE TABLE IF NOT EXISTS responsible_schedule (
        responsible TEXT PRIMARY KEY, next_poll_ms INTEGER NOT NULL DEFAULT 0,
        failures INTEGER NOT NULL DEFAULT 0, last_error TEXT, last_attempt_ms INTEGER, claim TEXT
    );")?;
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

/// Poll only metadata; no input, resumption, publication, or notification is sent.
pub fn tick(db: &Connection, codex: &Path) -> Result<()> {
    tick_with(db, &now_ms, &mut |method, params| {
        crate::goals::rpc_with_timeout(codex, method, params, Duration::from_secs(15))
    })
}

fn parse_turn(result: &Value) -> Result<Option<(String, String)>> {
    let turns = result["data"].as_array().context("missing turn page")?;
    ensure!(turns.len() <= 1, "turn page exceeded requested limit");
    let Some(turn) = turns.first() else {
        return Ok(None);
    };
    let id = turn["id"].as_str().context("missing turn ID")?;
    ensure!(
        !id.is_empty() && id.len() <= 255 && id.bytes().all(|b| b.is_ascii_graphic()),
        "invalid turn ID"
    );
    let status = turn["status"].as_str().context("missing turn status")?;
    ensure!(
        matches!(
            status,
            "inProgress" | "completed" | "interrupted" | "failed"
        ),
        "unsupported turn status"
    );
    Ok(Some((id.to_owned(), status.to_owned())))
}

fn tick_with(
    db: &Connection,
    clock: &dyn Fn() -> i64,
    call: &mut dyn FnMut(&str, Value) -> Result<Value>,
) -> Result<()> {
    initialize(db)?;
    let now = clock();
    let sources = {
        let mut query = db.prepare(
            "SELECT c.responsible FROM coordinators c
            LEFT JOIN responsible_schedule s ON s.responsible=c.responsible
            WHERE coalesce(s.next_poll_ms,0)<=?1 AND EXISTS
            (SELECT 1 FROM obligations o WHERE o.thread=c.responsible AND o.resolved=0)
            ORDER BY coalesce(s.next_poll_ms,0),c.responsible LIMIT ?2",
        )?;
        let rows = query.query_map(params![now, BATCH], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for source in sources {
        let now = clock();
        let claim = Uuid::new_v4().to_string();
        let claimed = db.execute("INSERT INTO responsible_schedule(responsible,next_poll_ms,last_attempt_ms,claim)
            VALUES(?1,?2,?3,?4) ON CONFLICT(responsible) DO UPDATE SET
            next_poll_ms=excluded.next_poll_ms,last_attempt_ms=excluded.last_attempt_ms,claim=excluded.claim
            WHERE responsible_schedule.next_poll_ms<=?3",params![source,now.saturating_add(LEASE_MS),now,claim])?;
        if claimed == 0 {
            continue;
        }
        let result = match call(
            "thread/turns/list",
            json!({"threadId":source,"limit":1,"sortDirection":"desc","itemsView":"notLoaded"}),
        ) {
            Ok(value) => parse_turn(&value).map_err(|_| "invalid_response"),
            Err(_) => Err("rpc_error"),
        };
        let tx =
            rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
        let failures: Option<i64> = tx
            .query_row(
                "SELECT failures FROM responsible_schedule WHERE responsible=?1 AND claim=?2",
                params![source, claim],
                |row| row.get(0),
            )
            .optional()?;
        let Some(failures) = failures else {
            tx.commit()?;
            continue;
        };
        let now = clock();
        match result {
            Ok(Some((id, status))) => {
                let interval = if status == "inProgress" {
                    ACTIVE_MS
                } else {
                    IDLE_MS
                };
                tx.execute("INSERT INTO responsible_observations(responsible,turn_id,turn_status,state,observed_at)
                    VALUES(?1,?2,?3,'observed',CURRENT_TIMESTAMP) ON CONFLICT(responsible) DO UPDATE SET
                    turn_id=excluded.turn_id,turn_status=excluded.turn_status,state='observed',observed_at=CURRENT_TIMESTAMP",params![source,id,status])?;
                tx.execute("UPDATE responsible_schedule SET next_poll_ms=?1,failures=0,last_error=NULL,claim=NULL WHERE responsible=?2 AND claim=?3",params![now.saturating_add(interval),source,claim])?;
            }
            Ok(None) => {
                tx.execute("INSERT INTO responsible_observations(responsible,state,observed_at) VALUES(?1,'no_turn',CURRENT_TIMESTAMP)
                    ON CONFLICT(responsible) DO UPDATE SET turn_id=NULL,turn_status=NULL,state='no_turn',observed_at=CURRENT_TIMESTAMP",[&source])?;
                tx.execute("UPDATE responsible_schedule SET next_poll_ms=?1,failures=0,last_error=NULL,claim=NULL WHERE responsible=?2 AND claim=?3",params![now.saturating_add(IDLE_MS),source,claim])?;
            }
            Err(reason) => {
                let next_failures = failures.saturating_add(1).min(32);
                let backoff = ACTIVE_MS
                    .saturating_mul(1_i64 << (next_failures - 1).min(5))
                    .min(MAX_BACKOFF_MS);
                tx.execute("INSERT INTO responsible_observations(responsible,state) VALUES(?1,'unavailable')
                    ON CONFLICT(responsible) DO UPDATE SET state='unavailable'",[&source])?;
                tx.execute("UPDATE responsible_schedule SET next_poll_ms=?1,failures=?2,last_error=?3,claim=NULL WHERE responsible=?4 AND claim=?5",params![now.saturating_add(backoff),next_failures,reason,source,claim])?;
            }
        }
        tx.commit()?;
    }
    Ok(())
}

/// A snapshot, not a completion signal or proof that any alert was delivered.
pub fn status(db: &Connection) -> Result<Value> {
    initialize(db)?;
    let mut query = db.prepare(
        "SELECT c.responsible,c.coordinator,o.turn_id,o.turn_status,o.state,o.observed_at,
        (SELECT count(*) FROM obligations WHERE thread=c.responsible AND resolved=0),
        s.next_poll_ms,s.failures,s.last_error,s.last_attempt_ms,s.claim IS NOT NULL
        FROM coordinators c LEFT JOIN responsible_observations o ON o.responsible=c.responsible
        LEFT JOIN responsible_schedule s ON s.responsible=c.responsible
        WHERE EXISTS(SELECT 1 FROM obligations WHERE thread=c.responsible AND resolved=0)
        ORDER BY c.responsible",
    )?;
    let rows=query.query_map([],|r|Ok(json!({"responsible":r.get::<_,String>(0)?,"coordinator":r.get::<_,String>(1)?,
        "turn_id":r.get::<_,Option<String>>(2)?,"turn_status":r.get::<_,Option<String>>(3)?,
        "state":r.get::<_,Option<String>>(4)?.unwrap_or_else(||"unobserved".into()),"observed_at":r.get::<_,Option<String>>(5)?,
        "pending":r.get::<_,i64>(6)?,"next_poll_ms":r.get::<_,Option<i64>>(7)?,"failures":r.get::<_,Option<i64>>(8)?.unwrap_or(0),
        "last_error":r.get::<_,Option<String>>(9)?,"last_attempt_ms":r.get::<_,Option<i64>>(10)?,
        "poll_claimed":r.get::<_,bool>(11)?,
        "interruption_is_uncertain":true,"stopless_automatic_notification":false})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        crate::obligations::initialize(&db).unwrap();
        db
    }
    fn owner(db: &Connection, n: u128) -> String {
        let owner = Uuid::from_u128(n).to_string();
        let coordinator = Uuid::from_u128(999).to_string();
        crate::obligations::register_coordinator(db, &owner, &coordinator).unwrap();
        crate::obligations::register(
            db,
            &owner,
            "artifact",
            "ci",
            "package",
            "available",
            "check",
        )
        .unwrap();
        owner
    }
    #[test]
    fn bounds_and_schedules_observations_fairly() {
        let db = db();
        for n in 1..=10 {
            owner(&db, n);
        }
        let count = std::cell::Cell::new(0);
        let mut rpc = |_: &str, _: Value| {
            count.set(count.get() + 1);
            Ok(json!({"data":[{"id":"turn1","status":"inProgress"}]}))
        };
        tick_with(&db, &|| 1000, &mut rpc).unwrap();
        assert_eq!(count.get(), 8);
        tick_with(&db, &|| 1000, &mut rpc).unwrap();
        assert_eq!(count.get(), 10);
        tick_with(&db, &|| 1001, &mut rpc).unwrap();
        assert_eq!(count.get(), 10);
        tick_with(&db, &|| 31_000, &mut rpc).unwrap();
        assert_eq!(count.get(), 18);
    }
    #[test]
    fn reconstructed_interruption_can_later_appear_completed_without_sending() {
        let db = db();
        owner(&db, 1);
        tick_with(&db, &|| 1000, &mut |_, _| {
            Ok(json!({"data":[{"id":"same","status":"interrupted"}]}))
        })
        .unwrap();
        assert_eq!(status(&db).unwrap()[0]["turn_status"], "interrupted");
        tick_with(&db, &|| 301_000, &mut |_, _| {
            Ok(json!({"data":[{"id":"same","status":"completed"}]}))
        })
        .unwrap();
        let result = status(&db).unwrap();
        assert_eq!(result[0]["turn_status"], "completed");
        assert_eq!(result[0]["stopless_automatic_notification"], false);
        let alerts: i64 = db
            .query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(alerts, 0);
    }

    #[test]
    fn expired_claim_cannot_overwrite_a_newer_attempt() {
        let db = db();
        let source = owner(&db, 1);
        tick_with(&db, &|| 1000, &mut |_, _| {
            db.execute("UPDATE responsible_schedule SET claim='newer',next_poll_ms=999999 WHERE responsible=?1", [&source]).unwrap();
            Ok(json!({"data":[{"id":"stale","status":"completed"}]}))
        }).unwrap();
        let row = status(&db).unwrap();
        assert_eq!(row[0]["state"], "unobserved");
        assert!(row[0]["turn_id"].is_null());
        assert_eq!(row[0]["next_poll_ms"], 999999);
    }

    #[test]
    fn failure_is_diagnosed_backed_off_and_keeps_uncertain_snapshot() {
        let db = db();
        owner(&db, 1);
        tick_with(&db, &|| 1000, &mut |_, _| {
            Ok(json!({"data":[{"id":"turn1","status":"interrupted"}]}))
        })
        .unwrap();
        let snapshot = status(&db).unwrap();
        assert_eq!(snapshot[0]["interruption_is_uncertain"], true);
        assert_eq!(snapshot[0]["stopless_automatic_notification"], false);
        tick_with(&db, &|| 301_000, &mut |_, _| {
            anyhow::bail!("private error details")
        })
        .unwrap();
        let failed = status(&db).unwrap();
        assert_eq!(failed[0]["state"], "unavailable");
        assert_eq!(failed[0]["turn_id"], "turn1");
        assert_eq!(failed[0]["last_error"], "rpc_error");
        assert_eq!(failed[0]["next_poll_ms"], 331_000);
        tick_with(&db, &|| 331_000, &mut |_, _| Ok(json!({"data":"invalid"}))).unwrap();
        let invalid = status(&db).unwrap();
        assert_eq!(invalid[0]["last_error"], "invalid_response");
        assert_eq!(invalid[0]["next_poll_ms"], 391_000);
        let alerts: i64 = db
            .query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(alerts, 0);
    }
}
