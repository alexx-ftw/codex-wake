//! Metadata-only visibility for responsible chats with pending obligations.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::path::Path;

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS responsible_observations (
        responsible TEXT PRIMARY KEY,
        turn_id TEXT,
        turn_status TEXT,
        state TEXT NOT NULL,
        observed_at TEXT
    );",
    )?;
    Ok(())
}

/// Poll only metadata. An interrupted status may be a reconstructed live turn.
pub fn tick(db: &Connection, codex: &Path) -> Result<()> {
    tick_with(db, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
}

fn tick_with(db: &Connection, call: &mut dyn FnMut(&str, Value) -> Result<Value>) -> Result<()> {
    initialize(db)?;
    let sources = {
        let mut query = db.prepare(
            "SELECT responsible FROM coordinators c WHERE EXISTS
            (SELECT 1 FROM obligations o WHERE o.thread=c.responsible AND o.resolved=0)
            ORDER BY responsible",
        )?;
        let rows = query.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for source in sources {
        let observation = (|| -> Result<Option<(String, String)>> {
            let result = call(
                "thread/turns/list",
                json!({"threadId":source,"limit":1,"sortDirection":"desc","itemsView":"notLoaded"}),
            )?;
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
        })();
        // Do not erase a previous observation on an RPC failure.
        match observation {
            Ok(Some((id, status))) => {
                db.execute("INSERT INTO responsible_observations(responsible,turn_id,turn_status,state,observed_at)
                VALUES(?1,?2,?3,'observed',CURRENT_TIMESTAMP)
                ON CONFLICT(responsible) DO UPDATE SET turn_id=excluded.turn_id,turn_status=excluded.turn_status,state='observed',observed_at=CURRENT_TIMESTAMP",params![source,id,status])?;
            }
            Ok(None) => {
                db.execute("INSERT INTO responsible_observations(responsible,state,observed_at) VALUES(?1,'no_turn',CURRENT_TIMESTAMP)
                ON CONFLICT(responsible) DO UPDATE SET turn_id=NULL,turn_status=NULL,state='no_turn',observed_at=CURRENT_TIMESTAMP",[source])?;
            }
            Err(_) => {
                db.execute("INSERT INTO responsible_observations(responsible,state) VALUES(?1,'unavailable')
                ON CONFLICT(responsible) DO UPDATE SET state='unavailable'",[source])?;
            }
        }
    }
    Ok(())
}

/// A snapshot, not a completion signal or proof that any alert was delivered.
pub fn status(db: &Connection) -> Result<Value> {
    initialize(db)?;
    let mut query = db.prepare(
        "SELECT c.responsible,c.coordinator,o.turn_id,o.turn_status,o.state,o.observed_at,
        (SELECT count(*) FROM obligations WHERE thread=c.responsible AND resolved=0)
        FROM coordinators c LEFT JOIN responsible_observations o ON o.responsible=c.responsible
        WHERE EXISTS(SELECT 1 FROM obligations WHERE thread=c.responsible AND resolved=0)
        ORDER BY c.responsible",
    )?;
    let rows = query
        .query_map([], |r| {
            Ok(
                json!({"responsible":r.get::<_,String>(0)?,"coordinator":r.get::<_,String>(1)?,
        "turn_id":r.get::<_,Option<String>>(2)?,"turn_status":r.get::<_,Option<String>>(3)?,
        "state":r.get::<_,Option<String>>(4)?.unwrap_or_else(||"unobserved".into()),
        "observed_at":r.get::<_,Option<String>>(5)?,"pending":r.get::<_,i64>(6)?,
        "interruption_is_uncertain":true,"stopless_automatic_notification":false}),
            )
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_status_is_uncertain_and_failure_keeps_last_observation() {
        let db = Connection::open_in_memory().unwrap();
        crate::obligations::initialize(&db).unwrap();
        let owner = "11111111-1111-4111-8111-111111111111";
        let coordinator = "22222222-2222-4222-8222-222222222222";
        crate::obligations::register_coordinator(&db, owner, coordinator).unwrap();
        crate::obligations::register(
            &db,
            owner,
            "artifact",
            "ci",
            "package",
            "available",
            "check",
        )
        .unwrap();
        tick_with(&db, &mut |_, _| {
            Ok(json!({"data":[{"id":"turn1","status":"interrupted"}]}))
        })
        .unwrap();
        let observed = status(&db).unwrap();
        assert_eq!(observed[0]["turn_status"], "interrupted");
        assert_eq!(observed[0]["interruption_is_uncertain"], true);
        assert_eq!(observed[0]["stopless_automatic_notification"], false);
        tick_with(&db, &mut |_, _| anyhow::bail!("offline")).unwrap();
        let failed = status(&db).unwrap();
        assert_eq!(failed[0]["state"], "unavailable");
        assert_eq!(failed[0]["turn_id"], "turn1");
        assert_eq!(failed[0]["turn_status"], "interrupted");
        let alerts: i64 = db
            .query_row("SELECT count(*) FROM coordinator_alerts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(alerts, 0);
    }
}
