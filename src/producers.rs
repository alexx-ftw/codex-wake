//! Identify the registered source of a waiting subscription.
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

pub fn subscriptions_status(db: &Connection) -> Result<Value> {
    let mut subscriptions = crate::subscriptions::status(db)?;
    for row in subscriptions
        .as_array_mut()
        .context("Invalid subscription status")?
    {
        let id = row["id"].as_str().context("Missing subscription ID")?;
        let producer = status(db, id)?;
        row["producer"] = producer;
    }
    Ok(subscriptions)
}

pub fn subscription_status(db: &Connection, id: &str) -> Result<Value> {
    let mut subscription = crate::subscriptions::status_for_id(db, id)?;
    subscription["producer"] = status(db, id)?;
    Ok(subscription)
}

pub fn status(db: &Connection, id: &str) -> Result<Value> {
    let (kind, repo, resource, event, state): (String, String, String, String, String) = db
        .query_row(
            "SELECT kind,repo,resource,event,state FROM subscriptions WHERE id=?1",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    if state != "waiting" {
        return Ok(Value::Null);
    }
    let observed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM observers WHERE subscription_id=?1)
             OR EXISTS(SELECT 1 FROM native_observers WHERE subscription_id=?1)",
        [id],
        |row| row.get(0),
    )?;
    if observed {
        let mut producer = json!({"type":"automatic_configured", "health":"unverified"});
        let observation: Option<(Option<String>, Option<i64>)> = db
            .query_row(
                "SELECT last_reason,last_check FROM observers WHERE subscription_id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((Some(reason), checked)) = observation {
            producer["last_observation"] = json!(reason);
            producer["last_check"] = json!(checked);
        }
        return Ok(producer);
    }
    if matches!(
        kind.as_str(),
        "pull_request" | "review" | "deployment" | "git_ref"
    ) {
        return Ok(json!({"type":"automatic_capability", "health":"unverified"}));
    }
    let mut statement = db.prepare(
        "SELECT DISTINCT thread FROM obligations
         WHERE kind=?1 AND repo=?2 AND resource=?3 AND outcome=?4 AND resolved=0
         ORDER BY thread",
    )?;
    let threads = statement
        .query_map(params![kind, repo, resource, event], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if threads.is_empty() {
        Ok(
            json!({"type":"unknown", "warning":"No publisher is recorded in Wake for this event; the subscription may wait indefinitely."}),
        )
    } else {
        Ok(json!({"type":"obligation", "threads":threads}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_automatic_registered_unknown_and_finished() {
        let db = Connection::open_in_memory().unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::observers::initialize(&db).unwrap();
        crate::native_poll::initialize(&db).unwrap();
        crate::obligations::initialize(&db).unwrap();
        let destination = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let a =
            crate::subscriptions::subscribe(&db, "artifact", "ci", "pkg", "available", destination)
                .unwrap();
        let g = crate::subscriptions::subscribe(
            &db,
            "pull_request",
            "org/repo",
            "1",
            "merged",
            destination,
        )
        .unwrap();
        crate::obligations::register(
            &db,
            destination,
            "artifact",
            "different",
            "pkg",
            "available",
            "another namespace",
        )
        .unwrap();
        let n = crate::subscriptions::subscribe(
            &db,
            "thread",
            "",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "turn_completed",
            destination,
        )
        .unwrap();
        assert_eq!(status(&db, &a).unwrap()["type"], "unknown");
        let subscriptions = subscriptions_status(&db).unwrap();
        assert_eq!(
            subscriptions
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["id"] == a)
                .unwrap()["producer"]["type"],
            "unknown"
        );
        assert_eq!(
            status(&db, &g).unwrap(),
            json!({"type":"automatic_capability", "health":"unverified"})
        );
        assert_eq!(status(&db, &n).unwrap()["type"], "unknown");
        db.execute("INSERT INTO native_observers VALUES(?1,'source','destination',NULL,NULL,0,'unknown',NULL,0)", [&n]).unwrap();
        assert_eq!(
            status(&db, &n).unwrap(),
            json!({"type":"automatic_configured", "health":"unverified"})
        );
        let producer_a = "11111111-1111-4111-8111-111111111111";
        let producer_b = "22222222-2222-4222-8222-222222222222";
        for producer in [producer_b, producer_a, producer_a] {
            crate::obligations::register(
                &db,
                producer,
                "artifact",
                "ci",
                "pkg",
                "available",
                "publish",
            )
            .unwrap();
        }
        crate::obligations::register(
            &db,
            producer_b,
            "artifact",
            "ci",
            "other",
            "available",
            "publish",
        )
        .unwrap();
        assert_eq!(
            status(&db, &a).unwrap(),
            json!({"type":"obligation","threads":[producer_a,producer_b]})
        );
        crate::obligations::resolve_publication(&db, "artifact", "ci", "pkg", "available").unwrap();
        assert_eq!(status(&db, &a).unwrap()["type"], "unknown");
        crate::observers::attach(
            &db,
            &a,
            &crate::observers::Observation::File {
                path: "/tmp/wake-producer-test".into(),
            },
        )
        .unwrap();
        assert_eq!(
            status(&db, &a).unwrap(),
            json!({"type":"automatic_configured", "health":"unverified"})
        );
        db.execute(
            "UPDATE observers SET last_reason='unit_not_found',last_check=42 WHERE subscription_id=?1",
            [&a],
        )
        .unwrap();
        let producer = status(&db, &a).unwrap();
        assert_eq!(producer["health"], "unverified");
        assert_eq!(producer["last_observation"], "unit_not_found");
        assert_eq!(producer["last_check"], 42);
        db.execute("UPDATE subscriptions SET state='ready' WHERE id=?1", [&a])
            .unwrap();
        assert!(status(&db, &a).unwrap().is_null());
    }
}
