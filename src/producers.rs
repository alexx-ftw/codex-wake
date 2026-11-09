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

fn process_watch_producer(db: &Connection, id: &str) -> Result<Option<Value>> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='process_watches')",
        [],
        |row| row.get(0),
    )?;
    if !exists
        || !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM process_watches WHERE subscription_id=?1)",
            [id],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Ok(None);
    }
    let watch = crate::process_watch::status(db, id)?;
    let needs_attention =
        matches!(
            watch["state"].as_str(),
            Some("needs_attention" | "launch_uncertain" | "publish_error")
        ) || matches!(watch["retention_state"].as_str(), Some("error" | "failed"))
            || watch["supervisor_alive"] == false;
    Ok(Some(json!({
        "type":"process_watch",
        "health":if needs_attention { "needs_attention" } else { "unverified" },
        "state":watch["state"],
        "retention_state":watch["retention_state"],
        "supervisor_alive":watch["supervisor_alive"],
        "child_alive":watch["child_alive"],
        "diagnostic":watch["diagnostic"],
        "retention_diagnostic":watch["retention_diagnostic"]
    })))
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
    let watch = if kind == "job" && event == "completed" {
        process_watch_producer(db, id).unwrap_or_else(|_| {
            Some(json!({
                "type":"process_watch",
                "health":"needs_attention",
                "diagnostic":"Process-watch status is unavailable; inspect its database and output directory."
            }))
        })
    } else {
        None
    };
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
        if let Some(watch) = watch {
            producer["process_watch"] = watch;
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
        Ok(watch.unwrap_or_else(|| json!({"type":"unknown", "warning":"No publisher is recorded in Wake for this event; the subscription may wait indefinitely."})))
    } else {
        let mut producer = json!({"type":"obligation", "threads":threads});
        if let Some(watch) = watch {
            producer["process_watch"] = watch;
        }
        Ok(producer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inaccessible_watch_status_does_not_hide_other_subscriptions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = Connection::open(dir.path().join("state.sqlite")).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::observers::initialize(&db).unwrap();
        crate::native_poll::initialize(&db).unwrap();
        crate::obligations::initialize(&db).unwrap();
        crate::process_watch::initialize(&db).unwrap();
        let thread = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let watched =
            crate::subscriptions::subscribe(&db, "job", "local", "one", "completed", thread)
                .unwrap();
        let other =
            crate::subscriptions::subscribe(&db, "job", "local", "two", "completed", thread)
                .unwrap();
        db.execute("INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path) VALUES(?1,'watching',1,'test','x','/tmp/out','/tmp/err')", [&watched]).unwrap();
        let output = dir.path().join("process-watch");
        std::fs::create_dir(&output).unwrap();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755)).unwrap();
        let readable = subscription_status(&db, &watched).unwrap();
        assert!(readable["producer"]["diagnostic"].is_null());
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o755
        );
        db.execute(
            "UPDATE process_watches SET selection_json='invalid' WHERE subscription_id=?1",
            [&watched],
        )
        .unwrap();
        let rows = subscriptions_status(&db).unwrap();
        let rows = rows.as_array().unwrap();
        let broken = rows.iter().find(|row| row["id"] == watched).unwrap();
        assert_eq!(broken["producer"]["health"], "needs_attention");
        assert!(
            broken["producer"]["diagnostic"]
                .as_str()
                .unwrap()
                .contains("unavailable")
        );
        assert!(rows.iter().any(|row| row["id"] == other));
        assert_eq!(
            subscription_status(&db, &watched).unwrap()["producer"]["health"],
            "needs_attention"
        );
    }

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

    #[test]
    fn process_watch_status_reports_supervisor_and_failure_without_claiming_health() {
        let dir = tempfile::tempdir().unwrap();
        let db = Connection::open(dir.path().join("state.sqlite")).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::observers::initialize(&db).unwrap();
        crate::native_poll::initialize(&db).unwrap();
        crate::obligations::initialize(&db).unwrap();
        crate::process_watch::initialize(&db).unwrap();
        let id = crate::subscriptions::subscribe(
            &db,
            "job",
            "local",
            "build",
            "completed",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(status(&db, &id).unwrap()["type"], "unknown");
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let start = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let identity = format!("{}:{start}", boot.trim());
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path) VALUES(?1,'watching',?2,?3,'READY','/tmp/stdout','/tmp/stderr')",
            params![id, std::process::id(), identity],
        ).unwrap();
        let producer = subscription_status(&db, &id).unwrap()["producer"].clone();
        assert_eq!(producer["type"], "process_watch");
        assert_eq!(producer["health"], "unverified");
        assert_eq!(producer["state"], "watching");
        assert_eq!(producer["supervisor_alive"], true);
        assert_eq!(subscriptions_status(&db).unwrap()[0]["producer"], producer);

        let obligated = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        crate::obligations::register(
            &db,
            obligated,
            "job",
            "local",
            "build",
            "completed",
            "publish",
        )
        .unwrap();
        db.execute("UPDATE process_watches SET state='needs_attention',diagnostic='watch failed',retention_state='failed' WHERE subscription_id=?1", [&id]).unwrap();
        let obligated_status = status(&db, &id).unwrap();
        assert_eq!(obligated_status["type"], "obligation");
        assert_eq!(obligated_status["threads"], json!([obligated]));
        assert_eq!(
            obligated_status["process_watch"]["health"],
            "needs_attention"
        );
        db.execute(
            "INSERT INTO observers(subscription_id,config) VALUES(?1,'{}')",
            [&id],
        )
        .unwrap();
        let observed_status = status(&db, &id).unwrap();
        assert_eq!(observed_status["type"], "automatic_configured");
        assert_eq!(
            observed_status["process_watch"]["health"],
            "needs_attention"
        );
        db.execute("DELETE FROM observers WHERE subscription_id=?1", [&id])
            .unwrap();
        crate::obligations::resolve_publication(&db, "job", "local", "build", "completed").unwrap();

        let failed = status(&db, &id).unwrap();
        assert_eq!(failed["health"], "needs_attention");
        assert_eq!(failed["state"], "needs_attention");
        assert_eq!(failed["retention_state"], "failed");
        assert_eq!(failed["diagnostic"], "watch failed");

        db.execute("UPDATE process_watches SET state='watching',retention_state='not_started',supervisor_start='stale' WHERE subscription_id=?1", [&id]).unwrap();
        let stopped = status(&db, &id).unwrap();
        assert_eq!(stopped["supervisor_alive"], false);
        assert_eq!(stopped["health"], "needs_attention");
        db.execute("UPDATE subscriptions SET state='ready' WHERE id=?1", [&id])
            .unwrap();
        assert!(status(&db, &id).unwrap().is_null());
    }
}
