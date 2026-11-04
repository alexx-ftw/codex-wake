use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const DETAIL_DAYS: i64 = 42;
const ROLLUP_DAYS: i64 = 90;
const MAX_ROWS: i64 = 100_000;
const MAX_PAGE_COUNT: i64 = 16_384; // 64 MiB at SQLite's 4 KiB page size.
const WRITE_WAIT: Duration = Duration::from_secs(1);
static BUILD_VERSION: OnceLock<String> = OnceLock::new();
static WRITER: Mutex<()> = Mutex::new(());

pub struct Event<'a> {
    pub trace: &'a str,
    pub parent: Option<&'a str>,
    pub operation: &'a str,
    pub outcome: &'a str,
    pub reason: &'a str,
    pub subject: Option<&'a str>,
    pub duration_ms: u64,
    pub count: u64,
}

pub fn subject(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_ms() -> Result<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("Current time exceeds SQLite integer range")
}

fn build_version() -> &'static str {
    BUILD_VERSION.get_or_init(|| {
        format!(
            "{}:{}",
            env!("CARGO_PKG_VERSION"),
            &crate::manager::source_digest()[..24]
        )
    })
}

fn current_uid() -> Result<u32> {
    Ok(fs::metadata("/proc/self")?.uid())
}

fn check_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(meta.is_file(), "Telemetry database must be a regular file");
    ensure!(
        meta.uid() == current_uid()?,
        "Telemetry database owner mismatch"
    );
    ensure!(
        meta.mode() & 0o777 == 0o600,
        "Telemetry database mode must be 0600"
    );
    Ok(())
}

fn open_write(path: &Path) -> Result<Connection> {
    let parent = path.parent().context("Telemetry database has no parent")?;
    let parent_meta = fs::symlink_metadata(parent)?;
    ensure!(
        parent_meta.is_dir() && !parent_meta.file_type().is_symlink(),
        "Telemetry parent must be a real directory"
    );
    ensure!(
        parent_meta.uid() == current_uid()? && parent_meta.mode() & 0o077 == 0,
        "Telemetry parent must be private and user-owned"
    );
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(_) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error).context("Create telemetry database"),
    }
    check_file(path)?;
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    check_file(path)?;
    db.busy_timeout(WRITE_WAIT)?;
    Ok(db)
}

fn lock_database(path: &Path) -> Result<fs::File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let deadline = Instant::now() + WRITE_WAIT;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(lock);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock
            && error.raw_os_error() != Some(libc::EINTR)
        {
            return Err(error).context("Lock telemetry database");
        }
        ensure!(Instant::now() < deadline, "Telemetry writer lock timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub fn initialize(path: &Path) -> Result<()> {
    let _writer = WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut db = open_write(path)?;
    let _process_lock = lock_database(path)?;
    let journal_mode: String = db.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        db.pragma_update(None, "journal_mode", "DELETE")?;
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    enforce_page_limit(&tx)?;
    initialize_schema(&tx)?;
    tx.commit()?;
    Ok(())
}

pub fn record(path: &Path, event: &Event<'_>) -> Result<()> {
    let version = build_version().to_owned();
    let _writer = WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let duration_ms =
        i64::try_from(event.duration_ms).context("duration_ms exceeds SQLite integer range")?;
    let count = i64::try_from(event.count).context("count exceeds SQLite integer range")?;
    let mut db = open_write(path)?;
    let _process_lock = lock_database(path)?;
    let now = unix_ms()?;
    let day_text: String =
        db.query_row("SELECT date(?1/1000,'unixepoch')", params![now], |row| {
            row.get(0)
        })?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    enforce_page_limit(&tx)?;
    initialize_schema(&tx)?;
    tx.execute(
        "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            Uuid::new_v4().to_string(),
            now,
            event.trace,
            event.parent,
            event.operation,
            event.outcome,
            event.reason,
            event.subject,
            duration_ms,
            count,
            std::process::id(),
            version
        ],
    )?;
    tx.execute(
        "INSERT INTO rollups VALUES(?1,?2,?3,?4,1,?5,?6,?6)
         ON CONFLICT(day,operation,outcome,reason) DO UPDATE SET
         calls=calls+1,count=count+excluded.count,duration_ms=duration_ms+excluded.duration_ms,
         max_duration_ms=max(max_duration_ms,excluded.max_duration_ms)",
        params![
            day_text,
            event.operation,
            event.outcome,
            event.reason,
            count,
            duration_ms
        ],
    )?;
    let cutoff_rollup: String = tx.query_row(
        "SELECT date(?1/1000,'unixepoch')",
        params![now - (ROLLUP_DAYS - 1) * 86_400_000],
        |row| row.get(0),
    )?;
    tx.execute("DELETE FROM rollups WHERE day < ?1", params![cutoff_rollup])?;
    let cutoff = now - DETAIL_DAYS * 86_400_000;
    let dropped = prune_details(&tx, cutoff, MAX_ROWS)?;
    if dropped > 0 {
        tx.execute(
            "UPDATE telemetry_meta SET value=value+?1 WHERE key='dropped_detail'",
            params![dropped],
        )?;
        tx.execute(
            "INSERT INTO telemetry_meta(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=value+excluded.value",
            params![format!("dropped_detail:{day_text}"), dropped],
        )?;
    }
    tx.execute(
        "DELETE FROM telemetry_meta WHERE key LIKE 'dropped_detail:____-__-__' AND substr(key,16)< ?1",
        params![cutoff_rollup],
    )?;
    tx.commit()?;
    Ok(())
}

fn prune_details(tx: &rusqlite::Transaction<'_>, cutoff_ms: i64, max_rows: i64) -> Result<i64> {
    let aged = tx.execute("DELETE FROM events WHERE at_ms < ?1", params![cutoff_ms])? as i64;
    let overflow = tx.execute(
        "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY at_ms DESC LIMIT -1 OFFSET ?1)",
        params![max_rows],
    )? as i64;
    Ok(aged + overflow)
}

fn initialize_schema(db: &rusqlite::Transaction<'_>) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,at_ms INTEGER NOT NULL,trace TEXT NOT NULL,parent TEXT,operation TEXT NOT NULL,outcome TEXT NOT NULL,reason TEXT NOT NULL,subject TEXT,duration_ms INTEGER NOT NULL,count INTEGER NOT NULL,pid INTEGER NOT NULL,version TEXT NOT NULL);
         CREATE INDEX IF NOT EXISTS events_at ON events(at_ms DESC);
         CREATE INDEX IF NOT EXISTS events_trace_operation_at ON events(trace,operation,at_ms);
         CREATE TABLE IF NOT EXISTS rollups(day TEXT NOT NULL,operation TEXT NOT NULL,outcome TEXT NOT NULL,reason TEXT NOT NULL,calls INTEGER NOT NULL,count INTEGER NOT NULL,duration_ms INTEGER NOT NULL,max_duration_ms INTEGER NOT NULL,PRIMARY KEY(day,operation,outcome,reason));
         CREATE TABLE IF NOT EXISTS telemetry_meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
         INSERT OR IGNORE INTO telemetry_meta(key,value) VALUES('dropped_detail',0),('schema_version',1);",
    )?;
    Ok(())
}

fn enforce_page_limit(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    let current: i64 = tx.pragma_query_value(None, "max_page_count", |row| row.get(0))?;
    if current > MAX_PAGE_COUNT {
        tx.pragma_update(None, "max_page_count", MAX_PAGE_COUNT)?;
    }
    Ok(())
}

fn event_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "unix_ms":row.get::<_,i64>(0)?,"trace":row.get::<_,String>(1)?,
        "parent":row.get::<_,Option<String>>(2)?,"operation":row.get::<_,String>(3)?,
        "outcome":row.get::<_,String>(4)?,"reason":row.get::<_,String>(5)?,
        "subject":row.get::<_,Option<String>>(6)?,"duration_ms":row.get::<_,i64>(7)?,
        "count":row.get::<_,i64>(8)?,"pid":row.get::<_,i64>(9)?,"version":row.get::<_,String>(10)?
    }))
}

pub fn report(path: &Path, days: u32) -> Result<Value> {
    ensure!((1..=90).contains(&days), "days must be between 1 and 90");
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"enabled":false}));
        }
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    check_file(path)?;
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(Duration::from_millis(250))?;
    let cutoff_day: String = db.query_row(
        "SELECT date(?1/1000,'unixepoch')",
        params![unix_ms()? - (i64::from(days) - 1) * 86_400_000],
        |row| row.get(0),
    )?;
    let mut statement = db.prepare("SELECT day,operation,outcome,reason,calls,count,duration_ms,max_duration_ms FROM rollups WHERE day>=? ORDER BY day,operation,outcome,reason")?;
    let groups = statement.query_map(params![cutoff_day], |row| Ok(json!({
        "day": row.get::<_,String>(0)?, "operation":row.get::<_,String>(1)?, "outcome":row.get::<_,String>(2)?, "reason":row.get::<_,String>(3)?,
        "calls":row.get::<_,i64>(4)?, "count":row.get::<_,i64>(5)?, "duration_ms":row.get::<_,i64>(6)?, "max_duration_ms":row.get::<_,i64>(7)?
    })))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let recent_events = db.prepare("SELECT at_ms,trace,parent,operation,outcome,reason,subject,duration_ms,count,pid,version FROM events ORDER BY at_ms DESC,rowid DESC LIMIT 50")?
        .query_map([], event_json)?.collect::<rusqlite::Result<Vec<_>>>()?;
    let recent_problems = db.prepare("SELECT at_ms,trace,parent,operation,outcome,reason,subject,duration_ms,count,pid,version FROM events WHERE outcome IN ('error','rejected','needs_attention','warning','ready') ORDER BY at_ms DESC,rowid DESC LIMIT 50")?
        .query_map([], event_json)?.collect::<rusqlite::Result<Vec<_>>>()?;
    let incomplete_spans = db.prepare("SELECT e.trace,e.operation,e.at_ms FROM events e WHERE e.outcome='started' AND e.operation NOT IN ('cli.mcp','cli.receiver') AND NOT EXISTS (SELECT 1 FROM events t WHERE t.trace=e.trace AND t.operation=e.operation AND (t.at_ms>e.at_ms OR (t.at_ms=e.at_ms AND t.rowid>e.rowid)) AND t.outcome<>'started') ORDER BY e.at_ms DESC,e.rowid DESC LIMIT 50")?
        .query_map([], |row| Ok(json!({"trace":row.get::<_,String>(0)?,"operation":row.get::<_,String>(1)?,"started_unix_ms":row.get::<_,i64>(2)?,"state":"incomplete"})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let schema_version: i64 = db.query_row(
        "SELECT value FROM telemetry_meta WHERE key='schema_version'",
        [],
        |row| row.get(0),
    )?;
    let dropped: i64 = db.query_row(
        "SELECT value FROM telemetry_meta WHERE key='dropped_detail'",
        [],
        |row| row.get(0),
    )?;
    let daily_dropped = db
        .prepare("SELECT substr(key,16),value FROM telemetry_meta WHERE key LIKE 'dropped_detail:____-__-__' AND substr(key,16)>=? ORDER BY key")?
        .query_map(params![cutoff_day], |row| {
            Ok(json!({"day":row.get::<_,String>(0)?,"dropped":row.get::<_,i64>(1)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let bounds: (Option<i64>, Option<i64>) =
        db.query_row("SELECT min(at_ms),max(at_ms) FROM events", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    let last_heartbeat: Option<(i64, String)> = db
        .query_row(
            "SELECT at_ms,outcome FROM events WHERE operation='receiver.heartbeat' ORDER BY at_ms DESC,rowid DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(
        json!({"enabled":true,"schema_version":schema_version,"days":days,"daily_groups":groups,"daily_pruned_detail":daily_dropped,"recent_events":recent_events,"recent_problems":recent_problems,"incomplete_spans":incomplete_spans,"retention":{"detail_days":DETAIL_DAYS,"rollup_days":ROLLUP_DAYS,"max_rows":MAX_ROWS,"max_file_bytes":MAX_PAGE_COUNT*4096,"dropped_detail":dropped,"earliest_unix_ms":bounds.0,"latest_unix_ms":bounds.1,"last_heartbeat_unix_ms":last_heartbeat.as_ref().map(|heartbeat| heartbeat.0),"last_heartbeat_outcome":last_heartbeat.map(|heartbeat| heartbeat.1)},"outcome_semantics":{"started":"The operation began; no later event for its trace and operation means the span is incomplete. Incomplete does not mean failed.","ok":"The instrumented request returned successfully; this does not imply that queued work or a turn finished.","queued":"Accepted for later work, not completion."}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_lock_timeout_has_a_specific_private_classification() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        let lock = lock_database(&path).unwrap();
        let error = lock_database(&path).unwrap_err();
        assert_eq!(
            crate::observability::error_class(&error.context("record event")),
            "telemetry_writer_lock_timeout"
        );
        drop(lock);
        assert!(lock_database(&path).is_ok());
    }
    use std::{os::unix::fs::PermissionsExt, sync::Arc, thread};

    fn event<'a>(trace: &'a str, outcome: &'a str, subject: Option<&'a str>) -> Event<'a> {
        Event {
            trace,
            parent: None,
            operation: "dispatch",
            outcome,
            reason: "done",
            subject,
            duration_ms: 7,
            count: 2,
        }
    }

    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn transient_reader_and_writer_contention_keep_the_event() {
        for reader in [false, true] {
            let dir = private_tempdir();
            let path = dir.path().join("telemetry.sqlite3");
            initialize(&path).unwrap();
            let blocked_path = path.clone();
            let (ready, waiting) = std::sync::mpsc::channel();
            let holder = thread::spawn(move || {
                if reader {
                    let db = Connection::open(&blocked_path).unwrap();
                    db.execute_batch("BEGIN").unwrap();
                    let _: i64 = db
                        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
                        .unwrap();
                    ready.send(()).unwrap();
                    thread::sleep(Duration::from_millis(400));
                    db.execute_batch("COMMIT").unwrap();
                } else {
                    let _lock = lock_database(&blocked_path).unwrap();
                    ready.send(()).unwrap();
                    thread::sleep(Duration::from_millis(400));
                }
            });
            waiting.recv().unwrap();
            let result = record(&path, &event("transient-lock", "ok", None));
            holder.join().unwrap();
            result.unwrap();
            let db = Connection::open(&path).unwrap();
            let count: i64 = db
                .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn persists_aggregates_and_keeps_subject_private() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        let hash = subject("sensitive input");
        initialize(&path).unwrap();
        record(&path, &event("trace-1", "error", Some(&hash))).unwrap();
        drop(Connection::open(&path).unwrap());
        let report = report(&path, 1).unwrap();
        assert_eq!(report["daily_groups"][0]["calls"], 1);
        assert_eq!(report["daily_groups"][0]["count"], 2);
        assert_eq!(report["recent_problems"][0]["subject"], hash);
        let version = report["recent_events"][0]["version"].as_str().unwrap();
        assert!(version.starts_with(concat!(env!("CARGO_PKG_VERSION"), ":")));
        assert_eq!(version.rsplit(':').next().unwrap().len(), 24);
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["retention"]["max_file_bytes"], 64 * 1024 * 1024);
        assert_eq!(report["retention"]["last_heartbeat_unix_ms"], Value::Null);
        assert_eq!(hash.len(), 24);
        assert!(!hash.contains("sensitive"));
    }

    #[test]
    fn first_record_initializes_schema_and_page_limit_is_connection_local() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        record(&path, &event("first", "ok", None)).unwrap();
        let report = report(&path, 1).unwrap();
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["daily_groups"][0]["calls"], 1);
        let mut db = open_write(&path).unwrap();
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        enforce_page_limit(&tx).unwrap();
        let pages: i64 = tx
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .unwrap();
        assert!(pages <= MAX_PAGE_COUNT);
        tx.commit().unwrap();
    }

    #[test]
    fn heartbeat_is_receiver_specific_not_latest_event_time() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        record(
            &path,
            &Event {
                trace: "receiver",
                parent: None,
                operation: "receiver.heartbeat",
                outcome: "ok",
                reason: "",
                subject: None,
                duration_ms: 1,
                count: 1,
            },
        )
        .unwrap();
        record(&path, &event("later", "ok", None)).unwrap();
        let report = report(&path, 1).unwrap();
        let heartbeat = report["retention"]["last_heartbeat_unix_ms"]
            .as_i64()
            .unwrap();
        let latest = report["retention"]["latest_unix_ms"].as_i64().unwrap();
        assert!(heartbeat <= latest);
        assert_eq!(report["retention"]["last_heartbeat_outcome"], "ok");
    }

    #[test]
    fn separates_recent_problems_and_incomplete_spans_from_request_success() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        record(&path, &event("finished", "started", None)).unwrap();
        record(&path, &event("finished", "queued", None)).unwrap();
        record(&path, &event("pending", "started", None)).unwrap();
        record(&path, &event("request", "ok", None)).unwrap();
        record(&path, &event("problem", "needs_attention", None)).unwrap();
        let report = report(&path, 1).unwrap();
        assert_eq!(report["recent_events"].as_array().unwrap().len(), 5);
        assert_eq!(report["recent_problems"].as_array().unwrap().len(), 1);
        assert_eq!(report["recent_problems"][0]["outcome"], "needs_attention");
        assert_eq!(report["incomplete_spans"].as_array().unwrap().len(), 1);
        assert_eq!(report["incomplete_spans"][0]["trace"], "pending");
        assert_eq!(report["incomplete_spans"][0]["state"], "incomplete");
        assert_eq!(
            report["outcome_semantics"]["queued"],
            "Accepted for later work, not completion."
        );
    }

    #[test]
    fn rejects_symlink_and_bad_mode_and_missing_report_is_side_effect_free() {
        let dir = private_tempdir();
        let missing = dir.path().join("absent.sqlite3");
        assert_eq!(report(&missing, 30).unwrap(), json!({"enabled":false}));
        assert!(!missing.exists());
        let absent_parent = dir.path().join("removed-state");
        assert!(initialize(&absent_parent.join("telemetry.sqlite3")).is_err());
        assert!(!absent_parent.exists());
        let real = dir.path().join("real.sqlite3");
        initialize(&real).unwrap();
        let link = dir.path().join("link.sqlite3");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(initialize(&link).is_err());
        fs::set_permissions(&real, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(report(&real, 1).is_err());
    }

    #[test]
    fn prunes_old_detail_but_preserves_rollup() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        record(&path, &event("old", "failure", None)).unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute(
            "UPDATE events SET at_ms=?1",
            params![unix_ms().unwrap() - 43 * 86_400_000],
        )
        .unwrap();
        drop(db);
        record(&path, &event("new", "success", None)).unwrap();
        let report = report(&path, 90).unwrap();
        assert_eq!(report["retention"]["dropped_detail"], 1);
        let sum: i64 = report["daily_groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["calls"].as_i64().unwrap())
            .sum();
        assert_eq!(sum, 2);
    }

    #[test]
    fn prunes_capacity_overflow_and_counts_dropped_rows() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        for i in 0..4 {
            let trace = format!("trace-{i}");
            record(&path, &event(&trace, "success", None)).unwrap();
        }
        let mut db = Connection::open(&path).unwrap();
        let tx = db.transaction().unwrap();
        let dropped = prune_details(&tx, i64::MIN, 2).unwrap();
        tx.execute(
            "UPDATE telemetry_meta SET value=value+?1 WHERE key='dropped_detail'",
            params![dropped],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(report(&path, 1).unwrap()["retention"]["dropped_detail"], 2);
        let count: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn concurrent_writers_do_not_lose_rollup_updates() {
        let dir = private_tempdir();
        let path = Arc::new(dir.path().join("telemetry.sqlite3"));
        initialize(&path).unwrap();
        let joins: Vec<_> = (0..6)
            .map(|worker| {
                let path = Arc::clone(&path);
                thread::spawn(move || {
                    for i in 0..8 {
                        let trace = format!("{worker}-{i}");
                        record(&path, &event(&trace, "success", None)).unwrap();
                    }
                })
            })
            .collect();
        for join in joins {
            join.join().unwrap();
        }
        assert_eq!(report(&path, 1).unwrap()["daily_groups"][0]["calls"], 48);
    }
}
