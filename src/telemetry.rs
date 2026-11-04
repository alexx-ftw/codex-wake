use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const DETAIL_DAYS: i64 = 42;
const ROLLUP_DAYS: i64 = 90;
const MAX_ROWS: i64 = 100_000;
const MAX_PAGE_COUNT: i64 = 16_384; // 64 MiB at SQLite's 4 KiB page size.
const PENDING_PREFIX: &str = "telemetry-pending-";
const PENDING_LOCK: &str = "telemetry-pending.lock";
const MAX_PENDING_FILE: u64 = 64 * 1024;
const MAX_PENDING_BYTES: u64 = 64 * 1024 * 1024;
const MIN_PENDING_ACCOUNTED_BYTES: u64 = 4096; // Count a directory entry's minimum filesystem allocation.
const MAX_PENDING_REPLAY: usize = 128;
const WRITE_WAIT: Duration = Duration::from_secs(1);
static BUILD_VERSION: OnceLock<String> = OnceLock::new();
static WRITER: Mutex<()> = Mutex::new(());
static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PendingEvent {
    id: String,
    at_ms: i64,
    sequence: u64,
    trace: String,
    parent: Option<String>,
    operation: String,
    outcome: String,
    reason: String,
    subject: Option<String>,
    duration_ms: i64,
    count: i64,
    pid: u32,
    version: String,
}

impl PendingEvent {
    fn valid(&self) -> bool {
        (0..253_402_300_800_000).contains(&self.at_ms)
            && self.duration_ms >= 0
            && self.count >= 0
            && self.pid > 0
    }
}

struct PendingFile {
    path: std::path::PathBuf,
    event: PendingEvent,
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

fn check_parent(parent: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "Telemetry parent must be a real directory"
    );
    ensure!(
        meta.uid() == current_uid()? && meta.mode() & 0o077 == 0,
        "Telemetry parent must be private and user-owned"
    );
    Ok(())
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

fn pending_lock(parent: &Path) -> Result<File> {
    check_parent(parent)?;
    let path = parent.join(PENDING_LOCK);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(_) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error).context("Create telemetry pending lock"),
    }
    let meta = fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_file(),
        "Telemetry pending lock must be a regular file"
    );
    ensure!(
        meta.uid() == current_uid()?,
        "Telemetry pending lock owner mismatch"
    );
    ensure!(
        meta.mode() & 0o777 == 0o600,
        "Telemetry pending lock mode must be 0600"
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = lock.metadata()?;
    ensure!(
        opened.is_file() && opened.uid() == current_uid()? && opened.mode() & 0o777 == 0o600,
        "Telemetry pending lock is not private"
    );
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("Lock telemetry pending files");
    }
    Ok(lock)
}

fn try_pending_lock(parent: &Path) -> Result<Option<File>> {
    check_parent(parent)?;
    let path = parent.join(PENDING_LOCK);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(_) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let meta = fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_file() && meta.uid() == current_uid()? && meta.mode() & 0o777 == 0o600,
        "Telemetry pending lock is not private"
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = lock.metadata()?;
    ensure!(
        opened.is_file() && opened.uid() == current_uid()? && opened.mode() & 0o777 == 0o600,
        "Telemetry pending lock is not private"
    );
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(Some(lock))
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error.into())
        }
    }
}

fn pending_paths(parent: &Path) -> Result<Vec<(std::path::PathBuf, u64)>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(PENDING_PREFIX) {
            continue;
        }
        let meta = fs::symlink_metadata(entry.path())?;
        files.push((entry.path(), meta.len()));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn save_pending(parent: &Path, event: &PendingEvent) -> Result<()> {
    let bytes = serde_json::to_vec(event)?;
    ensure!(
        bytes.len() as u64 <= MAX_PENDING_FILE,
        "Telemetry pending event exceeds size limit"
    );
    let _lock = pending_lock(parent)?;
    let files = pending_paths(parent)?;
    let used = files
        .iter()
        .try_fold(0u64, |sum, (_, size)| {
            sum.checked_add((*size).max(MIN_PENDING_ACCOUNTED_BYTES))
        })
        .context("Telemetry pending size overflow")?;
    ensure!(
        used.checked_add((bytes.len() as u64).max(MIN_PENDING_ACCOUNTED_BYTES))
            .is_some_and(|n| n <= MAX_PENDING_BYTES),
        "Telemetry pending capacity exceeded"
    );
    let path = parent.join(format!("{PENDING_PREFIX}{}.json", event.id));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .context("Create telemetry pending event")?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn load_pending(parent: &Path) -> Result<Vec<PendingFile>> {
    let _lock = pending_lock(parent)?;
    read_pending(parent)
}

fn try_load_pending(parent: &Path) -> Result<Option<Vec<PendingFile>>> {
    let Some(_lock) = try_pending_lock(parent)? else {
        return Ok(None);
    };
    Ok(Some(read_pending(parent)?))
}

fn read_pending(parent: &Path) -> Result<Vec<PendingFile>> {
    let mut pending = Vec::new();
    for (path, size) in pending_paths(parent)? {
        if size > MAX_PENDING_FILE {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(id) = name
            .strip_prefix(PENDING_PREFIX)
            .and_then(|n| n.strip_suffix(".json"))
        else {
            continue;
        };
        let Ok(uuid) = Uuid::parse_str(id) else {
            continue;
        };
        if uuid.to_string() != id {
            continue;
        }
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta)
                if meta.is_file()
                    && meta.uid() == current_uid()?
                    && meta.mode() & 0o777 == 0o600 =>
            {
                meta
            }
            _ => continue,
        };
        if meta.len() > MAX_PENDING_FILE {
            continue;
        }
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(_) => continue,
        };
        let opened_meta = file.metadata()?;
        if !opened_meta.is_file()
            || opened_meta.uid() != current_uid()?
            || opened_meta.mode() & 0o777 != 0o600
        {
            continue;
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        if file
            .take(MAX_PENDING_FILE + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_PENDING_FILE
        {
            continue;
        }
        let Ok(event) = serde_json::from_slice::<PendingEvent>(&bytes) else {
            continue;
        };
        if event.id != id || !event.valid() {
            continue;
        }
        pending.push(PendingFile { path, event });
    }
    pending.sort_by_key(|file| (file.event.at_ms, file.event.pid, file.event.sequence));
    pending.truncate(MAX_PENDING_REPLAY);
    Ok(pending)
}

fn pending_stats(parent: &Path) -> Result<(u64, u64, Option<i64>)> {
    let mut count = 0;
    let mut bytes = 0u64;
    let mut oldest = None;
    for (path, size) in pending_paths(parent)? {
        count += 1;
        bytes = bytes.saturating_add(size.max(MIN_PENDING_ACCOUNTED_BYTES));
        if size > MAX_PENDING_FILE {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file()
            || meta.uid() != current_uid()?
            || meta.mode() & 0o777 != 0o600
            || meta.len() > MAX_PENDING_FILE
        {
            continue;
        }
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        else {
            continue;
        };
        let opened_meta = file.metadata()?;
        if !opened_meta.is_file()
            || opened_meta.uid() != current_uid()?
            || opened_meta.mode() & 0o777 != 0o600
        {
            continue;
        }
        let mut raw = Vec::with_capacity(meta.len() as usize);
        if file
            .take(MAX_PENDING_FILE + 1)
            .read_to_end(&mut raw)
            .is_err()
            || raw.len() as u64 > MAX_PENDING_FILE
        {
            continue;
        }
        if let Ok(event) = serde_json::from_slice::<PendingEvent>(&raw) {
            let id_matches = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix(PENDING_PREFIX))
                .and_then(|name| name.strip_suffix(".json"))
                == Some(event.id.as_str());
            if id_matches && event.valid() {
                oldest = Some(oldest.map_or(event.at_ms, |old: i64| old.min(event.at_ms)));
            }
        }
    }
    Ok((count, bytes, oldest))
}

fn try_pending_ids(parent: &Path) -> Result<Option<Vec<String>>> {
    let Some(_lock) = try_pending_lock(parent)? else {
        return Ok(None);
    };
    Ok(Some(
        pending_paths(parent)?
            .into_iter()
            .filter_map(|(path, _)| {
                let name = path.file_name()?.to_str()?;
                let id = name.strip_prefix(PENDING_PREFIX)?.strip_suffix(".json")?;
                let parsed = Uuid::parse_str(id).ok()?;
                (parsed.to_string() == id).then(|| id.to_owned())
            })
            .collect(),
    ))
}

fn add_event(tx: &rusqlite::Transaction<'_>, event: &PendingEvent) -> Result<bool> {
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO events VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            event.id,
            event.at_ms,
            event.trace,
            event.parent,
            event.operation,
            event.outcome,
            event.reason,
            event.subject,
            event.duration_ms,
            event.count,
            event.pid,
            event.version
        ],
    )?;
    if inserted == 0 {
        return Ok(false);
    }
    let day: String = tx.query_row(
        "SELECT date(?1/1000,'unixepoch')",
        params![event.at_ms],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO rollups VALUES(?1,?2,?3,?4,1,?5,?6,?6)
         ON CONFLICT(day,operation,outcome,reason) DO UPDATE SET
         calls=calls+1,count=count+excluded.count,duration_ms=duration_ms+excluded.duration_ms,
         max_duration_ms=max(max_duration_ms,excluded.max_duration_ms)",
        params![
            day,
            event.operation,
            event.outcome,
            event.reason,
            event.count,
            event.duration_ms
        ],
    )?;
    Ok(true)
}

fn contention(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.to_string() == "Telemetry writer lock timed out")
        || error.chain().any(|cause| matches!(cause.downcast_ref::<rusqlite::Error>(), Some(rusqlite::Error::SqliteFailure(code, _)) if matches!(code.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)))
}

fn capture_event(event: &Event<'_>) -> Result<PendingEvent> {
    Ok(PendingEvent {
        id: Uuid::new_v4().to_string(),
        at_ms: unix_ms()?,
        sequence: EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        trace: event.trace.to_owned(),
        parent: event.parent.map(str::to_owned),
        operation: event.operation.to_owned(),
        outcome: event.outcome.to_owned(),
        reason: event.reason.to_owned(),
        subject: event.subject.map(str::to_owned),
        duration_ms: i64::try_from(event.duration_ms)
            .context("duration_ms exceeds SQLite integer range")?,
        count: i64::try_from(event.count).context("count exceeds SQLite integer range")?,
        pid: std::process::id(),
        version: build_version().to_owned(),
    })
}

fn replay_locked(
    db: &mut Connection,
    current: Option<&PendingEvent>,
    pending: &[PendingFile],
    parent: &Path,
) -> Result<()> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    enforce_page_limit(&tx)?;
    initialize_schema(&tx)?;
    for file in pending {
        if !file.path.exists() {
            continue;
        }
        let marked = tx.execute(
            "INSERT OR IGNORE INTO telemetry_pending_applied(id) VALUES(?1)",
            params![file.event.id],
        )?;
        if marked > 0 {
            add_event(&tx, &file.event)?;
        }
    }
    if let Some(current) = current {
        add_event(&tx, current)?;
    }
    let now = current.map_or(unix_ms()?, |event| event.at_ms);
    let cutoff_rollup: String = tx.query_row(
        "SELECT date(?1/1000,'unixepoch')",
        params![now - (ROLLUP_DAYS - 1) * 86_400_000],
        |row| row.get(0),
    )?;
    tx.execute("DELETE FROM rollups WHERE day < ?1", params![cutoff_rollup])?;
    let dropped = prune_details(&tx, now - DETAIL_DAYS * 86_400_000, MAX_ROWS)?;
    if dropped > 0 {
        tx.execute(
            "UPDATE telemetry_meta SET value=value+?1 WHERE key='dropped_detail'",
            params![dropped],
        )?;
        let day_text: String =
            tx.query_row("SELECT date(?1/1000,'unixepoch')", params![now], |row| {
                row.get(0)
            })?;
        tx.execute("INSERT INTO telemetry_meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=value+excluded.value", params![format!("dropped_detail:{day_text}"), dropped])?;
    }
    tx.execute("DELETE FROM telemetry_meta WHERE key LIKE 'dropped_detail:____-__-__' AND substr(key,16)< ?1", params![cutoff_rollup])?;
    tx.commit()?;

    // The data commit is authoritative; cleanup failures leave idempotent markers/files to retry.
    let _ = cleanup_pending_files(parent, pending);
    let _ = cleanup_applied(parent, db);
    Ok(())
}

fn cleanup_pending_files(parent: &Path, pending: &[PendingFile]) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let Some(_lock) = try_pending_lock(parent)? else {
        return Ok(());
    };
    for file in pending {
        if let Ok(meta) = fs::symlink_metadata(&file.path)
            && meta.is_file()
            && meta.uid() == current_uid()?
            && meta.mode() & 0o777 == 0o600
        {
            fs::remove_file(&file.path)?;
        }
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn cleanup_applied(parent: &Path, db: &mut Connection) -> Result<()> {
    let Some(present) = try_pending_ids(parent)? else {
        return Ok(());
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ids = {
        let mut stmt = tx.prepare("SELECT id FROM telemetry_pending_applied")?;
        stmt.query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let missing: Vec<_> = ids.into_iter().filter(|id| !present.contains(id)).collect();
    if !missing.is_empty() {
        // Persist file removal before forgetting the receipt that prevents replay duplication.
        File::open(parent)?.sync_all()?;
    }
    for id in missing {
        tx.execute(
            "DELETE FROM telemetry_pending_applied WHERE id=?1",
            params![id],
        )?;
    }
    tx.commit()?;
    Ok(())
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
    let captured = capture_event(event)?;
    let _writer = WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let parent = path.parent().context("Telemetry database has no parent")?;
    let pending = load_pending(parent).unwrap_or_default();
    let mut db = match open_write(path) {
        Ok(db) => db,
        Err(error) if contention(&error) => {
            save_pending(parent, &captured)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let process_lock = match lock_database(path) {
        Ok(lock) => lock,
        Err(error) if contention(&error) => {
            drop(db);
            save_pending(parent, &captured)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let pending = try_load_pending(parent).ok().flatten().unwrap_or(pending);
    let result = replay_locked(&mut db, Some(&captured), &pending, parent);
    drop(process_lock);
    match result {
        Ok(()) => Ok(()),
        Err(error) if contention(&error) => {
            drop(db);
            save_pending(parent, &captured)?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
fn recover_pending(path: &Path) -> Result<usize> {
    let _writer = WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let parent = path.parent().context("Telemetry database has no parent")?;
    let pending = load_pending(parent)?;
    if pending.is_empty() {
        return Ok(0);
    }
    let mut db = open_write(path)?;
    let _process_lock = lock_database(path)?;
    let recovered = pending.len();
    replay_locked(&mut db, None, &pending, parent)?;
    Ok(recovered)
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
         CREATE TABLE IF NOT EXISTS telemetry_pending_applied(id TEXT PRIMARY KEY);
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
    let (pending_count, pending_bytes, pending_oldest) =
        pending_stats(path.parent().context("Telemetry database has no parent")?)?;
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
        json!({"enabled":true,"schema_version":schema_version,"days":days,"daily_groups":groups,"daily_pruned_detail":daily_dropped,"recent_events":recent_events,"recent_problems":recent_problems,"incomplete_spans":incomplete_spans,"pending":{"count":pending_count,"bytes":pending_bytes,"oldest_unix_ms":pending_oldest,"max_bytes":MAX_PENDING_BYTES,"max_file_bytes":MAX_PENDING_FILE,"max_replay_per_record":MAX_PENDING_REPLAY},"retention":{"detail_days":DETAIL_DAYS,"rollup_days":ROLLUP_DAYS,"max_rows":MAX_ROWS,"max_file_bytes":MAX_PAGE_COUNT*4096,"dropped_detail":dropped,"earliest_unix_ms":bounds.0,"latest_unix_ms":bounds.1,"last_heartbeat_unix_ms":last_heartbeat.as_ref().map(|heartbeat| heartbeat.0),"last_heartbeat_outcome":last_heartbeat.map(|heartbeat| heartbeat.1)},"outcome_semantics":{"started":"The operation began; no later event for its trace and operation means the span is incomplete. Incomplete does not mean failed.","ok":"The instrumented request returned successfully; this does not imply that queued work or a turn finished.","queued":"Accepted for later work, not completion."}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    static LONG_CONTENTION_TESTS: Mutex<()> = Mutex::new(());

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

    fn pending_test_event(at_ms: i64) -> PendingEvent {
        PendingEvent {
            id: Uuid::new_v4().to_string(),
            at_ms,
            sequence: EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            trace: "trace-original".into(),
            parent: Some("parent-original".into()),
            operation: "heartbeat".into(),
            outcome: "ok".into(),
            reason: "static_reason".into(),
            subject: Some(subject("fixture-safe-subject")),
            duration_ms: 23,
            count: 4,
            pid: 4242,
            version: "test:version".into(),
        }
    }

    #[test]
    fn long_flock_timeout_spools_original_event_and_recovers_without_new_record() {
        let _serial = LONG_CONTENTION_TESTS.lock().unwrap();
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        let held_path = path.clone();
        let (ready, waiting) = std::sync::mpsc::channel();
        let holder = thread::spawn(move || {
            let _lock = lock_database(&held_path).unwrap();
            ready.send(()).unwrap();
            thread::sleep(Duration::from_secs(2));
        });
        waiting.recv().unwrap();
        let before = unix_ms().unwrap();
        record(
            &path,
            &Event {
                trace: "original-trace",
                parent: Some("original-parent"),
                operation: "heartbeat",
                outcome: "ok",
                reason: "static_reason",
                subject: Some(&subject("safe")),
                duration_ms: 23,
                count: 4,
            },
        )
        .unwrap();
        let pending = load_pending(dir.path()).unwrap();
        assert_eq!(pending.len(), 1);
        let captured = &pending[0].event;
        assert!(captured.at_ms >= before && captured.at_ms <= before + 20);
        assert_eq!(captured.trace, "original-trace");
        assert_eq!(captured.parent.as_deref(), Some("original-parent"));
        assert_eq!(captured.pid, std::process::id());
        assert!(
            captured
                .version
                .starts_with(concat!(env!("CARGO_PKG_VERSION"), ":"))
        );
        holder.join().unwrap();

        assert_eq!(recover_pending(&path).unwrap(), 1);
        let db = Connection::open(&path).unwrap();
        let row: (i64, String, i64, String) = db
            .query_row(
                "SELECT at_ms,trace,pid,version FROM events WHERE id=?1",
                params![captured.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row.0, captured.at_ms);
        assert_eq!(row.1, "original-trace");
        assert_eq!(row.2, i64::from(captured.pid));
        assert_eq!(row.3, captured.version);
        assert_eq!(pending_stats(dir.path()).unwrap().0, 0);
    }

    #[test]
    fn long_sqlite_reader_busy_spools_and_recovers_event() {
        let _serial = LONG_CONTENTION_TESTS.lock().unwrap();
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        let held_path = path.clone();
        let (ready, waiting) = std::sync::mpsc::channel();
        let holder = thread::spawn(move || {
            let db = Connection::open(&held_path).unwrap();
            db.execute_batch("BEGIN").unwrap();
            let _: i64 = db
                .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
                .unwrap();
            ready.send(()).unwrap();
            thread::sleep(Duration::from_secs(2));
            db.execute_batch("COMMIT").unwrap();
        });
        waiting.recv().unwrap();
        record(
            &path,
            &Event {
                trace: "reader-blocked",
                parent: None,
                operation: "heartbeat",
                outcome: "ok",
                reason: "reader_busy",
                subject: None,
                duration_ms: 5,
                count: 1,
            },
        )
        .unwrap();
        assert_eq!(pending_stats(dir.path()).unwrap().0, 1);
        holder.join().unwrap();
        assert_eq!(recover_pending(&path).unwrap(), 1);
        let report = report(&path, 1).unwrap();
        assert_eq!(report["pending"]["count"], 0);
        assert_eq!(report["daily_groups"][0]["calls"], 1);
    }

    #[test]
    fn replay_order_is_preserved_across_batch_boundaries() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        let mut start = pending_test_event(unix_ms().unwrap());
        start.outcome = "started".into();
        save_pending(dir.path(), &start).unwrap();
        for n in 1..MAX_PENDING_REPLAY {
            let mut middle = pending_test_event(start.at_ms);
            middle.trace = format!("other-{n}");
            save_pending(dir.path(), &middle).unwrap();
        }
        let end = pending_test_event(start.at_ms);
        save_pending(dir.path(), &end).unwrap();
        assert_eq!(recover_pending(&path).unwrap(), MAX_PENDING_REPLAY);
        assert_eq!(
            report(&path, 1).unwrap()["incomplete_spans"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(recover_pending(&path).unwrap(), 1);
        assert!(
            report(&path, 1).unwrap()["incomplete_spans"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn replay_keeps_same_millisecond_span_order() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        let mut start = pending_test_event(unix_ms().unwrap());
        start.id = "ffffffff-ffff-4fff-8fff-ffffffffffff".into();
        start.outcome = "started".into();
        let mut end = pending_test_event(start.at_ms);
        end.id = "00000000-0000-4000-8000-000000000001".into();
        save_pending(dir.path(), &start).unwrap();
        save_pending(dir.path(), &end).unwrap();
        recover_pending(&path).unwrap();
        assert!(
            report(&path, 1).unwrap()["incomplete_spans"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn invalid_pending_timestamp_does_not_poison_new_events() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        let invalid = pending_test_event(i64::MAX);
        save_pending(dir.path(), &invalid).unwrap();
        record(&path, &event("valid-after-invalid", "ok", None)).unwrap();
        let db = Connection::open(&path).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn committed_pending_marker_prevents_duplicate_rollup_after_aged_pruning() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        let event = pending_test_event(unix_ms().unwrap() - 43 * 86_400_000);
        save_pending(dir.path(), &event).unwrap();
        let mut db = open_write(&path).unwrap();
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        initialize_schema(&tx).unwrap();
        tx.execute(
            "INSERT INTO telemetry_pending_applied(id) VALUES(?1)",
            params![event.id],
        )
        .unwrap();
        add_event(&tx, &event).unwrap();
        prune_details(&tx, unix_ms().unwrap() - DETAIL_DAYS * 86_400_000, MAX_ROWS).unwrap();
        tx.commit().unwrap(); // Simulates process death before pending-file unlink.

        assert_eq!(recover_pending(&path).unwrap(), 1);
        let calls: i64 = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT calls FROM rollups WHERE operation='heartbeat'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let detail: i64 = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM events WHERE id=?1",
                params![event.id],
                |row| row.get(0),
            )
            .unwrap();
        let markers: i64 = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM telemetry_pending_applied",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(detail, 0);
        assert_eq!(markers, 0);
    }

    #[test]
    fn incomplete_symlink_invalid_and_over_cap_pending_files_are_skipped_safely() {
        let dir = private_tempdir();
        let path = dir.path().join("telemetry.sqlite3");
        initialize(&path).unwrap();
        let incomplete = dir
            .path()
            .join(format!("{PENDING_PREFIX}{}.json", Uuid::new_v4()));
        fs::write(&incomplete, b"{in progress").unwrap();
        fs::set_permissions(&incomplete, fs::Permissions::from_mode(0o600)).unwrap();
        let outside = dir.path().join("safe-target");
        fs::write(&outside, b"not an event").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir
            .path()
            .join(format!("{PENDING_PREFIX}{}.json", Uuid::new_v4()));
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let mismatch = dir
            .path()
            .join(format!("{PENDING_PREFIX}{}.json", Uuid::new_v4()));
        let mismatched_event = pending_test_event(unix_ms().unwrap());
        fs::write(&mismatch, serde_json::to_vec(&mismatched_event).unwrap()).unwrap();
        fs::set_permissions(&mismatch, fs::Permissions::from_mode(0o600)).unwrap();
        let too_large = dir
            .path()
            .join(format!("{PENDING_PREFIX}{}.json", Uuid::new_v4()));
        let large = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&too_large)
            .unwrap();
        large.set_len(MAX_PENDING_FILE + 1).unwrap();
        let oversized = dir
            .path()
            .join(format!("{PENDING_PREFIX}{}.json", Uuid::new_v4()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&oversized)
            .unwrap();
        file.set_len(MAX_PENDING_BYTES).unwrap();

        assert!(load_pending(dir.path()).unwrap().is_empty());
        assert_eq!(recover_pending(&path).unwrap(), 0);
        assert!(save_pending(dir.path(), &pending_test_event(unix_ms().unwrap())).is_err());
        let stats = pending_stats(dir.path()).unwrap();
        assert_eq!(stats.0, 5);
        assert!(stats.1 >= MAX_PENDING_BYTES);
        assert!(!fs::read(&outside).unwrap().starts_with(b"{"));
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
