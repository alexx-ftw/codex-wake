use anyhow::{Context, Result, anyhow, ensure};
use regex::bytes::Regex;
use regex_syntax::hir::{Hir, HirKind, Look};
use rusqlite::{Connection, Error as SqlError, ErrorCode, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    os::unix::process::CommandExt,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use wait_timeout::ChildExt;

const WINDOW: usize = 1024 * 1024;
const POLL: Duration = Duration::from_millis(20);
const RETAIN_INTERVAL: Duration = Duration::from_millis(250);
const PUBLISH_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const START_RESOLUTION_WAIT: Duration = Duration::from_secs(5);
const CLAIM_CONFIRMATION_WAIT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Selection {
    reason: String,
    stream: Option<String>,
    observed_at_ms: i64,
    exit_code: Option<i32>,
    success: Option<bool>,
    recovered: bool,
    candidates: Option<Vec<String>>,
}

struct Watch {
    regex: String,
    child_pid: Option<u32>,
    child_start: Option<String>,
    deadline_at_ms: Option<i64>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    selection: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct ChildIdentity {
    pid: u32,
    start: String,
    started_at_ms: i64,
    deadline_at_ms: i64,
    #[serde(default)]
    stdout_file: Option<FileIdentity>,
    #[serde(default)]
    stderr_file: Option<FileIdentity>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

struct OutputPaths {
    stdout: PathBuf,
    stderr: PathBuf,
    writers: [File; 2],
    identities: [FileIdentity; 2],
}

struct OutputTail {
    files: [File; 2],
    windows: [Vec<u8>; 2],
    window_preceding: [Vec<u8>; 2],
    matched: [bool; 2],
    limit: Option<[u64; 2]>,
    match_context: [Option<Vec<u8>>; 2],
}

struct OutputScan {
    matched: Option<MatchObservation>,
    eof: [bool; 2],
}

struct MatchObservation {
    stream: &'static str,
    observed_at: Instant,
    observed_at_ms: i64,
}

enum ProcessObservation {
    Running,
    Exited(Option<ExitStatus>),
}

struct FinishContext<'a> {
    id: &'a str,
    pid: u32,
    stdout: &'a Path,
    stderr: &'a Path,
    outputs: Option<&'a OutputTail>,
    child: Option<Child>,
}

struct ReaperContext {
    database: PathBuf,
    database_identity: FileIdentity,
    id: String,
    pid: u32,
    child_start: String,
    stdout: PathBuf,
    stderr: PathBuf,
    selected: Selection,
    match_context: Option<Vec<u8>>,
    child: Option<Child>,
}

type WatchRegistration = (String, String, String, Option<i64>, Option<i64>);
type PublishedRegistration = (
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    bool,
    Option<String>,
);
type WatchStatus = (
    String,
    u32,
    String,
    Option<i64>,
    Option<String>,
    String,
    Option<String>,
);
type RecoveryRow = (
    String,
    u32,
    String,
    String,
    Option<u32>,
    Option<String>,
    bool,
    String,
);

struct MonitorContext<'a> {
    db: &'a Connection,
    id: &'a str,
    regex: &'a WatchRegex,
    child_pid: u32,
    child_start: &'a str,
    deadline: Instant,
    deadline_at_ms: i64,
    recovered: bool,
    stdout: &'a Path,
    stderr: &'a Path,
}

impl<'a> FinishContext<'a> {
    fn monitor(
        monitor: &'a MonitorContext<'_>,
        outputs: &'a OutputTail,
        child: Option<Child>,
    ) -> Self {
        Self {
            id: monitor.id,
            pid: monitor.child_pid,
            stdout: monitor.stdout,
            stderr: monitor.stderr,
            outputs: Some(outputs),
            child,
        }
    }

    fn resumed(id: &'a str, pid: u32, watch: &'a Watch, outputs: Option<&'a OutputTail>) -> Self {
        Self {
            id,
            pid,
            stdout: &watch.stdout_path,
            stderr: &watch.stderr_path,
            outputs,
            child: None,
        }
    }
}

impl OutputTail {
    fn open(stdout: &Path, stderr: &Path) -> Result<Self> {
        Ok(Self {
            files: [
                open_regular_nofollow(stdout, true, false)?,
                open_regular_nofollow(stderr, true, false)?,
            ],
            windows: [Vec::new(), Vec::new()],
            window_preceding: [Vec::new(), Vec::new()],
            matched: [false, false],
            limit: None,
            match_context: [None, None],
        })
    }

    fn verify_file_identities(&self, expected: [FileIdentity; 2]) -> Result<()> {
        for (file, expected) in self.files.iter().zip(expected) {
            ensure!(
                file_identity(file)? == expected,
                "Output path no longer names the original file"
            );
        }
        Ok(())
    }

    fn snapshot_lengths(&self) -> Result<[u64; 2]> {
        Ok([
            self.files[0].metadata()?.len(),
            self.files[1].metadata()?.len(),
        ])
    }

    fn has_unread_to(&mut self, lengths: [u64; 2]) -> Result<bool> {
        for (index, length) in lengths.into_iter().enumerate() {
            if self.files[index].stream_position()? < length {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn limit_to(&mut self, lengths: [u64; 2]) {
        self.limit = Some(lengths);
    }

    fn scan(&mut self, regex: &WatchRegex) -> Result<OutputScan> {
        let mut eof = [false; 2];
        for index in 0..2 {
            let mut chunk = [0; 8192];
            let wanted = if let Some(limit) = self.limit {
                let position = self.files[index].stream_position()?;
                let remaining = limit[index].saturating_sub(position);
                if remaining == 0 {
                    eof[index] = true;
                    if !self.matched[index] {
                        let mut context = Vec::with_capacity(
                            self.window_preceding[index].len() + self.windows[index].len(),
                        );
                        context.extend_from_slice(&self.window_preceding[index]);
                        context.extend_from_slice(&self.windows[index]);
                        let search_start = self.window_preceding[index].len();
                        if regex.complete.is_match_at(&context, search_start) {
                            self.matched[index] = true;
                            self.match_context[index] = Some(self.windows[index].clone());
                            return Ok(OutputScan {
                                matched: Some(MatchObservation {
                                    stream: if index == 0 { "stdout" } else { "stderr" },
                                    observed_at: Instant::now(),
                                    observed_at_ms: epoch_ms()?,
                                }),
                                eof,
                            });
                        }
                    }
                    continue;
                }
                chunk.len().min(remaining as usize)
            } else {
                chunk.len()
            };
            let count = loop {
                match self.files[index].read(&mut chunk[..wanted]) {
                    Ok(count) => break count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            };
            let position = self.files[index].stream_position()?;
            eof[index] = count == 0 || self.limit.is_some_and(|limit| position >= limit[index]);
            if count > 0 {
                let mut context = Vec::with_capacity(self.windows[index].len() + count + 4);
                context.extend_from_slice(&self.windows[index]);
                context.extend_from_slice(&chunk[..count]);
                let mut lookahead = [0; 4];
                let available = self.limit.map_or(lookahead.len(), |limit| {
                    limit[index]
                        .saturating_sub(position)
                        .min(lookahead.len() as u64) as usize
                });
                let lookahead_len =
                    self.files[index].read_at(&mut lookahead[..available], position)?;
                context.extend_from_slice(&lookahead[..lookahead_len]);
                let context_end = position.saturating_add(lookahead_len as u64);
                let stream_end = self.limit.map_or_else(
                    || self.files[index].metadata().map(|metadata| metadata.len()),
                    |limit| Ok(limit[index]),
                )?;
                let has_unread_suffix = context_end < stream_end;
                let final_eof = self.limit.is_some_and(|limit| context_end >= limit[index]);
                let search_start = self.window_preceding[index].len();
                let mut regex_context = Vec::with_capacity(context.len() + 1);
                regex_context.extend_from_slice(&self.window_preceding[index]);
                regex_context.extend_from_slice(&context);
                if !self.matched[index]
                    && regex.has_stable_match(
                        &regex_context,
                        has_unread_suffix,
                        search_start,
                        final_eof,
                    )
                {
                    self.matched[index] = true;
                    self.match_context[index] = Some(context);
                    append_scanned_window(
                        &mut self.windows[index],
                        &chunk[..count],
                        &mut self.window_preceding[index],
                    );
                    return Ok(OutputScan {
                        matched: Some(MatchObservation {
                            stream: if index == 0 { "stdout" } else { "stderr" },
                            observed_at: Instant::now(),
                            observed_at_ms: epoch_ms()?,
                        }),
                        eof,
                    });
                }
                append_scanned_window(
                    &mut self.windows[index],
                    &chunk[..count],
                    &mut self.window_preceding[index],
                );
            }
        }
        Ok(OutputScan { matched: None, eof })
    }

    fn match_empty_final_output(&mut self, regex: &WatchRegex) -> Result<Option<MatchObservation>> {
        if !regex.complete.is_match(b"") {
            return Ok(None);
        }
        for index in 0..2 {
            if self.matched[index]
                || !self.windows[index].is_empty()
                || self.files[index].stream_position()? != 0
                || self.files[index].metadata()?.len() != 0
            {
                continue;
            }
            self.matched[index] = true;
            self.match_context[index] = Some(Vec::new());
            return Ok(Some(MatchObservation {
                stream: if index == 0 { "stdout" } else { "stderr" },
                observed_at: Instant::now(),
                observed_at_ms: epoch_ms()?,
            }));
        }
        Ok(None)
    }
}

struct WatchRegex {
    complete: Regex,
    stable: Option<Regex>,
    boundary_sensitive: Option<Regex>,
}

impl WatchRegex {
    fn new(pattern: &str) -> Result<Self> {
        let complete = Regex::new(pattern)?;
        let mut parser = regex_syntax::ParserBuilder::new();
        parser.utf8(false);
        let hir = parser.build().parse(pattern)?;
        let (stable_hir, boundary_hir) = split_boundary_hir(&hir);
        let compile = |hir: Option<Hir>| -> Result<Option<Regex>> {
            hir.map(|hir| Regex::new(&hir.to_string()).map_err(Into::into))
                .transpose()
        };
        Ok(Self {
            complete,
            stable: compile(stable_hir)?,
            boundary_sensitive: compile(boundary_hir)?,
        })
    }

    fn has_stable_match(
        &self,
        context: &[u8],
        has_unread_suffix: bool,
        search_start: usize,
        final_eof: bool,
    ) -> bool {
        if final_eof && !has_unread_suffix {
            return self.complete.is_match_at(context, search_start);
        }
        self.stable
            .as_ref()
            .is_some_and(|regex| regex.is_match_at(context, search_start))
            || self
                .boundary_sensitive
                .as_ref()
                .is_some_and(|regex| has_interior_match(regex, context, search_start))
    }
}

fn has_interior_match(regex: &Regex, context: &[u8], search_start: usize) -> bool {
    let mut start = search_start;
    while let Some(found) = regex.find_at(context, start) {
        if found.end() < context.len() {
            return true;
        }
        if found.end() == context.len() {
            return false;
        }
        start = if found.start() == found.end() {
            next_regex_boundary(context, found.end())
        } else {
            found.end()
        };
    }
    false
}

fn next_regex_boundary(bytes: &[u8], offset: usize) -> usize {
    let remaining = &bytes[offset..];
    match std::str::from_utf8(remaining) {
        Ok(valid) => offset + valid.chars().next().map_or(1, char::len_utf8),
        Err(error) if error.valid_up_to() > 0 => {
            let valid = std::str::from_utf8(&remaining[..error.valid_up_to()]).unwrap();
            offset + valid.chars().next().unwrap().len_utf8()
        }
        Err(_) => offset + 1,
    }
}

fn has_right_boundary_suffix(hir: &Hir) -> bool {
    let suffixes = hir.properties().look_set_suffix_any();
    [
        Look::End,
        Look::EndLF,
        Look::EndCRLF,
        Look::WordAscii,
        Look::WordAsciiNegate,
        Look::WordUnicode,
        Look::WordUnicodeNegate,
        Look::WordStartAscii,
        Look::WordEndAscii,
        Look::WordStartUnicode,
        Look::WordEndUnicode,
        Look::WordStartHalfAscii,
        Look::WordEndHalfAscii,
        Look::WordStartHalfUnicode,
        Look::WordEndHalfUnicode,
    ]
    .iter()
    .any(|look| suffixes.contains(*look))
}

fn split_boundary_hir(hir: &Hir) -> (Option<Hir>, Option<Hir>) {
    if !has_right_boundary_suffix(hir) {
        return (Some(hir.clone()), None);
    }

    match hir.kind() {
        HirKind::Alternation(alternatives) => {
            let (mut stable, mut boundary_sensitive) = (Vec::new(), Vec::new());
            for alternative in alternatives {
                let (stable_part, boundary_part) = split_boundary_hir(alternative);
                stable.extend(stable_part);
                boundary_sensitive.extend(boundary_part);
            }
            (
                make_alternation(stable),
                make_alternation(boundary_sensitive),
            )
        }
        HirKind::Capture(capture) => {
            let wrap = |sub| {
                Hir::capture(regex_syntax::hir::Capture {
                    index: capture.index,
                    name: capture.name.clone(),
                    sub: Box::new(sub),
                })
            };
            let (stable, boundary_sensitive) = split_boundary_hir(&capture.sub);
            (stable.map(wrap), boundary_sensitive.map(wrap))
        }
        HirKind::Concat(parts) => {
            let (last_stable, last_boundary) = split_boundary_hir(parts.last().unwrap());
            let prefix = Hir::concat(parts[..parts.len() - 1].to_vec());
            let prefix_sensitive = has_right_boundary_suffix(&prefix);
            let mut stable = Vec::new();
            let mut boundary_sensitive = Vec::new();
            if let Some(part) = last_stable {
                let combined = Hir::concat(vec![prefix.clone(), part.clone()]);
                if prefix_sensitive && part.properties().minimum_len() == Some(0) {
                    boundary_sensitive.push(combined);
                } else {
                    stable.push(combined);
                }
            }
            boundary_sensitive.extend(
                last_boundary
                    .into_iter()
                    .map(|part| Hir::concat(vec![prefix.clone(), part])),
            );
            (
                make_alternation(stable),
                make_alternation(boundary_sensitive),
            )
        }
        HirKind::Repetition(repetition) => {
            let (stable_sub, _) = split_boundary_hir(&repetition.sub);
            let stable = stable_sub.and_then(|sub| {
                let mut stable_repetition = repetition.clone();
                stable_repetition.min = stable_repetition.min.max(1);
                if stable_repetition
                    .max
                    .is_some_and(|maximum| maximum < stable_repetition.min)
                {
                    None
                } else {
                    Some(Hir::repetition(stable_repetition.with(sub)))
                }
            });
            (stable, Some(hir.clone()))
        }
        _ => (None, Some(hir.clone())),
    }
}

fn make_alternation(parts: Vec<Hir>) -> Option<Hir> {
    match parts.len() {
        0 => None,
        1 => parts.into_iter().next(),
        _ => Some(Hir::alternation(parts)),
    }
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<()> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS process_watches (
        subscription_id TEXT PRIMARY KEY,
        claim_token TEXT,
        state TEXT NOT NULL,
        supervisor_pid INTEGER NOT NULL,
        supervisor_start TEXT NOT NULL,
        child_pid INTEGER,
        child_start TEXT,
        started_at_ms INTEGER,
        deadline_at_ms INTEGER,
        regex TEXT NOT NULL,
        stdout_path TEXT NOT NULL,
        stderr_path TEXT NOT NULL,
        selection_json TEXT,
        match_context BLOB,
        selected_at_ms INTEGER,
        exit_code INTEGER,
        exit_success INTEGER,
        diagnostic TEXT,
        retention_state TEXT NOT NULL DEFAULT 'not_started',
        retention_diagnostic TEXT
    )",
        )?;
        let columns = {
            let mut statement = db.prepare("PRAGMA table_info(process_watches)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (name, definition) in [
            ("claim_token", "TEXT"),
            ("match_context", "BLOB"),
            ("retention_state", "TEXT NOT NULL DEFAULT 'not_started'"),
            ("retention_diagnostic", "TEXT"),
        ] {
            if !columns.iter().any(|column| column == name) {
                db.execute(
                    &format!("ALTER TABLE process_watches ADD COLUMN {name} {definition}"),
                    [],
                )?;
            }
        }
        db.execute_batch(
            "UPDATE process_watches
         SET retention_state='error',
             retention_diagnostic=COALESCE(diagnostic,'Legacy output retention failure'),
             state=CASE WHEN selection_json IS NULL THEN 'needs_attention' ELSE 'selected' END,
             diagnostic=NULL
         WHERE state='retention_error';
         UPDATE process_watches SET retention_state='active'
         WHERE selection_json IS NOT NULL AND retention_state='not_started';",
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => db.execute_batch("COMMIT").map_err(Into::into),
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn epoch_ms() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn is_busy(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<SqlError>()
            .and_then(|error| match error {
                SqlError::SqliteFailure(code, _) => Some(code.code),
                _ => None,
            })
            .is_some_and(|code| matches!(code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked))
    })
}

fn retry_busy<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    let mut delay = Duration::from_millis(10);
    loop {
        match operation() {
            Err(error) if is_busy(&error) => {
                thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(250));
            }
            result => return result,
        }
    }
}

fn immediate<T>(db: &Connection, mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    retry_busy(|| {
        db.execute_batch("BEGIN IMMEDIATE")?;
        let result = operation();
        match result {
            Ok(value) => match db.execute_batch("COMMIT") {
                Ok(()) => Ok(value),
                Err(error) => {
                    let _ = db.execute_batch("ROLLBACK");
                    Err(error.into())
                }
            },
            Err(error) => {
                let _ = db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    })
}

fn database_path(db: &Connection) -> Result<PathBuf> {
    let mut statement = db.prepare("PRAGMA database_list")?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.context("Main SQLite database is missing")?;
    let path: String = row.get(2)?;
    ensure!(
        !path.is_empty(),
        "Process watch requires a file-backed database"
    );
    Ok(PathBuf::from(path))
}

fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == fs::metadata("/proc/self")?.uid()
            && metadata.mode() & 0o077 == 0,
        "Process-watch output directory must be a private directory owned by this user"
    );
    Ok(())
}

fn watch_dir(database: &Path) -> Result<PathBuf> {
    let path = watch_dir_path(database)?;
    private_dir(&path)?;
    Ok(path)
}

fn watch_dir_path(database: &Path) -> Result<PathBuf> {
    let parent = database
        .canonicalize()?
        .parent()
        .context("Database path has no parent")?
        .to_path_buf();
    Ok(parent.join("process-watch"))
}

pub fn remove_external_outputs(database: &Path) -> Result<()> {
    if !database.exists() {
        return Ok(());
    }
    let canonical = database.canonicalize()?;
    let directory = canonical
        .parent()
        .context("Database path has no parent")?
        .join("process-watch");
    let db = Connection::open_with_flags(&canonical, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    ensure_watches_terminal(&db)?;
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.file_type().is_dir() && metadata.uid() == fs::metadata("/proc/self")?.uid(),
        "Process-watch output directory is not an owned directory"
    );
    let has_table: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='process_watches')",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        remove_database_diagnostic_logs(&directory, &canonical)?;
        if fs::read_dir(&directory)?.next().is_none() {
            fs::remove_dir(&directory)?;
        }
        return Ok(());
    }
    let rows = {
        let mut statement =
            db.prepare("SELECT subscription_id,stdout_path,stderr_path FROM process_watches")?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    PathBuf::from(row.get::<_, String>(1)?),
                    PathBuf::from(row.get::<_, String>(2)?),
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (id, stdout, stderr) in rows {
        let prefix = format!("{}-", id_hash(&id));
        if !owned_output_path(&stdout, &directory, &prefix, "stdout")
            || !owned_output_path(&stderr, &directory, &prefix, "stderr")
        {
            continue;
        }
        for path in [
            stdout.clone(),
            retained_output_path(&stdout),
            match_context_path(&stdout),
            identity_path(&stdout),
            stderr.clone(),
            retained_output_path(&stderr),
            diagnostic_path_from_dir(&directory, &canonical, &id),
        ] {
            remove_file_if_present(&path)?;
        }
        remove_atomic_temporaries(&directory, &stdout)?;
        remove_atomic_temporaries(&directory, &stderr)?;
        remove_atomic_temporaries(&directory, &retained_output_path(&stdout))?;
        remove_atomic_temporaries(&directory, &retained_output_path(&stderr))?;
        remove_atomic_temporaries(&directory, &match_context_path(&stdout))?;
        remove_atomic_temporaries(&directory, &identity_path(&stdout))?;
    }
    remove_database_diagnostic_logs(&directory, &canonical)?;
    if fs::read_dir(&directory)?.next().is_none() {
        fs::remove_dir(&directory)?;
    }
    Ok(())
}

fn ensure_watches_terminal(db: &Connection) -> Result<()> {
    let has_table: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='process_watches')",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        return Ok(());
    }
    let rows = {
        let mut statement = db.prepare(
            "SELECT subscription_id,state,retention_state,supervisor_pid,supervisor_start,child_pid,child_start FROM process_watches",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<u32>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (id, state, retention, supervisor_pid, supervisor_start, child_pid, child_start) in rows {
        ensure!(
            state == "published" && retention == "complete",
            "Cannot uninstall database while process watch {id} has undelivered work or unfinished output retention"
        );
        let supervisor_alive = process_identity(supervisor_pid)
            .is_some_and(|(start, alive)| alive && start == supervisor_start);
        let child_alive = child_pid
            .zip(child_start.as_deref())
            .is_some_and(|(pid, expected)| {
                process_identity(pid).is_some_and(|(start, alive)| alive && start == expected)
            });
        let child_group_alive = child_pid.is_some_and(process_group_alive);
        ensure!(
            !supervisor_alive && !child_alive && !child_group_alive,
            "Cannot uninstall database while process watch {id} still has a live process"
        );
    }
    Ok(())
}

fn database_hash(database: &Path) -> String {
    format!("{:x}", Sha256::digest(database.as_os_str().as_bytes()))
}

fn diagnostic_path_from_dir(directory: &Path, database: &Path, id: &str) -> PathBuf {
    directory.join(format!(
        "{}-{}.monitor.log",
        database_hash(database),
        id_hash(id)
    ))
}

fn remove_database_diagnostic_logs(directory: &Path, database: &Path) -> Result<()> {
    let prefix = format!("{}-", database_hash(database));
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(id_hash) = name
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(".monitor.log"))
        else {
            continue;
        };
        if id_hash.len() == 64 && id_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            remove_file_if_present(&entry.path())?;
        }
    }
    Ok(())
}

fn owned_output_path(path: &Path, directory: &Path, prefix: &str, stream: &str) -> bool {
    if path.parent() != Some(directory) || path.extension().is_none_or(|ext| ext != stream) {
        return false;
    }
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_prefix(prefix))
        .is_some_and(|uuid| Uuid::parse_str(uuid).is_ok())
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_atomic_temporaries(directory: &Path, destination: &Path) -> Result<()> {
    let name = destination
        .file_name()
        .context("Output path has no filename")?
        .to_string_lossy();
    let prefix = format!(".{name}.tmp-");
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            remove_file_if_present(&entry.path())?;
        }
    }
    Ok(())
}

fn id_hash(id: &str) -> String {
    format!("{:x}", Sha256::digest(id.as_bytes()))
}

pub fn diagnostic_path(database: &Path, id: &str) -> Result<PathBuf> {
    let canonical = database.canonicalize()?;
    Ok(diagnostic_path_from_dir(
        &watch_dir(&canonical)?,
        &canonical,
        id,
    ))
}

fn diagnostic_path_without_creating_directory(database: &Path, id: &str) -> Result<PathBuf> {
    let canonical = database.canonicalize()?;
    Ok(diagnostic_path_from_dir(
        &watch_dir_path(&canonical)?,
        &canonical,
        id,
    ))
}

pub fn open_diagnostic(database: &Path, id: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(diagnostic_path(database, id)?)?)
}

fn output_paths(db: &Connection, id: &str) -> Result<OutputPaths> {
    let directory = watch_dir(&database_path(db)?)?;
    let stem = format!("{}-{}", id_hash(id), Uuid::new_v4());
    let stdout = directory.join(format!("{stem}.stdout"));
    let stderr = directory.join(format!("{stem}.stderr"));
    let stdout_writer = OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(&stdout)?;
    let stderr_writer = OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(&stderr)?;
    let identities = [
        file_identity(&stdout_writer)?,
        file_identity(&stderr_writer)?,
    ];
    Ok(OutputPaths {
        stdout,
        stderr,
        writers: [stdout_writer, stderr_writer],
        identities,
    })
}

pub fn retained_output_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.retained",
        path.file_name().unwrap_or_default().to_string_lossy()
    ))
}

fn match_context_path(stdout: &Path) -> PathBuf {
    stdout.with_file_name(format!(
        "{}.match",
        stdout.file_name().unwrap_or_default().to_string_lossy()
    ))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn open_regular_nofollow(path: &Path, read: bool, write: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(read)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        file.metadata()?.file_type().is_file(),
        "Output path is not a regular file"
    );
    Ok(file)
}

fn read_tail_file(file: &mut File, limit: usize) -> Result<Vec<u8>> {
    let length = file.metadata()?.len();
    file.seek(std::io::SeekFrom::Start(
        length.saturating_sub(limit as u64),
    ))?;
    let mut bytes = Vec::with_capacity(limit.min(length as usize));
    file.take(limit as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_tail(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read_tail_file(&mut open_regular_nofollow(path, true, false)?, limit)
}

fn retain_and_truncate(path: &Path, expected: FileIdentity) -> Result<()> {
    let mut active = open_regular_nofollow(path, true, true)?;
    ensure!(
        file_identity(&active)? == expected,
        "Opened output no longer has the original device/inode"
    );
    verify_path_identity(path, expected)?;
    if active.metadata()?.len() == 0 {
        return Ok(());
    }
    let retained = retained_output_path(path);
    let previous = match fs::symlink_metadata(&retained) {
        Ok(metadata) if metadata.file_type().is_symlink() => Vec::new(),
        Ok(metadata) if metadata.file_type().is_file() => read_tail(&retained, WINDOW)?,
        Ok(_) => anyhow::bail!("Retained output path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let current = read_tail_file(&mut active, WINDOW)?;
    let mut combined = Vec::with_capacity(WINDOW + current.len());
    combined.extend_from_slice(&previous);
    append_window(&mut combined, &current);
    atomic_write(&retained, &combined)?;
    ensure!(
        file_identity(&active)? == expected,
        "Opened output changed before truncation"
    );
    verify_path_identity(path, expected)?;
    active.set_len(0)?;
    active.sync_data()?;
    Ok(())
}

fn identity_path(stdout: &Path) -> PathBuf {
    stdout.with_extension("identity.json")
}

fn write_identity(stdout: &Path, identity: &ChildIdentity) -> Result<()> {
    atomic_write(&identity_path(stdout), &serde_json::to_vec(identity)?)
}

fn read_identity(stdout: &Path) -> Result<Option<ChildIdentity>> {
    let path = identity_path(stdout);
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn file_identity(file: &File) -> Result<FileIdentity> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file(),
        "Output is not a regular file"
    );
    Ok(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

fn saved_output_identities(stdout: &Path) -> Result<[FileIdentity; 2]> {
    let identity = read_identity(stdout)?.context("Saved output-file identity is missing")?;
    Ok([
        identity
            .stdout_file
            .context("Saved stdout device/inode is missing")?,
        identity
            .stderr_file
            .context("Saved stderr device/inode is missing")?,
    ])
}

fn verify_path_identity(path: &Path, expected: FileIdentity) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.dev() == expected.dev
            && metadata.ino() == expected.ino,
        "Output path no longer names the original file"
    );
    Ok(())
}

fn pid_namespace(pid: u32) -> Option<u64> {
    fs::metadata(format!("/proc/{pid}/ns/pid"))
        .ok()
        .map(|metadata| metadata.ino())
}

fn process_identity(pid: u32) -> Option<(String, bool)> {
    let (start, alive) = process_start_ticks(pid)?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()?
        .trim()
        .to_owned();
    let namespace = pid_namespace(pid)?;
    Some((format!("{boot_id}:{namespace}:{start}"), alive))
}

fn process_group_alive(process_group: u32) -> bool {
    let result = unsafe { libc::kill(-(process_group as i32), 0) };
    if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        return false;
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return true;
    };
    let Ok(owner_uid) = fs::metadata("/proc/self").map(|metadata| metadata.uid()) else {
        return true;
    };
    let mut unreadable = false;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => match process_stat_text(&stat) {
                Some((state, group, _)) if group == process_group => {
                    if state != "Z" && state != "X" {
                        return true;
                    }
                }
                Some(_) => {}
                None => unreadable = true,
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                if fs::metadata(format!("/proc/{pid}"))
                    .is_ok_and(|metadata| metadata.uid() == owner_uid)
                {
                    unreadable = true;
                }
            }
        }
    }
    unreadable
}

fn process_start_ticks(pid: u32) -> Option<(String, bool)> {
    let (state, _, start) = process_stat(pid)?;
    Some((start, state != "Z" && state != "X"))
}

fn process_stat(pid: u32) -> Option<(String, u32, String)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    process_stat_text(&stat)
}

fn process_stat_text(stat: &str) -> Option<(String, u32, String)> {
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    Some((
        fields.first()?.to_string(),
        fields.get(2)?.parse().ok()?,
        fields.get(19)?.to_string(),
    ))
}

fn legacy_identity_matches_live_process(pid: u32, stored_start: &str) -> bool {
    let Some((current_start, alive)) = process_start_ticks(pid) else {
        return false;
    };
    if !alive {
        return false;
    }
    if !stored_start.contains(':') {
        return current_start == stored_start;
    }
    let Some((boot, start)) = stored_start.split_once(':') else {
        return false;
    };
    if start.contains(':') || start != current_start {
        return false;
    }
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .is_ok_and(|current| current.trim() == boot)
}

fn identity_has_current_pid_namespace(identity: &str) -> bool {
    let mut parts = identity.split(':');
    let (Some(_boot), Some(namespace), Some(start), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    namespace.parse::<u64>().is_ok_and(|namespace| {
        pid_namespace(std::process::id()) == Some(namespace)
            && !start.is_empty()
            && start.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn current_identity() -> Result<(u32, String)> {
    let pid = std::process::id();
    Ok((
        pid,
        process_identity(pid)
            .context("Read supervisor process identity")?
            .0,
    ))
}

fn validate_subscription_for_watch(db: &Connection, id: &str) -> Result<()> {
    let registration: Option<WatchRegistration> = db
        .query_row(
            "SELECT kind,event,state,expires_in_secs,expires_at_ms FROM subscriptions WHERE id=?1",
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
        )
        .optional()?;
    let Some((kind, event, state, expires_in, expires_at)) = registration else {
        anyhow::bail!("No matching process-watch subscription")
    };
    ensure!(
        kind == "job" && event == "completed" && state == "waiting",
        "Process watch requires a waiting job/completed subscription"
    );
    ensure!(
        expires_in.is_none() && expires_at.is_none(),
        "Process-watch subscriptions cannot use generic expiry; the monitor owns its timeout"
    );
    Ok(())
}

fn validate_new_watch_claim(db: &Connection, id: &str) -> Result<()> {
    validate_subscription_for_watch(db, id)?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM process_watches WHERE subscription_id=?1)",
        [id],
        |row| row.get(0),
    )?;
    ensure!(
        !exists,
        "A process watch already exists for this subscription"
    );
    Ok(())
}

fn claim(
    db: &Connection,
    id: &str,
    pattern: &str,
    stdout: &Path,
    stderr: &Path,
    claim_token: Option<&str>,
) -> Result<()> {
    crate::subscriptions::initialize(db)?;
    initialize(db)?;
    let (supervisor_pid, supervisor_start) = current_identity()?;
    let stdout_path = stdout.display().to_string();
    let stderr_path = stderr.display().to_string();
    immediate(db, || {
        validate_new_watch_claim(db, id)?;
        db.execute(
            "INSERT INTO process_watches(subscription_id,claim_token,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path)
             VALUES(?1,?2,'starting',?3,?4,?5,?6,?7)",
            params![id, claim_token, supervisor_pid, supervisor_start, pattern, stdout_path, stderr_path],
        )?;
        Ok(())
    })
}

fn remove_failed_start(db: &Connection, id: &str, stdout: &Path, stderr: &Path) {
    let _ = db.execute(
        "DELETE FROM process_watches WHERE subscription_id=?1 AND child_pid IS NULL",
        [id],
    );
    let _ = fs::remove_file(stdout);
    let _ = fs::remove_file(stderr);
}

fn set_diagnostic(db: &Connection, id: &str, state: &str, message: &str) {
    let _ = retry_busy(|| {
        db.execute(
            "UPDATE process_watches SET state=?1,diagnostic=?2 WHERE subscription_id=?3",
            params![state, message, id],
        )?;
        Ok(())
    });
}

fn set_pid_namespace_attention(db: &Connection, id: &str, message: &str) {
    let _ = retry_busy(|| {
        db.execute(
            "UPDATE process_watches SET state='needs_attention',diagnostic=?1,
             retention_state=CASE WHEN selection_json IS NOT NULL THEN 'failed' ELSE retention_state END,
             retention_diagnostic=CASE WHEN selection_json IS NOT NULL THEN ?1 ELSE retention_diagnostic END
             WHERE subscription_id=?2",
            params![message, id],
        )?;
        Ok(())
    });
}

fn set_output_identity_failure(db: &Connection, id: &str, message: &str) {
    set_attention_and_fail_retention(db, id, message);
}

fn set_attention_and_fail_retention(db: &Connection, id: &str, message: &str) {
    set_diagnostic_and_fail_retention(db, id, "needs_attention", message);
}

fn set_diagnostic_and_fail_retention(db: &Connection, id: &str, state: &str, message: &str) {
    let _ = retry_busy(|| {
        db.execute(
            "UPDATE process_watches SET state=?1,diagnostic=?2,retention_state='failed',retention_diagnostic=?2 WHERE subscription_id=?3",
            params![state, message, id],
        )?;
        Ok(())
    });
}

fn selection(
    reason: &str,
    stream: Option<&str>,
    observed_at_ms: i64,
    status: Option<ExitStatus>,
    recovered: bool,
    candidates: Option<Vec<String>>,
) -> Selection {
    Selection {
        reason: reason.to_string(),
        stream: stream.map(str::to_owned),
        observed_at_ms,
        exit_code: status.and_then(|status| status.code()),
        success: status.map(|status| status.success()),
        recovered,
        candidates,
    }
}

fn persist_selection(
    db: &Connection,
    id: &str,
    selected: &Selection,
    match_context: Option<&[u8]>,
) -> Result<Selection> {
    let serialized = serde_json::to_string(selected)?;
    immediate(db, || {
        let changed = db.execute(
            "UPDATE process_watches SET selection_json=?1,match_context=?2,selected_at_ms=?3,exit_code=?4,exit_success=?5,state='selected',retention_state='active',retention_diagnostic=NULL WHERE subscription_id=?6 AND selection_json IS NULL",
            params![serialized, match_context, selected.observed_at_ms, selected.exit_code, selected.success, id],
        )?;
        if changed == 1 {
            return Ok(selected.clone());
        }
        let existing: String = db.query_row(
            "SELECT selection_json FROM process_watches WHERE subscription_id=?1",
            [id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&existing)?)
    })
}

fn stored_match_context(db: &Connection, id: &str) -> Result<Option<Vec<u8>>> {
    Ok(db.query_row(
        "SELECT match_context FROM process_watches WHERE subscription_id=?1",
        [id],
        |row| row.get(0),
    )?)
}

fn source(id: &str, selected: &Selection) -> Value {
    json!({"event_id":format!("process-watch:{id}"),"watch":selected})
}

fn publish_selection(db: &Connection, id: &str, selected: &Selection) -> Result<bool> {
    let source = source(id, selected);
    let source_json = serde_json::to_string(&source)?;
    let published =
        retry_busy(|| crate::subscriptions::publish_observation(db, id, "completed", &source))?;
    if published > 0 {
        retry_busy(|| {
            db.execute(
                "UPDATE process_watches SET state='published',diagnostic=NULL WHERE subscription_id=?1",
                [id],
            )?;
            Ok(())
        })?;
        return Ok(true);
    }
    let registration: Option<PublishedRegistration> = db
        .query_row(
            "SELECT state,outcome,kind,repo,source_event_key,process_watch_verified,source_json FROM subscriptions WHERE id=?1",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let already_published =
        if let Some((state, outcome, kind, repo, key, process_watch_verified, published_source)) =
            registration
        {
            let resource: String = db.query_row(
                "SELECT resource FROM subscriptions WHERE id=?1",
                [id],
                |row| row.get(0),
            )?;
            let expected = crate::subscriptions::source_event_identity(
                &kind,
                &repo,
                &resource,
                "completed",
                "completed",
                &source,
            )?;
            state != "waiting"
                && outcome.as_deref() == Some("completed")
                && process_watch_verified
                && published_source.as_deref() == Some(source_json.as_str())
                && key.is_some()
                && key == expected
        } else {
            false
        };
    if already_published {
        retry_busy(|| {
            db.execute(
                "UPDATE process_watches SET state='published',diagnostic=NULL WHERE subscription_id=?1",
                [id],
            )?;
            Ok(())
        })?;
        return Ok(true);
    }
    set_diagnostic(
        db,
        id,
        "needs_attention",
        "Selection is durable, but no verified process-watch publication was recorded; the subscription may have been consumed by another event",
    );
    Ok(false)
}

fn record_reaper_state(database: &Path, id: &str, state: &str, diagnostic: &str) {
    let _ = (|| -> Result<()> {
        let db = reaper_database(database)?;
        db.execute(
            "UPDATE process_watches SET retention_state=?1,retention_diagnostic=?2 WHERE subscription_id=?3",
            params![state, diagnostic, id],
        )?;
        Ok(())
    })();
}

fn mark_reaper_complete(database: &Path, id: &str) -> Result<()> {
    let db = reaper_database(database)?;
    db.execute(
        "UPDATE process_watches SET retention_state='complete',retention_diagnostic=NULL WHERE subscription_id=?1",
        [id],
    )?;
    Ok(())
}

fn with_watch_database<T>(
    database: &Path,
    expected: FileIdentity,
    operation: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    let canonical = match database.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let identity = |path: &Path| -> Result<FileIdentity> {
        let metadata = fs::metadata(path)?;
        ensure!(metadata.is_file(), "Watch database is not a regular file");
        Ok(FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    };
    if identity(&canonical)? != expected {
        return Ok(None);
    }
    let _guard = crate::polling::lock_database_parent(&canonical, true)?;
    if identity(&canonical)? != expected {
        return Ok(None);
    }
    operation().map(Some)
}

fn reaper_database(path: &Path) -> Result<Connection> {
    let db = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(Duration::from_millis(25))?;
    Ok(db)
}

fn retain_selected_output(
    stdout: &Path,
    stderr: &Path,
    selected: &Selection,
    match_context: Option<&[u8]>,
) -> Result<()> {
    let [stdout_identity, stderr_identity] = saved_output_identities(stdout)?;
    let match_possible = selected.reason == "match"
        || selected
            .candidates
            .as_ref()
            .is_some_and(|candidates| candidates.iter().any(|candidate| candidate == "match"));
    if match_possible && let Some(context) = match_context {
        let path = match_context_path(stdout);
        let should_write = match fs::symlink_metadata(&path) {
            Ok(metadata) => !metadata.file_type().is_file(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        if should_write {
            atomic_write(&path, context)?;
        }
    }
    retain_and_truncate(stdout, stdout_identity)?;
    retain_and_truncate(stderr, stderr_identity)?;
    Ok(())
}

fn reap_until_child_exit(mut context: ReaperContext) {
    loop {
        let child_alive = if let Some(child) = context.child.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => true,
                Err(_) => process_identity(context.pid)
                    .is_some_and(|(start, alive)| alive && start == context.child_start),
            }
        } else {
            process_identity(context.pid)
                .is_some_and(|(start, alive)| alive && start == context.child_start)
        };
        let finished = !child_alive && !process_group_alive(context.pid);
        let cycle = with_watch_database(&context.database, context.database_identity, || {
            if finished {
                match retain_selected_output(
                    &context.stdout,
                    &context.stderr,
                    &context.selected,
                    context.match_context.as_deref(),
                ) {
                    Ok(()) => match mark_reaper_complete(&context.database, &context.id) {
                        Ok(()) => return Ok(true),
                        Err(error) if is_busy(&error) => return Ok(false),
                        Err(error) => record_reaper_state(
                            &context.database,
                            &context.id,
                            "failed",
                            &format!("Could not record completed output retention: {error}"),
                        ),
                    },
                    Err(error) => record_reaper_state(
                        &context.database,
                        &context.id,
                        "failed",
                        &format!("Could not retain final child output: {error}"),
                    ),
                }
                return Ok(true);
            }
            if let Err(error) = retain_selected_output(
                &context.stdout,
                &context.stderr,
                &context.selected,
                context.match_context.as_deref(),
            ) {
                record_reaper_state(
                    &context.database,
                    &context.id,
                    "error",
                    &format!("Could not bound post-selection output: {error}"),
                );
            }
            Ok(false)
        });
        match cycle {
            Ok(Some(true)) | Ok(None) => return,
            Ok(Some(false)) => {}
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock) =>
            {
                // Uninstall or another database owner holds the shared directory lock.
            }
            Err(_) => {}
        }
        thread::sleep(RETAIN_INTERVAL);
    }
}

fn event_selection(
    stream: Option<&str>,
    observed_at: Instant,
    observed_at_ms: i64,
    deadline: Instant,
    deadline_at_ms: i64,
    recovered: bool,
) -> Selection {
    if observed_at >= deadline {
        selection("timeout", None, deadline_at_ms, None, recovered, None)
    } else {
        selection("match", stream, observed_at_ms, None, recovered, None)
    }
}

fn deadline_selection(
    outputs: &mut OutputTail,
    deadline_at_ms: i64,
    recovered: bool,
    process_exit_possible: bool,
) -> Result<Selection> {
    let frontier = outputs.snapshot_lengths()?;
    let unread = outputs.has_unread_to(frontier)?;
    if unread || process_exit_possible {
        let mut candidates = Vec::new();
        if unread {
            candidates.push("match".into());
        }
        candidates.push("timeout".into());
        if process_exit_possible {
            candidates.push("process_exit".into());
        }
        return Ok(selection(
            if recovered {
                "recovery_ambiguous"
            } else {
                "observation_ambiguous"
            },
            None,
            epoch_ms()?,
            None,
            recovered,
            Some(candidates),
        ));
    }
    Ok(selection(
        "timeout",
        None,
        deadline_at_ms,
        None,
        recovered,
        None,
    ))
}

fn exit_after_deadline_selection(
    outputs: &mut OutputTail,
    deadline_at_ms: i64,
    recovered: bool,
) -> Result<Selection> {
    deadline_selection(outputs, deadline_at_ms, recovered, true)
}

fn exit_drain_candidates(exit_observed_at: Instant, deadline: Instant) -> Vec<String> {
    let mut candidates = vec!["match".into(), "process_exit".into()];
    if exit_observed_at >= deadline {
        candidates.push("timeout".into());
    }
    candidates
}

fn observe_process(child: Option<&mut Child>, pid: u32, start: &str) -> Result<ProcessObservation> {
    if let Some(child) = child {
        return Ok(match child.try_wait()? {
            Some(status) => ProcessObservation::Exited(Some(status)),
            None => ProcessObservation::Running,
        });
    }
    Ok(
        if process_identity(pid).is_some_and(|(current, alive)| current == start && alive) {
            ProcessObservation::Running
        } else {
            ProcessObservation::Exited(None)
        },
    )
}

fn observed_match_selection(
    stream: &str,
    observed_at: Instant,
    observed_at_ms: i64,
    deadline: Instant,
    deadline_at_ms: i64,
    recovered: bool,
) -> Result<Selection> {
    if observed_at >= deadline {
        Ok(selection(
            "observation_ambiguous",
            Some(stream),
            observed_at_ms,
            None,
            recovered,
            Some(vec!["match".into(), "timeout".into()]),
        ))
    } else {
        Ok(event_selection(
            Some(stream),
            observed_at,
            observed_at_ms,
            deadline,
            deadline_at_ms,
            recovered,
        ))
    }
}

fn retry_publication_while_reaping(
    reaper: Option<&thread::JoinHandle<()>>,
    mut publish: impl FnMut() -> Result<bool>,
) -> Result<bool> {
    let mut result = publish();
    while result.is_err() && reaper.is_some_and(|reaper| !reaper.is_finished()) {
        thread::sleep(PUBLISH_RETRY_INTERVAL);
        result = publish();
    }
    result
}

fn finish(db: &Connection, mut selected: Selection, context: FinishContext<'_>) -> Result<Value> {
    let FinishContext {
        id,
        pid,
        stdout,
        stderr,
        outputs,
        child,
    } = context;
    let observed_stream = selected.stream.clone().or_else(|| {
        let has_match_candidate = selected
            .candidates
            .as_ref()
            .is_some_and(|candidates| candidates.iter().any(|candidate| candidate == "match"));
        if !has_match_candidate {
            return None;
        }
        outputs.and_then(|outputs| {
            outputs
                .match_context
                .iter()
                .position(Option::is_some)
                .map(|index| if index == 0 { "stdout" } else { "stderr" }.to_owned())
        })
    });
    if selected.stream.is_none() && observed_stream.is_some() {
        selected.stream = observed_stream.clone();
    }
    let match_context = observed_stream.as_deref().and_then(|stream| {
        let index = if stream == "stdout" { 0 } else { 1 };
        outputs.and_then(|outputs| outputs.match_context[index].as_deref())
    });
    let selected = persist_selection(db, id, &selected, match_context)?;
    let match_context = stored_match_context(db, id)?;
    let database = database_path(db)?.canonicalize()?;
    let database_metadata = fs::metadata(&database)?;
    let database_identity = FileIdentity {
        dev: database_metadata.dev(),
        ino: database_metadata.ino(),
    };
    let child_start: String = db.query_row(
        "SELECT child_start FROM process_watches WHERE subscription_id=?1",
        [id],
        |row| row.get(0),
    )?;
    let reaper = match saved_output_identities(stdout) {
        Err(error) => {
            record_reaper_state(
                &database,
                id,
                "failed",
                &format!("Cannot safely retain output without its original file identity: {error}"),
            );
            None
        }
        Ok(_) => {
            if let Err(error) = with_watch_database(&database, database_identity, || {
                retain_selected_output(stdout, stderr, &selected, match_context.as_deref())
            }) {
                record_reaper_state(
                    &database,
                    id,
                    "error",
                    &format!("Could not retain selected child output: {error}"),
                );
            }
            let reaper_context = ReaperContext {
                database: database.clone(),
                database_identity,
                id: id.to_owned(),
                pid,
                child_start,
                stdout: stdout.to_path_buf(),
                stderr: stderr.to_path_buf(),
                selected: selected.clone(),
                match_context: match_context.clone(),
                child,
            };
            Some(
                thread::Builder::new()
                    .name(format!(
                        "watch-retain-{}",
                        id.chars().take(8).collect::<String>()
                    ))
                    .spawn(move || reap_until_child_exit(reaper_context))
                    .map_err(|error| {
                        record_reaper_state(
                            &database,
                            id,
                            "error",
                            &format!("Could not start output reaper thread: {error}"),
                        );
                        anyhow!("Could not start post-selection output reaper: {error}")
                    })?,
            )
        }
    };
    let publish = retry_publication_while_reaping(reaper.as_ref(), || {
        let result = publish_selection(db, id, &selected);
        if let Err(error) = &result {
            set_diagnostic(db, id, "publish_error", &error.to_string());
        }
        result
    });
    let publish = match publish {
        Ok(true) => Ok(()),
        Ok(false) => Err(anyhow!(
            "Process-watch selection is durable but subscription was not available"
        )),
        Err(error) => {
            Err(error.context("Process-watch selection persisted; publication can be resumed"))
        }
    };
    if reaper.is_some_and(|reaper| reaper.join().is_err()) {
        record_reaper_state(
            &database,
            id,
            "error",
            "Post-selection output reaper panicked",
        );
    }
    publish?;
    Ok(json!({
        "subscription_id":id,
        "pid":pid,
        "reason":selected.reason,
        "exit_code":selected.exit_code,
        "success":selected.success,
        "stdout_path":stdout.display().to_string(),
        "stderr_path":stderr.display().to_string(),
        "stdout_retained_path":retained_output_path(stdout).display().to_string(),
        "stderr_retained_path":retained_output_path(stderr).display().to_string(),
        "match_context_path":match_context_path(stdout).display().to_string(),
        "recovered":selected.recovered
    }))
}

fn scan_outputs(
    db: &Connection,
    id: &str,
    outputs: &mut OutputTail,
    regex: &WatchRegex,
) -> Result<OutputScan> {
    outputs.scan(regex).inspect_err(|error| {
        set_diagnostic(
            db,
            id,
            "needs_attention",
            &format!("Could not read retained child output: {error}"),
        );
    })
}

fn monitor(
    context: MonitorContext<'_>,
    mut outputs: OutputTail,
    mut child: Option<Child>,
) -> Result<Value> {
    let mut pending_exit: Option<(Option<ExitStatus>, Instant)> = None;
    loop {
        let scan = scan_outputs(context.db, context.id, &mut outputs, context.regex)?;
        let observation = scan.matched.or(if pending_exit.is_some() {
            outputs.match_empty_final_output(context.regex)?
        } else {
            None
        });
        if let Some(observation) = observation {
            let stream = observation.stream;
            let observed_at = observation.observed_at;
            let observed_at_ms = observation.observed_at_ms;
            if let Some((None, exit_observed_at)) = pending_exit.as_ref() {
                let candidates = exit_drain_candidates(*exit_observed_at, context.deadline);
                return finish(
                    context.db,
                    selection(
                        "observation_ambiguous",
                        Some(stream),
                        observed_at_ms,
                        None,
                        context.recovered,
                        Some(candidates),
                    ),
                    FinishContext::monitor(&context, &outputs, child.take()),
                );
            }
            if let Some((Some(_), exit_observed_at)) = pending_exit.as_ref()
                && observed_at >= context.deadline
            {
                let candidates = exit_drain_candidates(*exit_observed_at, context.deadline);
                return finish(
                    context.db,
                    selection(
                        "observation_ambiguous",
                        Some(stream),
                        observed_at_ms,
                        None,
                        context.recovered,
                        Some(candidates),
                    ),
                    FinishContext::monitor(&context, &outputs, child.take()),
                );
            }
            return finish(
                context.db,
                observed_match_selection(
                    stream,
                    observed_at,
                    observed_at_ms,
                    context.deadline,
                    context.deadline_at_ms,
                    context.recovered,
                )?,
                FinishContext::monitor(&context, &outputs, child.take()),
            );
        }

        if let Some((status, exit_observed_at)) = pending_exit.as_ref() {
            if scan.eof.into_iter().all(|eof| eof) {
                if *exit_observed_at >= context.deadline {
                    return finish(
                        context.db,
                        exit_after_deadline_selection(
                            &mut outputs,
                            context.deadline_at_ms,
                            context.recovered,
                        )?,
                        FinishContext::monitor(&context, &outputs, child.take()),
                    );
                }
                return finish(
                    context.db,
                    match status {
                        Some(status) => selection(
                            "exit",
                            None,
                            epoch_ms()?,
                            Some(*status),
                            context.recovered,
                            None,
                        ),
                        None => selection(
                            "exit_status_unavailable",
                            None,
                            epoch_ms()?,
                            None,
                            context.recovered,
                            None,
                        ),
                    },
                    FinishContext::monitor(&context, &outputs, child.take()),
                );
            }
            if Instant::now() >= context.deadline {
                let candidates = exit_drain_candidates(*exit_observed_at, context.deadline);
                return finish(
                    context.db,
                    selection(
                        "observation_ambiguous",
                        None,
                        epoch_ms()?,
                        None,
                        context.recovered,
                        Some(candidates),
                    ),
                    FinishContext::monitor(&context, &outputs, child.take()),
                );
            }
            continue;
        }

        if Instant::now() >= context.deadline {
            match observe_process(child.as_mut(), context.child_pid, context.child_start)? {
                ProcessObservation::Running => {
                    return finish(
                        context.db,
                        deadline_selection(
                            &mut outputs,
                            context.deadline_at_ms,
                            context.recovered,
                            false,
                        )?,
                        FinishContext::monitor(&context, &outputs, child.take()),
                    );
                }
                ProcessObservation::Exited(status) => {
                    let observed_at = Instant::now();
                    outputs.limit_to(outputs.snapshot_lengths()?);
                    pending_exit = Some((status, observed_at));
                    continue;
                }
            }
        }

        if let Some(process) = child.as_mut() {
            if let Some(status) = process.try_wait()? {
                let observed_at = Instant::now();
                outputs.limit_to(outputs.snapshot_lengths()?);
                pending_exit = Some((Some(status), observed_at));
                continue;
            }
        } else if process_identity(context.child_pid)
            .is_none_or(|(start, alive)| start != context.child_start || !alive)
        {
            outputs.limit_to(outputs.snapshot_lengths()?);
            pending_exit = Some((None, Instant::now()));
            continue;
        }

        let remaining = context.deadline.saturating_duration_since(Instant::now());
        let wait = remaining.min(POLL);
        if let Some(process) = child.as_mut() {
            if let Some(status) = process.wait_timeout(wait)? {
                let observed_at = Instant::now();
                outputs.limit_to(outputs.snapshot_lengths()?);
                pending_exit = Some((Some(status), observed_at));
            }
        } else {
            thread::sleep(wait);
        }
    }
}

/// Start one supervised process. Output goes to private files so database or
/// supervisor failures cannot close the child's stdout/stderr pipes.
#[cfg(test)]
pub fn run(
    db: &Connection,
    id: &str,
    pattern: &str,
    timeout: Duration,
    command: &[String],
) -> Result<Value> {
    run_started_with_claim_token(db, id, pattern, timeout, command, None, |_, _, _| {})
}

pub fn run_started_with_claim_token(
    db: &Connection,
    id: &str,
    pattern: &str,
    timeout: Duration,
    command: &[String],
    claim_token: Option<&str>,
    started_callback: impl FnOnce(u32, &Path, &Path),
) -> Result<Value> {
    ensure!(!id.is_empty() && id.len() <= 256, "Invalid subscription ID");
    ensure!(!command.is_empty(), "Missing process command");
    ensure!(!timeout.is_zero(), "Process-watch timeout must be positive");
    let timeout_ms =
        i64::try_from(timeout.as_millis()).context("Process-watch timeout is too large")?;
    Instant::now()
        .checked_add(timeout)
        .context("Process-watch timeout is too large")?;
    let regex = WatchRegex::new(pattern).map_err(|_| anyhow!("Invalid Rust byte-regex pattern"))?;
    let OutputPaths {
        stdout,
        stderr,
        writers: [stdout_writer, stderr_writer],
        identities: output_identities,
    } = output_paths(db, id)?;
    if let Err(error) = claim(db, id, pattern, &stdout, &stderr, claim_token) {
        let _ = fs::remove_file(&stdout);
        let _ = fs::remove_file(&stderr);
        return Err(error);
    }
    let child = match Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::from(stdout_writer))
        .stderr(Stdio::from(stderr_writer))
        .process_group(0)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            remove_failed_start(db, id, &stdout, &stderr);
            return Err(anyhow!("Could not start process: {error}"));
        }
    };
    let pid = child.id();
    let started_at = Instant::now();
    let started_ms = epoch_ms()?;
    let deadline_at_ms = started_ms
        .checked_add(timeout_ms)
        .context("Process-watch deadline overflow")?;
    let child_start = match process_identity(pid) {
        Some((start, _)) => start,
        None => {
            set_diagnostic(
                db,
                id,
                "launch_uncertain",
                "Child started, but its process identity could not be read; output logs were retained and automatic relaunch was refused",
            );
            return Err(anyhow!(
                "Process started but its identity could not be recorded"
            ));
        }
    };
    let identity = ChildIdentity {
        pid,
        start: child_start.clone(),
        started_at_ms: started_ms,
        deadline_at_ms,
        stdout_file: Some(output_identities[0]),
        stderr_file: Some(output_identities[1]),
    };
    if let Err(error) = write_identity(&stdout, &identity) {
        set_diagnostic(
            db,
            id,
            "needs_attention",
            &format!("Could not persist child identity; output logs were retained: {error}"),
        );
        return Err(error);
    }
    retry_busy(|| {
        db.execute(
            "UPDATE process_watches SET state='watching',child_pid=?1,child_start=?2,started_at_ms=?3,deadline_at_ms=?4 WHERE subscription_id=?5",
            params![pid, child_start, started_ms, deadline_at_ms, id],
        )?;
        Ok(())
    })
    .inspect_err(|error| set_diagnostic(db, id, "needs_attention", &format!("Child is running but its database identity update failed: {error}")))?;
    let outputs = match OutputTail::open(&stdout, &stderr) {
        Ok(outputs) => outputs,
        Err(error) => {
            set_output_identity_failure(
                db,
                id,
                &format!("Could not open child output logs: {error}"),
            );
            return Err(error.context("Open process output logs"));
        }
    };
    if let Err(error) = outputs.verify_file_identities(output_identities) {
        set_output_identity_failure(
            db,
            id,
            &format!("Could not verify original child output files: {error}"),
        );
        return Err(error.context("Verify original process output files"));
    }
    started_callback(pid, &stdout, &stderr);
    monitor(
        MonitorContext {
            db,
            id,
            regex: &regex,
            child_pid: pid,
            child_start: &child_start,
            deadline: started_at + timeout,
            deadline_at_ms,
            recovered: false,
            stdout: &stdout,
            stderr: &stderr,
        },
        outputs,
        Some(child),
    )
}

fn load_watch(db: &Connection, id: &str) -> Result<Watch> {
    db.query_row(
        "SELECT regex,child_pid,child_start,deadline_at_ms,stdout_path,stderr_path,selection_json FROM process_watches WHERE subscription_id=?1",
        [id],
        |row| {
            Ok(Watch {
                regex: row.get(0)?,
                child_pid: row.get(1)?,
                child_start: row.get(2)?,
                deadline_at_ms: row.get(3)?,
                stdout_path: PathBuf::from(row.get::<_, String>(4)?),
                stderr_path: PathBuf::from(row.get::<_, String>(5)?),
                selection: row.get(6)?,
            })
        },
    )
    .optional()?
    .with_context(|| format!("No process-watch record for subscription {id}"))
}

fn take_over(db: &Connection, id: &str) -> Result<Watch> {
    let (pid, start) = current_identity()?;
    let (owner_pid, owner_start): (u32, String) = db.query_row(
        "SELECT supervisor_pid,supervisor_start FROM process_watches WHERE subscription_id=?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if legacy_identity_matches_live_process(owner_pid, &owner_start) {
        let (diagnostic, error) = if owner_start.contains(':') {
            (
                "Supervisor identity has a boot ID but no PID namespace; automatic takeover is unsafe",
                "Supervisor identity lacks a PID namespace; automatic takeover is unsafe",
            )
        } else {
            (
                "Supervisor identity predates boot IDs and matches a live PID/start pair; automatic takeover is unsafe",
                "Legacy supervisor identity lacks a boot ID; automatic takeover is unsafe",
            )
        };
        set_diagnostic(db, id, "needs_attention", diagnostic);
        anyhow::bail!("{error}")
    }
    if !identity_has_current_pid_namespace(&owner_start) {
        set_pid_namespace_attention(
            db,
            id,
            "Supervisor identity has no verifiable current PID namespace; automatic takeover is unsafe",
        );
        anyhow::bail!("Supervisor PID namespace cannot be verified; automatic takeover is unsafe")
    }
    immediate(db, || {
        let watch = load_watch(db, id)?;
        let (owner_pid, owner_start): (u32, String) = db.query_row(
            "SELECT supervisor_pid,supervisor_start FROM process_watches WHERE subscription_id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let owner_alive = process_identity(owner_pid)
            .is_some_and(|(found_start, alive)| alive && found_start == owner_start);
        ensure!(
            !owner_alive || owner_pid == pid,
            "Process-watch supervisor is still running"
        );
        db.execute(
            "UPDATE process_watches
             SET supervisor_pid=?1,supervisor_start=?2,
                 state=CASE WHEN selection_json IS NULL THEN 'resuming' ELSE 'selected' END,
                 retention_state=CASE WHEN selection_json IS NOT NULL THEN 'active' ELSE retention_state END,
                 retention_diagnostic=CASE WHEN selection_json IS NOT NULL THEN NULL ELSE retention_diagnostic END
             WHERE subscription_id=?3",
            params![pid, start, id],
        )?;
        Ok(watch)
    })
}

fn finish_resumed<F>(
    db: &Connection,
    selected: Selection,
    context: FinishContext<'_>,
    callback: &mut Option<F>,
) -> Result<Value>
where
    F: FnOnce(u32, &Path, &Path),
{
    if let Some(callback) = callback.take() {
        callback(context.pid, context.stdout, context.stderr);
    }
    finish(db, selected, context)
}

fn start_corrupt_selection_retention(
    db: &Connection,
    id: &str,
    watch: &Watch,
    pid: u32,
    child_start: &str,
) -> Result<thread::JoinHandle<()>> {
    let output_identities = saved_output_identities(&watch.stdout_path)?;
    let outputs = OutputTail::open(&watch.stdout_path, &watch.stderr_path)?;
    outputs.verify_file_identities(output_identities)?;
    let database = database_path(db)?.canonicalize()?;
    let metadata = fs::metadata(&database)?;
    let database_identity = FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    };
    let match_context = stored_match_context(db, id)?;
    let retention_selection = selection(
        "observation_ambiguous",
        None,
        epoch_ms()?,
        None,
        true,
        match_context.as_ref().map(|_| vec!["match".to_owned()]),
    );
    let context = ReaperContext {
        database,
        database_identity,
        id: id.to_owned(),
        pid,
        child_start: child_start.to_owned(),
        stdout: watch.stdout_path.clone(),
        stderr: watch.stderr_path.clone(),
        selected: retention_selection,
        match_context,
        child: None,
    };
    Ok(thread::Builder::new()
        .name(format!(
            "watch-repair-{}",
            id.chars().take(8).collect::<String>()
        ))
        .spawn(move || reap_until_child_exit(context))?)
}

pub fn resume_started(
    db: &Connection,
    id: &str,
    started_callback: impl FnOnce(u32, &Path, &Path),
) -> Result<Value> {
    initialize(db)?;
    let mut watch = take_over(db, id)?;
    let mut started_callback = Some(started_callback);
    if watch.child_pid.is_none() {
        let identity = match read_identity(&watch.stdout_path)? {
            Some(identity) => identity,
            None => {
                if let Some(value) = watch.selection.as_deref()
                    && let Err(error) = serde_json::from_str::<Selection>(value)
                {
                    let diagnostic = format!(
                        "Stored process-watch selection is corrupt; output retention cannot be resumed without a child identity: {error}"
                    );
                    set_diagnostic_and_fail_retention(db, id, "launch_uncertain", &diagnostic);
                    return Err(error).context(diagnostic);
                }
                set_diagnostic(
                    db,
                    id,
                    "launch_uncertain",
                    "No persisted child identity; logs retained and automatic relaunch refused",
                );
                anyhow::bail!("Process launch identity is unavailable; inspect the retained logs")
            }
        };
        retry_busy(|| {
            db.execute(
                "UPDATE process_watches SET child_pid=?1,child_start=?2,started_at_ms=?3,deadline_at_ms=?4 WHERE subscription_id=?5",
                params![identity.pid, identity.start, identity.started_at_ms, identity.deadline_at_ms, id],
            )?;
            Ok(())
        })?;
        watch.child_pid = Some(identity.pid);
        watch.child_start = Some(identity.start);
        watch.deadline_at_ms = Some(identity.deadline_at_ms);
    }
    let pid = watch.child_pid.unwrap_or(0);
    if watch.child_pid.is_some()
        && !watch
            .child_start
            .as_deref()
            .is_some_and(identity_has_current_pid_namespace)
    {
        if watch.child_start.is_none()
            && let Some(value) = watch.selection.as_deref()
            && let Err(error) = serde_json::from_str::<Selection>(value)
        {
            let diagnostic = format!(
                "Stored process-watch selection is corrupt; output retention cannot be resumed without the child start identity: {error}"
            );
            set_diagnostic_and_fail_retention(db, id, "needs_attention", &diagnostic);
            return Err(error).context(diagnostic);
        }
        set_pid_namespace_attention(
            db,
            id,
            "Child identity has no verifiable current PID namespace; automatic reattachment is unsafe",
        );
        anyhow::bail!("Child PID namespace cannot be verified; automatic reattachment is unsafe")
    }
    if let Some(value) = watch.selection.as_deref() {
        let selected: Selection = match serde_json::from_str(value) {
            Ok(selected) => selected,
            Err(error) => {
                let diagnostic = format!(
                    "Stored process-watch selection is corrupt; automatic recovery stopped: {error}"
                );
                let (Some(child_pid), Some(child_start)) =
                    (watch.child_pid, watch.child_start.as_deref())
                else {
                    let state = if watch.child_pid.is_none() {
                        "launch_uncertain"
                    } else {
                        "needs_attention"
                    };
                    let message = format!(
                        "{diagnostic}; output retention cannot be resumed safely because the child identity is incomplete"
                    );
                    set_diagnostic_and_fail_retention(db, id, state, &message);
                    return Err(error).context(message);
                };
                let reaper = match start_corrupt_selection_retention(
                    db,
                    id,
                    &watch,
                    child_pid,
                    child_start,
                ) {
                    Ok(reaper) => reaper,
                    Err(retention_error) => {
                        let message = format!(
                            "{diagnostic}; output retention could not be resumed safely: {retention_error}"
                        );
                        set_diagnostic(db, id, "needs_attention", &message);
                        set_output_identity_failure(db, id, &message);
                        return Err(error).context(message);
                    }
                };
                set_diagnostic(db, id, "needs_attention", &diagnostic);
                if reaper.join().is_err() {
                    anyhow::bail!(
                        "Output retention supervisor panicked while handling corrupt selection"
                    );
                }
                return Err(error).context(diagnostic);
            }
        };
        return finish_resumed(
            db,
            selected,
            FinishContext::resumed(id, pid, &watch, None),
            &mut started_callback,
        );
    }
    let child_pid = watch.child_pid.context(
        "Process launch was interrupted before its PID was recorded; inspect the retained logs",
    )?;
    let child_start = watch
        .child_start
        .as_deref()
        .context("Process start identity is missing; inspect the retained logs")?;
    if legacy_identity_matches_live_process(child_pid, child_start) {
        let diagnostic = if child_start.contains(':') {
            "Child identity has a boot ID but no PID namespace; automatic reattachment is unsafe"
        } else {
            "Child identity predates boot IDs and matches a live PID/start pair; automatic reattachment is unsafe"
        };
        set_diagnostic(db, id, "needs_attention", diagnostic);
        if child_start.contains(':') {
            anyhow::bail!("Child identity lacks a PID namespace; automatic reattachment is unsafe")
        } else {
            anyhow::bail!("Legacy child identity lacks a boot ID; automatic reattachment is unsafe")
        }
    }
    let deadline_at_ms = watch
        .deadline_at_ms
        .context("Process-watch deadline was not recorded")?;
    let regex = WatchRegex::new(&watch.regex)?;
    let output_identities = match saved_output_identities(&watch.stdout_path) {
        Ok(identities) => identities,
        Err(error) => {
            set_output_identity_failure(
                db,
                id,
                &format!("Cannot safely resume without original output-file identities: {error}"),
            );
            return Err(error);
        }
    };
    let mut outputs = match OutputTail::open(&watch.stdout_path, &watch.stderr_path) {
        Ok(outputs) => outputs,
        Err(error) => {
            set_output_identity_failure(
                db,
                id,
                &format!("Could not reopen child output logs: {error}"),
            );
            return Err(error);
        }
    };
    if let Err(error) = outputs.verify_file_identities(output_identities) {
        set_output_identity_failure(
            db,
            id,
            &format!("Could not verify original child output files: {error}"),
        );
        return Err(error);
    }
    let deadline = Instant::now()
        + Duration::from_millis(deadline_at_ms.saturating_sub(epoch_ms()?).max(0) as u64);
    let mut scan = scan_outputs(db, id, &mut outputs, &regex)?;
    let alive =
        process_identity(child_pid).is_some_and(|(start, running)| running && start == child_start);
    if let Some(observation) = scan.matched {
        let stream = observation.stream;
        let observed_at = observation.observed_at;
        let observed_at_ms = observation.observed_at_ms;
        let candidates = if alive {
            vec!["match".into(), "timeout".into()]
        } else {
            let mut candidates = vec!["match".into(), "process_exit".into()];
            if observed_at_ms >= deadline_at_ms || epoch_ms()? >= deadline_at_ms {
                candidates.push("timeout".into());
            }
            candidates
        };
        let selected = if !alive || observed_at >= deadline {
            selection(
                "recovery_ambiguous",
                Some(stream),
                observed_at_ms,
                None,
                true,
                Some(candidates),
            )
        } else {
            selection("match", Some(stream), observed_at_ms, None, true, None)
        };
        return finish_resumed(
            db,
            selected,
            FinishContext::resumed(id, child_pid, &watch, Some(&outputs)),
            &mut started_callback,
        );
    }
    if !alive {
        let lengths = outputs.snapshot_lengths()?;
        outputs.limit_to(lengths);
        if let Some(observation) = outputs.match_empty_final_output(&regex)? {
            let now = observation.observed_at_ms;
            let mut candidates = vec!["match".into(), "process_exit".into()];
            if now >= deadline_at_ms || epoch_ms()? >= deadline_at_ms {
                candidates.push("timeout".into());
            }
            return finish_resumed(
                db,
                selection(
                    "recovery_ambiguous",
                    Some(observation.stream),
                    now,
                    None,
                    true,
                    Some(candidates),
                ),
                FinishContext::resumed(id, child_pid, &watch, Some(&outputs)),
                &mut started_callback,
            );
        }
        scan = scan_outputs(db, id, &mut outputs, &regex)?;
        if let Some(observation) = scan.matched {
            let now = observation.observed_at_ms;
            let mut candidates = vec!["match".into(), "process_exit".into()];
            if now >= deadline_at_ms || epoch_ms()? >= deadline_at_ms {
                candidates.push("timeout".into());
            }
            return finish_resumed(
                db,
                selection(
                    "recovery_ambiguous",
                    Some(observation.stream),
                    now,
                    None,
                    true,
                    Some(candidates),
                ),
                FinishContext::resumed(id, child_pid, &watch, Some(&outputs)),
                &mut started_callback,
            );
        }
        loop {
            if scan.eof.into_iter().all(|eof| eof) {
                let now = epoch_ms()?;
                let selected = if now >= deadline_at_ms {
                    selection(
                        "recovery_ambiguous",
                        None,
                        now,
                        None,
                        true,
                        Some(vec!["timeout".into(), "process_exit".into()]),
                    )
                } else {
                    selection("exit_status_unavailable", None, now, None, true, None)
                };
                return finish_resumed(
                    db,
                    selected,
                    FinishContext::resumed(id, child_pid, &watch, Some(&outputs)),
                    &mut started_callback,
                );
            }
            if epoch_ms()? >= deadline_at_ms {
                let unread = outputs.has_unread_to(lengths)?;
                let mut candidates = vec!["timeout".into(), "process_exit".into()];
                if unread {
                    candidates.insert(0, "match".into());
                }
                return finish_resumed(
                    db,
                    selection(
                        "recovery_ambiguous",
                        None,
                        epoch_ms()?,
                        None,
                        true,
                        Some(candidates),
                    ),
                    FinishContext::resumed(id, child_pid, &watch, Some(&outputs)),
                    &mut started_callback,
                );
            }
            scan = scan_outputs(db, id, &mut outputs, &regex)?;
            if let Some(observation) = scan.matched {
                let observed_at_ms = observation.observed_at_ms;
                let mut candidates = vec!["match".into(), "process_exit".into()];
                if observed_at_ms >= deadline_at_ms || epoch_ms()? >= deadline_at_ms {
                    candidates.push("timeout".into());
                }
                return finish_resumed(
                    db,
                    selection(
                        "recovery_ambiguous",
                        Some(observation.stream),
                        observed_at_ms,
                        None,
                        true,
                        Some(candidates),
                    ),
                    FinishContext::resumed(id, child_pid, &watch, Some(&outputs)),
                    &mut started_callback,
                );
            }
        }
    }
    if epoch_ms()? >= deadline_at_ms {
        let process_exit_possible = matches!(
            observe_process(None, child_pid, child_start)?,
            ProcessObservation::Exited(_)
        );
        let selected =
            deadline_selection(&mut outputs, deadline_at_ms, true, process_exit_possible)?;
        return finish_resumed(
            db,
            selected,
            FinishContext::resumed(id, child_pid, &watch, Some(&outputs)),
            &mut started_callback,
        );
    }
    retry_busy(|| {
        db.execute(
            "UPDATE process_watches SET state='watching' WHERE subscription_id=?1 AND state='resuming'",
            [id],
        )?;
        Ok(())
    })?;
    if let Some(callback) = started_callback.take() {
        callback(pid, &watch.stdout_path, &watch.stderr_path);
    }
    monitor(
        MonitorContext {
            db,
            id,
            regex: &regex,
            child_pid,
            child_start,
            deadline,
            deadline_at_ms,
            recovered: true,
            stdout: &watch.stdout_path,
            stderr: &watch.stderr_path,
        },
        outputs,
        None,
    )
}

fn stale_supervisors_with_attention(
    db: &Connection,
    include_needs_attention: bool,
) -> Result<Vec<String>> {
    initialize(db)?;
    let rows = {
        let mut statement = db.prepare(
            "SELECT subscription_id,supervisor_pid,supervisor_start,state,child_pid,child_start,selection_json IS NOT NULL,retention_state FROM process_watches ORDER BY subscription_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<u32>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, bool>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<RecoveryRow>>>()?
    };
    Ok(rows
        .into_iter()
        .filter_map(
            |(id, pid, start, state, child_pid, child_start, has_selection, retention_state)| {
                let retention_pending = has_selection
                    && (matches!(retention_state.as_str(), "not_started" | "active" | "error")
                        || include_needs_attention && retention_state == "failed");
                let delivery_pending = matches!(
                    state.as_str(),
                    "starting" | "watching" | "resuming" | "selected" | "publish_error"
                );
                let child_alive =
                    child_pid
                        .zip(child_start.as_deref())
                        .is_some_and(|(pid, start)| {
                            process_identity(pid)
                                .is_some_and(|(found, alive)| alive && found == start)
                        });
                let recoverable_attention = state == "needs_attention"
                    && (retention_pending
                        || child_alive && retention_state != "failed"
                        || include_needs_attention && !has_selection);
                let pending = delivery_pending || retention_pending || recoverable_attention;
                let alive =
                    process_identity(pid).is_some_and(|(found, running)| running && found == start);
                (pending && !alive).then_some(id)
            },
        )
        .collect())
}

pub fn stale_supervisors(db: &Connection) -> Result<Vec<String>> {
    stale_supervisors_with_attention(db, true)
}

pub struct SupervisorLaunch {
    pub unit: String,
    pub pid: Option<u32>,
}

#[derive(Clone)]
struct ExistingUnit {
    active_state: String,
    description: String,
    pid: Option<u32>,
}

fn watch_unit_name(database: &Path, id: &str, recovery: bool) -> Result<String> {
    let database = database.canonicalize()?;
    let mut hash = Sha256::new();
    hash.update(database.as_os_str().as_bytes());
    hash.update([0]);
    hash.update(id.as_bytes());
    let prefix = if recovery {
        "codex-wake-resume"
    } else {
        "codex-wake-watch"
    };
    Ok(format!("{prefix}-{:x}.service", hash.finalize()))
}

fn systemd_unit(unit: &str) -> Result<Option<ExistingUnit>> {
    let systemctl = crate::manager::find_program("systemctl")?;
    let output = crate::manager::run(
        Command::new(systemctl).args([
            "--user",
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=MainPID",
            "--property=Description",
            unit,
        ]),
        Duration::from_secs(5),
    )?;
    if !output.status.success() {
        anyhow::bail!(
            "systemctl could not inspect process-watch unit {unit}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut load_state = String::new();
    let mut active_state = String::new();
    let mut description = String::new();
    let mut pid = None;
    let output_text = String::from_utf8_lossy(&output.stdout);
    for line in output_text.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            load_state = value.to_owned();
        } else if let Some(value) = line.strip_prefix("ActiveState=") {
            active_state = value.to_owned();
        } else if let Some(value) = line.strip_prefix("MainPID=") {
            pid = value.parse::<u32>().ok().filter(|pid| *pid > 0);
        } else if let Some(value) = line.strip_prefix("Description=") {
            description = value.to_owned();
        }
    }
    if load_state == "not-found" {
        return Ok(None);
    }
    ensure!(
        !load_state.is_empty(),
        "systemctl returned no load state for process-watch unit {unit}"
    );
    Ok(Some(ExistingUnit {
        active_state,
        description,
        pid,
    }))
}

fn write_systemd_environment_file(
    environment: &BTreeMap<OsString, OsString>,
    directory: &Path,
    unit: &str,
) -> Result<tempfile::NamedTempFile> {
    let directory_meta = fs::symlink_metadata(directory)?;
    ensure!(
        directory_meta.is_dir()
            && directory_meta.uid() == fs::metadata("/proc/self")?.uid()
            && directory_meta.mode() & 0o077 == 0,
        "Process-watch environment directory must be private"
    );
    let mut file = tempfile::Builder::new()
        .prefix(&format!(".{unit}.environment-"))
        .suffix(&format!("-u{}", Uuid::new_v4().simple()))
        .tempfile_in(directory)?;
    for (key, value) in environment {
        let key = key
            .to_str()
            .context("systemd environment key must be UTF-8")?;
        ensure!(
            key.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
                && key
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
            "Invalid systemd environment key"
        );
        let value = value
            .to_str()
            .context("systemd environment value must be UTF-8")?;
        let mut line = String::with_capacity(key.len() + value.len() + 5);
        line.push_str(key);
        line.push_str("=\"");
        for ch in value.chars() {
            match ch {
                '\\' => line.push_str("\\\\"),
                '"' => line.push_str("\\\""),
                '$' => line.push_str("\\$"),
                ch => line.push(ch),
            }
        }
        line.push_str("\"\n");
        file.write_all(line.as_bytes())?;
    }
    file.flush()?;
    ensure!(
        file.as_file().metadata()?.mode() & 0o077 == 0,
        "systemd environment file must be private"
    );
    Ok(file)
}

fn environment_file_argument(path: &Path) -> Result<OsString> {
    let path = path
        .to_str()
        .context("systemd environment file path must be UTF-8")?;
    Ok(format!("--property=EnvironmentFile={path}").into())
}

fn supports_disabled_environment_expansion(help: &str) -> bool {
    help.contains("--expand-environment=")
}

#[derive(Debug, Eq, PartialEq)]
enum LaunchResolution {
    Started(Option<u32>),
    Failed,
    Conflict,
    Uncertain,
}

fn resolve_unit_start(
    unit: &str,
    description: &str,
    timeout: Duration,
    mut query: impl FnMut(&str) -> Result<Option<ExistingUnit>>,
) -> LaunchResolution {
    let deadline = Instant::now() + timeout;
    loop {
        match query(unit) {
            Ok(Some(existing)) if existing.description != description => {
                return LaunchResolution::Conflict;
            }
            Ok(Some(existing)) if existing.active_state == "active" => {
                return LaunchResolution::Started(existing.pid);
            }
            Ok(Some(existing)) if existing.active_state == "activating" => {}
            Ok(Some(_)) => return LaunchResolution::Failed,
            Ok(None) => {}
            Err(_) => return LaunchResolution::Uncertain,
        }
        if Instant::now() >= deadline {
            return LaunchResolution::Uncertain;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn environment_unit_from_name(name: &str) -> Option<&str> {
    let name = name.strip_prefix('.')?;
    let (unit, suffix) = name.split_once(".environment-")?;
    let (nonce, id) = suffix.rsplit_once("-u")?;
    if nonce.is_empty() {
        return None;
    }
    Uuid::parse_str(id).ok()?;
    (unit.ends_with(".service")
        && (unit.starts_with("codex-wake-watch-") || unit.starts_with("codex-wake-resume-")))
    .then_some(unit)
}

fn lock_environment_directory(directory: &Path, nonblocking: bool) -> Result<Option<File>> {
    let lock = File::open(directory)?;
    let operation = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(lock.as_raw_fd(), operation) } == 0 {
        return Ok(Some(lock));
    }
    let error = std::io::Error::last_os_error();
    if nonblocking
        && (error.raw_os_error() == Some(libc::EWOULDBLOCK)
            || error.raw_os_error() == Some(libc::EAGAIN))
    {
        return Ok(None);
    }
    Err(error.into())
}

fn inherit_environment_lock(command: &mut Command, lock: &File) {
    let fd = lock.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn cleanup_environment_files_in(
    directory: &Path,
    mut query: impl FnMut(&str) -> Result<Option<ExistingUnit>>,
) -> Result<usize> {
    let uid = fs::metadata("/proc/self")?.uid();
    let directory_meta = fs::symlink_metadata(directory)?;
    ensure!(
        directory_meta.is_dir()
            && directory_meta.uid() == uid
            && directory_meta.mode() & 0o077 == 0,
        "Process-watch environment directory must be private"
    );
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(unit) = environment_unit_from_name(&name) else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0
        {
            continue;
        }
        let state = match query(unit) {
            Ok(existing) => existing,
            Err(_) => continue,
        };
        // StartTransientUnit() replies only after enqueueing its job. If the
        // systemd-run client times out before that reply, an absent unit is
        // not proof that the manager will never create it.
        if state
            .as_ref()
            .is_none_or(|existing| existing.active_state == "activating")
        {
            continue;
        }
        fs::remove_file(entry.path())?;
        removed += 1;
    }
    Ok(removed)
}

fn cleanup_environment_directory(
    directory: &Path,
    query: impl FnMut(&str) -> Result<Option<ExistingUnit>>,
) -> Result<usize> {
    let Some(_lock) = lock_environment_directory(directory, true)? else {
        return Ok(0);
    };
    cleanup_environment_files_in(directory, query)
}

fn has_environment_file_entries(directory: &Path) -> Result<bool> {
    for entry in fs::read_dir(directory)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if (name.starts_with(".codex-wake-watch-") || name.starts_with(".codex-wake-resume-"))
            && name.contains(".environment-")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn external_database_removal_guard_in(
    directory: &Path,
    mut query: impl FnMut(&str) -> Result<Option<ExistingUnit>>,
) -> Result<File> {
    let lock = lock_environment_directory(directory, true)?;
    let Some(lock) = lock else {
        anyhow::bail!("A process-watch launch is still in progress; external database was kept");
    };
    cleanup_environment_files_in(directory, &mut query)?;
    ensure!(
        !has_environment_file_entries(directory)?,
        "A process-watch systemd start is unresolved; external database was kept for later cleanup"
    );
    Ok(lock)
}

fn cleanup_environment_files(database: &Path) -> Result<usize> {
    let canonical = database.canonicalize()?;
    let directory = canonical
        .parent()
        .context("Database path has no parent")?
        .join("process-watch");
    match fs::symlink_metadata(&directory) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    }
    cleanup_environment_directory(&directory, systemd_unit)
}

pub(crate) fn external_database_removal_guard(database: &Path) -> Result<Option<File>> {
    let canonical = database.canonicalize()?;
    let directory = canonical
        .parent()
        .context("Database path has no parent")?
        .join("process-watch");
    match fs::symlink_metadata(&directory) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    external_database_removal_guard_in(&directory, systemd_unit).map(Some)
}

fn preserve_uncertain_environment_file(file: tempfile::NamedTempFile) -> Result<PathBuf> {
    let (file, path) = file.keep().map_err(|error| {
        anyhow!(
            "could not retain uncertain systemd environment file: {}",
            error.error
        )
    })?;
    drop(file);
    Ok(path)
}

fn unresolved_launch_error(
    error: anyhow::Error,
    environment_file: tempfile::NamedTempFile,
) -> Result<SupervisorLaunch> {
    let path = preserve_uncertain_environment_file(environment_file)?;
    Err(error.context(format!(
        "systemd start remains uncertain; private environment file was retained for state-checked cleanup at {}",
        path.display()
    )))
}

fn launch_transient_unit(
    database: &Path,
    id: &str,
    executable: &Path,
    args: &[OsString],
    recovery: bool,
    overrides: &[(OsString, OsString)],
) -> Result<SupervisorLaunch> {
    launch_transient_unit_at(
        database,
        id,
        executable,
        args,
        recovery,
        overrides,
        &env::current_dir()?,
    )
}

fn launch_transient_unit_at(
    database: &Path,
    id: &str,
    executable: &Path,
    args: &[OsString],
    recovery: bool,
    overrides: &[(OsString, OsString)],
    cwd: &Path,
) -> Result<SupervisorLaunch> {
    let database = database.canonicalize()?;
    let database_metadata = fs::metadata(&database)?;
    let database_identity = (database_metadata.dev(), database_metadata.ino());
    let environment_directory = watch_dir(&database)?;
    let environment_lock = lock_environment_directory(&environment_directory, false)?
        .context("Could not lock process-watch environment directory")?;
    let current_metadata = fs::metadata(&database)?;
    ensure!(
        (current_metadata.dev(), current_metadata.ino()) == database_identity,
        "Database changed while starting process-watch supervisor"
    );
    cleanup_environment_files_in(&environment_directory, systemd_unit)?;
    let unit = watch_unit_name(&database, id, recovery)?;
    let diagnostic = diagnostic_path(&database, id)?;
    drop(open_diagnostic(&database, id)?);
    ensure!(
        cwd.to_str().is_some(),
        "systemd process-watch working directory must be UTF-8"
    );
    let mut environment = env::vars_os().collect::<BTreeMap<_, _>>();
    environment.insert(
        OsString::from("CODEX_WAKE_DB"),
        database.as_os_str().to_owned(),
    );
    for (key, value) in overrides {
        environment.insert(key.clone(), value.clone());
    }
    for (key, value) in &environment {
        ensure!(
            key.to_str().is_some() && value.to_str().is_some(),
            "systemd process-watch environment must be UTF-8"
        );
    }

    let mut identity = Sha256::new();
    identity.update(executable.as_os_str().as_bytes());
    for arg in args {
        identity.update([0]);
        identity.update(arg.as_os_str().as_bytes());
    }
    if !recovery {
        identity.update([0]);
        identity.update(cwd.as_os_str().as_bytes());
        for (key, value) in &environment {
            identity.update([0]);
            identity.update(key.as_os_str().as_bytes());
            identity.update(*b"=");
            identity.update(value.as_os_str().as_bytes());
        }
    }
    let description = format!("Codex Wake process watch {:x}", identity.finalize());
    if let Some(existing) = systemd_unit(&unit)? {
        ensure!(
            existing.description == description,
            "Existing process-watch unit {unit} has a different command, working directory, or environment"
        );
        if matches!(existing.active_state.as_str(), "active" | "activating") {
            return Ok(SupervisorLaunch {
                unit,
                pid: existing.pid,
            });
        }
        anyhow::bail!(
            "Existing process-watch unit {unit} is {}; stale-watch recovery will use its own unit",
            existing.active_state
        );
    }

    let systemd_run = crate::manager::find_program("systemd-run")?;
    let help = crate::manager::run(
        Command::new(&systemd_run).arg("--help"),
        Duration::from_secs(5),
    )?;
    ensure!(
        help.status.success(),
        "Could not inspect systemd-run capabilities"
    );
    ensure!(
        supports_disabled_environment_expansion(&String::from_utf8_lossy(&help.stdout)),
        "Process watching requires systemd 254 or later (systemd-run --expand-environment=no)"
    );
    let environment_file =
        write_systemd_environment_file(&environment, &environment_directory, &unit)?;
    let environment_file_argument = environment_file_argument(environment_file.path())?;
    let mut command = Command::new(systemd_run);
    command.args([
        OsString::from("--user"),
        OsString::from("--expand-environment=no"),
        format!("--unit={unit}").into(),
        OsString::from("--collect"),
        OsString::from("--service-type=exec"),
        OsString::from("--slice=app.slice"),
        OsString::from("--property=KillMode=process"),
        OsString::from("--property=UMask=0077"),
        format!("--property=WorkingDirectory={}", cwd.display()).into(),
        format!("--property=Description={description}").into(),
        environment_file_argument,
        OsString::from("--property=StandardOutput=null"),
        format!("--property=StandardError=append:{}", diagnostic.display()).into(),
    ]);
    command.arg("--").arg(executable).args(args);
    inherit_environment_lock(&mut command, &environment_lock);
    let output = match crate::manager::run(&mut command, Duration::from_secs(15)) {
        Ok(output) => output,
        Err(error) => {
            match resolve_unit_start(&unit, &description, START_RESOLUTION_WAIT, systemd_unit) {
                LaunchResolution::Started(pid) => return Ok(SupervisorLaunch { unit, pid }),
                LaunchResolution::Failed => {
                    return Err(error.context(format!("Starting process-watch unit {unit}")));
                }
                LaunchResolution::Conflict => {
                    return Err(error.context(format!(
                        "Process-watch unit {unit} has a different identity"
                    )));
                }
                LaunchResolution::Uncertain => {
                    return unresolved_launch_error(error, environment_file);
                }
            }
        }
    };
    if !output.status.success() {
        let error = anyhow!(
            "systemd-run could not start process-watch unit {unit}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        match resolve_unit_start(&unit, &description, START_RESOLUTION_WAIT, systemd_unit) {
            LaunchResolution::Started(pid) => return Ok(SupervisorLaunch { unit, pid }),
            LaunchResolution::Failed => return Err(error),
            LaunchResolution::Conflict => {
                return Err(error.context(format!(
                    "Process-watch unit {unit} has a different identity"
                )));
            }
            LaunchResolution::Uncertain => {
                return unresolved_launch_error(error, environment_file);
            }
        }
    }
    if let Some(existing) = systemd_unit(&unit)? {
        ensure!(
            existing.description == description,
            "Existing process-watch unit {unit} has a different command, working directory, or environment"
        );
        return Ok(SupervisorLaunch {
            unit,
            pid: if matches!(existing.active_state.as_str(), "active" | "activating") {
                existing.pid
            } else {
                None
            },
        });
    }
    // Type=exec returning successfully proves the executable ran. Very short
    // commands may already have exited and been collected before MainPID is read.
    Ok(SupervisorLaunch { unit, pid: None })
}

pub fn launch_mcp_supervisor(
    config: &crate::manager::Config,
    id: &str,
    regex: &str,
    timeout_secs: u64,
    child_command: &[String],
) -> Result<SupervisorLaunch> {
    ensure!(!child_command.is_empty(), "Missing process command");
    let database = config.db.canonicalize()?;
    let validation_db = Connection::open(&database)?;
    validation_db.busy_timeout(Duration::from_secs(1))?;
    crate::subscriptions::initialize(&validation_db)?;
    initialize(&validation_db)?;
    validate_new_watch_claim(&validation_db, id)?;
    drop(validation_db);
    let claim_token = Uuid::new_v4().to_string();
    let executable = env::current_exe()?;
    let mut args = vec![
        OsString::from("--db"),
        database.as_os_str().to_owned(),
        OsString::from("watch-process"),
        OsString::from("--subscription-id"),
        id.into(),
        OsString::from("--regex"),
        regex.into(),
        OsString::from("--timeout-seconds"),
        timeout_secs.to_string().into(),
        OsString::from("--claim-token"),
        claim_token.clone().into(),
        OsString::from("--"),
    ];
    args.extend(child_command.iter().map(OsString::from));
    let mut overrides = vec![
        (
            "CODEX_WAKE_CODEX".into(),
            config.codex.as_os_str().to_owned(),
        ),
        ("CODEX_WAKE_GH".into(), config.gh.as_os_str().to_owned()),
        (
            "CODEX_HOME".into(),
            config.codex_home.as_os_str().to_owned(),
        ),
        (
            "CODEX_WAKE_RPC_SOCKET".into(),
            config.rpc_socket.as_os_str().to_owned(),
        ),
        (
            "CODEX_WAKE_ENABLE_WEBHOOKS".into(),
            if config.webhooks_enabled { "1" } else { "0" }.into(),
        ),
    ];
    if let Some(base) = &config.plugin_base {
        overrides.push(("CODEX_WAKE_PLUGIN_BASE".into(), base.as_os_str().to_owned()));
    }
    let launch = launch_transient_unit(&database, id, &executable, &args, false, &overrides)?;
    confirm_watch_claim(&database, id, &launch.unit, &claim_token)?;
    Ok(launch)
}

fn claim_token_matches(db: &Connection, id: &str, claim_token: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM process_watches WHERE subscription_id=?1 AND claim_token=?2)",
        params![id, claim_token],
        |row| row.get(0),
    )?)
}

fn confirm_watch_claim(database: &Path, id: &str, unit: &str, claim_token: &str) -> Result<()> {
    let diagnostic = diagnostic_path(database, id)?;
    let deadline = Instant::now() + CLAIM_CONFIRMATION_WAIT;
    loop {
        let db = Connection::open(database)?;
        db.busy_timeout(Duration::from_millis(100))?;
        let claimed = claim_token_matches(&db, id, claim_token)?;
        drop(db);
        if claimed {
            return Ok(());
        }
        if let Some(status) = systemd_unit(unit)?
            && !matches!(status.active_state.as_str(), "active" | "activating")
        {
            let validation_db = Connection::open(database)?;
            if let Err(error) = validate_subscription_for_watch(&validation_db, id) {
                return Err(error).context(format!(
                    "Process-watch supervisor rejected its claim; diagnostics: {}",
                    diagnostic.display()
                ));
            }
            anyhow::bail!(
                "Process-watch supervisor ended before recording its claim; diagnostics: {}",
                diagnostic.display()
            );
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "Process-watch supervisor did not confirm its claim within {} seconds; it may still be starting; diagnostics: {}",
                CLAIM_CONFIRMATION_WAIT.as_secs(),
                diagnostic.display()
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_resume(database: &Path, id: &str, systemd: bool) -> Result<(Option<String>, Option<u32>)> {
    let database = database.canonicalize()?;
    let args = [
        OsString::from("--db"),
        database.as_os_str().to_owned(),
        OsString::from("watch-process"),
        OsString::from("--resume"),
        OsString::from("--subscription-id"),
        id.into(),
    ];
    if systemd {
        let launch = launch_transient_unit(&database, id, &env::current_exe()?, &args, true, &[])?;
        Ok((Some(launch.unit), launch.pid))
    } else {
        let diagnostic = open_diagnostic(&database, id)?;
        let child = Command::new(env::current_exe()?)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(diagnostic))
            .process_group(0)
            .spawn()?;
        let pid = child.id();
        drop(reap_child(child));
        Ok((None, Some(pid)))
    }
}

fn reap_child(mut child: Child) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let _ = child.wait();
    })
}

pub fn schedule_stale(db: &Connection, database: &Path) -> Result<Value> {
    cleanup_environment_files(database)?;
    let stale = stale_supervisors(db)?;
    schedule_stale_from_ids(db, database, stale)
}

pub fn schedule_stale_auto(db: &Connection, database: &Path) -> Result<Value> {
    cleanup_environment_files(database)?;
    schedule_stale_from(db, database, false, true)
}

fn schedule_stale_from(
    db: &Connection,
    database: &Path,
    include_needs_attention: bool,
    systemd: bool,
) -> Result<Value> {
    schedule_stale_from_ids_mode(
        db,
        database,
        stale_supervisors_with_attention(db, include_needs_attention)?,
        systemd,
    )
}

fn schedule_stale_from_ids(db: &Connection, database: &Path, ids: Vec<String>) -> Result<Value> {
    schedule_stale_from_ids_mode(db, database, ids, false)
}

fn schedule_stale_from_ids_mode(
    db: &Connection,
    database: &Path,
    ids: Vec<String>,
    systemd: bool,
) -> Result<Value> {
    let mut scheduled = Vec::new();
    let mut errors = Vec::new();
    for id in ids {
        let previous: Option<(u32, String)> = db
            .query_row(
                "SELECT supervisor_pid,supervisor_start FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((previous_pid, previous_start)) = previous else {
            continue;
        };
        if !identity_has_current_pid_namespace(&previous_start) {
            set_pid_namespace_attention(
                db,
                &id,
                "Saved supervisor identity has no verifiable current PID namespace; automatic recovery was not attempted",
            );
            errors.push(json!({
                "subscription_id":id,
                "error":"supervisor PID namespace cannot be verified"
            }));
            continue;
        }
        if process_identity(previous_pid)
            .is_some_and(|(start, alive)| alive && start == previous_start)
        {
            continue;
        }
        match spawn_resume(database, &id, systemd) {
            Ok((unit, pid)) => {
                if let Some(pid) = pid
                    && let Some((start, true)) = wait_process_identity(pid)
                {
                    retry_busy(|| {
                        db.execute(
                            "UPDATE process_watches SET supervisor_pid=?1,supervisor_start=?2,state=CASE WHEN selection_json IS NULL THEN 'resuming' ELSE 'selected' END WHERE subscription_id=?3 AND supervisor_pid=?4 AND supervisor_start=?5",
                            params![pid, start, id, previous_pid, previous_start],
                        )?;
                        Ok(())
                    })?;
                }
                scheduled.push(json!({
                    "subscription_id":id,
                    "supervisor_pid":pid,
                    "supervisor_unit":unit
                }));
            }
            Err(error) => errors.push(json!({"subscription_id":id,"error":error.to_string()})),
        }
    }
    Ok(json!({"scheduled":scheduled,"errors":errors}))
}

fn wait_process_identity(pid: u32) -> Option<(String, bool)> {
    for _ in 0..20 {
        if let Some(identity) = process_identity(pid) {
            return Some(identity);
        }
        thread::sleep(Duration::from_millis(5));
    }
    None
}

pub fn status(db: &Connection, id: &str) -> Result<Value> {
    let watch = load_watch(db, id)?;
    let (
        state,
        supervisor_pid,
        supervisor_start,
        started_at,
        diagnostic,
        retention_state,
        retention_diagnostic,
    ): WatchStatus = db.query_row(
        "SELECT state,supervisor_pid,supervisor_start,started_at_ms,diagnostic,retention_state,retention_diagnostic FROM process_watches WHERE subscription_id=?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
    )?;
    let supervisor_alive = process_identity(supervisor_pid)
        .is_some_and(|(start, alive)| alive && start == supervisor_start)
        || legacy_identity_matches_live_process(supervisor_pid, &supervisor_start);
    let child_alive = watch
        .child_pid
        .zip(watch.child_start.as_deref())
        .is_some_and(|(pid, start)| {
            process_identity(pid).is_some_and(|(found, alive)| alive && found == start)
                || legacy_identity_matches_live_process(pid, start)
        });
    Ok(json!({
        "subscription_id":id,
        "state":state,
        "retention_state":retention_state,
        "retention_diagnostic":retention_diagnostic,
        "supervisor_pid":supervisor_pid,
        "supervisor_alive":supervisor_alive,
        "child_pid":watch.child_pid,
        "child_alive":child_alive,
        "started_at_ms":started_at,
        "deadline_at_ms":watch.deadline_at_ms,
        "selection":watch.selection.map(|value|serde_json::from_str::<Value>(&value)).transpose()?,
        "stdout_path":watch.stdout_path.display().to_string(),
        "stderr_path":watch.stderr_path.display().to_string(),
        "stdout_retained_path":retained_output_path(&watch.stdout_path).display().to_string(),
        "stderr_retained_path":retained_output_path(&watch.stderr_path).display().to_string(),
        "match_context_path":match_context_path(&watch.stdout_path).display().to_string(),
        "diagnostic_path":diagnostic_path_without_creating_directory(&database_path(db)?, id)?.display().to_string(),
        "diagnostic":diagnostic
    }))
}

fn append_window(window: &mut Vec<u8>, bytes: &[u8]) {
    window.extend_from_slice(bytes);
    if window.len() > WINDOW {
        window.drain(..window.len() - WINDOW);
    }
}

fn append_scanned_window(window: &mut Vec<u8>, bytes: &[u8], preceding: &mut Vec<u8>) {
    window.extend_from_slice(bytes);
    let discarded = window.len().saturating_sub(WINDOW);
    if discarded > 0 {
        if discarded >= 4 {
            preceding.clear();
            preceding.extend_from_slice(&window[discarded - 4..discarded]);
        } else {
            preceding.extend_from_slice(&window[..discarded]);
            if preceding.len() > 4 {
                preceding.drain(..preceding.len() - 4);
            }
        }
        window.drain(..discarded);
    }
}

#[cfg(test)]
fn unit_property(unit: &str, property: &str) -> Result<String> {
    let systemctl = crate::manager::find_program("systemctl")?;
    let option = format!("--property={property}");
    let output = crate::manager::run(
        Command::new(systemctl).args(["--user", "show", "--no-pager", &option, unit]),
        Duration::from_secs(5),
    )?;
    ensure!(
        output.status.success(),
        "Could not inspect isolated unit {unit}"
    );
    let prefix = format!("{property}=");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_owned)
        .context("systemctl omitted the requested unit property")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscriptions::{self, DeliveryConfig};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    struct ReleaseChildOnDrop(PathBuf);

    impl Drop for ReleaseChildOnDrop {
        fn drop(&mut self) {
            let _ = fs::write(&self.0, []);
        }
    }

    struct ReapChildOnDrop {
        child: Child,
        release: PathBuf,
        reaped: bool,
    }

    impl ReapChildOnDrop {
        fn id(&self) -> u32 {
            self.child.id()
        }

        fn wait(&mut self) -> std::io::Result<ExitStatus> {
            let status = self.child.wait()?;
            self.reaped = true;
            Ok(status)
        }
    }

    impl Drop for ReapChildOnDrop {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            let _ = fs::write(&self.release, []);
            // This fixture creates its own process group so a panic also cleans
            // up the shell and any short-lived sleep descendants.
            unsafe {
                let _ = libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }

    fn setup(expires: bool) -> (tempfile::TempDir, Connection, String) {
        let dir = tempdir().unwrap();
        let db = Connection::open(dir.path().join("watch.sqlite")).unwrap();
        db.busy_timeout(Duration::from_millis(10)).unwrap();
        subscriptions::initialize(&db).unwrap();
        initialize(&db).unwrap();
        let id = subscriptions::subscribe_with_delivery(
            &db,
            "job",
            "local",
            &Uuid::new_v4().to_string(),
            "completed",
            "11111111-1111-4111-8111-111111111111",
            DeliveryConfig {
                message_template: Some("Process watch: {{source.watch.reason}}"),
                expires_in_secs: expires.then_some(60),
                ..DeliveryConfig::default()
            },
        )
        .unwrap();
        (dir, db, id)
    }

    fn state(db: &Connection, id: &str) -> String {
        db.query_row("SELECT state FROM subscriptions WHERE id=?1", [id], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn stored_selection(db: &Connection, id: &str) -> Value {
        let selected: String = db
            .query_row(
                "SELECT selection_json FROM process_watches WHERE subscription_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str(&selected).unwrap()
    }

    fn stale_owner() -> String {
        format!(
            "test:{}:0",
            pid_namespace(std::process::id()).expect("current PID namespace")
        )
    }

    fn cmd(script: String) -> Vec<String> {
        vec!["sh".into(), "-c".into(), script]
    }

    struct KillTestProcessGroupOnDrop {
        pid: u32,
        start: String,
    }

    impl KillTestProcessGroupOnDrop {
        fn kill(&self) {
            if process_identity(self.pid).is_some_and(|(start, alive)| alive && start == self.start)
            {
                unsafe {
                    let _ = libc::kill(-(self.pid as libc::pid_t), libc::SIGKILL);
                }
            }
        }
    }

    impl Drop for KillTestProcessGroupOnDrop {
        fn drop(&mut self) {
            self.kill();
        }
    }

    fn assert_trailing_newline_matches_while_child_is_alive(pattern: &str) {
        let (_dir, db, id) = setup(false);
        db.busy_timeout(Duration::from_secs(2)).unwrap();
        let database = database_path(&db).unwrap();
        let worker_id = id.clone();
        let worker_pattern = pattern.to_owned();
        let worker = thread::spawn(move || {
            let worker_db = Connection::open(database).unwrap();
            worker_db.busy_timeout(Duration::from_secs(2)).unwrap();
            run(
                &worker_db,
                &worker_id,
                &worker_pattern,
                Duration::from_secs(4),
                &cmd("printf 'READY\\n'; exec sleep 10".into()),
            )
        });

        let selection_deadline = Instant::now() + Duration::from_secs(7);
        let mut cleanup = None;
        let saved = loop {
            let row: Option<(Option<u32>, Option<String>, Option<String>)> = db
                .query_row(
                    "SELECT child_pid,child_start,selection_json FROM process_watches WHERE subscription_id=?1",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .unwrap();
            if let Some((Some(pid), Some(start), selection)) = row {
                cleanup.get_or_insert_with(|| KillTestProcessGroupOnDrop {
                    pid,
                    start: start.clone(),
                });
                if let Some(selection) = selection {
                    break (pid, start, selection);
                }
            }
            assert!(
                Instant::now() < selection_deadline,
                "process watch did not persist an outcome"
            );
            thread::sleep(Duration::from_millis(50));
        };
        let (pid, start, selection) = saved;
        let cleanup = cleanup.expect("child identity is recorded with its selection");
        let selection: Value = serde_json::from_str(&selection).unwrap();
        let matched_while_alive = selection["reason"] == "match"
            && process_identity(pid).is_some_and(|(found, alive)| alive && found == start);
        cleanup.kill();
        let result = worker.join().unwrap().unwrap();

        assert!(
            matched_while_alive,
            "trailing newline match must be persisted while the child is still alive (selection={selection})"
        );
        assert_eq!(result["reason"], "match");
    }

    #[test]
    fn trailing_newline_establishes_word_boundary_for_live_quiet_child() {
        assert_trailing_newline_matches_while_child_is_alive(r"READY\b");
    }

    #[test]
    fn multiline_end_anchor_matches_before_newline_for_live_quiet_child() {
        assert_trailing_newline_matches_while_child_is_alive("(?m)^READY$");
    }

    #[test]
    fn external_output_cleanup_checks_live_watches_without_an_output_directory() {
        let (dir, db, id) = setup(false);
        let directory = dir.path().join("process-watch");
        assert!(!directory.exists());
        let database = database_path(&db).unwrap();
        let (pid, start) = current_identity().unwrap();
        let stdout = directory.join("missing.stdout");
        let stderr = directory.join("missing.stderr");
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'published',?2,?3,'x',?4,?5,'{}','complete')",
            params![id, pid, start, stdout.display().to_string(), stderr.display().to_string()],
        )
        .unwrap();

        let error = remove_external_outputs(&database).unwrap_err();

        assert!(error.to_string().contains("still has a live process"));
        assert!(database.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn status_does_not_create_a_missing_output_directory() {
        let (dir, db, id) = setup(false);
        let directory = dir.path().join("process-watch");
        assert!(!directory.exists());
        let stdout = directory.join("status.stdout");
        let stderr = directory.join("status.stderr");
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path,retention_state)
             VALUES(?1,'needs_attention',?2,?3,'x',?4,?5,'failed')",
            params![
                id,
                u32::MAX,
                stale_owner(),
                stdout.display().to_string(),
                stderr.display().to_string()
            ],
        )
        .unwrap();

        let report = status(&db, &id).unwrap();

        assert!(report["diagnostic_path"].as_str().is_some());
        assert!(!directory.exists());
    }

    #[test]
    fn corrupt_selection_without_child_identity_fails_retention_safely() {
        let (_dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'selected',?2,?3,424242,'x',?4,?5,'{','active')",
            params![
                id,
                u32::MAX,
                stale_owner(),
                paths.stdout.display().to_string(),
                paths.stderr.display().to_string()
            ],
        )
        .unwrap();

        let error = resume_started(&db, &id, |_, _, _| {}).unwrap_err();

        let (state, retention, diagnostic): (String, String, String) = db
            .query_row(
                "SELECT state,retention_state,diagnostic FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(error.to_string().contains("selection is corrupt"));
        assert_eq!(state, "needs_attention");
        assert_eq!(retention, "failed");
        assert!(diagnostic.contains("selection is corrupt"));
    }

    #[test]
    fn corrupt_selection_without_pid_preserves_launch_uncertain() {
        let (_dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'launch_uncertain',?2,?3,'x',?4,?5,'{','active')",
            params![
                id,
                u32::MAX,
                stale_owner(),
                paths.stdout.display().to_string(),
                paths.stderr.display().to_string()
            ],
        )
        .unwrap();

        let error = resume_started(&db, &id, |_, _, _| {}).unwrap_err();

        let (state, retention, diagnostic): (String, String, String) = db
            .query_row(
                "SELECT state,retention_state,diagnostic FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(error.to_string().contains("selection is corrupt"));
        assert_eq!(state, "launch_uncertain");
        assert_eq!(retention, "failed");
        assert!(diagnostic.contains("selection is corrupt"));
    }

    #[test]
    fn fragmented_match_is_observed_before_exit_and_published_once() {
        let (_dir, db, id) = setup(false);
        let result = run(
            &db,
            &id,
            "needle",
            Duration::from_secs(2),
            &cmd("printf nee; sleep .04; printf dle; sleep .04".into()),
        )
        .unwrap();
        assert_eq!(result["reason"], "match");
        assert_eq!(state(&db, &id), "ready");
        let verified: bool = db
            .query_row(
                "SELECT process_watch_verified FROM subscriptions WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(verified, "the monitor's own publication must be verified");
        assert!(Path::new(result["stdout_path"].as_str().unwrap()).exists());
    }

    #[test]
    fn publication_retries_while_reaper_waits_for_live_child() {
        let (dir, db, id) = setup(false);
        let database = dir.path().join("watch.sqlite");
        let release_child = dir.path().join("release-child");
        let _release_child_on_drop = ReleaseChildOnDrop(release_child.clone());
        let release_child = release_child.display().to_string();
        db.execute_batch(
            "CREATE TRIGGER temporary_publish_failure BEFORE UPDATE OF state ON subscriptions
             WHEN NEW.state='ready' AND NEW.outcome='completed'
             BEGIN SELECT RAISE(ABORT, 'temporary publication failure'); END;",
        )
        .unwrap();
        drop(db);

        let worker_database = database.clone();
        let worker_id = id.clone();
        let worker = thread::spawn(move || {
            let db = Connection::open(worker_database).unwrap();
            db.busy_timeout(Duration::from_secs(1)).unwrap();
            run(
                &db,
                &worker_id,
                "READY",
                Duration::from_secs(4),
                &cmd(format!(
                    "printf READY; i=0; while [ ! -e '{release_child}' ] && [ \"$i\" -lt 2000 ]; do sleep .01; i=$((i+1)); done"
                )),
            )
        });

        let observer = Connection::open(&database).unwrap();
        let publish_error_deadline = Instant::now() + Duration::from_secs(2);
        let child_pid = loop {
            let row: Option<(String, Option<u32>)> = observer
                .query_row(
                    "SELECT state,child_pid FROM process_watches WHERE subscription_id=?1",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .unwrap();
            let Some((state, pid)) = row else {
                assert!(
                    Instant::now() < publish_error_deadline,
                    "process watch was not registered"
                );
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            if state == "publish_error" {
                break pid.expect("the child PID is durable before selection publication");
            }
            assert!(
                Instant::now() < publish_error_deadline,
                "publication failure was not recorded"
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert!(process_identity(child_pid).is_some_and(|(_, alive)| alive));
        observer
            .execute_batch("DROP TRIGGER temporary_publish_failure")
            .unwrap();

        let published_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let state: String = observer
                .query_row(
                    "SELECT state FROM subscriptions WHERE id=?1",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            if state == "ready" {
                let watch_state: String = observer
                    .query_row(
                        "SELECT state FROM process_watches WHERE subscription_id=?1",
                        [&id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(watch_state, "published");
                assert!(
                    process_identity(child_pid).is_some_and(|(_, alive)| alive),
                    "publication should recover while the child is still alive"
                );
                break;
            }
            assert!(
                Instant::now() < published_deadline,
                "publication was not retried while retention continued"
            );
            thread::sleep(Duration::from_millis(10));
        }
        fs::write(dir.path().join("release-child"), []).unwrap();
        assert_eq!(worker.join().unwrap().unwrap()["reason"], "match");
    }

    #[test]
    fn empty_regex_matches_only_after_an_empty_stream_finishes() {
        let (_dir, db, id) = setup(false);
        let result = run(
            &db,
            &id,
            "^$",
            Duration::from_secs(2),
            &cmd("sleep .1".into()),
        )
        .unwrap();
        assert!(matches!(
            result["reason"].as_str(),
            Some("match" | "observation_ambiguous")
        ));
        if result["reason"] == "observation_ambiguous" {
            assert_eq!(
                stored_selection(&db, &id)["candidates"],
                json!(["match", "process_exit", "timeout"])
            );
        }
        assert_eq!(stored_selection(&db, &id)["stream"], "stdout");
        assert_eq!(state(&db, &id), "ready");
    }

    #[test]
    fn empty_regex_does_not_match_the_initial_prefix_before_output() {
        let (_dir, db, id) = setup(false);
        let result = run(
            &db,
            &id,
            "^$",
            Duration::from_secs(2),
            &cmd("sleep .1; printf x; printf y >&2".into()),
        )
        .unwrap();
        assert_eq!(result["reason"], "exit");
        assert_eq!(state(&db, &id), "ready");
    }

    #[test]
    fn truncation_keeps_the_active_inode_and_append_writer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("stdout.log");
        fs::write(&path, []).unwrap();
        let mut child_writer = OpenOptions::new().append(true).open(&path).unwrap();
        child_writer.write_all(b"before-selection").unwrap();
        let original_inode = fs::metadata(&path).unwrap().ino();
        let expected = file_identity(&child_writer).unwrap();

        retain_and_truncate(&path, expected).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().ino(), original_inode);
        assert_eq!(
            fs::read(retained_output_path(&path)).unwrap(),
            b"before-selection"
        );

        child_writer.write_all(b"after-truncate").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"after-truncate");
    }

    #[test]
    fn retained_output_is_a_rolling_window_per_active_log() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("stdout.log");
        fs::write(&path, vec![b'a'; WINDOW + 4096]).unwrap();
        let active = open_regular_nofollow(&path, true, false).unwrap();
        let expected = file_identity(&active).unwrap();

        retain_and_truncate(&path, expected).unwrap();

        let retained = fs::read(retained_output_path(&path)).unwrap();
        assert_eq!(retained.len(), WINDOW);
        assert!(retained.iter().all(|byte| *byte == b'a'));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn read_boundary_lookahead_prevents_false_end_anchor_match() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let mut bytes = vec![b'x'; 8187];
        bytes.extend_from_slice(b"READYX");
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, []).unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let regex = WatchRegex::new("READY$").unwrap();

        for _ in 0..2 {
            assert!(outputs.scan(&regex).unwrap().matched.is_none());
        }
    }

    #[test]
    fn end_anchor_waits_for_confirmed_process_exit() {
        let (_dir, db, id) = setup(false);
        let result = run(
            &db,
            &id,
            "READY$",
            Duration::from_secs(2),
            &cmd("printf READY; sleep .1; printf X; sleep .1".into()),
        )
        .unwrap();
        assert_eq!(result["reason"], "exit");

        let (_dir, db, id) = setup(false);
        let result = run(
            &db,
            &id,
            "READY$",
            Duration::from_secs(2),
            &cmd("printf READY".into()),
        )
        .unwrap();
        assert_eq!(result["reason"], "match");
    }

    #[test]
    fn failed_atomic_writes_remove_temporary_files() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("retained");
        fs::create_dir(&target).unwrap();
        assert!(atomic_write(&target, b"data").is_err());

        let stdout = dir.path().join("stdout.log");
        fs::create_dir(identity_path(&stdout)).unwrap();
        assert!(
            write_identity(
                &stdout,
                &ChildIdentity {
                    pid: 1,
                    start: "test".into(),
                    started_at_ms: 0,
                    deadline_at_ms: 1,
                    stdout_file: None,
                    stderr_file: None,
                },
            )
            .is_err()
        );
        assert!(
            fs::read_dir(dir.path())
                .unwrap()
                .all(|entry| { entry.unwrap().file_type().unwrap().is_dir() })
        );
    }

    #[test]
    fn symlinked_active_log_is_never_opened_or_truncated() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("unrelated.log");
        let active = dir.path().join("stdout.log");
        fs::write(&active, b"original log").unwrap();
        let original = open_regular_nofollow(&active, true, false).unwrap();
        let expected = file_identity(&original).unwrap();
        fs::remove_file(&active).unwrap();
        fs::write(&target, b"unrelated data").unwrap();
        std::os::unix::fs::symlink(&target, &active).unwrap();

        assert!(retain_and_truncate(&active, expected).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unrelated data");
    }

    #[test]
    fn replacing_output_path_after_creation_does_not_redirect_child_or_truncation() {
        let (_dir, db, id) = setup(false);
        let outputs = output_paths(&db, &id).unwrap();
        let OutputPaths {
            stdout,
            writers: [stdout_writer, stderr_writer],
            identities,
            ..
        } = outputs;
        let target = stdout.with_file_name("unrelated.log");
        fs::write(&target, b"unrelated data survives").unwrap();

        // Reproduce replacement after create_new but before the descriptors are
        // handed to the child. The child must keep writing to the original inode.
        fs::remove_file(&stdout).unwrap();
        fs::hard_link(&target, &stdout).unwrap();
        let original_stdout = stdout_writer.try_clone().unwrap();
        let mut child = Command::new("sh")
            .args(["-c", "printf child-output"])
            .stdout(Stdio::from(stdout_writer))
            .stderr(Stdio::from(stderr_writer))
            .spawn()
            .unwrap();
        assert!(child.wait().unwrap().success());

        assert_eq!(original_stdout.metadata().unwrap().len(), 12);
        assert_eq!(fs::read(&target).unwrap(), b"unrelated data survives");
        assert!(retain_and_truncate(&stdout, identities[0]).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unrelated data survives");
    }

    #[test]
    fn hardlink_or_regular_replacement_is_not_truncated() {
        let dir = tempdir().unwrap();
        let active = dir.path().join("stdout.log");
        let original = dir.path().join("original.log");
        fs::write(&active, b"original output").unwrap();
        let original_file = open_regular_nofollow(&active, true, false).unwrap();
        let expected = file_identity(&original_file).unwrap();

        let hardlink_target = dir.path().join("hardlink-target.log");
        fs::write(&hardlink_target, b"hardlink target must survive").unwrap();
        fs::remove_file(&active).unwrap();
        fs::hard_link(&hardlink_target, &active).unwrap();
        assert!(retain_and_truncate(&active, expected).is_err());
        assert_eq!(
            fs::read(&hardlink_target).unwrap(),
            b"hardlink target must survive"
        );

        fs::remove_file(&active).unwrap();
        fs::write(&original, b"replacement must survive").unwrap();
        fs::rename(&original, &active).unwrap();
        assert!(retain_and_truncate(&active, expected).is_err());
        assert_eq!(fs::read(&active).unwrap(), b"replacement must survive");
    }

    #[test]
    fn recovery_refuses_a_hardlinked_replacement_without_touching_its_target() {
        let (dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        let stdout = paths.stdout.clone();
        let stderr = paths.stderr.clone();
        let [stdout_identity, stderr_identity] = paths.identities;
        let target = dir.path().join("unrelated.log");
        fs::write(&target, b"unrelated data survives recovery").unwrap();
        fs::remove_file(&stdout).unwrap();
        fs::hard_link(&target, &stdout).unwrap();

        let mut child = Command::new("sh")
            .args(["-c", "sleep .2"])
            .process_group(0)
            .spawn()
            .unwrap();
        let child_pid = child.id();
        let child_start = process_identity(child_pid).unwrap().0;
        let started_at_ms = epoch_ms().unwrap();
        let deadline_at_ms = started_at_ms + 10_000;
        write_identity(
            &stdout,
            &ChildIdentity {
                pid: child_pid,
                start: child_start.clone(),
                started_at_ms,
                deadline_at_ms,
                stdout_file: Some(stdout_identity),
                stderr_file: Some(stderr_identity),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path)
             VALUES(?1,'watching',?2,?3,?4,?5,?6,?7,'NEEDLE',?8,?9)",
            params![id, u32::MAX, stale_owner(), child_pid, child_start, started_at_ms, deadline_at_ms, stdout.display().to_string(), stderr.display().to_string()],
        )
        .unwrap();

        let error = resume_started(&db, &id, |_, _, _| {}).unwrap_err();
        assert!(error.to_string().contains("original file"));
        assert_eq!(
            fs::read(&target).unwrap(),
            b"unrelated data survives recovery"
        );
        let states: (String, String) = db
            .query_row(
                "SELECT state,retention_state FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(states, ("needs_attention".into(), "failed".into()));
        child.wait().unwrap();
    }

    #[test]
    fn final_retention_failure_stops_auto_relaunch_but_allows_manual_retry() {
        let (dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        let stdout = paths.stdout.clone();
        let stderr = paths.stderr.clone();
        let target = dir.path().join("unrelated.log");
        let [stdout_identity, stderr_identity] = paths.identities;
        fs::write(&target, b"preserve me").unwrap();
        fs::remove_file(&stdout).unwrap();
        std::os::unix::fs::symlink(&target, &stdout).unwrap();

        let mut child = Command::new("true").process_group(0).spawn().unwrap();
        let child_pid = child.id();
        let child_start = process_identity(child_pid).unwrap().0;
        write_identity(
            &stdout,
            &ChildIdentity {
                pid: child_pid,
                start: child_start.clone(),
                started_at_ms: epoch_ms().unwrap(),
                deadline_at_ms: epoch_ms().unwrap() + 1000,
                stdout_file: Some(stdout_identity),
                stderr_file: Some(stderr_identity),
            },
        )
        .unwrap();
        child.wait().unwrap();
        let selected = selection("timeout", None, epoch_ms().unwrap(), None, false, None);
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'published',?2,?3,?4,?5,'x',?6,?7,?8,'active')",
            params![id, u32::MAX, stale_owner(), child_pid, child_start, stdout.display().to_string(), stderr.display().to_string(), serde_json::to_string(&selected).unwrap()],
        )
        .unwrap();

        let database = dir.path().join("watch.sqlite").canonicalize().unwrap();
        let database_metadata = fs::metadata(&database).unwrap();
        reap_until_child_exit(ReaperContext {
            database,
            database_identity: FileIdentity {
                dev: database_metadata.dev(),
                ino: database_metadata.ino(),
            },
            id: id.clone(),
            pid: child_pid,
            child_start,
            stdout,
            stderr,
            selected,
            match_context: None,
            child: None,
        });

        let states: (String, String) = db
            .query_row(
                "SELECT state,retention_state FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(states, ("published".into(), "failed".into()));
        assert_eq!(fs::read(target).unwrap(), b"preserve me");
        assert!(
            !stale_supervisors_with_attention(&db, false)
                .unwrap()
                .contains(&id)
        );
        assert!(
            stale_supervisors_with_attention(&db, true)
                .unwrap()
                .contains(&id)
        );
    }

    #[test]
    fn uninstall_refuses_database_and_logs_while_watch_child_is_live() {
        let (dir, db, id) = setup(false);
        db.pragma_update(None, "application_id", crate::uninstall::DATABASE_ID)
            .unwrap();
        let paths = output_paths(&db, &id).unwrap();
        let stdout = paths.stdout.clone();
        let mut child = Command::new("sleep")
            .arg("10")
            .stdout(Stdio::from(paths.writers[0].try_clone().unwrap()))
            .stderr(Stdio::from(paths.writers[1].try_clone().unwrap()))
            .process_group(0)
            .spawn()
            .unwrap();
        let (supervisor_pid, supervisor_start) = current_identity().unwrap();
        let child_start = process_identity(child.id()).unwrap().0;
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,regex,stdout_path,stderr_path,retention_state)
             VALUES(?1,'watching',?2,?3,?4,?5,'READY',?6,?7,'active')",
            params![
                id,
                supervisor_pid,
                supervisor_start,
                child.id(),
                child_start,
                paths.stdout.display().to_string(),
                paths.stderr.display().to_string()
            ],
        )
        .unwrap();
        let database = dir.path().join("watch.sqlite");

        let error = crate::uninstall::remove_external_database(&database).unwrap_err();
        assert!(error.to_string().contains("unfinished output retention"));
        assert!(database.exists());
        assert!(stdout.exists());
        assert!(process_identity(child.id()).is_some_and(|(_, alive)| alive));

        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn reaper_and_uninstall_serialize_without_recreating_removed_logs() {
        let (dir, db, id) = setup(false);
        db.pragma_update(None, "application_id", crate::uninstall::DATABASE_ID)
            .unwrap();
        let mut paths = output_paths(&db, &id).unwrap();
        paths.writers[0].write_all(b"selected output").unwrap();
        let selected = selection("timeout", None, epoch_ms().unwrap(), None, false, None);
        write_identity(
            &paths.stdout,
            &ChildIdentity {
                pid: 1,
                start: "test".into(),
                started_at_ms: epoch_ms().unwrap(),
                deadline_at_ms: epoch_ms().unwrap() + 1000,
                stdout_file: Some(paths.identities[0]),
                stderr_file: Some(paths.identities[1]),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'published',1,'test','x',?2,?3,?4,'complete')",
            params![
                id,
                paths.stdout.display().to_string(),
                paths.stderr.display().to_string(),
                serde_json::to_string(&selected).unwrap()
            ],
        )
        .unwrap();
        let unrelated = paths.stdout.parent().unwrap().join("user-file.log");
        fs::write(&unrelated, b"preserve").unwrap();
        let database = database_path(&db).unwrap();
        let orphan_diagnostic = diagnostic_path(&database, "failed-claim").unwrap();
        fs::write(&orphan_diagnostic, b"claim failure diagnostics").unwrap();
        let other_database = dir.path().join("other.sqlite");
        drop(Connection::open(&other_database).unwrap());
        let other_diagnostic = diagnostic_path(&other_database, "same-subscription-id").unwrap();
        fs::write(&other_diagnostic, b"other database diagnostics").unwrap();
        let database = database_path(&db).unwrap().canonicalize().unwrap();
        let database_metadata = fs::metadata(&database).unwrap();
        let database_identity = FileIdentity {
            dev: database_metadata.dev(),
            ino: database_metadata.ino(),
        };
        let stdout = paths.stdout.clone();
        let stderr = paths.stderr.clone();
        drop(paths);
        drop(db);

        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let reaper_stdout = stdout.clone();
        let reaper_stderr = stderr.clone();
        let reaper_selection = selected.clone();
        let reaper = thread::spawn(move || {
            with_watch_database(&database, database_identity, || {
                retain_selected_output(&reaper_stdout, &reaper_stderr, &reaper_selection, None)?;
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap()
        });
        locked_rx.recv().unwrap();

        let database = dir.path().join("watch.sqlite");
        assert!(crate::uninstall::remove_external_database(&database).is_err());
        assert!(database.exists());
        release_tx.send(()).unwrap();
        assert_eq!(reaper.join().unwrap(), Some(()));
        crate::uninstall::remove_external_database(&database).unwrap();
        assert!(!orphan_diagnostic.exists());
        assert_eq!(
            fs::read(&other_diagnostic).unwrap(),
            b"other database diagnostics"
        );

        let recreated = with_watch_database(&database, database_identity, || {
            retain_selected_output(&stdout, &stderr, &selected, None)
        })
        .unwrap();
        assert!(recreated.is_none());
        assert!(!stdout.exists());
        assert!(!retained_output_path(&stdout).exists());
        assert_eq!(fs::read(unrelated).unwrap(), b"preserve");
    }

    #[test]
    fn scan_reads_bounded_chunks_from_both_streams() {
        use std::io::Seek;

        let dir = tempfile::tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        fs::write(&stdout, vec![b'x'; 128 * 1024]).unwrap();
        fs::write(&stderr, b"READY").unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();

        let found = outputs.scan(&WatchRegex::new("READY").unwrap()).unwrap();
        assert_eq!(found.matched.unwrap().stream, "stderr");
        assert!(outputs.files[0].stream_position().unwrap() <= 8192);
    }

    #[test]
    fn lookahead_boundary_does_not_create_a_false_end_anchor_match() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let mut bytes = vec![b'x'; 8191];
        bytes.extend_from_slice(b"READYX");
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, []).unwrap();

        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let regex = WatchRegex::new("READY$").unwrap();
        assert!(outputs.scan(&regex).unwrap().matched.is_none());
        assert!(outputs.scan(&regex).unwrap().matched.is_none());

        let mut newline = vec![b'x'; 8190];
        newline.extend_from_slice(b"READY\nX");
        fs::write(&stdout, newline).unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        assert!(outputs.scan(&regex).unwrap().matched.is_none());
        assert!(outputs.scan(&regex).unwrap().matched.is_none());

        let mut terminal = vec![b'x'; 8191];
        terminal.extend_from_slice(b"READY");
        fs::write(&stdout, terminal).unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        outputs.limit_to(outputs.snapshot_lengths().unwrap());
        assert_eq!(
            outputs.scan(&regex).unwrap().matched.unwrap().stream,
            "stdout"
        );
    }

    #[test]
    fn alternative_anchors_and_word_boundaries_do_not_match_artificial_edges() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let mut bytes = vec![b'x'; 8191];
        bytes.extend_from_slice(b"READYX");
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, []).unwrap();

        for pattern in ["READY$|NEVER", r"READY\b|NEVER", "READY(?:$|NEVER)"] {
            let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
            let regex = WatchRegex::new(pattern).unwrap();
            assert!(
                outputs.scan(&regex).unwrap().matched.is_none(),
                "{pattern} must not treat the read-window edge as end of output"
            );
        }

        let mut bytes = b"NEVER".to_vec();
        bytes.extend(vec![b'x'; 8192]);
        fs::write(&stdout, bytes).unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        assert_eq!(
            outputs
                .scan(&WatchRegex::new("READY$|NEVER").unwrap())
                .unwrap()
                .matched
                .unwrap()
                .stream,
            "stdout",
            "the stable alternative must still match while output continues"
        );
    }

    #[test]
    fn unanchored_greedy_match_survives_the_artificial_context_end() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let mut bytes = b"READY".to_vec();
        bytes.extend(vec![b'x'; WINDOW + 4096]);
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, []).unwrap();

        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let observation = outputs
            .scan(&WatchRegex::new("READY.*").unwrap())
            .unwrap()
            .matched
            .expect("an unanchored match does not depend on the file end");
        assert_eq!(observation.stream, "stdout");
        assert!(
            outputs.match_context[0]
                .as_ref()
                .unwrap()
                .starts_with(b"READY")
        );
    }

    #[test]
    fn stable_alternative_inside_repetition_survives_large_output() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let mut bytes = b"READY".to_vec();
        bytes.extend(vec![b'x'; WINDOW + 4096]);
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, []).unwrap();

        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let regex = WatchRegex::new(r"(?:READY.*|READY$)+").unwrap();
        assert_eq!(
            outputs.scan(&regex).unwrap().matched.unwrap().stream,
            "stdout"
        );
    }

    #[test]
    fn byte_regex_accepts_invalid_utf8_in_live_output() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let mut bytes = vec![0xff];
        bytes.extend(vec![b'x'; 8192]);
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, []).unwrap();

        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let regex = WatchRegex::new(r"(?-u:\xFF)").unwrap();
        assert_eq!(
            outputs.scan(&regex).unwrap().matched.unwrap().stream,
            "stdout"
        );
    }

    #[test]
    fn unicode_word_boundaries_follow_byte_regex_semantics() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let regex = WatchRegex::new(r"\bREADY\b").unwrap();

        for (output, expected) in [("é READY", true), ("READYé", false)] {
            fs::write(&stdout, output.as_bytes()).unwrap();
            fs::write(&stderr, []).unwrap();
            let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
            outputs.limit_to(outputs.snapshot_lengths().unwrap());
            assert_eq!(
                outputs.scan(&regex).unwrap().matched.is_some(),
                expected,
                "unexpected Unicode word-boundary result for {output:?}"
            );
        }
    }

    #[test]
    fn regex_match_at_window_rollover_keeps_the_full_one_mib_span() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let mut bytes = vec![b'x'; WINDOW];
        bytes[1] = b'a';
        fs::write(&stdout, &bytes).unwrap();
        fs::write(&stderr, []).unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let regex = WatchRegex::new("a.*b").unwrap();
        for _ in 0..(WINDOW / 8192) {
            assert!(outputs.scan(&regex).unwrap().matched.is_none());
        }
        let mut file = OpenOptions::new().append(true).open(&stdout).unwrap();
        file.write_all(b"b").unwrap();
        assert_eq!(
            outputs.scan(&regex).unwrap().matched.unwrap().stream,
            "stdout"
        );
        assert_eq!(outputs.match_context[0].as_ref().unwrap().len(), WINDOW + 1);
    }

    #[test]
    fn rolling_window_does_not_turn_its_start_into_a_file_start() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        for prefix_len in [WINDOW, WINDOW - 4] {
            let mut bytes = vec![b'x'; prefix_len];
            bytes.extend_from_slice(b"READY");
            bytes.extend(vec![b'x'; WINDOW + 8192]);
            fs::write(&stdout, &bytes).unwrap();
            fs::write(&stderr, []).unwrap();

            for pattern in ["^READY", r"\AREADY", "(?m)^READY"] {
                let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
                let regex = WatchRegex::new(pattern).unwrap();
                for _ in 0..bytes.len().div_ceil(8192) {
                    assert!(
                        outputs.scan(&regex).unwrap().matched.is_none(),
                        "{pattern} must not treat a rolling-window boundary as an anchor"
                    );
                }
            }
        }

        let mut bytes = vec![b'x'; WINDOW - 1];
        bytes.extend_from_slice(b"\nREADY");
        bytes.extend(vec![b'x'; WINDOW + 8192]);
        fs::write(&stdout, &bytes).unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let regex = WatchRegex::new("(?m)^READY").unwrap();
        let mut matched = None;
        for _ in 0..bytes.len().div_ceil(8192) {
            matched = outputs.scan(&regex).unwrap().matched;
            if matched.is_some() {
                break;
            }
        }
        assert_eq!(
            matched.unwrap().stream,
            "stdout",
            "a real line start at the rolling-window edge must still match"
        );

        fs::write(&stdout, b"READY followed by output").unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        assert!(
            outputs
                .scan(&WatchRegex::new("^READY").unwrap())
                .unwrap()
                .matched
                .is_some()
        );
    }

    #[test]
    fn unicode_word_boundaries_keep_the_complete_preceding_codepoint() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let pattern = r"\bREADY\b";
        let native = Regex::new(pattern).unwrap();

        for character in ["é", "中", "𐐀"] {
            let mut bytes = vec![b'x'; WINDOW - character.len()];
            bytes.extend_from_slice(character.as_bytes());
            bytes.extend_from_slice(b"READY ");
            bytes.resize(WINDOW * 2, b'x');
            assert!(
                !native.is_match(&bytes),
                "native regex matched {character:?}"
            );
            fs::write(&stdout, &bytes).unwrap();
            fs::write(&stderr, []).unwrap();

            let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
            let regex = WatchRegex::new(pattern).unwrap();
            for _ in 0..bytes.len().div_ceil(8192) {
                assert!(
                    outputs.scan(&regex).unwrap().matched.is_none(),
                    "window rollover changed the native Unicode boundary for {character:?}"
                );
            }
        }
    }

    #[test]
    fn rolling_context_preserves_crlf_anchor_semantics() {
        let pattern = r"(?m)^READY\r?$";
        let native = Regex::new(pattern).unwrap();
        let watch = WatchRegex::new(pattern).unwrap();

        let mut bytes = vec![b'x'; WINDOW - 2];
        bytes.extend_from_slice(b"\r\nREADY\r\n");
        bytes.resize(WINDOW * 2, b'x');
        assert!(native.is_match(&bytes));

        let mut window = Vec::new();
        let mut preceding = Vec::new();
        for chunk in bytes.chunks(8192) {
            append_scanned_window(&mut window, chunk, &mut preceding);
        }
        let search_start = preceding.len();
        let mut rolled_context = preceding;
        rolled_context.extend_from_slice(&window);
        assert_eq!(
            watch.complete.is_match(&rolled_context),
            native.is_match(&bytes)
        );
        assert!(watch.has_stable_match(&rolled_context, false, search_start, false));

        let mut lone_cr = vec![b'x'; WINDOW - 1];
        lone_cr.extend_from_slice(b"\rREADY\r\n");
        lone_cr.resize(WINDOW * 2, b'x');
        assert!(!native.is_match(&lone_cr));
        let mut window = Vec::new();
        let mut preceding = Vec::new();
        for chunk in lone_cr.chunks(8192) {
            append_scanned_window(&mut window, chunk, &mut preceding);
        }
        let search_start = preceding.len();
        let mut rolled_context = preceding;
        rolled_context.extend_from_slice(&window);
        assert_eq!(
            watch.complete.is_match(&rolled_context),
            native.is_match(&lone_cr)
        );
        assert!(!watch.has_stable_match(&rolled_context, false, search_start, false));
    }

    #[test]
    fn process_group_with_only_zombies_is_not_live() {
        let mut child = Command::new("sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if process_start_ticks(child.id()).is_some_and(|(_, alive)| !alive) {
                break;
            }
            assert!(Instant::now() < deadline, "child did not become a zombie");
            thread::yield_now();
        }
        assert!(!process_group_alive(child.id()));
        child.wait().unwrap();
    }

    #[test]
    fn concurrent_initializers_serialize_schema_migration() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE process_watches (
              subscription_id TEXT PRIMARY KEY,state TEXT NOT NULL,
              supervisor_pid INTEGER NOT NULL,supervisor_start TEXT NOT NULL,
              child_pid INTEGER,child_start TEXT,started_at_ms INTEGER,
              deadline_at_ms INTEGER,regex TEXT NOT NULL,stdout_path TEXT NOT NULL,
              stderr_path TEXT NOT NULL,selection_json TEXT,selected_at_ms INTEGER,
              exit_code INTEGER,exit_success INTEGER,diagnostic TEXT)",
        )
        .unwrap();
        drop(db);
        let barrier = Arc::new(Barrier::new(2));
        let threads = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let db = Connection::open(path).unwrap();
                    db.busy_timeout(Duration::from_secs(3)).unwrap();
                    barrier.wait();
                    initialize(&db)
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let db = Connection::open(path).unwrap();
        let columns = {
            let mut statement = db.prepare("PRAGMA table_info(process_watches)").unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        for column in [
            "claim_token",
            "match_context",
            "retention_state",
            "retention_diagnostic",
        ] {
            assert!(columns.iter().any(|found| found == column));
        }
    }

    #[test]
    fn full_scheduler_requires_manual_repair_for_legacy_retention_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE process_watches (
              subscription_id TEXT PRIMARY KEY,state TEXT NOT NULL,
              supervisor_pid INTEGER NOT NULL,supervisor_start TEXT NOT NULL,
              child_pid INTEGER,child_start TEXT,started_at_ms INTEGER,
              deadline_at_ms INTEGER,regex TEXT NOT NULL,stdout_path TEXT NOT NULL,
              stderr_path TEXT NOT NULL,selection_json TEXT,selected_at_ms INTEGER,
              exit_code INTEGER,exit_success INTEGER,diagnostic TEXT);
             INSERT INTO process_watches
               (subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path,selection_json,diagnostic)
             VALUES
               ('legacy-retention','retention_error',4294967295,'dead-owner','x','/tmp/out','/tmp/err','{}','old failure');",
        )
        .unwrap();

        initialize(&db).unwrap();
        let state: (String, String) = db
            .query_row(
                "SELECT state,retention_state FROM process_watches WHERE subscription_id='legacy-retention'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, ("selected".into(), "error".into()));
        assert!(
            stale_supervisors_with_attention(&db, false)
                .unwrap()
                .contains(&"legacy-retention".to_owned()),
            "the migrated record is selected for the scheduler's identity check"
        );

        let report = schedule_stale_auto(&db, &path).unwrap();
        assert!(report["scheduled"].as_array().unwrap().is_empty());
        assert_eq!(report["errors"][0]["subscription_id"], "legacy-retention");
        let (state, retention, diagnostic): (String, String, String) = db
            .query_row(
                "SELECT state,retention_state,diagnostic FROM process_watches WHERE subscription_id='legacy-retention'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "needs_attention");
        assert_eq!(retention, "failed");
        assert!(diagnostic.contains("PID namespace"));
        assert!(
            !stale_supervisors_with_attention(&db, false)
                .unwrap()
                .contains(&"legacy-retention".to_owned()),
            "automatic retries stop until the unverifiable legacy identity is repaired"
        );
    }

    #[test]
    fn process_exit_drains_the_final_output_snapshot_before_selecting_exit() {
        let (_dir, db, id) = setup(false);
        let result = run(
            &db,
            &id,
            "NEEDLE",
            Duration::from_secs(3),
            &cmd("sleep .1; head -c 131072 /dev/zero; printf NEEDLE".into()),
        )
        .unwrap();
        assert_eq!(result["reason"], "match");
    }

    #[test]
    fn live_timeout_with_unread_log_blocks_is_ambiguous() {
        let (_dir, db, id) = setup(false);
        let marker = std::env::temp_dir().join(format!("wake-watch-{}", Uuid::new_v4()));
        let result = run(
            &db,
            &id,
            "NEEDLE",
            Duration::from_millis(80),
            &cmd(format!(
                "head -c 8388608 /dev/zero; sleep .15; touch '{}'",
                marker.display()
            )),
        )
        .unwrap();
        assert!(matches!(
            result["reason"].as_str(),
            Some("observation_ambiguous" | "timeout")
        ));
        let deadline = Instant::now() + Duration::from_secs(3);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "timeout selection must not stop the child");
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn unread_log_at_deadline_keeps_match_as_a_possible_event() {
        let dir = tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        let mut bytes = vec![b'x'; 32 * 1024];
        bytes.extend_from_slice(b"NEEDLE");
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, []).unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        assert!(
            outputs
                .scan(&WatchRegex::new("NEEDLE").unwrap())
                .unwrap()
                .matched
                .is_none()
        );

        let selected = deadline_selection(&mut outputs, epoch_ms().unwrap(), false, false).unwrap();
        assert_eq!(selected.reason, "observation_ambiguous");
        assert_eq!(
            selected.candidates,
            Some(vec!["match".into(), "timeout".into()])
        );
    }

    #[test]
    fn late_match_with_other_unread_blocks_is_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        fs::write(
            &stdout,
            b"NEEDLE"
                .iter()
                .copied()
                .chain(vec![b'x'; 32 * 1024])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        fs::write(&stderr, []).unwrap();
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let scan = outputs.scan(&WatchRegex::new("NEEDLE").unwrap()).unwrap();
        let observation = scan.matched.unwrap();
        let selected = observed_match_selection(
            observation.stream,
            observation.observed_at + Duration::from_millis(1),
            observation.observed_at_ms,
            Instant::now(),
            observation.observed_at_ms.saturating_sub(1),
            false,
        )
        .unwrap();
        assert_eq!(selected.reason, "observation_ambiguous");
        assert_eq!(selected.stream.as_deref(), Some("stdout"));
        assert_eq!(
            selected.candidates,
            Some(vec!["match".into(), "timeout".into()])
        );
    }

    #[test]
    fn exit_before_deadline_but_observed_after_remains_ambiguous() {
        let (_dir, db, id) = setup(false);
        let child = Command::new("sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let start = process_identity(pid).unwrap().0;
        let started_at_ms = epoch_ms().unwrap();
        let deadline = Instant::now() + Duration::from_millis(500);
        let deadline_at_ms = started_at_ms + 500;
        loop {
            if process_identity(pid).is_some_and(|(_, alive)| !alive) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exit before deadline"
            );
            thread::sleep(Duration::from_millis(2));
        }
        assert!(Instant::now() < deadline);
        thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
        );

        let paths = output_paths(&db, &id).unwrap();
        write_identity(
            &paths.stdout,
            &ChildIdentity {
                pid,
                start: start.clone(),
                started_at_ms,
                deadline_at_ms,
                stdout_file: Some(paths.identities[0]),
                stderr_file: Some(paths.identities[1]),
            },
        )
        .unwrap();
        drop(paths.writers);
        let supervisor_start = process_identity(std::process::id()).unwrap().0;
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path)
             VALUES(?1,'watching',?2,?3,?4,?5,?6,?7,'NEEDLE',?8,?9)",
            params![
                id,
                std::process::id(),
                supervisor_start,
                pid,
                start,
                started_at_ms,
                deadline_at_ms,
                paths.stdout.display().to_string(),
                paths.stderr.display().to_string()
            ],
        )
        .unwrap();
        let outputs = OutputTail::open(&paths.stdout, &paths.stderr).unwrap();
        let regex = WatchRegex::new("NEEDLE").unwrap();
        let result = monitor(
            MonitorContext {
                db: &db,
                id: &id,
                regex: &regex,
                child_pid: pid,
                child_start: &start,
                deadline,
                deadline_at_ms,
                recovered: false,
                stdout: &paths.stdout,
                stderr: &paths.stderr,
            },
            outputs,
            Some(child),
        )
        .unwrap();
        assert_eq!(result["reason"], "observation_ambiguous");
        assert_eq!(
            stored_selection(&db, &id)["candidates"],
            json!(["timeout", "process_exit"])
        );
    }

    #[test]
    fn draining_after_deadline_does_not_restore_timeout_after_early_exit() {
        let deadline = Instant::now();
        let exit_observed_at = deadline - Duration::from_millis(10);
        let drain_finished_at = deadline + Duration::from_millis(10);
        assert!(drain_finished_at >= deadline);
        assert_eq!(
            exit_drain_candidates(exit_observed_at, deadline),
            ["match", "process_exit"]
        );
        assert_eq!(
            exit_drain_candidates(deadline, deadline),
            ["match", "process_exit", "timeout"]
        );
    }

    #[test]
    fn ambiguous_observed_match_persists_stream_and_context_before_truncation() {
        let (_dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        let stdout = paths.stdout.clone();
        let stderr = paths.stderr.clone();
        let bytes = b"prefix NEEDLE suffix";
        fs::write(&stdout, bytes).unwrap();
        let [stdout_identity, stderr_identity] = paths.identities;
        let mut outputs = OutputTail::open(&stdout, &stderr).unwrap();
        let observation = outputs
            .scan(&WatchRegex::new("NEEDLE").unwrap())
            .unwrap()
            .matched
            .unwrap();
        let selected = observed_match_selection(
            observation.stream,
            observation.observed_at,
            observation.observed_at_ms,
            observation.observed_at,
            observation.observed_at_ms - 1,
            false,
        )
        .unwrap();

        let mut exited = Command::new("true").process_group(0).spawn().unwrap();
        let child_pid = exited.id();
        let child_start = process_identity(child_pid).unwrap().0;
        exited.wait().unwrap();
        write_identity(
            &stdout,
            &ChildIdentity {
                pid: child_pid,
                start: child_start.clone(),
                started_at_ms: epoch_ms().unwrap(),
                deadline_at_ms: epoch_ms().unwrap() + 1000,
                stdout_file: Some(stdout_identity),
                stderr_file: Some(stderr_identity),
            },
        )
        .unwrap();
        let (supervisor_pid, supervisor_start) = current_identity().unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,regex,stdout_path,stderr_path) VALUES(?1,'watching',?2,?3,?4,?5,'NEEDLE',?6,?7)",
            params![id, supervisor_pid, supervisor_start, child_pid, child_start, stdout.display().to_string(), stderr.display().to_string()],
        )
        .unwrap();

        finish(
            &db,
            selected,
            FinishContext {
                id: &id,
                pid: child_pid,
                stdout: &stdout,
                stderr: &stderr,
                outputs: Some(&outputs),
                child: None,
            },
        )
        .unwrap();

        let (selection, context): (String, Vec<u8>) = db
            .query_row(
                "SELECT selection_json,match_context FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let selection: Value = serde_json::from_str(&selection).unwrap();
        assert_eq!(selection["reason"], "observation_ambiguous");
        assert_eq!(selection["stream"], "stdout");
        assert_eq!(context, bytes);
        assert_eq!(fs::read(match_context_path(&stdout)).unwrap(), bytes);
        assert_eq!(fs::read(&stdout).unwrap(), b"");
    }

    #[test]
    fn recovery_separates_delivery_from_retention_and_keeps_attention_with_live_child() {
        let (_dir, db, _) = setup(false);
        let owner = stale_owner();
        for (id, retention) in [
            ("published-complete", "complete"),
            ("published-active", "active"),
            ("published-failed", "failed"),
        ] {
            db.execute(
                "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path,selection_json,retention_state)
                 VALUES(?1,'published',4294967295,?2,'x','/tmp/out','/tmp/err','{}',?3)",
                params![id, owner, retention],
            )
            .unwrap();
        }
        let child_pid = std::process::id();
        let child_start = process_identity(child_pid).unwrap().0;
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES('attention-live-child','needs_attention',4294967295,?1,?2,?3,'x','/tmp/out','/tmp/err','{}','complete')",
            params![owner, child_pid, child_start],
        )
        .unwrap();

        let recoverable = stale_supervisors_with_attention(&db, false).unwrap();
        assert!(recoverable.contains(&"published-active".to_owned()));
        assert!(recoverable.contains(&"attention-live-child".to_owned()));
        assert!(!recoverable.contains(&"published-complete".to_owned()));
        assert!(!recoverable.contains(&"published-failed".to_owned()));
        assert!(
            stale_supervisors_with_attention(&db, true)
                .unwrap()
                .contains(&"published-failed".to_owned())
        );

        take_over(&db, "attention-live-child").unwrap();
        let states: (String, String) = db
            .query_row(
                "SELECT state,retention_state FROM process_watches WHERE subscription_id='attention-live-child'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(states, ("selected".into(), "active".into()));
    }

    #[test]
    fn reaper_completion_does_not_change_delivery_state() {
        let (dir, db, id) = setup(false);
        let (supervisor_pid, supervisor_start) = current_identity().unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'selected',?2,?3,'x','/tmp/out','/tmp/err','{}','active')",
            params![id, supervisor_pid, supervisor_start],
        )
        .unwrap();

        mark_reaper_complete(&dir.path().join("watch.sqlite"), &id).unwrap();

        let states: (String, String) = db
            .query_row(
                "SELECT state,retention_state FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(states, ("selected".into(), "complete".into()));
    }

    #[test]
    fn reaper_retries_completion_after_transient_sqlite_busy() {
        let (dir, db, id) = setup(false);
        let database = dir.path().join("watch.sqlite");
        let paths = output_paths(&db, &id).unwrap();
        let stdout = paths.stdout.clone();
        let stderr = paths.stderr.clone();
        let identities = paths.identities;
        drop(paths);
        fs::write(&stdout, b"READY").unwrap();
        let child = Command::new("sh")
            .args(["-c", "sleep .1"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let child_start = process_identity(pid).unwrap().0;
        let started_at_ms = epoch_ms().unwrap();
        let selected = selection("match", Some("stdout"), started_at_ms, None, false, None);
        write_identity(
            &stdout,
            &ChildIdentity {
                pid,
                start: child_start.clone(),
                started_at_ms,
                deadline_at_ms: started_at_ms + 10_000,
                stdout_file: Some(identities[0]),
                stderr_file: Some(identities[1]),
            },
        )
        .unwrap();
        let (supervisor_pid, supervisor_start) = current_identity().unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'needs_attention',?2,?3,?4,?5,'READY',?6,?7,?8,'active')",
            params![
                id,
                supervisor_pid,
                supervisor_start,
                pid,
                child_start,
                stdout.display().to_string(),
                stderr.display().to_string(),
                serde_json::to_string(&selected).unwrap(),
            ],
        )
        .unwrap();
        let metadata = fs::metadata(&database).unwrap();
        let context = ReaperContext {
            database: database.clone(),
            database_identity: FileIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            id: id.clone(),
            pid,
            child_start,
            stdout,
            stderr,
            selected,
            match_context: None,
            child: Some(child),
        };

        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(mark_reaper_complete(&database, &id).is_err());
        let reaper = thread::spawn(move || reap_until_child_exit(context));
        thread::sleep(Duration::from_millis(600));
        db.execute_batch("COMMIT").unwrap();

        let observer = Connection::open(&database).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let retention: String = observer
                .query_row(
                    "SELECT retention_state FROM process_watches WHERE subscription_id=?1",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            if retention == "complete" {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "reaper did not retry completion after SQLite became available (state={retention})"
            );
            thread::sleep(Duration::from_millis(20));
        }
        reaper.join().unwrap();
    }

    #[test]
    fn recovered_live_timeout_does_not_skip_unread_blocks() {
        let (dir, db, id) = setup(false);
        let started = dir.path().join("recovery-child-started");
        let release = dir.path().join("release-recovery-child");
        let child = Command::new("timeout")
            .args([
                "--signal=KILL",
                "60s",
                "sh",
                "-c",
                &format!(
                    "touch '{}'; while [ ! -e '{}' ]; do sleep 1; done",
                    started.display(),
                    release.display()
                ),
            ])
            .process_group(0)
            .spawn()
            .unwrap();
        let mut child = ReapChildOnDrop {
            child,
            release: release.clone(),
            reaped: false,
        };
        let pid = child.id();
        let (child_start, alive) = process_identity(pid).unwrap();
        assert!(alive);
        let start_deadline = Instant::now() + Duration::from_secs(2);
        while !started.exists() && Instant::now() < start_deadline {
            thread::sleep(Duration::from_millis(100));
        }
        assert!(started.exists(), "recovery child did not start");
        let stdout = dir.path().join("recovered.stdout");
        let stderr = dir.path().join("recovered.stderr");
        fs::write(&stdout, vec![b'x'; 64 * 1024]).unwrap();
        fs::write(&stderr, []).unwrap();
        let stdout_identity =
            file_identity(&open_regular_nofollow(&stdout, true, false).unwrap()).unwrap();
        let stderr_identity =
            file_identity(&open_regular_nofollow(&stderr, true, false).unwrap()).unwrap();
        let deadline_at_ms = epoch_ms().unwrap() - 1;
        write_identity(
            &stdout,
            &ChildIdentity {
                pid,
                start: child_start.clone(),
                started_at_ms: deadline_at_ms - 1000,
                deadline_at_ms,
                stdout_file: Some(stdout_identity),
                stderr_file: Some(stderr_identity),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path) VALUES(?1,'watching',?2,?3,?4,?5,?6,?7,'NEEDLE',?8,?9)",
            params![id, u32::MAX, stale_owner(), pid, child_start, deadline_at_ms - 1000, deadline_at_ms, stdout.display().to_string(), stderr.display().to_string()],
        )
        .unwrap();

        let database = database_path(&db).unwrap();
        let worker_id = id.clone();
        let resume = thread::spawn(move || {
            let resume_db = Connection::open(database).unwrap();
            resume_db.busy_timeout(Duration::from_secs(2)).unwrap();
            resume_started(&resume_db, &worker_id, |_, _, _| {})
        });
        let observer = Connection::open(database_path(&db).unwrap()).unwrap();
        let selection_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let selected: Option<String> = retry_busy(|| {
                Ok(observer.query_row(
                    "SELECT selection_json FROM process_watches WHERE subscription_id=?1",
                    [&id],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
            if selected.is_some() {
                assert_eq!(
                    retry_busy(|| Ok(stored_selection(&observer, &id))).unwrap()["candidates"],
                    json!(["match", "timeout"])
                );
                break;
            }
            assert!(
                Instant::now() < selection_deadline,
                "recovery did not persist a selection while the child remained alive"
            );
            thread::sleep(Duration::from_millis(100));
        }
        fs::write(&release, []).unwrap();
        let result = resume.join().unwrap().unwrap();
        assert_eq!(result["reason"], "recovery_ambiguous");
        assert_eq!(
            stored_selection(&db, &id)["candidates"],
            json!(["match", "timeout"])
        );
        assert_eq!(state(&db, &id), "ready");
        child.wait().unwrap();
    }

    #[test]
    fn recovered_dead_child_with_no_unread_bytes_does_not_offer_match() {
        let (_dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        let child_start = process_identity(pid).unwrap().0;
        child.wait().unwrap();
        let deadline_at_ms = epoch_ms().unwrap() - 1;
        let started_at_ms = deadline_at_ms - 1000;
        write_identity(
            &paths.stdout,
            &ChildIdentity {
                pid,
                start: child_start.clone(),
                started_at_ms,
                deadline_at_ms,
                stdout_file: Some(paths.identities[0]),
                stderr_file: Some(paths.identities[1]),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path)
             VALUES(?1,'watching',?2,?3,?4,?5,?6,?7,'NEEDLE',?8,?9)",
            params![id, u32::MAX, stale_owner(), pid, child_start, started_at_ms, deadline_at_ms, paths.stdout.display().to_string(), paths.stderr.display().to_string()],
        )
        .unwrap();

        let result = resume_started(&db, &id, |_, _, _| {}).unwrap();
        assert_eq!(result["reason"], "recovery_ambiguous");
        assert_eq!(
            stored_selection(&db, &id)["candidates"],
            json!(["timeout", "process_exit"])
        );
    }

    #[test]
    fn recovered_dead_child_keeps_final_end_anchor_match_after_expired_deadline() {
        let (_dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        fs::write(&paths.stdout, b"READY").unwrap();
        let mut child = Command::new("true").process_group(0).spawn().unwrap();
        let pid = child.id();
        let child_start = process_identity(pid).unwrap().0;
        child.wait().unwrap();
        let deadline_at_ms = epoch_ms().unwrap() - 1;
        let started_at_ms = deadline_at_ms - 1000;
        write_identity(
            &paths.stdout,
            &ChildIdentity {
                pid,
                start: child_start.clone(),
                started_at_ms,
                deadline_at_ms,
                stdout_file: Some(paths.identities[0]),
                stderr_file: Some(paths.identities[1]),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path)
             VALUES(?1,'watching',?2,?3,?4,?5,?6,?7,'READY$',?8,?9)",
            params![id, u32::MAX, stale_owner(), pid, child_start, started_at_ms, deadline_at_ms, paths.stdout.display().to_string(), paths.stderr.display().to_string()],
        )
        .unwrap();

        let result = resume_started(&db, &id, |_, _, _| {}).unwrap();

        assert_eq!(result["reason"], "recovery_ambiguous");
        assert_eq!(stored_selection(&db, &id)["stream"], "stdout");
        assert_eq!(
            stored_selection(&db, &id)["candidates"],
            json!(["match", "process_exit", "timeout"])
        );
        assert_eq!(
            fs::read(match_context_path(&paths.stdout)).unwrap(),
            b"READY"
        );
    }

    #[test]
    fn recovered_dead_child_matches_an_empty_final_stream() {
        let (_dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        let mut child = Command::new("true").process_group(0).spawn().unwrap();
        let pid = child.id();
        let child_start = process_identity(pid).unwrap().0;
        child.wait().unwrap();
        let started_at_ms = epoch_ms().unwrap() - 100;
        let deadline_at_ms = started_at_ms + 10_000;
        write_identity(
            &paths.stdout,
            &ChildIdentity {
                pid,
                start: child_start.clone(),
                started_at_ms,
                deadline_at_ms,
                stdout_file: Some(paths.identities[0]),
                stderr_file: Some(paths.identities[1]),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path)
             VALUES(?1,'watching',?2,?3,?4,?5,?6,?7,'^$',?8,?9)",
            params![id, u32::MAX, stale_owner(), pid, child_start, started_at_ms, deadline_at_ms, paths.stdout.display().to_string(), paths.stderr.display().to_string()],
        )
        .unwrap();

        let result = resume_started(&db, &id, |_, _, _| {}).unwrap();
        assert_eq!(result["reason"], "recovery_ambiguous");
        assert_eq!(stored_selection(&db, &id)["stream"], "stdout");
        assert_eq!(
            stored_selection(&db, &id)["candidates"],
            json!(["match", "process_exit"])
        );
        assert_eq!(fs::read(match_context_path(&paths.stdout)).unwrap(), b"");
    }

    #[test]
    fn stale_scheduler_does_not_replace_a_live_legacy_supervisor() {
        let (_dir, db, id) = setup(false);
        let pid = std::process::id();
        let (legacy_start, _) = process_start_ticks(pid).unwrap();
        let paths = output_paths(&db, &id).unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path)
             VALUES(?1,'watching',?2,?3,'x',?4,?5)",
            params![id, pid, legacy_start, paths.stdout.display().to_string(), paths.stderr.display().to_string()],
        )
        .unwrap();

        let report =
            schedule_stale_from_ids(&db, &database_path(&db).unwrap(), vec![id.clone()]).unwrap();
        assert!(report["scheduled"].as_array().unwrap().is_empty());
        let saved: (u32, String, String) = db
            .query_row(
                "SELECT supervisor_pid,supervisor_start,state FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(saved, (pid, legacy_start, "needs_attention".into()));
    }

    #[test]
    fn stale_scheduler_does_not_recover_from_a_different_pid_namespace() {
        let (_dir, db, id) = setup(false);
        let pid = u32::MAX;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let namespace = pid_namespace(std::process::id()).unwrap().saturating_add(1);
        let foreign = format!("{}:{namespace}:1", boot.trim());
        let paths = output_paths(&db, &id).unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path)
             VALUES(?1,'watching',?2,?3,'x',?4,?5)",
            params![id, pid, foreign, paths.stdout.display().to_string(), paths.stderr.display().to_string()],
        )
        .unwrap();

        let report =
            schedule_stale_from_ids(&db, &database_path(&db).unwrap(), vec![id.clone()]).unwrap();
        assert!(report["scheduled"].as_array().unwrap().is_empty());
        let saved: (u32, String, String) = db
            .query_row(
                "SELECT supervisor_pid,supervisor_start,state FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(saved, (pid, foreign, "needs_attention".into()));
    }

    #[test]
    fn corrupt_selection_is_marked_attention_and_stops_automatic_retries() {
        let (_dir, db, id) = setup(false);
        let mut paths = output_paths(&db, &id).unwrap();
        paths.writers[0]
            .write_all(b"retained after corrupt selection")
            .unwrap();
        let mut child = Command::new("sleep")
            .arg("0.15")
            .process_group(0)
            .spawn()
            .unwrap();
        let child_pid = child.id();
        let child_start = process_identity(child_pid).unwrap().0;
        let started_at_ms = epoch_ms().unwrap();
        let deadline_at_ms = started_at_ms + 10_000;
        write_identity(
            &paths.stdout,
            &ChildIdentity {
                pid: child_pid,
                start: child_start.clone(),
                started_at_ms,
                deadline_at_ms,
                stdout_file: Some(paths.identities[0]),
                stderr_file: Some(paths.identities[1]),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'selected',4294967295,?2,?3,?4,?5,?6,'READY',?7,?8,'{','active')",
            params![id, stale_owner(), child_pid, child_start, started_at_ms, deadline_at_ms, paths.stdout.display().to_string(), paths.stderr.display().to_string()],
        )
        .unwrap();

        let error = resume_started(&db, &id, |_, _, _| {}).unwrap_err();
        child.wait().unwrap();
        assert!(error.to_string().contains("selection is corrupt"));
        let (state, retention_state, diagnostic): (String, String, String) = db
            .query_row(
                "SELECT state,retention_state,diagnostic FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "needs_attention");
        assert_eq!(retention_state, "complete");
        assert!(diagnostic.contains("selection is corrupt"));
        assert!(
            fs::read(retained_output_path(&paths.stdout))
                .unwrap()
                .windows(b"retained after corrupt selection".len())
                .any(|bytes| bytes == b"retained after corrupt selection")
        );
        db.execute(
            "UPDATE process_watches SET supervisor_pid=4294967295,supervisor_start=?1 WHERE subscription_id=?2",
            params![stale_owner(), id],
        )
        .unwrap();
        assert!(!stale_supervisors(&db).unwrap().contains(&id));
    }

    #[test]
    fn corrupt_selection_starts_retention_before_a_busy_diagnostic_write() {
        let (dir, db, id) = setup(false);
        let database = dir.path().join("watch.sqlite");
        let release = dir.path().join("stop-writer");
        let _release_child_on_drop = ReleaseChildOnDrop(release.clone());
        let OutputPaths {
            stdout,
            stderr,
            writers,
            identities,
        } = output_paths(&db, &id).unwrap();
        let [stdout_writer, stderr_writer] = writers;
        let script = format!(
            "while [ ! -e '{}' ]; do head -c 65536 /dev/zero; sleep .01; done",
            release.display()
        );
        let mut child = Command::new("sh")
            .args(["-c", &script])
            .stdout(Stdio::from(stdout_writer))
            .stderr(Stdio::from(stderr_writer))
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let child_start = process_identity(pid).unwrap().0;
        let started_at_ms = epoch_ms().unwrap();
        write_identity(
            &stdout,
            &ChildIdentity {
                pid,
                start: child_start.clone(),
                started_at_ms,
                deadline_at_ms: started_at_ms + 10_000,
                stdout_file: Some(identities[0]),
                stderr_file: Some(identities[1]),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'selected',4294967295,?2,?3,?4,?5,?6,'READY',?7,?8,'{','active')",
            params![
                id,
                stale_owner(),
                pid,
                child_start,
                started_at_ms,
                started_at_ms + 10_000,
                stdout.display().to_string(),
                stderr.display().to_string(),
            ],
        )
        .unwrap();
        let watch = load_watch(&db, &id).unwrap();
        let blocker = Connection::open(&database).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

        let reaper =
            start_corrupt_selection_retention(&db, &id, &watch, pid, &child_start).unwrap();
        let diagnostic_database = database.clone();
        let diagnostic_id = id.clone();
        let diagnostic = thread::spawn(move || {
            let db = Connection::open(diagnostic_database).unwrap();
            set_diagnostic(
                &db,
                &diagnostic_id,
                "needs_attention",
                "Stored selection is corrupt",
            );
        });
        thread::sleep(Duration::from_millis(1000));
        assert!(
            !diagnostic.is_finished(),
            "the held write lock blocks the diagnostic"
        );
        let active_len = fs::metadata(&stdout).unwrap().len();
        assert!(
            active_len < (4 * WINDOW) as u64,
            "retention must already bound output while the diagnostic write is blocked (active log: {active_len} bytes)"
        );

        blocker.execute_batch("COMMIT").unwrap();
        diagnostic.join().unwrap();
        fs::write(&release, []).unwrap();
        assert!(child.wait().unwrap().success());
        reaper.join().unwrap();
        let retention: String = db
            .query_row(
                "SELECT retention_state FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retention, "complete");
    }

    #[test]
    fn reaper_database_writes_are_bounded_by_sqlite_lock_and_never_create_database() {
        let (dir, db, id) = setup(false);
        let path = dir.path().join("watch.sqlite");
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        record_reaper_state(&path, &id, "error", "test lock");
        assert!(mark_reaper_complete(&path, &id).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        db.execute_batch("ROLLBACK").unwrap();

        let missing = dir.path().join("uninstalled.sqlite");
        record_reaper_state(&missing, &id, "error", "missing database");
        assert!(mark_reaper_complete(&missing, &id).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn recovered_match_after_first_chunk_keeps_recovered_flag() {
        let (dir, db, id) = setup(false);
        let mut child = Command::new("sh")
            .args(["-c", "sleep .4"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let child_start = process_identity(pid).unwrap().0;
        let stdout = dir.path().join("recovered.stdout");
        let stderr = dir.path().join("recovered.stderr");
        let mut bytes = vec![b'x'; 8192];
        bytes.extend_from_slice(b"READY");
        fs::write(&stdout, bytes).unwrap();
        fs::write(&stderr, []).unwrap();
        let stdout_identity =
            file_identity(&open_regular_nofollow(&stdout, true, false).unwrap()).unwrap();
        let stderr_identity =
            file_identity(&open_regular_nofollow(&stderr, true, false).unwrap()).unwrap();
        let started_at_ms = epoch_ms().unwrap();
        let deadline_at_ms = started_at_ms + 5000;
        write_identity(
            &stdout,
            &ChildIdentity {
                pid,
                start: child_start.clone(),
                started_at_ms,
                deadline_at_ms,
                stdout_file: Some(stdout_identity),
                stderr_file: Some(stderr_identity),
            },
        )
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,child_pid,child_start,started_at_ms,deadline_at_ms,regex,stdout_path,stderr_path)
             VALUES(?1,'watching',?2,?3,?4,?5,?6,?7,'READY',?8,?9)",
            params![id, u32::MAX, stale_owner(), pid, child_start, started_at_ms, deadline_at_ms, stdout.display().to_string(), stderr.display().to_string()],
        )
        .unwrap();
        let waiter = thread::spawn(move || child.wait().unwrap());

        let result = resume_started(&db, &id, |_, _, _| {}).unwrap();
        assert!(matches!(
            result["reason"].as_str(),
            Some("match" | "recovery_ambiguous")
        ));
        if result["reason"] == "recovery_ambiguous" {
            assert!(
                stored_selection(&db, &id)["candidates"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|candidate| candidate == "match")
            );
        }
        assert!(result["recovered"].as_bool().unwrap());
        waiter.join().unwrap();
    }

    #[test]
    fn process_identity_includes_the_current_boot_id() {
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let pid = std::process::id();
        let (identity, alive) = process_identity(pid).unwrap();
        assert!(alive);
        assert!(identity.starts_with(&format!("{}:", boot_id.trim())));
        assert!(identity_has_current_pid_namespace(&identity));
        let (legacy_start, _) = process_start_ticks(pid).unwrap();
        assert!(legacy_identity_matches_live_process(pid, &legacy_start));
    }

    #[test]
    fn asynchronously_waited_supervisor_is_reaped() {
        let child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        reap_child(child).join().unwrap();
        assert!(process_identity(pid).is_none());
    }

    #[test]
    fn legacy_live_supervisor_is_diagnosed_instead_of_reattached() {
        let (dir, db, id) = setup(false);
        initialize(&db).unwrap();
        let pid = std::process::id();
        let (legacy_start, _) = process_start_ticks(pid).unwrap();
        let stdout = dir.path().join("legacy.stdout");
        let stderr = dir.path().join("legacy.stderr");
        fs::write(&stdout, []).unwrap();
        fs::write(&stderr, []).unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path) VALUES(?1,'watching',?2,?3,'match',?4,?5)",
            params![id, pid, legacy_start, stdout.display().to_string(), stderr.display().to_string()],
        )
        .unwrap();

        let error = resume_started(&db, &id, |_, _, _| {}).unwrap_err();
        assert!(error.to_string().contains("lacks a boot ID"));
        let (state, diagnostic): (String, String) = db
            .query_row(
                "SELECT state,diagnostic FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "needs_attention");
        assert!(diagnostic.contains("predates boot IDs"));

        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let boot_aware_legacy = format!("{}:{legacy_start}", boot.trim());
        db.execute(
            "UPDATE process_watches SET state='watching',supervisor_start=?1 WHERE subscription_id=?2",
            params![boot_aware_legacy, id],
        )
        .unwrap();
        let error = resume_started(&db, &id, |_, _, _| {}).unwrap_err();
        assert!(error.to_string().contains("PID namespace"));
        let diagnostic: String = db
            .query_row(
                "SELECT diagnostic FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(diagnostic.contains("boot ID but no PID namespace"));
    }

    #[test]
    fn timeout_does_not_stop_process_and_reaper_keeps_supervising_it() {
        let (_dir, db, id) = setup(false);
        let marker = std::env::temp_dir().join(format!("wake-watch-{}", Uuid::new_v4()));
        let result = run(
            &db,
            &id,
            "late",
            Duration::from_millis(40),
            &cmd(format!(
                "sleep .15; echo late; touch '{}'",
                marker.display()
            )),
        )
        .unwrap();
        assert!(matches!(
            result["reason"].as_str(),
            Some("timeout" | "observation_ambiguous")
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
        assert!(marker.exists(), "timeout must not stop the child");
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn generic_subscription_expiry_is_rejected_before_launch() {
        let (_dir, db, id) = setup(true);
        assert!(
            validate_new_watch_claim(&db, &id)
                .unwrap_err()
                .to_string()
                .contains("monitor owns its timeout")
        );
        let result = run(
            &db,
            &id,
            "hit",
            Duration::from_secs(1),
            &cmd("echo hit".into()),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("monitor owns its timeout")
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM process_watches", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn missing_subscription_is_rejected_before_any_watch_can_launch() {
        let (_dir, db, id) = setup(false);
        validate_new_watch_claim(&db, &id).unwrap();
        let error = validate_new_watch_claim(&db, "missing-subscription").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("No matching process-watch subscription")
        );
    }

    #[test]
    fn mcp_claim_confirmation_rejects_a_concurrent_cli_claim() {
        let (_dir, db, id) = setup(false);
        let paths = output_paths(&db, &id).unwrap();
        let expected_token = Uuid::new_v4().to_string();
        validate_new_watch_claim(&db, &id).unwrap();

        claim(&db, &id, "READY", &paths.stdout, &paths.stderr, None).unwrap();
        assert!(
            !claim_token_matches(&db, &id, &expected_token).unwrap(),
            "a CLI claim without the MCP request token cannot confirm that request"
        );
        assert!(
            claim(
                &db,
                &id,
                "READY",
                &paths.stdout,
                &paths.stderr,
                Some(&expected_token)
            )
            .is_err(),
            "the concurrent MCP supervisor must not take over the CLI claim"
        );

        db.execute(
            "DELETE FROM process_watches WHERE subscription_id=?1",
            [&id],
        )
        .unwrap();
        claim(
            &db,
            &id,
            "READY",
            &paths.stdout,
            &paths.stderr,
            Some(&expected_token),
        )
        .unwrap();
        assert!(claim_token_matches(&db, &id, &expected_token).unwrap());
    }

    #[test]
    fn busy_database_does_not_block_child_output_or_expire_selected_event() {
        let (dir, db, id) = setup(false);
        let ready = dir.path().join("ready");
        let finished = dir.path().join("finished");
        let db_path = dir.path().join("watch.sqlite");
        let lock_ready = ready.clone();
        let lock_finished = finished.clone();
        let lock_db = db_path.clone();
        let lock = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !lock_ready.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            let held = Connection::open(lock_db).unwrap();
            held.execute_batch("BEGIN IMMEDIATE").unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while !lock_finished.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            assert!(
                lock_finished.exists(),
                "the child must keep running during SQLite contention"
            );
            held.execute_batch("COMMIT").unwrap();
        });
        let result = run(
            &db,
            &id,
            "hit",
            Duration::from_secs(2),
            &cmd(format!(
                "touch '{}'; sleep .08; echo hit; sleep .08; touch '{}'",
                ready.display(),
                finished.display()
            )),
        )
        .unwrap();
        lock.join().unwrap();
        assert_eq!(result["reason"], "match");
        assert_eq!(state(&db, &id), "ready");
        let selected: String = db
            .query_row(
                "SELECT selection_json FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&selected).unwrap()["reason"],
            "match"
        );
    }

    #[test]
    fn exit_finishes_without_waiting_for_the_timeout() {
        let (_dir, db, id) = setup(false);
        let began = Instant::now();
        let result = run(
            &db,
            &id,
            "no-match",
            Duration::from_secs(5),
            &cmd("exit 7".into()),
        )
        .unwrap();
        assert_eq!(result["reason"], "exit");
        assert_eq!(result["exit_code"], 7);
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn failed_publication_keeps_selected_event_and_child_output() {
        let (dir, db, id) = setup(false);
        db.execute_batch("CREATE TRIGGER fail_watch_publish BEFORE UPDATE ON subscriptions BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        let marker = dir.path().join("child-finished");
        let result = run(
            &db,
            &id,
            "HIT",
            Duration::from_secs(2),
            &cmd(format!("echo HIT; sleep .1; touch '{}'", marker.display())),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("selection persisted")
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            marker.exists(),
            "publication failure must not stop the child"
        );
        let (selected, state): (String, String) = db
            .query_row(
                "SELECT selection_json,state FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&selected).unwrap()["reason"],
            "match"
        );
        assert_eq!(state, "publish_error");
    }

    #[test]
    fn matching_external_source_key_is_not_accepted_as_watch_publication() {
        let (_dir, db, id) = setup(false);
        let selected = selection(
            "match",
            Some("stdout"),
            epoch_ms().unwrap(),
            None,
            false,
            None,
        );
        let source = source(&id, &selected);
        let source_json = serde_json::to_string(&source).unwrap();
        let (kind, repo, resource, event): (String, String, String, String) = db
            .query_row(
                "SELECT kind,repo,resource,event FROM subscriptions WHERE id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        let source_event_key = subscriptions::source_event_identity(
            &kind,
            &repo,
            &resource,
            &event,
            "completed",
            &source,
        )
        .unwrap()
        .unwrap();
        db.execute(
            "INSERT INTO process_watches(subscription_id,state,supervisor_pid,supervisor_start,regex,stdout_path,stderr_path,selection_json,retention_state)
             VALUES(?1,'selected',4294967295,'stale:0','READY','/tmp/out','/tmp/err',?2,'active')",
            params![id, serde_json::to_string(&selected).unwrap()],
        )
        .unwrap();

        // Model a regular publisher accepting an event with the exact same
        // source key and payload. It did not pass publish_observation's
        // process-watch verification, so the marker must remain false.
        db.execute(
            "UPDATE subscriptions SET state='ready',outcome='completed',source_event_key=?1,source_json=?2,process_watch_verified=0 WHERE id=?3",
            params![source_event_key, source_json, id],
        )
        .unwrap();

        assert!(!publish_selection(&db, &id, &selected).unwrap());
        let (watch_state, diagnostic): (String, String) = db
            .query_row(
                "SELECT state,diagnostic FROM process_watches WHERE subscription_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let verified: bool = db
            .query_row(
                "SELECT process_watch_verified FROM subscriptions WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!verified);
        assert_eq!(watch_state, "needs_attention");
        assert!(diagnostic.contains("no verified process-watch publication"));
    }

    #[test]
    fn environment_file_is_private_and_keeps_secrets_out_of_unit_arguments() -> Result<()> {
        let dir = tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let unit = "codex-wake-watch-test.service";
        let secret = "secret-${HOME}-\"quoted\"-\\slash\nnext";
        let environment =
            BTreeMap::from([(OsString::from("CODEX_WAKE_TEST_SECRET"), secret.into())]);
        let file = write_systemd_environment_file(&environment, dir.path(), unit)?;
        assert_eq!(file.as_file().metadata()?.mode() & 0o777, 0o600);
        assert_eq!(
            fs::read_to_string(file.path())?,
            "CODEX_WAKE_TEST_SECRET=\"secret-\\${HOME}-\\\"quoted\\\"-\\\\slash\nnext\"\n"
        );
        let argument = environment_file_argument(file.path())?;
        let argument = argument.to_string_lossy();
        assert!(argument.contains(file.path().to_str().unwrap()));
        assert!(!argument.contains("secret-"));
        assert!(!argument.starts_with("--setenv="));
        Ok(())
    }

    #[test]
    fn environment_file_argument_preserves_percent_specifiers_verbatim() {
        let path = Path::new("/var/tmp/process-watch-%n-environment");
        assert_eq!(
            environment_file_argument(path).unwrap(),
            OsString::from("--property=EnvironmentFile=/var/tmp/process-watch-%n-environment")
        );
    }

    #[test]
    fn expansion_option_detection_rejects_systemd_before_254() {
        assert!(supports_disabled_environment_expansion(
            "--expand-environment=BOOL Control expansion"
        ));
        assert!(!supports_disabled_environment_expansion(
            "--property=NAME=VALUE Set a unit property"
        ));
    }

    #[test]
    fn uncertain_start_waits_for_active_or_terminal_unit_state() {
        let activating = ExistingUnit {
            active_state: "activating".into(),
            description: "expected".into(),
            pid: None,
        };
        let active = ExistingUnit {
            active_state: "active".into(),
            description: "expected".into(),
            pid: Some(123),
        };
        let mut states = [Some(activating.clone()), Some(active)];
        assert_eq!(
            resolve_unit_start("unit", "expected", Duration::from_secs(1), |_| {
                Ok(states[0].take().or_else(|| states[1].clone()))
            }),
            LaunchResolution::Started(Some(123))
        );
        assert_eq!(
            resolve_unit_start("unit", "expected", Duration::ZERO, |_| {
                Ok(Some(activating.clone()))
            }),
            LaunchResolution::Uncertain
        );
    }

    #[test]
    fn uncertain_systemd_start_keeps_environment_file_until_resolved() -> Result<()> {
        let dir = tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let unit = "codex-wake-watch-abc.service";
        let environment = BTreeMap::from([(OsString::from("TOKEN"), OsString::from("secret"))]);
        let file = write_systemd_environment_file(&environment, dir.path(), unit)?;
        let path = preserve_uncertain_environment_file(file)?;
        assert!(path.exists());

        let activating = ExistingUnit {
            active_state: "activating".into(),
            description: "expected".into(),
            pid: None,
        };
        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(Some(activating.clone())))?,
            0
        );
        assert!(
            path.exists(),
            "cleanup removed a file still read by systemd"
        );

        let active = ExistingUnit {
            active_state: "active".into(),
            description: "expected".into(),
            pid: Some(123),
        };
        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(Some(active.clone())))?,
            1
        );
        assert!(!path.exists(), "resolved EnvironmentFile was not cleaned");
        Ok(())
    }

    #[test]
    fn orphan_environment_file_waits_until_a_delayed_unit_is_observed() -> Result<()> {
        let dir = tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let unit = "codex-wake-resume-abc.service";
        let environment = BTreeMap::from([(OsString::from("TOKEN"), OsString::from("secret"))]);
        let file = write_systemd_environment_file(&environment, dir.path(), unit)?;
        let path = preserve_uncertain_environment_file(file)?;

        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(None))?,
            0,
            "an absent unit does not prove a timed-out StartTransientUnit was not queued"
        );
        assert!(path.exists());
        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| anyhow::bail!(
                "systemd manager unavailable"
            ))?,
            0,
            "a systemd query error must never authorize deleting the environment file"
        );
        assert!(path.exists());

        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(None))?,
            0,
            "repeated absence, however long, cannot prove the manager will not enqueue the unit later"
        );
        assert!(path.exists());

        let delayed = ExistingUnit {
            active_state: "activating".into(),
            description: "expected".into(),
            pid: None,
        };
        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(Some(delayed.clone())))?,
            0,
            "a late unit still needs its environment file while activating"
        );
        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(Some(ExistingUnit {
                active_state: "failed".into(),
                description: "expected".into(),
                pid: None,
            })))?,
            1
        );
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn launch_lock_prevents_cleanup_and_database_removal_before_unit_registration() -> Result<()> {
        let dir = tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let unit = "codex-wake-watch-preparing.service";
        let environment = BTreeMap::from([(OsString::from("TOKEN"), OsString::from("secret"))]);
        let lock = lock_environment_directory(dir.path(), false)?.unwrap();
        let file = write_systemd_environment_file(&environment, dir.path(), unit)?;
        let path = preserve_uncertain_environment_file(file)?;
        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(None))?,
            0,
            "cleanup must skip a live launcher even when the unit is not registered"
        );
        assert!(
            external_database_removal_guard_in(dir.path(), |_| Ok(None)).is_err(),
            "uninstall must not pass a live launcher's directory lock"
        );
        assert!(path.exists());

        let mut helper = Command::new("/bin/sh");
        helper.args(["-c", "sleep 0.15"]);
        inherit_environment_lock(&mut helper, &lock);
        let mut helper = helper.spawn()?;
        drop(lock);
        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(None))?,
            0,
            "the systemd-run client must keep the lock if its parent is killed"
        );
        ensure!(
            helper.wait_timeout(Duration::from_secs(3))?.is_some(),
            "lock-holder probe did not exit"
        );

        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(None))?,
            0,
            "an absent unit remains unresolved after the launcher exits"
        );
        assert!(path.exists());
        assert_eq!(
            cleanup_environment_directory(dir.path(), |_| Ok(Some(ExistingUnit {
                active_state: "inactive".into(),
                description: "expected".into(),
                pid: None,
            })))?,
            1,
            "a manager-observed terminal unit resolves the environment-file lifetime"
        );
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn external_database_removal_waits_for_uncertain_environment_file() -> Result<()> {
        let dir = tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let database = dir.path().join("external.sqlite");
        let db = Connection::open(&database)?;
        db.pragma_update(None, "application_id", crate::uninstall::DATABASE_ID)?;
        drop(db);
        let environment_directory = dir.path().join("process-watch");
        fs::create_dir(&environment_directory)?;
        fs::set_permissions(&environment_directory, fs::Permissions::from_mode(0o700))?;
        let unit = "codex-wake-watch-uninstall.service";
        let environment = BTreeMap::from([(OsString::from("TOKEN"), OsString::from("secret"))]);
        let file = write_systemd_environment_file(&environment, &environment_directory, unit)?;
        let path = preserve_uncertain_environment_file(file)?;
        let absent_error =
            external_database_removal_guard_in(&environment_directory, |_| Ok(None)).unwrap_err();
        assert!(absent_error.to_string().contains("unresolved"));
        assert!(database.exists());
        assert!(path.exists());
        let activating = ExistingUnit {
            active_state: "activating".into(),
            description: "expected".into(),
            pid: None,
        };

        let guard_error = external_database_removal_guard_in(&environment_directory, |_| {
            Ok(Some(activating.clone()))
        })
        .unwrap_err();
        assert!(guard_error.to_string().contains("unresolved"));
        let query_error = external_database_removal_guard_in(&environment_directory, |_| {
            anyhow::bail!("systemd manager unavailable")
        })
        .unwrap_err();
        assert!(query_error.to_string().contains("unresolved"));
        let error = crate::uninstall::remove_external_database(&database).unwrap_err();
        assert!(error.to_string().contains("unresolved"), "{error}");
        assert!(database.exists());
        assert!(path.exists());

        let active = ExistingUnit {
            active_state: "active".into(),
            description: "expected".into(),
            pid: Some(123),
        };
        assert_eq!(
            cleanup_environment_files_in(&environment_directory, |_| Ok(Some(active.clone())))?,
            1
        );
        assert!(!path.exists());
        crate::uninstall::remove_external_database(&database)?;
        assert!(!database.exists());
        Ok(())
    }

    #[test]
    fn uninstall_removes_only_orphan_diagnostics_owned_by_that_database() -> Result<()> {
        let dir = tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let database = dir.path().join("external.sqlite");
        let db = Connection::open(&database)?;
        db.pragma_update(None, "application_id", crate::uninstall::DATABASE_ID)?;
        drop(db);
        let other_database = dir.path().join("other.sqlite");
        let other = Connection::open(&other_database)?;
        other.pragma_update(None, "application_id", 0x1234)?;
        drop(other);
        let orphan = diagnostic_path(&database, "unclaimed")?;
        let other_log = diagnostic_path(&other_database, "unclaimed")?;
        fs::write(&orphan, b"unclaimed supervisor diagnostic")?;
        fs::write(&other_log, b"other database diagnostic")?;

        crate::uninstall::remove_external_database(&database)?;

        assert!(!database.exists());
        assert!(!orphan.exists());
        assert_eq!(fs::read(other_log)?, b"other database diagnostic");
        Ok(())
    }

    #[test]
    fn transient_unit_preserves_percent_paths_for_workdir_environment_and_diagnostic() -> Result<()>
    {
        let systemctl = match crate::manager::find_program("systemctl") {
            Ok(path) => path,
            Err(_) => {
                eprintln!("skipping isolated percent-path systemd test: systemctl unavailable");
                return Ok(());
            }
        };
        if !crate::manager::run(
            Command::new(&systemctl).args(["--user", "show-environment"]),
            Duration::from_secs(5),
        )
        .is_ok_and(|output| output.status.success())
        {
            eprintln!("skipping isolated percent-path systemd test: user manager unavailable");
            return Ok(());
        }

        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(systemctl) = crate::manager::find_program("systemctl") {
                    let _ = crate::manager::run(
                        Command::new(&systemctl).args(["--user", "stop", &self.0]),
                        Duration::from_secs(10),
                    );
                    let _ = crate::manager::run(
                        Command::new(&systemctl).args(["--user", "reset-failed", &self.0]),
                        Duration::from_secs(5),
                    );
                }
            }
        }

        let dir = tempdir()?;
        let parent = dir.path().join("literal-%n-directory");
        fs::create_dir(&parent)?;
        let cwd = parent.join("work-%n");
        fs::create_dir(&cwd)?;
        let database = parent.join("state.sqlite");
        drop(Connection::open(&database)?);
        let result_path = dir.path().join("working-directory.txt");
        let environment_path = dir.path().join("environment-value.txt");
        let args = [
            OsString::from("-c"),
            OsString::from(
                "pwd > \"$1\"; printf '%s' \"$CODEX_WAKE_TEST_PERCENT\" > \"$2\"; printf diagnostic-percent >&2",
            ),
            OsString::from("percent-path-probe"),
            result_path.as_os_str().to_owned(),
            environment_path.as_os_str().to_owned(),
        ];
        let launch = launch_transient_unit_at(
            &database,
            "percent-path-probe",
            Path::new("/bin/sh"),
            &args,
            false,
            &[(
                "CODEX_WAKE_TEST_PERCENT".into(),
                "literal-environment-value".into(),
            )],
            &cwd,
        )?;
        let _cleanup = Cleanup(launch.unit);
        let diagnostic = diagnostic_path(&database, "percent-path-probe")?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while (fs::read_to_string(&result_path).ok().as_deref()
            != Some(
                cwd.to_str()
                    .context("test working directory must be UTF-8")?,
            )
            || fs::read_to_string(&environment_path).ok().as_deref()
                != Some("literal-environment-value")
            || !fs::read_to_string(&diagnostic)
                .is_ok_and(|contents| contents.contains("diagnostic-percent")))
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(result_path)?.trim_end(),
            cwd.display().to_string()
        );
        assert_eq!(
            fs::read_to_string(environment_path)?,
            "literal-environment-value"
        );
        assert_eq!(fs::read_to_string(diagnostic)?, "diagnostic-percent");
        Ok(())
    }

    #[test]
    fn transient_supervisor_and_child_survive_owner_service_stop() -> Result<()> {
        let systemctl = match crate::manager::find_program("systemctl") {
            Ok(path) => path,
            Err(_) => {
                eprintln!("skipping isolated systemd lifecycle test: systemctl unavailable");
                return Ok(());
            }
        };
        let ready = crate::manager::run(
            Command::new(&systemctl).args(["--user", "show-environment"]),
            Duration::from_secs(5),
        )
        .is_ok_and(|output| output.status.success());
        if !ready {
            eprintln!("skipping isolated systemd lifecycle test: user manager unavailable");
            return Ok(());
        }

        struct Cleanup {
            units: Vec<String>,
            children: Vec<u32>,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(systemctl) = crate::manager::find_program("systemctl") {
                    for unit in &self.units {
                        let _ = crate::manager::run(
                            Command::new(&systemctl).args(["--user", "stop", unit]),
                            Duration::from_secs(10),
                        );
                    }
                }
                for pid in &self.children {
                    unsafe {
                        libc::kill(*pid as i32, libc::SIGTERM);
                    }
                }
            }
        }

        let dir = tempdir()?;
        let database = dir.path().join("state.sqlite");
        fs::write(&database, b"isolated transient service probe")?;
        let mut cleanup = Cleanup {
            units: Vec::new(),
            children: Vec::new(),
        };
        let owner = launch_transient_unit(
            &database,
            "owner-probe",
            Path::new("/bin/sleep"),
            &[OsString::from("120")],
            false,
            &[],
        )?;
        cleanup.units.push(owner.unit.clone());

        let child_pid_file = dir.path().join("child.pid");
        let worker = launch_transient_unit(
            &database,
            "watch-probe",
            Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from("sleep 120 & echo $! > \"$1\"; wait"),
                OsString::from("watch-probe"),
                child_pid_file.as_os_str().to_owned(),
            ],
            false,
            &[(
                "CODEX_WAKE_TEST_SECRET".into(),
                "secret-never-in-argv".into(),
            )],
        )?;
        cleanup.units.push(worker.unit.clone());
        for property in ["Environment", "EnvironmentFiles"] {
            ensure!(
                !unit_property(&worker.unit, property)?.contains("secret-never-in-argv"),
                "process-watch unit exposed an environment value in {property}"
            );
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let child_pid = loop {
            if let Ok(pid) = fs::read_to_string(&child_pid_file)
                && let Ok(pid) = pid.trim().parse::<u32>()
            {
                break pid;
            }
            ensure!(Instant::now() < deadline, "watch child did not start");
            thread::sleep(Duration::from_millis(20));
        };
        cleanup.children.push(child_pid);
        assert_eq!(unit_property(&worker.unit, "KillMode")?, "process");
        let unit_cgroup = unit_property(&worker.unit, "ControlGroup")?;
        let child_cgroups = fs::read_to_string(format!("/proc/{child_pid}/cgroup"))?;
        ensure!(
            child_cgroups.lines().any(|line| {
                line.rsplit_once(':')
                    .is_some_and(|(_, path)| path == unit_cgroup)
            }),
            "watched child is outside its transient service cgroup"
        );
        ensure!(
            unit_property(&owner.unit, "ControlGroup")? != unit_cgroup,
            "owner and process-watch services unexpectedly share a cgroup"
        );

        let conflict = launch_transient_unit(
            &database,
            "watch-probe",
            Path::new("/bin/sleep"),
            &[OsString::from("120")],
            false,
            &[],
        )
        .err()
        .context("different request reused an active process-watch unit")?;
        ensure!(
            conflict
                .to_string()
                .contains("different command, working directory, or environment"),
            "unit mismatch was not diagnosed: {conflict}"
        );

        let quick_result = dir.path().join("quick-result");
        let quick = launch_transient_unit(
            &database,
            "quick-probe",
            Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from(
                    "printf '%s\\n%s\\n%s\\n%s' \"$PWD\" \"$CODEX_WAKE_TEST_VALUE\" \"$CODEX_WAKE_DB\" \"$2\" > \"$1\"",
                ),
                OsString::from("quick-probe"),
                quick_result.as_os_str().to_owned(),
                OsString::from("${CODEX_WAKE_TEST_VALUE}"),
            ],
            false,
            &[(
                "CODEX_WAKE_TEST_VALUE".into(),
                "preserved-${HOME}-\"quoted\"-\\slash\nsecond-line".into(),
            )],
        )?;
        cleanup.units.push(quick.unit);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !quick_result.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let quick_output = fs::read_to_string(quick_result)?;
        let quick_expected = format!(
            "{}\npreserved-${{HOME}}-\"quoted\"-\\slash\nsecond-line\n{}\n${{CODEX_WAKE_TEST_VALUE}}",
            env::current_dir()?.display(),
            database.display()
        );
        ensure!(
            quick_output == quick_expected,
            "transient unit changed cwd, environment, absolute database path, or literal dollar argument: {quick_output:?}"
        );

        let crashed_pid_file = dir.path().join("crashed-child.pid");
        let crashed = launch_transient_unit(
            &database,
            "crashed-supervisor-probe",
            Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from("sleep 120 & echo $! > \"$1\"; exit 1"),
                OsString::from("crashed-supervisor-probe"),
                crashed_pid_file.as_os_str().to_owned(),
            ],
            false,
            &[],
        )?;
        cleanup.units.push(crashed.unit.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        let crashed_child = loop {
            if let Ok(pid) = fs::read_to_string(&crashed_pid_file)
                && let Ok(pid) = pid.trim().parse::<u32>()
            {
                break pid;
            }
            ensure!(Instant::now() < deadline, "crash-probe child did not start");
            thread::sleep(Duration::from_millis(20));
        };
        cleanup.children.push(crashed_child);
        let deadline = Instant::now() + Duration::from_secs(5);
        while systemd_unit(&crashed.unit)?.is_some_and(|unit| unit.active_state != "failed")
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(20));
        }
        ensure!(
            process_identity(crashed_child).is_some_and(|(_, alive)| alive),
            "watch child died when its supervisor failed"
        );
        let resumed = launch_transient_unit(
            &database,
            "resume-probe",
            Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from("kill -0 \"$1\" && echo resumed > \"$2\""),
                OsString::from("resume-probe"),
                crashed_child.to_string().into(),
                dir.path().join("resumed").into_os_string(),
            ],
            true,
            &[],
        )?;
        cleanup.units.push(resumed.unit);
        let resumed_marker = dir.path().join("resumed");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !resumed_marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        ensure!(
            resumed_marker.exists(),
            "separate recovery unit could not observe the surviving child"
        );

        let stopped = crate::manager::run(
            Command::new(&systemctl).args(["--user", "stop", &owner.unit]),
            Duration::from_secs(10),
        )?;
        ensure!(
            stopped.status.success(),
            "isolated owner service did not stop"
        );
        ensure!(
            systemd_unit(&worker.unit)?.is_some_and(|unit| {
                matches!(unit.active_state.as_str(), "active" | "activating")
                    && unit.pid == worker.pid
            }) && process_identity(child_pid).is_some_and(|(_, alive)| alive),
            "process-watch service or child died when the owner service stopped"
        );
        Ok(())
    }
}
