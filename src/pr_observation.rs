//! Durable, privacy-preserving observation of PR creation tool calls.
//!
//! This module stores only a SHA-256 digest of tool_input and small identifying
//! metadata. A PostToolUse candidate is committed before GitHub is queried, so a
//! transport failure never discards it. No database writes register a PR.

use std::{path::PathBuf, process::Command, time::Duration};

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::pr_hook::{
    PrCandidate, PreToolUseObservation, VerificationOutcome, VerifiedPullRequest,
    parse_pr_candidate, verify_pr_candidate,
};

const MCP_CREATE_PR_TOOL: &str = "mcp__codex_apps__github_create_pull_request";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pr_hook_pre_observations (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    turn_id TEXT,
    tool_use_id TEXT,
    tool_name TEXT,
    input_digest TEXT,
    repository TEXT,
    head_ref TEXT,
    base_ref TEXT,
    author_login TEXT,
    gh_provenance TEXT,
    observed_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL,
    reason TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS pr_hook_pre_call_identity
    ON pr_hook_pre_observations(session_id, turn_id, tool_use_id)
    WHERE session_id IS NOT NULL AND turn_id IS NOT NULL AND tool_use_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS pr_hook_candidates (
    id INTEGER PRIMARY KEY,
    session_id TEXT,
    turn_id TEXT,
    tool_use_id TEXT,
    tool_name TEXT NOT NULL,
    input_digest TEXT,
    exact_id_correlation INTEGER NOT NULL DEFAULT 0,
    raw_creation_result INTEGER NOT NULL DEFAULT 0,
    number INTEGER NOT NULL,
    url TEXT NOT NULL,
    invocation_key TEXT NOT NULL UNIQUE,
    pre_id INTEGER,
    state TEXT NOT NULL,
    reason TEXT,
    get_status INTEGER,
    verified_json TEXT,
    consumed_at_ms INTEGER,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at_ms INTEGER,
    work_claim_until_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pr_hook_candidate_state
    ON pr_hook_candidates(state, updated_at_ms);
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreRecord {
    Ignored,
    Recorded { id: i64 },
    Duplicate { id: i64 },
    Ambiguous { id: i64, reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateState {
    Pending,
    Verified,
    Ambiguous,
    Timeout,
    TransportError,
    Inconclusive,
}

impl CandidateState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Ambiguous => "ambiguous",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
            Self::Inconclusive => "inconclusive",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "verified" => Some(Self::Verified),
            "ambiguous" => Some(Self::Ambiguous),
            "timeout" => Some(Self::Timeout),
            "transport_error" => Some(Self::TransportError),
            "inconclusive" => Some(Self::Inconclusive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRecord {
    pub id: i64,
    pub session_id: Option<String>,
    pub turn_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub number: u64,
    pub url: String,
    pub state: CandidateState,
    /// Sanitized static reason or transport error class; never raw stderr/body.
    pub reason: Option<String>,
    pub get_status: Option<u16>,
    /// Safe PR metadata persisted before any caller can register it.
    pub verified: Option<VerifiedPullRequest>,
    pub consumed_at_ms: Option<i64>,
    pub retry_count: u32,
    pub next_retry_at_ms: Option<i64>,
    /// Lease token captured when this worker claimed the candidate.
    pub work_claim_until_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportFailure {
    Timeout,
    Network,
    Other,
}

#[derive(Debug, Clone)]
pub struct GetPullRequestResponse {
    pub status: u16,
    pub body: Value,
    /// UTC Unix milliseconds captured when the response was received.
    pub observed_at_ms: i64,
}

/// Implementations call only GitHub GET
/// `/repos/{repo}/pulls/{number}`, enforce the supplied timeout, and must not
/// include credentials or response bodies in `TransportFailure`.
pub trait PullRequestGetTransport {
    fn trusted_host(&self) -> std::result::Result<bool, TransportFailure> {
        Ok(true)
    }
    fn get_pull_request(
        &self,
        repository: &str,
        number: u64,
        timeout: Duration,
    ) -> std::result::Result<GetPullRequestResponse, TransportFailure>;
}

/// Uses the existing `gh api` authentication path and `manager::run` process
/// wrapper. Only this fixed read endpoint is constructed; no request body is
/// accepted by the adapter.
pub struct GhCliPullRequestGet {
    gh: PathBuf,
}

impl GhCliPullRequestGet {
    /// `gh` must be the executable path resolved by application configuration.
    pub fn new(gh: impl Into<PathBuf>) -> Self {
        Self { gh: gh.into() }
    }

    pub fn from_config(config: &crate::manager::Config) -> Self {
        Self::new(config.gh.clone())
    }
}

impl PullRequestGetTransport for GhCliPullRequestGet {
    fn trusted_host(&self) -> std::result::Result<bool, TransportFailure> {
        if !gh_supported_version(&self.gh)? {
            return Ok(false);
        }
        direct_gh_config_from_command(&self.gh)
    }
    fn get_pull_request(
        &self,
        repository: &str,
        number: u64,
        timeout: Duration,
    ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
        let Some(repository) = safe_repository(repository) else {
            return Err(TransportFailure::Other);
        };
        if number == 0 {
            return Err(TransportFailure::Other);
        }
        let endpoint = format!("https://api.github.com/repos/{repository}/pulls/{number}");
        let mut command = Command::new(&self.gh);
        command.args(["api", &endpoint, "--method", "GET", "--include"]);
        let output = crate::manager::run(&mut command, timeout).map_err(|error| {
            if error.to_string().contains("Command timed out") {
                TransportFailure::Timeout
            } else {
                TransportFailure::Network
            }
        })?;
        const CAPTURE_LIMIT: usize = 1024 * 1024;
        if output.stdout.len() == CAPTURE_LIMIT || output.stderr.len() == CAPTURE_LIMIT {
            return Err(TransportFailure::Other);
        }
        let (status, body) = parse_included_http_response(&output.stdout)?;
        if !output.status.success() && status == 200 {
            return Err(TransportFailure::Other);
        }
        Ok(GetPullRequestResponse {
            status,
            body,
            observed_at_ms: unix_now_ms(),
        })
    }
}

fn parse_included_http_response(
    output: &[u8],
) -> std::result::Result<(u16, Value), TransportFailure> {
    let output = std::str::from_utf8(output).map_err(|_| TransportFailure::Other)?;
    let (headers, body) = output
        .split_once("\r\n\r\n")
        .or_else(|| output.split_once("\n\n"))
        .ok_or(TransportFailure::Other)?;
    let status_line = headers
        .lines()
        .find(|line| line.starts_with("HTTP/"))
        .ok_or(TransportFailure::Other)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or(TransportFailure::Other)?;
    let body = serde_json::from_str(body.trim()).map_err(|_| TransportFailure::Other)?;
    Ok((status, body))
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandleResult {
    Ignored,
    Candidate {
        record: Box<CandidateRecord>,
        verified: Option<VerifiedPullRequest>,
    },
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(SCHEMA)
        .context("initialize PR observation tables")?;
    ensure_candidate_column(db, "exact_id_correlation", "INTEGER NOT NULL DEFAULT 0")?;
    ensure_candidate_column(db, "raw_creation_result", "INTEGER NOT NULL DEFAULT 0")?;
    ensure_pre_provenance_column(db)?;
    Ok(())
}

fn ensure_pre_provenance_column(db: &Connection) -> Result<()> {
    let exists = |db: &Connection| -> rusqlite::Result<bool> {
        let mut statement = db.prepare("PRAGMA table_info(pr_hook_pre_observations)")?;
        let names = statement.query_map([], |row| row.get::<_, String>(1))?;
        for name in names {
            if name? == "gh_provenance" {
                return Ok(true);
            }
        }
        Ok(false)
    };
    if exists(db)? {
        return Ok(());
    }
    let tx = if db.is_autocommit() {
        Some(rusqlite::Transaction::new_unchecked(
            db,
            rusqlite::TransactionBehavior::Immediate,
        )?)
    } else {
        None
    };
    let conn: &Connection = tx.as_deref().unwrap_or(db);
    if !exists(conn)? {
        conn.execute(
            "ALTER TABLE pr_hook_pre_observations ADD COLUMN gh_provenance TEXT",
            [],
        )?;
        conn.execute(
            "UPDATE pr_hook_candidates SET state='ambiguous', verified_json=NULL,
            work_claim_until_ms=NULL, reason='creation host provenance is unavailable'
            WHERE tool_name='Bash' AND state='verified' AND consumed_at_ms IS NULL",
            [],
        )?;
    }
    if let Some(tx) = tx {
        tx.commit()?;
    }
    Ok(())
}

// The hook and gh inherit the same local environment in normal operation. These
// snapshots cannot see unexported shell functions or prove configuration was
// unchanged between observations. Store only a digest, never credentials.
#[cfg(test)]
std::thread_local! {
    static TEST_GH_PROVENANCE: std::cell::RefCell<Option<String>> =
        std::cell::RefCell::new(Some("fixture-direct".into()));
    static TEST_INTERRUPT_POST_CAPTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn gh_provenance(gh: &std::path::Path, event: &Value) -> Option<String> {
    #[cfg(test)]
    if let Some(value) = TEST_GH_PROVENANCE.with(|state| state.borrow().clone()) {
        if let Some(path) = value.strip_prefix("fixture-executable:") {
            return direct_gh_config_from_command(std::path::Path::new(path))
                .ok()
                .filter(|direct| *direct)
                .map(|_| "fixture-direct".into());
        }
        return (value != "ambiguous").then_some(value);
    }
    if !bash_environment_is_inspectable(
        std::env::var_os("BASH_ENV").as_deref(),
        std::env::var_os("BASH_FUNC_gh%%").as_deref(),
    ) {
        return None;
    }
    if !gh_supported_version(gh).ok()? {
        return None;
    }
    let direct = gh_direct_provenance(gh).ok().flatten()?;
    let cwd = std::path::Path::new(event.get("cwd")?.as_str()?);
    if !cwd.is_absolute() || std::fs::canonicalize(cwd).ok()? != std::env::current_dir().ok()? {
        return None;
    }
    let input = event.get("tool_input")?;
    let command = input.get("command")?.as_str()?;
    let args = shell_tokens(command)?;
    let (explicit_repo, _, _, _) = intent_metadata("Bash", input);
    let mut hash = Sha256::new();
    hash.update(direct.as_bytes());
    hash.update(cwd.as_os_str().as_encoded_bytes());
    let configured_host = std::env::var("GH_HOST")
        .ok()
        .filter(|host| !host.is_empty());
    let uses_remotes = args.get(1).map(String::as_str) == Some("pr")
        && explicit_repo.is_none()
        && std::env::var_os("GH_REPO").is_none_or(|value| value.is_empty());
    if uses_remotes {
        hash.update(local_github_remote_fingerprint(cwd)?.as_bytes());
    }
    if configured_host.is_none() {
        // Match the verified gh versions using only locally configured host keys.
        if !gh_default_host_is_github(gh).ok()? {
            return None;
        }
        hash.update(b"default:github.com");
    }
    if args.get(1).map(String::as_str) == Some("pr") && explicit_repo.is_none() {
        match std::env::var("GH_REPO") {
            Ok(repo) if !repo.is_empty() => {
                if !gh_repo_is_github(&repo) {
                    return None;
                }
                hash.update(repo.as_bytes());
            }
            Err(std::env::VarError::NotUnicode(_)) => return None,
            _ => {}
        }
    }
    Some(format!("{:x}", hash.finalize()))
}

fn gh_direct_provenance(
    gh: &std::path::Path,
) -> std::result::Result<Option<String>, TransportFailure> {
    let host = match std::env::var("GH_HOST") {
        Ok(host) => Some(host),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => return Ok(None),
    };
    if host
        .as_deref()
        .is_some_and(|value| !value.is_empty() && !value.eq_ignore_ascii_case("github.com"))
    {
        return Ok(None);
    }
    if !direct_gh_config_from_command(gh)? {
        return Ok(None);
    }
    let mut digest = Sha256::new();
    let executable = resolve_executable(gh).ok_or(TransportFailure::Network)?;
    let metadata = std::fs::metadata(&executable).map_err(|_| TransportFailure::Network)?;
    use std::os::unix::fs::MetadataExt;
    digest.update(executable.as_os_str().as_encoded_bytes());
    digest.update(metadata.dev().to_be_bytes());
    digest.update(metadata.ino().to_be_bytes());
    digest.update(metadata.size().to_be_bytes());
    digest.update(metadata.mtime().to_be_bytes());
    digest.update(metadata.mtime_nsec().to_be_bytes());
    for key in [
        "GH_HOST",
        "GH_REPO",
        "GH_CONFIG_DIR",
        "XDG_CONFIG_HOME",
        "HOME",
    ] {
        let value = std::env::var_os(key);
        let bytes = match value.as_ref() {
            Some(v) => match v.to_str() {
                Some(value) => value,
                None => return Ok(None),
            },
            None => "",
        };
        digest.update((key.len() as u64).to_be_bytes());
        digest.update(key.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes.as_bytes());
    }
    Ok(Some(format!("{:x}", digest.finalize())))
}

// Only versions whose DefaultHost and configuration loading were checked are
// supported. Errors and unsupported YAML are deliberately ambiguous.
fn gh_supported_version(gh: &std::path::Path) -> std::result::Result<bool, TransportFailure> {
    let version = crate::manager::run(Command::new(gh).arg("--version"), Duration::from_secs(5))
        .map_err(|_| TransportFailure::Network)?;
    if !version.status.success() {
        return Err(TransportFailure::Network);
    }
    let version = std::str::from_utf8(&version.stdout).map_err(|_| TransportFailure::Network)?;
    let words: Vec<_> = version.split_whitespace().take(3).collect();
    Ok(words == ["gh", "version", "2.99.0"] || words == ["gh", "version", "2.103.3"])
}

fn gh_default_host_is_github(_gh: &std::path::Path) -> std::result::Result<bool, TransportFailure> {
    let config_dir = std::env::var_os("GH_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map(|v| std::path::PathBuf::from(v).join("gh"))
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|v| std::path::PathBuf::from(v).join(".config/gh"))
        });
    let Some(config_dir) = config_dir else {
        return Ok(false);
    };
    Ok(local_default_host_is_github(&config_dir).unwrap_or(false))
}

type GhHostKeys = std::collections::BTreeMap<String, serde::de::IgnoredAny>;

#[derive(serde::Deserialize)]
struct GhGeneralConfig {
    #[serde(default)]
    hosts: Option<GhHostKeys>,
}

// Never log or retain the input: hosts.yml can contain credentials. Reject YAML
// features whose interpretation may differ from gh's yamlmap implementation.
fn read_gh_yaml<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Option<Option<T>> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(None),
        Err(_) => return None,
    };
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 1024 * 1024
        || bytes.iter().any(|b| matches!(b, b'&' | b'*' | b'!' | b'%'))
        || bytes.windows(2).any(|pair| pair == b"<<")
    {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    serde_saphyr::from_str::<Option<T>>(text).ok()
}

fn local_default_host_is_github(config_dir: &std::path::Path) -> Option<bool> {
    let general = read_gh_yaml::<GhGeneralConfig>(&config_dir.join("config.yml"))?;
    let hosts = read_gh_yaml::<GhHostKeys>(&config_dir.join("hosts.yml"))?;
    let general_hosts = general.and_then(|config| config.hosts);
    // Avoid guessing yamlmap's treatment of the same key in both files.
    if general_hosts.is_some() && hosts.as_ref().is_some_and(|map| !map.is_empty()) {
        return None;
    }
    let host_keys = hosts.filter(|map| !map.is_empty()).or(general_hosts);
    let Some(host_keys) = host_keys else {
        return Some(true);
    };
    if host_keys.len() != 1 {
        return Some(true);
    }
    Some(host_keys.keys().next()?.eq_ignore_ascii_case("github.com"))
}

fn local_github_remote_fingerprint(cwd: &std::path::Path) -> Option<String> {
    let run = |args: &[&str]| {
        let mut command = Command::new("git");
        command.arg("-C").arg(cwd).args(args);
        let output = crate::manager::run(&mut command, Duration::from_secs(3)).ok()?;
        (output.status.success() && output.stdout.len() < 1024 * 1024).then_some(output.stdout)
    };
    let remotes = run(&["remote"])?;
    let remotes = std::str::from_utf8(&remotes).ok()?;
    let names: Vec<_> = remotes.lines().filter(|name| !name.is_empty()).collect();
    if names.is_empty() || names.len() > 8 {
        return None;
    }
    let mut resolved = Command::new("git");
    resolved
        .arg("-C")
        .arg(cwd)
        .args(["config", "--get-regexp", r"^remote\..*\.gh-resolved$"]);
    let resolved = crate::manager::run(&mut resolved, Duration::from_secs(3)).ok()?;
    if !(resolved.status.success() || resolved.status.code() == Some(1))
        || resolved.stdout.len() >= 1024 * 1024
    {
        return None;
    }
    let resolved = std::str::from_utf8(&resolved.stdout).ok()?;
    for line in resolved.lines() {
        let (_, value) = line.split_once(' ')?;
        if value != "base"
            && !github_git_url(value)
            && crate::pr_hook::normalize_repository(value).is_none()
        {
            return None;
        }
    }
    let mut entries = vec![resolved.to_owned()];
    for name in names {
        let urls = run(&["remote", "get-url", "--all", name])?;
        let urls = std::str::from_utf8(&urls).ok()?;
        if urls.lines().next().is_none() || !urls.lines().all(github_git_url) {
            return None;
        }
        entries.push(format!("{name}\0{urls}"));
    }
    entries.sort();
    let mut digest = Sha256::new();
    for entry in entries {
        digest.update((entry.len() as u64).to_be_bytes());
        digest.update(entry.as_bytes());
    }
    Some(format!("{:x}", digest.finalize()))
}

fn github_git_url(url: &str) -> bool {
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))
        .or_else(|| url.strip_prefix("ssh://git@github.com:22/"))
        .or_else(|| url.strip_prefix("git@github.com:"));
    path.and_then(|path| path.strip_suffix(".git").or(Some(path)))
        .and_then(crate::pr_hook::normalize_repository)
        .is_some()
}

fn resolve_executable(program: &std::path::Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let executable = |path: PathBuf| {
        let metadata = std::fs::metadata(&path).ok()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }
        std::fs::canonicalize(path).ok()
    };
    if program.components().count() > 1 {
        return executable(program.to_path_buf());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .find_map(|directory| executable(directory.join(program)))
}

fn gh_repo_is_github(repo: &str) -> bool {
    let parts: Vec<_> = repo.split('/').collect();
    match parts.as_slice() {
        [owner, name] => !owner.is_empty() && !name.is_empty(),
        [host, owner, name] => {
            host.eq_ignore_ascii_case("github.com") && !owner.is_empty() && !name.is_empty()
        }
        _ => false,
    }
}

fn direct_gh_config_from_command(
    gh: &std::path::Path,
) -> std::result::Result<bool, TransportFailure> {
    let mut command = Command::new(gh);
    command.args(["config", "list", "--host", "github.com"]);
    let output = crate::manager::run(&mut command, Duration::from_secs(5))
        .map_err(|_| TransportFailure::Network)?;
    if !output.status.success() {
        return Err(TransportFailure::Network);
    }
    if output.stdout.len() >= 1024 * 1024 {
        return Ok(false);
    }
    let Ok(config) = std::str::from_utf8(&output.stdout) else {
        return Ok(false);
    };
    if config.lines().any(|line| line.starts_with("api_host=")) {
        return Ok(direct_gh_config(config));
    }
    // api_host was introduced in gh 2.100. Unknown or development builds
    // remain ambiguous when the setting cannot be inspected.
    let output = crate::manager::run(Command::new(gh).arg("--version"), Duration::from_secs(5))
        .map_err(|_| TransportFailure::Network)?;
    if !output.status.success() {
        return Err(TransportFailure::Network);
    }
    let legacy = std::str::from_utf8(&output.stdout).is_ok_and(legacy_gh_without_api_host);
    Ok(legacy && direct_gh_config(&format!("{config}\napi_host=\n")))
}

fn legacy_gh_without_api_host(version: &str) -> bool {
    let Some(version) = version
        .strip_prefix("gh version ")
        .and_then(|value| value.split_whitespace().next())
    else {
        return false;
    };
    let parts: Vec<_> = version.split('.').collect();
    matches!(parts.as_slice(), ["2", minor, patch]
        if !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit())
        && !patch.is_empty() && patch.bytes().all(|b| b.is_ascii_digit())
        && minor.parse::<u32>().is_ok_and(|minor| minor < 100))
}

fn bash_environment_is_inspectable(
    bash_env: Option<&std::ffi::OsStr>,
    exported_gh: Option<&std::ffi::OsStr>,
) -> bool {
    bash_env.is_none_or(std::ffi::OsStr::is_empty) && exported_gh.is_none()
}

fn direct_gh_config(config: &str) -> bool {
    let mut api_host = None;
    let mut socket = None;
    for line in config.lines() {
        if let Some(value) = line.strip_prefix("api_host=")
            && api_host.replace(value.trim()).is_some()
        {
            return false;
        }
        if let Some(value) = line.strip_prefix("http_unix_socket=")
            && socket.replace(value.trim()).is_some()
        {
            return false;
        }
    }
    api_host == Some("") && socket == Some("")
}

fn ensure_candidate_column(db: &Connection, name: &str, definition: &str) -> Result<()> {
    let exists = || -> Result<bool> {
        let mut statement = db.prepare("PRAGMA table_info(pr_hook_candidates)")?;
        let names = statement.query_map([], |row| row.get::<_, String>(1))?;
        for column in names {
            if column? == name {
                return Ok(true);
            }
        }
        Ok(false)
    };
    if !exists()? {
        let sql = format!("ALTER TABLE pr_hook_candidates ADD COLUMN {name} {definition}");
        if let Err(error) = db.execute(&sql, []) {
            // Another connection may have completed this idempotent migration
            // after our schema read.
            if !exists()? {
                return Err(error).context("migrate PR observation candidate columns");
            }
        }
    }
    Ok(())
}

fn candidate_result(
    db: &Connection,
    id: i64,
    verified: Option<VerifiedPullRequest>,
) -> Result<HandleResult> {
    let record = candidate_record(db, id)?.ok_or_else(|| anyhow!("candidate disappeared"))?;
    Ok(HandleResult::Candidate {
        record: Box::new(record),
        verified,
    })
}

/// Cheap, side-effect-free gate for `PreToolUse`: callers can skip opening the
/// database entirely for unrelated tools. Malformed/unknown input is false.
pub fn is_relevant_pre_tool_use(event: &Value) -> bool {
    if event.get("hook_event_name").and_then(Value::as_str) != Some("PreToolUse") {
        return false;
    }
    let Some(tool_name) = event.get("tool_name").and_then(Value::as_str) else {
        return false;
    };
    event
        .get("tool_input")
        .is_some_and(|input| is_pr_creation_intent(tool_name, input))
}

fn claim_candidates(
    db: &mut Connection,
    now_ms: i64,
    lease_ms: i64,
    limit: usize,
    verified: bool,
) -> Result<Vec<CandidateRecord>> {
    initialize(db)?;
    let lease_until = now_ms
        .checked_add(lease_ms.max(1))
        .ok_or_else(|| anyhow!("candidate claim lease overflow"))?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let condition = if verified {
        "state='verified' AND consumed_at_ms IS NULL"
    } else {
        "(state IN ('timeout','transport_error') AND next_retry_at_ms<=?1)
         OR (state='pending' AND (work_claim_until_ms IS NULL OR work_claim_until_ms<=?1))"
    };
    let query = format!(
        "SELECT id FROM pr_hook_candidates WHERE ({condition})
         AND (work_claim_until_ms IS NULL OR work_claim_until_ms<=?1)
         ORDER BY COALESCE(next_retry_at_ms,created_at_ms),id LIMIT ?2"
    );
    let ids = tx
        .prepare(&query)?
        .query_map(
            params![now_ms, limit.min(i64::MAX as usize) as i64],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in &ids {
        tx.execute(
            "UPDATE pr_hook_candidates SET work_claim_until_ms=?1 WHERE id=?2",
            params![lease_until, id],
        )?;
    }
    tx.commit()?;
    ids.into_iter()
        .filter_map(|id| match candidate_record(db, id) {
            Ok(Some(mut record)) => {
                // Return the token this claimant wrote, even if another worker
                // reclaims the row before the post-commit read completes.
                record.work_claim_until_ms = Some(lease_until);
                Some(Ok(record))
            }
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

/// Atomically claim verified candidates for a worker. Lease expiry makes work
/// recoverable after a crash and prevents concurrent workers handling a row.
pub fn claim_verified_pending(
    db: &mut Connection,
    now_ms: i64,
    lease_ms: i64,
    limit: usize,
) -> Result<Vec<CandidateRecord>> {
    claim_candidates(db, now_ms, lease_ms, limit, true)
}

/// Acknowledge only after the caller's registration succeeds. Returns false
/// if the row is not verified, is already consumed, or its claim has expired.
#[cfg(test)]
pub fn mark_candidate_consumed(db: &Connection, id: i64, now_ms: i64) -> Result<bool> {
    initialize(db)?;
    Ok(db.execute(
        "UPDATE pr_hook_candidates SET consumed_at_ms=?1,work_claim_until_ms=NULL,updated_at_ms=?1
         WHERE id=?2 AND state='verified' AND consumed_at_ms IS NULL AND work_claim_until_ms>?1",
        params![now_ms, id],
    )? == 1)
}

/// Atomically lease due retries or interrupted pending verifications so
/// concurrent workers cannot issue duplicate GitHub GET requests.
pub fn claim_due_retries(
    db: &mut Connection,
    now_ms: i64,
    lease_ms: i64,
    limit: usize,
) -> Result<Vec<CandidateRecord>> {
    claim_candidates(db, now_ms, lease_ms, limit, false)
}

/// Record relevant PreToolUse observations. Only session/turn/tool IDs,
/// SHA-256(tool_input), and available repository/ref/author metadata are kept.
/// `expires_after_ms` bounds unmatched PreToolUse retention.
pub fn record_pre_tool_use(
    db: &mut Connection,
    event: &Value,
    observed_at_ms: i64,
    expires_after_ms: i64,
) -> Result<PreRecord> {
    initialize(db)?;
    cleanup_expired_pre(db, observed_at_ms)?;

    let Some(tool_name) = event.get("tool_name").and_then(Value::as_str) else {
        return Ok(PreRecord::Ignored);
    };
    let Some(tool_input) = event.get("tool_input") else {
        return Ok(PreRecord::Ignored);
    };
    if event.get("hook_event_name").and_then(Value::as_str) != Some("PreToolUse")
        || !is_pr_creation_intent(tool_name, tool_input)
    {
        return Ok(PreRecord::Ignored);
    }

    let session_id = nonempty(event.get("session_id").and_then(Value::as_str));
    let turn_id = nonempty(event.get("turn_id").and_then(Value::as_str));
    let tool_use_id = nonempty(event.get("tool_use_id").and_then(Value::as_str));
    let input_digest = input_digest(tool_input)?;
    let provenance = if tool_name == "Bash" {
        gh_provenance(std::path::Path::new("gh"), event)
    } else {
        None
    };
    let expires_at_ms = observed_at_ms
        .checked_add(expires_after_ms.max(0))
        .ok_or_else(|| anyhow!("PreToolUse expiration timestamp overflow"))?;
    let (explicit_repository, head_ref, base_ref, author_login) =
        intent_metadata(tool_name, tool_input);
    let repository = effective_creation_repository(
        tool_name,
        tool_input,
        explicit_repository,
        std::env::var("GH_REPO").ok().as_deref(),
    );
    let initial_state = if session_id.is_some() && turn_id.is_some() && input_digest.is_some() {
        "pending"
    } else {
        "ambiguous"
    };
    let initial_reason =
        (initial_state == "ambiguous").then_some("PreToolUse lacks session, turn, or input digest");

    let tx = db.transaction()?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO pr_hook_pre_observations
         (session_id,turn_id,tool_use_id,tool_name,input_digest,repository,head_ref,base_ref,
          author_login,observed_at_ms,expires_at_ms,state,reason,gh_provenance)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            session_id,
            turn_id,
            tool_use_id,
            tool_name,
            input_digest,
            repository,
            head_ref,
            base_ref,
            author_login,
            observed_at_ms,
            expires_at_ms,
            initial_state,
            initial_reason,
            provenance
        ],
    )?;
    if inserted == 1 {
        let id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE pr_hook_candidates SET state='ambiguous',
             reason='multiple PreToolUse entries match session and input digest',
             verified_json=NULL,work_claim_until_ms=NULL,updated_at_ms=?1
             WHERE session_id=?2 AND turn_id=?3 AND tool_name=?4 AND input_digest=?5
               AND exact_id_correlation=0 AND consumed_at_ms IS NULL
               AND state IN ('pending','timeout','transport_error','inconclusive','verified')",
            params![observed_at_ms, session_id, turn_id, tool_name, input_digest],
        )?;
        tx.commit()?;
        return Ok(if initial_state == "pending" {
            PreRecord::Recorded { id }
        } else {
            PreRecord::Ambiguous {
                id,
                reason: initial_reason.unwrap_or("PreToolUse is incomplete"),
            }
        });
    }

    let existing_id = match (
        session_id.as_deref(),
        turn_id.as_deref(),
        tool_use_id.as_deref(),
    ) {
        (Some(session), Some(turn), Some(call)) => tx
            .query_row(
                "SELECT id,input_digest,state FROM pr_hook_pre_observations
                 WHERE session_id=?1 AND turn_id=?2 AND tool_use_id=?3",
                params![session, turn, call],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?,
        _ => None,
    };
    if let Some((id, prior_digest, prior_state)) = existing_id {
        if prior_digest != input_digest {
            tx.execute(
                "UPDATE pr_hook_pre_observations SET state='ambiguous',
                 reason='same tool identity received different input digests' WHERE id=?1",
                [id],
            )?;
            tx.execute(
                "UPDATE pr_hook_candidates SET state='ambiguous',
                 reason='correlated PreToolUse identity received conflicting input',
                 verified_json=NULL,work_claim_until_ms=NULL,updated_at_ms=?1
                 WHERE pre_id=?2 AND consumed_at_ms IS NULL
                   AND state IN ('pending','timeout','transport_error','inconclusive','verified')",
                params![observed_at_ms, id],
            )?;
            tx.commit()?;
            return Ok(PreRecord::Ambiguous {
                id,
                reason: "same tool identity received different input digests",
            });
        }
        tx.commit()?;
        return Ok(if prior_state == "pending" {
            PreRecord::Duplicate { id }
        } else {
            PreRecord::Ambiguous {
                id,
                reason: "PreToolUse identity already has a non-pending state",
            }
        });
    }

    tx.commit()?;
    Ok(PreRecord::Ignored)
}

/// Persist a PostToolUse candidate, correlate it to a durable PreToolUse, then
/// call the injected GET transport. Candidate persistence commits before any
/// network operation; timeout and error states remain queryable and retryable.
pub fn handle_post_tool_use(
    db: &mut Connection,
    event: &Value,
    transport: &dyn PullRequestGetTransport,
    timeout: Duration,
    max_pre_to_creation_ms: i64,
) -> Result<HandleResult> {
    initialize(db)?;
    let Some((candidate, post_id)) = parse_candidate_preserving_missing_id(event) else {
        record_completed_non_candidate_call(db, event)?;
        return Ok(HandleResult::Ignored);
    };
    let tool_name = event
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let session_id = nonempty(event.get("session_id").and_then(Value::as_str));
    let turn_id = nonempty(event.get("turn_id").and_then(Value::as_str));
    let input_digest = event
        .get("tool_input")
        .and_then(|input| input_digest(input).ok().flatten());
    let now_ms = unix_now_ms();
    let invocation_key = candidate_invocation_key(
        session_id.as_deref(),
        turn_id.as_deref(),
        post_id.as_deref(),
        tool_name,
        input_digest.as_deref(),
        candidate.number,
        &candidate.url,
    )?;
    let number =
        i64::try_from(candidate.number).context("PR number exceeds SQLite integer range")?;

    let tx = db.transaction()?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO pr_hook_candidates
         (session_id,turn_id,tool_use_id,tool_name,input_digest,number,url,invocation_key,
          state,reason,created_at_ms,updated_at_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'ambiguous',
                 'post provenance capture incomplete',?9,?9)",
        params![
            session_id,
            turn_id,
            post_id,
            tool_name,
            input_digest,
            number,
            candidate.url,
            invocation_key,
            now_ms
        ],
    )?;
    let candidate_id = if inserted == 1 {
        tx.last_insert_rowid()
    } else {
        let (id, old_digest, old_number, old_url, old_tool) = tx.query_row(
            "SELECT id,input_digest,number,url,tool_name FROM pr_hook_candidates
             WHERE invocation_key=?1",
            [&invocation_key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )?;
        if old_digest == input_digest
            && old_number == number
            && old_url == candidate.url
            && old_tool == tool_name
        {
            tx.commit()?;
            return resume_pending_candidate(db, id, timeout, transport, max_pre_to_creation_ms);
        }
        tx.execute(
            "UPDATE pr_hook_candidates SET state='ambiguous',
             reason='duplicate invocation carried conflicting candidate data',
             work_claim_until_ms=NULL,updated_at_ms=?1
             WHERE id=?2",
            params![now_ms, id],
        )?;
        tx.commit()?;
        return candidate_result(db, id, None);
    };

    // Commit the URL before any process or filesystem probe. If the hook dies
    // during capture, the original post environment cannot be reconstructed;
    // the durable ambiguous state requires attention instead of inventing it.
    tx.commit()?;
    #[cfg(test)]
    if TEST_INTERRUPT_POST_CAPTURE.with(|flag| flag.get()) {
        return Err(anyhow!(
            "synthetic interruption after candidate persistence"
        ));
    }
    let post_provenance = if tool_name == "Bash" {
        gh_provenance(std::path::Path::new("gh"), event)
    } else {
        None
    };
    let tx = db.transaction()?;
    let still_capturing = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pr_hook_candidates WHERE id=?1
         AND state='ambiguous' AND reason='post provenance capture incomplete')",
        [candidate_id],
        |row| row.get::<_, bool>(0),
    )?;
    if !still_capturing {
        tx.commit()?;
        return candidate_result(db, candidate_id, None);
    }
    let correlation = correlate_pre(
        &tx,
        session_id.as_deref(),
        turn_id.as_deref(),
        post_id.as_deref(),
        tool_name,
        input_digest.as_deref(),
    )?;
    let mut creation_host_unverified = false;
    match correlation {
        Correlation::Unique {
            pre_id,
            exact_tool_use_id,
        } => {
            if tool_name == "Bash" {
                let prior: Option<String> = tx.query_row(
                    "SELECT gh_provenance FROM pr_hook_pre_observations WHERE id=?1",
                    [pre_id],
                    |row| row.get(0),
                )?;
                creation_host_unverified = prior.is_none() || prior != post_provenance;
            }
            tx.execute(
                "UPDATE pr_hook_candidates SET pre_id=?1,exact_id_correlation=?2,
                 raw_creation_result=?3 WHERE id=?4",
                params![
                    pre_id,
                    exact_tool_use_id,
                    raw_creation_result(tool_name, event.get("tool_input"))
                        && !creation_host_unverified,
                    candidate_id
                ],
            )?;
            tx.execute(
                "UPDATE pr_hook_pre_observations SET state='linked',reason=NULL WHERE id=?1",
                [pre_id],
            )?;
        }
        Correlation::Ambiguous(reason) => {
            tx.execute(
                "UPDATE pr_hook_candidates SET state='ambiguous',reason=?1 WHERE id=?2",
                params![reason, candidate_id],
            )?;
            tx.commit()?;
            return candidate_result(db, candidate_id, None);
        }
    }
    if creation_host_unverified {
        tx.execute(
            "UPDATE pr_hook_candidates SET state='ambiguous',
             reason='creation host provenance is unavailable',updated_at_ms=?1 WHERE id=?2",
            params![now_ms, candidate_id],
        )?;
        tx.commit()?;
        return candidate_result(db, candidate_id, None);
    }
    if command_output_can_be_filtered(tool_name, event.get("tool_input")) {
        tx.execute(
            "UPDATE pr_hook_candidates SET state='ambiguous',
             reason='gh api output uses jq/template formatting',updated_at_ms=?1 WHERE id=?2",
            params![now_ms, candidate_id],
        )?;
        tx.commit()?;
        return candidate_result(db, candidate_id, None);
    }
    tx.execute(
        "UPDATE pr_hook_candidates SET state='pending',reason=NULL,updated_at_ms=?1 WHERE id=?2",
        params![now_ms, candidate_id],
    )?;
    tx.commit()?;
    resume_pending_candidate(db, candidate_id, timeout, transport, max_pre_to_creation_ms)
}

// Each host check may run version, config, and the legacy version probe,
// each bounded by five seconds. Two checks plus GET need 30 seconds beyond
// the GET timeout, with another five seconds for ordinary bookkeeping.
fn verification_lease_ms(timeout: Duration) -> i64 {
    let get_ms = timeout.as_millis().min(i64::MAX as u128) as i64;
    get_ms.max(1).saturating_add(35_000)
}

fn resume_pending_candidate(
    db: &mut Connection,
    candidate_id: i64,
    timeout: Duration,
    transport: &dyn PullRequestGetTransport,
    max_pre_to_creation_ms: i64,
) -> Result<HandleResult> {
    let now = unix_now_ms();
    let until = now.saturating_add(verification_lease_ms(timeout));
    let claimed = db.execute(
        "UPDATE pr_hook_candidates SET work_claim_until_ms=?1
         WHERE id=?2 AND state='pending'
         AND (work_claim_until_ms IS NULL OR work_claim_until_ms<=?3)",
        params![until, candidate_id, now],
    )? == 1;
    if claimed {
        verify_persisted_candidate(
            db,
            candidate_id,
            until,
            CandidateState::Pending,
            transport,
            timeout,
            max_pre_to_creation_ms,
        )
    } else {
        Ok(candidate_status(db, candidate_id)?
            .map(|record| HandleResult::Candidate {
                verified: record.verified.clone(),
                record: Box::new(record),
            })
            .unwrap_or(HandleResult::Ignored))
    }
}

/// Retry a durable candidate after it was returned by `claim_due_retries`.
/// A valid, unexpired lease is required; no retry removes the candidate.
pub fn retry_candidate(
    db: &mut Connection,
    candidate_id: i64,
    expected_lease_until_ms: i64,
    transport: &dyn PullRequestGetTransport,
    timeout: Duration,
    max_pre_to_creation_ms: i64,
) -> Result<HandleResult> {
    initialize(db)?;
    // The caller's lease may be shorter than the two host probes plus GET.
    // Extend it while it is still ours, before doing any external work.
    let now = unix_now_ms();
    let minimum_until = now.saturating_add(verification_lease_ms(timeout));
    let extended = db
        .query_row(
            "UPDATE pr_hook_candidates SET work_claim_until_ms=MAX(work_claim_until_ms,?1)
         WHERE id=?2 AND work_claim_until_ms=?3 AND work_claim_until_ms>?4
         RETURNING work_claim_until_ms",
            params![minimum_until, candidate_id, expected_lease_until_ms, now],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(expected_lease_until_ms) = extended else {
        return Ok(candidate_status(db, candidate_id)?
            .map(|record| HandleResult::Candidate {
                verified: record.verified.clone(),
                record: Box::new(record),
            })
            .unwrap_or(HandleResult::Ignored));
    };
    let state = load_candidate_for_verify(db, candidate_id)?
        .map(|stored| stored.state)
        .unwrap_or(CandidateState::Ambiguous);
    verify_persisted_candidate(
        db,
        candidate_id,
        expected_lease_until_ms,
        state,
        transport,
        timeout,
        max_pre_to_creation_ms,
    )
}

pub fn candidate_status(db: &Connection, candidate_id: i64) -> Result<Option<CandidateRecord>> {
    initialize(db)?;
    candidate_record(db, candidate_id)
}

/// Expired PreToolUse rows without an active candidate reference are removed.
/// Candidate rows are retained regardless of state.
pub fn cleanup_expired_pre(db: &Connection, now_ms: i64) -> Result<usize> {
    initialize(db)?;
    Ok(db.execute(
        "DELETE FROM pr_hook_pre_observations AS p
         WHERE p.expires_at_ms<=?1
         AND NOT EXISTS (
             SELECT 1 FROM pr_hook_candidates c
             WHERE c.pre_id=p.id AND (
                 c.state IN ('pending','timeout','transport_error','inconclusive')
                 OR (c.state='verified' AND c.consumed_at_ms IS NULL)
             )
         )",
        [now_ms],
    )?)
}

#[derive(Debug)]
enum Correlation {
    Unique {
        pre_id: i64,
        exact_tool_use_id: bool,
    },
    Ambiguous(&'static str),
}

fn correlate_pre(
    db: &Connection,
    session_id: Option<&str>,
    turn_id: Option<&str>,
    post_tool_use_id: Option<&str>,
    tool_name: &str,
    digest: Option<&str>,
) -> Result<Correlation> {
    let (Some(session), Some(turn), Some(digest)) = (session_id, turn_id, digest) else {
        return Ok(Correlation::Ambiguous(
            "PostToolUse lacks session, turn, or input digest",
        ));
    };
    let mut statement = db.prepare(
        "SELECT id,tool_use_id,input_digest,state FROM pr_hook_pre_observations
         WHERE session_id=?1 AND turn_id=?2 AND tool_name=?3 AND state IN ('pending','linked')",
    )?;
    let rows = statement.query_map(params![session, turn, tool_name], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut matches = Vec::new();
    let mut id_input_conflict = false;
    for row in rows {
        let (id, pre_id, pre_digest, _state) = row?;
        match (post_tool_use_id, pre_id.as_deref()) {
            (Some(post_id), Some(pre_id)) if post_id == pre_id => {
                if pre_digest.as_deref() == Some(digest) {
                    matches.push((id, true));
                } else {
                    id_input_conflict = true;
                }
            }
            (Some(_), Some(_)) => {}
            _ if pre_digest.as_deref() == Some(digest) => matches.push((id, false)),
            _ => {}
        }
    }
    if id_input_conflict {
        return Ok(Correlation::Ambiguous(
            "tool_use_id matched but PreToolUse and PostToolUse input digests differ",
        ));
    }
    match matches.as_slice() {
        [(id, exact_tool_use_id)] => Ok(Correlation::Unique {
            pre_id: *id,
            exact_tool_use_id: *exact_tool_use_id,
        }),
        [] => Ok(Correlation::Ambiguous(
            "no PreToolUse matches session, turn, tool and input digest",
        )),
        _ => Ok(Correlation::Ambiguous(
            "multiple PreToolUse entries match session and input digest",
        )),
    }
}

fn verify_persisted_candidate(
    db: &mut Connection,
    candidate_id: i64,
    expected_lease_until: i64,
    expected_state: CandidateState,
    transport: &dyn PullRequestGetTransport,
    timeout: Duration,
    max_pre_to_creation_ms: i64,
) -> Result<HandleResult> {
    let Some(stored) = load_candidate_for_verify(db, candidate_id)? else {
        return Ok(HandleResult::Ignored);
    };
    let StoredCandidate {
        candidate,
        pre_id,
        state,
        session_id,
        turn_id,
        tool_use_id,
        tool_name,
        input_digest,
        exact_id_correlation,
        raw_creation_result,
    } = stored;
    if matches!(state, CandidateState::Verified | CandidateState::Ambiguous) {
        return candidate_result(db, candidate_id, None);
    }
    let Some(pre_id) = pre_id else {
        set_candidate_state(
            db,
            candidate_id,
            CandidateState::Ambiguous,
            (expected_state, expected_lease_until),
            Some("candidate has no correlated PreToolUse"),
            None,
            None,
        )?;
        return candidate_result(db, candidate_id, None);
    };
    let Some(pre) = load_pre_observation(db, pre_id)? else {
        set_candidate_state(
            db,
            candidate_id,
            CandidateState::Ambiguous,
            (expected_state, expected_lease_until),
            Some("correlated PreToolUse evidence is unavailable"),
            None,
            None,
        )?;
        return candidate_result(db, candidate_id, None);
    };
    if pre.state != "linked" {
        set_candidate_state(
            db,
            candidate_id,
            CandidateState::Ambiguous,
            (expected_state, expected_lease_until),
            Some("correlated PreToolUse is not in linked state"),
            None,
            None,
        )?;
        return candidate_result(db, candidate_id, None);
    }
    if tool_name == "Bash" && pre.gh_provenance.is_none() {
        set_candidate_state(
            db,
            candidate_id,
            CandidateState::Ambiguous,
            (expected_state, expected_lease_until),
            Some("creation host provenance is unavailable"),
            None,
            None,
        )?;
        return candidate_result(db, candidate_id, None);
    }
    let repo = repository_from_pr_url(&candidate.url)
        .ok_or_else(|| anyhow!("persisted candidate URL has invalid repository"))?;
    let exact_call_and_result = exact_id_correlation
        && raw_creation_result
        && session_id
            .as_deref()
            .is_some_and(|id| Some(id) == pre.session_id.as_deref())
        && turn_id
            .as_deref()
            .is_some_and(|id| Some(id) == pre.turn_id.as_deref())
        && tool_use_id
            .as_deref()
            .is_some_and(|id| Some(id) == pre.tool_use_id.as_deref())
        && input_digest
            .as_deref()
            .is_some_and(|digest| Some(digest) == pre.input_digest.as_deref())
        && pre.tool_name.as_deref() == Some(tool_name.as_str());
    // Reject an unsafe observed configuration; snapshots do not prove what
    // configuration the separate GET process used.
    let host_state = match transport.trusted_host() {
        Ok(value) => value,
        Err(_) => {
            set_candidate_state(
                db,
                candidate_id,
                CandidateState::TransportError,
                (expected_state, expected_lease_until),
                Some("GitHub host check failed"),
                None,
                None,
            )?;
            return candidate_result(db, candidate_id, None);
        }
    };
    if !host_state {
        set_candidate_state(
            db,
            candidate_id,
            CandidateState::Ambiguous,
            (expected_state, expected_lease_until),
            Some("GitHub verification host provenance is unavailable"),
            None,
            None,
        )?;
        return candidate_result(db, candidate_id, None);
    }
    let response = match transport.get_pull_request(&repo, candidate.number, timeout) {
        Ok(response) => response,
        Err(TransportFailure::Timeout) => {
            set_candidate_state(
                db,
                candidate_id,
                CandidateState::Timeout,
                (expected_state, expected_lease_until),
                Some("GitHub GET timed out"),
                None,
                None,
            )?;
            return candidate_result(db, candidate_id, None);
        }
        Err(failure) => {
            set_candidate_state(
                db,
                candidate_id,
                CandidateState::TransportError,
                (expected_state, expected_lease_until),
                Some(failure.safe_label()),
                None,
                None,
            )?;
            return candidate_result(db, candidate_id, None);
        }
    };
    let host_state = match transport.trusted_host() {
        Ok(value) => value,
        Err(_) => {
            set_candidate_state(
                db,
                candidate_id,
                CandidateState::TransportError,
                (expected_state, expected_lease_until),
                Some("GitHub host check failed"),
                None,
                None,
            )?;
            return candidate_result(db, candidate_id, None);
        }
    };
    if !host_state {
        set_candidate_state(
            db,
            candidate_id,
            CandidateState::Ambiguous,
            (expected_state, expected_lease_until),
            Some("GitHub verification host provenance changed"),
            None,
            None,
        )?;
        return candidate_result(db, candidate_id, None);
    }
    if let Some(reason) = retryable_http_failure(response.status, &response.body) {
        set_candidate_state(
            db,
            candidate_id,
            CandidateState::TransportError,
            (expected_state, expected_lease_until),
            Some(reason),
            Some(response.status),
            None,
        )?;
        return candidate_result(db, candidate_id, None);
    }
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let observations = match (session_id.as_deref(), turn_id.as_deref()) {
        (Some(session), Some(turn)) => load_plausible_pre_observations(
            &tx,
            session,
            turn,
            &repo,
            pre_id,
            exact_call_and_result,
        )?,
        _ => Vec::new(),
    };
    let outcome = verify_pr_candidate(
        &candidate,
        &observations,
        max_pre_to_creation_ms,
        response.status,
        &response.body,
        response.observed_at_ms,
    );
    let (state, reason, verified) = match outcome {
        VerificationOutcome::Attributed(pr) => (CandidateState::Verified, None, Some(pr)),
        VerificationOutcome::ExistsButAmbiguous { reason, .. } => {
            (CandidateState::Ambiguous, Some(reason), None)
        }
        VerificationOutcome::Inconclusive { reason } => {
            (CandidateState::Inconclusive, Some(reason), None)
        }
    };
    let changed = set_candidate_state(
        &tx,
        candidate_id,
        state,
        (expected_state, expected_lease_until),
        reason,
        Some(response.status),
        verified.as_ref(),
    )?;
    tx.commit()?;
    let verified = if changed {
        verified
    } else {
        candidate_record(db, candidate_id)?.and_then(|record| record.verified)
    };
    candidate_result(db, candidate_id, verified)
}

fn raw_creation_result(tool_name: &str, tool_input: Option<&Value>) -> bool {
    if tool_name == MCP_CREATE_PR_TOOL {
        return true;
    }
    if tool_name != "Bash" {
        return false;
    }
    let Some(command) = tool_input
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Some(args) = shell_tokens(command) else {
        return false;
    };
    if args.get(1).map(String::as_str) == Some("api") {
        !has_explicit_foreign_api_host(&args)
    } else {
        // The candidate parser does not bind grouped or attached short options.
        // Skip option values before rejecting those ambiguous forms.
        !has_unparsed_pr_short_options(&args[3..])
    }
}

fn has_unparsed_pr_short_options(args: &[String]) -> bool {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if arg == "--" {
            return index + 1 != args.len();
        }
        let (option, inline) = arg
            .split_once('=')
            .map_or((arg.as_str(), false), |(option, _)| (option, true));
        if option.starts_with('-') && !option.starts_with("--") && (option.len() > 2 || inline) {
            return true;
        }
        if takes_value(option)
            || matches!(
                option,
                "-R" | "--repo"
                    | "-B"
                    | "--base"
                    | "-H"
                    | "--head"
                    | "-p"
                    | "-T"
                    | "--template"
                    | "--attach"
            )
        {
            if !inline {
                index += 1;
                if index >= args.len() {
                    return true;
                }
            }
        } else if !matches!(
            option,
            "-d" | "--draft"
                | "--dry-run"
                | "-e"
                | "--editor"
                | "-f"
                | "--fill"
                | "--fill-first"
                | "--fill-verbose"
                | "--no-maintainer-edit"
                | "-w"
                | "--web"
                | "--help"
        ) {
            return true;
        }
        index += 1;
    }
    false
}

fn has_explicit_foreign_api_host(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("gh")
        || args.get(1).map(String::as_str) != Some("api")
    {
        return false;
    }
    let api_index = 1;
    for (index, arg) in args.iter().enumerate().skip(api_index + 1) {
        if let Some(host) = arg.strip_prefix("--hostname=")
            && !is_github_api_host(host)
        {
            return true;
        }
        if arg == "--hostname"
            && args
                .get(index + 1)
                .is_some_and(|host| !is_github_api_host(host))
        {
            return true;
        }
        if let Some(path) = arg.strip_prefix("https://") {
            let host = path.split('/').next().unwrap_or_default();
            if !is_github_api_host(host) {
                return true;
            }
        }
    }
    false
}

fn is_github_api_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("api.github.com") || host.eq_ignore_ascii_case("github.com")
}

fn record_completed_non_candidate_call(db: &mut Connection, event: &Value) -> Result<()> {
    if event.get("hook_event_name").and_then(Value::as_str) != Some("PostToolUse") {
        return Ok(());
    }
    let (Some(session), Some(turn), Some(call)) = (
        nonempty(event.get("session_id").and_then(Value::as_str)),
        nonempty(event.get("turn_id").and_then(Value::as_str)),
        nonempty(event.get("tool_use_id").and_then(Value::as_str)),
    ) else {
        return Ok(());
    };
    let input_digest = event
        .get("tool_input")
        .and_then(|input| input_digest(input).ok().flatten());
    if input_digest.is_none() {
        return Ok(());
    }
    db.execute(
        "UPDATE pr_hook_pre_observations SET state='completed',reason='tool call completed without a PR candidate'
         WHERE session_id=?1 AND turn_id=?2 AND tool_use_id=?3 AND input_digest=?4 AND state='pending'",
        params![session, turn, call, input_digest],
    )?;
    Ok(())
}

fn retryable_http_failure(status: u16, body: &Value) -> Option<&'static str> {
    match status {
        429 => Some("GitHub API rate limited"),
        500 | 502 | 503 | 504 => Some("GitHub API temporarily unavailable"),
        403 if body
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.to_ascii_lowercase().contains("rate limit")) =>
        {
            Some("GitHub API rate limited")
        }
        _ => None,
    }
}

#[derive(Debug)]
struct StoredCandidate {
    candidate: PrCandidate,
    pre_id: Option<i64>,
    state: CandidateState,
    session_id: Option<String>,
    turn_id: Option<String>,
    tool_use_id: Option<String>,
    tool_name: String,
    input_digest: Option<String>,
    exact_id_correlation: bool,
    raw_creation_result: bool,
}

fn load_candidate_for_verify(db: &Connection, id: i64) -> Result<Option<StoredCandidate>> {
    let row = db
        .query_row(
            "SELECT session_id,turn_id,tool_use_id,tool_name,input_digest,number,url,pre_id,state,
                    exact_id_correlation,raw_creation_result
             FROM pr_hook_candidates WHERE id=?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, bool>(9)?,
                    row.get::<_, bool>(10)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            session_id,
            turn_id,
            tool_use_id,
            tool_name,
            input_digest,
            number,
            url,
            pre_id,
            state,
            exact_id_correlation,
            raw_creation_result,
        )| {
            Ok(StoredCandidate {
                candidate: PrCandidate {
                    tool_use_id: tool_use_id.clone().unwrap_or_default(),
                    number: u64::try_from(number).context("invalid stored PR number")?,
                    url,
                },
                pre_id,
                state: CandidateState::from_str(&state)
                    .ok_or_else(|| anyhow!("unknown persisted candidate state"))?,
                session_id,
                turn_id,
                tool_use_id,
                tool_name,
                input_digest,
                exact_id_correlation,
                raw_creation_result,
            })
        },
    )
    .transpose()
}

#[derive(Debug)]
struct StoredPre {
    state: String,
    observed_at_ms: i64,
    session_id: Option<String>,
    turn_id: Option<String>,
    tool_use_id: Option<String>,
    tool_name: Option<String>,
    input_digest: Option<String>,
    repository: Option<String>,
    head_ref: Option<String>,
    base_ref: Option<String>,
    author_login: Option<String>,
    gh_provenance: Option<String>,
}

fn load_pre_observation(db: &Connection, id: i64) -> Result<Option<StoredPre>> {
    Ok(db
        .query_row(
            "SELECT state,observed_at_ms,session_id,turn_id,tool_use_id,tool_name,input_digest,
                    repository,head_ref,base_ref,author_login,gh_provenance
             FROM pr_hook_pre_observations WHERE id=?1",
            [id],
            |row| {
                Ok(StoredPre {
                    state: row.get(0)?,
                    observed_at_ms: row.get(1)?,
                    session_id: row.get(2)?,
                    turn_id: row.get(3)?,
                    tool_use_id: row.get(4)?,
                    tool_name: row.get(5)?,
                    input_digest: row.get(6)?,
                    repository: row.get(7)?,
                    head_ref: row.get(8)?,
                    base_ref: row.get(9)?,
                    author_login: row.get(10)?,
                    gh_provenance: row.get(11)?,
                })
            },
        )
        .optional()?)
}

fn load_plausible_pre_observations(
    db: &Connection,
    session_id: &str,
    turn_id: &str,
    candidate_repo: &str,
    correlated_pre_id: i64,
    correlated_exact_call: bool,
) -> Result<Vec<PreToolUseObservation>> {
    let ids = {
        let mut statement = db.prepare(
            "SELECT p.id FROM pr_hook_pre_observations p
             WHERE p.session_id=?1 AND p.turn_id=?2 AND (
                 p.state='pending' OR (p.state='linked' AND NOT EXISTS (
                     SELECT 1 FROM pr_hook_candidates c
                     WHERE c.pre_id=p.id AND c.state='verified'
                 ))
             )",
        )?;
        statement
            .query_map(params![session_id, turn_id], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut observations = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(pre) = load_pre_observation(db, id)? else {
            continue;
        };
        observations.push(PreToolUseObservation {
            observed_at_unix_ms: pre.observed_at_ms,
            repository: pre.repository.unwrap_or_else(|| candidate_repo.to_owned()),
            head_ref: pre.head_ref,
            base_ref: pre.base_ref,
            author_login: pre.author_login,
            exact_call_and_result: id == correlated_pre_id && correlated_exact_call,
        });
    }
    Ok(observations)
}

fn candidate_record(db: &Connection, id: i64) -> Result<Option<CandidateRecord>> {
    let row = db
        .query_row(
            "SELECT id,session_id,turn_id,tool_use_id,number,url,state,reason,get_status,verified_json,
                    consumed_at_ms,retry_count,next_retry_at_ms,work_claim_until_ms
             FROM pr_hook_candidates WHERE id=?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<u16>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, u32>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            id,
            session_id,
            turn_id,
            tool_use_id,
            number,
            url,
            state,
            reason,
            get_status,
            verified_json,
            consumed_at_ms,
            retry_count,
            next_retry_at_ms,
            work_claim_until_ms,
        )| {
            let number = u64::try_from(number).context("invalid stored PR number")?;
            Ok(CandidateRecord {
                id,
                session_id,
                turn_id,
                tool_use_id,
                number,
                url,
                state: CandidateState::from_str(&state)
                    .ok_or_else(|| anyhow!("unknown persisted candidate state"))?,
                reason,
                get_status,
                verified: verified_json
                    .map(|json| parse_verified_json(&json))
                    .transpose()?,
                consumed_at_ms,
                retry_count,
                next_retry_at_ms,
                work_claim_until_ms,
            })
        },
    )
    .transpose()
}

fn set_candidate_state(
    db: &Connection,
    id: i64,
    state: CandidateState,
    expected: (CandidateState, i64),
    reason: Option<&str>,
    get_status: Option<u16>,
    verified: Option<&VerifiedPullRequest>,
) -> Result<bool> {
    let (expected_state, expected_lease_until) = expected;
    let verified_json = verified.map(verified_to_json).transpose()?;
    let retry_count: u32 = db.query_row(
        "SELECT retry_count FROM pr_hook_candidates WHERE id=?1",
        [id],
        |row| row.get(0),
    )?;
    let retryable = matches!(
        state,
        CandidateState::Timeout | CandidateState::TransportError
    );
    let next_retry = if retryable {
        let seconds = 30_i64.saturating_mul(1_i64 << retry_count.min(7)).min(3600);
        Some(unix_now_ms().saturating_add(seconds * 1000))
    } else {
        None
    };
    db.execute(
        "UPDATE pr_hook_candidates SET state=?1,reason=?2,get_status=?3,
         verified_json=COALESCE(?4,verified_json),
         retry_count=retry_count+CASE WHEN ?1 IN ('timeout','transport_error') THEN 1 ELSE 0 END,
         next_retry_at_ms=?5,work_claim_until_ms=NULL,updated_at_ms=?6
         WHERE id=?7 AND state=?8 AND work_claim_until_ms=?9",
        params![
            state.as_str(),
            reason,
            get_status,
            verified_json,
            next_retry,
            unix_now_ms(),
            id,
            expected_state.as_str(),
            expected_lease_until
        ],
    )?;
    Ok(db.changes() == 1)
}

fn verified_to_json(pr: &VerifiedPullRequest) -> Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "number": pr.number,
        "repository": pr.repository,
        "url": pr.url,
        "created_at": pr.created_at,
        "head_ref": pr.head_ref,
        "base_ref": pr.base_ref,
        "author_login": pr.author_login,
    }))?)
}

fn parse_verified_json(serialized: &str) -> Result<VerifiedPullRequest> {
    let value: Value = serde_json::from_str(serialized)?;
    Ok(VerifiedPullRequest {
        number: value["number"]
            .as_u64()
            .context("invalid stored PR number")?,
        repository: value["repository"]
            .as_str()
            .context("invalid stored repository")?
            .to_owned(),
        url: value["url"]
            .as_str()
            .context("invalid stored PR URL")?
            .to_owned(),
        created_at: value["created_at"].as_str().map(str::to_owned),
        head_ref: value["head_ref"].as_str().map(str::to_owned),
        base_ref: value["base_ref"].as_str().map(str::to_owned),
        author_login: value["author_login"].as_str().map(str::to_owned),
    })
}

fn parse_candidate_preserving_missing_id(event: &Value) -> Option<(PrCandidate, Option<String>)> {
    let tool_use_id = nonempty(event.get("tool_use_id").and_then(Value::as_str));
    if let Some(candidate) = parse_pr_candidate(event) {
        return Some((candidate, tool_use_id));
    }
    if tool_use_id.is_some() {
        return None;
    }
    let mut event = event.clone();
    event["tool_use_id"] = Value::String("missing-tool-use-id".into());
    parse_pr_candidate(&event).map(|candidate| (candidate, None))
}

fn is_pr_creation_intent(tool_name: &str, input: &Value) -> bool {
    if tool_name == MCP_CREATE_PR_TOOL {
        return true;
    }
    if tool_name != "Bash" {
        return false;
    }
    let Some(command) = input.get("command").and_then(Value::as_str) else {
        return false;
    };
    let Some(tokens) = shell_tokens(command) else {
        return false;
    };
    if tokens.first().map(String::as_str) != Some("gh") {
        return false;
    }
    match (
        tokens.get(1).map(String::as_str),
        tokens.get(2).map(String::as_str),
    ) {
        (Some("pr"), Some("create")) => !crate::pr_hook::gh_pr_has_dry_run(&tokens[3..]),
        (Some("api"), _) => crate::pr_hook::parse_gh_api_create(&tokens).is_some(),
        _ => false,
    }
}

fn effective_creation_repository(
    tool_name: &str,
    input: &Value,
    explicit: Option<String>,
    gh_repo: Option<&str>,
) -> Option<String> {
    if explicit.is_some() {
        return explicit;
    }
    if tool_name == "Bash"
        && input
            .get("command")
            .and_then(Value::as_str)
            .and_then(shell_tokens)
            .is_some_and(|args| {
                args.get(0..3)
                    .is_some_and(|parts| parts == ["gh", "pr", "create"])
            })
    {
        return gh_repo
            .and_then(crate::pr_hook::normalize_repository)
            .map(str::to_owned);
    }
    None
}

fn intent_metadata(
    tool_name: &str,
    input: &Value,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    if tool_name == MCP_CREATE_PR_TOOL {
        return (
            input
                .get("repository_full_name")
                .and_then(Value::as_str)
                .and_then(safe_repository)
                .map(str::to_owned),
            input
                .get("head")
                .and_then(Value::as_str)
                .and_then(safe_ref)
                .map(str::to_owned),
            input
                .get("base")
                .and_then(Value::as_str)
                .and_then(safe_ref)
                .map(str::to_owned),
            input
                .get("author_login")
                .and_then(Value::as_str)
                .and_then(safe_login)
                .map(str::to_owned),
        );
    }
    let Some(command) = input.get("command").and_then(Value::as_str) else {
        return (None, None, None, None);
    };
    let Some(tokens) = shell_tokens(command) else {
        return (None, None, None, None);
    };
    if tokens.first().map(String::as_str) == Some("gh")
        && tokens.get(1).map(String::as_str) == Some("api")
    {
        return (None, None, None, None);
    }
    if tokens.first().map(String::as_str) != Some("gh")
        || tokens.get(1).map(String::as_str) != Some("pr")
        || tokens.get(2).map(String::as_str) != Some("create")
    {
        return (None, None, None, None);
    }
    let mut repo = None;
    let mut head = None;
    let mut base = None;
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if matches!(token, "-R" | "--repo" | "--head" | "-H" | "--base" | "-B") {
            let value = tokens.get(index + 1).map(String::as_str);
            match token {
                "-R" | "--repo" => repo = value.and_then(safe_repository).map(str::to_owned),
                "--head" | "-H" => head = value.and_then(safe_ref).map(str::to_owned),
                "--base" | "-B" => base = value.and_then(safe_ref).map(str::to_owned),
                _ => {}
            }
            index += 1;
        } else if takes_value(token) {
            index += 1;
        } else {
            if let Some(value) = token.strip_prefix("--repo=") {
                repo = safe_repository(value).map(str::to_owned);
            } else if let Some(value) = token.strip_prefix("--head=") {
                head = safe_ref(value).map(str::to_owned);
            } else if let Some(value) = token.strip_prefix("--base=") {
                base = safe_ref(value).map(str::to_owned);
            }
        }
        index += 1;
    }
    (repo, head, base, None)
}

fn takes_value(option: &str) -> bool {
    matches!(
        option,
        "-a" | "--assignee"
            | "-b"
            | "--body"
            | "-F"
            | "--body-file"
            | "-l"
            | "--label"
            | "-m"
            | "--milestone"
            | "--project"
            | "-p"
            | "-T"
            | "--template"
            | "--attach"
            | "-r"
            | "--reviewer"
            | "--recover"
            | "-t"
            | "--title"
    )
}

fn shell_tokens(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' && quote != Some('\'') {
            match chars.next()? {
                '\n' => continue,
                escaped => {
                    word.push(escaped);
                    started = true;
                }
            }
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
            started = true;
        } else if quote.is_none() && ch.is_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(ch);
            started = true;
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

fn safe_repository(value: &str) -> Option<&str> {
    crate::pr_hook::normalize_repository(value)
}

fn safe_ref(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 255
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')))
    .then_some(value)
}

fn safe_login(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 39
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
    .then_some(value)
}

fn command_output_can_be_filtered(tool_name: &str, input: Option<&Value>) -> bool {
    if tool_name != "Bash" {
        return false;
    }
    let Some(command) = input
        .and_then(|value| value.get("command"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Some(tokens) = shell_tokens(command) else {
        return false;
    };
    if tokens.first().map(String::as_str) != Some("gh")
        || tokens.get(1).map(String::as_str) != Some("api")
    {
        return false;
    }
    tokens.iter().any(|token| {
        matches!(token.as_str(), "-q" | "--jq" | "-t" | "--template")
            || token.starts_with("--jq=")
            || token.starts_with("--template=")
    })
}

fn candidate_invocation_key(
    session_id: Option<&str>,
    turn_id: Option<&str>,
    tool_use_id: Option<&str>,
    tool_name: &str,
    digest: Option<&str>,
    number: u64,
    url: &str,
) -> Result<String> {
    let identity =
        if let (Some(session), Some(turn), Some(call)) = (session_id, turn_id, tool_use_id) {
            serde_json::json!(["call", session, turn, call])
        } else {
            serde_json::json!([
                "fallback", session_id, turn_id, tool_name, digest, number, url
            ])
        };
    let encoded = serde_json::to_vec(&identity)?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn input_digest(input: &Value) -> Result<Option<String>> {
    let encoded = serde_json::to_vec(input)?;
    let digest = Sha256::digest(encoded);
    Ok(Some(format!("{digest:x}")))
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn repository_from_pr_url(url: &str) -> Option<String> {
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    (parts.next()? == "pull").then(|| format!("{owner}/{repo}"))
}

fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

impl TransportFailure {
    fn safe_label(&self) -> &'static str {
        match self {
            Self::Timeout => "GitHub GET timed out",
            Self::Network => "GitHub GET transport failed",
            Self::Other => "GitHub GET failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn distinct_gh_executables_have_distinct_resolved_paths() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        for path in [&first, &second] {
            std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_ne!(resolve_executable(&first), resolve_executable(&second));
    }

    #[test]
    fn inferred_repository_uses_tokens_and_explicit_override() {
        let input = json!({"command":"gh  pr\tcreate --title test"});
        assert_eq!(
            effective_creation_repository("Bash", &input, None, Some("github.com/other/repo"))
                .as_deref(),
            Some("other/repo")
        );
        assert_eq!(
            effective_creation_repository(
                "Bash",
                &input,
                Some("acme/widget".into()),
                Some("other/repo")
            )
            .as_deref(),
            Some("acme/widget")
        );
    }

    #[test]
    fn git_remote_evidence_rejects_enterprise_mixed_and_rewrites() {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .unwrap();
            assert!(status.success());
        };
        run(&["init", "--quiet"]);
        run(&[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widget.git",
        ]);
        let public = local_github_remote_fingerprint(dir.path()).unwrap();
        run(&[
            "config",
            "--local",
            "remote.origin.gh-resolved",
            "acme/widget",
        ]);
        assert!(local_github_remote_fingerprint(dir.path()).is_some());
        run(&["config", "--local", "--unset", "remote.origin.gh-resolved"]);
        run(&[
            "remote",
            "add",
            "upstream",
            "git@github.com:acme/upstream.git",
        ]);
        assert_ne!(local_github_remote_fingerprint(dir.path()).unwrap(), public);
        run(&[
            "remote",
            "add",
            "enterprise",
            "https://enterprise.example/acme/widget.git",
        ]);
        assert!(local_github_remote_fingerprint(dir.path()).is_none());
        run(&["remote", "remove", "enterprise"]);
        run(&[
            "config",
            "--local",
            "url.https://enterprise.example/.insteadOf",
            "https://github.com/",
        ]);
        assert!(local_github_remote_fingerprint(dir.path()).is_none());
    }

    #[test]
    fn unrelated_bash_never_invokes_gh_configuration() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let gh = dir.path().join("gh");
        let sentinel = dir.path().join("called");
        std::fs::write(&gh, format!("#!/bin/sh\ntouch '{}'\n", sentinel.display())).unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o700)).unwrap();
        TEST_GH_PROVENANCE.with(|state| {
            *state.borrow_mut() = Some(format!("fixture-executable:{}", gh.display()))
        });
        let mut db = Connection::open_in_memory().unwrap();
        assert_eq!(
            record_pre_tool_use(&mut db, &pre("s", "t", "call", "echo hi"), 1, 60_000).unwrap(),
            PreRecord::Ignored
        );
        assert!(!sentinel.exists());
    }

    #[test]
    fn isolated_hook_checks_real_gh_and_git_across_path_change() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        const PHASE: &str = "CODEX_WAKE_TEST_PROVENANCE_PHASE";
        if let Ok(phase) = std::env::var(PHASE) {
            TEST_GH_PROVENANCE.with(|state| *state.borrow_mut() = None);
            let cwd = std::env::current_dir().unwrap();
            let path = std::env::var_os("CODEX_WAKE_TEST_PROVENANCE_DB").unwrap();
            let mut db = Connection::open(path).unwrap();
            let command = std::env::var("CODEX_WAKE_TEST_PROVENANCE_COMMAND").unwrap();
            if phase == "pre" {
                let mut event = pre("s", "t", "call", &command);
                event["cwd"] = json!(cwd);
                record_pre_tool_use(&mut db, &event, 1_735_787_045_500, 60_000).unwrap();
            } else {
                let transport = GhCliPullRequestGet::new(
                    std::env::var_os("CODEX_WAKE_TEST_GET_GH").unwrap_or_else(|| "gh".into()),
                );
                let result = if phase == "retry" {
                    let old = candidate_status(&db, 1).unwrap().unwrap();
                    let claim =
                        claim_due_retries(&mut db, old.next_retry_at_ms.unwrap(), 60_000, 1)
                            .unwrap()
                            .pop()
                            .unwrap();
                    retry_candidate(
                        &mut db,
                        claim.id,
                        claim.work_claim_until_ms.unwrap(),
                        &transport,
                        Duration::from_secs(2),
                        60_000,
                    )
                    .unwrap()
                } else {
                    let mut event = post("s", "t", Some("call"), &command);
                    event["cwd"] = json!(cwd);
                    if phase == "timeout" {
                        let timeout = FixtureTransport {
                            response: Err(TransportFailure::Timeout),
                            calls: Cell::new(0),
                        };
                        handle_post_tool_use(
                            &mut db,
                            &event,
                            &timeout,
                            Duration::from_secs(2),
                            60_000,
                        )
                        .unwrap()
                    } else {
                        handle_post_tool_use(
                            &mut db,
                            &event,
                            &transport,
                            Duration::from_secs(2),
                            60_000,
                        )
                        .unwrap()
                    }
                };
                let HandleResult::Candidate { record, .. } = result else {
                    panic!("candidate missing")
                };
                let expected = std::env::var("CODEX_WAKE_TEST_PROVENANCE_EXPECTED").unwrap();
                assert_eq!(record.state.as_str(), expected);
            }
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let git = |args: &[&str]| {
            let mut command = Command::new("git");
            command
                .arg("-C")
                .arg(&repo)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null");
            for (key, _) in std::env::vars_os() {
                if key.to_string_lossy().starts_with("GIT_")
                    && key != "GIT_CONFIG_NOSYSTEM"
                    && key != "GIT_CONFIG_GLOBAL"
                {
                    command.env_remove(key);
                }
            }
            assert!(command.status().unwrap().success());
        };
        git(&["init", "--quiet"]);
        git(&[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widget.git",
        ]);
        let bin = root.path().join("gh-real");
        std::fs::write(
            &bin,
            "#!/bin/sh\nif [ \"$1\" = --version ]; then if [ \"$CODEX_WAKE_TEST_UNKNOWN\" = 1 ]; then printf 'gh version 2.98.0\\n'; elif [ \"$CODEX_WAKE_TEST_LEGACY\" = 1 ]; then printf 'gh version 2.99.0\\n'; else printf 'gh version 2.103.3\\n'; fi; elif [ \"$1\" = auth ]; then exit 19; elif [ \"$1\" = api ]; then [ \"$2\" = https://api.github.com/repos/acme/widget/pulls/42 ] && [ \"$3\" = --method ] && [ \"$4\" = GET ] && [ \"$5\" = --include ] || exit 9; printf 'HTTP/2 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{\"number\":42,\"html_url\":\"https://github.com/acme/widget/pull/42\",\"created_at\":\"2025-01-02T03:04:06Z\",\"base\":{\"ref\":\"main\",\"repo\":{\"full_name\":\"acme/widget\"}},\"head\":{\"ref\":\"feature\"},\"user\":{\"login\":\"alice\"}}'; elif [ \"$CODEX_WAKE_TEST_GATEWAY\" = 1 ]; then printf 'api_host=gateway.example\\nhttp_unix_socket=\\n'; else printf 'api_host=\\nhttp_unix_socket=\\n'; fi\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let unsupported_get = root.path().join("unsupported-get-gh");
        std::fs::write(&unsupported_get, "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'gh version 2.104.0\\n'; elif [ \"$1\" = config ]; then printf 'api_host=\\nhttp_unix_socket=\\n'; else touch \"$0.called\"; fi\n").unwrap();
        std::fs::set_permissions(&unsupported_get, std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        symlink(&bin, first.join("gh")).unwrap();
        symlink(&bin, second.join("gh")).unwrap();
        let binary = std::env::current_exe().unwrap();
        let run = |phase: &str,
                   path: &std::path::Path,
                   db: &std::path::Path,
                   command: &str,
                   expected: &str| {
            let filename = db.file_name().unwrap().to_string_lossy();
            let config_dir = root.path().join(format!("gh-config-{filename}"));
            std::fs::create_dir_all(&config_dir).unwrap();
            std::fs::write(config_dir.join("config.yml"), "git_protocol: https\n").unwrap();
            let host = if filename.starts_with("foreign-default-")
                || filename.starts_with("host-override-")
            {
                "enterprise.example"
            } else {
                "github.com"
            };
            std::fs::write(
                config_dir.join("hosts.yml"),
                format!("{host}:\n  user: fixture\n  oauth_token: synthetic_token\n"),
            )
            .unwrap();
            let mut child = Command::new(&binary);
            child.env_clear().env("HOME", root.path()).args(["--exact", "pr_observation::tests::isolated_hook_checks_real_gh_and_git_across_path_change", "--nocapture"])
                .current_dir(&repo).env(PHASE, phase).env("CODEX_WAKE_TEST_PROVENANCE_DB", db)
                .env("CODEX_WAKE_TEST_PROVENANCE_COMMAND", command).env("CODEX_WAKE_TEST_PROVENANCE_EXPECTED", expected)
                .env("CODEX_WAKE_TEST_GATEWAY", if db.file_name().unwrap().to_string_lossy().starts_with("gateway-") { "1" } else { "0" })
                .env("CODEX_WAKE_TEST_LEGACY", if db.file_name().unwrap().to_string_lossy().starts_with("legacy-") { "1" } else { "0" })
                .env("CODEX_WAKE_TEST_UNKNOWN", if filename.starts_with("unknown-") { "1" } else { "0" })
                .env("CODEX_WAKE_TEST_DEFAULT_FOREIGN", if db.file_name().unwrap().to_string_lossy().starts_with("foreign-default-") { "1" } else { "0" })
                .env("GH_REPO", if db.file_name().unwrap().to_string_lossy().starts_with("mismatch-") { "github.com/other/repo" } else { "" }).env_remove("BASH_ENV").env_remove("BASH_FUNC_gh%%")
                .env("GH_CONFIG_DIR", &config_dir)
                .env("PATH", format!("{}:/usr/bin:/bin", path.display()))
                .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null");
            if filename.starts_with("get-unknown-") {
                child.env("CODEX_WAKE_TEST_GET_GH", &unsupported_get);
            }
            if filename.starts_with("default-")
                || filename.starts_with("foreign-default-")
                || filename.starts_with("legacy-")
            {
                child.env_remove("GH_HOST");
            } else {
                child.env("GH_HOST", "github.com");
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "child test failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "child test did not run"
            );
        };
        for (index, command) in [
            "gh pr create --title change",
            "gh api -X POST repos/acme/widget/pulls -f title=test",
        ]
        .iter()
        .enumerate()
        {
            let db = root.path().join(format!("direct-{index}.sqlite"));
            run("pre", &first, &db, command, "verified");
            run("post", &second, &db, command, "verified");
            let retry = root.path().join(format!("retry-{index}.sqlite"));
            run("pre", &first, &retry, command, "timeout");
            run("timeout", &first, &retry, command, "timeout");
            run("retry", &second, &retry, command, "verified");
            let default = root.path().join(format!("default-{index}.sqlite"));
            run("pre", &first, &default, command, "verified");
            run("post", &second, &default, command, "verified");
            if index == 1 {
                let legacy = root.path().join("legacy-default.sqlite");
                run("pre", &first, &legacy, command, "verified");
                run("post", &second, &legacy, command, "verified");
                let foreign = root.path().join(format!("foreign-default-{index}.sqlite"));
                run("pre", &first, &foreign, command, "ambiguous");
                run("post", &second, &foreign, command, "ambiguous");
            }
            let gateway = root.path().join(format!("gateway-{index}.sqlite"));
            run("pre", &first, &gateway, command, "ambiguous");
            run("post", &second, &gateway, command, "ambiguous");
        }
        let unknown = root.path().join("unknown-version.sqlite");
        let command = "gh api -X POST repos/acme/widget/pulls -f title=test";
        run("pre", &first, &unknown, command, "ambiguous");
        run("post", &second, &unknown, command, "ambiguous");
        let override_host = root.path().join("host-override-enterprise.sqlite");
        let command = "gh api -X POST repos/acme/widget/pulls -f title=test";
        run("pre", &first, &override_host, command, "verified");
        run("post", &second, &override_host, command, "verified");
        let unknown_get = root.path().join("get-unknown-version.sqlite");
        let command = "gh api -X POST repos/acme/widget/pulls -f title=test";
        run("pre", &first, &unknown_get, command, "ambiguous");
        run("post", &second, &unknown_get, command, "ambiguous");
        assert!(!root.path().join("unsupported-get-gh.called").exists());
        let mismatch = root.path().join("mismatch-no-override.sqlite");
        run(
            "pre",
            &first,
            &mismatch,
            "gh  pr create --title change",
            "ambiguous",
        );
        run(
            "post",
            &second,
            &mismatch,
            "gh  pr create --title change",
            "ambiguous",
        );
        let override_db = root.path().join("mismatch-override.sqlite");
        run(
            "pre",
            &first,
            &override_db,
            "gh pr create -R acme/widget --title change",
            "verified",
        );
        run(
            "post",
            &second,
            &override_db,
            "gh pr create -R acme/widget --title change",
            "verified",
        );
        let changed = root.path().join("remote-changed.sqlite");
        run(
            "pre",
            &first,
            &changed,
            "gh pr create --title change",
            "ambiguous",
        );
        git(&[
            "remote",
            "set-url",
            "origin",
            "https://enterprise.example/acme/widget.git",
        ]);
        run(
            "post",
            &second,
            &changed,
            "gh pr create --title change",
            "ambiguous",
        );
        let db = root.path().join("enterprise.sqlite");
        let command = "gh pr create --title change";
        run("pre", &first, &db, command, "ambiguous");
        run("post", &second, &db, command, "ambiguous");
    }

    #[test]
    fn local_default_host_reads_config_without_persisting_values() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yml");
        let hosts = dir.path().join("hosts.yml");
        assert_eq!(local_default_host_is_github(dir.path()), Some(true));
        std::fs::write(&config, "git_protocol: https\n").unwrap();
        std::fs::write(
            &hosts,
            "github.com:\n  user: sample\n  oauth_token: synthetic_secret\n",
        )
        .unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), Some(true));
        std::fs::write(&hosts, "enterprise.example:\n  user: sample\n").unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), Some(false));
        std::fs::write(
            &hosts,
            "enterprise.example:\n  user: sample\ngithub.com:\n  user: sample\n",
        )
        .unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), Some(true));
        std::fs::remove_file(&hosts).unwrap();
        std::fs::write(&config, "hosts:\n  enterprise.example:\n    user: sample\n").unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), Some(false));
        std::fs::write(&hosts, "github.com:\n  user: sample\n").unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), None);
        std::fs::write(&config, "git_protocol: https\n").unwrap();
        std::fs::write(&hosts, "github.com: &alias {}\n").unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), None);
        std::fs::write(
            &hosts,
            "# unsupported! comment\ngithub.com:\n  user: sample\n",
        )
        .unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), None);
        std::fs::write(
            &hosts,
            "github.com:\n  user: sample\n  oauth_token: synthetic!token\n",
        )
        .unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), None);
        std::fs::write(&hosts, "github.com: {}\ngithub.com: {}\n").unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), None);
        std::fs::write(&hosts, "github.com: [invalid\n").unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), None);
        std::fs::remove_file(&hosts).unwrap();
        std::fs::create_dir(&hosts).unwrap();
        assert_eq!(local_default_host_is_github(dir.path()), None);
    }

    #[test]
    fn get_host_check_retries_version_failures_and_rejects_unknown_versions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let gh = dir.path().join("gh");
        std::fs::write(&gh, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            GhCliPullRequestGet::new(&gh).trusted_host(),
            Err(TransportFailure::Network)
        );
        std::fs::write(&gh, "#!/bin/sh\nprintf '\\377'\n").unwrap();
        assert_eq!(
            GhCliPullRequestGet::new(&gh).trusted_host(),
            Err(TransportFailure::Network)
        );
        std::fs::write(&gh, "#!/bin/sh\nprintf 'gh version 2.104.0\\n'\n").unwrap();
        assert_eq!(GhCliPullRequestGet::new(&gh).trusted_host(), Ok(false));
    }

    #[test]
    fn gh_repo_rejects_foreign_or_invalid_hosts() {
        assert!(gh_repo_is_github("owner/repo"));
        assert!(gh_repo_is_github("GitHub.com/owner/repo"));
        assert!(!gh_repo_is_github("foreign.example/owner/repo"));
        assert!(!gh_repo_is_github("owner/"));
    }

    #[test]
    fn legacy_gh_versions_require_a_known_release() {
        assert!(legacy_gh_without_api_host("gh version 2.99.0 (2026-08-01)"));
        assert!(!legacy_gh_without_api_host(
            "gh version 2.100.0 (2026-09-01)"
        ));
        assert!(!legacy_gh_without_api_host("gh version 2.99.0-dev"));
        assert!(!legacy_gh_without_api_host("not gh"));
        assert!(direct_gh_config("http_unix_socket=\napi_host=\n"));
        assert!(!direct_gh_config("http_unix_socket=\n"));
    }

    #[test]
    fn gh_config_requires_direct_host_and_no_unix_socket() {
        assert!(direct_gh_config("api_host=\nhttp_unix_socket=\n"));
        assert!(!direct_gh_config(
            "api_host=gateway.example\nhttp_unix_socket=\n"
        ));
        assert!(!direct_gh_config(
            "api_host=\nhttp_unix_socket=/tmp/gh.sock\n"
        ));
        assert!(!direct_gh_config("api_host=\n"));
        assert!(!direct_gh_config(
            "api_host=\napi_host=evil\nhttp_unix_socket=\n"
        ));
    }

    #[test]
    fn gh_create_flows_accept_direct_config_and_reject_gateway() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake_gh = dir.path().join("gh");
        for command in [
            "gh pr create -R acme/widget --title change",
            "gh api -X POST repos/acme/widget/pulls -f title=test",
        ] {
            for (config, expected) in [
                ("api_host=\nhttp_unix_socket=\n", CandidateState::Verified),
                (
                    "api_host=gateway.example\nhttp_unix_socket=\n",
                    CandidateState::Ambiguous,
                ),
            ] {
                std::fs::write(&fake_gh, format!("#!/bin/sh\nprintf '%s' '{}'\n", config)).unwrap();
                std::fs::set_permissions(&fake_gh, std::fs::Permissions::from_mode(0o700)).unwrap();
                TEST_GH_PROVENANCE.with(|state| {
                    *state.borrow_mut() = Some(format!("fixture-executable:{}", fake_gh.display()));
                });
                let mut db = Connection::open_in_memory().unwrap();
                record_pre_tool_use(
                    &mut db,
                    &pre("s", "t", "call", command),
                    1_735_787_045_500,
                    60_000,
                )
                .unwrap();
                let result = handle_post_tool_use(
                    &mut db,
                    &post("s", "t", Some("call"), command),
                    &fixture_transport(),
                    Duration::from_secs(2),
                    60_000,
                )
                .unwrap();
                let HandleResult::Candidate { record, .. } = result else {
                    panic!("candidate missing")
                };
                assert_eq!(record.state, expected);
            }
        }
    }

    #[test]
    fn fake_gh_configuration_is_inspected_without_real_gh() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let gh = dir.path().join("gh");
        for (output, expected) in [
            ("api_host=\nhttp_unix_socket=\n", true),
            ("api_host=gateway.example\nhttp_unix_socket=\n", false),
        ] {
            std::fs::write(&gh, format!("#!/bin/sh\nprintf '%s' '{}'\n", output)).unwrap();
            std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(direct_gh_config_from_command(&gh).unwrap(), expected);
        }
        std::fs::write(&gh, "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'gh version 2.99.0\\n'; else printf 'http_unix_socket=\\n'; fi\n").unwrap();
        assert!(direct_gh_config_from_command(&gh).unwrap());
        std::fs::write(&gh, "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'gh version 2.100.0\\n'; else printf 'http_unix_socket=\\n'; fi\n").unwrap();
        assert!(!direct_gh_config_from_command(&gh).unwrap());
        assert!(direct_gh_config_from_command(&dir.path().join("missing-gh")).is_err());
    }

    #[test]
    fn interrupted_post_capture_retains_url_and_does_not_invent_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let command = "gh pr create -R acme/widget --title change";
        let event = post("s", "t", Some("call"), command);
        let mut db = Connection::open(&path).unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        TEST_INTERRUPT_POST_CAPTURE.with(|flag| flag.set(true));
        let result = handle_post_tool_use(
            &mut db,
            &event,
            &fixture_transport(),
            Duration::from_secs(2),
            60_000,
        );
        TEST_INTERRUPT_POST_CAPTURE.with(|flag| flag.set(false));
        assert!(result.is_err());
        drop(db);
        let mut db = Connection::open(&path).unwrap();
        let record = candidate_status(&db, 1).unwrap().unwrap();
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert_eq!(
            record.reason.as_deref(),
            Some("post provenance capture incomplete")
        );
        assert_eq!(record.url, "https://github.com/acme/widget/pull/42");
        assert!(
            claim_due_retries(&mut db, unix_now_ms(), 60_000, 1)
                .unwrap()
                .is_empty()
        );
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &event,
            &fixture_transport(),
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
    }

    #[test]
    fn unavailable_creation_probe_retains_candidate_for_attention() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create -R acme/widget --title change";
        TEST_GH_PROVENANCE.with(|state| *state.borrow_mut() = Some("ambiguous".into()));
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        TEST_GH_PROVENANCE.with(|state| *state.borrow_mut() = Some("fixture-direct".into()));
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &fixture_transport(),
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert_eq!(
            record.reason.as_deref(),
            Some("creation host provenance is unavailable")
        );
        assert_eq!(record.url, "https://github.com/acme/widget/pull/42");
        assert!(verified.is_none());
    }

    #[test]
    fn unavailable_post_probe_retains_candidate_for_attention() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create -R acme/widget --title change";
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        TEST_GH_PROVENANCE.with(|state| *state.borrow_mut() = Some("ambiguous".into()));
        let result = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &fixture_transport(),
            Duration::from_secs(2),
            60_000,
        );
        TEST_GH_PROVENANCE.with(|state| *state.borrow_mut() = Some("fixture-direct".into()));
        let HandleResult::Candidate { record, verified } = result.unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert_eq!(
            record.reason.as_deref(),
            Some("creation host provenance is unavailable")
        );
        assert_eq!(record.url, "https://github.com/acme/widget/pull/42");
        assert!(verified.is_none());
        assert!(
            claim_due_retries(&mut db, unix_now_ms(), 60_000, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn host_checks_hold_lease_against_second_connection_for_initial_and_retry() {
        struct CompetingWorker {
            db: std::cell::RefCell<Connection>,
            checks: std::cell::Cell<usize>,
            fail_get: bool,
        }
        impl PullRequestGetTransport for CompetingWorker {
            fn trusted_host(&self) -> std::result::Result<bool, TransportFailure> {
                // Past the old timeout+5s lease, but before the bounded probe budget.
                let now = unix_now_ms().saturating_add(11_000);
                let claimed = claim_due_retries(&mut self.db.borrow_mut(), now, 60_000, 1).unwrap();
                assert!(claimed.is_empty());
                self.checks.set(self.checks.get() + 1);
                Ok(true)
            }
            fn get_pull_request(
                &self,
                _: &str,
                _: u64,
                _: Duration,
            ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
                if self.fail_get {
                    Err(TransportFailure::Timeout)
                } else {
                    Ok(fixture_response())
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let mut db = Connection::open(&path).unwrap();
        let command = "gh pr create -R acme/widget --title change";
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let first = CompetingWorker {
            db: std::cell::RefCell::new(Connection::open(&path).unwrap()),
            checks: std::cell::Cell::new(0),
            fail_get: true,
        };
        let HandleResult::Candidate { record, .. } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &first,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Timeout);
        assert_eq!(first.checks.get(), 1);
        db.execute("UPDATE pr_hook_candidates SET next_retry_at_ms=0", [])
            .unwrap();
        let claim = claim_due_retries(&mut db, unix_now_ms(), 10_000, 1)
            .unwrap()
            .pop()
            .unwrap();
        let second = CompetingWorker {
            db: std::cell::RefCell::new(Connection::open(&path).unwrap()),
            checks: std::cell::Cell::new(0),
            fail_get: false,
        };
        let HandleResult::Candidate { record, .. } = retry_candidate(
            &mut db,
            claim.id,
            claim.work_claim_until_ms.unwrap(),
            &second,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Verified);
        assert_eq!(second.checks.get(), 2);
    }

    #[test]
    fn transient_verification_host_failure_is_retryable() {
        struct FlakyHost(std::cell::Cell<bool>);
        impl PullRequestGetTransport for FlakyHost {
            fn trusted_host(&self) -> std::result::Result<bool, TransportFailure> {
                if self.0.replace(false) {
                    Err(TransportFailure::Network)
                } else {
                    Ok(true)
                }
            }
            fn get_pull_request(
                &self,
                _: &str,
                _: u64,
                _: Duration,
            ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
                Ok(fixture_response())
            }
        }
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create -R acme/widget --title change";
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let transport = FlakyHost(std::cell::Cell::new(true));
        let HandleResult::Candidate { record, .. } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::TransportError);
        let claim = claim_due_retries(&mut db, record.next_retry_at_ms.unwrap(), 60_000, 1)
            .unwrap()
            .pop()
            .unwrap();
        let HandleResult::Candidate { record, .. } = retry_candidate(
            &mut db,
            claim.id,
            claim.work_claim_until_ms.unwrap(),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Verified);
    }

    #[test]
    fn bash_startup_override_prevents_host_attribution() {
        use std::ffi::OsStr;
        assert!(bash_environment_is_inspectable(None, None));
        assert!(!bash_environment_is_inspectable(
            Some(OsStr::new("/tmp/startup")),
            None
        ));
        assert!(!bash_environment_is_inspectable(
            None,
            Some(OsStr::new("() { fake; }"))
        ));
        assert!(
            direct_gh_config("api_host=\nhttp_unix_socket=\n"),
            "direct GET does not use Bash startup files"
        );
    }

    #[test]
    fn changed_verification_host_during_get_is_ambiguous() {
        struct Changed(Cell<usize>);
        impl PullRequestGetTransport for Changed {
            fn trusted_host(&self) -> std::result::Result<bool, TransportFailure> {
                let calls = self.0.get();
                self.0.set(calls + 1);
                Ok(calls == 0)
            }
            fn get_pull_request(
                &self,
                _: &str,
                _: u64,
                _: Duration,
            ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
                Ok(fixture_response())
            }
        }
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s", "t", "call"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &mcp_post("s", "t", "call"),
            &Changed(Cell::new(0)),
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
    }

    #[test]
    fn retry_uses_persisted_creation_evidence_not_receiver_environment() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create --title test";
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let timeout = FixtureTransport {
            response: Err(TransportFailure::Timeout),
            calls: Cell::new(0),
        };
        let HandleResult::Candidate { record, .. } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &timeout,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Timeout);
        TEST_GH_PROVENANCE.with(|state| {
            *state.borrow_mut() = Some("fixture-executable:/nonexistent-different-path/gh".into())
        });
        let claim = claim_due_retries(&mut db, record.next_retry_at_ms.unwrap(), 60_000, 1)
            .unwrap()
            .pop()
            .unwrap();
        let HandleResult::Candidate { record, .. } = retry_candidate(
            &mut db,
            claim.id,
            claim.work_claim_until_ms.unwrap(),
            &fixture_transport(),
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Verified);
    }

    #[test]
    fn old_observations_migrate_without_asserting_provenance() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(&SCHEMA.replace("    gh_provenance TEXT,\n", ""))
            .unwrap();
        db.execute("INSERT INTO pr_hook_pre_observations(observed_at_ms,expires_at_ms,state) VALUES(1,2,'pending')", []).unwrap();
        db.execute("INSERT INTO pr_hook_candidates(tool_name,number,url,invocation_key,state,created_at_ms,updated_at_ms) VALUES('Bash',42,'https://github.com/a/b/pull/42','legacy','verified',1,1)", []).unwrap();
        initialize(&db).unwrap();
        initialize(&db).unwrap();
        let provenance: Option<String> = db
            .query_row(
                "SELECT gh_provenance FROM pr_hook_pre_observations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(provenance.is_none());
        let state: String = db
            .query_row(
                "SELECT state FROM pr_hook_candidates WHERE invocation_key='legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "ambiguous");
    }

    #[test]
    fn missing_or_changed_creation_provenance_stays_ambiguous() {
        for prior in [None, Some("different-snapshot")] {
            let mut db = Connection::open_in_memory().unwrap();
            let command = "gh pr create --title change --body summary";
            record_pre_tool_use(
                &mut db,
                &pre("s", "t", "call", command),
                1_735_787_045_500,
                60_000,
            )
            .unwrap();
            db.execute(
                "UPDATE pr_hook_pre_observations SET gh_provenance=?1",
                [prior],
            )
            .unwrap();
            let transport = fixture_transport();
            let HandleResult::Candidate { record, verified } = handle_post_tool_use(
                &mut db,
                &post("s", "t", Some("call"), command),
                &transport,
                Duration::from_secs(2),
                60_000,
            )
            .unwrap() else {
                panic!("candidate missing")
            };
            assert_eq!(record.state, CandidateState::Ambiguous);
            assert!(verified.is_none());
        }
    }

    #[test]
    fn untrusted_verification_transport_stays_ambiguous_without_fetch() {
        struct Untrusted;
        impl PullRequestGetTransport for Untrusted {
            fn trusted_host(&self) -> std::result::Result<bool, TransportFailure> {
                Ok(false)
            }
            fn get_pull_request(
                &self,
                _: &str,
                _: u64,
                _: Duration,
            ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
                panic!("untrusted verification transport must not fetch")
            }
        }
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s", "t", "call"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &mcp_post("s", "t", "call"),
            &Untrusted,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate missing")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
    }
    use std::cell::Cell;
    use std::sync::mpsc;

    const TRUSTED_API_CREATE: &str =
        "gh api -X POST https://api.github.com/repos/acme/widget/pulls -f title=test";

    struct FixtureTransport {
        response: std::result::Result<GetPullRequestResponse, TransportFailure>,
        calls: Cell<usize>,
    }

    impl PullRequestGetTransport for FixtureTransport {
        fn get_pull_request(
            &self,
            _repository: &str,
            _number: u64,
            _timeout: Duration,
        ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
            self.calls.set(self.calls.get() + 1);
            self.response.clone()
        }
    }

    fn pre(session: &str, turn: &str, call: &str, command: &str) -> Value {
        json!({
            "hook_event_name":"PreToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_use_id":call,
            "tool_name":"Bash",
            "tool_input":{"command":command}
        })
    }

    fn mcp_input() -> Value {
        json!({"repository_full_name":"acme/widget","title":"change"})
    }

    fn mcp_pre(session: &str, turn: &str, call: &str) -> Value {
        json!({
            "hook_event_name":"PreToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_use_id":call,
            "tool_name":MCP_CREATE_PR_TOOL,
            "tool_input":mcp_input()
        })
    }

    fn mcp_post(session: &str, turn: &str, call: &str) -> Value {
        json!({
            "hook_event_name":"PostToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_use_id":call,
            "tool_name":MCP_CREATE_PR_TOOL,
            "tool_input":mcp_input(),
            "tool_response":{"structuredContent":{
                "number":42,
                "html_url":"https://github.com/acme/widget/pull/42"
            }}
        })
    }

    fn post(session: &str, turn: &str, call: Option<&str>, command: &str) -> Value {
        let tool_response = if command.starts_with("gh api ") {
            json!({
                "number":42,
                "html_url":"https://github.com/acme/widget/pull/42",
                "created_at":"2025-01-02T03:04:06Z"
            })
            .to_string()
        } else {
            "https://github.com/acme/widget/pull/42".to_owned()
        };
        let mut value = json!({
            "hook_event_name":"PostToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_name":"Bash",
            "tool_input":{"command":command},
            "tool_response":tool_response
        });
        if let Some(call) = call {
            value["tool_use_id"] = json!(call);
        }
        value
    }

    fn fixture_response() -> GetPullRequestResponse {
        GetPullRequestResponse {
            status: 200,
            observed_at_ms: 1_735_787_047_000,
            body: json!({
                "number":42,
                "html_url":"https://github.com/acme/widget/pull/42",
                "created_at":"2025-01-02T03:04:06Z",
                "base":{"ref":"main","repo":{"full_name":"acme/widget"}},
                "head":{"ref":"feature"},
                "user":{"login":"alice"}
            }),
        }
    }

    fn fixture_transport() -> FixtureTransport {
        FixtureTransport {
            response: Ok(fixture_response()),
            calls: Cell::new(0),
        }
    }

    #[test]
    fn initialize_migrates_legacy_candidates_without_losing_rows() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE pr_hook_candidates (
                id INTEGER PRIMARY KEY, session_id TEXT, turn_id TEXT, tool_use_id TEXT,
                tool_name TEXT NOT NULL, input_digest TEXT, number INTEGER NOT NULL,
                url TEXT NOT NULL, invocation_key TEXT NOT NULL UNIQUE, pre_id INTEGER,
                state TEXT NOT NULL, reason TEXT, get_status INTEGER, verified_json TEXT,
                consumed_at_ms INTEGER, retry_count INTEGER NOT NULL DEFAULT 0,
                next_retry_at_ms INTEGER, work_claim_until_ms INTEGER,
                created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
             );
             INSERT INTO pr_hook_candidates
                (id,tool_name,number,url,invocation_key,state,created_at_ms,updated_at_ms)
             VALUES (7,'Bash',42,'https://github.com/acme/widget/pull/42','legacy','pending',10,11);",
        )
        .unwrap();

        initialize(&db).unwrap();
        initialize(&db).unwrap();

        let (state, created_at, updated_at, exact, raw): (String, i64, i64, bool, bool) = db
            .query_row(
                "SELECT state,created_at_ms,updated_at_ms,exact_id_correlation,raw_creation_result
                 FROM pr_hook_candidates WHERE id=7",
                [],
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
            .unwrap();
        assert_eq!(
            (state.as_str(), created_at, updated_at),
            ("pending", 10, 11)
        );
        assert!(!exact);
        assert!(!raw);
    }

    #[test]
    fn explicit_foreign_gh_api_host_blocks_attribution_at_any_age() {
        let command =
            "gh api --hostname api.attacker.test -X POST repos/acme/widget/pulls -f title=test";
        let observed_at_ms = 1_735_787_044_500;
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            observed_at_ms,
            60_000,
        )
        .unwrap();
        let mut event = post("s", "t", Some("call"), command);
        event["tool_response"] = json!(
            r#"{"number":42,"html_url":"https://github.com/acme/widget/pull/42","created_at":"2025-01-02T03:04:06Z"}"#
        );
        let transport = fixture_transport();
        let HandleResult::Candidate { record, verified } =
            handle_post_tool_use(&mut db, &event, &transport, Duration::from_secs(2), 60_000)
                .unwrap()
        else {
            panic!("recognized result should remain a candidate")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
        assert_eq!(transport.calls.get(), 1);
    }

    #[test]
    fn compact_repo_flag_cannot_attribute_without_validated_repository() {
        for command in [
            "gh pr create -Rforeign.example/acme/widget --title change",
            "gh pr create -R=foreign.example/acme/widget --title change",
            "gh pr create -dRforeign.example/acme/widget --title change",
            "gh pr create -wRforeign.example/acme/widget --title change",
            "gh pr create -Racme/widget --title change",
        ] {
            let mut db = Connection::open_in_memory().unwrap();
            record_pre_tool_use(
                &mut db,
                &pre("s", "t", "call", command),
                1_735_787_045_500,
                60_000,
            )
            .unwrap();
            let result = handle_post_tool_use(
                &mut db,
                &post("s", "t", Some("call"), command),
                &fixture_transport(),
                Duration::from_secs(2),
                60_000,
            )
            .unwrap();
            let HandleResult::Candidate { record, .. } = result else {
                panic!("candidate missing")
            };
            assert_eq!(record.state, CandidateState::Ambiguous);
        }
    }

    #[test]
    fn option_value_starting_with_dash_r_is_not_a_short_option() {
        let input = json!({"command":"gh pr create --title '-Release notes'"});
        assert!(raw_creation_result("Bash", Some(&input)));
        for option in ["--template", "--attach", "-T", "-p"] {
            let input = json!({"command":format!("gh pr create {option} '-Release notes'")});
            assert!(raw_creation_result("Bash", Some(&input)));
        }
        let input = json!({"command":"gh pr create --template -- -dRforeign.example/owner/repo"});
        assert!(!raw_creation_result("Bash", Some(&input)));
        let input =
            json!({"command":"gh pr create --future-option -- -dRforeign.example/owner/repo"});
        assert!(!raw_creation_result("Bash", Some(&input)));
    }

    #[test]
    fn explicit_foreign_host_cannot_attribute_a_bash_creation() {
        let command = "gh api --hostname=api.attacker.test -X POST https://api.github.com/repos/acme/widget/pulls -f title=test";
        {
            let mut db = Connection::open_in_memory().unwrap();
            record_pre_tool_use(
                &mut db,
                &pre("s", "t", "call", command),
                1_735_787_045_500,
                60_000,
            )
            .unwrap();
            let transport = fixture_transport();
            let HandleResult::Candidate { record, verified } = handle_post_tool_use(
                &mut db,
                &post("s", "t", Some("call"), command),
                &transport,
                Duration::from_secs(2),
                60_000,
            )
            .unwrap() else {
                panic!("recognized creation output should remain queryable")
            };
            assert_eq!(record.state, CandidateState::Ambiguous);
            assert!(verified.is_none());
        }
    }

    #[test]
    fn durable_pre_matches_post_by_session_turn_id_and_digest_then_get_verifies() {
        let mut db = Connection::open_in_memory().unwrap();
        let recorded = record_pre_tool_use(
            &mut db,
            &mcp_pre("s1", "t1", "call-1"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        assert!(matches!(recorded, PreRecord::Recorded { .. }));

        let transport = fixture_transport();
        let result = handle_post_tool_use(
            &mut db,
            &mcp_post("s1", "t1", "call-1"),
            &transport,
            Duration::from_secs(3),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, verified } = result else {
            panic!("verification should return the stored candidate")
        };
        assert_eq!(record.state, CandidateState::Verified);
        assert!(verified.is_some());
        assert_eq!(transport.calls.get(), 1);

        let stored: String = db
            .query_row(
                "SELECT input_digest FROM pr_hook_pre_observations LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored.len(), 64);
        assert!(!stored.contains("repository_full_name"));
    }

    #[test]
    fn repeated_post_returns_durable_verification_without_another_get() {
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s", "t", "call"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let transport = fixture_transport();
        let first = handle_post_tool_use(
            &mut db,
            &mcp_post("s", "t", "call"),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record: first, .. } = first else {
            panic!()
        };
        assert_eq!(first.state, CandidateState::Verified);
        assert!(first.verified.is_some());

        let repeated = handle_post_tool_use(
            &mut db,
            &mcp_post("s", "t", "call"),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate {
            record: second,
            verified,
        } = repeated
        else {
            panic!()
        };
        assert_eq!(second.id, first.id);
        assert_eq!(second.verified, first.verified);
        assert_eq!(verified, first.verified);
        assert_eq!(transport.calls.get(), 1);
    }

    #[test]
    fn all_plausible_pre_calls_make_creation_ambiguous() {
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s", "t", "call-1"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s", "t", "call-2"),
            1_735_787_045_600,
            60_000,
        )
        .unwrap();
        let transport = fixture_transport();
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &mcp_post("s", "t", "call-1"),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate should remain queryable")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(record.reason.unwrap().contains("multiple outstanding"));
        assert!(verified.is_none());
    }

    #[test]
    fn retry_rechecks_all_plausible_pre_calls() {
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s", "t", "call-1"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s", "t", "call-2"),
            1_735_787_045_600,
            60_000,
        )
        .unwrap();
        let timeout = FixtureTransport {
            response: Err(TransportFailure::Timeout),
            calls: Cell::new(0),
        };
        let HandleResult::Candidate { record, .. } = handle_post_tool_use(
            &mut db,
            &mcp_post("s", "t", "call-1"),
            &timeout,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("timed out candidate should remain queryable")
        };
        assert_eq!(record.state, CandidateState::Timeout);
        db.execute(
            "UPDATE pr_hook_candidates SET next_retry_at_ms=0 WHERE id=?1",
            [record.id],
        )
        .unwrap();
        let claim = claim_due_retries(&mut db, unix_now_ms(), 60_000, 1)
            .unwrap()
            .pop()
            .unwrap();
        let transport = fixture_transport();
        let HandleResult::Candidate { record, verified } = retry_candidate(
            &mut db,
            claim.id,
            claim.work_claim_until_ms.unwrap(),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("retried candidate should remain queryable")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
    }

    #[test]
    fn exact_gh_pr_create_result_is_attributed_after_github_get() {
        let command = "gh pr create --title test";
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_044_500,
            60_000,
        )
        .unwrap();
        let transport = fixture_transport();
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("recognized CLI URL should remain a candidate")
        };
        assert_eq!(record.state, CandidateState::Verified);
        assert!(verified.is_some());
        assert_eq!(transport.calls.get(), 1);
    }

    #[test]
    fn explicit_foreign_gh_api_host_stays_ambiguous() {
        let observed_at_ms = 1_735_787_046_500; // 2025-01-02T03:04:06.500Z
        let command =
            "gh api --hostname=api.attacker.test -X POST repos/acme/widget/pulls -f title=test";
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            observed_at_ms,
            60_000,
        )
        .unwrap();
        let transport = fixture_transport();
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("relative API endpoint should produce a queryable candidate")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
        assert_eq!(transport.calls.get(), 1);

        let absolute_foreign =
            "gh api -X POST https://api.attacker.test/repos/acme/widget/pulls -f title=test";
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "absolute-call", absolute_foreign),
            observed_at_ms,
            60_000,
        )
        .unwrap();
        let transport = fixture_transport();
        assert_eq!(
            handle_post_tool_use(
                &mut db,
                &post("s", "t", Some("absolute-call"), absolute_foreign),
                &transport,
                Duration::from_secs(2),
                60_000,
            )
            .unwrap(),
            HandleResult::Ignored
        );
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn completed_creation_does_not_block_a_later_creation() {
        let command = "gh pr create --title test";
        let mut db = Connection::open_in_memory().unwrap();
        let first_pre = pre("s", "t", "call-1", command);
        record_pre_tool_use(&mut db, &first_pre, 1_735_787_046_500, 60_000).unwrap();
        let transport = fixture_transport();
        let first = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call-1"), command),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        assert!(
            matches!(first, HandleResult::Candidate { record, .. } if record.state == CandidateState::Verified)
        );

        let second_pre = pre("s", "t", "call-2", command);
        record_pre_tool_use(&mut db, &second_pre, 1_735_787_046_600, 60_000).unwrap();
        let mut second_post = post("s", "t", Some("call-2"), command);
        second_post["tool_response"] = json!("https://github.com/acme/widget/pull/43");
        let response_43 = FixtureTransport {
            response: Ok(GetPullRequestResponse {
                status: 200,
                observed_at_ms: 1_735_787_047_000,
                body: json!({
                    "number":43,
                    "html_url":"https://github.com/acme/widget/pull/43",
                    "created_at":"2025-01-02T03:04:06Z",
                    "base":{"ref":"main","repo":{"full_name":"acme/widget"}},
                    "head":{"ref":"feature"},
                    "user":{"login":"alice"}
                }),
            }),
            calls: Cell::new(0),
        };
        let second = handle_post_tool_use(
            &mut db,
            &second_post,
            &response_43,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        assert!(
            matches!(second, HandleResult::Candidate { record, .. } if record.state == CandidateState::Verified)
        );
        let linked: i64 = db
            .query_row(
                "SELECT count(*) FROM pr_hook_pre_observations WHERE state='linked'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(linked, 2);
    }

    #[test]
    fn failed_concurrent_call_completing_during_successful_get_does_not_block_attribution() {
        struct BlockingTransport {
            started: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        }
        impl PullRequestGetTransport for BlockingTransport {
            fn get_pull_request(
                &self,
                _repository: &str,
                _number: u64,
                _timeout: Duration,
            ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
                self.started.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(fixture_response())
            }
        }

        let file = tempfile::NamedTempFile::new().unwrap();
        let failed_command = "gh pr create --title failed";
        let successful_command = "gh pr create --title successful";
        {
            let mut db = Connection::open(file.path()).unwrap();
            record_pre_tool_use(
                &mut db,
                &pre("s", "t", "call-failed", failed_command),
                1_735_787_046_400,
                60_000,
            )
            .unwrap();
            record_pre_tool_use(
                &mut db,
                &pre("s", "t", "call-success", successful_command),
                1_735_787_046_500,
                60_000,
            )
            .unwrap();
        }

        let path = file.path().to_owned();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let success_event = post("s", "t", Some("call-success"), successful_command);
        let verifier = std::thread::spawn(move || {
            let mut db = Connection::open(path).unwrap();
            handle_post_tool_use(
                &mut db,
                &success_event,
                &BlockingTransport {
                    started: started_tx,
                    release: release_rx,
                },
                Duration::from_secs(3),
                60_000,
            )
            .unwrap()
        });
        started_rx.recv().unwrap();

        let mut failed_post = post("s", "t", Some("call-failed"), failed_command);
        failed_post["tool_response"] = json!("creation failed");
        let mut db = Connection::open(file.path()).unwrap();
        assert_eq!(
            handle_post_tool_use(
                &mut db,
                &failed_post,
                &fixture_transport(),
                Duration::from_secs(3),
                60_000,
            )
            .unwrap(),
            HandleResult::Ignored
        );
        release_tx.send(()).unwrap();

        let HandleResult::Candidate { record, verified } = verifier.join().unwrap() else {
            panic!("successful creation candidate should be retained")
        };
        assert_eq!(record.state, CandidateState::Verified);
        assert!(verified.is_some());
        let failed_state: String = db
            .query_row(
                "SELECT state FROM pr_hook_pre_observations WHERE tool_use_id='call-failed'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(failed_state, "completed");
    }

    #[test]
    fn completed_non_candidate_call_does_not_block_concurrent_success() {
        let failed_command = "gh pr create --title failed";
        let successful_command = "gh pr create --title successful";
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call-failed", failed_command),
            1_735_787_046_500,
            60_000,
        )
        .unwrap();
        let mut failed_post = post("s", "t", Some("call-failed"), failed_command);
        failed_post["tool_response"] = json!("creation failed");
        assert_eq!(
            handle_post_tool_use(
                &mut db,
                &failed_post,
                &fixture_transport(),
                Duration::from_secs(2),
                60_000,
            )
            .unwrap(),
            HandleResult::Ignored
        );
        let failed_state: String = db
            .query_row("SELECT state FROM pr_hook_pre_observations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(failed_state, "completed");

        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call-success", successful_command),
            1_735_787_046_600,
            60_000,
        )
        .unwrap();
        let result = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call-success"), successful_command),
            &fixture_transport(),
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        assert!(
            matches!(result, HandleResult::Candidate { record, .. } if record.state == CandidateState::Verified)
        );
    }

    #[test]
    fn same_second_digest_fallback_remains_ambiguous() {
        let command = "gh pr create --title test";
        let observed_at_ms = 1_735_787_046_500;
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            observed_at_ms,
            60_000,
        )
        .unwrap();
        let transport = fixture_transport();
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &post("s", "t", None, command),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("fallback-correlated candidate should be retained")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
        assert_eq!(transport.calls.get(), 1);
    }

    #[test]
    fn conflicting_post_for_same_tool_use_is_ambiguous_and_never_reverified() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create --title test";
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let transport = fixture_transport();
        let first = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record: first, .. } = first else {
            panic!()
        };
        let conflict = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), "gh pr create --title changed"),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, .. } = conflict else {
            panic!()
        };
        assert_eq!(record.id, first.id);
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert_eq!(transport.calls.get(), 1);
    }

    #[test]
    fn repeated_post_recovers_candidate_left_pending_by_interruption() {
        struct Interrupted;
        impl PullRequestGetTransport for Interrupted {
            fn get_pull_request(
                &self,
                _repository: &str,
                _number: u64,
                _timeout: Duration,
            ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
                panic!("simulated interruption after durable candidate commit")
            }
        }

        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s", "t", "call"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let event = mcp_post("s", "t", "call");
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = handle_post_tool_use(
                &mut db,
                &event,
                &Interrupted,
                Duration::from_secs(2),
                60_000,
            );
        }));
        assert!(interrupted.is_err());
        db.execute(
            "UPDATE pr_hook_candidates SET work_claim_until_ms=0 WHERE tool_use_id='call'",
            [],
        )
        .unwrap();
        let now = unix_now_ms();
        let claimed = claim_due_retries(&mut db, now, 60_000, 10).unwrap();
        assert_eq!(claimed.len(), 1);
        let transport = fixture_transport();
        let HandleResult::Candidate { record, .. } = retry_candidate(
            &mut db,
            claimed[0].id,
            claimed[0].work_claim_until_ms.unwrap(),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(record.state, CandidateState::Verified);
        assert_eq!(transport.calls.get(), 1);
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM pr_hook_candidates", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn conflicting_post_during_get_cannot_overwrite_ambiguous_state() {
        struct BlockingTransport {
            started: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            response: GetPullRequestResponse,
        }
        impl PullRequestGetTransport for BlockingTransport {
            fn get_pull_request(
                &self,
                _repository: &str,
                _number: u64,
                _timeout: Duration,
            ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
                self.started.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(self.response.clone())
            }
        }

        let file = tempfile::NamedTempFile::new().unwrap();
        let command = "gh pr create --title original";
        {
            let mut setup = Connection::open(file.path()).unwrap();
            record_pre_tool_use(
                &mut setup,
                &pre("s", "t", "call", command),
                1_735_787_045_500,
                60_000,
            )
            .unwrap();
        }
        let path = file.path().to_owned();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let post_event = post("s", "t", Some("call"), command);
        let verifier = std::thread::spawn(move || {
            let mut db = Connection::open(path).unwrap();
            let transport = BlockingTransport {
                started: started_tx,
                release: release_rx,
                response: fixture_response(),
            };
            handle_post_tool_use(
                &mut db,
                &post_event,
                &transport,
                Duration::from_secs(3),
                60_000,
            )
            .unwrap()
        });

        started_rx.recv().unwrap();
        let mut conflicting_db = Connection::open(file.path()).unwrap();
        let conflict = handle_post_tool_use(
            &mut conflicting_db,
            &post("s", "t", Some("call"), "gh pr create --title conflicting"),
            &fixture_transport(),
            Duration::from_secs(3),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, .. } = conflict else {
            panic!("conflicting observation should be retained")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        release_tx.send(()).unwrap();

        let HandleResult::Candidate { record, verified } = verifier.join().unwrap() else {
            panic!("in-flight observation should remain queryable")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
    }

    #[test]
    fn new_or_conflicting_pre_during_get_cannot_authorize_attribution() {
        let mut control_db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut control_db,
            &mcp_pre("control", "turn", "call"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let control = handle_post_tool_use(
            &mut control_db,
            &mcp_post("control", "turn", "call"),
            &fixture_transport(),
            Duration::from_secs(3),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate {
            record,
            verified: Some(_),
        } = control
        else {
            panic!("an unconflicted exact call should verify")
        };
        assert_eq!(record.state, CandidateState::Verified);
        struct BlockingTransport {
            started: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            response: GetPullRequestResponse,
        }
        impl PullRequestGetTransport for BlockingTransport {
            fn get_pull_request(
                &self,
                _repository: &str,
                _number: u64,
                _timeout: Duration,
            ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
                self.started.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(self.response.clone())
            }
        }

        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let mut db = Connection::open(file.path()).unwrap();
            record_pre_tool_use(
                &mut db,
                &mcp_pre("s", "t", "call-1"),
                1_735_787_045_500,
                60_000,
            )
            .unwrap();
        }
        let path = file.path().to_owned();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let event = mcp_post("s", "t", "call-1");
        let verifier = std::thread::spawn(move || {
            let mut db = Connection::open(path).unwrap();
            let transport = BlockingTransport {
                started: started_tx,
                release: release_rx,
                response: fixture_response(),
            };
            handle_post_tool_use(&mut db, &event, &transport, Duration::from_secs(3), 60_000)
                .unwrap()
        });

        started_rx.recv().unwrap();
        let mut second_pre = Connection::open(file.path()).unwrap();
        record_pre_tool_use(
            &mut second_pre,
            &mcp_pre("s", "t", "call-2"),
            1_735_787_045_600,
            60_000,
        )
        .unwrap();
        release_tx.send(()).unwrap();

        let HandleResult::Candidate { record, verified } = verifier.join().unwrap() else {
            panic!("in-flight candidate should remain queryable")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
    }

    #[test]
    fn verified_snapshot_survives_database_reopen() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let id = {
            let mut db = Connection::open(file.path()).unwrap();
            record_pre_tool_use(
                &mut db,
                &mcp_pre("s", "t", "call"),
                1_735_787_045_500,
                60_000,
            )
            .unwrap();
            let HandleResult::Candidate { record, .. } = handle_post_tool_use(
                &mut db,
                &mcp_post("s", "t", "call"),
                &fixture_transport(),
                Duration::from_secs(2),
                60_000,
            )
            .unwrap() else {
                panic!()
            };
            record.id
        };
        let db = Connection::open(file.path()).unwrap();
        let stored = candidate_status(&db, id).unwrap().unwrap();
        assert_eq!(stored.state, CandidateState::Verified);
        assert_eq!(stored.verified.unwrap().number, 42);
    }

    #[test]
    fn read_only_gh_api_does_not_compete_with_pr_creation() {
        let mut db = Connection::open_in_memory().unwrap();
        for (call, command) in [
            ("read", "gh api -X GET repos/acme/widget/pulls"),
            (
                "read-input",
                "gh api --method GET --input body.json repos/acme/widget/pulls",
            ),
        ] {
            let event = pre("s", "t", call, command);
            assert!(!is_relevant_pre_tool_use(&event), "{command}");
            assert_eq!(
                record_pre_tool_use(&mut db, &event, 100, 1000).unwrap(),
                PreRecord::Ignored,
                "{command}"
            );
        }
        let create = pre(
            "s",
            "t",
            "create",
            "gh api repos/acme/widget/pulls --input body.json",
        );
        assert!(is_relevant_pre_tool_use(&create));
        assert!(matches!(
            record_pre_tool_use(&mut db, &create, 100, 1000).unwrap(),
            PreRecord::Recorded { .. }
        ));
        let count: i64 = db
            .query_row("SELECT count(*) FROM pr_hook_pre_observations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn pre_observation_tokenizer_removes_bash_line_continuations() {
        let mut db = Connection::open_in_memory().unwrap();
        for (call, command) in [
            ("between", "gh api \\\n -X POST repos/acme/widget/pulls"),
            ("flag", "gh api --me\\\nthod POST repos/acme/widget/pulls"),
            ("endpoint", "gh api -X POST repos/acme/\\\nwidget/pulls"),
            (
                "double-quoted",
                "gh api -X POST \"/repos/acme/\\\nwidget/pulls\"",
            ),
            ("gh-pr", "gh pr \\\n create --title change"),
        ] {
            let event = pre("s", call, call, command);
            assert!(is_relevant_pre_tool_use(&event), "{command:?}");
            assert!(matches!(
                record_pre_tool_use(&mut db, &event, 100, 1_000),
                Ok(PreRecord::Recorded { .. })
            ));
        }

        let single_quoted = "gh api -X POST 'repos/acme/\\\nwidget/pulls'";
        let tokens = shell_tokens(single_quoted).unwrap();
        assert_eq!(tokens[4], "repos/acme/\\\nwidget/pulls");
        assert!(!is_relevant_pre_tool_use(&pre(
            "s",
            "single-quoted",
            "single-quoted",
            single_quoted
        )));

        let crlf = "gh api -X POST repos/acme/\\\r\nwidget/pulls";
        assert!(!is_relevant_pre_tool_use(&pre("s", "crlf", "crlf", crlf)));
    }

    #[test]
    fn gh_pr_body_value_cannot_be_misread_as_head_metadata() {
        let secret = "Bearer-SECRET-value";
        let command =
            format!("gh pr create --title '--dry-run' --body '--head={secret} --repo=other/repo'");
        let event = pre("s", "t", "c", &command);
        assert!(is_relevant_pre_tool_use(&event));
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(&mut db, &event, 100, 1000).unwrap();
        let (repo, head, base, author) = intent_metadata("Bash", &event["tool_input"]);
        assert_eq!((repo, head, base, author), (None, None, None, None));
        let persisted: String = db.query_row(
            "SELECT COALESCE(repository,'') || COALESCE(head_ref,'') || COALESCE(base_ref,'') || COALESCE(author_login,'') FROM pr_hook_pre_observations",
            [], |row| row.get(0),
        ).unwrap();
        assert!(!persisted.contains(secret));
        assert!(!persisted.contains("other/repo"));
    }

    #[test]
    fn gh_pr_repo_host_prefix_is_normalized_in_pretool_metadata() {
        let event = pre(
            "s",
            "t",
            "c",
            "gh pr create --repo github.com/owner/repo --head feature",
        );
        assert!(is_relevant_pre_tool_use(&event));
        assert_eq!(
            intent_metadata("Bash", &event["tool_input"]),
            (
                Some("owner/repo".into()),
                Some("feature".into()),
                None,
                None
            )
        );
    }

    #[test]
    fn gh_api_creation_intent_skips_input_preview_and_cache_values_before_route() {
        let command = "gh api --input body.json --preview corsair --cache 1m -X POST /repos/acme/widget/pulls -f title=x";
        let event = pre("s", "t", "call", command);
        assert!(is_relevant_pre_tool_use(&event));
        let mut db = Connection::open_in_memory().unwrap();
        assert!(matches!(
            record_pre_tool_use(&mut db, &event, 100, 1000).unwrap(),
            PreRecord::Recorded { .. }
        ));
    }

    #[test]
    fn rate_limit_and_service_unavailable_responses_are_backoff_retries() {
        for (status, body, expected_reason) in [
            (
                429,
                json!({"message":"secondary rate limit"}),
                "GitHub API rate limited",
            ),
            (
                403,
                json!({"message":"API rate limit exceeded"}),
                "GitHub API rate limited",
            ),
            (
                503,
                json!({"message":"service unavailable"}),
                "GitHub API temporarily unavailable",
            ),
            (
                500,
                json!({"message":"server error"}),
                "GitHub API temporarily unavailable",
            ),
            (
                502,
                json!({"message":"bad gateway"}),
                "GitHub API temporarily unavailable",
            ),
            (
                504,
                json!({"message":"gateway timeout"}),
                "GitHub API temporarily unavailable",
            ),
        ] {
            let mut db = Connection::open_in_memory().unwrap();
            let command = "gh pr create --title test";
            record_pre_tool_use(
                &mut db,
                &pre("s", "t", "call", command),
                1_735_787_045_500,
                60_000,
            )
            .unwrap();
            let mut response = fixture_response();
            response.status = status;
            response.body = body;
            let transport = FixtureTransport {
                response: Ok(response),
                calls: Cell::new(0),
            };
            let HandleResult::Candidate { record, verified } = handle_post_tool_use(
                &mut db,
                &post("s", "t", Some("call"), command),
                &transport,
                Duration::from_secs(2),
                60_000,
            )
            .unwrap() else {
                panic!()
            };
            assert_eq!(record.state, CandidateState::TransportError);
            assert_eq!(record.get_status, Some(status));
            assert_eq!(record.reason.as_deref(), Some(expected_reason));
            assert!(record.next_retry_at_ms.is_some());
            assert!(verified.is_none());
        }
    }

    #[test]
    fn jq_template_candidate_is_retained_ambiguous_without_get() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh api --method POST repos/acme/widget/pulls -f title=x --jq .html_url";
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let mut event = post("s", "t", Some("call"), command);
        event["tool_response"] = json!(
            r#"{"number":42,"html_url":"https://github.com/acme/widget/pull/42","created_at":"2025-01-02T03:04:06Z"}"#
        );
        let transport = fixture_transport();
        let HandleResult::Candidate { record, .. } =
            handle_post_tool_use(&mut db, &event, &transport, Duration::from_secs(2), 60_000)
                .unwrap()
        else {
            panic!()
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn non_200_get_is_not_verified_and_http_include_parser_requires_json() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create --title test";
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let mut response = fixture_response();
        response.status = 404;
        let transport = FixtureTransport {
            response: Ok(response),
            calls: Cell::new(0),
        };
        let HandleResult::Candidate { record, verified } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(record.state, CandidateState::Inconclusive);
        assert_eq!(record.get_status, Some(404));
        assert!(verified.is_none());
        assert_eq!(
            parse_included_http_response(
                b"HTTP/2 404 Not Found\r\ncontent-type: application/json\r\n\r\n{}"
            ),
            Ok((404, json!({})))
        );
        assert_eq!(
            parse_included_http_response(b"HTTP/2 200 OK\r\n\r\nnot-json"),
            Err(TransportFailure::Other)
        );
    }

    #[cfg(unix)]
    #[test]
    fn gh_adapter_uses_configured_executable_preserves_http_404_and_rejects_capped_output() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let gh = dir.path().join("configured-gh");
        std::fs::write(
            &gh,
            "#!/bin/sh\n[ \"$2\" = \"https://api.github.com/repos/acme/widget/pulls/42\" ] || exit 2\nprintf 'HTTP/2 404 Not Found\\r\\ncontent-type: application/json\\r\\n\\r\\n%s\\n' '{\"message\":\"Not Found\"}'\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o700)).unwrap();
        let response = GhCliPullRequestGet::new(&gh)
            .get_pull_request("acme/widget", 42, Duration::from_secs(2))
            .unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body["message"], "Not Found");

        std::fs::write(&gh, "#!/bin/sh\nprintf '%*s' 1048576 x\n").unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            GhCliPullRequestGet::new(&gh).get_pull_request(
                "acme/widget",
                42,
                Duration::from_secs(2)
            ),
            Err(TransportFailure::Other)
        ));
    }

    #[test]
    fn concurrent_same_input_without_id_is_ambiguous_and_does_not_get() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create --title test";
        record_pre_tool_use(&mut db, &pre("s1", "t1", "c1", command), 1000, 60_000).unwrap();
        record_pre_tool_use(&mut db, &pre("s1", "t1", "c2", command), 1001, 60_000).unwrap();
        let transport = fixture_transport();
        let result = handle_post_tool_use(
            &mut db,
            &post("s1", "t1", None, command),
            &transport,
            Duration::from_secs(3),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, .. } = result else {
            panic!("candidate should be retained");
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert_eq!(transport.calls.get(), 0);
        assert!(record.reason.unwrap().contains("multiple PreToolUse"));
    }

    #[test]
    fn digest_or_session_mismatch_preserves_ambiguous_candidate() {
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("other-session", "t1", "call-1", "gh pr create --title test"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let transport = fixture_transport();
        let result = handle_post_tool_use(
            &mut db,
            &post("s1", "t1", Some("call-1"), "gh pr create --title test"),
            &transport,
            Duration::from_secs(3),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, .. } = result else {
            panic!("candidate should be retained");
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert_eq!(transport.calls.get(), 0);
        assert!(candidate_status(&db, record.id).unwrap().is_some());
    }

    #[test]
    fn timeout_and_transport_error_are_visible_and_retryable() {
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &mcp_pre("s1", "t1", "call-1"),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let timeout = FixtureTransport {
            response: Err(TransportFailure::Timeout),
            calls: Cell::new(0),
        };
        let result = handle_post_tool_use(
            &mut db,
            &mcp_post("s1", "t1", "call-1"),
            &timeout,
            Duration::from_millis(50),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, .. } = result else {
            panic!("candidate should remain persisted");
        };
        assert_eq!(record.state, CandidateState::Timeout);
        assert_eq!(record.reason.as_deref(), Some("GitHub GET timed out"));
        assert_eq!(record.retry_count, 1);
        assert!(
            claim_due_retries(&mut db, record.next_retry_at_ms.unwrap() - 1, 60_000, 10)
                .unwrap()
                .is_empty()
        );
        let due = record.next_retry_at_ms.unwrap();
        let claims = claim_due_retries(&mut db, due, 60_000, 10).unwrap();
        assert_eq!(claims.len(), 1);
        assert!(
            claim_due_retries(&mut db, due, 60_000, 10)
                .unwrap()
                .is_empty()
        );

        let retry = fixture_transport();
        let result = retry_candidate(
            &mut db,
            claims[0].id,
            claims[0].work_claim_until_ms.unwrap(),
            &retry,
            Duration::from_secs(3),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate {
            record: retried, ..
        } = result
        else {
            panic!("retry should return the stored candidate")
        };
        assert_eq!(retried.state, CandidateState::Verified);
        let stored = candidate_status(&db, record.id).unwrap().unwrap();
        assert_eq!(stored.state, CandidateState::Verified);
        assert_eq!(stored.retry_count, 1);
        assert!(stored.next_retry_at_ms.is_none());
    }

    #[test]
    fn stale_retry_claim_cannot_adopt_a_new_workers_lease() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = TRUSTED_API_CREATE;
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let timeout = FixtureTransport {
            response: Err(TransportFailure::Timeout),
            calls: Cell::new(0),
        };
        let HandleResult::Candidate { record, .. } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &timeout,
            Duration::from_millis(50),
            60_000,
        )
        .unwrap() else {
            panic!("candidate should remain persisted")
        };
        let first = claim_due_retries(&mut db, record.next_retry_at_ms.unwrap(), 60_000, 1)
            .unwrap()
            .remove(0);
        let second = claim_due_retries(&mut db, first.work_claim_until_ms.unwrap(), 60_000, 1)
            .unwrap()
            .remove(0);
        let transport = fixture_transport();
        let stale = retry_candidate(
            &mut db,
            first.id,
            first.work_claim_until_ms.unwrap(),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate {
            record: stale_record,
            ..
        } = stale
        else {
            panic!("stale claim should preserve candidate")
        };
        assert_eq!(stale_record.state, CandidateState::Timeout);
        assert_eq!(transport.calls.get(), 0);
        assert_eq!(
            candidate_status(&db, second.id)
                .unwrap()
                .unwrap()
                .work_claim_until_ms,
            second.work_claim_until_ms
        );
    }

    #[test]
    fn persisted_ambiguous_pre_blocks_retry_before_github_get() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let command = TRUSTED_API_CREATE;
        let record = {
            let mut db = Connection::open(file.path()).unwrap();
            record_pre_tool_use(
                &mut db,
                &pre("s", "t", "call", command),
                1_735_787_045_500,
                60_000,
            )
            .unwrap();
            let timeout = FixtureTransport {
                response: Err(TransportFailure::Timeout),
                calls: Cell::new(0),
            };
            let HandleResult::Candidate { record, .. } = handle_post_tool_use(
                &mut db,
                &post("s", "t", Some("call"), command),
                &timeout,
                Duration::from_millis(50),
                60_000,
            )
            .unwrap() else {
                panic!("candidate should remain persisted")
            };
            // Model a durable ambiguous Pre observation whose candidate-state
            // update was interrupted before it could be committed.
            db.execute(
                "UPDATE pr_hook_pre_observations SET state='ambiguous' WHERE tool_use_id='call'",
                [],
            )
            .unwrap();
            record
        };

        let mut db = Connection::open(file.path()).unwrap();
        let claim = claim_due_retries(&mut db, record.next_retry_at_ms.unwrap(), 60_000, 1)
            .unwrap()
            .remove(0);
        let transport = fixture_transport();
        let HandleResult::Candidate { record, verified } = retry_candidate(
            &mut db,
            claim.id,
            claim.work_claim_until_ms.unwrap(),
            &transport,
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!("candidate should remain queryable")
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(verified.is_none());
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn verified_worker_claims_once_and_acknowledges_only_after_claim() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = TRUSTED_API_CREATE;
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, .. } = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
            &fixture_transport(),
            Duration::from_secs(2),
            60_000,
        )
        .unwrap() else {
            panic!()
        };
        let now = unix_now_ms();
        assert!(!mark_candidate_consumed(&db, record.id, now).unwrap());
        let claimed = claim_verified_pending(&mut db, now, 60_000, 10).unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(
            claim_verified_pending(&mut db, now, 60_000, 10)
                .unwrap()
                .is_empty()
        );
        assert!(mark_candidate_consumed(&db, record.id, now + 1).unwrap());
        assert!(
            claim_verified_pending(&mut db, now + 2, 60_000, 10)
                .unwrap()
                .is_empty()
        );
        assert!(!mark_candidate_consumed(&db, record.id, now + 2).unwrap());
    }

    #[test]
    fn relevance_gate_is_cheap_and_has_no_database_effects() {
        assert!(!is_relevant_pre_tool_use(&json!({
            "hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}
        })));
        assert!(!is_relevant_pre_tool_use(&json!({
            "hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr create --dry-run"}
        })));
        assert!(is_relevant_pre_tool_use(&pre(
            "s",
            "t",
            "c",
            "gh pr create --title x"
        )));
        assert!(is_relevant_pre_tool_use(&json!({
            "hook_event_name":"PreToolUse","tool_name":MCP_CREATE_PR_TOOL,"tool_input":{}
        })));
        assert!(!is_relevant_pre_tool_use(&json!({
            "hook_event_name":"PostToolUse","tool_name":MCP_CREATE_PR_TOOL,"tool_input":{}
        })));
    }

    #[test]
    fn expired_unmatched_pre_rows_are_cleaned_but_candidates_are_not() {
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &pre("s1", "t1", "old", "gh pr create --title old"),
            100,
            10,
        )
        .unwrap();
        assert_eq!(cleanup_expired_pre(&db, 111).unwrap(), 1);

        let result = handle_post_tool_use(
            &mut db,
            &post("s1", "t1", Some("missing"), "gh pr create --title new"),
            &FixtureTransport {
                response: Err(TransportFailure::Network),
                calls: Cell::new(0),
            },
            Duration::from_secs(1),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, .. } = result else {
            panic!("candidate should be retained");
        };
        assert_eq!(record.state, CandidateState::Ambiguous);
        assert!(candidate_status(&db, record.id).unwrap().is_some());
        assert_eq!(cleanup_expired_pre(&db, i64::MAX).unwrap(), 0);
    }

    #[test]
    fn cleanup_expires_ambiguous_pre_without_reference_but_preserves_active_reference() {
        let mut db = Connection::open_in_memory().unwrap();
        let mut incomplete = pre("s", "t", "amb", "gh pr create --title old");
        incomplete.as_object_mut().unwrap().remove("turn_id");
        assert!(matches!(
            record_pre_tool_use(&mut db, &incomplete, 100, 10).unwrap(),
            PreRecord::Ambiguous { .. }
        ));
        assert_eq!(cleanup_expired_pre(&db, 111).unwrap(), 1);

        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", "gh pr create --title active"),
            200,
            10,
        )
        .unwrap();
        let candidate_id: i64 = db.execute(
            "INSERT INTO pr_hook_candidates(session_id,turn_id,tool_use_id,tool_name,input_digest,number,url,invocation_key,pre_id,state,created_at_ms,updated_at_ms) SELECT session_id,turn_id,tool_use_id,tool_name,input_digest,42,'https://github.com/acme/widget/pull/42','active',id,'timeout',200,200 FROM pr_hook_pre_observations WHERE tool_use_id='call'",
            [],
        ).map(|_| db.last_insert_rowid()).unwrap();
        assert!(candidate_status(&db, candidate_id).unwrap().is_some());
        assert_eq!(cleanup_expired_pre(&db, 211).unwrap(), 0);
    }

    #[test]
    fn get_identity_mismatch_is_inconclusive_not_attributed() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create --title test";
        record_pre_tool_use(
            &mut db,
            &pre("s1", "t1", "call-1", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let mut response = fixture_response();
        response.body["number"] = json!(43);
        let transport = FixtureTransport {
            response: Ok(response),
            calls: Cell::new(0),
        };
        let result = handle_post_tool_use(
            &mut db,
            &post("s1", "t1", Some("call-1"), command),
            &transport,
            Duration::from_secs(3),
            60_000,
        )
        .unwrap();
        let HandleResult::Candidate { record, verified } = result else {
            panic!("candidate should be retained");
        };
        assert_eq!(record.state, CandidateState::Inconclusive);
        assert!(verified.is_none());
        assert_eq!(record.get_status, Some(200));
    }
}
