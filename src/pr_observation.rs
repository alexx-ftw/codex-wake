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
    fn get_pull_request(
        &self,
        repository: &str,
        number: u64,
        timeout: Duration,
    ) -> std::result::Result<GetPullRequestResponse, TransportFailure> {
        if !valid_repository(repository) || number == 0 {
            return Err(TransportFailure::Other);
        }
        let endpoint = format!("repos/{repository}/pulls/{number}");
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

fn valid_repository(repository: &str) -> bool {
    let Some((owner, repo)) = repository.split_once('/') else {
        return false;
    };
    let valid_part = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    valid_part(owner) && valid_part(repo) && !repo.contains('/')
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
        .context("initialize PR observation tables")
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
            Ok(Some(record)) => Some(Ok(record)),
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
    let expires_at_ms = observed_at_ms
        .checked_add(expires_after_ms.max(0))
        .ok_or_else(|| anyhow!("PreToolUse expiration timestamp overflow"))?;
    let (repository, head_ref, base_ref, author_login) = intent_metadata(tool_name, tool_input);
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
          author_login,observed_at_ms,expires_at_ms,state,reason)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
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
            initial_reason
        ],
    )?;
    if inserted == 1 {
        let id = tx.last_insert_rowid();
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
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'pending',NULL,?9,?9)",
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

    let correlation = correlate_pre(
        &tx,
        session_id.as_deref(),
        turn_id.as_deref(),
        post_id.as_deref(),
        tool_name,
        input_digest.as_deref(),
    )?;
    match correlation {
        Correlation::Unique {
            pre_id,
            exact_tool_use_id,
        } => {
            tx.execute(
                "UPDATE pr_hook_candidates SET pre_id=?1,exact_id_correlation=?2,
                 raw_creation_result=?3 WHERE id=?4",
                params![
                    pre_id,
                    exact_tool_use_id,
                    !command_output_can_be_filtered(tool_name, event.get("tool_input")),
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
    if command_output_can_be_filtered(tool_name, event.get("tool_input")) {
        tx.execute(
            "UPDATE pr_hook_candidates SET state='ambiguous',
             reason='gh api output uses jq/template formatting',updated_at_ms=?1 WHERE id=?2",
            params![now_ms, candidate_id],
        )?;
        tx.commit()?;
        return candidate_result(db, candidate_id, None);
    }
    tx.commit()?;
    resume_pending_candidate(db, candidate_id, timeout, transport, max_pre_to_creation_ms)
}

fn resume_pending_candidate(
    db: &mut Connection,
    candidate_id: i64,
    timeout: Duration,
    transport: &dyn PullRequestGetTransport,
    max_pre_to_creation_ms: i64,
) -> Result<HandleResult> {
    let now = unix_now_ms();
    let lease_ms = timeout.as_millis().min(i64::MAX as u128) as i64;
    let until = now.saturating_add(lease_ms.max(1).saturating_add(5_000));
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
    transport: &dyn PullRequestGetTransport,
    timeout: Duration,
    max_pre_to_creation_ms: i64,
) -> Result<HandleResult> {
    initialize(db)?;
    let lease_until = db
        .query_row(
            "SELECT work_claim_until_ms FROM pr_hook_candidates WHERE id=?1",
            [candidate_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    let Some(lease_until) = lease_until.filter(|until| *until > unix_now_ms()) else {
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
        lease_until,
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
             WHERE c.pre_id=p.id AND c.state IN ('pending','timeout','transport_error','inconclusive')
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
    let observation = PreToolUseObservation {
        observed_at_unix_ms: pre.observed_at_ms,
        repository: pre.repository.unwrap_or(repo.clone()),
        head_ref: pre.head_ref,
        base_ref: pre.base_ref,
        author_login: pre.author_login,
        exact_call_and_result,
    };

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
    let outcome = verify_pr_candidate(
        &candidate,
        &[observation],
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
        db,
        candidate_id,
        state,
        (expected_state, expected_lease_until),
        reason,
        Some(response.status),
        verified.as_ref(),
    )?;
    let verified = if changed {
        verified
    } else {
        candidate_record(db, candidate_id)?.and_then(|record| record.verified)
    };
    candidate_result(db, candidate_id, verified)
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
                    tool_use_id: tool_use_id.unwrap_or_default(),
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
}

fn load_pre_observation(db: &Connection, id: i64) -> Result<Option<StoredPre>> {
    Ok(db
        .query_row(
            "SELECT observed_at_ms,session_id,turn_id,tool_use_id,tool_name,input_digest,
                    repository,head_ref,base_ref,author_login
             FROM pr_hook_pre_observations WHERE id=?1",
            [id],
            |row| {
                Ok(StoredPre {
                    observed_at_ms: row.get(0)?,
                    session_id: row.get(1)?,
                    turn_id: row.get(2)?,
                    tool_use_id: row.get(3)?,
                    tool_name: row.get(4)?,
                    input_digest: row.get(5)?,
                    repository: row.get(6)?,
                    head_ref: row.get(7)?,
                    base_ref: row.get(8)?,
                    author_login: row.get(9)?,
                })
            },
        )
        .optional()?)
}

fn candidate_record(db: &Connection, id: i64) -> Result<Option<CandidateRecord>> {
    let row = db
        .query_row(
            "SELECT id,session_id,turn_id,tool_use_id,number,url,state,reason,get_status,verified_json,
                    consumed_at_ms,retry_count,next_retry_at_ms
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
        (Some("api"), _) => api_endpoint(&tokens[2..])
            .is_some_and(|endpoint| api_pulls_repository(endpoint).is_some()),
        _ => false,
    }
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
    let mut escaped = false;
    let mut started = false;
    for ch in command.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
            started = true;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
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
    if escaped || quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

/// Find the positional endpoint without mistaking values to `-H`, `-f`, or
/// other `gh api` options for it. Only the endpoint is retained.
fn api_endpoint(args: &[String]) -> Option<&str> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if !arg.starts_with('-') {
            return Some(arg);
        }
        if matches!(
            arg,
            "-H" | "--header"
                | "-f"
                | "--field"
                | "-F"
                | "--raw-field"
                | "-X"
                | "--method"
                | "--input"
                | "--preview"
                | "-p"
                | "--cache"
                | "--hostname"
                | "-q"
                | "--jq"
                | "-t"
                | "--template"
        ) {
            index += 2;
        } else {
            index += 1;
        }
    }
    None
}

fn api_pulls_repository(endpoint: &str) -> Option<&str> {
    let path = endpoint.strip_prefix('/').unwrap_or(endpoint);
    let tail = path.strip_prefix("repos/")?;
    let mut parts = tail.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if parts.next()? != "pulls" || parts.next().is_some() {
        return None;
    }
    let repository = tail.get(..owner.len() + 1 + repo.len())?;
    safe_repository(repository)
}

fn safe_repository(value: &str) -> Option<&str> {
    if !valid_repository(value) {
        return None;
    }
    Some(value)
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
    use std::cell::Cell;
    use std::sync::mpsc;

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

    fn post(session: &str, turn: &str, call: Option<&str>, command: &str) -> Value {
        let mut value = json!({
            "hook_event_name":"PostToolUse",
            "session_id":session,
            "turn_id":turn,
            "tool_name":"Bash",
            "tool_input":{"command":command},
            "tool_response":"https://github.com/acme/widget/pull/42"
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
    fn durable_pre_matches_post_by_session_turn_id_and_digest_then_get_verifies() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create --title test";
        let recorded = record_pre_tool_use(
            &mut db,
            &pre("s1", "t1", "call-1", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        assert!(matches!(recorded, PreRecord::Recorded { .. }));

        let transport = fixture_transport();
        let result = handle_post_tool_use(
            &mut db,
            &post("s1", "t1", Some("call-1"), command),
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
        assert!(!stored.contains("gh pr create"));
    }

    #[test]
    fn repeated_post_returns_durable_verification_without_another_get() {
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
        assert_eq!(first.state, CandidateState::Verified);
        assert!(first.verified.is_some());

        let repeated = handle_post_tool_use(
            &mut db,
            &post("s", "t", Some("call"), command),
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
    fn exact_tool_identity_and_raw_result_allow_matching_pr_created_in_same_second() {
        let command = "gh pr create --title test";
        let observed_at_ms = 1_735_787_046_500; // 2025-01-02T03:04:06.500Z
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
            panic!("the recognized creation output should produce a candidate")
        };
        assert_eq!(record.state, CandidateState::Verified);
        assert_eq!(verified.unwrap().number, 42);
        assert_eq!(transport.calls.get(), 1);
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
        let command = "gh pr create --title test";
        record_pre_tool_use(
            &mut db,
            &pre("s", "t", "call", command),
            1_735_787_045_500,
            60_000,
        )
        .unwrap();
        let event = post("s", "t", Some("call"), command);
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
    fn verified_snapshot_survives_database_reopen() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let command = "gh pr create --title test";
        let id = {
            let mut db = Connection::open(file.path()).unwrap();
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
            record.id
        };
        let db = Connection::open(file.path()).unwrap();
        let stored = candidate_status(&db, id).unwrap().unwrap();
        assert_eq!(stored.state, CandidateState::Verified);
        assert_eq!(stored.verified.unwrap().number, 42);
    }

    #[test]
    fn gh_api_route_accepts_optional_leading_slash_and_never_stores_body_or_headers() {
        assert_eq!(
            api_pulls_repository("repos/acme/widget/pulls"),
            Some("acme/widget")
        );
        assert_eq!(
            api_pulls_repository("/repos/acme/widget/pulls"),
            Some("acme/widget")
        );
        assert_eq!(api_pulls_repository("repos/acme/widget/pulls/42"), None);
        let secret = "Bearer-very-secret-42";
        let input = json!({"command": format!(
            "gh api -H 'Authorization: {secret}' -f title={secret} -f head=feature repos/acme/widget/pulls"
        )});
        assert!(is_pr_creation_intent("Bash", &input));
        let (repo, head, base, author) = intent_metadata("Bash", &input);
        assert_eq!((repo, head, base, author), (None, None, None, None));
        let mut db = Connection::open_in_memory().unwrap();
        record_pre_tool_use(
            &mut db,
            &json!({"hook_event_name":"PreToolUse","session_id":"s","turn_id":"t","tool_use_id":"c","tool_name":"Bash","tool_input":input}),
            100,
            1000,
        ).unwrap();
        let stored: String = db.query_row(
            "SELECT COALESCE(repository,'') || COALESCE(head_ref,'') || COALESCE(base_ref,'') || COALESCE(author_login,'') FROM pr_hook_pre_observations",
            [], |row| row.get(0),
        ).unwrap();
        assert!(!stored.contains(secret));
        assert!(!stored.contains("feature"));
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
            "#!/bin/sh\nprintf 'HTTP/2 404 Not Found\\r\\ncontent-type: application/json\\r\\n\\r\\n{\\\"message\\\":\\\"Not Found\\\"}\\n'\nexit 1\n",
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
        let command = "gh pr create --title test";
        record_pre_tool_use(
            &mut db,
            &pre("s1", "t1", "call-1", command),
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
            &post("s1", "t1", Some("call-1"), command),
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
        let result =
            retry_candidate(&mut db, record.id, &retry, Duration::from_secs(3), 60_000).unwrap();
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
    fn verified_worker_claims_once_and_acknowledges_only_after_claim() {
        let mut db = Connection::open_in_memory().unwrap();
        let command = "gh pr create --title test";
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
