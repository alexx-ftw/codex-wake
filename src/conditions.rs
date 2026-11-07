//! Durable AND/OR groups over Wake-compatible event selectors.
//!
//! Events are matched only against members that exist when publication is
//! observed. Claims are permanent; delivery acceptance and uncertainty are
//! recorded separately, and neither advances a dependency until real completion.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use uuid::Uuid;

const MAX_SOURCE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    And,
    Or,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Or => "or",
        }
    }
}

/// Wake subscription identity. `outcome: None` matches any outcome for this
/// exact kind/repo/resource/event selector (for example `job/completed`).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Selector {
    pub kind: String,
    pub repo: String,
    pub resource: String,
    pub event: String,
    pub outcome: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublishedEvent {
    pub selector: Selector,
    /// Stable event key supplied by the publisher for redelivery deduplication.
    pub source_event_key: String,
    /// Native turn cursor, when this is a `thread` or `subagent` event.
    pub cursor: Option<String>,
    /// Exact GitHub Actions run identity when this event represents CI.
    pub ci: Option<CiRunIdentity>,
    /// Original publisher payload, retained for downstream templates.
    pub source: Value,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventRecord {
    pub ready_groups: usize,
    /// Newly matched or buffered member rows written by this call.
    pub new_members: usize,
    /// Distinct groups with at least one newly matched or buffered member.
    pub new_groups: usize,
    /// At least one unarmed member already had its single retained event; this
    /// occurrence was ledgered but intentionally not buffered for that member.
    pub buffer_overflow: bool,
    /// A stable key had conflicting content or identity; the conflict is
    /// durable and did not satisfy a group.
    pub payload_collision: bool,
}

/// Exact Actions identity. It is persisted independently of selector strings.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CiRunIdentity {
    pub repo: String,
    pub run_id: i64,
    pub attempt: i64,
    pub sha: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ObservationMode {
    Explicit,
    Polling,
}

/// Registration metadata kept separate from Wake's selector identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MemberRegistration {
    pub selector: Selector,
    pub observation: ObservationMode,
    pub ci: Option<CiRunIdentity>,
}

impl MemberRegistration {
    pub fn explicit(selector: Selector) -> Self {
        Self {
            selector,
            observation: ObservationMode::Explicit,
            ci: None,
        }
    }

    #[cfg(test)]
    pub fn explicit_with_ci(selector: Selector, ci: CiRunIdentity) -> Self {
        Self {
            selector,
            observation: ObservationMode::Explicit,
            ci: Some(ci),
        }
    }

    pub fn polling(selector: Selector, ci: Option<CiRunIdentity>) -> Self {
        Self {
            selector,
            observation: ObservationMode::Polling,
            ci,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeDependency {
    SuccessOnly,
    AnyTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub group_id: String,
    pub mode: ModeDependency,
}

impl ModeDependency {
    fn as_str(self) -> &'static str {
        match self {
            Self::SuccessOnly => "success_only",
            Self::AnyTerminal => "any_terminal",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionOutcome {
    Succeeded,
    Failed,
}

impl CompletionOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MatchedSource {
    pub selector: Selector,
    pub ci: Option<CiRunIdentity>,
    pub source_event_key: String,
    pub source: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Delivery {
    pub group_id: String,
    pub target_thread: String,
    pub message_template: Option<String>,
    pub sources: Vec<MatchedSource>,
}

#[derive(Clone, Debug, PartialEq)]
#[cfg(test)]
pub struct DeliveryStatus {
    pub group_id: String,
    pub state: String,
    pub reason: Option<String>,
    pub sender_pid: Option<i64>,
    pub sender_start: Option<i64>,
    pub sender_boot: Option<String>,
    pub sender_namespace: Option<String>,
    pub retry_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PollingMemberStatus {
    pub group_id: String,
    pub selector: Selector,
    pub ci: Option<CiRunIdentity>,
    pub group_state: String,
    pub armed: bool,
    pub baseline_cursor: Option<String>,
    pub last_cursor: Option<String>,
    pub buffer_overflow: bool,
    pub buffer_overflow_count: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SenderIdentity {
    pub(crate) pid: i64,
    pub(crate) start: i64,
    pub(crate) boot: String,
    pub(crate) namespace: String,
}

fn valid_field(value: &str, max: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= max
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate_selector(selector: &Selector) -> Result<()> {
    ensure!(
        valid_field(&selector.kind, 64, false),
        "Invalid selector kind"
    );
    ensure!(
        valid_field(&selector.repo, 255, true),
        "Invalid selector repo"
    );
    ensure!(
        valid_field(&selector.resource, 255, false),
        "Invalid selector resource"
    );
    ensure!(
        valid_field(&selector.event, 64, false),
        "Invalid selector event"
    );
    if let Some(outcome) = &selector.outcome {
        ensure!(valid_field(outcome, 64, false), "Invalid selector outcome");
    }
    Ok(())
}

fn valid_ci_repo(repo: &str) -> bool {
    let mut parts = repo.split('/');
    let valid = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    };
    parts.next().is_some_and(valid) && parts.next().is_some_and(valid) && parts.next().is_none()
}

fn validate_ci(selector: &Selector, ci: Option<&CiRunIdentity>) -> Result<()> {
    if let Some(ci) = ci {
        ensure!(
            selector.kind == "job",
            "CI identity is only valid for job members"
        );
        ensure!(
            valid_ci_repo(&ci.repo) && ci.repo == selector.repo,
            "CI repository must exactly match selector repo"
        );
        ensure!(
            ci.run_id > 0 && ci.attempt > 0,
            "CI run_id and attempt must be positive"
        );
        ensure!(
            ci.sha.len() == 40 && ci.sha.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "CI SHA must be 40 hexadecimal characters"
        );
    }
    Ok(())
}

fn ci_parts(ci: Option<&CiRunIdentity>) -> (&str, i64, i64, &str) {
    ci.map(|ci| (ci.repo.as_str(), ci.run_id, ci.attempt, ci.sha.as_str()))
        .unwrap_or(("", 0, 0, ""))
}

fn polling_kind(selector: &Selector, ci: Option<&CiRunIdentity>) -> bool {
    matches!(
        selector.kind.as_str(),
        "thread" | "subagent" | "pull_request" | "review" | "deployment" | "git_ref"
    ) || (selector.kind == "job" && ci.is_some())
}

fn outcome_value(outcome: Option<&str>) -> &str {
    outcome.unwrap_or("")
}

pub(crate) fn current_sender_identity() -> Result<SenderIdentity> {
    let pid = std::process::id();
    let start = crate::obligations::process_start_time(pid)
        .and_then(|value| i64::try_from(value).ok())
        .context("Could not verify condition sender start time")?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let namespace = std::fs::read_link("/proc/self/ns/pid")?;
    let boot = boot.trim().to_owned();
    let namespace = namespace
        .to_str()
        .context("Could not read condition sender PID namespace")?
        .to_owned();
    ensure!(
        valid_field(&boot, 64, false),
        "Invalid condition sender boot ID"
    );
    ensure!(
        valid_field(&namespace, 128, false),
        "Invalid condition sender PID namespace"
    );
    Ok(SenderIdentity {
        pid: i64::from(pid),
        start,
        boot,
        namespace,
    })
}

pub(crate) fn sender_confirmed_gone(owner: &SenderIdentity) -> bool {
    let Ok(current) = current_sender_identity() else {
        return false;
    };
    if owner.pid <= 0 {
        return false;
    }
    if current.boot != owner.boot {
        return true;
    }
    if current.namespace != owner.namespace {
        return false;
    }
    let Ok(pid) = u32::try_from(owner.pid) else {
        return false;
    };
    if let Some(start) = crate::obligations::process_start_time(pid) {
        return i64::try_from(start).ok() != Some(owner.start);
    }
    (unsafe { libc::kill(pid as libc::pid_t, 0) == -1 })
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

fn require_sender(db: &Connection, group_id: &str) -> Result<SenderIdentity> {
    let owner: (Option<i64>, Option<i64>, Option<String>, Option<String>) = db.query_row(
        "SELECT sender_pid,sender_start,sender_boot,sender_namespace
         FROM condition_groups WHERE id=?1",
        [group_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let current = current_sender_identity()?;
    ensure!(
        owner
            == (
                Some(current.pid),
                Some(current.start),
                Some(current.boot.clone()),
                Some(current.namespace.clone())
            ),
        "This process does not own the delivery claim"
    );
    Ok(current)
}

fn native_selector(selector: &Selector) -> bool {
    matches!(selector.kind.as_str(), "thread" | "subagent")
}

/// Initialize the persistent condition tables. Existing publication paths
/// should call this during database startup before using the `_in` functions.
pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS condition_groups (
            id TEXT PRIMARY KEY,
            mode TEXT NOT NULL CHECK(mode IN ('and','or')),
            target_thread TEXT NOT NULL,
            message_template TEXT,
            depends_on TEXT REFERENCES condition_groups(id),
            depends_on_mode TEXT CHECK(depends_on_mode IN ('success_only','any_terminal')),
            state TEXT NOT NULL DEFAULT 'pending'
                CHECK(state IN ('pending','ready','claimed','accepted','uncertain','send_failed','succeeded','failed')),
            reason TEXT,
            sender_pid INTEGER,
            sender_start INTEGER,
            sender_boot TEXT,
            sender_namespace TEXT,
            retry_at TEXT,
            created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK((depends_on IS NULL) = (depends_on_mode IS NULL))
        );
        CREATE TABLE IF NOT EXISTS condition_members (
            group_id TEXT NOT NULL REFERENCES condition_groups(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            repo TEXT NOT NULL,
            resource TEXT NOT NULL,
            event TEXT NOT NULL,
            outcome TEXT NOT NULL DEFAULT '',
            matched INTEGER NOT NULL DEFAULT 0 CHECK(matched IN (0,1)),
            source_json TEXT,
            matched_event_key TEXT,
            armed INTEGER NOT NULL DEFAULT 1 CHECK(armed IN (0,1)),
            baseline_cursor TEXT,
            last_cursor TEXT,
            polling INTEGER NOT NULL DEFAULT 0 CHECK(polling IN (0,1)),
            buffer_overflow INTEGER NOT NULL DEFAULT 0 CHECK(buffer_overflow IN (0,1)),
            buffer_overflow_count INTEGER NOT NULL DEFAULT 0,
            order_uncertain INTEGER NOT NULL DEFAULT 0 CHECK(order_uncertain IN (0,1)),
            ambiguous_cursor TEXT,
            ci_repo TEXT NOT NULL DEFAULT '',
            ci_run_id INTEGER NOT NULL DEFAULT 0,
            ci_attempt INTEGER NOT NULL DEFAULT 0,
            ci_sha TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(group_id,kind,repo,resource,event,outcome,ci_repo,ci_run_id,ci_attempt,ci_sha)
        );
        CREATE TABLE IF NOT EXISTS condition_publications (
            source_event_key TEXT NOT NULL,
            kind TEXT NOT NULL,
            repo TEXT NOT NULL,
            resource TEXT NOT NULL,
            event TEXT NOT NULL,
            outcome TEXT NOT NULL DEFAULT '',
            ci_repo TEXT NOT NULL DEFAULT '',
            ci_run_id INTEGER NOT NULL DEFAULT 0,
            ci_attempt INTEGER NOT NULL DEFAULT 0,
            ci_sha TEXT NOT NULL DEFAULT '',
            event_cursor TEXT NOT NULL DEFAULT '',
            source_digest TEXT NOT NULL,
            native_poll_digest TEXT,
            recorded TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(source_event_key,kind,repo,resource,event,outcome,ci_repo,ci_run_id,ci_attempt,ci_sha)
        );
        CREATE TABLE IF NOT EXISTS condition_pending_events (
            group_id TEXT NOT NULL REFERENCES condition_groups(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            repo TEXT NOT NULL,
            resource TEXT NOT NULL,
            event TEXT NOT NULL,
            outcome TEXT NOT NULL DEFAULT '',
            ci_repo TEXT NOT NULL DEFAULT '',
            ci_run_id INTEGER NOT NULL DEFAULT 0,
            ci_attempt INTEGER NOT NULL DEFAULT 0,
            ci_sha TEXT NOT NULL DEFAULT '',
            source_event_key TEXT NOT NULL,
            event_cursor TEXT NOT NULL,
            source_digest TEXT NOT NULL,
            source_json TEXT NOT NULL,
            recorded TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(group_id,kind,repo,resource,event,outcome,ci_repo,ci_run_id,ci_attempt,ci_sha,source_event_key)
        );
        CREATE TABLE IF NOT EXISTS condition_publication_collisions (
            source_event_key TEXT NOT NULL,
            attempted_kind TEXT NOT NULL,
            attempted_repo TEXT NOT NULL,
            attempted_resource TEXT NOT NULL,
            attempted_event TEXT NOT NULL,
            attempted_outcome TEXT NOT NULL DEFAULT '',
            attempted_ci_repo TEXT NOT NULL DEFAULT '',
            attempted_ci_run_id INTEGER NOT NULL DEFAULT 0,
            attempted_ci_attempt INTEGER NOT NULL DEFAULT 0,
            attempted_ci_sha TEXT NOT NULL DEFAULT '',
            prior_digest TEXT,
            attempted_digest TEXT NOT NULL,
            reason TEXT NOT NULL CHECK(reason IN ('payload_changed','identity_reused')),
            conflict_count INTEGER NOT NULL DEFAULT 1,
            recorded TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(source_event_key)
        );
        CREATE TABLE IF NOT EXISTS condition_completions (
            group_id TEXT PRIMARY KEY REFERENCES condition_groups(id),
            kind TEXT NOT NULL,
            repo TEXT NOT NULL,
            resource TEXT NOT NULL,
            event TEXT NOT NULL,
            outcome TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL CHECK(result IN ('succeeded','failed')),
            source_event_key TEXT NOT NULL,
            source_json TEXT NOT NULL,
            recorded TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS condition_groups_ready
            ON condition_groups(state,created,id);
        CREATE INDEX IF NOT EXISTS condition_members_matched_event
            ON condition_members(matched_event_key) WHERE matched_event_key IS NOT NULL;
        CREATE INDEX IF NOT EXISTS condition_members_waiting
            ON condition_members(kind,repo,resource,event,outcome) WHERE matched=0;",
    )?;
    Ok(())
}

/// Register a group with exact Wake selectors and an optional single predecessor.
/// New IDs are generated here, and dependencies can only point to existing
/// groups, so this API cannot introduce a cycle. Past publications are not read.
#[cfg(test)]
pub fn register_group(
    db: &Connection,
    mode: Mode,
    members: &[Selector],
    target_thread: &str,
    message_template: Option<&str>,
    depends_on: Option<&Dependency>,
) -> Result<String> {
    let registrations = members
        .iter()
        .cloned()
        .map(|selector| {
            if native_selector(&selector) {
                MemberRegistration::polling(selector, None)
            } else {
                MemberRegistration::explicit(selector)
            }
        })
        .collect::<Vec<_>>();
    register_group_with_members(
        db,
        mode,
        &registrations,
        target_thread,
        message_template,
        depends_on,
    )
}

/// Register per-member observation mode. Explicit publications remain armed
/// immediately; polling members stay ineligible until their source baseline is
/// durably captured and `arm_observed_member` succeeds.
pub fn register_group_with_members(
    db: &Connection,
    mode: Mode,
    members: &[MemberRegistration],
    target_thread: &str,
    message_template: Option<&str>,
    depends_on: Option<&Dependency>,
) -> Result<String> {
    ensure!(
        !members.is_empty(),
        "A condition group needs at least one selector"
    );
    ensure!(
        members.len() <= 256,
        "A condition group has too many selectors"
    );
    let mut unique = HashSet::new();
    for member in members {
        validate_selector(&member.selector)?;
        validate_ci(&member.selector, member.ci.as_ref())?;
        ensure!(
            !native_selector(&member.selector) || member.observation == ObservationMode::Polling,
            "Native members must use polling observation"
        );
        ensure!(
            member.observation != ObservationMode::Polling
                || polling_kind(&member.selector, member.ci.as_ref()),
            "This selector kind has no supported polling observer"
        );
        ensure!(
            unique.insert(member),
            "Duplicate selector in condition group"
        );
    }
    let target_thread = Uuid::parse_str(target_thread)?.to_string();
    if let Some(template) = message_template {
        crate::templates::validate(template)?;
    }
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    if let Some(dependency) = depends_on {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM condition_groups WHERE id=?1)",
            [&dependency.group_id],
            |row| row.get(0),
        )?;
        ensure!(exists, "Unknown predecessor group");
    }
    let id = uuid::Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO condition_groups
         (id,mode,target_thread,message_template,depends_on,depends_on_mode)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            id,
            mode.as_str(),
            target_thread,
            message_template,
            depends_on.map(|dependency| dependency.group_id.as_str()),
            depends_on.map(|dependency| dependency.mode.as_str())
        ],
    )?;
    for member in members {
        let (ci_repo, ci_run_id, ci_attempt, ci_sha) = ci_parts(member.ci.as_ref());
        let polling = member.observation == ObservationMode::Polling;
        tx.execute(
            "INSERT INTO condition_members
             (group_id,kind,repo,resource,event,outcome,armed,polling,ci_repo,ci_run_id,ci_attempt,ci_sha)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                id,
                member.selector.kind,
                member.selector.repo,
                member.selector.resource,
                member.selector.event,
                outcome_value(member.selector.outcome.as_deref()),
                i64::from(!polling),
                i64::from(polling),
                ci_repo,
                ci_run_id,
                ci_attempt,
                ci_sha
            ],
        )?;
    }
    tx.commit()?;
    Ok(id)
}

/// Arm a native member only after native_poll has finished capturing its
/// baseline. This stores the baseline and flips `armed` in one transaction;
/// it does not perform or certify the native observation itself.
#[cfg(test)]
pub fn arm_native_member(
    db: &Connection,
    group_id: &str,
    selector: &Selector,
    baseline_cursor: Option<&str>,
) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let armed = arm_native_member_in(&tx, group_id, selector, baseline_cursor)?;
    tx.commit()?;
    Ok(armed)
}

/// Transaction-aware native baseline registration for the poller.
pub fn arm_native_member_in(
    db: &Connection,
    group_id: &str,
    selector: &Selector,
    baseline_cursor: Option<&str>,
) -> Result<bool> {
    ensure!(native_selector(selector), "Selector is not a native member");
    arm_observed_member_in(
        db,
        group_id,
        &MemberRegistration::polling(selector.clone(), None),
        baseline_cursor,
    )
}

/// Arm any polling-backed member after its poller has durably captured the
/// source baseline. Native events are matched only by their member's poller.
#[cfg(test)]
pub fn arm_observed_member(
    db: &Connection,
    group_id: &str,
    member: &MemberRegistration,
    baseline_cursor: Option<&str>,
) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let armed = arm_observed_member_in(&tx, group_id, member, baseline_cursor)?;
    tx.commit()?;
    Ok(armed)
}

/// Transaction-aware form for pollers already holding `BEGIN IMMEDIATE`.
pub fn arm_observed_member_in(
    db: &Connection,
    group_id: &str,
    member: &MemberRegistration,
    baseline_cursor: Option<&str>,
) -> Result<bool> {
    let selector = &member.selector;
    validate_selector(selector)?;
    validate_ci(selector, member.ci.as_ref())?;
    ensure!(
        member.observation == ObservationMode::Polling,
        "Only polling members need arming"
    );
    ensure!(
        polling_kind(selector, member.ci.as_ref()),
        "This selector kind has no supported polling observer"
    );
    if native_selector(selector) {
        ensure!(
            (selector.kind == "thread" && selector.event == "turn_completed")
                || (selector.kind == "subagent" && selector.event == "completed"),
            "Unsupported native completion selector"
        );
    }
    if let Some(cursor) = baseline_cursor {
        ensure!(valid_field(cursor, 255, false), "Invalid baseline cursor");
    }
    ensure!(
        native_selector(selector) || baseline_cursor.is_some(),
        "Polling members require a captured baseline cursor"
    );
    let overflow_count: i64 = db.query_row(
        "SELECT COALESCE((SELECT buffer_overflow_count FROM condition_members
          WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6
            AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10),0)",
        params![
            group_id,
            selector.kind,
            selector.repo,
            selector.resource,
            selector.event,
            outcome_value(selector.outcome.as_deref()),
            ci_parts(member.ci.as_ref()).0,
            ci_parts(member.ci.as_ref()).1,
            ci_parts(member.ci.as_ref()).2,
            ci_parts(member.ci.as_ref()).3
        ],
        |row| row.get(0),
    )?;
    // Native pollers recover their turns from the saved baseline, not this unordered hook buffer.
    if overflow_count > 0 && !native_selector(selector) {
        ensure!(
            has_eligible_pending_event(db, group_id, member, baseline_cursor)?,
            "Pre-arm event buffer overflowed; retained event is not newer than baseline"
        );
    }
    let changed = db.execute(
        "UPDATE condition_members SET baseline_cursor=?1,last_cursor=?1,armed=1
         WHERE group_id=?2 AND kind=?3 AND repo=?4 AND resource=?5 AND event=?6
           AND outcome=?7 AND ci_repo=?8 AND ci_run_id=?9 AND ci_attempt=?10 AND ci_sha=?11
           AND polling=1 AND armed=0 AND matched=0",
        params![
            baseline_cursor,
            group_id,
            selector.kind,
            selector.repo,
            selector.resource,
            selector.event,
            outcome_value(selector.outcome.as_deref()),
            ci_parts(member.ci.as_ref()).0,
            ci_parts(member.ci.as_ref()).1,
            ci_parts(member.ci.as_ref()).2,
            ci_parts(member.ci.as_ref()).3
        ],
    )?;
    if changed == 1 {
        reconcile_member_pending_in(db, group_id, member, baseline_cursor)?;
        refresh_ready_in(db)?;
        return Ok(true);
    }
    let prior: Option<(bool, Option<String>)> = db
        .query_row(
            "SELECT armed,baseline_cursor FROM condition_members
             WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6
               AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10 AND polling=1",
            params![
                group_id,
                selector.kind,
                selector.repo,
                selector.resource,
                selector.event,
                outcome_value(selector.outcome.as_deref()),
                ci_parts(member.ci.as_ref()).0,
                ci_parts(member.ci.as_ref()).1,
                ci_parts(member.ci.as_ref()).2,
                ci_parts(member.ci.as_ref()).3
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match prior {
        Some((true, prior_cursor)) if prior_cursor.as_deref() == baseline_cursor => Ok(false),
        Some((true, _)) => bail!("Polling member is already armed to another baseline"),
        Some(_) => bail!("Native member is missing or already matched"),
        None => bail!("Native member is not registered in this group"),
    }
}

fn ordered_cursor_is_after_baseline(baseline_cursor: Option<&str>, cursor: &str) -> bool {
    baseline_cursor.is_some_and(|baseline| cursor > baseline)
}

fn has_eligible_pending_event(
    db: &Connection,
    group_id: &str,
    member: &MemberRegistration,
    baseline_cursor: Option<&str>,
) -> Result<bool> {
    let selector = &member.selector;
    if native_selector(selector) {
        return Ok(false);
    }
    let (ci_repo, ci_run_id, ci_attempt, ci_sha) = ci_parts(member.ci.as_ref());
    let cursor: Option<String> = db
        .query_row(
            "SELECT event_cursor FROM condition_pending_events
         WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6
           AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10
         ORDER BY event_cursor,recorded,source_event_key LIMIT 1",
            params![
                group_id,
                selector.kind,
                selector.repo,
                selector.resource,
                selector.event,
                outcome_value(selector.outcome.as_deref()),
                ci_repo,
                ci_run_id,
                ci_attempt,
                ci_sha
            ],
            |row| row.get(0),
        )
        .optional()?;
    Ok(cursor.is_some_and(|cursor| ordered_cursor_is_after_baseline(baseline_cursor, &cursor)))
}

fn reconcile_member_pending_in(
    db: &Connection,
    group_id: &str,
    member: &MemberRegistration,
    baseline_cursor: Option<&str>,
) -> Result<()> {
    let (ci_repo, ci_run_id, ci_attempt, ci_sha) = ci_parts(member.ci.as_ref());
    let selector = &member.selector;
    let pending = {
        let mut statement = db.prepare(
            "SELECT event_cursor,source_event_key,source_json FROM condition_pending_events
             WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6
               AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10
             ORDER BY event_cursor,recorded,source_event_key",
        )?;
        statement
            .query_map(
                params![
                    group_id,
                    selector.kind,
                    selector.repo,
                    selector.resource,
                    selector.event,
                    outcome_value(selector.outcome.as_deref()),
                    ci_repo,
                    ci_run_id,
                    ci_attempt,
                    ci_sha
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let eligible = if native_selector(selector) {
        // Native events need the member poller's chronological turn list.
        None
    } else {
        pending
            .into_iter()
            .find(|(cursor, _, _)| ordered_cursor_is_after_baseline(baseline_cursor, cursor))
    };
    if let Some((cursor, source_event_key, source)) = eligible {
        db.execute(
            "UPDATE condition_members SET matched=1,source_json=?1,last_cursor=?2,matched_event_key=?3,
                 buffer_overflow=0,buffer_overflow_count=0
             WHERE group_id=?4 AND kind=?5 AND repo=?6 AND resource=?7 AND event=?8 AND outcome=?9
               AND ci_repo=?10 AND ci_run_id=?11 AND ci_attempt=?12 AND ci_sha=?13
               AND armed=1 AND matched=0",
            params![
                source,
                cursor,
                source_event_key,
                group_id,
                selector.kind,
                selector.repo,
                selector.resource,
                selector.event,
                outcome_value(selector.outcome.as_deref()),
                ci_repo,
                ci_run_id,
                ci_attempt,
                ci_sha
            ],
        )?;
    }
    if native_selector(selector) {
        db.execute(
            "UPDATE condition_members SET buffer_overflow=0,buffer_overflow_count=0
             WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5
               AND outcome=?6 AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10",
            params![
                group_id,
                selector.kind,
                selector.repo,
                selector.resource,
                selector.event,
                outcome_value(selector.outcome.as_deref()),
                ci_repo,
                ci_run_id,
                ci_attempt,
                ci_sha
            ],
        )?;
    }
    db.execute(
        "DELETE FROM condition_pending_events
         WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6
           AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10",
        params![
            group_id,
            selector.kind,
            selector.repo,
            selector.resource,
            selector.event,
            outcome_value(selector.outcome.as_deref()),
            ci_repo,
            ci_run_id,
            ci_attempt,
            ci_sha
        ],
    )?;
    Ok(())
}

/// Observe one publication against registered members. Global and native
/// poller payload digests are tracked separately; native members require their
/// own poller's ordering evidence.
pub fn record_published_event(db: &Connection, event: &PublishedEvent) -> Result<EventRecord> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let ready = record_published_event_in(&tx, event)?;
    tx.commit()?;
    Ok(ready)
}

/// Record a native completion after this member's poller proved it follows its
/// own baseline in the source's chronological turn list.
pub fn record_native_poll_event(
    db: &Connection,
    group_id: &str,
    event: &PublishedEvent,
) -> Result<EventRecord> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let record = record_native_poll_event_in(&tx, group_id, event)?;
    tx.commit()?;
    Ok(record)
}

/// Transaction-aware native poll publication for callers already holding a
/// write transaction. Its exact payload is checked in the poller provenance slot.
pub fn record_native_poll_event_in(
    db: &Connection,
    group_id: &str,
    event: &PublishedEvent,
) -> Result<EventRecord> {
    record_native_member_event_in(db, group_id, event, true)
}

/// Record an explicitly accepted ambiguous hook event for one armed member.
/// It keeps the global publisher provenance separate from native poller data.
pub fn record_native_accepted_event_in(
    db: &Connection,
    group_id: &str,
    event: &PublishedEvent,
) -> Result<EventRecord> {
    record_native_member_event_in(db, group_id, event, false)
}

fn record_native_member_event_in(
    db: &Connection,
    group_id: &str,
    event: &PublishedEvent,
    native_poll_provenance: bool,
) -> Result<EventRecord> {
    ensure!(
        native_selector(&event.selector),
        "Selector is not a native member"
    );
    ensure!(
        valid_field(group_id, 255, false),
        "Invalid condition group ID"
    );
    let registered: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM condition_members
         WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5
           AND (outcome='' OR outcome=?6) AND polling=1 AND armed=1)",
        params![
            group_id,
            event.selector.kind,
            event.selector.repo,
            event.selector.resource,
            event.selector.event,
            outcome_value(event.selector.outcome.as_deref())
        ],
        |row| row.get(0),
    )?;
    ensure!(registered, "Native event has no armed group member");
    record_published_event_scoped_in(db, event, Some(group_id), native_poll_provenance)
}

/// Transaction-aware form for publishers that already update subscriptions in
/// a transaction; this keeps condition matching atomic with the Wake publish.
pub fn record_published_event_in(db: &Connection, event: &PublishedEvent) -> Result<EventRecord> {
    record_published_event_scoped_in(db, event, None, false)
}

fn record_published_event_scoped_in(
    db: &Connection,
    event: &PublishedEvent,
    native_group_id: Option<&str>,
    native_poll_provenance: bool,
) -> Result<EventRecord> {
    validate_selector(&event.selector)?;
    ensure!(
        valid_field(&event.source_event_key, 512, false),
        "Invalid source event key"
    );
    let source = serde_json::to_string(&event.source)?;
    ensure!(
        source.len() <= MAX_SOURCE_BYTES,
        "Event source exceeds 1 MiB"
    );
    let selector = &event.selector;
    ensure!(
        !native_poll_provenance || (native_selector(selector) && native_group_id.is_some()),
        "Native poll provenance requires a scoped native member"
    );
    validate_ci(selector, event.ci.as_ref())?;
    if let Some(cursor) = event.cursor.as_deref() {
        ensure!(valid_field(cursor, 255, false), "Invalid event cursor");
    }
    if native_selector(selector) {
        ensure!(
            event
                .cursor
                .as_deref()
                .is_some_and(|cursor| valid_field(cursor, 255, false)),
            "Native publication requires a valid turn cursor"
        );
    }
    let (ci_repo, ci_run_id, ci_attempt, ci_sha) = ci_parts(event.ci.as_ref());
    let cursor = event.cursor.as_deref().unwrap_or("");
    let digest = format!("{:x}", Sha256::digest(source.as_bytes()));
    type PriorContext = (String, String, String, String, i64, i64, String, String);
    let prior_context: Option<PriorContext> = db
        .query_row(
            "SELECT kind,repo,resource,ci_repo,ci_run_id,ci_attempt,ci_sha,event_cursor FROM condition_publications
             WHERE source_event_key=?1 LIMIT 1",
            [&event.source_event_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
        )
        .optional()?;
    if prior_context.is_some_and(|prior| {
        prior
            != (
                selector.kind.clone(),
                selector.repo.clone(),
                selector.resource.clone(),
                ci_repo.to_owned(),
                ci_run_id,
                ci_attempt,
                ci_sha.to_owned(),
                cursor.to_owned(),
            )
    }) {
        save_event_collision(db, event, &digest, None, "identity_reused")?;
        return Ok(EventRecord {
            ready_groups: 0,
            new_members: 0,
            new_groups: 0,
            buffer_overflow: false,
            payload_collision: true,
        });
    }
    let prior_digest: Option<String> = if native_poll_provenance {
        db.query_row(
            "SELECT native_poll_digest FROM condition_publications
             WHERE source_event_key=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6
               AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10",
            params![
                event.source_event_key,
                selector.kind,
                selector.repo,
                selector.resource,
                selector.event,
                outcome_value(selector.outcome.as_deref()),
                ci_repo,
                ci_run_id,
                ci_attempt,
                ci_sha
            ],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
    } else {
        db.query_row(
            "SELECT source_digest FROM condition_publications
             WHERE source_event_key=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6
               AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10",
            params![
                event.source_event_key,
                selector.kind,
                selector.repo,
                selector.resource,
                selector.event,
                outcome_value(selector.outcome.as_deref()),
                ci_repo,
                ci_run_id,
                ci_attempt,
                ci_sha
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .filter(|prior| !prior.is_empty())
    };
    if let Some(prior) = prior_digest {
        if prior != digest {
            save_event_collision(db, event, &digest, Some(&prior), "payload_changed")?;
            return Ok(EventRecord {
                ready_groups: 0,
                new_members: 0,
                new_groups: 0,
                buffer_overflow: false,
                payload_collision: true,
            });
        }
        if native_group_id.is_none() {
            return Ok(EventRecord::default());
        }
    } else {
        let publication_exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM condition_publications
             WHERE source_event_key=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6
               AND ci_repo=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10)",
            params![
                event.source_event_key,
                selector.kind,
                selector.repo,
                selector.resource,
                selector.event,
                outcome_value(selector.outcome.as_deref()),
                ci_repo,
                ci_run_id,
                ci_attempt,
                ci_sha
            ],
            |row| row.get(0),
        )?;
        if publication_exists {
            let changed = if native_poll_provenance {
                db.execute(
                    "UPDATE condition_publications SET native_poll_digest=?1
                     WHERE source_event_key=?2 AND kind=?3 AND repo=?4 AND resource=?5 AND event=?6 AND outcome=?7
                       AND ci_repo=?8 AND ci_run_id=?9 AND ci_attempt=?10 AND ci_sha=?11
                       AND native_poll_digest IS NULL",
                    params![
                        digest,
                        event.source_event_key,
                        selector.kind,
                        selector.repo,
                        selector.resource,
                        selector.event,
                        outcome_value(selector.outcome.as_deref()),
                        ci_repo,
                        ci_run_id,
                        ci_attempt,
                        ci_sha
                    ],
                )?
            } else {
                db.execute(
                    "UPDATE condition_publications SET source_digest=?1
                     WHERE source_event_key=?2 AND kind=?3 AND repo=?4 AND resource=?5 AND event=?6 AND outcome=?7
                       AND ci_repo=?8 AND ci_run_id=?9 AND ci_attempt=?10 AND ci_sha=?11 AND source_digest=''",
                    params![
                        digest,
                        event.source_event_key,
                        selector.kind,
                        selector.repo,
                        selector.resource,
                        selector.event,
                        outcome_value(selector.outcome.as_deref()),
                        ci_repo,
                        ci_run_id,
                        ci_attempt,
                        ci_sha
                    ],
                )?
            };
            ensure!(changed == 1, "Publication digest changed concurrently");
        } else {
            // The global digest column is mandatory; an empty value marks a
            // poller-first receipt that has no global publisher digest yet.
            let (source_digest, native_poll_digest) = if native_poll_provenance {
                ("", Some(digest.as_str()))
            } else {
                (digest.as_str(), None)
            };
            db.execute(
                "INSERT INTO condition_publications
                 (source_event_key,kind,repo,resource,event,outcome,ci_repo,ci_run_id,ci_attempt,ci_sha,event_cursor,source_digest,native_poll_digest)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    event.source_event_key,
                    selector.kind,
                    selector.repo,
                    selector.resource,
                    selector.event,
                    outcome_value(selector.outcome.as_deref()),
                    ci_repo,
                    ci_run_id,
                    ci_attempt,
                    ci_sha,
                    cursor,
                    source_digest,
                    native_poll_digest
                ],
            )?;
        }
    }
    let buffered_groups: Vec<String> = if native_group_id.is_some() {
        Vec::new()
    } else {
        let mut statement = db.prepare(
        "INSERT OR IGNORE INTO condition_pending_events
         (group_id,kind,repo,resource,event,outcome,ci_repo,ci_run_id,ci_attempt,ci_sha,
          source_event_key,event_cursor,source_digest,source_json)
         SELECT group_id,kind,repo,resource,event,outcome,ci_repo,ci_run_id,ci_attempt,ci_sha,
                ?1,?7,?12,?13
         FROM condition_members m WHERE m.matched=0 AND m.armed=0 AND m.polling=1
           AND ?7!=''
           AND m.kind=?2 AND m.repo=?3 AND m.resource=?4 AND m.event=?5
           AND (m.outcome='' OR m.outcome=?6)
           AND (m.ci_run_id=0 OR (m.ci_repo=?8 AND m.ci_run_id=?9 AND m.ci_attempt=?10 AND m.ci_sha=?11))
           AND NOT EXISTS (
               SELECT 1 FROM condition_pending_events p WHERE p.group_id=m.group_id
                 AND p.kind=m.kind AND p.repo=m.repo AND p.resource=m.resource AND p.event=m.event
                 AND p.outcome=m.outcome AND p.ci_repo=m.ci_repo AND p.ci_run_id=m.ci_run_id
                 AND p.ci_attempt=m.ci_attempt AND p.ci_sha=m.ci_sha
           )
         RETURNING group_id",
        )?;
        statement
            .query_map(
                params![
                    event.source_event_key,
                    selector.kind,
                    selector.repo,
                    selector.resource,
                    selector.event,
                    outcome_value(selector.outcome.as_deref()),
                    cursor,
                    ci_repo,
                    ci_run_id,
                    ci_attempt,
                    ci_sha,
                    digest,
                    source
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let overflowed_groups: Vec<String> = if native_group_id.is_some() {
        Vec::new()
    } else {
        let mut statement = db.prepare(
            "UPDATE condition_members AS m
             SET buffer_overflow=1,buffer_overflow_count=buffer_overflow_count+1
             WHERE matched=0 AND armed=0 AND polling=1
               AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5
               AND (outcome='' OR outcome=?6)
               AND (ci_run_id=0 OR (ci_repo=?8 AND ci_run_id=?9 AND ci_attempt=?10 AND ci_sha=?11))
               AND EXISTS (
                   SELECT 1 FROM condition_pending_events p WHERE p.group_id=m.group_id
                     AND p.kind=m.kind AND p.repo=m.repo AND p.resource=m.resource AND p.event=m.event
                     AND p.outcome=m.outcome AND p.ci_repo=m.ci_repo AND p.ci_run_id=m.ci_run_id
                     AND p.ci_attempt=m.ci_attempt AND p.ci_sha=m.ci_sha AND p.source_event_key!=?1
               )
             RETURNING group_id",
        )?;
        statement
            .query_map(
                params![
                    event.source_event_key,
                    selector.kind,
                    selector.repo,
                    selector.resource,
                    selector.event,
                    outcome_value(selector.outcome.as_deref()),
                    cursor,
                    ci_repo,
                    ci_run_id,
                    ci_attempt,
                    ci_sha
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let matched_groups = {
        let mut statement = db.prepare(
        "UPDATE condition_members SET matched=1,source_json=?1,matched_event_key=?12,
             last_cursor=CASE WHEN polling=1 THEN ?7 ELSE last_cursor END
         WHERE matched=0 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5
           AND (outcome='' OR outcome=?6) AND armed=1
           AND (ci_run_id=0 OR (ci_repo=?8 AND ci_run_id=?9 AND ci_attempt=?10 AND ci_sha=?11))
           AND (
                (kind IN ('thread','subagent') AND ?13 IS NOT NULL AND group_id=?13) OR
                (kind NOT IN ('thread','subagent') AND ?13 IS NULL
                    AND (polling=0 OR (?7!='' AND baseline_cursor IS NOT NULL AND ?7>baseline_cursor)))
           )
         RETURNING group_id",
        )?;
        statement
            .query_map(
                params![
                    source,
                    selector.kind,
                    selector.repo,
                    selector.resource,
                    selector.event,
                    outcome_value(selector.outcome.as_deref()),
                    cursor,
                    ci_repo,
                    ci_run_id,
                    ci_attempt,
                    ci_sha,
                    event.source_event_key,
                    native_group_id
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let new_groups = buffered_groups
        .iter()
        .chain(&matched_groups)
        .collect::<HashSet<_>>()
        .len();
    Ok(EventRecord {
        ready_groups: refresh_ready_in(db)?,
        new_members: buffered_groups.len() + matched_groups.len(),
        new_groups,
        buffer_overflow: !overflowed_groups.is_empty(),
        payload_collision: false,
    })
}

fn save_event_collision(
    db: &Connection,
    event: &PublishedEvent,
    attempted_digest: &str,
    prior_digest: Option<&str>,
    reason: &str,
) -> Result<()> {
    let (ci_repo, ci_run_id, ci_attempt, ci_sha) = ci_parts(event.ci.as_ref());
    db.execute(
        "INSERT OR IGNORE INTO condition_publication_collisions
         (source_event_key,attempted_kind,attempted_repo,attempted_resource,attempted_event,
          attempted_outcome,attempted_ci_repo,attempted_ci_run_id,attempted_ci_attempt,
          attempted_ci_sha,prior_digest,attempted_digest,reason)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(source_event_key) DO UPDATE SET
           attempted_kind=excluded.attempted_kind,attempted_repo=excluded.attempted_repo,
           attempted_resource=excluded.attempted_resource,attempted_event=excluded.attempted_event,
           attempted_outcome=excluded.attempted_outcome,attempted_ci_repo=excluded.attempted_ci_repo,
           attempted_ci_run_id=excluded.attempted_ci_run_id,attempted_ci_attempt=excluded.attempted_ci_attempt,
           attempted_ci_sha=excluded.attempted_ci_sha,prior_digest=excluded.prior_digest,
           attempted_digest=excluded.attempted_digest,reason=excluded.reason,
           conflict_count=condition_publication_collisions.conflict_count+1,
           recorded=CURRENT_TIMESTAMP",
        params![
            event.source_event_key,
            event.selector.kind,
            event.selector.repo,
            event.selector.resource,
            event.selector.event,
            outcome_value(event.selector.outcome.as_deref()),
            ci_repo,
            ci_run_id,
            ci_attempt,
            ci_sha,
            prior_digest,
            attempted_digest,
            reason
        ],
    )?;
    Ok(())
}

/// Bounded, payload-free collision notice for publication callers to surface as
/// a warning without rolling back their unrelated subscription/obligation work.
pub fn publication_collision_count(db: &Connection, source_event_key: &str) -> Result<i64> {
    db.query_row(
        "SELECT COALESCE((SELECT conflict_count FROM condition_publication_collisions
                          WHERE source_event_key=?1),0)",
        [source_event_key],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// Number of distinct groups satisfied by this publication, not by an older
/// event with the same selector.
#[cfg(test)]
pub fn matched_group_count_for_event(db: &Connection, source_event_key: &str) -> Result<i64> {
    db.query_row(
        "SELECT count(DISTINCT group_id) FROM condition_members WHERE matched_event_key=?1",
        [source_event_key],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// Enumerate unmatched polling members without returning event payloads.
/// Unarmed entries are waiting for their baseline handshake; armed entries
/// expose the saved cursor so pollers can resume observation after restart.
pub fn pending_polling_members(
    db: &Connection,
    only_group: Option<&str>,
) -> Result<Vec<PollingMemberStatus>> {
    let mut statement = db.prepare(
        "SELECT m.group_id,m.kind,m.repo,m.resource,m.event,m.outcome,
                m.ci_repo,m.ci_run_id,m.ci_attempt,m.ci_sha,g.state,m.armed,
                m.baseline_cursor,m.last_cursor,m.buffer_overflow,m.buffer_overflow_count
         FROM condition_members m JOIN condition_groups g ON g.id=m.group_id
         WHERE m.polling=1 AND m.matched=0 AND (?1 IS NULL OR m.group_id=?1)
         ORDER BY g.created,m.group_id,m.kind,m.repo,m.resource,m.event,m.outcome,
                  m.ci_repo,m.ci_run_id,m.ci_attempt,m.ci_sha",
    )?;
    let rows = statement.query_map([only_group], |row| {
        let kind: String = row.get(1)?;
        let repo: String = row.get(2)?;
        let resource: String = row.get(3)?;
        let event: String = row.get(4)?;
        let outcome: String = row.get(5)?;
        let ci_repo: String = row.get(6)?;
        let ci_run_id: i64 = row.get(7)?;
        let ci_attempt: i64 = row.get(8)?;
        let ci_sha: String = row.get(9)?;
        Ok(PollingMemberStatus {
            group_id: row.get(0)?,
            selector: Selector {
                kind,
                repo,
                resource,
                event,
                outcome: (!outcome.is_empty()).then_some(outcome),
            },
            ci: (ci_run_id > 0).then_some(CiRunIdentity {
                repo: ci_repo,
                run_id: ci_run_id,
                attempt: ci_attempt,
                sha: ci_sha,
            }),
            group_state: row.get(10)?,
            armed: row.get(11)?,
            baseline_cursor: row.get(12)?,
            last_cursor: row.get(13)?,
            buffer_overflow: row.get(14)?,
            buffer_overflow_count: row.get(15)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Claim one delivery exactly once. A claim left by a crash is not reclaimed,
/// because the external send may have succeeded despite an unknown receipt.
pub fn claim_ready(db: &Connection) -> Result<Option<Delivery>> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE condition_groups SET state='ready',reason=NULL,retry_at=NULL,sender_pid=NULL,
             sender_start=NULL,sender_boot=NULL,sender_namespace=NULL
         WHERE state='send_failed' AND reason='target_unavailable_before_send'
           AND retry_at IS NOT NULL AND retry_at<=CURRENT_TIMESTAMP",
        [],
    )?;
    let row: Option<(String, String, Option<String>)> = tx
        .query_row(
            "SELECT id,target_thread,message_template FROM condition_groups
             WHERE state='ready' ORDER BY created,id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((id, target_thread, message_template)) = row else {
        tx.commit()?;
        return Ok(None);
    };
    let sender = current_sender_identity()?;
    ensure!(
        tx.execute(
            "UPDATE condition_groups SET state='claimed',reason=NULL,sender_pid=?2,
                 sender_start=?3,sender_boot=?4,sender_namespace=?5
             WHERE id=?1 AND state='ready'",
            params![id, sender.pid, sender.start, sender.boot, sender.namespace],
        )? == 1,
        "Ready delivery changed while being claimed"
    );
    let sources = {
        let mut statement = tx.prepare(
            "SELECT kind,repo,resource,event,outcome,source_json,ci_repo,ci_run_id,ci_attempt,ci_sha,matched_event_key FROM condition_members
             WHERE group_id=?1 AND matched=1 ORDER BY kind,repo,resource,event,outcome",
        )?;
        statement
            .query_map([&id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            })?
            .map(|row| {
                let (
                    kind,
                    repo,
                    resource,
                    event,
                    outcome,
                    source,
                    ci_repo,
                    ci_run_id,
                    ci_attempt,
                    ci_sha,
                    source_event_key,
                ) = row?;
                Ok(MatchedSource {
                    selector: Selector {
                        kind,
                        repo,
                        resource,
                        event,
                        outcome: (!outcome.is_empty()).then_some(outcome),
                    },
                    ci: (ci_run_id > 0).then_some(CiRunIdentity {
                        repo: ci_repo,
                        run_id: ci_run_id,
                        attempt: ci_attempt,
                        sha: ci_sha,
                    }),
                    source_event_key: source_event_key
                        .context("Matched condition member has no source event key")?,
                    source: serde_json::from_str(&source)?,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };
    tx.commit()?;
    Ok(Some(Delivery {
        group_id: id,
        target_thread,
        message_template,
        sources,
    }))
}

/// Persist the sender's explicit acceptance. This does not complete the work
/// or enable dependent groups.
pub fn record_delivery_accepted(db: &Connection, group_id: &str) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let changed = record_delivery_accepted_in(&tx, group_id)?;
    tx.commit()?;
    Ok(changed)
}

pub fn record_delivery_accepted_in(db: &Connection, group_id: &str) -> Result<bool> {
    let state: Option<String> = db
        .query_row(
            "SELECT state FROM condition_groups WHERE id=?1",
            [group_id],
            |row| row.get(0),
        )
        .optional()?;
    match state.as_deref() {
        Some("accepted") => Ok(false),
        Some("succeeded" | "failed") => {
            require_sender(db, group_id)?;
            Ok(false)
        }
        Some("claimed" | "uncertain") => {
            require_sender(db, group_id)?;
            Ok(db.execute(
                "UPDATE condition_groups SET state='accepted',reason=NULL
                 WHERE id=?1 AND state IN ('claimed','uncertain')",
                [group_id],
            )? == 1)
        }
        Some(_) => bail!("Delivery is not awaiting sender acceptance"),
        None => bail!("Unknown delivery group"),
    }
}

/// Record a send whose acceptance is unknown. It remains unreclaimable, but a
/// later explicit acceptance or terminal event can resolve the uncertainty.
pub fn record_delivery_uncertain(db: &Connection, group_id: &str) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let changed = record_delivery_uncertain_in(&tx, group_id)?;
    tx.commit()?;
    Ok(changed)
}

pub fn record_delivery_uncertain_in(db: &Connection, group_id: &str) -> Result<bool> {
    let state: Option<String> = db
        .query_row(
            "SELECT state FROM condition_groups WHERE id=?1",
            [group_id],
            |row| row.get(0),
        )
        .optional()?;
    match state.as_deref() {
        Some("uncertain") => Ok(false),
        Some("succeeded" | "failed") => {
            require_sender(db, group_id)?;
            Ok(false)
        }
        Some("claimed") => {
            require_sender(db, group_id)?;
            Ok(db.execute(
                "UPDATE condition_groups SET state='uncertain',reason='send_outcome_unknown'
                 WHERE id=?1 AND state='claimed'",
                [group_id],
            )? == 1)
        }
        Some(_) => bail!("Delivery is not awaiting a send result"),
        None => bail!("Unknown delivery group"),
    }
}

/// Reconcile only claims whose recorded sender identity is provably gone.
/// Active or unverifiable senders stay claimed; ambiguous sends stay unreclaimable.
pub fn reconcile_interrupted_claims(db: &Connection) -> Result<usize> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let owners = {
        let mut statement = tx.prepare(
            "SELECT id,sender_pid,sender_start,sender_boot,sender_namespace
             FROM condition_groups WHERE state='claimed'",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut count = 0;
    for (id, pid, start, boot, namespace) in owners {
        let (Some(pid), Some(start), Some(boot), Some(namespace)) = (pid, start, boot, namespace)
        else {
            continue;
        };
        let owner = SenderIdentity {
            pid,
            start,
            boot,
            namespace,
        };
        if sender_confirmed_gone(&owner) {
            count += tx.execute(
                "UPDATE condition_groups SET state='uncertain',reason='sender_exit_confirmed'
                 WHERE id=?1 AND state='claimed' AND sender_pid=?2 AND sender_start=?3
                   AND sender_boot=?4 AND sender_namespace=?5",
                params![id, owner.pid, owner.start, owner.boot, owner.namespace],
            )?;
        }
    }
    tx.commit()?;
    Ok(count)
}

/// A bounded machine-readable reason for a failure known to occur before any
/// bytes/message were transmitted. Unlike `uncertain`, this state may be retried.
pub fn record_delivery_pre_send_failed(
    db: &Connection,
    group_id: &str,
    reason: &str,
) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let changed = record_delivery_pre_send_failed_in(&tx, group_id, reason)?;
    tx.commit()?;
    Ok(changed)
}

pub fn record_delivery_pre_send_failed_in(
    db: &Connection,
    group_id: &str,
    reason: &str,
) -> Result<bool> {
    ensure!(
        matches!(reason, "template_error" | "target_unavailable_before_send"),
        "Unsupported pre-send failure reason"
    );
    require_sender(db, group_id)?;
    Ok(db.execute(
        "UPDATE condition_groups SET state='send_failed',reason=?2,
             retry_at=CASE WHEN ?2='target_unavailable_before_send'
                           THEN datetime('now','+15 seconds') ELSE NULL END
         WHERE id=?1 AND state='claimed'",
        params![group_id, reason],
    )? == 1)
}

/// Explicitly retry only a known pre-send error; `uncertain` is never retried.
#[cfg(test)]
pub fn retry_pre_send_failed(db: &Connection, group_id: &str) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE condition_groups SET state='ready',reason=NULL,retry_at=NULL,sender_pid=NULL,
             sender_start=NULL,sender_boot=NULL,sender_namespace=NULL
         WHERE id=?1 AND state='send_failed' AND reason='target_unavailable_before_send'
           AND retry_at IS NOT NULL AND retry_at<=CURRENT_TIMESTAMP",
        [group_id],
    )?;
    tx.commit()?;
    Ok(changed == 1)
}

#[cfg(test)]
pub fn delivery_status(db: &Connection, group_id: &str) -> Result<DeliveryStatus> {
    let (state, reason, sender_pid, sender_start, sender_boot, sender_namespace, retry_at) = db
        .query_row(
            "SELECT state,reason,sender_pid,sender_start,sender_boot,sender_namespace,retry_at
         FROM condition_groups WHERE id=?1",
            [group_id],
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
        )?;
    Ok(DeliveryStatus {
        group_id: group_id.to_owned(),
        state,
        reason,
        sender_pid,
        sender_start,
        sender_boot,
        sender_namespace,
        retry_at,
    })
}

/// Complete an accepted or uncertain step from a terminal event correlated to
/// its destination chat. The caller supplies the observed work result; queued
/// acceptance is never a completion. Dependents advance atomically.
#[cfg(test)]
pub fn complete_delivery(
    db: &Connection,
    group_id: &str,
    event: &PublishedEvent,
    result: CompletionOutcome,
) -> Result<bool> {
    initialize(db)?;
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let changed = complete_delivery_in(&tx, group_id, event, result)?;
    tx.commit()?;
    Ok(changed)
}

/// Transaction-aware completion form for an explicit event publisher.
pub fn complete_delivery_in(
    db: &Connection,
    group_id: &str,
    event: &PublishedEvent,
    result: CompletionOutcome,
) -> Result<bool> {
    validate_selector(&event.selector)?;
    ensure!(
        valid_field(&event.source_event_key, 512, false),
        "Invalid source event key"
    );
    let source = serde_json::to_string(&event.source)?;
    ensure!(
        source.len() <= MAX_SOURCE_BYTES,
        "Event source exceeds 1 MiB"
    );
    let state: Option<(String, String)> = db
        .query_row(
            "SELECT state,target_thread FROM condition_groups WHERE id=?1",
            [group_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((state, target_thread)) = state else {
        bail!("Unknown delivery group")
    };
    if matches!(state.as_str(), "succeeded" | "failed") {
        validate_terminal_event(event, group_id, &target_thread, result)?;
        let recorded = record_published_event_in(db, event)?;
        if recorded.payload_collision {
            return Ok(false);
        }
        let prior: (String, String, String, String, String, String, String) = db.query_row(
            "SELECT kind,repo,resource,event,outcome,result,source_event_key FROM condition_completions
             WHERE group_id=?1",
            [group_id],
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
        )?;
        let selector = &event.selector;
        ensure!(
            prior
                == (
                    selector.kind.clone(),
                    selector.repo.clone(),
                    selector.resource.clone(),
                    selector.event.clone(),
                    outcome_value(selector.outcome.as_deref()).to_owned(),
                    result.as_str().to_owned(),
                    event.source_event_key.clone()
                ),
            "Delivery already has a different completion event"
        );
        return Ok(false);
    }
    ensure!(
        matches!(state.as_str(), "claimed" | "accepted" | "uncertain"),
        "Delivery must be claimed, accepted, or explicitly uncertain before completion"
    );
    validate_terminal_event(event, group_id, &target_thread, result)?;
    if record_published_event_in(db, event)?.payload_collision {
        return Ok(false);
    }
    let selector = &event.selector;
    db.execute(
        "INSERT INTO condition_completions
         (group_id,kind,repo,resource,event,outcome,result,source_event_key,source_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            group_id,
            selector.kind,
            selector.repo,
            selector.resource,
            selector.event,
            outcome_value(selector.outcome.as_deref()),
            result.as_str(),
            event.source_event_key,
            source
        ],
    )?;
    db.execute(
        "UPDATE condition_groups SET state=?1,reason=NULL
         WHERE id=?2 AND state IN ('claimed','accepted','uncertain')",
        params![result.as_str(), group_id],
    )?;
    refresh_ready_in(db)?;
    Ok(true)
}

fn validate_terminal_event(
    event: &PublishedEvent,
    group_id: &str,
    target_thread: &str,
    result: CompletionOutcome,
) -> Result<()> {
    let selector = &event.selector;
    ensure!(
        event.source.get("group_id").and_then(Value::as_str) == Some(group_id),
        "Completion publication must cite this group_id"
    );
    let turn_id = event
        .source
        .get("turn_id")
        .or_else(|| event.source.get("turnId"))
        .and_then(Value::as_str);
    ensure!(
        turn_id.is_some_and(|turn| valid_field(turn, 255, false)),
        "Completion publication must cite the work turn"
    );
    ensure!(
        selector.resource == target_thread,
        "Completion event does not match the delivery's target chat"
    );
    match selector.kind.as_str() {
        "chat" => {
            ensure!(
                selector.outcome.as_deref() == Some(selector.event.as_str())
                    && matches!(selector.event.as_str(), "completed" | "failed" | "blocked"),
                "Chat completion must have an explicit terminal outcome"
            );
            let expected = if selector.event == "completed" {
                CompletionOutcome::Succeeded
            } else {
                CompletionOutcome::Failed
            };
            ensure!(
                result == expected,
                "Completion result conflicts with chat outcome"
            );
        }
        "thread" => ensure!(
            selector.event == "turn_completed"
                && selector.outcome.as_deref() == Some("turn_completed")
                && event.cursor.as_deref() == turn_id
                && event.source.get("result").and_then(Value::as_str) == Some(result.as_str()),
            "Thread completion needs the cited terminal turn and result"
        ),
        _ => bail!("Completion must come from the target chat or thread"),
    }
    Ok(())
}

pub fn refresh_ready_in(db: &Connection) -> Result<usize> {
    Ok(db.execute(
        "UPDATE condition_groups AS g SET state='ready'
         WHERE g.state='pending'
           AND (g.depends_on IS NULL OR EXISTS (
               SELECT 1 FROM condition_groups p
               WHERE p.id=g.depends_on AND (
                   (g.depends_on_mode='success_only' AND p.state='succeeded') OR
                   (g.depends_on_mode='any_terminal' AND p.state IN ('succeeded','failed'))
               )
           ))
           AND (
               (g.mode='and' AND NOT EXISTS (
                   SELECT 1 FROM condition_members m
                   WHERE m.group_id=g.id AND m.matched=0
               ))
               OR
               (g.mode='or' AND EXISTS (
                   SELECT 1 FROM condition_members m
                   WHERE m.group_id=g.id AND m.matched=1
               ))
           )",
        [],
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Barrier, thread, time::Duration};
    use tempfile::tempdir;

    const TARGET: &str = "11111111-1111-4111-8111-111111111111";

    fn selector(
        kind: &str,
        repo: &str,
        resource: &str,
        event: &str,
        outcome: Option<&str>,
    ) -> Selector {
        Selector {
            kind: kind.into(),
            repo: repo.into(),
            resource: resource.into(),
            event: event.into(),
            outcome: outcome.map(str::to_owned),
        }
    }

    fn source_key(selector: &Selector) -> String {
        format!(
            "test/v1/{}/{}/{}/{}/{}",
            selector.kind,
            selector.repo,
            selector.resource,
            selector.event,
            selector.outcome.as_deref().unwrap_or("*")
        )
    }

    fn published(selector: Selector) -> PublishedEvent {
        let source_event_key = source_key(&selector);
        PublishedEvent {
            source: serde_json::json!({"sample":"source payload"}),
            selector,
            source_event_key,
            cursor: None,
            ci: None,
        }
    }

    fn published_as(selector: Selector, source_event_key: &str) -> PublishedEvent {
        PublishedEvent {
            source: serde_json::json!({"sample":"source payload"}),
            selector,
            source_event_key: source_event_key.into(),
            cursor: None,
            ci: None,
        }
    }

    fn completion(group_id: &str, event: &str, result: CompletionOutcome) -> PublishedEvent {
        let mut event = published(selector("chat", "", TARGET, event, Some(event)));
        event.source_event_key = format!("completion/{group_id}/{}", result.as_str());
        event.source = serde_json::json!({
            "group_id": group_id,
            "turn_id": format!("turn-{group_id}"),
            "result": result.as_str()
        });
        event
    }

    fn native_published(selector: Selector, key: &str, cursor: &str) -> PublishedEvent {
        PublishedEvent {
            selector,
            source_event_key: key.into(),
            cursor: Some(cursor.into()),
            ci: None,
            source: serde_json::json!({"sample":"native source", "turn_id":cursor}),
        }
    }

    fn db() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let connection = Connection::open(dir.path().join("conditions.sqlite")).unwrap();
        connection.busy_timeout(Duration::from_secs(5)).unwrap();
        initialize(&connection).unwrap();
        (dir, connection)
    }

    fn dependency(group_id: &str, mode: ModeDependency) -> Dependency {
        Dependency {
            group_id: group_id.into(),
            mode,
        }
    }

    fn register(
        db: &Connection,
        mode: Mode,
        members: &[Selector],
        depends_on: Option<&Dependency>,
    ) -> String {
        register_group(
            db,
            mode,
            members,
            TARGET,
            Some("{{source.sample}}"),
            depends_on,
        )
        .unwrap()
    }

    fn ready_group(db: &Connection) -> String {
        let resource = uuid::Uuid::new_v4().to_string();
        let selector = selector("job", "org/repo", &resource, "success", Some("success"));
        let group = register(db, Mode::And, std::slice::from_ref(&selector), None);
        record_published_event(db, &published(selector)).unwrap();
        group
    }

    #[test]
    fn and_matches_distinct_wake_selectors_in_either_order_and_retains_sources() {
        let (_dir, db) = db();
        let ci = selector("job", "org/repo", "run-44", "success", Some("success"));
        let review = selector("review", "org/repo", "pr-9", "approved", Some("approved"));
        let group = register(&db, Mode::And, &[ci.clone(), review.clone()], None);
        assert_eq!(
            record_published_event(&db, &published(review))
                .unwrap()
                .ready_groups,
            0
        );
        assert!(claim_ready(&db).unwrap().is_none());
        assert_eq!(
            record_published_event(&db, &published(ci))
                .unwrap()
                .ready_groups,
            1
        );
        let delivery = claim_ready(&db).unwrap().unwrap();
        assert_eq!(delivery.group_id, group);
        assert_eq!(delivery.target_thread, TARGET);
        assert_eq!(
            delivery.message_template.as_deref(),
            Some("{{source.sample}}")
        );
        assert_eq!(delivery.sources.len(), 2);
        assert_eq!(delivery.sources[0].source["sample"], "source payload");
    }

    #[test]
    fn event_before_registration_is_not_replayed_but_future_event_matches() {
        let (_dir, db) = db();
        let old = published(selector(
            "review",
            "org/repo",
            "pr-4",
            "approved",
            Some("approved"),
        ));
        record_published_event(&db, &old).unwrap();
        let group = register(&db, Mode::Or, std::slice::from_ref(&old.selector), None);
        assert!(claim_ready(&db).unwrap().is_none());
        let later = published_as(old.selector.clone(), "review-event-2");
        assert_eq!(record_published_event(&db, &old).unwrap().ready_groups, 0);
        assert_eq!(record_published_event(&db, &later).unwrap().ready_groups, 1);
        assert_eq!(
            matched_group_count_for_event(&db, "review-event-2").unwrap(),
            1
        );
        assert_eq!(
            matched_group_count_for_event(&db, &source_key(&old.selector)).unwrap(),
            0
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
    }

    #[test]
    fn exact_selector_isolation_outcome_wildcard_and_duplicate_publication() {
        let (_dir, db) = db();
        let group = register(
            &db,
            Mode::Or,
            &[selector("job", "org/repo", "run-2", "completed", None)],
            None,
        );
        let success_only = register(
            &db,
            Mode::Or,
            &[selector(
                "job",
                "org/repo",
                "run-2",
                "completed",
                Some("success"),
            )],
            None,
        );
        let wrong = published(selector(
            "job",
            "org/other",
            "run-2",
            "completed",
            Some("success"),
        ));
        assert_eq!(record_published_event(&db, &wrong).unwrap().ready_groups, 0);
        let event = published(selector(
            "job",
            "org/repo",
            "run-2",
            "completed",
            Some("failure"),
        ));
        assert_eq!(record_published_event(&db, &event).unwrap().ready_groups, 1);
        assert_eq!(record_published_event(&db, &event).unwrap().ready_groups, 0);
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
        assert!(claim_ready(&db).unwrap().is_none());
        assert_ne!(group, success_only);
    }

    #[test]
    fn one_event_key_can_match_alias_selectors_and_replays_are_per_selector() {
        let (_dir, db) = db();
        let target_a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let target_b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let success = selector("job", "org/repo", "run-44", "success", Some("success"));
        let completed = selector("job", "org/repo", "run-44", "completed", None);
        let group_a = register_group(
            &db,
            Mode::Or,
            std::slice::from_ref(&success),
            target_a,
            None,
            None,
        )
        .unwrap();
        let group_b = register_group(
            &db,
            Mode::Or,
            std::slice::from_ref(&completed),
            target_b,
            None,
            None,
        )
        .unwrap();
        let first = published_as(success.clone(), "ci/occurrence-44");
        let alias = published_as(completed.clone(), "ci/occurrence-44");
        let first_result = record_published_event(&db, &first).unwrap();
        assert_eq!(first_result.ready_groups, 1);
        assert_eq!((first_result.new_members, first_result.new_groups), (1, 1));
        let alias_result = record_published_event(&db, &alias).unwrap();
        assert_eq!(alias_result.ready_groups, 1);
        assert_eq!((alias_result.new_members, alias_result.new_groups), (1, 1));
        assert_eq!(
            matched_group_count_for_event(&db, "ci/occurrence-44").unwrap(),
            2
        );
        let first_replay = record_published_event(&db, &first).unwrap();
        assert_eq!(first_replay.ready_groups, 0);
        assert_eq!((first_replay.new_members, first_replay.new_groups), (0, 0));
        let alias_replay = record_published_event(&db, &alias).unwrap();
        assert_eq!(alias_replay.ready_groups, 0);
        assert_eq!((alias_replay.new_members, alias_replay.new_groups), (0, 0));
        let mut changed_replay = first.clone();
        changed_replay.source["sample"] = serde_json::json!("altered payload");
        db.execute_batch("CREATE TABLE ordinary_publish_effect(value TEXT);")
            .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        db.execute(
            "INSERT INTO ordinary_publish_effect VALUES('committed')",
            [],
        )
        .unwrap();
        let collision = record_published_event_in(&db, &changed_replay).unwrap();
        db.execute_batch("COMMIT").unwrap();
        assert!(collision.payload_collision);
        assert_eq!(
            publication_collision_count(&db, "ci/occurrence-44").unwrap(),
            1
        );
        assert_eq!(
            publication_collision_count(&db, "event-without-collision").unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT value FROM ordinary_publish_effect", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "committed"
        );
        let deliveries = [
            claim_ready(&db).unwrap().unwrap(),
            claim_ready(&db).unwrap().unwrap(),
        ];
        assert_eq!(
            deliveries
                .iter()
                .map(|d| d.group_id.as_str())
                .collect::<HashSet<_>>(),
            HashSet::from([group_a.as_str(), group_b.as_str()])
        );
        assert_eq!(
            deliveries
                .iter()
                .map(|d| d.target_thread.as_str())
                .collect::<HashSet<_>>(),
            HashSet::from([target_a, target_b])
        );

        let collision = published_as(
            selector("job", "other/repo", "run-44", "success", Some("success")),
            "ci/occurrence-44",
        );
        assert!(
            record_published_event(&db, &collision)
                .unwrap()
                .payload_collision
        );
    }

    #[test]
    fn event_counters_count_new_members_and_distinct_groups_separately() {
        let (_dir, db) = db();
        let wildcard = selector("job", "org/repo", "run-count", "completed", None);
        let exact = selector("job", "org/repo", "run-count", "completed", Some("success"));
        let group = register(&db, Mode::And, &[wildcard, exact.clone()], None);
        let event = published_as(exact, "job/count/1");
        let record = record_published_event(&db, &event).unwrap();
        assert_eq!(record.new_members, 2);
        assert_eq!(record.new_groups, 1);
        assert_eq!(record.ready_groups, 1);
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
        let replay = record_published_event(&db, &event).unwrap();
        assert_eq!(replay.new_members, 0);
        assert_eq!(replay.new_groups, 0);
        assert_eq!(replay.ready_groups, 0);
    }

    #[test]
    fn native_member_is_ineligible_until_baseline_is_captured_and_armed() {
        let (_dir, db) = db();
        let native = selector(
            "thread",
            "",
            TARGET,
            "turn_completed",
            Some("turn_completed"),
        );
        let group = register(&db, Mode::Or, std::slice::from_ref(&native), None);
        let old = native_published(native.clone(), "thread/turn-1", "turn-1");
        assert_eq!(record_published_event(&db, &old).unwrap().ready_groups, 0);
        assert!(claim_ready(&db).unwrap().is_none());

        // The poller invokes this only after its baseline read is complete and persisted.
        assert!(arm_native_member(&db, &group, &native, Some("turn-1")).unwrap());
        assert_eq!(record_published_event(&db, &old).unwrap().ready_groups, 0); // receipt replay is not replayed
        assert!(!arm_native_member(&db, &group, &native, Some("turn-1")).unwrap());
        assert!(arm_native_member(&db, &group, &native, Some("turn-2")).is_err());

        let next = native_published(native, "thread/turn-2", "turn-2");
        assert_eq!(record_published_event(&db, &next).unwrap().ready_groups, 0);
        assert_eq!(
            record_native_poll_event(&db, &group, &next)
                .unwrap()
                .ready_groups,
            1
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
    }

    #[test]
    fn native_baseline_filters_peer_publications_per_member() {
        let (_dir, db) = db();
        let native = selector(
            "thread",
            "",
            TARGET,
            "turn_completed",
            Some("turn_completed"),
        );
        let active_group = register(&db, Mode::Or, std::slice::from_ref(&native), None);
        let completed_group = register(&db, Mode::Or, std::slice::from_ref(&native), None);
        assert!(arm_native_member(&db, &active_group, &native, None).unwrap());
        assert!(arm_native_member(&db, &completed_group, &native, Some("turn-1")).unwrap());

        let historical = native_published(native.clone(), "thread/turn-1", "turn-1");
        assert_eq!(
            record_published_event(&db, &historical)
                .unwrap()
                .ready_groups,
            0
        );
        assert_eq!(
            record_native_poll_event(&db, &active_group, &historical)
                .unwrap()
                .ready_groups,
            1
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, active_group);

        let next = native_published(native, "thread/turn-2", "turn-2");
        assert_eq!(record_published_event(&db, &next).unwrap().ready_groups, 0);
        assert_eq!(
            record_native_poll_event(&db, &completed_group, &next)
                .unwrap()
                .ready_groups,
            1
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, completed_group);
    }

    #[test]
    fn native_poll_digest_still_rejects_changed_payload_from_same_provenance() {
        let (_dir, db) = db();
        let native = selector(
            "thread",
            "",
            TARGET,
            "turn_completed",
            Some("turn_completed"),
        );
        let first_group = register(&db, Mode::Or, std::slice::from_ref(&native), None);
        let second_group = register(&db, Mode::Or, std::slice::from_ref(&native), None);
        assert!(arm_native_member(&db, &first_group, &native, Some("baseline")).unwrap());
        assert!(arm_native_member(&db, &second_group, &native, Some("baseline")).unwrap());

        let event = native_published(native, "native/same-turn", "same-turn");
        let first = record_native_poll_event(&db, &first_group, &event).unwrap();
        assert_eq!(first.ready_groups, 1);
        let mut changed = event.clone();
        changed.source["sample"] = serde_json::json!("changed poller payload");
        let collision = record_native_poll_event(&db, &second_group, &changed).unwrap();
        assert!(collision.payload_collision);
        assert_eq!((collision.ready_groups, collision.new_members), (0, 0));
        assert_eq!(
            publication_collision_count(&db, "native/same-turn").unwrap(),
            1
        );
        assert_eq!(
            matched_group_count_for_event(&db, "native/same-turn").unwrap(),
            1
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, first_group);
        assert!(claim_ready(&db).unwrap().is_none());
        assert_eq!(
            delivery_status(&db, &second_group).unwrap().state,
            "pending"
        );
    }

    #[test]
    fn native_hook_buffer_waits_for_member_poll_order_then_matches_once() {
        let (_dir, db) = db();
        let native = selector(
            "thread",
            "",
            TARGET,
            "turn_completed",
            Some("turn_completed"),
        );
        let group = register(&db, Mode::Or, std::slice::from_ref(&native), None);
        // Poller captured turn-10 as baseline; hook observes turn-11 before arm commits.
        let hook = native_published(native.clone(), "native/turn-11", "turn-11");
        let buffered = record_published_event(&db, &hook).unwrap();
        assert_eq!(buffered.ready_groups, 0);
        assert_eq!((buffered.new_members, buffered.new_groups), (1, 1));
        assert!(claim_ready(&db).unwrap().is_none());
        db.execute(
            "UPDATE condition_pending_events SET recorded='2000-01-01 00:00:00' WHERE source_event_key='native/turn-11'",
            [],
        ).unwrap();
        initialize(&db).unwrap();
        assert_eq!(db.query_row(
            "SELECT count(*) FROM condition_pending_events WHERE source_event_key='native/turn-11'",
            [], |row| row.get::<_, i64>(0),
        ).unwrap(), 1);

        assert!(arm_native_member(&db, &group, &native, Some("turn-10")).unwrap());
        assert_eq!(
            matched_group_count_for_event(&db, "native/turn-11").unwrap(),
            0
        );
        assert!(claim_ready(&db).unwrap().is_none());
        record_native_poll_event(&db, &group, &hook).unwrap();
        assert_eq!(
            matched_group_count_for_event(&db, "native/turn-11").unwrap(),
            1
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
        // Polling rereads the same canonical turn identity with a different representation.
        let mut polling = hook.clone();
        polling.source = serde_json::json!({"turn_id":"turn-11", "representation":"poll"});
        let replay = record_published_event(&db, &polling).unwrap();
        assert!(replay.payload_collision);
        assert_eq!(
            publication_collision_count(&db, "native/turn-11").unwrap(),
            1
        );
        assert!(claim_ready(&db).unwrap().is_none());
    }

    #[test]
    fn unarmed_polling_insert_binds_and_persists_digest_and_source_payload() {
        let (_dir, db) = db();
        let selector = selector("review", "org/repo", "pr-buffer-bindings", "approved", None);
        let member = MemberRegistration::polling(selector.clone(), None);
        let group =
            register_group_with_members(&db, Mode::Or, &[member], TARGET, None, None).unwrap();
        let event = native_published(selector, "review/pr-buffer-bindings/1", "cursor-021");
        let source_json = serde_json::to_string(&event.source).unwrap();
        let expected_digest = format!("{:x}", Sha256::digest(source_json.as_bytes()));

        let record = record_published_event(&db, &event).unwrap();
        assert_eq!((record.new_members, record.new_groups), (1, 1));
        assert_eq!(record.ready_groups, 0);
        let (stored_digest, stored_source): (String, String) = db
            .query_row(
                "SELECT source_digest,source_json FROM condition_pending_events
                 WHERE group_id=?1 AND source_event_key=?2",
                params![group, event.source_event_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored_digest, expected_digest);
        assert_eq!(stored_source, source_json);
    }

    #[test]
    fn prearm_buffer_is_bounded_and_overflow_is_visible_without_losing_first_event() {
        let (_dir, db) = db();
        let selector = selector("review", "org/repo", "pr-buffer", "approved", None);
        let member = MemberRegistration::polling(selector.clone(), None);
        let group = register_group_with_members(
            &db,
            Mode::Or,
            std::slice::from_ref(&member),
            TARGET,
            None,
            None,
        )
        .unwrap();
        let first = native_published(selector.clone(), "review/pr-buffer/1", "cursor-011");
        let first_result = record_published_event(&db, &first).unwrap();
        assert_eq!((first_result.new_members, first_result.new_groups), (1, 1));
        assert!(!first_result.buffer_overflow);

        let second = native_published(selector, "review/pr-buffer/2", "cursor-012");
        let overflow = record_published_event(&db, &second).unwrap();
        assert_eq!((overflow.new_members, overflow.new_groups), (0, 0));
        assert!(overflow.buffer_overflow);
        let status = pending_polling_members(&db, Some(&group))
            .unwrap()
            .remove(0);
        assert!(status.buffer_overflow);
        assert_eq!(status.buffer_overflow_count, 1);
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM condition_pending_events WHERE group_id=?1",
                [&group],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(db.query_row(
            "SELECT count(*) FROM condition_publications WHERE source_event_key='review/pr-buffer/2'",
            [], |row| row.get::<_, i64>(0),
        ).unwrap(), 1);

        // The single retained event predates the baseline, so arming must fail visibly.
        assert!(arm_observed_member(&db, &group, &member, Some("cursor-011")).is_err());
        let still_pending = pending_polling_members(&db, Some(&group))
            .unwrap()
            .remove(0);
        assert!(!still_pending.armed);
        assert!(still_pending.buffer_overflow);
        assert_eq!(
            matched_group_count_for_event(&db, "review/pr-buffer/1").unwrap(),
            0
        );
    }

    #[test]
    fn overflow_is_harmless_when_retained_first_occurrence_satisfies_one_shot() {
        let (_dir, db) = db();
        let selector = selector("deployment", "org/repo", "deploy-buffer", "success", None);
        let member = MemberRegistration::polling(selector.clone(), None);
        let group = register_group_with_members(
            &db,
            Mode::Or,
            std::slice::from_ref(&member),
            TARGET,
            None,
            None,
        )
        .unwrap();
        let first = native_published(selector.clone(), "deployment/event-1", "cursor-011");
        record_published_event(&db, &first).unwrap();
        let second = native_published(selector, "deployment/event-2", "cursor-012");
        assert!(
            record_published_event(&db, &second)
                .unwrap()
                .buffer_overflow
        );

        assert!(arm_observed_member(&db, &group, &member, Some("cursor-010")).unwrap());
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
        assert_eq!(
            matched_group_count_for_event(&db, "deployment/event-1").unwrap(),
            1
        );
        assert!(
            pending_polling_members(&db, Some(&group))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn polling_members_require_baseline_for_each_github_source_kind() {
        let (_dir, db) = db();
        let cases = [
            ("pull_request", "org/repo", "17", "merged"),
            ("review", "org/repo", "17", "approved"),
            ("deployment", "org/repo", "deploy-8", "success"),
            ("git_ref", "org/repo", "refs/heads/main", "updated"),
        ];
        let mut groups = Vec::new();
        for (index, (kind, repo, resource, event_name)) in cases.into_iter().enumerate() {
            let selector = selector(kind, repo, resource, event_name, None);
            let member = MemberRegistration::polling(selector.clone(), None);
            let group = register_group_with_members(
                &db,
                Mode::Or,
                std::slice::from_ref(&member),
                TARGET,
                None,
                None,
            )
            .unwrap();
            // The observed event is recorded before baseline capture and cannot be replayed.
            let old = native_published(selector.clone(), &format!("poll/{kind}/old"), "cursor-0");
            assert_eq!(record_published_event(&db, &old).unwrap().ready_groups, 0);
            assert!(arm_observed_member(&db, &group, &member, Some("cursor-0")).unwrap());
            assert_eq!(record_published_event(&db, &old).unwrap().ready_groups, 0);
            let current = native_published(selector, &format!("poll/{kind}/new"), "cursor-1");
            assert_eq!(
                record_published_event(&db, &current).unwrap().ready_groups,
                1
            );
            groups.push((index, group));
        }
        let claimed = (0..4)
            .map(|_| claim_ready(&db).unwrap().unwrap().group_id)
            .collect::<HashSet<_>>();
        assert_eq!(
            claimed,
            groups.into_iter().map(|(_, group)| group).collect()
        );
    }

    #[test]
    fn ci_identity_is_typed_exact_and_only_digest_is_kept_in_global_receipts() {
        let (_dir, db) = db();
        let sha = "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0";
        let selector = selector("job", "org/repo", "build", "completed", Some("success"));
        let ci = CiRunIdentity {
            repo: "org/repo".into(),
            run_id: 42,
            attempt: 3,
            sha: sha.into(),
        };
        let member = MemberRegistration::explicit_with_ci(selector.clone(), ci.clone());
        let group =
            register_group_with_members(&db, Mode::And, &[member], TARGET, None, None).unwrap();

        let mut wrong = published_as(selector.clone(), "actions/42/2");
        wrong.ci = Some(CiRunIdentity {
            attempt: 2,
            ..ci.clone()
        });
        assert_eq!(record_published_event(&db, &wrong).unwrap().ready_groups, 0);
        let mut right = published_as(selector, "actions/42/3");
        right.ci = Some(ci.clone());
        assert_eq!(record_published_event(&db, &right).unwrap().ready_groups, 1);
        let delivery = claim_ready(&db).unwrap().unwrap();
        assert_eq!(delivery.group_id, group);
        assert_eq!(delivery.sources[0].ci, Some(ci));

        let columns = {
            let mut stmt = db
                .prepare("PRAGMA table_info(condition_publications)")
                .unwrap();
            stmt.query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert!(columns.iter().any(|column| column == "source_digest"));
        assert!(columns.iter().any(|column| column == "native_poll_digest"));
        assert!(!columns.iter().any(|column| column == "source_json"));
    }

    #[test]
    fn pending_polling_api_lists_job_only_with_exact_ci_and_never_payload() {
        let (_dir, db) = db();
        let selector = selector("job", "org/repo", "build", "completed", Some("success"));
        let without_ci = MemberRegistration::polling(selector.clone(), None);
        assert!(
            register_group_with_members(&db, Mode::Or, &[without_ci], TARGET, None, None).is_err()
        );

        let ci = CiRunIdentity {
            repo: "org/repo".into(),
            run_id: 42,
            attempt: 3,
            sha: "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0".into(),
        };
        let member = MemberRegistration::polling(selector.clone(), Some(ci.clone()));
        let group = register_group_with_members(
            &db,
            Mode::Or,
            std::slice::from_ref(&member),
            TARGET,
            None,
            None,
        )
        .unwrap();
        let pending = pending_polling_members(&db, Some(&group)).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].group_id, group);
        assert_eq!(pending[0].selector, selector);
        assert_eq!(pending[0].ci, Some(ci.clone()));
        assert_eq!(pending[0].group_state, "pending");
        assert!(!pending[0].armed);
        assert_eq!(pending[0].baseline_cursor, None);

        assert!(arm_observed_member(&db, &group, &member, Some("run-cursor-001")).unwrap());
        let pending = pending_polling_members(&db, None).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].armed);
        assert_eq!(
            pending[0].baseline_cursor.as_deref(),
            Some("run-cursor-001")
        );
        assert_eq!(pending[0].last_cursor.as_deref(), Some("run-cursor-001"));

        let mut event = published_as(selector, "actions/42/3/completed");
        event.ci = Some(ci);
        event.cursor = Some("run-cursor-002".into());
        assert_eq!(record_published_event(&db, &event).unwrap().ready_groups, 1);
        assert!(
            pending_polling_members(&db, Some(&group))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn known_pre_send_failure_is_visible_and_retryable_but_uncertain_is_not() {
        let (_dir, db) = db();
        let before_send = ready_group(&db);
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, before_send);
        assert!(
            record_delivery_pre_send_failed(&db, &before_send, "target_unavailable_before_send")
                .unwrap()
        );
        let status = delivery_status(&db, &before_send).unwrap();
        assert_eq!(status.state, "send_failed");
        assert_eq!(
            status.reason.as_deref(),
            Some("target_unavailable_before_send")
        );
        assert!(status.retry_at.is_some());
        assert!(!retry_pre_send_failed(&db, &before_send).unwrap());
        db.execute(
            "UPDATE condition_groups SET retry_at='2000-01-01 00:00:00' WHERE id=?1",
            [&before_send],
        )
        .unwrap();
        assert!(retry_pre_send_failed(&db, &before_send).unwrap());
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, before_send);
        assert!(record_delivery_uncertain(&db, &before_send).unwrap());
        assert!(!retry_pre_send_failed(&db, &before_send).unwrap());
        assert_eq!(
            delivery_status(&db, &before_send).unwrap().state,
            "uncertain"
        );

        let template = ready_group(&db);
        claim_ready(&db).unwrap().unwrap();
        assert!(record_delivery_pre_send_failed(&db, &template, "template_error").unwrap());
        let status = delivery_status(&db, &template).unwrap();
        assert_eq!(status.reason.as_deref(), Some("template_error"));
        assert_eq!(status.retry_at, None);
        assert!(!retry_pre_send_failed(&db, &template).unwrap());
    }

    #[test]
    fn transaction_aware_recording_uses_callers_immediate_transaction() {
        let (_dir, db) = db();
        let event = published(selector(
            "review",
            "org/repo",
            "pr-transaction",
            "approved",
            Some("approved"),
        ));
        let group = register(&db, Mode::Or, std::slice::from_ref(&event.selector), None);
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert_eq!(
            record_published_event_in(&db, &event).unwrap().ready_groups,
            1
        );
        db.execute_batch("COMMIT").unwrap();
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
    }

    #[test]
    fn correlated_completion_can_win_before_acceptance_and_late_ack_is_noop() {
        let (_dir, db) = db();
        let group = ready_group(&db);
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
        let event = completion(&group, "completed", CompletionOutcome::Succeeded);
        assert!(complete_delivery(&db, &group, &event, CompletionOutcome::Succeeded).unwrap());
        assert!(!record_delivery_accepted(&db, &group).unwrap());
        assert!(!record_delivery_uncertain(&db, &group).unwrap());
        assert_eq!(delivery_status(&db, &group).unwrap().state, "succeeded");
    }

    #[test]
    fn uncorrelated_stop_never_completes_a_claimed_delivery() {
        let (_dir, db) = db();
        let group = ready_group(&db);
        claim_ready(&db).unwrap().unwrap();
        let stop = published(selector("chat", "", TARGET, "completed", Some("completed")));
        assert!(complete_delivery(&db, &group, &stop, CompletionOutcome::Succeeded).is_err());
        assert_eq!(delivery_status(&db, &group).unwrap().state, "claimed");
    }

    #[test]
    fn dependencies_apply_success_only_or_any_terminal_per_edge() {
        let (_dir, db) = db();
        let successful_parent = ready_group(&db);
        let failed_parent = ready_group(&db);
        let child_selector = selector(
            "artifact",
            "org/repo",
            "pkg",
            "available",
            Some("available"),
        );
        let success_child = register(
            &db,
            Mode::And,
            std::slice::from_ref(&child_selector),
            Some(&dependency(&successful_parent, ModeDependency::SuccessOnly)),
        );
        let any_child = register(
            &db,
            Mode::And,
            std::slice::from_ref(&child_selector),
            Some(&dependency(&failed_parent, ModeDependency::AnyTerminal)),
        );
        record_published_event(&db, &published(child_selector)).unwrap();

        let claimed_success = claim_ready(&db).unwrap().unwrap();
        let claimed_failure = claim_ready(&db).unwrap().unwrap();
        assert_ne!(claimed_success.group_id, claimed_failure.group_id);
        assert!(claim_ready(&db).unwrap().is_none()); // claimed/queued is not completion
        assert!(record_delivery_accepted(&db, &successful_parent).unwrap());
        assert!(record_delivery_accepted(&db, &failed_parent).unwrap());
        assert!(claim_ready(&db).unwrap().is_none()); // accepted is not work completion
        complete_delivery(
            &db,
            &successful_parent,
            &completion(
                &successful_parent,
                "completed",
                CompletionOutcome::Succeeded,
            ),
            CompletionOutcome::Succeeded,
        )
        .unwrap();
        complete_delivery(
            &db,
            &failed_parent,
            &completion(&failed_parent, "failed", CompletionOutcome::Failed),
            CompletionOutcome::Failed,
        )
        .unwrap();
        let first = claim_ready(&db).unwrap().unwrap().group_id;
        let second = claim_ready(&db).unwrap().unwrap().group_id;
        assert_eq!(
            HashSet::from([first, second]),
            HashSet::from([success_child, any_child])
        );
    }

    #[test]
    fn failed_predecessor_does_not_advance_success_only_but_advances_any_terminal() {
        let (_dir, db) = db();
        let parent = ready_group(&db);
        let member = selector("chat", "", TARGET, "failed", Some("failed"));
        let success_child = register(
            &db,
            Mode::And,
            std::slice::from_ref(&member),
            Some(&dependency(&parent, ModeDependency::SuccessOnly)),
        );
        let any_child = register(
            &db,
            Mode::And,
            std::slice::from_ref(&member),
            Some(&dependency(&parent, ModeDependency::AnyTerminal)),
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, parent);
        assert!(record_delivery_accepted(&db, &parent).unwrap());
        complete_delivery(
            &db,
            &parent,
            &completion(&parent, "failed", CompletionOutcome::Failed),
            CompletionOutcome::Failed,
        )
        .unwrap();
        let child = claim_ready(&db).unwrap().unwrap();
        assert_eq!(child.group_id, any_child);
        assert_eq!(child.sources[0].source["group_id"], parent);
        assert!(claim_ready(&db).unwrap().is_none());
        assert_ne!(success_child, any_child);
    }

    #[test]
    fn three_step_chain_advances_only_after_each_preceding_work_completes() {
        let (_dir, db) = db();
        let a = ready_group(&db);
        let b_event = selector("review", "org/repo", "pr-81", "approved", Some("approved"));
        let c_event = selector(
            "artifact",
            "org/repo",
            "pkg-81",
            "available",
            Some("available"),
        );
        let b = register(
            &db,
            Mode::And,
            std::slice::from_ref(&b_event),
            Some(&dependency(&a, ModeDependency::SuccessOnly)),
        );
        let c = register(
            &db,
            Mode::And,
            std::slice::from_ref(&c_event),
            Some(&dependency(&b, ModeDependency::AnyTerminal)),
        );
        record_published_event(&db, &published(b_event)).unwrap();
        record_published_event(&db, &published(c_event)).unwrap();

        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, a);
        assert!(record_delivery_accepted(&db, &a).unwrap());
        assert!(claim_ready(&db).unwrap().is_none());
        assert!(
            complete_delivery(
                &db,
                &a,
                &completion(&a, "completed", CompletionOutcome::Succeeded),
                CompletionOutcome::Succeeded,
            )
            .unwrap()
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, b);

        assert!(record_delivery_accepted(&db, &b).unwrap());
        assert!(claim_ready(&db).unwrap().is_none());
        assert!(
            complete_delivery(
                &db,
                &b,
                &completion(&b, "failed", CompletionOutcome::Failed),
                CompletionOutcome::Failed,
            )
            .unwrap()
        );
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, c);
    }

    #[test]
    fn duplicate_completions_and_restart_never_reclaim_a_claim() {
        let (dir, db) = db();
        let group = ready_group(&db);
        assert_eq!(claim_ready(&db).unwrap().unwrap().group_id, group);
        assert_eq!(reconcile_interrupted_claims(&db).unwrap(), 0);
        assert!(record_delivery_uncertain(&db, &group).unwrap());
        drop(db);

        let reopened = Connection::open(dir.path().join("conditions.sqlite")).unwrap();
        reopened.busy_timeout(Duration::from_secs(5)).unwrap();
        initialize(&reopened).unwrap();
        assert!(claim_ready(&reopened).unwrap().is_none());
        let mut unrelated = published(selector(
            "artifact",
            "org/repo",
            TARGET,
            "available",
            Some("available"),
        ));
        unrelated.source = serde_json::json!({"group_id":"some-other-group", "turn_id":"turn-old"});
        assert!(
            complete_delivery(&reopened, &group, &unrelated, CompletionOutcome::Succeeded).is_err()
        );
        let completion = completion(&group, "completed", CompletionOutcome::Succeeded);
        assert!(
            complete_delivery(&reopened, &group, &completion, CompletionOutcome::Succeeded)
                .unwrap()
        );
        assert!(
            !complete_delivery(&reopened, &group, &completion, CompletionOutcome::Succeeded)
                .unwrap()
        );
        assert!(
            complete_delivery(&reopened, &group, &completion, CompletionOutcome::Failed).is_err()
        );
    }

    #[test]
    fn recovery_marks_only_a_sender_proven_dead_in_same_boot_and_namespace() {
        let (_dir, db) = db();
        let group = ready_group(&db);
        claim_ready(&db).unwrap().unwrap();
        let live = current_sender_identity().unwrap();
        // PID_MAX on Linux is below this value; kill(pid, 0) can prove ESRCH.
        db.execute(
            "UPDATE condition_groups SET sender_pid=?2,sender_start=1,
                 sender_boot=?3,sender_namespace=?4 WHERE id=?1",
            params![group, i64::from(i32::MAX), live.boot, live.namespace],
        )
        .unwrap();
        assert_eq!(reconcile_interrupted_claims(&db).unwrap(), 1);
        let status = delivery_status(&db, &group).unwrap();
        assert_eq!(status.state, "uncertain");
        assert_eq!(status.reason.as_deref(), Some("sender_exit_confirmed"));
        assert!(!retry_pre_send_failed(&db, &group).unwrap());
    }

    #[test]
    fn recovery_keeps_namespace_mismatch_claimed_but_expires_previous_boot_without_replay() {
        let (_dir, db) = db();
        let group = ready_group(&db);
        claim_ready(&db).unwrap().unwrap();
        let mut owner = current_sender_identity().unwrap();
        owner.namespace.push_str("-other");
        db.execute(
            "UPDATE condition_groups SET sender_start=?2,sender_boot=?3,
                 sender_namespace=?4 WHERE id=?1",
            params![group, owner.start, owner.boot, owner.namespace],
        )
        .unwrap();

        assert_eq!(reconcile_interrupted_claims(&db).unwrap(), 0);
        assert_eq!(delivery_status(&db, &group).unwrap().state, "claimed");

        db.execute(
            "UPDATE condition_groups SET sender_boot='previous-boot' WHERE id=?1",
            [&group],
        )
        .unwrap();
        assert_eq!(reconcile_interrupted_claims(&db).unwrap(), 1);
        let status = delivery_status(&db, &group).unwrap();
        assert_eq!(status.state, "uncertain");
        assert_eq!(status.reason.as_deref(), Some("sender_exit_confirmed"));
        assert!(claim_ready(&db).unwrap().is_none());
        assert!(!retry_pre_send_failed(&db, &group).unwrap());
    }

    #[test]
    fn concurrent_claimers_claim_once() {
        let (dir, db) = db();
        let group = ready_group(&db);
        drop(db);
        let barrier = std::sync::Arc::new(Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = dir.path().join("conditions.sqlite");
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let db = Connection::open(path).unwrap();
                    db.busy_timeout(Duration::from_secs(5)).unwrap();
                    barrier.wait();
                    claim_ready(&db).unwrap()
                })
            })
            .collect();
        barrier.wait();
        let claims: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
        assert_eq!(claims.into_iter().flatten().next().unwrap().group_id, group);
    }
}
