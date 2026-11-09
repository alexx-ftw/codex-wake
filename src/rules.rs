use anyhow::{Context, Result, ensure};
use rmcp::schemars::{self, JsonSchema};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    #[default]
    All,
    Any,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub enum AuthorType {
    User,
    Bot,
}
impl AuthorType {
    fn as_str(&self) -> &str {
        match self {
            Self::User => "User",
            Self::Bot => "Bot",
        }
    }
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleInput {
    pub repo: String,
    pub pr: i64,
    /// Match this GitHub login (case insensitive).
    pub author: Option<String>,
    /// Exact GitHub account type: User or Bot.
    pub author_type: Option<AuthorType>,
    /// Literal, case-sensitive substring. Comment text is used only for matching.
    pub contains: Option<String>,
    /// Combine configured author, type and phrase predicates with all (default) or any.
    #[serde(default)]
    pub match_mode: MatchMode,
    /// Trusted task template; use source.*, event.* or target.thread placeholders.
    pub prompt: String,
    pub target_thread: Option<String>,
    pub project_id: Option<String>,
    pub cwd: Option<String>,
    /// Optional goal objective template for a newly created thread.
    pub goal_objective: Option<String>,
    /// Set only when explicitly requested; requires goal_objective.
    pub token_budget: Option<i64>,
    /// Execution model; new chats default to gpt-6.1-terra.
    pub model: Option<String>,
    /// Execution reasoning effort; new chats default to medium.
    pub reasoning_effort: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SimulateRuleInput {
    pub rule: RuleInput,
    /// GitHub event header: issue_comment or pull_request_review_comment.
    pub event_header: String,
    /// Example GitHub webhook payload; it is never dispatched.
    pub payload: Value,
}

fn bounded(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.contains('\0')
}
fn path(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            && !value.contains('\0'),
        "cwd must be an absolute normalized path"
    );
    Ok(path)
}
fn validate(input: &mut RuleInput) -> Result<()> {
    let parts: Vec<_> = input.repo.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && part.len() <= 100
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))),
        "Invalid owner/repository"
    );
    ensure!(input.pr > 0, "PR number must be positive");
    ensure!(bounded(&input.prompt, 16384), "Invalid trusted prompt");
    crate::templates::validate(&input.prompt)?;
    if input.target_thread.is_none() || input.model.is_some() || input.reasoning_effort.is_some() {
        let model = input.model.get_or_insert_with(|| "gpt-6.1-terra".into());
        ensure!(
            bounded(model, 255) && model.bytes().all(|b| b.is_ascii_graphic()),
            "Invalid model"
        );
        let effort = input
            .reasoning_effort
            .get_or_insert_with(|| "medium".into());
        ensure!(
            bounded(effort, 100) && effort.bytes().all(|b| b.is_ascii_graphic()),
            "Invalid reasoning effort"
        );
    }
    if let Some(author) = &input.author {
        ensure!(
            bounded(author, 100)
                && author
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-[]".contains(&b)),
            "Invalid GitHub author"
        );
    }
    if let Some(contains) = &input.contains {
        ensure!(bounded(contains, 1024), "Invalid contains predicate");
    }
    if let Some(cwd) = &input.cwd {
        path(cwd)?;
    }
    if let Some(project) = &input.project_id {
        ensure!(
            bounded(project, 255) && !project.chars().any(char::is_control),
            "Invalid project ID"
        );
    }
    if let Some(objective) = &input.goal_objective {
        ensure!(bounded(objective, 16384), "Invalid goal objective");
        crate::templates::validate(objective)?;
    }
    if let Some(budget) = input.token_budget {
        ensure!(
            budget > 0 && input.goal_objective.is_some(),
            "token_budget requires an explicit goal objective and must be positive"
        );
    }
    if let Some(thread) = &input.target_thread {
        input.target_thread = Some(
            Uuid::parse_str(thread)
                .context("Invalid target thread UUID")?
                .to_string(),
        );
        ensure!(
            input.project_id.is_none() && input.cwd.is_none(),
            "Existing-thread rules cannot set project_id or cwd"
        );
        ensure!(
            input.goal_objective.is_none(),
            "Goals are supported only for new-thread rules"
        );
    }
    Ok(())
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY, input TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS rule_deliveries (
        rule_id TEXT NOT NULL, event_header TEXT NOT NULL, comment_id TEXT NOT NULL, source TEXT NOT NULL,
        source_event_key TEXT, event_identity_verified INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT 'ready' CHECK(state IN ('ready','creating','queued','needs_attention')),
        thread_id TEXT, reason TEXT, updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(rule_id,event_header,comment_id));")?;
    let mut columns = db.prepare("PRAGMA table_info(rule_deliveries)")?;
    let names = columns
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(columns);
    if !names.iter().any(|name| name == "source_event_key") {
        db.execute_batch("ALTER TABLE rule_deliveries ADD COLUMN source_event_key TEXT")?;
    }
    if !names.iter().any(|name| name == "event_identity_verified") {
        db.execute_batch("ALTER TABLE rule_deliveries ADD COLUMN event_identity_verified INTEGER NOT NULL DEFAULT 0")?;
    }
    Ok(())
}

pub fn configure(db: &Connection, input: RuleInput) -> Result<String> {
    configure_inner(db, input, true)
}

fn configure_inner(db: &Connection, mut input: RuleInput, log: bool) -> Result<String> {
    validate(&mut input)?;
    initialize(db)?;
    let id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO rules(id,input) VALUES(?1,?2)",
        params![id, serde_json::to_string(&input)?],
    )?;
    if log {
        crate::observability::emit(
            "rule.configure",
            "created",
            "",
            Some(&id),
            Duration::ZERO,
            1,
        );
    }
    Ok(id)
}

fn matches(input: &RuleInput, author: &str, author_type: &str, body: &str) -> bool {
    let checks = [
        input
            .author
            .as_ref()
            .map(|v| v.eq_ignore_ascii_case(author)),
        input
            .author_type
            .as_ref()
            .map(|v| v.as_str() == author_type),
        input.contains.as_ref().map(|v| body.contains(v)),
    ];
    let checks: Vec<_> = checks.into_iter().flatten().collect();
    checks.is_empty()
        || match input.match_mode {
            MatchMode::All => checks.iter().all(|v| *v),
            MatchMode::Any => checks.iter().any(|v| *v),
        }
}

fn render_context(
    input: &RuleInput,
    source: &Value,
    header: &str,
    comment_id: u64,
    thread: &str,
) -> Result<Value> {
    Ok(
        json!({"source":source,"event":{"repo":input.repo,"pr":input.pr,"comment_id":comment_id,"author":source.pointer("/comment/user/login").and_then(Value::as_str).context("Missing source author")?,"event_header":header},"target":{"thread":thread}}),
    )
}

/// Exercise the real matcher against an isolated in-memory database without dispatching.
pub fn simulate(mut example: SimulateRuleInput) -> Result<Value> {
    validate(&mut example.rule)?;
    let db = Connection::open_in_memory()?;
    configure_inner(&db, example.rule.clone(), false)?;
    if accept_inner(&db, &example.event_header, &example.payload, false)? == 0 {
        return Ok(json!({"matched":false,"dispatched":false}));
    }
    let comment_id = example
        .payload
        .pointer("/comment/id")
        .and_then(Value::as_u64)
        .context("Invalid comment ID")?;
    let thread = example
        .rule
        .target_thread
        .as_deref()
        .unwrap_or("<new-thread-id>");
    let context = render_context(
        &example.rule,
        &example.payload,
        &example.event_header,
        comment_id,
        thread,
    )?;
    let prompt = crate::templates::render(&example.rule.prompt, &context)?;
    let objective = example
        .rule
        .goal_objective
        .as_ref()
        .map(|value| crate::templates::render(value, &context))
        .transpose()?;
    if let Some(template) = &example.rule.goal_objective {
        let validation_thread = example
            .rule
            .target_thread
            .as_deref()
            .unwrap_or("00000000-0000-0000-0000-000000000000");
        let validation_context = render_context(
            &example.rule,
            &example.payload,
            &example.event_header,
            comment_id,
            validation_thread,
        )?;
        let validation_objective = crate::templates::render(template, &validation_context)?;
        ensure!(
            !validation_objective.trim().is_empty() && validation_objective.chars().count() <= 4000,
            "Invalid rendered goal objective"
        );
    }
    Ok(
        json!({"matched":true,"dispatched":false,"action":if example.rule.target_thread.is_some() {"message_thread"} else {"create_thread"},"target_thread":example.rule.target_thread,"new_thread_placeholder":"<new-thread-id>","project_id":example.rule.project_id,"cwd":example.rule.cwd,"prompt":prompt,"goal_objective":objective,"token_budget":example.rule.token_budget,"model":example.rule.model,"reasoning_effort":example.rule.reasoning_effort,"project_and_execution_verified":false}),
    )
}

/// Signature verification belongs to the upstream receiver. Source payload stays in the private database.
pub fn accept(db: &Connection, event_header: &str, payload: &Value) -> Result<usize> {
    accept_inner(db, event_header, payload, true)
}

fn accept_inner(db: &Connection, event_header: &str, payload: &Value, log: bool) -> Result<usize> {
    ensure!(
        serde_json::to_vec(payload)?.len() <= 1024 * 1024,
        "Payload exceeds 1 MiB"
    );
    if !matches!(
        event_header,
        "issue_comment" | "pull_request_review_comment"
    ) || !matches!(payload["action"].as_str(), Some("created" | "edited"))
    {
        if log {
            crate::observability::emit("event.accept", "ignored", "", None, Duration::ZERO, 0);
        }
        return Ok(0);
    }
    if event_header == "issue_comment"
        && !payload
            .pointer("/issue/pull_request")
            .is_some_and(Value::is_object)
    {
        if log {
            crate::observability::emit("event.accept", "ignored", "", None, Duration::ZERO, 0);
        }
        return Ok(0);
    }
    let pr = payload
        .pointer(if event_header == "issue_comment" {
            "/issue/number"
        } else {
            "/pull_request/number"
        })
        .and_then(Value::as_i64)
        .filter(|n| *n > 0)
        .context("Invalid PR number")?;
    let repo = payload
        .pointer("/repository/full_name")
        .and_then(Value::as_str)
        .context("Missing repository")?;
    let comment = &payload["comment"];
    let id = comment["id"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("Invalid comment ID")?
        .to_string();
    let author = comment
        .pointer("/user/login")
        .and_then(Value::as_str)
        .context("Missing comment author")?;
    let author_type = comment
        .pointer("/user/type")
        .and_then(Value::as_str)
        .context("Missing author type")?;
    let body = comment["body"].as_str().context("Missing comment body")?;
    let source_event_key =
        crate::delivery_evidence::github_comment_event_identity(event_header, payload)?;
    let event_identity_verified = source_event_key.is_some();
    initialize(db)?;
    let mut statement = db.prepare("SELECT id,input FROM rules WHERE enabled=1")?;
    let rules = statement
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let transaction = db.unchecked_transaction()?;
    let mut count = 0;
    for (rule_id, raw) in rules {
        let input: RuleInput = serde_json::from_str(&raw)?;
        if input.repo == repo && input.pr == pr && matches(&input, author, author_type, body) {
            count += transaction.execute("INSERT OR IGNORE INTO rule_deliveries(rule_id,event_header,comment_id,source,source_event_key,event_identity_verified) VALUES(?1,?2,?3,?4,?5,?6)", params![rule_id,event_header,id,serde_json::to_string(payload)?,source_event_key,event_identity_verified])?;
        }
    }
    transaction.commit()?;
    let subject = format!("{event_header}/{id}");
    if log {
        crate::observability::emit(
            "event.accept",
            if count > 0 { "matched" } else { "no_new_match" },
            "",
            Some(&subject),
            Duration::ZERO,
            count as u64,
        );
    }
    Ok(count)
}

/// Diagnostic inventory; no rule deletion feature is provided.
pub fn status(db: &Connection) -> Result<Value> {
    initialize(db)?;
    let mut rules = db.prepare("SELECT id,input,enabled FROM rules ORDER BY id")?;
    let rules = rules
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(|(id, input, enabled)| -> Result<Value> {
            Ok(json!({"id":id,"input":serde_json::from_str::<Value>(&input)?,"enabled":enabled}))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut deliveries = db.prepare("SELECT rule_id,event_header,comment_id,state,thread_id,reason,event_identity_verified FROM rule_deliveries ORDER BY rule_id,event_header,comment_id")?;
    let deliveries = deliveries.query_map([], |r| Ok(json!({"rule_id":r.get::<_,String>(0)?,"event_header":r.get::<_,String>(1)?,"comment_id":r.get::<_,String>(2)?,"state":r.get::<_,String>(3)?,"thread_id":r.get::<_,Option<String>>(4)?,"reason":r.get::<_,Option<String>>(5)?,"event_identity_verified":r.get::<_,bool>(6)?,"receipt_coverage":if r.get::<_,bool>(6)? {"unknown"} else {"unknown_source_identity"}})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!({"rules":rules,"deliveries":deliveries}))
}

#[cfg(test)]
fn dispatch_with(
    db: &mut Connection,
    workspace_base: &Path,
    rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
    finish: &mut impl FnMut(&str, &RuleInput, &str) -> Result<(String, Option<String>)>,
    check_execution: &mut impl FnMut(&RuleInput) -> Result<()>,
) -> Result<usize> {
    dispatch_with_identity(
        db,
        workspace_base,
        rpc,
        &mut |thread, input, message, _, _| finish(thread, input, message),
        check_execution,
    )
}

fn dispatch_with_identity(
    db: &mut Connection,
    workspace_base: &Path,
    rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
    finish: &mut impl FnMut(
        &str,
        &RuleInput,
        &str,
        Option<&str>,
        Option<&str>,
    ) -> Result<(String, Option<String>)>,
    check_execution: &mut impl FnMut(&RuleInput) -> Result<()>,
) -> Result<usize> {
    initialize(db)?;
    let mut count = 0;
    loop {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = tx.query_row("SELECT d.rule_id,d.event_header,d.comment_id,r.input,d.source,d.source_event_key,d.event_identity_verified,d.thread_id FROM rule_deliveries d JOIN rules r ON r.id=d.rule_id WHERE d.state='ready' AND r.enabled=1 AND (d.reason IS NULL OR d.reason NOT IN ('target_busy_before_send','target_unavailable_before_send') OR d.updated<=datetime('now','-15 seconds')) ORDER BY d.updated,d.rule_id LIMIT 1", [], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,bool>(6)?,r.get::<_,Option<String>>(7)?))).optional()?;
        let Some((
            rule_id,
            header,
            comment_id,
            raw,
            source,
            stored_event_key,
            event_identity_verified,
            existing_thread,
        )) = row
        else {
            tx.commit()?;
            return Ok(count);
        };
        tx.execute("UPDATE rule_deliveries SET state='creating',updated=CURRENT_TIMESTAMP WHERE rule_id=?1 AND event_header=?2 AND comment_id=?3 AND state='ready'", params![rule_id,header,comment_id])?;
        tx.commit()?;
        let subject = format!("{rule_id}/{header}/{comment_id}");
        let _trace = crate::observability::TraceGuard::new();
        let span = crate::observability::Span::new("dispatch.rule", Some(&subject));
        let mut stage = "invalid_configuration";
        let mut may_retry = false;
        let mut delivery_thread = None;
        let result = (|| -> Result<(String, Option<String>)> {
            let mut input: RuleInput = serde_json::from_str(&raw)?;
            validate(&mut input)?;
            let source: Value = serde_json::from_str(&source)?;
            let mut context = render_context(
                &input,
                &source,
                &header,
                comment_id.parse::<u64>()?,
                input
                    .target_thread
                    .as_deref()
                    .unwrap_or("00000000-0000-0000-0000-000000000000"),
            )?;
            stage = "goal_template_failed";
            if let Some(objective) = &input.goal_objective {
                let rendered = crate::templates::render(objective, &context)?;
                ensure!(
                    !rendered.trim().is_empty() && rendered.chars().count() <= 4000,
                    "Invalid rendered goal objective"
                );
            }
            stage = "prompt_template_failed";
            crate::templates::render(&input.prompt, &context)?;
            stage = "execution_validation_failed";
            check_execution(&input)?;
            let thread = if let Some(thread) = &existing_thread {
                Uuid::parse_str(thread)?.to_string()
            } else if let Some(thread) = &input.target_thread {
                thread.clone()
            } else {
                let cwd = if let Some(project_id) = &input.project_id {
                    stage = "project_resolution_failed";
                    let project = rpc("project/read", json!({"projectId":project_id}))?;
                    ensure!(
                        project.pointer("/project/id").and_then(Value::as_str) == Some(project_id),
                        "Project identity mismatch"
                    );
                    let roots = project
                        .pointer("/project/roots")
                        .and_then(Value::as_array)
                        .context("Missing project roots")?;
                    let root = if let Some(cwd) = &input.cwd {
                        ensure!(
                            roots.iter().any(|r| r["path"].as_str() == Some(cwd)),
                            "cwd must be a configured project root"
                        );
                        cwd.as_str()
                    } else {
                        roots
                            .first()
                            .and_then(|r| r["path"].as_str())
                            .context("Project has no root")?
                    };
                    path(root)?
                } else if let Some(cwd) = &input.cwd {
                    path(cwd)?
                } else {
                    ensure!(
                        workspace_base.is_absolute(),
                        "Workspace base must be absolute"
                    );
                    let cwd = workspace_base.join(&rule_id).join(&comment_id);
                    std::fs::create_dir_all(&cwd)?;
                    cwd
                };
                stage = "thread_creation_outcome_unknown";
                may_retry = true;
                let response = rpc(
                    "thread/start",
                    json!({"model":input.model,"config":{"model_reasoning_effort":input.reasoning_effort},"allowProviderModelFallback":false,"projectId":input.project_id,"cwd":cwd}),
                )?;
                may_retry = false;
                Uuid::parse_str(
                    response
                        .pointer("/thread/id")
                        .and_then(Value::as_str)
                        .context("Missing created thread ID")?,
                )?
                .to_string()
            };
            delivery_thread = Some(thread.clone());
            db.execute("UPDATE rule_deliveries SET thread_id=?1,updated=CURRENT_TIMESTAMP WHERE rule_id=?2 AND event_header=?3 AND comment_id=?4", params![thread,rule_id,header,comment_id])?;
            crate::observability::emit(
                "delivery.target",
                "observed",
                "",
                Some(&thread),
                Duration::ZERO,
                0,
            );
            stage = "prompt_template_failed";
            context["target"]["thread"] = json!(thread);
            let rendered_prompt = crate::templates::render(&input.prompt, &context)?;
            if let Some(objective) = &input.goal_objective {
                input.goal_objective = Some(crate::templates::render(objective, &context)?);
            }
            let identity = if event_identity_verified
                && (execution_options(&input).is_some()
                    || crate::execution::native_queue_available())
            {
                stored_event_key
                    .map(|event_key| {
                        let delivery_key = crate::delivery_evidence::source_fields_identity(
                            "codex-wake/rule-delivery/v1",
                            &[&rule_id, &event_key],
                        )?;
                        crate::delivery_evidence::begin(db, &delivery_key, &thread, true)
                            .map(|(client_id, _)| (delivery_key, client_id))
                    })
                    .transpose()?
            } else {
                None
            };
            let message = format!(
                "{}\n\nMatched PR comment event data: repository={}, pr={}, comment_id={}, event={}.",
                rendered_prompt, input.repo, input.pr, comment_id, header
            );
            stage = "goal_or_delivery_outcome_unknown";
            may_retry = input.goal_objective.is_none();
            finish(
                &thread,
                &input,
                &message,
                identity.as_ref().map(|(event, _)| event.as_str()),
                identity.as_ref().map(|(_, client)| client.as_str()),
            )
        })();
        let (state, reason) = match result {
            Ok((state, reason)) if state == "queued" => (state, reason),
            Ok((_, reason)) => (
                "needs_attention".into(),
                reason.or(Some("delivery_not_queued".into())),
            ),
            Err(error)
                if may_retry
                    && (crate::execution::before_send_retry_reason(&error).is_some()
                        || (stage == "thread_creation_outcome_unknown"
                            && error
                                .downcast_ref::<crate::goals::BeforeConnect>()
                                .is_some())) =>
            {
                (
                    "ready".into(),
                    Some(
                        crate::execution::before_send_retry_reason(&error)
                            .unwrap_or("target_unavailable_before_send")
                            .to_owned(),
                    ),
                )
            }
            Err(error) => (
                "needs_attention".into(),
                Some(format!("{stage}: {error}").chars().take(1024).collect()),
            ),
        };
        if state == "queued" && reason.as_deref() == Some("native_queue_resume_warning") {
            let thread = delivery_thread
                .as_deref()
                .context("Accepted rule delivery has no target thread")?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            codex_wake::pr_ci_runtime::record_native_wake_recovery(
                &tx,
                thread,
                "native_queue_resume_warning",
            )?;
            ensure!(
                tx.execute("UPDATE rule_deliveries SET state=?1,reason=?2,updated=CURRENT_TIMESTAMP WHERE rule_id=?3 AND event_header=?4 AND comment_id=?5 AND state='creating'",params![state,reason,rule_id,header,comment_id])? == 1,
                "Rule delivery claim was lost before wake recovery was recorded"
            );
            tx.commit()?;
        } else {
            db.execute("UPDATE rule_deliveries SET state=?1,reason=?2,updated=CURRENT_TIMESTAMP WHERE rule_id=?3 AND event_header=?4 AND comment_id=?5",params![state,reason,rule_id,header,comment_id])?;
        }
        span.finish(
            match state.as_str() {
                "queued" => "queued",
                "ready" => "ready",
                _ => "needs_attention",
            },
            crate::observability::reason(reason.as_deref()),
            1,
        );
        count += 1;
    }
}

fn execution_options(input: &RuleInput) -> Option<crate::execution::ExecutionOptions> {
    Some(crate::execution::ExecutionOptions {
        model: input.model.clone()?,
        reasoning_effort: input.reasoning_effort.clone()?,
    })
}

pub fn dispatch(db: &mut Connection, codex: &Path, workspace_base: &Path) -> Result<usize> {
    let mut live_signals: Vec<(String, String, String, Vec<Value>)> = Vec::new();
    let dispatched = dispatch_with_identity(
        db,
        workspace_base,
        &mut |method, params| crate::goals::rpc(codex, method, params),
        &mut |thread, input, message, event_key, client_id| {
            if let Some(objective) = &input.goal_objective {
                crate::goals::create(codex, thread, objective, input.token_budget)?;
                // Goal activation can already start a turn; leave continuation to Codex.
                return if let Some(client_id) = client_id {
                    crate::execution::queue_with_identity(
                        codex,
                        thread,
                        message,
                        client_id,
                        false,
                        Duration::from_secs(120),
                    )
                } else {
                    crate::execution::queue_prepared(codex, thread, message)
                };
            }
            if let (Some(event_key), Some(client_id), Some(options)) =
                (event_key, client_id, execution_options(input))
            {
                let (state, reason, notifications) =
                    crate::execution::deliver_with_identity_observed(
                        codex, thread, message, &options, client_id,
                    )?;
                live_signals.push((
                    event_key.to_owned(),
                    thread.to_owned(),
                    client_id.to_owned(),
                    notifications,
                ));
                Ok((state, reason))
            } else if let Some(client_id) = client_id {
                crate::execution::queue_with_identity(
                    codex,
                    thread,
                    message,
                    client_id,
                    true,
                    Duration::from_secs(120),
                )
            } else {
                crate::execution::deliver(
                    codex,
                    Duration::from_secs(120),
                    thread,
                    message,
                    true,
                    execution_options(input).as_ref(),
                )
            }
        },
        &mut |input| match execution_options(input) {
            Some(options) => crate::execution::validate(codex, &options),
            None => Ok(()),
        },
    );
    for (event_key, thread, client_id, notifications) in live_signals {
        let (_, should_warn) = crate::delivery_evidence::record_notifications(
            db,
            &event_key,
            &thread,
            &client_id,
            &notifications,
        )?;
        if should_warn {
            crate::delivery_evidence::warn_once(db, codex, &event_key, &thread)?;
        }
    }
    dispatched
}

#[cfg(test)]
mod tests {
    use super::*;
    const THREAD: &str = "11111111-1111-4111-8111-111111111111";
    fn test_dispatch(
        db: &mut Connection,
        base: &Path,
        rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
        finish: &mut impl FnMut(&str, &RuleInput, &str) -> Result<(String, Option<String>)>,
    ) -> Result<usize> {
        super::dispatch_with(db, base, rpc, finish, &mut |input| {
            ensure!(
                input.model.as_deref() == Some("gpt-6.1-terra")
                    && input.reasoning_effort.as_deref() == Some("medium"),
                "simulated unsupported execution selection"
            );
            Ok(())
        })
    }
    fn input() -> RuleInput {
        serde_json::from_value(json!({"repo":"owner/repo","pr":42,"author":"alice","author_type":null,"contains":"ship it","prompt":"Review the existing task"})).unwrap()
    }
    fn payload() -> Value {
        json!({"action":"created","repository":{"full_name":"owner/repo"},"issue":{"number":42,"pull_request":{}},"comment":{"id":7,"user":{"login":"alice","type":"User"},"body":"ship it untrusted body"}})
    }
    #[test]
    fn simulation_uses_real_matching_and_renders_without_dispatch() {
        let mut rule = input();
        rule.target_thread = Some(THREAD.into());
        rule.prompt = "Review {{source.comment.body}} for {{target.thread}}".into();
        let report = simulate(SimulateRuleInput {
            rule: rule.clone(),
            event_header: "issue_comment".into(),
            payload: payload(),
        })
        .unwrap();
        assert_eq!(report["matched"], true);
        assert_eq!(report["dispatched"], false);
        assert_eq!(report["action"], "message_thread");
        assert_eq!(
            report["prompt"],
            format!("Review ship it untrusted body for {THREAD}")
        );
        let mut other = payload();
        other["comment"]["body"] = json!("not yet");
        assert_eq!(
            simulate(SimulateRuleInput {
                rule,
                event_header: "issue_comment".into(),
                payload: other
            })
            .unwrap(),
            json!({"matched":false,"dispatched":false})
        );
    }

    #[test]
    fn simulation_reports_unknown_new_thread_and_template_errors() {
        let mut rule = input();
        rule.prompt = "For {{target.thread}}: {{source.comment.body}}".into();
        let report = simulate(SimulateRuleInput {
            rule: rule.clone(),
            event_header: "issue_comment".into(),
            payload: payload(),
        })
        .unwrap();
        assert_eq!(report["action"], "create_thread");
        assert!(
            report["prompt"]
                .as_str()
                .unwrap()
                .contains("<new-thread-id>")
        );
        assert_eq!(report["project_and_execution_verified"], false);
        rule.prompt = "{{source.missing}}".into();
        assert!(
            simulate(SimulateRuleInput {
                rule,
                event_header: "issue_comment".into(),
                payload: payload()
            })
            .is_err()
        );
    }

    #[test]
    fn simulation_keeps_multiple_thread_placeholders_and_checks_full_uuid_length() {
        let mut rule = input();
        rule.prompt = "{{target.thread}}/{{target.thread}}".into();
        rule.goal_objective = Some(format!(
            "{} {{{{target.thread}}}} and {{{{target.thread}}}}",
            "x".repeat(3900)
        ));
        let report = simulate(SimulateRuleInput {
            rule: rule.clone(),
            event_header: "issue_comment".into(),
            payload: payload(),
        })
        .unwrap();
        assert_eq!(report["prompt"], "<new-thread-id>/<new-thread-id>");
        assert_eq!(
            report["goal_objective"]
                .as_str()
                .unwrap()
                .matches("<new-thread-id>")
                .count(),
            2
        );

        rule.goal_objective = Some(format!(
            "{} {{{{target.thread}}}} and {{{{target.thread}}}}",
            "x".repeat(3940)
        ));
        assert!(
            simulate(SimulateRuleInput {
                rule,
                event_header: "issue_comment".into(),
                payload: payload(),
            })
            .is_err()
        );
    }

    #[test]
    fn existing_target_without_preset_keeps_its_execution_settings() {
        let mut rule = input();
        rule.target_thread = Some(THREAD.into());
        validate(&mut rule).unwrap();
        assert!(execution_options(&rule).is_none());
        assert!(rule.model.is_none());
        assert!(rule.reasoning_effort.is_none());

        let mut new_chat = input();
        validate(&mut new_chat).unwrap();
        let options = execution_options(&new_chat).unwrap();
        assert_eq!(options.model, "gpt-6.1-terra");
        assert_eq!(options.reasoning_effort, "medium");
    }

    #[test]
    fn separate_rules_for_same_event_and_chat_have_distinct_delivery_ids() {
        let mut db = Connection::open_in_memory().unwrap();
        for prompt in ["first", "second"] {
            let mut rule = input();
            rule.target_thread = Some(THREAD.into());
            rule.model = Some("test-model".into());
            rule.reasoning_effort = Some("medium".into());
            rule.prompt = prompt.into();
            configure(&db, rule).unwrap();
        }
        assert_eq!(accept(&db, "issue_comment", &payload()).unwrap(), 2);
        let dir = tempfile::tempdir().unwrap();
        let mut ids = Vec::new();
        dispatch_with_identity(
            &mut db,
            dir.path(),
            &mut |_, _| unreachable!(),
            &mut |_, _, _, _, client| {
                ids.push(client.unwrap().to_owned());
                Ok(("queued".into(), None))
            },
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn retry_before_send_reuses_new_chat_without_creating_another() {
        let mut db = Connection::open_in_memory().unwrap();
        configure(&db, input()).unwrap();
        accept(&db, "issue_comment", &payload()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut starts = 0;
        let mut rpc = |method: &str, _: Value| {
            assert_eq!(method, "thread/start");
            starts += 1;
            Ok(json!({"thread":{"id":THREAD}}))
        };
        let mut attempts = 0;
        let mut send = |_: &str, _: &RuleInput, _: &str, _: Option<&str>, _: Option<&str>| {
            attempts += 1;
            if attempts == 1 {
                Err(crate::execution::TargetUnavailableBeforeSend.into())
            } else {
                Ok(("queued".into(), None))
            }
        };
        dispatch_with_identity(&mut db, dir.path(), &mut rpc, &mut send, &mut |_| Ok(())).unwrap();
        assert_eq!(status(&db).unwrap()["deliveries"][0]["state"], "ready");
        db.execute(
            "UPDATE rule_deliveries SET updated=datetime('now','-16 seconds')",
            [],
        )
        .unwrap();
        dispatch_with_identity(&mut db, dir.path(), &mut rpc, &mut send, &mut |_| Ok(())).unwrap();
        assert_eq!(starts, 1);
        assert_eq!(attempts, 2);
        assert_eq!(status(&db).unwrap()["deliveries"][0]["state"], "queued");
    }

    #[test]
    fn accepted_comment_resume_warning_records_native_wake_recovery() {
        let mut db = Connection::open_in_memory().unwrap();
        let mut rule = input();
        rule.target_thread = Some(THREAD.into());
        rule.model = Some("gpt-6.1-sol".into());
        rule.reasoning_effort = Some("medium".into());
        let rule_id = configure(&db, rule).unwrap();
        let source = payload();
        assert_eq!(accept(&db, "issue_comment", &source).unwrap(), 1);
        let source_event_key =
            crate::delivery_evidence::github_comment_event_identity("issue_comment", &source)
                .unwrap()
                .unwrap();
        let delivery_key = crate::delivery_evidence::source_fields_identity(
            "codex-wake/rule-delivery/v1",
            &[&rule_id, &source_event_key],
        )
        .unwrap();
        let expected_client_id =
            crate::delivery_evidence::client_user_message_id(&delivery_key, THREAD).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut actual_client_id = None;

        dispatch_with_identity(
            &mut db,
            directory.path(),
            &mut |_, _| unreachable!(),
            &mut |thread, _, _, event_key, client_id| {
                assert_eq!(thread, THREAD);
                assert_eq!(event_key, Some(delivery_key.as_str()));
                actual_client_id = client_id.map(str::to_owned);
                Ok(("queued".into(), Some("native_queue_resume_warning".into())))
            },
            &mut |_| Ok(()),
        )
        .unwrap();

        assert_eq!(
            actual_client_id.as_deref(),
            Some(expected_client_id.as_str())
        );
        let (state, reason): (String, Option<String>) = db
            .query_row("SELECT state,reason FROM rule_deliveries", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(state, "queued");
        assert_eq!(reason.as_deref(), Some("native_queue_resume_warning"));
        let (thread, recovery_reason): (String, String) = db
            .query_row(
                "SELECT thread,reason FROM native_wake_recovery",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(thread, THREAD);
        assert_eq!(recovery_reason, "native_queue_resume_warning");
    }

    #[test]
    fn retry_creation_only_when_failure_precedes_thread_start() {
        let mut db = Connection::open_in_memory().unwrap();
        configure(&db, input()).unwrap();
        accept(&db, "issue_comment", &payload()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut starts = 0;
        let mut rpc = |_: &str, _: Value| {
            starts += 1;
            if starts == 1 {
                Err(crate::goals::BeforeConnect("initialize failed".into()).into())
            } else {
                Ok(json!({"thread":{"id":THREAD}}))
            }
        };
        let mut sends = 0;
        let mut send = |_: &str, _: &RuleInput, _: &str, _: Option<&str>, _: Option<&str>| {
            sends += 1;
            Ok(("queued".into(), None))
        };
        dispatch_with_identity(&mut db, dir.path(), &mut rpc, &mut send, &mut |_| Ok(())).unwrap();
        assert_eq!(status(&db).unwrap()["deliveries"][0]["state"], "ready");
        db.execute(
            "UPDATE rule_deliveries SET updated=datetime('now','-16 seconds')",
            [],
        )
        .unwrap();
        dispatch_with_identity(&mut db, dir.path(), &mut rpc, &mut send, &mut |_| Ok(())).unwrap();
        assert_eq!(starts, 2);
        assert_eq!(sends, 1);
        assert_eq!(status(&db).unwrap()["deliveries"][0]["state"], "queued");

        let mut uncertain = Connection::open_in_memory().unwrap();
        configure(&uncertain, input()).unwrap();
        accept(&uncertain, "issue_comment", &payload()).unwrap();
        dispatch_with_identity(
            &mut uncertain,
            dir.path(),
            &mut |_, _| anyhow::bail!("response lost"),
            &mut |_, _, _, _, _| unreachable!(),
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            status(&uncertain).unwrap()["deliveries"][0]["state"],
            "needs_attention"
        );
    }
    #[test]
    fn legacy_ready_deliveries_remain_without_verified_event_identity() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE rules (
                id TEXT PRIMARY KEY, input TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE rule_deliveries (
                rule_id TEXT NOT NULL, event_header TEXT NOT NULL,
                comment_id TEXT NOT NULL, source TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'ready', thread_id TEXT,
                reason TEXT, updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(rule_id,event_header,comment_id)
            );
            INSERT INTO rule_deliveries(rule_id,event_header,comment_id,source,state)
            VALUES('legacy-rule','issue_comment','77','{}','ready');",
        )
        .unwrap();

        initialize(&db).unwrap();

        let (state, key, verified): (String, Option<String>, bool) = db
            .query_row(
                "SELECT state,source_event_key,event_identity_verified
                 FROM rule_deliveries WHERE rule_id='legacy-rule'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "ready");
        assert_eq!(key, None);
        assert!(!verified);
    }

    #[test]
    fn matching_all_any_bot_and_non_pr() {
        let mut i = input();
        assert!(matches(&i, "alice", "User", "ship it"));
        assert!(!matches(&i, "bob", "User", "ship it"));
        assert!(!matches(&i, "alice", "User", "no"));
        i.match_mode = MatchMode::Any;
        assert!(matches(&i, "bob", "User", "ship it"));
        i.author = None;
        i.contains = None;
        i.author_type = Some(AuthorType::Bot);
        assert!(matches(&i, "renovate[bot]", "Bot", "no"));
        assert!(!matches(&i, "alice", "User", "ship it"));
        let db = Connection::open_in_memory().unwrap();
        configure(&db, input()).unwrap();
        let mut p = payload();
        p["issue"].as_object_mut().unwrap().remove("pull_request");
        assert_eq!(accept(&db, "issue_comment", &p).unwrap(), 0);
    }
    #[test]
    fn dedup_and_claim_never_recreate_and_body_is_not_forwarded() {
        let mut db = Connection::open_in_memory().unwrap();
        configure(&db, input()).unwrap();
        assert_eq!(accept(&db, "issue_comment", &payload()).unwrap(), 1);
        assert_eq!(accept(&db, "issue_comment", &payload()).unwrap(), 0);
        let dir = tempfile::tempdir().unwrap();
        let mut creates = 0;
        let mut rpc = |method: &str, params: Value| {
            assert_eq!(method, "thread/start");
            assert_eq!(params["model"], "gpt-6.1-terra");
            assert_eq!(params["config"]["model_reasoning_effort"], "medium");
            creates += 1;
            Ok(json!({"thread":{"id":THREAD}}))
        };
        assert_eq!(
            test_dispatch(&mut db, dir.path(), &mut rpc, &mut |_, _, message| {
                assert!(!message.contains("untrusted body"));
                Ok(("queued".into(), None))
            })
            .unwrap(),
            1
        );
        assert_eq!(
            test_dispatch(&mut db, dir.path(), &mut rpc, &mut |_, _, _| unreachable!()).unwrap(),
            0
        );
        assert_eq!(creates, 1);
        assert_eq!(accept(&db, "issue_comment", &payload()).unwrap(), 0);
        db.execute("UPDATE rule_deliveries SET state='creating'", [])
            .unwrap();
        assert_eq!(
            test_dispatch(
                &mut db,
                dir.path(),
                &mut |_, _| unreachable!(),
                &mut |_, _, _| unreachable!()
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn project_resolution_existing_target_and_ambiguous_creation_are_durable() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Connection::open_in_memory().unwrap();
        let mut i = input();
        i.project_id = Some("project-1".into());
        configure(&db, i).unwrap();
        accept(&db, "issue_comment", &payload()).unwrap();
        let mut calls = Vec::new();
        test_dispatch(
            &mut db,
            dir.path(),
            &mut |method, params| {
                calls.push(method.to_owned());
                if method == "project/read" {
                    assert_eq!(params, json!({"projectId":"project-1"}));
                    Ok(json!({"project":{"id":"project-1","roots":[{"path":dir.path()}]}}))
                } else {
                    assert_eq!(params["projectId"], "project-1");
                    assert_eq!(params["cwd"], dir.path().to_str().unwrap());
                    Ok(json!({"thread":{"id":THREAD}}))
                }
            },
            &mut |_, _, _| anyhow::bail!("simulated queue ambiguity"),
        )
        .unwrap();
        assert_eq!(calls, ["project/read", "thread/start"]);
        let delivery = &status(&db).unwrap()["deliveries"][0];
        assert_eq!(delivery["thread_id"], THREAD);
        assert_eq!(delivery["state"], "needs_attention");
        assert_eq!(
            test_dispatch(
                &mut db,
                dir.path(),
                &mut |_, _| unreachable!(),
                &mut |_, _, _| unreachable!()
            )
            .unwrap(),
            0
        );

        let mut db = Connection::open_in_memory().unwrap();
        let mut i = input();
        i.target_thread = Some(THREAD.into());
        configure(&db, i).unwrap();
        accept(&db, "issue_comment", &payload()).unwrap();
        assert_eq!(
            test_dispatch(
                &mut db,
                dir.path(),
                &mut |_, _| unreachable!(),
                &mut |thread, _, _| {
                    assert_eq!(thread, THREAD);
                    Ok(("queued".into(), None))
                }
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn review_comments_have_separate_delivery_identity() {
        let db = Connection::open_in_memory().unwrap();
        configure(&db, input()).unwrap();
        let mut p = payload();
        p["pull_request"] = json!({"number":42});
        assert_eq!(accept(&db, "issue_comment", &p).unwrap(), 1);
        assert_eq!(accept(&db, "pull_request_review_comment", &p).unwrap(), 1);
        assert_eq!(accept(&db, "pull_request_review_comment", &p).unwrap(), 0);
        assert_eq!(
            status(&db).unwrap()["deliveries"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn templates_render_only_opted_fields_and_fail_without_recreation() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Connection::open_in_memory().unwrap();
        let mut i = input();
        i.prompt = "Reply {{source.comment.body}} in {{target.thread}}".into();
        i.goal_objective = Some("Handle PR {{event.pr}}".into());
        configure(&db, i).unwrap();
        accept(&db, "issue_comment", &payload()).unwrap();
        test_dispatch(
            &mut db,
            dir.path(),
            &mut |method, _| {
                assert_eq!(method, "thread/start");
                Ok(json!({"thread":{"id":THREAD}}))
            },
            &mut |_, input, message| {
                assert_eq!(input.goal_objective.as_deref(), Some("Handle PR 42"));
                assert!(message.contains("ship it untrusted body"));
                assert!(message.contains(THREAD));
                Ok(("queued".into(), None))
            },
        )
        .unwrap();
        assert!(
            !status(&db)
                .unwrap()
                .to_string()
                .contains("ship it untrusted body")
        );

        for goal_missing in [true, false] {
            let mut db = Connection::open_in_memory().unwrap();
            let mut i = input();
            if goal_missing {
                i.goal_objective = Some("{{source.missing}}".into());
            } else {
                i.prompt = "{{source.missing}}".into();
            }
            configure(&db, i).unwrap();
            accept(&db, "issue_comment", &payload()).unwrap();
            let mut starts = 0;
            test_dispatch(
                &mut db,
                dir.path(),
                &mut |method, _| {
                    assert_eq!(method, "thread/start");
                    starts += 1;
                    Ok(json!({"thread":{"id":THREAD}}))
                },
                &mut |_, _, _| unreachable!(),
            )
            .unwrap();
            assert_eq!(starts, 0);
            let delivery = &status(&db).unwrap()["deliveries"][0];
            assert_eq!(delivery["state"], "needs_attention");
            assert!(delivery["thread_id"].is_null());
            assert_eq!(
                test_dispatch(
                    &mut db,
                    dir.path(),
                    &mut |_, _| unreachable!(),
                    &mut |_, _, _| unreachable!()
                )
                .unwrap(),
                0
            );
        }
    }

    #[test]
    fn unsupported_model_or_effort_stops_before_creation() {
        for (model, effort) in [("missing", "low"), ("gpt-6.1-sol", "unsupported")] {
            let mut db = Connection::open_in_memory().unwrap();
            let mut i = input();
            i.model = Some(model.into());
            i.reasoning_effort = Some(effort.into());
            configure(&db, i).unwrap();
            accept(&db, "issue_comment", &payload()).unwrap();
            let dir = tempfile::tempdir().unwrap();
            test_dispatch(
                &mut db,
                dir.path(),
                &mut |_, _| unreachable!(),
                &mut |_, _, _| unreachable!(),
            )
            .unwrap();
            assert_eq!(
                status(&db).unwrap()["deliveries"][0]["state"],
                "needs_attention"
            );
        }
    }

    #[test]
    fn explicit_execution_selection_reaches_creation_and_delivery_for_each_comment() {
        let mut db = Connection::open_in_memory().unwrap();
        let mut i = input();
        i.model = Some("configured-model".into());
        i.reasoning_effort = Some("high".into());
        configure(&db, i).unwrap();
        let mut p = payload();
        accept(&db, "issue_comment", &p).unwrap();
        p["comment"]["id"] = json!(8);
        accept(&db, "issue_comment", &p).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut starts = 0;
        let mut checks = 0;
        let mut sends = 0;
        assert_eq!(
            super::dispatch_with(
                &mut db,
                dir.path(),
                &mut |method, params| {
                    assert_eq!(method, "thread/start");
                    assert_eq!(params["model"], "configured-model");
                    assert_eq!(params["config"]["model_reasoning_effort"], "high");
                    starts += 1;
                    Ok(json!({"thread":{"id":Uuid::new_v4().to_string()}}))
                },
                &mut |_, input, _| {
                    let options = execution_options(input).unwrap();
                    assert_eq!(options.model, "configured-model");
                    assert_eq!(options.reasoning_effort, "high");
                    sends += 1;
                    Ok(("queued".into(), None))
                },
                &mut |input| {
                    assert_eq!(input.model.as_deref(), Some("configured-model"));
                    checks += 1;
                    Ok(())
                }
            )
            .unwrap(),
            2
        );
        assert_eq!((starts, checks, sends), (2, 2, 2));
        let rows = status(&db).unwrap();
        assert_ne!(
            rows["deliveries"][0]["thread_id"],
            rows["deliveries"][1]["thread_id"]
        );
    }

    #[test]
    fn creation_error_and_project_root_mismatch_do_not_retry_or_guess() {
        for project_mismatch in [false, true] {
            let mut db = Connection::open_in_memory().unwrap();
            let mut i = input();
            if project_mismatch {
                i.project_id = Some("p".into());
                i.cwd = Some("/not-a-project-root".into());
            }
            configure(&db, i).unwrap();
            accept(&db, "issue_comment", &payload()).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let mut calls = 0;
            test_dispatch(
                &mut db,
                dir.path(),
                &mut |method, _| {
                    calls += 1;
                    if project_mismatch {
                        assert_eq!(method, "project/read");
                        Ok(json!({"project":{"id":"p","roots":[{"path":dir.path()}]}}))
                    } else {
                        assert_eq!(method, "thread/start");
                        anyhow::bail!("creation response lost")
                    }
                },
                &mut |_, _, _| unreachable!(),
            )
            .unwrap();
            assert_eq!(calls, 1);
            let delivery = &status(&db).unwrap()["deliveries"][0];
            assert_eq!(delivery["state"], "needs_attention");
            assert!(delivery["thread_id"].is_null());
            assert_eq!(
                test_dispatch(
                    &mut db,
                    dir.path(),
                    &mut |_, _| unreachable!(),
                    &mut |_, _, _| unreachable!()
                )
                .unwrap(),
                0
            );
            assert_eq!(accept(&db, "issue_comment", &payload()).unwrap(), 0);
        }
    }

    #[test]
    fn validates_goal_cwd_and_existing_target() {
        let db = Connection::open_in_memory().unwrap();
        let mut i = input();
        i.token_budget = Some(1);
        assert!(configure(&db, i).is_err());
        let mut i = input();
        i.cwd = Some("relative".into());
        assert!(configure(&db, i).is_err());
        let mut i = input();
        i.target_thread = Some(THREAD.into());
        i.project_id = Some("p".into());
        assert!(configure(&db, i).is_err());
        let mut i = input();
        i.target_thread = Some(THREAD.into());
        i.goal_objective = Some("goal".into());
        assert!(configure(&db, i).is_err());
        assert!(
            serde_json::from_value::<RuleInput>(
                json!({"repo":"o/r","pr":1,"prompt":"x","match_mode":"maybe"})
            )
            .is_err()
        );
    }
}
