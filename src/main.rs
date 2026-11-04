mod bridge;
mod execution;
mod goals;
mod host_cleanup;
mod manager;
mod observability;
mod probe;
mod rules;
mod subscriptions;
mod telemetry;
mod templates;
mod uninstall;

use anyhow::{Context, Result, bail};
use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, model::CallToolResult, schemars, tool,
    tool_router,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    io::{self, Read},
    path::PathBuf,
    time::Duration,
};

#[derive(Clone)]
struct WakeTools {
    config: manager::Config,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Registration {
    /// Exact owner/repository in GitHub.
    repo: String,
    /// GitHub Actions run ID, not the display number.
    run_id: i64,
    attempt: i64,
    /// Exact commit SHA for this attempt.
    sha: String,
    /// Explicit destination Codex chat UUID.
    thread: String,
    /// Optional input: {{source.path}}, {{event.repo}}, {{target.thread}}.
    message_template: Option<String>,
    execution: Option<execution::ExecutionOptions>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SubscriptionInput {
    /// pull_request, review, deployment, git_ref, job, chat, thread, subagent, dependency, resource, or artifact.
    kind: String,
    /// GitHub owner/repository, or an explicit namespace for local/external publishers.
    #[serde(default)]
    repo: String,
    /// Exact PR/deployment number, branch, job/artifact/resource ID, or source chat/agent UUID.
    resource: String,
    /// Exact event supported for this kind; see the tool description.
    event: String,
    /// Explicit destination Codex chat UUID. Multiple subscriptions may target this chat.
    thread: String,
    /// Optional input: {{source.path}}, {{event.resource}}, {{target.thread}}.
    message_template: Option<String>,
    execution: Option<execution::ExecutionOptions>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PublicationInput {
    /// job, chat, dependency, resource, or artifact.
    kind: String,
    #[serde(default)]
    repo: String,
    resource: String,
    /// Verified outcome: success/failure/cancelled/completed for job; completed/blocked/failed for chat; recovered, released, or available for the respective other kinds.
    outcome: String,
    /// Optional original values for matching subscribers' source.* placeholders.
    source: Option<Value>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ThreadInput {
    thread: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CatalogInput {
    cursor: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CreateGoalInput {
    thread: String,
    objective: String,
    /// Only provide a positive budget when the user explicitly requested one.
    token_budget: Option<i64>,
    message_template: Option<String>,
    source: Option<Value>,
    execution: Option<execution::ExecutionOptions>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EditGoalInput {
    thread: String,
    /// Omit to preserve the objective. Codex controls usage accounting.
    objective: Option<String>,
    token_budget: Option<i64>,
    message_template: Option<String>,
    source: Option<Value>,
    execution: Option<execution::ExecutionOptions>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ResumeGoalInput {
    thread: String,
    message_template: Option<String>,
    source: Option<Value>,
    execution: Option<execution::ExecutionOptions>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct QueueInput {
    thread: String,
    /// Literal input with optional {{source.path}} and {{target.thread}} placeholders.
    message_template: String,
    /// Original values available under source.* in placeholders.
    source: Option<Value>,
    /// False queues only; true also resumes execution.
    #[serde(default)]
    resume: bool,
    execution: Option<execution::ExecutionOptions>,
}

fn goal_input_result(
    config: &manager::Config,
    thread: &str,
    goal: Value,
    template: Option<&str>,
    source: Option<Value>,
) -> Value {
    let Some(template) = template else {
        return json!({"goal":goal});
    };
    let result = (|| -> Result<Value> {
        let message = templates::render(
            template,
            &json!({"source":source.unwrap_or(Value::Null),"target":{"thread":thread},"goal":goal}),
        )?;
        let (state, reason) = execution::queue_prepared(&config.codex, thread, &message)?;
        Ok(json!({"state":state,"reason":reason}))
    })();
    match result {
        Ok(delivery) => json!({"goal":goal,"delivery":delivery,"turn_execution_verified":false}),
        Err(error) => {
            observability::emit(
                "goal.input",
                "needs_attention",
                observability::error_class(&error),
                Some(thread),
                Duration::ZERO,
                1,
            );
            json!({"goal":goal,"delivery_error":error.to_string(),"turn_execution_verified":false})
        }
    }
}

fn database(config: &manager::Config) -> Result<rusqlite::Connection> {
    manager::require_installed(config)?;
    let db = bridge::connect(&config.db)?;
    subscriptions::initialize(&db)?;
    rules::initialize(&db)?;
    Ok(db)
}

fn recover(config: &manager::Config) -> Result<usize> {
    let mut db = database(config)?;
    Ok(
        bridge::dispatch(&mut db, &config.codex, Duration::from_secs(120))?
            + subscriptions::dispatch(&mut db, &config.codex, Duration::from_secs(120))?
            + rules::dispatch(&mut db, &config.codex, &config.state.join("workspaces"))?,
    )
}

fn lifecycle_output(event: &str, matched: usize, states: &[String]) -> Value {
    if matched == 0 {
        return json!({});
    }
    let count = |state: &str| {
        states
            .iter()
            .filter(|value| value.as_str() == state)
            .count()
    };
    json!({"systemMessage":format!(
        "codex-wake {event}: {matched} newly matched subscription(s). Current subscriptions for this source: {} queue acceptance(s), {} pending, {} requiring attention. Queue acceptance does not verify execution.",
        count("queued"), count("ready") + count("sending"), count("needs_attention")
    )})
}

fn run_hook(config: &manager::Config, payload: &Value) -> Result<Value> {
    let operation = match payload["hook_event_name"].as_str() {
        Some("SessionStart") => "hook.session_start",
        Some("Stop") => "hook.stop",
        Some("SubagentStop") => "hook.subagent_stop",
        _ => "hook.unsupported",
    };
    let span = observability::Span::new(
        operation,
        payload["agent_id"]
            .as_str()
            .or(payload["session_id"].as_str()),
    );
    let result = run_hook_inner(config, payload);
    span.result(&result);
    result
}

fn run_hook_inner(config: &manager::Config, payload: &Value) -> Result<Value> {
    if payload["hook_event_name"] == "SessionStart" {
        let status = manager::ensure_receiver(config)?;
        return Ok(
            json!({"systemMessage":if status["controller_ready"] == true {
                "codex-wake: shared receiver and Codex controller are available."
            } else {
                "codex-wake: shared receiver is available; Codex controller is not ready."
            }}),
        );
    }
    let (kind, event, resource) = match payload["hook_event_name"].as_str() {
        Some("Stop") => ("thread", "turn_completed", payload["session_id"].as_str()),
        Some("SubagentStop") => ("subagent", "completed", payload["agent_id"].as_str()),
        _ => bail!("Unsupported lifecycle hook"),
    };
    let resource = uuid::Uuid::parse_str(resource.context("Hook source ID missing")?)?.to_string();
    let db = database(config)?;
    let matched = subscriptions::publish_with_source(&db, kind, "", &resource, event, payload)?;
    observability::emit(
        "hook.matches",
        if matched > 0 {
            "matched"
        } else {
            "no_new_match"
        },
        "",
        Some(&resource),
        Duration::ZERO,
        matched as u64,
    );
    recover(config)?;
    let mut statement = db.prepare(
        "SELECT state FROM subscriptions WHERE kind=?1 AND repo='' AND resource=?2 AND event=?3",
    )?;
    let states = statement
        .query_map(rusqlite::params![kind, resource, event], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(lifecycle_output(
        payload["hook_event_name"].as_str().unwrap_or_default(),
        matched,
        &states,
    ))
}

fn tool_result(result: Result<Value>) -> CallToolResult {
    match result {
        Ok(value) => CallToolResult::structured(value),
        Err(error) => {
            observability::emit(
                "mcp.result",
                "error",
                observability::error_class(&error),
                None,
                Duration::ZERO,
                1,
            );
            CallToolResult::error(vec![rmcp::model::ContentBlock::text(error.to_string())])
        }
    }
}

#[tool_router]
impl WakeTools {
    #[tool(
        description = "List available models and supported reasoning efforts.",
        annotations(read_only_hint = true)
    )]
    fn list_models(&self, Parameters(input): Parameters<CatalogInput>) -> CallToolResult {
        tool_result(goals::rpc(
            &self.config.codex,
            "model/list",
            json!({"limit":100,"cursor":input.cursor}),
        ))
    }

    #[tool(
        description = "List Codex projects available for conditional thread creation.",
        annotations(read_only_hint = true)
    )]
    fn list_projects(&self, Parameters(input): Parameters<CatalogInput>) -> CallToolResult {
        tool_result(goals::rpc(
            &self.config.codex,
            "project/list",
            json!({"limit":100,"cursor":input.cursor}),
        ))
    }

    #[tool(
        description = "Configure a PR-comment rule: match author/type/text with all/any, then create a thread or message an existing one. Optional project, goal, template and execution preset.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    fn configure_rule(&self, Parameters(input): Parameters<rules::RuleInput>) -> CallToolResult {
        tool_result((|| {
            Ok(json!({"rule_id":rules::configure(&database(&self.config)?,input)?}))
        })())
    }

    #[tool(
        description = "Render and queue input for a thread. resume also wakes it; execution presets require an idle resumable thread.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    fn queue_thread(&self, Parameters(input): Parameters<QueueInput>) -> CallToolResult {
        tool_result((|| {
            let thread = uuid::Uuid::parse_str(&input.thread)?.to_string();
            let message = templates::render(
                &input.message_template,
                &json!({"source":input.source.unwrap_or(Value::Null),"target":{"thread":thread}}),
            )?;
            let (state, reason) = execution::deliver(
                &self.config.codex,
                Duration::from_secs(120),
                &thread,
                &message,
                input.resume,
                input.execution.as_ref(),
            )?;
            Ok(json!({"state":state,"reason":reason,"turn_execution_verified":false}))
        })())
    }

    #[tool(
        description = "Read a Codex thread's saved goal without waking it.",
        annotations(read_only_hint = true)
    )]
    fn get_goal(&self, Parameters(input): Parameters<ThreadInput>) -> CallToolResult {
        tool_result(goals::get(&self.config.codex, &input.thread))
    }

    #[tool(
        description = "Create an authorized goal; fails if one exists. Codex may continue automatically. Optional presets apply first; input is queued. Omit unrequested budgets.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    fn create_goal(&self, Parameters(input): Parameters<CreateGoalInput>) -> CallToolResult {
        tool_result((|| {
            if let Some(template) = &input.message_template {
                templates::validate(template)?;
            }
            if let Some(options) = &input.execution {
                execution::prepare(&self.config.codex, &input.thread, options)?;
            }
            let goal = goals::create(
                &self.config.codex,
                &input.thread,
                &input.objective,
                input.token_budget,
            )?;
            Ok(goal_input_result(
                &self.config,
                &input.thread,
                goal,
                input.message_template.as_deref(),
                input.source,
            ))
        })())
    }

    #[tool(
        description = "Edit a saved goal; Codex may continue active goals automatically. Optional presets apply first; input is queued. Omitted fields stay unchanged; Codex controls usage accounting.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    fn edit_goal(&self, Parameters(input): Parameters<EditGoalInput>) -> CallToolResult {
        tool_result((|| {
            if let Some(template) = &input.message_template {
                templates::validate(template)?;
            }
            if let Some(options) = &input.execution {
                execution::prepare(&self.config.codex, &input.thread, options)?;
            }
            let goal = goals::edit(
                &self.config.codex,
                &input.thread,
                input.objective.as_deref(),
                input.token_budget,
            )?;
            Ok(goal_input_result(
                &self.config,
                &input.thread,
                goal,
                input.message_template.as_deref(),
                input.source,
            ))
        })())
    }

    #[tool(
        description = "Activate an authorized saved goal. Optional input is queued; Codex controls continuation. Presets apply before activation.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    fn resume_goal(&self, Parameters(input): Parameters<ResumeGoalInput>) -> CallToolResult {
        tool_result((|| {
            if let Some(template) = &input.message_template {
                templates::validate(template)?;
            }
            if let Some(options) = &input.execution {
                execution::prepare(&self.config.codex, &input.thread, options)?;
            }
            let goal = goals::resume(&self.config.codex, &input.thread)?;
            Ok(goal_input_result(
                &self.config,
                &input.thread,
                goal,
                input.message_template.as_deref(),
                input.source,
            ))
        })())
    }

    #[tool(
        description = "Subscribe a thread to one source/resource/event; other subscriptions stay independent. get_status lists supported events. Lifecycle signals require trusted hooks.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    fn subscribe(&self, Parameters(input): Parameters<SubscriptionInput>) -> CallToolResult {
        tool_result((|| {
            let db = database(&self.config)?;
            let id = subscriptions::subscribe_with_delivery(
                &db,
                &input.kind,
                &input.repo,
                &input.resource,
                &input.event,
                &input.thread,
                subscriptions::DeliveryConfig {
                    message_template: input.message_template.as_deref(),
                    execution: input.execution.as_ref(),
                },
            )?;
            let rows = subscriptions::status(&db)?;
            let record = rows
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["id"] == id))
                .context("Registered subscription missing")?;
            Ok(json!({"subscription_id":id,"subscription":record}))
        })())
    }

    #[tool(
        description = "Publish a verified job/chat result, dependency recovery, resource release or artifact availability to matching subscriptions.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    fn publish_result(&self, Parameters(input): Parameters<PublicationInput>) -> CallToolResult {
        tool_result((|| {
            anyhow::ensure!(
                ["job", "chat", "dependency", "resource", "artifact"]
                    .contains(&input.kind.as_str()),
                "Unsupported publication kind"
            );
            let db = database(&self.config)?;
            let matched = if let Some(source) = input.source {
                subscriptions::publish_with_source(
                    &db,
                    &input.kind,
                    &input.repo,
                    &input.resource,
                    &input.outcome,
                    &source,
                )?
            } else {
                subscriptions::publish(
                    &db,
                    &input.kind,
                    &input.repo,
                    &input.resource,
                    &input.outcome,
                )?
            };
            drop(db);
            Ok(json!({"matched":matched,"attempted":recover(&self.config)?}))
        })())
    }

    #[tool(
        description = "Subscribe a thread to completion of an exact GitHub Actions repo/run/attempt/SHA.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    fn register_wait(&self, Parameters(input): Parameters<Registration>) -> CallToolResult {
        tool_result((|| {
            let db = database(&self.config)?;
            bridge::register_with_template(
                &db,
                &input.repo,
                input.run_id,
                input.attempt,
                &input.thread,
                &input.sha,
                input.message_template.as_deref(),
                input.execution.as_ref(),
            )?;
            Ok(json!({"registered": true, "run_id": input.run_id, "attempt": input.attempt}))
        })())
    }

    #[tool(
        description = "Read local receiver health, supported events and delivery states. queued means acceptance, not verified execution.",
        annotations(read_only_hint = true)
    )]
    fn get_status(&self) -> CallToolResult {
        tool_result((|| {
            let db = database(&self.config)?;
            Ok(
                json!({"receiver": manager::status(&self.config)?, "waits": bridge::status(&db)?, "subscriptions":subscriptions::status(&db)?,"rules":rules::status(&db)?,"supported_events":subscriptions::ALLOWED_EVENTS,"diagnostics":diagnostics(&self.config,42)?}),
            )
        })())
    }

    #[tool(
        description = "Dispatch stored ready events. Never retries sending or needs_attention records.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    fn recover_ready(&self) -> CallToolResult {
        tool_result((|| {
            let count = recover(&self.config)?;
            Ok(json!({"attempted": count}))
        })())
    }
}

#[rmcp::tool_handler(router = Self::tool_router())]
impl rmcp::ServerHandler for WakeTools {
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        let operation = match request.name.as_ref() {
            "list_models" => "mcp.list_models",
            "list_projects" => "mcp.list_projects",
            "configure_rule" => "mcp.configure_rule",
            "queue_thread" => "mcp.queue_thread",
            "get_goal" => "mcp.get_goal",
            "create_goal" => "mcp.create_goal",
            "edit_goal" => "mcp.edit_goal",
            "resume_goal" => "mcp.resume_goal",
            "subscribe" => "mcp.subscribe",
            "publish_result" => "mcp.publish_result",
            "register_wait" => "mcp.register_wait",
            "get_status" => "mcp.get_status",
            "recover_ready" => "mcp.recover_ready",
            _ => "mcp.unknown_tool",
        };
        observability::TRACE
            .scope(uuid::Uuid::new_v4().to_string(), async {
                let span = observability::Span::new(operation, None);
                let result = Self::tool_router()
                    .call(rmcp::handler::server::tool::ToolCallContext::new(
                        self, request, context,
                    ))
                    .await;
                match &result {
                    Ok(rmcp::model::CallToolResponse::Complete(value))
                        if value.is_error == Some(true) =>
                    {
                        span.finish("error", "tool_error", 1)
                    }
                    Err(_) => span.finish("rejected", "invalid_tool_request", 1),
                    Ok(rmcp::model::CallToolResponse::Complete(value)) => {
                        let value = value.structured_content.as_ref();
                        let partial = value.is_some_and(|v| {
                            v.get("delivery_error").is_some()
                                || v["state"] == "needs_attention"
                                || v.pointer("/delivery/state") == Some(&json!("needs_attention"))
                        });
                        span.finish(
                            if partial { "needs_attention" } else { "ok" },
                            if partial {
                                "delivery_not_confirmed"
                            } else {
                                ""
                            },
                            1,
                        );
                    }
                    _ => span.finish("ok", "", 1),
                }
                result
            })
            .await
    }
}

fn option(args: &mut Vec<String>, name: &str) -> Result<Option<String>> {
    let Some(index) = args.iter().position(|s| s == name) else {
        return Ok(None);
    };
    args.remove(index);
    anyhow::ensure!(index < args.len(), "Missing value for {name}");
    let value = args.remove(index);
    anyhow::ensure!(!args.iter().any(|s| s == name), "Duplicate option {name}");
    Ok(Some(value))
}

fn required(args: &mut Vec<String>, name: &str) -> Result<String> {
    option(args, name)?.with_context(|| format!("Missing {name}"))
}

fn diagnostics(config: &manager::Config, days: u32) -> Result<Value> {
    anyhow::ensure!((1..=90).contains(&days), "days must be between 1 and 90");
    let mut report = telemetry::report(&config.state.join("telemetry.sqlite3"), days)
        .unwrap_or_else(
            |error| json!({"enabled":false,"error_class":observability::error_class(&error)}),
        );
    report["telemetry_write_failures_this_process"] = json!(observability::failures());
    let queues = (|| -> Result<Value> {
        if !config.db.exists() {
            return Ok(json!({}));
        }
        let db = rusqlite::Connection::open_with_flags(
            &config.db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        db.busy_timeout(Duration::from_millis(250))?;
        let mut queues = serde_json::Map::new();
        for table in ["waits", "subscriptions", "rule_deliveries"] {
            let exists: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )?;
            if !exists {
                continue;
            }
            let mut stmt = db.prepare(&format!("SELECT state,count(*),max(max(0,unixepoch()-unixepoch(updated))) FROM {table} GROUP BY state"))?;
            let groups = stmt.query_map([], |r| Ok(json!({"state":r.get::<_,String>(0)?,"count":r.get::<_,i64>(1)?,"oldest_seconds":r.get::<_,Option<i64>>(2)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
            queues.insert(table.into(), json!(groups));
        }
        Ok(json!(queues))
    })();
    report["queues"] =
        queues.unwrap_or_else(|error| json!({"error_class":observability::error_class(&error)}));
    Ok(report)
}

fn cli_execution(args: &mut Vec<String>) -> Result<Option<execution::ExecutionOptions>> {
    let model = option(args, "--model")?;
    let effort = option(args, "--reasoning-effort")?;
    if model.is_none() && effort.is_none() {
        return Ok(None);
    }
    let defaults = execution::ExecutionOptions::default();
    Ok(Some(execution::ExecutionOptions {
        model: model.unwrap_or(defaults.model),
        reasoning_effort: effort.unwrap_or(defaults.reasoning_effort),
    }))
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let mut config = manager::Config::from_env()?;
    if let Some(value) = option(&mut args, "--db")? {
        config.db = PathBuf::from(value);
    }
    if let Some(value) = option(&mut args, "--codex")? {
        config.codex = PathBuf::from(value);
    }
    anyhow::ensure!(
        !args.is_empty(),
        "Usage: codex-wake [--db PATH] [--codex PATH] mcp|ensure|receiver|register|subscribe|publish|handle|hook|status|subscriptions|recover|remove-service|smoke-live|smoke-github"
    );
    let command = args.remove(0);
    // Cleanup must never recreate state after removing the plugin.
    if command != "cleanup-uninstalled" && command != "diagnostics" {
        observability::configure(config.state.join("telemetry.sqlite3"));
    }
    let operation = match command.as_str() {
        "mcp" => "cli.mcp",
        "ensure" => "cli.ensure",
        "record-funnel" => "cli.record_funnel",
        "receiver" => "cli.receiver",
        "register" => "cli.register",
        "subscribe" => "cli.subscribe",
        "publish" => "cli.publish",
        "handle" => "cli.handle",
        "hook" => "cli.hook",
        "status" => "cli.status",
        "subscriptions" => "cli.subscriptions",
        "recover" => "cli.recover",
        "configure-rule" => "cli.configure_rule",
        "goal-get" => "cli.goal_get",
        "remove-service" => "cli.remove_service",
        "cleanup-uninstalled" => "cli.cleanup",
        "smoke-live" | "smoke-github" => "cli.probe",
        "diagnostics" => "cli.diagnostics",
        _ => "cli.unknown_command",
    };
    observability::TRACE
        .scope(uuid::Uuid::new_v4().to_string(), async {
            let span = observability::Span::new(operation, None);
            let result = run_command(config, command, args).await;
            span.result(&result);
            result
        })
        .await
}

async fn run_command(
    config: manager::Config,
    command: String,
    mut args: Vec<String>,
) -> Result<()> {
    match command.as_str() {
        "record-funnel" => {
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            println!("{}", manager::record_funnel(&config)?);
        }
        "diagnostics" => {
            let days = option(&mut args, "--days")?
                .unwrap_or_else(|| "42".into())
                .parse::<u32>()?;
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            println!("{}", diagnostics(&config, days)?);
        }
        "configure-rule" => {
            let path = required(&mut args, "--file")?;
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            let mut raw = Vec::new();
            std::fs::File::open(path)?
                .take(256 * 1024 + 1)
                .read_to_end(&mut raw)?;
            anyhow::ensure!(raw.len() <= 256 * 1024, "Rule file exceeds 256 KiB");
            let input: rules::RuleInput = serde_json::from_slice(&raw)?;
            println!(
                "{}",
                json!({"rule_id":rules::configure(&database(&config)?,input)?})
            );
        }
        "goal-get" => {
            let thread = required(&mut args, "--thread")?;
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            println!("{}", goals::get(&config.codex, &thread)?);
        }
        "mcp" => {
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            manager::ensure_receiver(&config)?;
            let _client = manager::register_client(&config)?;
            let service = WakeTools { config }.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }
        "ensure" => {
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            println!("{}", manager::ensure_receiver(&config)?);
        }
        "receiver" => {
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            manager::run_receiver(&config)?;
        }
        "remove-service" => {
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            manager::remove_service(&config)?;
            println!("{}", json!({"removed":true,"state_preserved":true}));
        }
        "cleanup-uninstalled" => {
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            manager::cleanup_uninstalled(&config)?;
        }
        "register" => {
            let repo = required(&mut args, "--repo")?;
            let run = required(&mut args, "--run")?.parse()?;
            let attempt = required(&mut args, "--attempt")?.parse()?;
            let thread = required(&mut args, "--thread")?;
            let sha = required(&mut args, "--sha")?;
            let message_template = option(&mut args, "--message-template")?;
            let execution = cli_execution(&mut args)?;
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            bridge::register_with_template(
                &bridge::connect(&config.db)?,
                &repo,
                run,
                attempt,
                &thread,
                &sha,
                message_template.as_deref(),
                execution.as_ref(),
            )?;
            println!("{}", json!({"registered":true}));
        }
        "subscribe" => {
            let kind = required(&mut args, "--kind")?;
            let repo = option(&mut args, "--repo")?.unwrap_or_default();
            let resource = required(&mut args, "--resource")?;
            let event = required(&mut args, "--event")?;
            let thread = required(&mut args, "--thread")?;
            let message_template = option(&mut args, "--message-template")?;
            let execution = cli_execution(&mut args)?;
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            let id = subscriptions::subscribe_with_delivery(
                &database(&config)?,
                &kind,
                &repo,
                &resource,
                &event,
                &thread,
                subscriptions::DeliveryConfig {
                    message_template: message_template.as_deref(),
                    execution: execution.as_ref(),
                },
            )?;
            println!("{}", json!({"subscription_id":id}));
        }
        "publish" => {
            let kind = required(&mut args, "--kind")?;
            let repo = option(&mut args, "--repo")?.unwrap_or_default();
            let resource = required(&mut args, "--resource")?;
            let outcome = required(&mut args, "--outcome")?;
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            anyhow::ensure!(
                ["job", "chat", "dependency", "resource", "artifact"].contains(&kind.as_str()),
                "Unsupported publication kind"
            );
            let matched =
                subscriptions::publish(&database(&config)?, &kind, &repo, &resource, &outcome)?;
            println!(
                "{}",
                json!({"matched":matched,"attempted":recover(&config)?})
            );
        }
        "hook" => {
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            let mut raw = Vec::new();
            io::stdin().take(1024 * 1024 + 1).read_to_end(&mut raw)?;
            anyhow::ensure!(raw.len() <= 1024 * 1024, "Hook payload exceeds 1 MiB");
            let payload: Value = serde_json::from_slice(&raw)?;
            match run_hook(&config, &payload) {
                Ok(output) => println!("{output}"),
                Err(error) => {
                    eprintln!("codex-wake hook error: {error:#}");
                    println!(
                        "{}",
                        json!({"systemMessage":"codex-wake: hook processing failed; event delivery is not confirmed. See hook diagnostics."})
                    );
                    return Err(error);
                }
            }
        }
        "smoke-live" | "smoke-github" => {
            let thread = required(&mut args, "--test-thread")?;
            let webhook = PathBuf::from(required(&mut args, "--webhook")?);
            let result = if command == "smoke-live" {
                let attempt = option(&mut args, "--attempt")?
                    .unwrap_or_else(|| "1".into())
                    .parse()?;
                anyhow::ensure!(args.is_empty(), "Unexpected arguments");
                probe::live(&thread, &webhook, attempt)?
            } else {
                let repo = required(&mut args, "--repo")?;
                anyhow::ensure!(args.is_empty(), "Unexpected arguments");
                probe::github(&repo, &thread, &webhook)?
            };
            println!("{result}");
        }
        "handle" => {
            let source = option(&mut args, "--payload-env")?;
            let event_env = option(&mut args, "--event-env")?;
            let event = event_env
                .map(|name| env::var(name).context("Receiver event header missing"))
                .transpose()?
                .unwrap_or_else(|| "workflow_run".into());
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            let reader: Box<dyn Read> = if let Some(name) = source {
                Box::new(std::fs::File::open(
                    env::var(name).context("Receiver payload filename missing")?,
                )?)
            } else {
                Box::new(io::stdin())
            };
            let mut raw = Vec::new();
            reader.take(1024 * 1024 + 1).read_to_end(&mut raw)?;
            anyhow::ensure!(raw.len() <= 1024 * 1024, "Payload exceeds 1 MiB");
            let db = database(&config)?;
            let payload: Value = serde_json::from_slice(&raw)?;
            let matched_rules = rules::accept(&db, &event, &payload)?;
            let result = if event == "workflow_run" {
                json!(bridge::accept(&db, &payload)?)
            } else if matches!(
                event.as_str(),
                "issue_comment" | "pull_request_review_comment"
            ) {
                json!({"matched":0})
            } else {
                json!({"matched":subscriptions::accept(&db,&event,&payload)?})
            };
            drop(db);
            if env::var("CODEX_WAKE_DEFER").as_deref() != Ok("1") {
                recover(&config)?;
            }
            println!("{}", json!({"result":result,"matched_rules":matched_rules}));
        }
        "status" | "subscriptions" | "recover" => {
            anyhow::ensure!(args.is_empty(), "Unexpected arguments");
            let db = database(&config)?;
            let value = if command == "status" {
                bridge::status(&db)?
            } else if command == "subscriptions" {
                subscriptions::status(&db)?
            } else {
                drop(db);
                json!({"attempted":recover(&config)?})
            };
            println!("{value}");
        }
        _ => bail!("Unknown command {command}"),
    }
    Ok(())
}

#[cfg(test)]
mod hook_output_tests {
    use super::*;

    #[test]
    fn no_new_subscription_is_quiet() {
        assert_eq!(lifecycle_output("Stop", 0, &["queued".into()]), json!({}));
    }

    #[test]
    fn useful_results_are_not_context_or_continuation_instructions() {
        let output = lifecycle_output(
            "SubagentStop",
            4,
            &[
                "queued".into(),
                "ready".into(),
                "sending".into(),
                "needs_attention".into(),
            ],
        );
        let text = output["systemMessage"].as_str().unwrap();
        assert!(text.contains("4 newly matched"));
        assert!(text.contains("1 queue acceptance(s), 2 pending, 1 requiring attention"));
        assert!(text.contains("does not verify execution"));
        assert_eq!(output.as_object().unwrap().len(), 1);
    }

    #[test]
    fn hook_reports_real_delivery_states_and_duplicate_is_quiet() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = manager::Config::from_env().unwrap();
        config.plugin_base = None;
        config.state = temp.path().join("state");
        config.db = config.state.join("state.sqlite3");
        config.codex = temp.path().join("missing-codex");
        let db = database(&config).unwrap();
        let source = "11111111-1111-4111-8111-111111111111";
        subscriptions::subscribe_with_delivery(
            &db,
            "thread",
            "",
            source,
            "turn_completed",
            "22222222-2222-4222-8222-222222222222",
            subscriptions::DeliveryConfig {
                message_template: None,
                execution: None,
            },
        )
        .unwrap();
        let payload = json!({"hook_event_name":"Stop","session_id":source,"last_assistant_message":"PRIVATE_TEXT_NOT_FOR_HOOK_OUTPUT"});
        let output = run_hook(&config, &payload).unwrap();
        let text = output["systemMessage"].as_str().unwrap();
        assert!(text.contains("1 newly matched"));
        assert!(text.contains("0 queue acceptance(s), 1 pending"));
        assert!(!text.contains("PRIVATE_TEXT"));
        assert_eq!(run_hook(&config, &payload).unwrap(), json!({}));
    }
}
