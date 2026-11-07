use anyhow::{Context, Result, ensure};
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    error::Error,
    fmt,
    path::Path,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) struct TargetBusyBeforeSend;

impl fmt::Display for TargetBusyBeforeSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Target thread has an active writer; input was not sent")
    }
}

impl Error for TargetBusyBeforeSend {}

pub(crate) fn is_target_busy(error: &anyhow::Error) -> bool {
    error.downcast_ref::<TargetBusyBeforeSend>().is_some()
}

#[derive(Debug)]
struct TargetUnavailableBeforeSend;

impl fmt::Display for TargetUnavailableBeforeSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Target unavailable during preparation; input was not sent")
    }
}

impl Error for TargetUnavailableBeforeSend {}

fn preparation_transport_error(error: &anyhow::Error) -> bool {
    let io = error.downcast_ref::<std::io::Error>().or_else(|| {
        match error.downcast_ref::<tungstenite::Error>() {
            Some(tungstenite::Error::Io(io)) => Some(io),
            _ => None,
        }
    });
    io.is_some_and(|io| {
        matches!(
            io.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::NotFound
        )
    }) || matches!(
        error.downcast_ref::<tungstenite::Error>(),
        Some(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed)
    )
}

pub(crate) fn before_send_retry_reason(error: &anyhow::Error) -> Option<&'static str> {
    if is_target_busy(error) {
        Some("target_busy_before_send")
    } else if error
        .downcast_ref::<TargetUnavailableBeforeSend>()
        .is_some()
    {
        Some("target_unavailable_before_send")
    } else {
        None
    }
}

fn is_active_writer_resume_error(error: &anyhow::Error, thread: &str) -> bool {
    let text = error.to_string();
    let Some(response) = text.strip_prefix("Codex app-server RPC failed: ") else {
        return false;
    };
    let Ok(response) = serde_json::from_str::<Value>(response) else {
        return false;
    };
    response["code"].as_i64() == Some(-32600)
        && response["message"].as_str()
            == Some(format!("thread {thread} already has an active writer").as_str())
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOptions {
    pub model: String,
    pub reasoning_effort: String,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            model: "gpt-6.1-sol".into(),
            reasoning_effort: "low".into(),
        }
    }
}

fn valid_option(value: &str, max: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate_with(
    options: &ExecutionOptions,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<String> {
    ensure!(valid_option(&options.model, 255), "Invalid model");
    ensure!(
        valid_option(&options.reasoning_effort, 100),
        "Invalid reasoning effort"
    );
    let mut cursor = None::<String>;
    let mut seen = HashSet::new();
    loop {
        let catalog = call("model/list", json!({"limit":100,"cursor":cursor}))?;
        for model in catalog["data"]
            .as_array()
            .context("Invalid model catalog")?
        {
            if model["model"].as_str() == Some(&options.model)
                || model["id"].as_str() == Some(&options.model)
            {
                ensure!(
                    model["supportedReasoningEfforts"]
                        .as_array()
                        .context("Missing supported reasoning efforts")?
                        .iter()
                        .any(|entry| {
                            entry["reasoningEffort"].as_str() == Some(&options.reasoning_effort)
                        }),
                    "Unsupported reasoning effort for model"
                );
                return model["model"]
                    .as_str()
                    .map(str::to_owned)
                    .context("Missing canonical model in catalog");
            }
        }
        let Some(next) = catalog["nextCursor"].as_str() else {
            anyhow::bail!("Configured model is unavailable");
        };
        ensure!(
            seen.insert(next.to_owned()),
            "Repeated model catalog cursor"
        );
        cursor = Some(next.to_owned());
    }
}

/// Confirm the selected model and effort against the owning Codex daemon's catalog.
pub fn validate(codex: &Path, options: &ExecutionOptions) -> Result<()> {
    validate_with(options, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
    .map(|_| ())
}

fn prepare_with(
    thread: &str,
    options: &ExecutionOptions,
    persist: bool,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<String> {
    let mut call = |method: &str, params: Value| {
        call(method, params).map_err(|error| {
            if preparation_transport_error(&error) {
                error.context(TargetUnavailableBeforeSend)
            } else {
                error
            }
        })
    };
    let thread = Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string();
    let model = validate_with(options, &mut call)?;
    let read = call(
        "thread/read",
        json!({"threadId":thread,"includeTurns":false}),
    )?;
    let status = read
        .pointer("/thread/status/type")
        .and_then(Value::as_str)
        .context("Thread read response has no status")?;
    if status == "active" {
        return Err(TargetBusyBeforeSend.into());
    }
    ensure!(
        matches!(status, "idle" | "notLoaded"),
        "Thread cannot apply execution options in status {status}"
    );
    // A newly started idle thread has no rollout to resume until its first turn.
    if status == "idle" && !persist {
        return Ok(thread);
    }
    if let Err(error) = call(
        "thread/resume",
        json!({
            "threadId":thread,
            "model":options.model,
            "config":{"model_reasoning_effort":options.reasoning_effort},
            "excludeTurns":true
        }),
    ) {
        return Err(if is_active_writer_resume_error(&error, &thread) {
            TargetBusyBeforeSend.into()
        } else {
            error
        });
    }
    let read = call(
        "thread/read",
        json!({"threadId":thread,"includeTurns":false}),
    )?;
    ensure!(
        read["thread"]["model"].as_str() == Some(model.as_str()),
        "Server did not confirm the configured model"
    );
    ensure!(
        read["thread"]["reasoningEffort"].as_str() == Some(options.reasoning_effort.as_str()),
        "Server did not confirm the configured reasoning effort"
    );
    Ok(thread)
}

/// Apply and confirm the preset before the caller mutates a goal or submits input.
/// This checks current state; preparation and subsequent actions are not atomic.
pub fn prepare(codex: &Path, thread: &str, options: &ExecutionOptions) -> Result<()> {
    prepare_with(thread, options, true, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
    .map(|_| ())
}

fn queue_prepared_with(
    thread: &str,
    message: &str,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<(String, Option<String>)> {
    let thread = Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string();
    Ok(
        match call(
            "thread/queue/add",
            json!({
                "threadId":thread,
                "clientUserMessageId":Uuid::new_v4().to_string(),
                "input":[{"type":"text","text":message,"text_elements":[]}]
            }),
        ) {
            Ok(_) => ("queued".into(), Some("native_queue_accepted".into())),
            Err(_) => ("needs_attention".into(), Some("native_queue_error".into())),
        },
    )
}

/// Queue input on the prepared controller thread; acceptance does not confirm execution.
pub fn queue_prepared(
    codex: &Path,
    thread: &str,
    message: &str,
) -> Result<(String, Option<String>)> {
    queue_prepared_with(thread, message, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
}

/// Submit a known event identity without changing the chat's execution settings.
pub fn queue_with_identity(
    codex: &Path,
    thread: &str,
    message: &str,
    client_id: &str,
    resume: bool,
    timeout: Duration,
) -> Result<(String, Option<String>)> {
    let started = Instant::now();
    let result =
        queue_with_identity_using(thread, message, client_id, resume, &mut |method, params| {
            let remaining = timeout.saturating_sub(started.elapsed());
            ensure!(!remaining.is_zero(), "Native queue timeout");
            crate::goals::rpc_with_timeout(codex, method, params, remaining)
        });
    if result.as_ref().err().is_some_and(|error| {
        error
            .downcast_ref::<crate::goals::BeforeConnect>()
            .is_some()
    }) {
        return crate::bridge::send_mode(
            codex,
            timeout.saturating_sub(started.elapsed()),
            thread,
            message,
            resume,
        );
    }
    result
}

fn queue_with_identity_using(
    thread: &str,
    message: &str,
    client_id: &str,
    resume: bool,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<(String, Option<String>)> {
    let thread = Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string();
    Uuid::parse_str(client_id).context("Invalid client message UUID")?;
    let response = call(
        "thread/queue/add",
        json!({"threadId":thread,"clientUserMessageId":client_id,"input":[{"type":"text","text":message,"text_elements":[]}]}),
    );
    if response.as_ref().err().is_some_and(|error| {
        error
            .downcast_ref::<crate::goals::BeforeConnect>()
            .is_some()
    }) {
        return Err(response.unwrap_err());
    }
    let accepted = response.is_ok_and(|response| {
        response
            .pointer("/queuedSubmission/id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
    });
    if !accepted {
        return Ok((
            "needs_attention".into(),
            Some("native_queue_outcome_unknown".into()),
        ));
    }
    if resume {
        let result = (|| -> Result<()> {
            let read = call(
                "thread/read",
                json!({"threadId":thread,"includeTurns":false}),
            )?;
            let status = read
                .pointer("/thread/status/type")
                .and_then(Value::as_str)
                .context("Missing thread status")?;
            if status == "notLoaded" {
                call(
                    "thread/resume",
                    json!({"threadId":thread,"excludeTurns":true}),
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            return Ok(("queued".into(), Some("native_queue_resume_warning".into())));
        }
    }
    Ok(("queued".into(), Some("native_queue_accepted".into())))
}

pub fn native_queue_available() -> bool {
    crate::goals::rpc_socket(
        std::env::var_os("CODEX_WAKE_RPC_SOCKET"),
        std::env::var_os("XDG_STATE_HOME"),
        std::env::var_os("HOME"),
    )
    .is_some_and(|socket| Path::new(&socket).exists())
}

fn deliver_with_id(
    thread: &str,
    message: &str,
    options: &ExecutionOptions,
    client_user_message_id: &str,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<(String, Option<String>)> {
    let thread = prepare_with(thread, options, false, call)?;
    let result = call(
        "turn/start",
        json!({
            "threadId":thread,
            "model":options.model,
            "effort":options.reasoning_effort,
            "input":[{"type":"text","text":message,"text_elements":[]}],
            "clientUserMessageId":client_user_message_id
        }),
    );
    match result {
        Ok(_) => Ok(("queued".into(), Some("turn_start_accepted".into()))),
        Err(_) => Ok(("needs_attention".into(), Some("execution_api_error".into()))),
    }
}

fn deliver_with(
    thread: &str,
    message: &str,
    options: &ExecutionOptions,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<(String, Option<String>)> {
    deliver_with_id(thread, message, options, &Uuid::new_v4().to_string(), call)
}

/// Deliver a message, applying explicit execution options to the resumed thread and turn.
/// Without options, preserve the existing CLI delivery behavior and resume choice.
pub fn deliver(
    codex: &Path,
    timeout: Duration,
    thread: &str,
    message: &str,
    resume: bool,
    options: Option<&ExecutionOptions>,
) -> Result<(String, Option<String>)> {
    let Some(options) = options else {
        return crate::bridge::send_mode(codex, timeout, thread, message, resume);
    };
    ensure!(
        resume,
        "Configured model and reasoning effort require resume=true; queued messages use the thread's model"
    );
    deliver_with(thread, message, options, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
}

/// Native delivery variant that retains notifications observed before the
/// matching turn/start response. It does not infer missing notifications.
pub fn deliver_with_identity_observed(
    codex: &Path,
    thread: &str,
    message: &str,
    options: &ExecutionOptions,
    client_user_message_id: &str,
) -> Result<(String, Option<String>, Vec<Value>)> {
    let thread = prepare_with(thread, options, false, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })?;
    match crate::goals::rpc_with_notifications(
        codex,
        "turn/start",
        json!({
            "threadId":thread,
            "model":options.model,
            "effort":options.reasoning_effort,
            "input":[{"type":"text","text":message,"text_elements":[]}],
            "clientUserMessageId":client_user_message_id
        }),
    ) {
        Ok((_, notifications)) => Ok((
            "queued".into(),
            Some("turn_start_accepted".into()),
            notifications,
        )),
        Err(_) => Ok((
            "needs_attention".into(),
            Some("execution_api_error".into()),
            Vec::new(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREAD: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn identified_queue_preserves_resume_order_and_never_retries_unknown_send() {
        let client_id = "22222222-2222-4222-8222-222222222222";
        for (resume, status, methods) in [
            (false, "idle", vec!["thread/queue/add"]),
            (true, "active", vec!["thread/queue/add", "thread/read"]),
            (true, "idle", vec!["thread/queue/add", "thread/read"]),
            (
                true,
                "notLoaded",
                vec!["thread/queue/add", "thread/read", "thread/resume"],
            ),
        ] {
            let mut calls = Vec::new();
            let result = queue_with_identity_using(
                THREAD,
                "message",
                client_id,
                resume,
                &mut |method, params| {
                    calls.push(method.to_owned());
                    assert!(params.get("model").is_none());
                    assert!(params.get("effort").is_none());
                    if method == "thread/queue/add" {
                        assert_eq!(params["clientUserMessageId"], client_id);
                    }
                    Ok(if method == "thread/read" {
                        json!({"thread":{"status":{"type":status}}})
                    } else if method == "thread/queue/add" {
                        json!({"queuedSubmission":{"id":"submission"}})
                    } else {
                        json!({})
                    })
                },
            )
            .unwrap();
            assert_eq!(calls, methods);
            assert_eq!(result.0, "queued");
        }
        let mut calls = 0;
        let result = queue_with_identity_using(THREAD, "message", client_id, true, &mut |_, _| {
            calls += 1;
            anyhow::bail!("response lost")
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(result.0, "needs_attention");
        let before_send =
            queue_with_identity_using(THREAD, "message", client_id, true, &mut |_, _| {
                Err(crate::goals::BeforeConnect(std::io::Error::from(
                    std::io::ErrorKind::ConnectionRefused,
                ))
                .into())
            })
            .unwrap_err();
        assert!(
            before_send
                .downcast_ref::<crate::goals::BeforeConnect>()
                .is_some()
        );
        let malformed =
            queue_with_identity_using(THREAD, "message", client_id, true, &mut |_, _| {
                Ok(json!({}))
            })
            .unwrap();
        assert_eq!(malformed.0, "needs_attention");
        let mut calls = 0;
        let result = queue_with_identity_using(THREAD, "message", client_id, true, &mut |_, _| {
            calls += 1;
            if calls == 1 {
                Ok(json!({"queuedSubmission":{"id":"submission"}}))
            } else {
                anyhow::bail!("read failed")
            }
        })
        .unwrap();
        assert_eq!(
            result,
            ("queued".into(), Some("native_queue_resume_warning".into()))
        );
        assert_eq!(calls, 2);
    }

    fn catalog_page(model: &str, id: &str, effort: &str, cursor: Option<&str>) -> Value {
        json!({
            "data":[{"model":model,"id":id,"supportedReasoningEfforts":[{"reasoningEffort":effort}]}],
            "nextCursor":cursor
        })
    }

    #[test]
    fn validates_across_catalog_pages_and_matches_model_id() {
        let options = ExecutionOptions {
            model: "model-id".into(),
            reasoning_effort: "high".into(),
        };
        let mut pages = 0;
        validate_with(&options, &mut |method, params| {
            assert_eq!(method, "model/list");
            assert_eq!(params["limit"], 100);
            pages += 1;
            Ok(if pages == 1 {
                catalog_page("other", "other-id", "low", Some("next"))
            } else {
                assert_eq!(params["cursor"], "next");
                catalog_page("canonical-model", "model-id", "high", None)
            })
        })
        .unwrap();
        assert_eq!(pages, 2);
    }

    #[test]
    fn rejects_an_effort_not_advertised_by_the_model() {
        let options = ExecutionOptions {
            model: "gpt-custom".into(),
            reasoning_effort: "xhigh".into(),
        };
        let error = validate_with(&options, &mut |_, _| {
            Ok(catalog_page("gpt-custom", "custom", "high", None))
        })
        .unwrap_err();
        assert!(error.to_string().contains("Unsupported reasoning effort"));
    }

    #[test]
    fn new_idle_thread_starts_without_resuming_a_nonexistent_rollout() {
        let mut methods = Vec::new();
        let result = deliver_with(
            THREAD,
            "first input",
            &ExecutionOptions::default(),
            &mut |method, _| {
                methods.push(method.to_owned());
                Ok(match method {
                    "model/list" => catalog_page("gpt-6.1-sol", "sol", "low", None),
                    "thread/read" => json!({"thread":{"status":{"type":"idle"}}}),
                    "turn/start" => json!({"turn":{}}),
                    _ => panic!("new thread must not resume: {method}"),
                })
            },
        )
        .unwrap();
        assert_eq!(result.0, "queued");
        assert_eq!(methods, ["model/list", "thread/read", "turn/start"]);
    }

    #[test]
    fn configured_delivery_resumes_then_starts_with_exact_options() {
        let options = ExecutionOptions {
            model: "gpt-custom".into(),
            reasoning_effort: "xhigh".into(),
        };
        let mut methods = Vec::new();
        let mut reads = 0;
        let result = deliver_with(THREAD, "run this", &options, &mut |method, params| {
            methods.push(method.to_owned());
            Ok(match method {
                "model/list" => catalog_page("gpt-custom", "custom", "xhigh", None),
                "thread/read" => {
                    reads += 1;
                    if reads == 1 {
                        json!({"thread":{"status":{"type":"notLoaded"}}})
                    } else {
                        json!({"thread":{"model":"gpt-custom","reasoningEffort":"xhigh"}})
                    }
                }
                "thread/resume" => {
                    assert_eq!(params["threadId"], THREAD);
                    assert_eq!(params["model"], "gpt-custom");
                    assert_eq!(params["config"]["model_reasoning_effort"], "xhigh");
                    json!({})
                }
                "turn/start" => {
                    assert_eq!(params["threadId"], THREAD);
                    assert_eq!(params["model"], "gpt-custom");
                    assert_eq!(params["effort"], "xhigh");
                    assert_eq!(params["input"][0]["text"], "run this");
                    assert_eq!(params["input"][0]["text_elements"], json!([]));
                    assert!(
                        Uuid::parse_str(params["clientUserMessageId"].as_str().unwrap()).is_ok()
                    );
                    json!({"turn":{}})
                }
                _ => panic!("unexpected RPC method {method}"),
            })
        })
        .unwrap();
        assert_eq!(
            methods,
            [
                "model/list",
                "thread/read",
                "thread/resume",
                "thread/read",
                "turn/start"
            ]
        );
        assert_eq!(
            result,
            ("queued".into(), Some("turn_start_accepted".into()))
        );
    }

    #[test]
    fn active_thread_is_rejected_without_resume_or_turn_start() {
        let options = ExecutionOptions::default();
        let mut methods = Vec::new();
        let error = deliver_with(THREAD, "run", &options, &mut |method, _| {
            methods.push(method.to_owned());
            Ok(match method {
                "model/list" => catalog_page("gpt-6.1-sol", "sol", "low", None),
                "thread/read" => json!({"thread":{"status":{"type":"active"}}}),
                _ => panic!("active thread must not be changed"),
            })
        })
        .unwrap_err();
        assert!(is_target_busy(&error));
        assert_eq!(methods, ["model/list", "thread/read"]);
    }

    #[test]
    fn exact_resume_active_writer_rejection_is_typed_before_turn_start() {
        let options = ExecutionOptions::default();
        let mut methods = Vec::new();
        let error = deliver_with(THREAD, "run", &options, &mut |method, _| {
            methods.push(method.to_owned());
            match method {
                "model/list" => Ok(catalog_page("gpt-6.1-sol", "sol", "low", None)),
                "thread/read" => Ok(json!({"thread":{"status":{"type":"notLoaded"}}})),
                "thread/resume" => Err(anyhow::anyhow!(
                    "Codex app-server RPC failed: {}",
                    json!({
                        "code":-32600,
                        "message":format!("thread {THREAD} already has an active writer")
                    })
                )),
                _ => panic!("busy rejection must stop before {method}"),
            }
        })
        .unwrap_err();
        assert!(is_target_busy(&error));
        assert_eq!(methods, ["model/list", "thread/read", "thread/resume"]);
    }

    #[test]
    fn unrelated_resume_errors_are_not_typed_as_target_busy() {
        let other_thread = "22222222-2222-4222-8222-222222222222";
        let cases = [
            (
                format!(
                    "Codex app-server RPC failed: {}",
                    json!({"code":-32600,"message":format!("thread {other_thread} already has an active writer")})
                ),
                false,
            ),
            (
                format!(
                    "Codex app-server RPC failed: {}",
                    json!({"code":-32000,"message":format!("thread {THREAD} already has an active writer")})
                ),
                false,
            ),
            ("transport reset".to_owned(), false),
        ];
        for (rpc_error, expected_busy) in cases {
            let options = ExecutionOptions::default();
            let mut methods = Vec::new();
            let error = deliver_with(THREAD, "run", &options, &mut |method, _| {
                methods.push(method.to_owned());
                match method {
                    "model/list" => Ok(catalog_page("gpt-6.1-sol", "sol", "low", None)),
                    "thread/read" => Ok(json!({"thread":{"status":{"type":"notLoaded"}}})),
                    "thread/resume" => Err(anyhow::anyhow!("{rpc_error}")),
                    _ => panic!("resume error must stop before {method}"),
                }
            })
            .unwrap_err();
            assert_eq!(is_target_busy(&error), expected_busy);
            assert_eq!(methods, ["model/list", "thread/read", "thread/resume"]);
        }
    }

    #[test]
    fn ambiguous_turn_start_error_is_not_retried() {
        let options = ExecutionOptions::default();
        let mut starts = 0;
        let result = deliver_with(THREAD, "run", &options, &mut |method, _| match method {
            "model/list" => Ok(catalog_page("gpt-6.1-sol", "sol", "low", None)),
            "thread/read" => Ok(json!({"thread":{"status":{"type":"idle"},"model":"gpt-6.1-sol","reasoningEffort":"low"}})),
            "thread/resume" => Ok(json!({})),
            "turn/start" => {
                starts += 1;
                anyhow::bail!("transport lost after request")
            }
            _ => panic!("unexpected RPC method {method}"),
        })
        .unwrap();
        assert_eq!(starts, 1);
        assert_eq!(
            result,
            ("needs_attention".into(), Some("execution_api_error".into()))
        );
    }

    #[test]
    fn preparation_transport_errors_are_retryable_without_sending_input() {
        for kind in [
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::NotFound,
        ] {
            for failed_call in 0..4 {
                let mut calls = 0;
                let error = deliver_with(
                    THREAD,
                    "run",
                    &ExecutionOptions::default(),
                    &mut |method, _| {
                        let current = calls;
                        calls += 1;
                        if current == failed_call {
                            return Err(std::io::Error::from(kind).into());
                        }
                        Ok(match method {
                            "model/list" => catalog_page("gpt-6.1-sol", "sol", "low", None),
                            "thread/read" if current == 1 => {
                                json!({"thread":{"status":{"type":"notLoaded"}}})
                            }
                            "thread/resume" => json!({}),
                            "thread/read" => {
                                json!({"thread":{"model":"gpt-6.1-sol","reasoningEffort":"low"}})
                            }
                            _ => panic!("input must not be sent during preparation"),
                        })
                    },
                )
                .unwrap_err();
                assert_eq!(
                    before_send_retry_reason(&error),
                    Some("target_unavailable_before_send")
                );
                assert_eq!(calls, failed_call + 1);
            }
        }
        let error = deliver_with(THREAD, "run", &ExecutionOptions::default(), &mut |_, _| {
            Err(
                anyhow::Error::new(tungstenite::Error::Io(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                )))
                .context("Read Unix WebSocket RPC"),
            )
        })
        .unwrap_err();
        assert_eq!(
            before_send_retry_reason(&error),
            Some("target_unavailable_before_send")
        );
    }

    #[test]
    fn retry_classification_excludes_rpc_rejections_validation_and_sent_input() {
        let busy: anyhow::Error = TargetBusyBeforeSend.into();
        assert_eq!(
            before_send_retry_reason(&busy),
            Some("target_busy_before_send")
        );
        for message in [
            "Codex app-server RPC failed: {\"message\":\"timeout\"}",
            "Invalid model catalog",
            "Expected a Unix WebSocket text frame",
            "App-server Unix WebSocket HTTP Upgrade failed",
        ] {
            let error = deliver_with(THREAD, "run", &ExecutionOptions::default(), &mut |_, _| {
                Err(anyhow::anyhow!("{message}"))
            })
            .unwrap_err();
            assert_eq!(before_send_retry_reason(&error), None);
        }
        let error = deliver_with(THREAD, "run", &ExecutionOptions::default(), &mut |_, _| {
            Err(anyhow::Error::new(tungstenite::Error::Http(Box::new(
                tungstenite::http::Response::builder()
                    .status(401)
                    .body(None)
                    .unwrap(),
            )))
            .context("App-server Unix WebSocket HTTP Upgrade failed"))
        })
        .unwrap_err();
        assert_eq!(before_send_retry_reason(&error), None);
        let error = deliver_with(THREAD, "run", &ExecutionOptions::default(), &mut |_, _| {
            Ok(json!({"data":[]}))
        })
        .unwrap_err();
        assert_eq!(before_send_retry_reason(&error), None);
        let result = deliver_with(
            THREAD,
            "run",
            &ExecutionOptions::default(),
            &mut |method, _| match method {
                "model/list" => Ok(catalog_page("gpt-6.1-sol", "sol", "low", None)),
                "thread/read" => Ok(json!({"thread":{"status":{"type":"idle"}}})),
                "turn/start" => Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into()),
                _ => panic!("unexpected RPC"),
            },
        )
        .unwrap();
        assert_eq!(
            result,
            ("needs_attention".into(), Some("execution_api_error".into()))
        );
    }

    #[test]
    fn preparation_always_resumes_idle_or_unloaded_then_confirms_canonical_preset() {
        for status in ["idle", "notLoaded"] {
            let options = ExecutionOptions {
                model: "custom-id".into(),
                reasoning_effort: "high".into(),
            };
            let mut methods = Vec::new();
            let mut reads = 0;
            prepare_with(THREAD, &options, true, &mut |method, params| {
                methods.push(method.to_owned());
                Ok(match method {
                    "model/list" => catalog_page("canonical-model", "custom-id", "high", None),
                    "thread/read" => {
                        assert_eq!(params, json!({"threadId":THREAD,"includeTurns":false}));
                        reads += 1;
                        if reads == 1 { json!({"thread":{"status":{"type":status}}}) }
                        else { json!({"thread":{"model":"canonical-model","reasoningEffort":"high"}}) }
                    }
                    "thread/resume" => {
                        assert_eq!(params, json!({"threadId":THREAD,"model":"custom-id","config":{"model_reasoning_effort":"high"},"excludeTurns":true}));
                        json!({})
                    }
                    _ => panic!("preparation must not mutate goals or submit input: {method}"),
                })
            }).unwrap();
            assert_eq!(
                methods,
                ["model/list", "thread/read", "thread/resume", "thread/read"]
            );
        }
    }

    #[test]
    fn preparation_rejects_active_or_unsupported_status_without_resume() {
        for status in ["active", "systemError", "unknown"] {
            let mut methods = Vec::new();
            assert!(
                prepare_with(
                    THREAD,
                    &ExecutionOptions::default(),
                    true,
                    &mut |method, _| {
                        methods.push(method.to_owned());
                        Ok(match method {
                            "model/list" => catalog_page("gpt-6.1-sol", "sol", "low", None),
                            "thread/read" => json!({"thread":{"status":{"type":status}}}),
                            _ => panic!("rejected thread must not be changed"),
                        })
                    }
                )
                .is_err()
            );
            assert_eq!(methods, ["model/list", "thread/read"]);
        }
    }

    #[test]
    fn preparation_requires_confirmed_model_and_effort() {
        for confirmed in [
            json!({}),
            json!({"model":"wrong","reasoningEffort":"low"}),
            json!({"model":"gpt-6.1-sol","reasoningEffort":null}),
            json!({"model":"gpt-6.1-sol","reasoningEffort":"high"}),
        ] {
            let mut reads = 0;
            assert!(
                prepare_with(
                    THREAD,
                    &ExecutionOptions::default(),
                    true,
                    &mut |method, _| {
                        Ok(match method {
                            "model/list" => catalog_page("gpt-6.1-sol", "sol", "low", None),
                            "thread/read" => {
                                reads += 1;
                                if reads == 1 {
                                    json!({"thread":{"status":{"type":"idle"}}})
                                } else {
                                    json!({"thread":confirmed})
                                }
                            }
                            "thread/resume" => json!({}),
                            _ => panic!("unexpected mutation"),
                        })
                    }
                )
                .is_err()
            );
        }
    }

    #[test]
    fn prepared_queue_is_one_native_call_and_never_retries_ambiguous_errors() {
        for fail in [false, true] {
            let mut calls = 0;
            let result = queue_prepared_with(THREAD, "run this", &mut |method, params| {
                calls += 1;
                assert_eq!(method, "thread/queue/add");
                assert_eq!(params["threadId"], THREAD);
                assert_eq!(
                    params["input"],
                    json!([{"type":"text","text":"run this","text_elements":[]}])
                );
                assert!(Uuid::parse_str(params["clientUserMessageId"].as_str().unwrap()).is_ok());
                if fail {
                    anyhow::bail!("response lost after acceptance");
                }
                Ok(json!({"queuedSubmission":{}}))
            })
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(
                result,
                if fail {
                    ("needs_attention".into(), Some("native_queue_error".into()))
                } else {
                    ("queued".into(), Some("native_queue_accepted".into()))
                }
            );
        }
    }
}
