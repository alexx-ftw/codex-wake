//! Operational metadata only: never persist user input or unfiltered errors.
use crate::telemetry::{self, Event};
use std::{
    path::PathBuf,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

static PATH: OnceLock<PathBuf> = OnceLock::new();
static PROCESS: OnceLock<String> = OnceLock::new();
static FAILURES: AtomicU64 = AtomicU64::new(0);
static CAPTURE_DROPPED: AtomicU64 = AtomicU64::new(0);
struct Captured {
    operation: &'static str,
    outcome: &'static str,
    reason: &'static str,
    subject: Option<String>,
    duration: Duration,
    count: u64,
}
static CAPTURE: OnceLock<std::sync::mpsc::SyncSender<Captured>> = OnceLock::new();

fn child_emit(
    operation: &'static str,
    outcome: &'static str,
    reason: &'static str,
    subject: Option<&str>,
    duration: Duration,
    count: u64,
) {
    let sender = CAPTURE.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Captured>(1024);
        std::thread::spawn(move || {
            for event in receiver {
                emit(
                    event.operation,
                    event.outcome,
                    event.reason,
                    event.subject.as_deref(),
                    event.duration,
                    event.count,
                );
                let dropped = CAPTURE_DROPPED.swap(0, Ordering::Relaxed);
                if dropped > 0 {
                    emit(
                        "child.logs",
                        "discarded",
                        "capture_queue_full",
                        None,
                        Duration::ZERO,
                        dropped,
                    );
                }
            }
        });
        sender
    });
    if sender
        .try_send(Captured {
            operation,
            outcome,
            reason,
            subject: subject.map(str::to_owned),
            duration,
            count,
        })
        .is_err()
    {
        CAPTURE_DROPPED.fetch_add(count.max(1), Ordering::Relaxed);
    }
}
tokio::task_local! { pub static TRACE: String; }
std::thread_local! { static SYNC_TRACE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) }; }

fn current_trace() -> Option<String> {
    SYNC_TRACE
        .with(|trace| trace.borrow().clone())
        .or_else(|| TRACE.try_with(Clone::clone).ok())
}

/// Dispatch is synchronous; keep its nested RPCs correlated without crossing awaits.
pub struct TraceGuard {
    previous: Option<String>,
    _local: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl TraceGuard {
    pub fn new() -> Self {
        let previous =
            SYNC_TRACE.with(|trace| trace.replace(Some(uuid::Uuid::new_v4().to_string())));
        Self {
            previous,
            _local: std::marker::PhantomData,
        }
    }
}
impl Drop for TraceGuard {
    fn drop(&mut self) {
        SYNC_TRACE.with(|trace| {
            trace.replace(self.previous.take());
        });
    }
}

pub fn configure(path: PathBuf) {
    if path.parent().is_some_and(std::path::Path::is_dir) {
        let _ = telemetry::initialize(&path);
    }
    let _ = PATH.set(path);
}

pub fn failures() -> u64 {
    FAILURES.load(Ordering::Relaxed)
}

pub fn emit(
    operation: &'static str,
    outcome: &'static str,
    reason: &str,
    subject: Option<&str>,
    duration: Duration,
    count: u64,
) {
    let trace = current_trace().unwrap_or_else(|| {
        PROCESS
            .get_or_init(|| uuid::Uuid::new_v4().to_string())
            .clone()
    });
    write(&trace, operation, outcome, reason, subject, duration, count);
}

fn write(
    trace: &str,
    operation: &str,
    outcome: &str,
    reason: &str,
    subject: Option<&str>,
    duration: Duration,
    count: u64,
) {
    let Some(path) = PATH.get() else {
        return;
    };
    // Startup may precede state creation; cleanup must never resurrect that directory.
    if !path.parent().is_some_and(std::path::Path::is_dir) {
        return;
    }
    let subject = subject.map(telemetry::subject);
    if let Err(error) = telemetry::record(
        path,
        &Event {
            trace,
            parent: None,
            operation,
            outcome,
            reason,
            subject: subject.as_deref(),
            duration_ms: duration.as_millis().min(u64::MAX as u128) as u64,
            count,
        },
    ) {
        let failures = FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
        if failures.is_power_of_two() {
            eprintln!(
                "{}",
                serde_json::json!({"component":"codex-wake","event":"telemetry_write_failed","operation":operation,"error_class":error_class(&error),"failures_this_process":failures})
            );
        }
    }
}

pub struct Span {
    operation: &'static str,
    trace: String,
    subject: Option<String>,
    started: Instant,
}

impl Span {
    pub fn new(operation: &'static str, subject: Option<&str>) -> Self {
        let trace = current_trace().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        write(&trace, operation, "started", "", subject, Duration::ZERO, 0);
        Self {
            operation,
            trace,
            subject: subject.map(str::to_owned),
            started: Instant::now(),
        }
    }
    pub fn finish(self, outcome: &'static str, reason: &str, count: u64) {
        write(
            &self.trace,
            self.operation,
            outcome,
            reason,
            self.subject.as_deref(),
            self.started.elapsed(),
            count,
        );
    }
    pub fn result<T>(self, result: &anyhow::Result<T>) {
        match result {
            Ok(_) => self.finish("ok", "", 1),
            Err(error) => self.finish("error", error_class(error), 1),
        }
    }
}

pub fn error_class(error: &anyhow::Error) -> &'static str {
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        return match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "timeout",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe => "connection_failed",
            _ => "io_error",
        };
    }
    if error.downcast_ref::<serde_json::Error>().is_some() {
        return "invalid_json";
    }
    if let Some(error) = error.downcast_ref::<rusqlite::Error>() {
        return match error {
            rusqlite::Error::SqliteFailure(code, _) => match code.code {
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                    "database_busy"
                }
                rusqlite::ErrorCode::DiskFull => "disk_full",
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase => {
                    "database_corrupt"
                }
                rusqlite::ErrorCode::ReadOnly | rusqlite::ErrorCode::PermissionDenied => {
                    "permission_denied"
                }
                _ => "database_error",
            },
            _ => "database_error",
        };
    }
    if error.downcast_ref::<uuid::Error>().is_some() {
        return "invalid_identifier";
    }
    let text = format!("{error:#}").to_ascii_lowercase();
    if text.contains("timed out") || text.contains("timeout") {
        "timeout"
    } else if text.contains("rpc failed") {
        "rpc_rejected"
    } else if text.contains("socket missing") || text.contains("socket is unavailable") {
        "controller_unavailable"
    } else if text.contains("template") || text.contains("placeholder") {
        "template_error"
    } else if text.contains("model") || text.contains("effort") {
        "execution_options_error"
    } else if text.contains("websocket") {
        "transport_error"
    } else {
        "operation_failed"
    }
}

pub fn reason(value: Option<&str>) -> &'static str {
    let Some(value) = value else {
        return "";
    };
    let prefix = value.split(':').next().unwrap_or("");
    match prefix {
        "template_error" => "template_error",
        "execution_options_error" => "execution_options_error",
        "send_outcome_unknown" => "send_outcome_unknown",
        "invalid_send_classification" => "invalid_send_classification",
        "invalid_configuration" => "invalid_configuration",
        "goal_template_failed" => "goal_template_failed",
        "prompt_template_failed" => "prompt_template_failed",
        "execution_validation_failed" => "execution_validation_failed",
        "project_resolution_failed" => "project_resolution_failed",
        "thread_creation_outcome_unknown" => "thread_creation_outcome_unknown",
        "goal_or_delivery_outcome_unknown" => "goal_or_delivery_outcome_unknown",
        "delivery_not_queued" => "delivery_not_queued",
        "turn_start_accepted" => "turn_start_accepted",
        "native_queue_accepted" => "native_queue_accepted",
        "native_queue_error" => "native_queue_error",
        "execution_api_error" => "execution_api_error",
        "executable_not_found" => "executable_not_found",
        "os_error_delivery_unknown" => "os_error_delivery_unknown",
        "resume_owned_by_active_writer" => "resume_owned_by_active_writer",
        "resume_daemon_unavailable" => "resume_daemon_unavailable",
        "cli_warning_after_queue_ack" => "cli_warning_after_queue_ack",
        "target_busy_before_send" => "target_busy_before_send",
        "cli_warning_or_nonzero_exit" => "cli_warning_or_nonzero_exit",
        "timeout_delivery_unknown" => "timeout_delivery_unknown",
        "send_failed_delivery_unknown" => "send_failed_delivery_unknown",
        "send_timed_out_delivery_unknown" => "send_timed_out_delivery_unknown",
        _ => "other_reason",
    }
}

/// Discard child output after extracting allowlisted metadata; never forward raw lines.
pub fn capture(reader: impl std::io::Read + Send + 'static, component: &'static str) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(reader);
        let mut line = Vec::new();
        let mut oversized = false;
        loop {
            let buffer = match reader.fill_buf() {
                Ok(b) => b,
                Err(_) => {
                    child_emit(
                        "child.log_reader",
                        "error",
                        "io_error",
                        None,
                        Duration::ZERO,
                        1,
                    );
                    return;
                }
            };
            if buffer.is_empty() {
                break;
            }
            let n = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buffer.len(), |i| i + 1);
            let complete = buffer[n - 1] == b'\n';
            if line.len() + n <= 8192 && !oversized {
                line.extend_from_slice(&buffer[..n]);
            } else {
                oversized = true;
            }
            reader.consume(n);
            if complete {
                if oversized {
                    child_emit(
                        "child.log_reader",
                        "discarded",
                        "oversized_line",
                        None,
                        Duration::ZERO,
                        1,
                    );
                } else {
                    child_line(component, &String::from_utf8_lossy(&line));
                }
                line.clear();
                oversized = false;
            }
        }
        if !line.is_empty() && !oversized {
            child_line(component, &String::from_utf8_lossy(&line));
        }
        child_emit("child.log_reader", "closed", "", None, Duration::ZERO, 1);
    });
}

fn child_line(component: &str, line: &str) {
    if component == "webhook" {
        static HTTP: OnceLock<regex::Regex> = OnceLock::new();
        // adnanh/webhook 2.8.3 middleware format; URI/host are deliberately ignored.
        let re = HTTP.get_or_init(|| regex::Regex::new(r"^\[webhook\] [0-9/ :]{19} \[([a-zA-Z0-9-]{1,64})\] ([1-5][0-9]{2}) \| [^|\r\n]{1,32} \| ([^|\r\n]{1,40}) \| ").unwrap());
        if let Some(c) = re.captures(line) {
            let (outcome, reason) = match &c[2] {
                "200" | "202" | "204" => ("ok", "http_2xx"),
                "403" => ("rejected", "signature_or_trigger_mismatch"),
                "404" => ("rejected", "unknown_route"),
                "405" => ("rejected", "method_not_allowed"),
                code if code.starts_with('5') => ("error", "http_5xx"),
                _ => ("rejected", "http_other"),
            };
            child_emit(
                "webhook.http",
                outcome,
                reason,
                Some(&c[1]),
                go_duration(c[3].trim()).unwrap_or_default(),
                1,
            );
        } else {
            let reason = if line.contains("couldn't load hooks")
                || line.contains("couldn't load any hooks")
            {
                Some("invalid_hook_configuration")
            } else if line.contains("listen tcp") || line.contains("address already in use") {
                Some("listener_failed")
            } else if line.contains("error occurred:") || line.contains("error extracting command")
            {
                Some("handler_failed")
            } else {
                None
            };
            if let Some(reason) = reason {
                child_emit("webhook.log", "error", reason, None, Duration::ZERO, 1);
            }
        }
    } else if line.contains("ERROR") || line.contains("WARN") {
        let reason = if line.contains("Responses WebSocket") {
            "responses_websocket"
        } else if line.contains("timed out") {
            "timeout"
        } else {
            "controller_warning"
        };
        child_emit(
            "controller.log",
            if line.contains("ERROR") {
                "error"
            } else {
                "warning"
            },
            reason,
            None,
            Duration::ZERO,
            1,
        );
    }
}

fn go_duration(value: &str) -> Option<Duration> {
    static PART: OnceLock<regex::Regex> = OnceLock::new();
    let re = PART
        .get_or_init(|| regex::Regex::new(r"([0-9]+(?:\.[0-9]+)?)(ns|µs|us|ms|s|m|h)").unwrap());
    let mut end = 0;
    let mut seconds = 0.0;
    for c in re.captures_iter(value) {
        let matched = c.get(0)?;
        if matched.start() != end {
            return None;
        }
        end = matched.end();
        let scale = match &c[2] {
            "ns" => 1e-9,
            "µs" | "us" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        seconds += c[1].parse::<f64>().ok()? * scale;
    }
    if end != value.len() || end == 0 {
        return None;
    }
    Duration::try_from_secs_f64(seconds).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn never_returns_untrusted_error_or_reason_text() {
        for value in ["resume_daemon_unavailable", "cli_warning_after_queue_ack"] {
            assert_eq!(reason(Some(value)), value);
        }
        let secret = "SECRET_PAYLOAD_TOKEN";
        assert_eq!(reason(Some(secret)), "other_reason");
        assert_eq!(
            reason(Some(&format!("template_error: {secret}"))),
            "template_error"
        );
        assert_eq!(
            error_class(&anyhow::anyhow!("{secret}")),
            "operation_failed"
        );
        assert_eq!(
            error_class(&std::io::Error::from(std::io::ErrorKind::TimedOut).into()),
            "timeout"
        );
    }
    #[test]
    fn parses_only_bounded_http_metadata_and_go_duration() {
        assert_eq!(go_duration("1m2.5s"), Some(Duration::from_millis(62500)));
        assert_eq!(go_duration("200ms PRIVATE"), None);
        assert_eq!(go_duration(""), None);
    }
}
