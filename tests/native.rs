//! Explicit end-to-end qualification against the active Codex Desktop service.
mod support;

use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
use support::Client;
use tungstenite::{Message, WebSocket, client};

type HmacSha256 = Hmac<Sha256>;
const TURN_MARKER: &str = "CODEX_WAKE_NATIVE_OK";

fn xdg(name: &str, default: PathBuf) -> PathBuf {
    env::var_os(name).map(PathBuf::from).unwrap_or(default)
}

fn state_dir() -> PathBuf {
    let home = PathBuf::from(env::var_os("HOME").expect("HOME is set"));
    xdg("XDG_STATE_HOME", home.join(".local/state")).join("codex-wake")
}

fn db_path() -> PathBuf {
    env::var_os("CODEX_WAKE_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir().join("state.sqlite3"))
}

fn webhook_secret() -> Vec<u8> {
    let home = PathBuf::from(env::var_os("HOME").expect("HOME is set"));
    let config = xdg("XDG_CONFIG_HOME", home.join(".config"));
    fs::read_to_string(config.join("codex-wake/webhook.secret"))
        .expect("read webhook secret")
        .trim()
        .as_bytes()
        .to_vec()
}

fn socket_path() -> PathBuf {
    env::var_os("CODEX_WAKE_RPC_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir().join("app-server.sock"))
}

fn signed_webhook(body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(&webhook_secret()).expect("valid HMAC key");
    mac.update(body);
    let signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256={signature}")
}

fn post_once(body: &[u8]) -> u16 {
    let mut stream = TcpStream::connect_timeout(
        &"127.0.0.1:9000".to_socket_addrs().unwrap().next().unwrap(),
        Duration::from_secs(5),
    )
    .expect("connect to local receiver");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(stream, "POST /hooks/codex-wake HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-GitHub-Event: issue_comment\r\nX-Hub-Signature-256: {}\r\n\r\n", body.len(), signed_webhook(body)).unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8_lossy(&response)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .expect("HTTP status from webhook receiver")
}

struct RuleCleanup {
    db: PathBuf,
    id: String,
}

impl Drop for RuleCleanup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl RuleCleanup {
    fn cleanup(&mut self) -> rusqlite::Result<()> {
        if self.id.is_empty() {
            return Ok(());
        }
        let mut db = rusqlite::Connection::open(&self.db)?;
        let tx = db.transaction()?;
        tx.execute("UPDATE rules SET enabled=0 WHERE id=?1", [&self.id])?;
        tx.execute("DELETE FROM rule_deliveries WHERE rule_id=?1", [&self.id])?;
        tx.execute("DELETE FROM rules WHERE id=?1", [&self.id])?;
        tx.commit()?;
        self.id.clear();
        Ok(())
    }
}

struct NativeRpc {
    socket: WebSocket<std::os::unix::net::UnixStream>,
    next_id: u64,
}

impl NativeRpc {
    fn connect() -> Self {
        use std::os::unix::net::UnixStream;
        let stream =
            UnixStream::connect(socket_path()).expect("connect to native app-server socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (mut socket, _) = client("ws://localhost/", stream).expect("WebSocket handshake");
        socket
            .send(Message::Text(json!({"id":"qualification-init","method":"initialize","params":{"clientInfo":{"name":"codex-wake-native-qualification","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":true}}}).to_string().into()))
            .unwrap();
        Self::receive(
            &mut socket,
            "qualification-init",
            Instant::now() + Duration::from_secs(15),
        );
        socket
            .send(Message::Text(
                json!({"method":"initialized","params":{}})
                    .to_string()
                    .into(),
            ))
            .unwrap();
        Self { socket, next_id: 1 }
    }

    fn receive(
        socket: &mut WebSocket<std::os::unix::net::UnixStream>,
        id: &str,
        deadline: Instant,
    ) -> Value {
        loop {
            assert!(Instant::now() < deadline, "native RPC timed out");
            match socket.read().expect("read native RPC") {
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(&text).expect("native RPC JSON");
                    if value.get("id") == Some(&json!(id)) {
                        assert!(value.get("error").is_none(), "native RPC returned an error");
                        return value["result"].clone();
                    }
                }
                Message::Close(_) => panic!("native RPC socket closed"),
                _ => {}
            }
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = format!("qualification-{}", self.next_id);
        self.next_id += 1;
        self.socket
            .send(Message::Text(
                json!({"id":id,"method":method,"params":params})
                    .to_string()
                    .into(),
            ))
            .expect("send native RPC");
        Self::receive(
            &mut self.socket,
            &id,
            Instant::now() + Duration::from_secs(15),
        )
    }

    fn turns(&mut self, thread: &str) -> Value {
        self.call(
            "thread/turns/list",
            json!({"threadId":thread,"limit":100,"sortDirection":"desc","itemsView":"full"}),
        )
    }
}

fn assistant_final_text(turn: &Value) -> Option<&str> {
    let messages = turn["items"].as_array()?;
    let final_answer = messages
        .iter()
        .filter(|item| item["type"] == "agentMessage")
        .find(|item| item["phase"] == "final_answer")
        .or_else(|| {
            messages
                .iter()
                .rev()
                .find(|item| item["type"] == "agentMessage")
        })?;
    final_answer["text"].as_str()
}

fn completed_text(page: &Value) -> bool {
    let turn = page["data"].as_array().and_then(|turns| turns.first());
    let Some(turn) = turn else { return false };
    turn["status"] == "completed" && assistant_final_text(turn) == Some(TURN_MARKER)
}

#[cfg(test)]
mod self_checks {
    use super::*;

    #[test]
    fn completion_requires_the_assistant_answer_not_the_prompt() {
        let prompt_only = json!({"data":[{"status":"completed","items":[
            {"type":"userMessage","content":[{"type":"text","text":TURN_MARKER}]}
        ]}]});
        let correct_answer = json!({"data":[{"status":"completed","items":[
            {"type":"userMessage","content":[{"type":"text","text":TURN_MARKER}]},
            {"type":"agentMessage","phase":"final_answer","text":TURN_MARKER}
        ]}]});

        assert!(!completed_text(&prompt_only));
        assert!(completed_text(&correct_answer));
    }
}

fn poll_turn(rpc: &mut NativeRpc, thread: &str) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let page = rpc.turns(thread);
        assert_ne!(page["data"][0]["status"], "failed", "native turn failed");
        if completed_text(&page) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "native turn did not complete within 90 seconds"
        );
        thread::sleep(Duration::from_secs(1));
    }
}

#[test]
#[ignore = "creates a dedicated test thread and one webhook turn; goal metadata may start a continuation"]
fn native_rule_turn_and_goal_metadata_qualification() {
    let mut mcp = Client::start();
    mcp.initialize();
    let status = mcp.call("get_status", json!({}));
    assert_eq!(
        status["receiver"]["local_ready"], true,
        "shared service is not ready"
    );

    let comment_id = (std::process::id() as u64) * 1_000_000 + 1;
    let comment_id_string = comment_id.to_string();
    let input = json!({
        "repo":"codex-wake-qualification/local", "pr":1,
        "author":"codex-wake-fixture[bot]", "author_type":"Bot",
        "contains":"native-test",
        "prompt":"Reply exactly CODEX_WAKE_NATIVE_OK. Do not call tools.",
        "model":"gpt-6.1-sol", "reasoning_effort":"low"
    });
    let configured = mcp.call("configure_rule", input);
    let rule_id = configured["rule_id"]
        .as_str()
        .expect("configured rule id")
        .to_owned();
    let mut _cleanup = RuleCleanup {
        db: db_path(),
        id: rule_id.clone(),
    };
    let payload = json!({"action":"created","repository":{"full_name":"codex-wake-qualification/local"},
        "issue":{"number":1,"pull_request":{}},"comment":{"id":comment_id,
        "user":{"login":"codex-wake-fixture[bot]","type":"Bot"},"body":"native-test"}});
    let body = serde_json::to_vec(&payload).unwrap();
    let results_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-results/native");
    fs::create_dir_all(&results_dir).unwrap();
    let report_dir = results_dir.join(uuid::Uuid::new_v4().to_string());
    let report_path = report_dir.join("result.json");
    // Persist the one-shot event intent so an interrupted accepted request cannot be blindly replayed.
    let pending_event = results_dir.join("pending-event.json");
    let mut pending = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending_event)
        .expect("a previous native event is unresolved; inspect its report before retrying");
    pending
        .write_all(
            json!({"state":"sending","rule_id":rule_id,"comment_id":comment_id_string,
                "report_path":report_path})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    pending.sync_all().unwrap();
    fs::create_dir_all(&report_dir).unwrap();
    fs::write(
        &report_path,
        json!({"outcome":"prepared","rule_id":rule_id,"comment_id":comment_id}).to_string(),
    )
    .unwrap();
    let status = post_once(&body);
    assert!(
        (200..300).contains(&status),
        "webhook returned HTTP {status}"
    );
    fs::write(
        &pending_event,
        json!({"state":"accepted","rule_id":rule_id,"comment_id":comment_id_string,
            "report_path":report_path})
        .to_string(),
    )
    .unwrap();
    fs::write(
        &report_path,
        json!({"outcome":"accepted_waiting_for_delivery","rule_id":rule_id,
            "comment_id":comment_id})
        .to_string(),
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(90);
    let thread_id = loop {
        let status = mcp.call("get_status", json!({}));
        let delivery = status["rules"]["deliveries"].as_array().and_then(|all| {
            all.iter().find(|d| {
                d["rule_id"] == rule_id && d["comment_id"].as_str() == Some(&comment_id_string)
            })
        });
        if let Some(delivery) = delivery {
            let state = delivery["state"].as_str().unwrap_or_default();
            if let Some(thread) = delivery["thread_id"].as_str() {
                fs::write(
                    &report_path,
                    json!({"outcome":if state == "needs_attention" { "needs_attention" }
                            else if state == "queued" { "queued" } else { "thread_created" },
                        "delivery_state":state,"reason":delivery["reason"],"thread_id":thread,
                        "rule_id":rule_id,"comment_id":comment_id})
                    .to_string(),
                )
                .unwrap();
                fs::write(
                    &pending_event,
                    json!({"state":"thread_captured","rule_id":rule_id,
                        "comment_id":comment_id_string,"thread_id":thread,"report_path":report_path})
                        .to_string(),
                )
                .unwrap();
                if state == "needs_attention" {
                    panic!(
                        "fixture delivery needs attention; see {}",
                        report_path.display()
                    );
                }
                if state == "queued" {
                    break thread.to_owned();
                }
            } else if state == "needs_attention" {
                fs::write(
                    &report_path,
                    json!({"outcome":"needs_attention_without_thread","rule_id":rule_id,
                        "comment_id":comment_id,"reason":delivery["reason"]})
                    .to_string(),
                )
                .unwrap();
                panic!(
                    "fixture delivery needs attention; see {}",
                    report_path.display()
                );
            }
        }
        if Instant::now() >= deadline {
            fs::write(
                &report_path,
                json!({"outcome":"delivery_timeout_no_retry","rule_id":rule_id,
                    "comment_id":comment_id})
                .to_string(),
            )
            .unwrap();
            panic!(
                "fixture delivery timed out; webhook will not be retried; see {}",
                report_path.display()
            );
        }
        thread::sleep(Duration::from_secs(1));
    };

    let mut rpc = NativeRpc::connect();
    poll_turn(&mut rpc, &thread_id);
    let first_turn_page = rpc.turns(&thread_id);
    let first_turn = &first_turn_page["data"][0];
    let final_text = assistant_final_text(first_turn).expect("assistant final text");
    assert_eq!(final_text, TURN_MARKER);
    let thread_read = rpc.call(
        "thread/read",
        json!({"threadId":thread_id,"includeTurns":false}),
    );
    assert_eq!(
        thread_read.pointer("/thread/model").and_then(Value::as_str),
        Some("gpt-6.1-sol")
    );
    assert_eq!(
        thread_read
            .pointer("/thread/reasoningEffort")
            .and_then(Value::as_str),
        Some("low")
    );
    let first_turn_evidence = json!({
        "assistant_final_text":final_text,
        "persisted_thread_model":thread_read["thread"]["model"],
        "persisted_thread_reasoning_effort":thread_read["thread"]["reasoningEffort"],
        "settings_evidence":"persisted thread settings"
    });
    fs::write(
        &report_path,
        json!({"outcome":"first_turn_verified","thread_id":thread_id,
            "rule_id":rule_id,"comment_id":comment_id,"first_turn":first_turn_evidence})
        .to_string(),
    )
    .unwrap();
    mcp.close();
    let mut mcp = Client::start();
    mcp.initialize();
    assert_eq!(
        mcp.call("get_status", json!({}))["receiver"]["local_ready"],
        true
    );

    let create_goal_args = json!({"thread":thread_id,
        "objective":"Verify goal create/edit/read metadata for this qualification thread",
        "execution":{"model":"gpt-6.1-sol","reasoning_effort":"low"}});
    assert!(create_goal_args.get("message_template").is_none());
    let created = mcp.call("create_goal", create_goal_args);
    assert_eq!(
        created["goal"]["objective"],
        "Verify goal create/edit/read metadata for this qualification thread"
    );
    let edit_goal_args = json!({"thread":thread_id,
        "objective":"Verified goal create/edit/read metadata for this qualification thread"});
    assert!(edit_goal_args.get("message_template").is_none());
    let edited = mcp.call("edit_goal", edit_goal_args);
    assert_eq!(
        edited["goal"]["objective"],
        "Verified goal create/edit/read metadata for this qualification thread"
    );
    let read = mcp.call("get_goal", json!({"thread":thread_id}));
    assert_eq!(
        read["objective"],
        "Verified goal create/edit/read metadata for this qualification thread"
    );
    let completed = rpc.call(
        "thread/goal/set",
        json!({"threadId":thread_id,"status":"complete","origin":"automatic"}),
    );
    assert!(completed["goal"].is_object() || completed.is_object());
    assert_eq!(
        rpc.call("thread/goal/get", json!({"threadId":thread_id}))["goal"]["status"],
        "complete"
    );

    let terminal_deadline = Instant::now() + Duration::from_secs(90);
    let mut previous_terminal_turns: Option<Value> = None;
    let mut stable_terminal_reads = 0;
    let terminal_page = loop {
        let page = rpc.turns(&thread_id);
        let turns = page["data"].as_array().expect("turn list data");
        let all_terminal = !turns.is_empty()
            && turns.iter().all(|turn| {
                matches!(
                    turn["status"].as_str(),
                    Some("completed" | "failed" | "interrupted")
                )
            });
        if all_terminal {
            if previous_terminal_turns.as_ref() == Some(&page["data"]) {
                stable_terminal_reads += 1;
            } else {
                stable_terminal_reads = 1;
            }
            if stable_terminal_reads >= 3 {
                break page;
            }
            previous_terminal_turns = Some(page["data"].clone());
        } else {
            stable_terminal_reads = 0;
            previous_terminal_turns = None;
        }
        if Instant::now() >= terminal_deadline {
            fs::write(
                &report_path,
                json!({"thread_id":thread_id,"rule_id":rule_id,"comment_id":comment_id,
                    "outcome":"goal_continuation_timeout","first_turn":first_turn_evidence,
                    "observed_turns":turns.len(),
                    "statuses":turns.iter().map(|turn|turn["status"].clone()).collect::<Vec<_>>(),
                    "goal":"complete","metadata_started_native_continuation":turns.len() > 1,
                    "native_continuation_count":turns.len().saturating_sub(1),
                    "explicit_message_template_supplied":false,"queue_thread_calls":0})
                .to_string(),
            )
            .unwrap();
            panic!("goal continuation did not reach a terminal state; fixture goal is complete");
        }
        thread::sleep(Duration::from_secs(1));
    };
    let turns = terminal_page["data"].as_array().unwrap();
    let turn_ids: Vec<_> = turns.iter().map(|turn| turn["id"].clone()).collect();
    assert!(
        turn_ids.contains(&first_turn["id"]),
        "initial verified turn is missing"
    );
    let metadata_evidence = json!({
        "total_turns":turns.len(),
        "turn_ids":turn_ids,
        "turn_statuses":turns.iter().map(|turn|turn["status"].clone()).collect::<Vec<_>>(),
        "metadata_started_native_continuation":turns.len() > 1,
        "native_continuation_count":turns.len().saturating_sub(1),
        "explicit_message_template_supplied":false,
        "queue_thread_calls":0,
        "create_goal_execution":{"model":"gpt-6.1-sol","reasoning_effort":"low",
            "prepare_and_readback_succeeded":true},
        "goal":"complete"
    });
    fs::write(
        &report_path,
        json!({"outcome":"complete","thread_id":thread_id,"rule_id":rule_id,
            "comment_id":comment_id,"first_turn":first_turn_evidence,
            "goal_metadata":metadata_evidence})
        .to_string(),
    )
    .unwrap();
    _cleanup
        .cleanup()
        .expect("remove only the qualification rule and deliveries");
    assert!(report_path.exists());
    drop(rpc);
    mcp.close();
    fs::remove_file(pending_event).expect("clear completed one-shot event guard");
}
