//! Explicit end-to-end qualification against the active Codex Desktop service.
mod support;

use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    panic::{AssertUnwindSafe, catch_unwind},
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

fn stable_qualification_message_id(event_id: &str, thread_id: &str) -> String {
    let identity = format!("codex-wake-qualification-v1:{event_id}:{thread_id}");
    let digest = Sha256::digest(identity.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn qualification_user_message(page: &Value, turn_id: &str, event_marker: &str) -> Option<Value> {
    let turn = page["data"]
        .as_array()?
        .iter()
        .find(|turn| turn["id"] == turn_id)?;
    turn["items"].as_array()?.iter().find_map(|item| {
        if item["type"] != "userMessage" {
            return None;
        }
        let contains_event = item["content"].as_array().is_some_and(|content| {
            content.iter().any(|entry| {
                entry["text"]
                    .as_str()
                    .is_some_and(|text| text.contains(event_marker))
            })
        });
        contains_event.then(|| item.clone())
    })
}

struct EphemeralThread {
    rpc: NativeRpc,
    id: Option<String>,
}

impl EphemeralThread {
    fn cleanup(&mut self) -> &'static str {
        let Some(id) = self.id.as_deref() else {
            return "not_created";
        };
        if catch_unwind(AssertUnwindSafe(|| {
            self.rpc.call("thread/delete", json!({"threadId":id}))
        }))
        .is_ok()
        {
            self.id = None;
            return "deleted";
        }
        if catch_unwind(AssertUnwindSafe(|| {
            self.rpc.call("thread/archive", json!({"threadId":id}))
        }))
        .is_ok()
        {
            self.id = None;
            return "archived";
        }
        "cleanup_failed"
    }
}

impl Drop for EphemeralThread {
    fn drop(&mut self) {
        if self.id.is_some() {
            let outcome = self.cleanup();
            if outcome == "cleanup_failed" {
                eprintln!("could not delete or archive ephemeral qualification thread");
            }
        }
    }
}

#[test]
#[ignore = "creates one ephemeral thread and sends one qualification input; run only on a ready Codex host"]
fn native_client_user_message_id_is_persisted_in_ephemeral_thread() {
    let rpc = NativeRpc::connect();
    let mut fixture = EphemeralThread { rpc, id: None };
    let cwd = tempfile::tempdir().expect("create isolated ephemeral thread cwd");
    let event_id = uuid::Uuid::new_v4().to_string();
    let event_marker = format!("codex-wake-qualification-event:{event_id}");
    let report_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-results/native-client-id");
    fs::create_dir_all(&report_dir).expect("create qualification report directory");
    let report_path = report_dir.join(format!("{event_id}.json"));
    let pending_path = report_dir.join("pending.json");
    let mut pending = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending_path)
        .expect("an earlier qualification is unresolved; inspect its report before another send");
    pending
        .write_all(
            json!({"state":"preparing","event_id":event_id})
                .to_string()
                .as_bytes(),
        )
        .expect("persist one-shot qualification guard");
    pending
        .sync_all()
        .expect("sync one-shot qualification guard");
    drop(pending);
    fs::write(
        &report_path,
        json!({"outcome":"prepared","event_id":event_id,"turn_start_calls":0}).to_string(),
    )
    .expect("persist qualification intent before creating the chat");
    let started = fixture.rpc.call(
        "thread/start",
        json!({
            "model":"gpt-6.1-terra",
            "config":{"model_reasoning_effort":"medium"},
            "cwd":cwd.path(),
            "ephemeral":true,
            "allowProviderModelFallback":false
        }),
    );
    let thread_id = started
        .pointer("/thread/id")
        .and_then(Value::as_str)
        .expect("thread/start returned a destination thread ID")
        .to_owned();
    uuid::Uuid::parse_str(&thread_id).expect("destination is a UUID");
    fixture.id = Some(thread_id.clone());
    fs::write(
        &report_path,
        json!({"outcome":"ephemeral_chat_created","event_id":event_id,
            "destination_thread_id":thread_id,"turn_start_calls":0})
        .to_string(),
    )
    .expect("persist exact destination identity");

    let destination = fixture.rpc.call(
        "thread/read",
        json!({"threadId":thread_id,"includeTurns":false}),
    );
    let readback_thread_id = destination.pointer("/thread/id").and_then(Value::as_str);
    if readback_thread_id != Some(thread_id.as_str()) {
        fs::write(
            &report_path,
            json!({"outcome":"destination_readback_mismatch_no_input_sent","event_id":event_id,
                "destination_thread_id":thread_id,"readback_thread_id":readback_thread_id,
                "turn_start_calls":0})
            .to_string(),
        )
        .expect("persist destination mismatch evidence");
        let cleanup = fixture.cleanup();
        assert_ne!(
            cleanup, "cleanup_failed",
            "mismatched ephemeral fixture could not be cleaned"
        );
        fs::remove_file(&pending_path).expect("clear guard after no-send cleanup");
        panic!("thread/read did not confirm the exact ephemeral destination; no input was sent");
    }
    let baseline = fixture.rpc.turns(&thread_id);
    let baseline_turn_count = baseline["data"].as_array().map_or(0, Vec::len);
    if baseline_turn_count != 0 {
        fs::write(
            &report_path,
            json!({"outcome":"fixture_not_empty_no_input_sent","event_id":event_id,
                "destination_thread_id":thread_id,"baseline_turn_count":baseline_turn_count,
                "turn_start_calls":0})
            .to_string(),
        )
        .expect("persist contaminated fixture evidence");
        let cleanup = fixture.cleanup();
        assert_ne!(
            cleanup, "cleanup_failed",
            "contaminated ephemeral fixture could not be cleaned"
        );
        fs::remove_file(&pending_path).expect("clear guard after no-send cleanup");
        panic!("ephemeral fixture chat was not empty; no input was sent");
    }

    let client_message_id = stable_qualification_message_id(&event_id, &thread_id);
    let input = format!("{event_marker}\nReply exactly CODEX_WAKE_CLIENT_ID_OK.");
    fs::write(
        &report_path,
        json!({"outcome":"turn_start_in_flight","event_id":event_id,
            "destination_thread_id":thread_id,"client_user_message_id":client_message_id,
            "event_marker":event_marker,"turn_start_calls":1})
        .to_string(),
    )
    .expect("persist single-send intent before turn/start");
    let mut pending = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&pending_path)
        .expect("reopen one-shot qualification guard");
    pending
        .write_all(
            json!({"state":"turn_start_in_flight","event_id":event_id,
                "destination_thread_id":thread_id,"client_user_message_id":client_message_id,
                "turn_start_calls":1})
            .to_string()
            .as_bytes(),
        )
        .expect("record single-send intent");
    pending
        .sync_all()
        .expect("sync single-send intent before turn/start");
    drop(pending);
    let accepted = fixture.rpc.call(
        "turn/start",
        json!({
            "threadId":thread_id,
            "model":"gpt-6.1-terra",
            "effort":"medium",
            "input":[{"type":"text","text":input,"text_elements":[]}],
            "clientUserMessageId":client_message_id
        }),
    );
    let accepted_turn_id = accepted
        .pointer("/turn/id")
        .and_then(Value::as_str)
        .expect("turn/start returned a turn ID")
        .to_owned();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut page = fixture.rpc.turns(&thread_id);
    let mut user_message = qualification_user_message(&page, &accepted_turn_id, &event_marker);
    while user_message.is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_secs(1));
        page = fixture.rpc.turns(&thread_id);
        user_message = qualification_user_message(&page, &accepted_turn_id, &event_marker);
    }
    let observed_message_id = user_message
        .as_ref()
        .and_then(|message| message["id"].as_str());
    let observed_client_id = user_message
        .as_ref()
        .and_then(|message| message["clientId"].as_str());
    let observed_turn_count = page["data"].as_array().map_or(0, Vec::len);
    let matching_count = page["data"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|turn| turn["items"].as_array().into_iter().flatten())
        .filter(|item| item["type"] == "userMessage" && item["clientId"] == client_message_id)
        .count();
    let event_message_count = page["data"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|turn| turn["items"].as_array().into_iter().flatten())
        .filter(|item| {
            item["type"] == "userMessage"
                && item["content"].as_array().is_some_and(|content| {
                    content.iter().any(|entry| {
                        entry["text"]
                            .as_str()
                            .is_some_and(|text| text.contains(&event_marker))
                    })
                })
        })
        .count();

    let cleanup = fixture.cleanup();
    fs::write(
        &report_path,
        json!({
            "outcome":if observed_client_id == Some(client_message_id.as_str()) && matching_count == 1 && event_message_count == 1 { "client_id_matched_persisted_user_message" } else { "client_id_mapping_not_confirmed" },
            "event_id":event_id,
            "destination_thread_id":thread_id,
            "accepted_turn_id":accepted_turn_id,
            "observed_turn_count":observed_turn_count,
            "user_message_id":observed_message_id,
            "persisted_user_message_content":user_message.as_ref().map(|message| &message["content"]),
            "client_user_message_id":client_message_id,
            "persisted_user_message_client_id":observed_client_id,
            "matching_message_count":matching_count,
            "event_marker_message_count":event_message_count,
            "event_marker":event_marker,
            "cleanup":cleanup
        })
        .to_string(),
    )
    .expect("persist event-chat-message evidence");
    assert_ne!(
        cleanup, "cleanup_failed",
        "ephemeral fixture could not be deleted or archived"
    );
    fs::remove_file(&pending_path).expect("clear completed one-shot qualification guard");
    assert_eq!(
        observed_client_id,
        Some(client_message_id.as_str()),
        "protocol did not persist the submitted client ID on the matching user message"
    );
    assert_eq!(
        observed_turn_count, 1,
        "fresh ephemeral chat must contain exactly the qualification turn"
    );
    assert_eq!(
        matching_count, 1,
        "the exact event-destination ID must identify one persisted user message"
    );
    assert_eq!(
        event_message_count, 1,
        "the event marker must identify exactly one persisted user message"
    );
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
