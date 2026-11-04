use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

pub(crate) struct Client {
    child: Child,
    input: Option<ChildStdin>,
    replies: Receiver<Value>,
    next_id: i64,
}

impl Client {
    pub(crate) fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_codex-wake"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start MCP client");
        let stdout = child.stdout.take().expect("MCP stdout");
        let (sender, replies) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(value) = serde_json::from_str(&line) else {
                    break;
                };
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            input: child.stdin.take(),
            child,
            replies,
            next_id: 1,
        }
    }

    pub(crate) fn send(&mut self, value: Value) {
        writeln!(self.input.as_mut().expect("MCP stdin"), "{value}").expect("send MCP request");
    }

    pub(crate) fn response(&self, id: i64, timeout: Duration) -> Value {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!left.is_zero(), "MCP response timed out");
            let value = self
                .replies
                .recv_timeout(left)
                .expect("MCP response timed out");
            if value.get("id") == Some(&json!(id)) {
                return value;
            }
        }
    }

    pub(crate) fn initialize(&mut self) {
        self.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"codex-wake-test","version":"1"}}}));
        let reply = self.response(1, Duration::from_secs(15));
        assert!(reply.get("error").is_none(), "MCP initialize failed");
        assert!(
            reply["result"]["instructions"]
                .as_str()
                .is_none_or(str::is_empty),
            "MCP must expose its tools without injected usage instructions"
        );
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        self.next_id = 2;
    }

    pub(crate) fn call(&mut self, name: &str, arguments: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}}));
        let response = self.response(id, Duration::from_secs(15));
        assert!(response.get("error").is_none(), "MCP request failed");
        let result = &response["result"];
        assert_ne!(result["isError"], true, "MCP tool failed");
        result["structuredContent"].clone()
    }

    pub(crate) fn close(&mut self) {
        drop(self.input.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if self.child.try_wait().expect("wait MCP").is_some() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "MCP did not exit after stdin closed"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
