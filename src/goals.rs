use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

const TIMEOUT: Duration = Duration::from_secs(15);

fn thread_id(thread: &str) -> Result<String> {
    Ok(Uuid::parse_str(thread)
        .context("Invalid thread UUID")?
        .to_string())
}

fn matched_response(message: Value, id: &str) -> Result<Option<Value>> {
    if message.get("id") != Some(&json!(id)) {
        return Ok(None);
    }
    if let Some(error) = message.get("error") {
        bail!("Codex app-server RPC failed: {error}");
    }
    Ok(Some(
        message
            .get("result")
            .cloned()
            .context("App-server response has no result")?,
    ))
}

#[cfg(unix)]
pub(crate) fn socket_rpc(
    socket: &Path,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<Value> {
    use std::os::unix::net::UnixStream;
    use tungstenite::{Message, WebSocket};

    fn timeouts(ws: &mut WebSocket<UnixStream>, deadline: Instant) -> Result<()> {
        let left = deadline.saturating_duration_since(Instant::now());
        ensure!(!left.is_zero(), "Unix WebSocket RPC timed out");
        ws.get_mut().set_read_timeout(Some(left))?;
        ws.get_mut().set_write_timeout(Some(left))?;
        Ok(())
    }
    fn send(ws: &mut WebSocket<UnixStream>, deadline: Instant, message: Value) -> Result<()> {
        timeouts(ws, deadline)?;
        ws.send(Message::Text(message.to_string().into()))
            .context("Send Unix WebSocket RPC")
    }
    fn receive(ws: &mut WebSocket<UnixStream>, deadline: Instant, id: &str) -> Result<Value> {
        loop {
            timeouts(ws, deadline)?;
            match ws.read().context("Read Unix WebSocket RPC")? {
                Message::Text(text) => {
                    let message =
                        serde_json::from_str(&text).context("Invalid Unix WebSocket RPC JSON")?;
                    if let Some(result) = matched_response(message, id)? {
                        return Ok(result);
                    }
                }
                Message::Close(_) => bail!("Unix WebSocket closed before matched response"),
                Message::Binary(_) => bail!("Expected a Unix WebSocket text frame"),
                _ => {}
            }
        }
    }

    let deadline = Instant::now() + timeout;
    let stream = UnixStream::connect(socket).context(
        "Connect to app-server Unix socket: check the receiver service and CODEX_WAKE_RPC_SOCKET",
    )?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    // --listen unix:// uses HTTP Upgrade followed by WebSocket text frames.
    let (mut ws, _) = tungstenite::client("ws://localhost/", stream)
        .map_err(|_| anyhow!("App-server Unix WebSocket HTTP Upgrade failed"))?;
    let result = (|| {
        send(
            &mut ws,
            deadline,
            json!({"id":"codex-wake-initialize","method":"initialize",
            "params":{"clientInfo":{"name":"codex-wake","title":"Codex Wake","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":true}}}),
        )?;
        receive(&mut ws, deadline, "codex-wake-initialize")?;
        send(
            &mut ws,
            deadline,
            json!({"method":"initialized","params":{}}),
        )?;
        send(
            &mut ws,
            deadline,
            json!({"id":"codex-wake-request","method":method,"params":params}),
        )?;
        receive(&mut ws, deadline, "codex-wake-request")
    })();
    // Close only this client connection; the receiver owns the persistent server.
    if Instant::now() < deadline {
        let _ = ws.close(None);
    }
    result
}

fn rpc_socket(
    explicit: Option<std::ffi::OsString>,
    state_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<std::ffi::OsString> {
    explicit.or_else(|| {
        let state = state_home
            .map(PathBuf::from)
            .or_else(|| home.map(|home| PathBuf::from(home).join(".local/state")))?;
        let socket = state.join("codex-wake/app-server.sock");
        socket.exists().then(|| socket.into_os_string())
    })
}

/// Connect to CODEX_WAKE_RPC_SOCKET or the receiver's XDG state socket (HOME/.local/state by default).
/// The receiver owns the persistent server; this client never starts or stops a process.
/// The executable argument is retained for API compatibility and is unused.
pub fn rpc(_codex: &Path, method: &str, params: Value) -> Result<Value> {
    let socket = rpc_socket(
        std::env::var_os("CODEX_WAKE_RPC_SOCKET"),
        std::env::var_os("XDG_STATE_HOME"),
        std::env::var_os("HOME"),
    ).context("Codex Wake app-server socket missing: start the receiver service or set CODEX_WAKE_RPC_SOCKET to its Unix socket")?;
    ensure!(
        Path::new(&socket).exists(),
        "Codex Wake app-server socket missing: start the receiver service or correct CODEX_WAKE_RPC_SOCKET"
    );
    #[cfg(unix)]
    {
        socket_rpc(Path::new(&socket), method, params, TIMEOUT)
    }
    #[cfg(not(unix))]
    {
        bail!("Codex Wake app-server requires Unix sockets")
    }
}

fn get_with(thread: &str, call: &mut impl FnMut(&str, Value) -> Result<Value>) -> Result<Value> {
    let thread = thread_id(thread)?;
    let response = call("thread/goal/get", json!({"threadId":thread}))?;
    Ok(response.get("goal").cloned().unwrap_or(Value::Null))
}

fn set_with(
    thread: &str,
    params: Value,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<Value> {
    let thread = thread_id(thread)?;
    let mut params = params;
    params["threadId"] = json!(thread);
    params["origin"] = json!("automatic");
    call("thread/goal/set", params)?;
    let goal = get_with(&thread, call)?;
    ensure!(
        goal.is_object(),
        "Server did not confirm a goal after mutation"
    );
    Ok(goal)
}

fn create_with(
    thread: &str,
    objective: &str,
    token_budget: Option<i64>,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<Value> {
    validate_objective(objective)?;
    validate_budget(token_budget)?;
    ensure!(
        get_with(thread, call)?.is_null(),
        "Thread already has a goal"
    );
    let mut params = json!({"objective":objective});
    if let Some(budget) = token_budget {
        params["tokenBudget"] = json!(budget);
    }
    set_with(thread, params, call)
}

fn edit_with(
    thread: &str,
    objective: Option<&str>,
    token_budget: Option<i64>,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<Value> {
    ensure!(
        objective.is_some() || token_budget.is_some(),
        "Provide an objective or token budget to edit"
    );
    if let Some(objective) = objective {
        validate_objective(objective)?;
    }
    validate_budget(token_budget)?;
    ensure!(
        !get_with(thread, call)?.is_null(),
        "Thread has no goal to edit"
    );
    let mut params = json!({});
    if let Some(objective) = objective {
        params["objective"] = json!(objective);
    }
    if let Some(budget) = token_budget {
        params["tokenBudget"] = json!(budget);
    }
    set_with(thread, params, call)
}

fn resume_with(thread: &str, call: &mut impl FnMut(&str, Value) -> Result<Value>) -> Result<Value> {
    ensure!(
        !get_with(thread, call)?.is_null(),
        "Thread has no goal to resume"
    );
    let goal = set_with(thread, json!({"status":"active"}), call)?;
    ensure!(
        goal["status"] == "active",
        "Server did not confirm an active goal after resume"
    );
    Ok(goal)
}

fn validate_objective(objective: &str) -> Result<()> {
    ensure!(!objective.is_empty(), "Goal objective must not be empty");
    ensure!(
        objective.chars().count() <= 4000,
        "Goal objective exceeds 4000 characters"
    );
    Ok(())
}

fn validate_budget(token_budget: Option<i64>) -> Result<()> {
    ensure!(
        token_budget.is_none_or(|budget| budget > 0),
        "Token budget must be positive"
    );
    Ok(())
}

/// Read the goal stored by the Codex server for one thread.
pub fn get(codex: &Path, thread: &str) -> Result<Value> {
    get_with(thread, &mut |method, params| rpc(codex, method, params))
}

/// Create a goal only when the thread does not already have one.
pub fn create(
    codex: &Path,
    thread: &str,
    objective: &str,
    token_budget: Option<i64>,
) -> Result<Value> {
    create_with(thread, objective, token_budget, &mut |method, params| {
        rpc(codex, method, params)
    })
}

/// Change only the supplied fields; replacing the objective resets usage on the server.
pub fn edit(
    codex: &Path,
    thread: &str,
    objective: Option<&str>,
    token_budget: Option<i64>,
) -> Result<Value> {
    edit_with(thread, objective, token_budget, &mut |method, params| {
        rpc(codex, method, params)
    })
}

/// Activate an existing goal and return the goal confirmed by the Codex server.
pub fn resume(codex: &Path, thread: &str) -> Result<Value> {
    resume_with(thread, &mut |method, params| rpc(codex, method, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::{fs, thread};

    const THREAD: &str = "11111111-1111-4111-8111-111111111111";

    #[cfg(unix)]
    struct SocketDir(PathBuf);

    #[cfg(unix)]
    impl SocketDir {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let path = std::env::temp_dir().join(format!("codex-wake-test-{}", Uuid::new_v4()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }

    #[cfg(unix)]
    impl Drop for SocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn socket_selection_prefers_explicit_then_existing_xdg_then_home_default() {
        use std::os::unix::net::UnixListener;
        let fixture = SocketDir::new();
        let home = fixture.0.as_path();
        let xdg = home.join("state");
        let select = |explicit: Option<std::ffi::OsString>, state: Option<&Path>| {
            rpc_socket(
                explicit,
                state.map(|p| p.as_os_str().to_owned()),
                Some(home.as_os_str().to_owned()),
            )
        };
        assert_eq!(select(None, Some(&xdg)), None);
        let default_socket = home.join(".local/state/codex-wake/app-server.sock");
        fs::create_dir_all(default_socket.parent().unwrap()).unwrap();
        let _default_listener = UnixListener::bind(&default_socket).unwrap();
        assert_eq!(select(None, None), Some(default_socket.into_os_string()));
        assert_eq!(select(None, Some(&xdg)), None);
        let managed_socket = xdg.join("codex-wake/app-server.sock");
        fs::create_dir_all(managed_socket.parent().unwrap()).unwrap();
        let _managed_listener = UnixListener::bind(&managed_socket).unwrap();
        assert_eq!(
            select(None, Some(&xdg)),
            Some(managed_socket.into_os_string())
        );
        let explicit = home.join("explicit-missing.sock").into_os_string();
        assert_eq!(select(Some(explicit.clone()), Some(&xdg)), Some(explicit));
    }

    #[cfg(unix)]
    #[test]
    fn unix_websocket_upgrades_and_matches_responses_across_connections() {
        use std::os::unix::net::UnixListener;
        use tungstenite::Message;
        let fixture = SocketDir::new();
        let path = fixture.0.as_path().join("rpc.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            for failure in [false, true] {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut ws = tungstenite::accept(stream).unwrap();
                let init: Value =
                    serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
                assert_eq!(init["method"], "initialize");
                assert_eq!(init["params"]["capabilities"]["experimentalApi"], true);
                assert!(init.get("jsonrpc").is_none());
                for message in [
                    json!({"method":"notification","params":{}}),
                    json!({"id":"unrelated","result":"ignored"}),
                    json!({"id":init["id"],"result":{}}),
                ] {
                    ws.send(Message::Text(message.to_string().into())).unwrap();
                }
                let initialized: Value =
                    serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
                assert_eq!(initialized["method"], "initialized");
                assert!(initialized.get("id").is_none());
                let request: Value =
                    serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
                assert_eq!(request["method"], "thread/goal/get");
                assert_eq!(request["params"]["threadId"], THREAD);
                assert!(request.get("jsonrpc").is_none());
                ws.send(Message::Ping(vec![1, 2].into())).unwrap();
                let response = if failure {
                    json!({"id":request["id"],"error":{"code":-32000,"message":"server denied request"}})
                } else {
                    json!({"id":request["id"],"result":{"goal":null}})
                };
                ws.send(Message::Text(response.to_string().into())).unwrap();
                while !matches!(ws.read(), Ok(Message::Close(_)) | Err(_)) {}
                // A second connection must work after the first client closes.
            }
        });
        assert_eq!(
            socket_rpc(
                &path,
                "thread/goal/get",
                json!({"threadId":THREAD}),
                Duration::from_secs(2)
            )
            .unwrap(),
            json!({"goal":null})
        );
        let error = socket_rpc(
            &path,
            "thread/goal/get",
            json!({"threadId":THREAD}),
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("server denied request"),
            "{error:#}"
        );
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_websocket_bounds_wait_for_initialize_response() {
        use std::os::unix::net::UnixListener;
        let fixture = SocketDir::new();
        let path = fixture.0.as_path().join("rpc.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            ws.read().unwrap();
            thread::sleep(Duration::from_millis(250));
        });
        let started = Instant::now();
        assert!(socket_rpc(&path, "project/list", json!({}), Duration::from_millis(100)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_websocket_rejects_malformed_json_and_missing_result() {
        use std::os::unix::net::UnixListener;
        use tungstenite::Message;
        let fixture = SocketDir::new();
        let path = fixture.0.join("rpc.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            for reply in ["{", r#"{"id":"codex-wake-initialize"}"#] {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut ws = tungstenite::accept(stream).unwrap();
                ws.read().unwrap();
                ws.send(Message::Text(reply.into())).unwrap();
                while !matches!(ws.read(), Ok(Message::Close(_)) | Err(_)) {}
            }
        });
        for expected in [
            "Invalid Unix WebSocket RPC JSON",
            "App-server response has no result",
        ] {
            let error =
                socket_rpc(&path, "project/list", json!({}), Duration::from_secs(2)).unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }
        server.join().unwrap();
    }

    #[test]
    fn create_uses_automatic_origin_and_omits_unspecified_budget() {
        let mut calls = Vec::new();
        let mut call = |method: &str, params: Value| {
            calls.push((method.to_owned(), params));
            Ok(if calls.len() == 1 {
                json!({"goal":null})
            } else {
                json!({"goal":{"objective":"work"}})
            })
        };
        assert_eq!(
            create_with(THREAD, "work", None, &mut call).unwrap(),
            json!({"objective":"work"})
        );
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].0, "thread/goal/get");
        assert_eq!(calls[1].0, "thread/goal/set");
        assert_eq!(calls[1].1["origin"], "automatic");
        assert!(calls[1].1.get("tokenBudget").is_none());
    }

    #[test]
    fn create_refuses_existing_goal_and_edit_refuses_missing_goal() {
        let mut call = |_: &str, _: Value| Ok(json!({"goal":{"objective":"existing"}}));
        assert!(create_with(THREAD, "new", None, &mut call).is_err());
        let mut call = |_: &str, _: Value| Ok(json!({"goal":null}));
        assert!(edit_with(THREAD, Some("new"), None, &mut call).is_err());
    }

    #[test]
    fn resume_sets_only_active_and_returns_server_readback() {
        let goal = json!({"objective":"work","status":"active","tokensUsed":4,"tokenBudget":20});
        let mut calls = Vec::new();
        let mut call = |method: &str, params: Value| {
            calls.push((method.to_owned(), params.clone()));
            Ok(match method {
                "thread/goal/get" => json!({"goal":goal}),
                _ => json!({"goal":goal}),
            })
        };
        assert_eq!(resume_with(THREAD, &mut call).unwrap(), goal);
        let set = &calls[1].1;
        assert_eq!(set["status"], "active");
        assert_eq!(set["origin"], "automatic");
        assert!(set.get("objective").is_none());
        assert!(set.get("tokenBudget").is_none());
    }

    #[test]
    fn edit_budget_preserves_objective_and_status_and_returns_readback() {
        let goal = json!({"objective":"work","status":"paused","tokensUsed":4,"tokenBudget":30});
        let mut calls = Vec::new();
        let mut call = |method: &str, params: Value| {
            calls.push((method.to_owned(), params));
            Ok(if method == "thread/goal/set" {
                json!({"goal":{"stale":true}})
            } else {
                json!({"goal":goal})
            })
        };
        assert_eq!(edit_with(THREAD, None, Some(30), &mut call).unwrap(), goal);
        assert_eq!(
            calls[1].1,
            json!({"threadId":THREAD,"origin":"automatic","tokenBudget":30})
        );
        assert_eq!(calls[2].0, "thread/goal/get");
    }

    #[test]
    fn resume_refuses_unconfirmed_active_status() {
        for status in ["paused", "budgetLimited", "complete"] {
            let mut call = |_: &str, _: Value| Ok(json!({"goal":{"status":status}}));
            assert!(resume_with(THREAD, &mut call).is_err());
        }
        let mut count = 0;
        let mut call = |_: &str, _: Value| {
            count += 1;
            Ok(if count == 3 {
                json!({"goal":null})
            } else {
                json!({"goal":{"status":"active"}})
            })
        };
        assert!(resume_with(THREAD, &mut call).is_err());
    }
}
