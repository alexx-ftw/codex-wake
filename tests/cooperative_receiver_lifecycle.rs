//! Opt-in local qualification; run only in private user, mount, PID and network namespaces.
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    env, fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket};
use wait_timeout::ChildExt;

#[derive(Default)]
struct Diagnostics {
    bytes: AtomicUsize,
    classes: AtomicUsize,
    finished: AtomicBool,
}

fn error_classes(bytes: &[u8]) -> usize {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    usize::from(lower.contains("permission denied"))
        | (usize::from(lower.contains("address already in use")) << 1)
        | (usize::from(lower.contains("no such file")) << 2)
        | (usize::from(lower.contains("panic")) << 3)
        | (usize::from(lower.contains("socket")) << 4)
        | (usize::from(lower.contains("authentication")) << 5)
}

fn diagnostic_summary(bytes: usize, classes: usize) -> String {
    let mut labels = Vec::new();
    for (bit, label) in [
        (0, "permission"),
        (1, "address_in_use"),
        (2, "missing_file"),
        (3, "panic"),
        (4, "socket"),
        (5, "authentication"),
    ] {
        if classes & (1 << bit) != 0 {
            labels.push(label);
        }
    }
    format!("stderr_bytes={bytes}, classes={}", labels.join(","))
}

struct OwnedChild(Child, Arc<Diagnostics>, &'static str);
impl OwnedChild {
    fn new(label: &'static str, mut child: Child) -> Self {
        let mut stderr = child.stderr.take().expect("stderr pipe");
        let diagnostics = Arc::new(Diagnostics::default());
        let captured = Arc::clone(&diagnostics);
        // Do not join this reader: a descendant might retain the pipe.
        thread::spawn(move || {
            let mut chunk = [0; 4096];
            let mut previous = Vec::new();
            loop {
                let size = match stderr.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(size) => size,
                };
                captured.bytes.fetch_add(size, Ordering::Relaxed);
                previous.extend_from_slice(&chunk[..size]);
                captured
                    .classes
                    .fetch_or(error_classes(&previous), Ordering::Relaxed);
                if previous.len() > 256 {
                    previous.drain(..previous.len() - 256);
                }
            }
            captured.finished.store(true, Ordering::Release);
        });
        Self(child, diagnostics, label)
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let status = self.0.try_wait().ok().flatten();
        if status.is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
        if thread::panicking() {
            let deadline = Instant::now() + Duration::from_millis(200);
            while !self.1.finished.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            eprintln!(
                "{}: status={}, {}",
                self.2,
                status.map_or_else(
                    || "running_at_failure".to_owned(),
                    |value| value.to_string()
                ),
                diagnostic_summary(
                    self.1.bytes.load(Ordering::Relaxed),
                    self.1.classes.load(Ordering::Relaxed)
                )
            );
        }
    }
}

fn wait_standby(child: &mut OwnedChild) {
    let output = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(output).read_line(&mut line).map(|_| line);
        let _ = tx.send(result);
    });
    let line = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("standby readiness timeout")
        .unwrap();
    assert_eq!(line, "receiver-standby-ready-v1\n");
}

fn run(cmd: &mut Command) -> Value {
    let output = cmd.output().expect("run isolated wake command");
    assert!(
        output.status.success(),
        "isolated wake command failed: {}",
        diagnostic_summary(output.stderr.len(), error_classes(&output.stderr))
    );
    serde_json::from_slice(&output.stdout).expect("wake command JSON")
}

#[test]
fn diagnostics_never_include_stderr_content() {
    let private = b"Permission denied: PRIVATE_TEST_SECRET /path/to/socket";
    let summary = diagnostic_summary(private.len(), error_classes(private));
    assert!(summary.contains("permission"));
    assert!(summary.contains("socket"));
    assert!(!summary.contains("PRIVATE_TEST_SECRET"));
    assert!(!summary.contains("/path/to/socket"));

    let mut child = OwnedChild::new(
        "fixture",
        Command::new("/bin/sh")
            .args([
                "-c",
                "printf 'Permission denied: PRIVATE_TEST_SECRET /path/to/socket' >&2",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(child.0.wait().unwrap().success());
    wait_for(
        || child.1.finished.load(Ordering::Acquire),
        "diagnostic capture",
    );
    let actual = diagnostic_summary(
        child.1.bytes.load(Ordering::Relaxed),
        child.1.classes.load(Ordering::Relaxed),
    );
    assert!(actual.contains("permission") && actual.contains("socket"));
    assert!(!actual.contains("PRIVATE_TEST_SECRET") && !actual.contains("/path/to/socket"));
}

fn rpc(ws: &mut WebSocket<UnixStream>, id: &str, method: &str) -> Value {
    ws.send(Message::Text(
        json!({"id":id,"method":method,"params":{}})
            .to_string()
            .into(),
    ))
    .unwrap();
    loop {
        let message = ws.read().unwrap();
        if let Ok(value) = serde_json::from_str::<Value>(message.to_text().unwrap_or(""))
            && value["id"] == id
        {
            assert!(value.get("error").is_none(), "RPC returned an error");
            return value["result"].clone();
        }
    }
}

fn read_byte(reader: &mut BufReader<TcpStream>, deadline: Instant) -> io::Result<u8> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "HTTP response deadline"))?;
    reader.get_mut().set_read_timeout(Some(remaining))?;
    let mut byte = [0];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn read_line(reader: &mut BufReader<TcpStream>, deadline: Instant) -> io::Result<String> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let byte = read_byte(reader, deadline)?;
        bytes.push(byte);
        if byte == b'\n' {
            return String::from_utf8(bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP line"));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP line too long",
    ))
}

fn read_response(reader: &mut BufReader<TcpStream>, deadline: Instant) -> io::Result<()> {
    let line = read_line(reader, deadline)?;
    if !line.starts_with("HTTP/1.1 200 ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "webhook did not accept event",
        ));
    }
    let mut length = None;
    let mut chunked = false;
    for _ in 0..128 {
        let line = read_line(reader, deadline)?;
        if line == "\r\n" {
            if chunked {
                loop {
                    let line = read_line(reader, deadline)?;
                    let size =
                        usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "invalid chunk")
                            })?;
                    if size > 65536 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk too large",
                        ));
                    }
                    if size == 0 {
                        if read_line(reader, deadline)? != "\r\n" {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid chunk end",
                            ));
                        }
                        return Ok(());
                    }
                    for _ in 0..size + 2 {
                        read_byte(reader, deadline)?;
                    }
                }
            }
            let size = length
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP length"))?;
            if size > 65536 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
            for _ in 0..size {
                read_byte(reader, deadline)?;
            }
            return Ok(());
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length =
                Some(value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP length")
                })?);
        }
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "too many HTTP headers",
    ))
}

fn post(reader: &mut BufReader<TcpStream>, port: u16, payload: &[u8], signature: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let request = format!(
        "POST /hooks/codex-wake HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nX-GitHub-Event: workflow_run\r\nX-Hub-Signature-256: sha256={signature}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        payload.len()
    );
    let mut request = request.into_bytes();
    request.extend_from_slice(payload);
    let mut remaining = request.as_slice();
    while !remaining.is_empty() {
        let time = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .expect("HTTP request deadline");
        reader.get_mut().set_write_timeout(Some(time)).unwrap();
        let written = reader
            .get_mut()
            .write(remaining)
            .expect("HTTP request write");
        assert!(written > 0, "HTTP request closed");
        remaining = &remaining[written..];
    }
    read_response(reader, deadline).expect("bounded HTTP response");
}

#[test]
fn http_response_rejects_eof_and_total_deadline() {
    for slow in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            if slow {
                for byte in b"HTTP/1.1 200 OK\r\nX-Slow: still-sending" {
                    if socket.write_all(&[*byte]).is_err() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            } else {
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nX-Test: value\r\n")
                    .unwrap();
            }
        });
        let mut reader = BufReader::new(TcpStream::connect(address).unwrap());
        let start = Instant::now();
        let error = read_response(&mut reader, start + Duration::from_millis(150)).unwrap_err();
        if slow {
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ),
                "slow response must hit the total deadline"
            );
        } else {
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(reader);
        server.join().unwrap();
    }
}

fn wait_for(mut check: impl FnMut() -> bool, stage: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !check() {
        assert!(Instant::now() < deadline, "timed out at {stage}");
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
#[ignore = "requires private user/mount/PID/network namespaces and explicit native binaries"]
fn controller_and_webhook_survive_receiver_handoff() {
    assert_eq!(env::var("WAKE_LIFECYCLE_ISOLATED").as_deref(), Ok("1"));
    let codex = env::var_os("WAKE_LIFECYCLE_CODEX").expect("native Codex path");
    let webhook = env::var_os("WAKE_LIFECYCLE_WEBHOOK").expect("webhook path");
    let staged_wake = env::var_os("WAKE_LIFECYCLE_WAKE").map(PathBuf::from);
    let wake = staged_wake
        .as_deref()
        .unwrap_or_else(|| Path::new(env!("CARGO_BIN_EXE_codex-wake")));
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let home = root.path();
    let state = home.join("state");
    let db_path = state.join("codex-wake/state.sqlite3");
    let socket = home.join("controller.sock");
    fs::create_dir_all(home.join("codex")).unwrap();
    let base = |program: &Path| {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", home)
            .env("CODEX_HOME", home.join("codex"))
            .env("XDG_STATE_HOME", &state)
            .env("CODEX_WAKE_DB", &db_path)
            .env("CODEX_WAKE_CODEX", &codex)
            .env("CODEX_WAKE_GH", "/usr/bin/false")
            .env("CODEX_WAKE_ENABLE_WEBHOOKS", "0")
            .env("CODEX_WAKE_RPC_SOCKET", &socket)
            .stdin(Stdio::null())
            .stderr(Stdio::piped());
        cmd
    };
    let mut controller = OwnedChild::new(
        "controller",
        base(Path::new(&codex))
            .args(["app-server", "--listen"])
            .arg(format!("unix://{}", socket.display()))
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(
        || {
            socket.exists()
                || controller
                    .0
                    .try_wait()
                    .expect("controller status")
                    .is_some()
        },
        "controller socket",
    );
    assert!(socket.exists(), "controller exited before socket readiness");
    let link = fs::symlink_metadata(&socket).unwrap();
    let endpoint = fs::metadata(&socket).unwrap();
    let stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (mut ws, _) = tungstenite::client("ws://localhost/", stream).unwrap();
    ws.send(Message::Text(json!({"id":"init","method":"initialize","params":{"clientInfo":{"name":"wake-test","version":"1"},"capabilities":{"experimentalApi":true}}}).to_string().into())).unwrap();
    loop {
        let value: Value = serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap();
        if value["id"] == "init" {
            assert!(value.get("error").is_none());
            break;
        }
    }
    ws.send(Message::Text(
        json!({"method":"initialized","params":{}})
            .to_string()
            .into(),
    ))
    .unwrap();
    rpc(&mut ws, "before", "thread/loaded/list");
    let started = rpc(&mut ws, "start-isolated-thread", "thread/start");
    let direct_thread = started
        .pointer("/thread/id")
        .and_then(Value::as_str)
        .expect("isolated thread id")
        .to_owned();
    let pid_controller = controller.0.id();
    let thread_id = "11111111-1111-4111-8111-111111111111";
    let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    run(base(Path::new(wake)).args([
        "register",
        "--repo",
        "owner/repo",
        "--run",
        "123",
        "--attempt",
        "1",
        "--thread",
        thread_id,
        "--sha",
        sha,
    ]));
    run(base(Path::new(wake)).args([
        "register",
        "--repo",
        "owner/repo",
        "--run",
        "125",
        "--attempt",
        "1",
        "--thread",
        thread_id,
        "--sha",
        sha,
    ]));
    let db = rusqlite::Connection::open(&db_path).unwrap();
    db.execute("INSERT INTO waits(repo,run_id,attempt,thread,sha,state) VALUES('owner/repo',124,1,?1,?2,'sending')", [thread_id,sha]).unwrap();
    drop(db);
    let owner_a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let owner_b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let owner_c = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    run(base(Path::new(wake)).args(["cooperative-gate", "init", "--owner", owner_a]));
    run(base(Path::new(wake)).args([
        "cooperative-gate",
        "open",
        "--owner",
        owner_a,
        "--generation",
        "1",
    ]));
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    drop(tcp);
    let hooks = env::var_os("WAKE_LIFECYCLE_HOOKS")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("hooks.json.tmpl"));
    let mut ingress = OwnedChild::new(
        "webhook",
        base(Path::new(&webhook))
            .args([
                "-ip",
                "127.0.0.1",
                "-port",
                &port.to_string(),
                "-template",
                "-hooks",
            ])
            .arg(hooks)
            .env("GITHUB_WEBHOOK_SECRET", "isolated-test-secret")
            .env("CODEX_WAKE_EXECUTABLE", wake)
            .env("CODEX_WAKE_DEFER", "1")
            // The long-lived webhook keeps its original identity while the
            // receiver moves to later owners. Only durable ingress is allowed.
            .env("CODEX_WAKE_GATE_OWNER", owner_a)
            .env("CODEX_WAKE_GATE_GENERATION", "1")
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut http = None;
    wait_for(
        || {
            http = TcpStream::connect(("127.0.0.1", port)).ok();
            http.is_some() || ingress.0.try_wait().expect("webhook status").is_some()
        },
        "webhook readiness",
    );
    let http = http.expect("webhook exited before readiness");
    http.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    http.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut http = BufReader::new(http);
    let spawn_receiver = |owner: &str, generation: &str| -> OwnedChild {
        OwnedChild::new(
            "receiver",
            base(Path::new(wake))
                .arg("receiver")
                .env("CODEX_WAKE_COOPERATIVE_RECEIVER", "1")
                .env("CODEX_WAKE_GATE_OWNER", owner)
                .env("CODEX_WAKE_GATE_GENERATION", generation)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        )
    };
    let telemetry = state.join("codex-wake/telemetry.sqlite3");
    let ready = |pid: u32| {
        rusqlite::Connection::open_with_flags(&telemetry,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()
            .and_then(|db| db.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE pid=?1 AND operation='receiver.heartbeat' AND outcome='ok')", [pid], |r| r.get::<_,bool>(0)).ok()).unwrap_or(false)
    };
    let mut old = spawn_receiver(owner_a, "1");
    wait_for(|| ready(old.0.id()), "old receiver readiness");
    run(base(Path::new(wake)).args([
        "cooperative-gate",
        "close",
        "--owner",
        owner_a,
        "--generation",
        "1",
    ]));
    assert!(
        old.0
            .wait_timeout(Duration::from_secs(30))
            .unwrap()
            .expect("old receiver did not stop")
            .success()
    );
    assert!(controller.0.try_wait().unwrap().is_none());
    assert!(ingress.0.try_wait().unwrap().is_none());
    let payload = json!({"action":"completed","repository":{"full_name":"owner/repo"},"workflow_run":{"id":123,"run_attempt":1,"head_sha":sha,"status":"completed","conclusion":"success"}}).to_string().into_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"isolated-test-secret").unwrap();
    mac.update(&payload);
    let signature = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    post(&mut http, port, &payload, &signature);
    let db = rusqlite::Connection::open(&db_path).unwrap();
    let state: String = db
        .query_row("SELECT state FROM waits WHERE run_id=123", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "ready");
    let uncertain: String = db
        .query_row("SELECT state FROM waits WHERE run_id=124", [], |r| r.get(0))
        .unwrap();
    assert_eq!(uncertain, "sending");
    drop(db);
    run(base(Path::new(wake)).args([
        "cooperative-gate",
        "arm",
        "--owner",
        owner_a,
        "--generation",
        "1",
    ]));
    let producer = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    run(base(Path::new(wake)).args([
        "cooperative-gate",
        "producer",
        "--owner",
        owner_a,
        "--generation",
        "1",
        "--producer-id",
        producer,
    ]));
    assert!(
        !base(Path::new(wake))
            .args([
                "cooperative-gate",
                "open",
                "--owner",
                owner_a,
                "--generation",
                "1",
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    run(base(Path::new(wake)).args([
        "cooperative-gate",
        "transfer",
        "--owner",
        owner_a,
        "--generation",
        "1",
        "--next-owner",
        owner_b,
    ]));
    let standby = |owner: &str, generation: &str| -> OwnedChild {
        OwnedChild::new(
            "standby",
            base(Path::new(wake))
                .arg("receiver")
                .env("CODEX_WAKE_COOPERATIVE_RECEIVER", "1")
                .env("CODEX_WAKE_RECEIVER_STANDBY", "1")
                .env("CODEX_WAKE_GATE_OWNER", owner)
                .env("CODEX_WAKE_GATE_GENERATION", generation)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    };
    let mut no_controller = OwnedChild::new(
        "standby_without_controller",
        base(Path::new(wake))
            .arg("receiver")
            .env("CODEX_WAKE_COOPERATIVE_RECEIVER", "1")
            .env("CODEX_WAKE_RECEIVER_STANDBY", "1")
            .env("CODEX_WAKE_GATE_OWNER", owner_b)
            .env("CODEX_WAKE_GATE_GENERATION", "2")
            .env("CODEX_WAKE_RPC_SOCKET", home.join("missing.sock"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(
        !no_controller
            .0
            .wait_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap()
            .success()
    );
    let mut wrong = standby(owner_a, "2");
    assert!(
        !wrong
            .0
            .wait_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap()
            .success()
    );
    let mut premature = standby(owner_b, "2");
    wait_standby(&mut premature);
    premature.0.stdin.take().unwrap().write_all(b"X").unwrap();
    assert!(
        !premature
            .0
            .wait_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap()
            .success()
    );
    let mut disconnected = standby(owner_b, "2");
    wait_standby(&mut disconnected);
    drop(disconnected.0.stdin.take());
    assert!(
        !disconnected
            .0
            .wait_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap()
            .success()
    );
    let mut terminated = standby(owner_b, "2");
    wait_standby(&mut terminated);
    terminated.0.kill().unwrap();
    assert!(
        !terminated
            .0
            .wait_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap()
            .success()
    );
    let db = rusqlite::Connection::open(&db_path).unwrap();
    let (closed, owner, generation): (bool, String, i64) = db
        .query_row(
            "SELECT is_open,owner,generation FROM wake_delivery_claim_gate WHERE id=1",
            [],
            |row| Ok((!row.get::<_, bool>(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(closed);
    assert_eq!((owner.as_str(), generation), (owner_b, 2));
    drop(db);
    assert!(controller.0.try_wait().unwrap().is_none());
    assert!(ingress.0.try_wait().unwrap().is_none());
    // Hold the writer lock across the activation signal and kill: no commit
    // can cross this boundary while the intended owner is gone.
    let mut blocked = standby(owner_b, "2");
    wait_standby(&mut blocked);
    let locked = rusqlite::Connection::open(&db_path).unwrap();
    locked.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut activation = blocked.0.stdin.take().unwrap();
    activation.write_all(b"G").unwrap();
    wait_for(
        || {
            let mut pending: libc::c_int = -1;
            let rc = unsafe { libc::ioctl(activation.as_raw_fd(), libc::FIONREAD, &mut pending) };
            assert_eq!(rc, 0, "cannot inspect activation pipe");
            pending == 0
        },
        "activation signal consumed under writer lock",
    );
    assert!(blocked.0.try_wait().unwrap().is_none());
    blocked.0.kill().unwrap();
    assert!(!blocked.0.wait().unwrap().success());
    locked.execute_batch("ROLLBACK").unwrap();
    let closed: bool = locked
        .query_row(
            "SELECT NOT is_open FROM wake_delivery_claim_gate",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(closed);
    drop(locked);

    // Kill immediately after the receiver commits its bound opening. The
    // persistent bit remains set, but another process with the cohort cannot claim.
    let mut killed = standby(owner_b, "2");
    wait_standby(&mut killed);
    killed.0.stdin.take().unwrap().write_all(b"G").unwrap();
    wait_for(
        || {
            rusqlite::Connection::open(&db_path)
                .ok()
                .and_then(|db| {
                    db.query_row("SELECT is_open FROM wake_delivery_claim_gate", [], |r| {
                        r.get::<_, bool>(0)
                    })
                    .ok()
                })
                .unwrap_or(false)
        },
        "bound opening",
    );
    killed.0.kill().unwrap();
    assert!(!killed.0.wait().unwrap().success());
    let db = rusqlite::Connection::open(&db_path).unwrap();
    let bit_open: bool = db
        .query_row("SELECT is_open FROM wake_delivery_claim_gate", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(bit_open, "test requires the persisted open bit after death");
    db.execute("INSERT INTO waits(repo,run_id,attempt,thread,sha,state,conclusion) VALUES('owner/repo',126,1,?1,?2,'ready','success')", [thread_id,sha]).unwrap();
    drop(db);
    let recovered = run(base(Path::new(wake))
        .env("CODEX_WAKE_GATE_OWNER", owner_b)
        .env("CODEX_WAKE_GATE_GENERATION", "2")
        .arg("recover"));
    assert_eq!(recovered["attempted"], 0);
    let db = rusqlite::Connection::open(&db_path).unwrap();
    let retained: String = db
        .query_row("SELECT state FROM waits WHERE run_id=126", [], |r| r.get(0))
        .unwrap();
    assert_eq!(retained, "ready");
    drop(db);
    run(base(Path::new(wake)).args([
        "cooperative-gate",
        "close",
        "--owner",
        owner_b,
        "--generation",
        "2",
    ]));
    let request_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let submit_direct = || -> Value {
        let mut child = base(Path::new(wake))
            .env("CODEX_WAKE_PRODUCER_ID", producer)
            .arg("queue-direct")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        write!(child.stdin.take().unwrap(), "{}", json!({"thread":direct_thread,"message_template":"isolated fixture","request_id":request_id})).unwrap();
        if child
            .wait_timeout(Duration::from_secs(15))
            .unwrap()
            .is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated direct producer timed out");
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "isolated direct producer failed: {}",
            diagnostic_summary(output.stderr.len(), error_classes(&output.stderr))
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };
    assert_eq!(submit_direct()["state"], "pending");
    // A killed bound receiver has no successful-exit proof. Never clear its binding.
    assert!(
        !base(Path::new(wake))
            .args([
                "cooperative-gate",
                "transfer",
                "--owner",
                owner_b,
                "--generation",
                "2",
                "--next-owner",
                owner_c,
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(submit_direct()["state"], "pending");
    assert_eq!(controller.0.id(), pid_controller);
    assert!(controller.0.try_wait().unwrap().is_none());
    assert!(ingress.0.try_wait().unwrap().is_none());
    assert_eq!(
        (
            fs::symlink_metadata(&socket).unwrap().dev(),
            fs::symlink_metadata(&socket).unwrap().ino()
        ),
        (link.dev(), link.ino())
    );
    assert_eq!(
        (
            fs::metadata(&socket).unwrap().dev(),
            fs::metadata(&socket).unwrap().ino()
        ),
        (endpoint.dev(), endpoint.ino())
    );
    rpc(&mut ws, "after", "thread/loaded/list");
    let db = rusqlite::Connection::open(&db_path).unwrap();
    let uncertain: String = db
        .query_row("SELECT state FROM waits WHERE run_id=124", [], |r| r.get(0))
        .unwrap();
    assert_eq!(uncertain, "sending");
    drop(db);
    let payload_after = json!({"action":"completed","repository":{"full_name":"owner/repo"},"workflow_run":{"id":125,"run_attempt":1,"head_sha":sha,"status":"completed","conclusion":"failure"}}).to_string().into_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"isolated-test-secret").unwrap();
    mac.update(&payload_after);
    let signature_after = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    post(&mut http, port, &payload_after, &signature_after);
    let db = rusqlite::Connection::open(&db_path).unwrap();
    let (state, conclusion): (String, Option<String>) = db
        .query_row(
            "SELECT state,conclusion FROM waits WHERE run_id=125",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_ne!(state, "waiting");
    assert_eq!(conclusion.as_deref(), Some("failure"));
    drop(db);
}
