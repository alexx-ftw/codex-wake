//! Explicit hosted-CI qualification. Never used by the installer or receiver.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    env, fs, io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket};

const CONTROLLER: &str = "wake-qualification-controller.service";
const RECEIVER: &str = "wake-qualification-receiver.service";
type Socket = WebSocket<UnixStream>;

fn main() {
    if run().is_err() {
        eprintln!("controller qualification failed; inspect the sanitized receipt");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    ensure!(
        env::var("WAKE_PRIVATE_QUALIFICATION")? == "1",
        "qualification guard"
    );
    let home = PathBuf::from(env::var_os("HOME").context("missing private home")?);
    let meta = fs::symlink_metadata(&home)?;
    let root = home.parent().context("private root missing")?;
    ensure!(
        root.parent() == Some(Path::new("/tmp"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("wq."))
            && home.file_name().is_some_and(|s| s == "h")
            && meta.is_dir()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0,
        "invalid private qualification home"
    );
    let args: Vec<_> = env::args_os().skip(1).collect();
    let (mode, args) = args.split_first().context("missing qualification mode")?;
    match (mode.to_str(), args) {
        (Some("controller"), [native, socket, marker]) => {
            controller(Path::new(native), Path::new(socket), Path::new(marker))
        }
        (Some("ready"), [native, socket]) => {
            let _ = ready(Path::new(native), Path::new(socket))?;
            Ok(())
        }
        (Some("cleanup-lock"), [socket, lock]) => {
            let uid = unsafe { libc::geteuid() };
            let daemon = PathBuf::from(format!("/tmp/codex-daemon-{uid}"));
            remove_owned_socket(Path::new(socket), Path::new(lock), &daemon, uid)
        }
        (Some("verify"), [native, socket, marker, receipt]) => {
            let mut report = Receipt::new(PathBuf::from(receipt))?;
            let result = verify(
                Path::new(native),
                Path::new(socket),
                Path::new(marker),
                &mut report,
            );
            if let Err(error) = &result {
                report.data["error_class"] = json!(error_class(error));
            }
            report.finish(result.is_ok())?;
            result
        }
        _ => bail!("invalid qualification arguments"),
    }
}

fn remove_owned_socket(socket: &Path, lock: &Path, daemon: &Path, uid: u32) -> Result<()> {
    let directory = fs::symlink_metadata(daemon)?;
    ensure!(
        directory.is_dir() && directory.uid() == uid && directory.mode() & 0o077 == 0,
        "untrusted daemon directory"
    );
    let name = socket
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid socket name")?;
    ensure!(
        socket.parent() == Some(daemon)
            && lock.parent() == Some(daemon)
            && name.len() == 64
            && name.bytes().all(|byte| byte.is_ascii_hexdigit())
            && lock.file_name().and_then(|name| name.to_str())
                == Some(format!("{name}.lock").as_str()),
        "invalid cleanup target"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(lock)?;
    let locked = file.metadata()?;
    ensure!(
        locked.is_file() && locked.uid() == uid && locked.nlink() == 1,
        "untrusted lock file"
    );
    let mut record: libc::flock = unsafe { std::mem::zeroed() };
    record.l_type = libc::F_WRLCK as libc::c_short;
    record.l_whence = libc::SEEK_SET as libc::c_short;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &record) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let current = fs::symlink_metadata(lock)?;
    ensure!(
        (current.dev(), current.ino()) == (locked.dev(), locked.ino()),
        "lock file changed"
    );
    match fs::symlink_metadata(socket) {
        Ok(meta) => {
            ensure!(
                meta.file_type().is_socket() && meta.uid() == uid && meta.nlink() == 1,
                "untrusted socket"
            );
            fs::remove_file(socket)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(lock)?;
    Ok(())
}

fn error_class(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("deadline") {
        "deadline"
    } else if message.contains("cgroup") {
        "cgroup"
    } else if message.contains("peer") {
        "peer_identity"
    } else if message.contains("socket changed") {
        "socket_changed"
    } else if message.contains("controller process changed") {
        "controller_changed"
    } else if message.contains("receiver did not restart") {
        "receiver_not_restarted"
    } else if message.contains("RPC rejected") {
        "rpc_rejected"
    } else {
        "other"
    }
}

// Runs as the unit's main PID, creates a known helper in that cgroup, then execs Codex.
fn controller(native: &Path, socket: &Path, marker: &Path) -> Result<()> {
    for family in [libc::AF_INET, libc::AF_INET6] {
        let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            bail!("network restriction is ineffective");
        }
        ensure!(
            [Some(libc::EAFNOSUPPORT), Some(libc::EPERM)]
                .contains(&io::Error::last_os_error().raw_os_error()),
            "network restriction was not verified"
        );
    }
    let helper = Command::new("/usr/bin/sleep")
        .arg("600")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    fs::write(marker, helper.id().to_string())?;
    Err(Command::new(native)
        .args(["app-server", "--listen"])
        .arg(format!("unix://{}", socket.display()))
        .exec()
        .into())
}

fn systemctl(args: &[&str]) -> Result<String> {
    let result = Command::new("/usr/bin/systemctl")
        .arg("--user")
        .args(args)
        .stderr(Stdio::null())
        .output()?;
    ensure!(
        result.status.success(),
        "private user manager command failed"
    );
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}
fn property(unit: &str, property: &str) -> Result<String> {
    systemctl(&["show", unit, "--property", property, "--value"])
}
fn pid(unit: &str) -> Result<u32> {
    let value: u32 = property(unit, "MainPID")?.parse()?;
    ensure!(value > 1, "unit has no main process");
    Ok(value)
}
fn process_stat(pid: u32) -> Result<(String, String)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = stat.rsplit_once(") ").context("invalid process stat")?.1;
    let fields: Vec<_> = tail.split_whitespace().collect();
    Ok((
        fields.first().context("missing state")?.to_string(),
        fields.get(19).context("missing start")?.to_string(),
    ))
}
fn process_group(pid: u32) -> Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    Ok(text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("cgroup v2 required")?
        .to_owned())
}
fn group(unit: &str, pid: u32) -> Result<String> {
    let group = property(unit, "ControlGroup")?;
    ensure!(
        !group.is_empty() && group == process_group(pid)?,
        "process is outside its unit cgroup"
    );
    Ok(group)
}
fn group_empty(group: &str) -> Result<bool> {
    ensure!(
        group.starts_with('/') && !group.split('/').any(|part| part == ".."),
        "invalid cgroup path"
    );
    match fs::read_to_string(
        Path::new("/sys/fs/cgroup")
            .join(group.trim_start_matches('/'))
            .join("cgroup.events"),
    ) {
        Ok(events) => Ok(events.lines().any(|line| line == "populated 0")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}
fn wait_until(mut check: impl FnMut() -> Result<bool>, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if check()? {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "qualification deadline exceeded");
        thread::sleep(Duration::from_millis(100));
    }
}

fn receiver_ready(binary: &Path, telemetry: &Path, minimum_starts: i64) -> Result<(u32, String)> {
    let mut result = None;
    wait_until(
        || {
            let check = || -> Result<Option<(u32, String)>> {
                if property(RECEIVER, "ActiveState")? != "active" {
                    return Ok(None);
                }
                let receiver = pid(RECEIVER)?;
                let actual = fs::metadata(format!("/proc/{receiver}/exe"))?;
                let expected = fs::metadata(binary)?;
                if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
                    return Ok(None);
                }
                let db = rusqlite::Connection::open_with_flags(
                    telemetry,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )?;
                let starts: i64 = db.query_row(
                    "SELECT count(*) FROM events WHERE operation='receiver.start' AND outcome='ok'",
                    [],
                    |r| r.get(0),
                )?;
                let own: i64 = db.query_row("SELECT count(*) FROM events WHERE operation='receiver.start' AND outcome='ok' AND pid=?1", [receiver], |r| r.get(0))?;
                if starts < minimum_starts || own == 0 {
                    return Ok(None);
                }
                Ok(Some((receiver, process_stat(receiver)?.1)))
            };
            if let Ok(Some(identity)) = check() {
                result = Some(identity);
                return Ok(true);
            }
            Ok(false)
        },
        Duration::from_secs(30),
    )?;
    result.context("receiver did not become ready")
}
fn response(ws: &mut Socket, id: i64) -> Result<Value> {
    loop {
        match ws.read()? {
            Message::Text(text) => {
                let message: Value = serde_json::from_str(&text)?;
                if message["id"] == id {
                    ensure!(message.get("error").is_none(), "RPC rejected");
                    return Ok(message["result"].clone());
                }
            }
            Message::Close(_) => bail!("connection closed"),
            _ => (),
        }
    }
}
fn loaded(ws: &mut Socket, id: i64) -> Result<()> {
    ws.send(Message::Text(
        json!({"id":id,"method":"thread/loaded/list","params":{}})
            .to_string()
            .into(),
    ))?;
    ensure!(
        response(ws, id)?["data"].is_array(),
        "invalid controller response"
    );
    Ok(())
}
fn connect(socket: &Path) -> Result<Socket> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (mut ws, _) = tungstenite::client("ws://localhost/", stream)
        .map_err(|_| anyhow::anyhow!("websocket handshake failed"))?;
    ws.send(Message::Text(json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"wake-systemd-qualification","version":"1"},"capabilities":{"experimentalApi":true}}}).to_string().into()))?;
    ensure!(
        response(&mut ws, 1)?.is_object(),
        "invalid initialize response"
    );
    ws.send(Message::Text(
        json!({"method":"initialized","params":{}})
            .to_string()
            .into(),
    ))?;
    loaded(&mut ws, 2)?;
    Ok(ws)
}
fn controller_socket_ready(socket: &Path) -> Result<bool> {
    let meta = match fs::symlink_metadata(socket) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let uid = unsafe { libc::geteuid() };
    ensure!(meta.uid() == uid, "socket owner mismatch");
    if meta.file_type().is_socket() {
        return Ok(true);
    }
    ensure!(
        meta.file_type().is_symlink(),
        "unexpected controller socket path"
    );
    let target = fs::read_link(socket)?;
    let root = socket.parent().context("qualification root missing")?;
    let name = format!("codex-daemon-{uid}");
    let private_daemon = root.join("t").join(&name);
    let external_daemon = Path::new("/tmp").join(&name);
    let daemon = target
        .parent()
        .context("controller target parent missing")?;
    ensure!(
        (daemon == private_daemon || daemon == external_daemon)
            && target
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(
                    |name| name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
                ),
        "controller socket is outside the private temporary directory"
    );
    let directory = match fs::symlink_metadata(daemon) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        directory.is_dir() && directory.uid() == uid && directory.mode() & 0o077 == 0,
        "controller socket directory is not private"
    );
    let target_meta = match fs::symlink_metadata(target) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        target_meta.file_type().is_socket() && target_meta.uid() == uid,
        "controller socket target is not owned"
    );
    Ok(true)
}

fn ready(native: &Path, socket: &Path) -> Result<(Socket, u32)> {
    let mut answer = None;
    wait_until(
        || {
            if !controller_socket_ready(socket)? {
                return Ok(false);
            }
            if let Ok(ws) = connect(socket) {
                answer = Some(ws);
                return Ok(true);
            }
            Ok(false)
        },
        Duration::from_secs(45),
    )?;
    let ws = answer.context("controller not ready")?;
    let controller = pid(CONTROLLER)?;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&peer) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                ws.get_ref().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut len,
            )
        } == 0,
        "peer identity unavailable"
    );
    ensure!(
        peer.pid == controller as i32 && peer.uid == unsafe { libc::geteuid() },
        "unexpected socket owner"
    );
    let expected = fs::metadata(native)?;
    let actual = fs::metadata(format!("/proc/{controller}/exe"))?;
    ensure!(
        expected.dev() == actual.dev() && expected.ino() == actual.ino(),
        "unexpected controller executable"
    );
    Ok((ws, controller))
}

struct Receipt {
    path: PathBuf,
    data: Value,
}
impl Receipt {
    fn new(path: PathBuf) -> Result<Self> {
        let mut report = Self {
            path,
            data: json!({"status":"running","stage":"starting","raw_logs":false}),
        };
        report.stage("starting")?;
        Ok(report)
    }
    fn save(&self) -> Result<()> {
        let mut file =
            tempfile::NamedTempFile::new_in(self.path.parent().context("receipt parent missing")?)?;
        serde_json::to_writer(&mut file, &self.data)?;
        file.persist(&self.path)?;
        Ok(())
    }
    fn stage(&mut self, stage: &'static str) -> Result<()> {
        self.data["stage"] = json!(stage);
        self.save()
    }
    fn mark(&mut self, name: &'static str) -> Result<()> {
        self.data[name] = json!(true);
        self.save()
    }
    fn finish(&mut self, ok: bool) -> Result<()> {
        self.data["status"] = json!(if ok { "passed" } else { "failed" });
        self.save()
    }
}

fn verify(native: &Path, socket: &Path, marker: &Path, report: &mut Receipt) -> Result<()> {
    report.stage("controller_ready")?;
    let (mut ws, controller) = ready(native, socket)?;
    let controller_start = process_stat(controller)?.1;
    let controller_group = group(CONTROLLER, controller)?;
    let socket_link = fs::symlink_metadata(socket)?;
    let socket_target = fs::metadata(socket)?;
    let helper: u32 = fs::read_to_string(marker)?.trim().parse()?;
    let helper_start = process_stat(helper)?.1;
    ensure!(
        process_group(helper)? == controller_group,
        "test helper is outside controller cgroup"
    );
    ensure!(
        property(CONTROLLER, "KillMode")? == "control-group"
            && property(RECEIVER, "KillMode")? == "control-group"
            && property(CONTROLLER, "Restart")? == "no"
            && property(RECEIVER, "Restart")? == "no",
        "incorrect kill mode"
    );
    ensure!(
        property(CONTROLLER, "RestrictAddressFamilies")?
            .split_whitespace()
            .eq(["AF_UNIX"])
            && property(RECEIVER, "RestrictAddressFamilies")?
                .split_whitespace()
                .eq(["AF_UNIX"]),
        "address family restriction missing"
    );
    report.mark("controller_ip_sockets_blocked")?;
    let root = socket.parent().context("qualification root missing")?;
    let receiver_binary = root.join("wake");
    let telemetry = root.join("h/s/codex-wake/telemetry.sqlite3");
    let (receiver_before, receiver_start) = receiver_ready(&receiver_binary, &telemetry, 1)?;
    let receiver_group = group(RECEIVER, receiver_before)?;
    ensure!(
        receiver_group != controller_group
            && !receiver_group.starts_with(&(controller_group.clone() + "/"))
            && !controller_group.starts_with(&(receiver_group.clone() + "/")),
        "service cgroups overlap"
    );
    report.mark("separate_cgroups_verified")?;
    report.mark("receiver_readiness_verified")?;
    report.stage("receiver_restart")?;
    systemctl(&["restart", RECEIVER])?;
    let (receiver_after, receiver_after_start) = receiver_ready(&receiver_binary, &telemetry, 2)?;
    ensure!(
        (receiver_before, receiver_start) != (receiver_after, receiver_after_start.clone()),
        "receiver did not restart"
    );
    ensure!(
        group(RECEIVER, receiver_after)? == receiver_group,
        "receiver cgroup changed unexpectedly"
    );
    ensure!(
        pid(CONTROLLER)? == controller && process_stat(controller)?.1 == controller_start,
        "controller process changed"
    );
    ensure!(
        group(CONTROLLER, controller)? == controller_group,
        "controller cgroup changed"
    );
    let after_link = fs::symlink_metadata(socket)?;
    let after_target = fs::metadata(socket)?;
    ensure!(
        (
            socket_link.dev(),
            socket_link.ino(),
            socket_target.dev(),
            socket_target.ino()
        ) == (
            after_link.dev(),
            after_link.ino(),
            after_target.dev(),
            after_target.ino()
        ),
        "controller socket changed"
    );
    loaded(&mut ws, 3)?;
    report.mark("same_controller_socket_connection_after_restart")?;
    report.stage("controller_failure")?;
    systemctl(&["kill", "--kill-whom=main", "--signal=SIGKILL", CONTROLLER])?;
    wait_until(
        || Ok(property(CONTROLLER, "ActiveState")? == "failed" && group_empty(&controller_group)?),
        Duration::from_secs(30),
    )?;
    match process_stat(helper) {
        Ok((state, start)) => ensure!(
            state == "Z" || start != helper_start,
            "helper survived controller cgroup cleanup"
        ),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    ensure!(
        property(RECEIVER, "ActiveState")? == "active"
            && pid(RECEIVER)? == receiver_after
            && process_stat(receiver_after)?.1 == receiver_after_start,
        "controller failure stopped receiver"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    ws.get_mut()
        .set_read_timeout(Some(Duration::from_secs(1)))?;
    loop {
        match ws.read() {
            Err(
                tungstenite::Error::ConnectionClosed
                | tungstenite::Error::AlreadyClosed
                | tungstenite::Error::Protocol(
                    tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                ),
            )
            | Ok(Message::Close(_)) => break,
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                break;
            }
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => bail!("unexpected websocket failure"),
            _ => (),
        }
        ensure!(
            Instant::now() < deadline,
            "controller connection remained open"
        );
    }
    report.mark("controller_failure_and_cgroup_drain_verified")?;
    report.stage("receiver_cleanup")?;
    systemctl(&["stop", RECEIVER])?;
    wait_until(|| group_empty(&receiver_group), Duration::from_secs(30))?;
    report.mark("receiver_cgroup_drain_verified")?;
    report.stage("complete")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_is_atomic_and_contains_no_error_payload() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("receipt.json");
        let mut receipt = Receipt::new(path.clone()).unwrap();
        receipt.stage("receiver_restart").unwrap();
        receipt.mark("separate_cgroups_verified").unwrap();
        receipt.finish(false).unwrap();
        let raw = fs::read_to_string(path).unwrap();
        let data: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(data["stage"], "receiver_restart");
        assert_eq!(data["status"], "failed");
        assert_eq!(data["separate_cgroups_verified"], true);
        assert!(!raw.contains("PRIVATE_PAYLOAD"));
        assert_eq!(
            error_class(&anyhow::anyhow!("RPC rejected PRIVATE_PAYLOAD")),
            "rpc_rejected"
        );
    }
    #[test]
    fn refuses_untrusted_cgroup_path() {
        assert!(group_empty("/../../tmp").is_err());
        assert!(group_empty("relative").is_err());
    }

    #[test]
    fn refuses_foreign_socket_links_before_connecting() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("socket");
        assert!(!controller_socket_ready(&socket).unwrap());
        symlink("/tmp/not-the-private-daemon/socket", &socket).unwrap();
        assert!(controller_socket_ready(&socket).is_err());
        fs::remove_file(&socket).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        assert!(controller_socket_ready(&socket).unwrap());
    }

    #[test]
    fn cleanup_preserves_a_locked_socket_and_requires_owned_files() {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let name = "a".repeat(64);
        let socket = temp.path().join(&name);
        let lock = temp.path().join(format!("{name}.lock"));
        let listener = UnixListener::bind(&socket).unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock)
            .unwrap();
        let mut held: libc::flock = unsafe { std::mem::zeroed() };
        held.l_type = libc::F_WRLCK as libc::c_short;
        held.l_whence = libc::SEEK_SET as libc::c_short;
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &held) },
            0
        );
        let uid = unsafe { libc::geteuid() };
        assert!(remove_owned_socket(&socket, &lock, temp.path(), uid).is_err());
        assert!(socket.exists() && lock.exists());
        held.l_type = libc::F_UNLCK as libc::c_short;
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &held) },
            0
        );
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(remove_owned_socket(&socket, &lock, temp.path(), uid).is_err());
        assert!(socket.exists() && lock.exists());
        drop(file);
        drop(listener);
        remove_owned_socket(&socket, &lock, temp.path(), uid).unwrap();
        assert!(!socket.exists() && !lock.exists());
    }

    #[test]
    fn readiness_and_followup_share_one_connection_without_leaking_errors() {
        use std::os::unix::net::UnixListener;
        for rejected in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("controller.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut ws = tungstenite::accept(stream).unwrap();
                let init: Value =
                    serde_json::from_str(&ws.read().unwrap().into_text().unwrap()).unwrap();
                assert_eq!(init["method"], "initialize");
                if rejected {
                    ws.send(Message::Text(
                        json!({"id":1,"error":{"message":"PRIVATE_PAYLOAD"}})
                            .to_string()
                            .into(),
                    ))
                    .unwrap();
                    return;
                }
                ws.send(Message::Text(
                    json!({"method":"unrelated/notice"}).to_string().into(),
                ))
                .unwrap();
                ws.send(Message::Text(
                    json!({"id":1,"result":{}}).to_string().into(),
                ))
                .unwrap();
                let initialized: Value =
                    serde_json::from_str(&ws.read().unwrap().into_text().unwrap()).unwrap();
                assert_eq!(initialized["method"], "initialized");
                for id in [2, 3] {
                    let request: Value =
                        serde_json::from_str(&ws.read().unwrap().into_text().unwrap()).unwrap();
                    assert_eq!(request["id"], id);
                    ws.send(Message::Text(
                        json!({"id":id,"result":{"data":[]}}).to_string().into(),
                    ))
                    .unwrap();
                }
            });
            match connect(&path) {
                Ok(mut ws) => {
                    assert!(!rejected);
                    loaded(&mut ws, 3).unwrap();
                }
                Err(error) => {
                    assert!(rejected);
                    assert!(!format!("{error:#}").contains("PRIVATE_PAYLOAD"));
                }
            }
            server.join().unwrap();
        }
    }
}
