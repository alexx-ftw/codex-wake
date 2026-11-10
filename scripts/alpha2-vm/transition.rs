use super::*;
use anyhow::Context;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
const OLD: &str = "a2lab-old.service";
const NEW: &str = "a2lab-new.service";
const SCOPE: &str = "a2lab-controller.scope";
fn show(unit: &str) -> Result<Value> {
    let s = integrated::ctl(&[
        "show",
        unit,
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "MainPID",
        "-p",
        "ControlGroup",
        "-p",
        "InvocationID",
        "-p",
        "Result",
        "-p",
        "ExecMainStatus",
        "-p",
        "ExecMainCode",
    ])?;
    Ok(Value::Object(
        s.lines()
            .filter_map(|s| s.split_once('='))
            .map(|(k, v)| (k.into(), json!(v)))
            .collect(),
    ))
}
fn service(
    name: &str,
    binary: &str,
    args: &str,
    uid: u32,
    internal_socket: bool,
    cut: &str,
) -> Result<()> {
    ensure!(
        [OLD, NEW, "a2lab-reader.service"].contains(&name),
        "guest unit only"
    );
    let c = wake(binary, &[]);
    let mut body = format!(
        "[Unit]\nDefaultDependencies=no\n[Service]\nType=exec\nUser={uid}\nGroup={uid}\nRestart=no\nKillMode=control-group\nTimeoutStopSec=3\nStandardOutput=null\nStandardError=append:/lab/{name}.stderr\nExecStart={binary} {args}\n"
    );
    for (k, v) in c.get_envs() {
        if let Some(v) = v {
            let value = if k == "CODEX_WAKE_RPC_SOCKET" && internal_socket {
                "/lab/state/codex-wake/app-server.sock".into()
            } else if k == "CODEX_HOME" && uid == persistent::NEW_UID {
                "/lab/new-codex".into()
            } else {
                v.to_string_lossy().into_owned()
            };
            body.push_str(&format!("Environment={}={value}\n", k.to_string_lossy()));
        }
    }
    let unit = format!("/etc/systemd/system/{name}");
    if name == NEW && cut == "successor-unit-partial" {
        fs::write(&unit, &body.as_bytes()[..body.len() / 2])?;
        checkpoint("successor-unit-partial", cut)?;
    }
    let staged = format!("{unit}.tmp");
    fs::write(&staged, body)?;
    File::open(&staged)?.sync_all()?;
    fs::rename(&staged, &unit)?;
    if name == NEW {
        checkpoint("successor-unit-written", cut)?;
    }
    integrated::ctl(&["daemon-reload"])?;
    if name == NEW {
        checkpoint("successor-reloaded", cut)?;
    }
    if let Err(e) = integrated::ctl(&["start", name]) {
        bail!("{e}; unit={}", show(name)?);
    }
    ensure!(show(name)?["ActiveState"] == "active", "unit failed {name}");
    if name == NEW {
        checkpoint("successor-started", cut)?;
    }
    Ok(())
}
pub fn start() -> Result<(WebSocket<UnixStream>, u32)> {
    service(OLD, "/guest/legacy", "receiver", UID, true, "none")?;
    std::os::unix::fs::symlink("/lab/state/codex-wake/app-server.sock", "/lab/native.sock")?;
    wait("legacy controller socket", || {
        UnixStream::connect("/lab/native.sock").is_ok()
    })?;
    let (ws, pid) = connect()?;
    let state = show(OLD)?;
    let parent: u32 = state["MainPID"].as_str().context("old pid")?.parse()?;
    let oldcg = state["ControlGroup"].as_str().context("old cgroup")?;
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?.contains(oldcg),
        "controller not owned by legacy unit"
    );
    let exe = fs::metadata(format!("/proc/{pid}/exe"))?;
    let socket = fs::metadata("/lab/native.sock")?;
    let identity = json!({"pid":pid,"start":persistent::start_tick(pid)?,"exe_dev":exe.dev(),"exe_ino":exe.ino(),"socket_dev":socket.dev(),"socket_ino":socket.ino(),"parent":parent,"old_unit":state});
    fs::write(
        "/guest/identity.json",
        serde_json::to_vec_pretty(&identity)?,
    )?;
    save("systemd-before", identity)?;
    Ok((ws, pid))
}
pub fn freeze_inventory() -> Result<Vec<std::os::fd::OwnedFd>> {
    arm_add(40)?;
    let mut stopped = std::collections::BTreeMap::new();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        ensure!(Instant::now() < end, "inventory quiescence timeout");
        for (&pid, fd) in &stopped {
            if persistent::dead(fd) {
                continue;
            }
            for tid in persistent::ids_in(Path::new(&format!("/proc/{pid}/task")))? {
                let (_, state) =
                    persistent::status_at(Path::new(&format!("/proc/{pid}/task/{tid}/status")))?;
                ensure!(
                    matches!(state, 'T' | 't' | 'Z' | 'X'),
                    "inventory task resumed: {pid}/{tid}"
                );
            }
        }
        let mut pids = persistent::old_live(0)?;
        pids.sort_unstable();
        let mut added = false;
        for pid in pids {
            if stopped.contains_key(&pid) {
                continue;
            }
            let before = persistent::start_tick(pid)?;
            let fd = persistent::pidfd(pid)?;
            ensure!(
                persistent::start_tick(pid)? == before,
                "inventory PID changed"
            );
            persistent::signal(&fd, libc::SIGSTOP)?;
            loop {
                let mut all = true;
                for tid in persistent::ids_in(Path::new(&format!("/proc/{pid}/task")))? {
                    all &= matches!(
                        persistent::status_at(Path::new(&format!(
                            "/proc/{pid}/task/{tid}/status"
                        )))?
                        .1,
                        'T' | 't' | 'Z' | 'X'
                    );
                }
                if all {
                    break;
                }
                ensure!(Instant::now() < end, "inventory stop timeout");
                thread::sleep(Duration::from_millis(2));
            }
            stopped.insert(pid, fd);
            added = true;
        }
        if !added {
            break;
        }
    }
    save(
        "inventory-quiescence",
        json!({"all_untrusted_including_controller_stopped_before_inventory":true,"sigcont_blocked_for_untrusted_peers":true,"pids":stopped.keys().collect::<Vec<_>>(),"single_identity_snapshot_for_policy_and_audit":true}),
    )?;
    Ok(stopped.into_values().collect())
}
fn identity() -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read("/guest/identity.json")?)?)
}
fn validate(i: &Value) -> Result<u32> {
    let pid = i["pid"].as_u64().context("controller")? as u32;
    ensure!(
        persistent::start_tick(pid)? == i["start"].as_str().context("start")?,
        "controller identity changed"
    );
    let m = fs::metadata(format!("/proc/{pid}/exe"))?;
    let s = fs::metadata("/lab/native.sock")?;
    ensure!(
        json!(m.dev()) == i["exe_dev"]
            && json!(m.ino()) == i["exe_ino"]
            && json!(s.dev()) == i["socket_dev"]
            && json!(s.ino()) == i["socket_ino"],
        "image/socket identity changed"
    );
    persistent::bound_paths()?;
    Ok(pid)
}
fn bus(args: &[String]) -> Result<()> {
    let o = Command::new("/usr/bin/busctl")
        .args([
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
        ])
        .args(args)
        .output()?;
    ensure!(
        o.status.success(),
        "scope: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(())
}
fn attach(pid: u32) -> Result<()> {
    if !fs::read_to_string(format!("/proc/{pid}/cgroup"))?.contains(SCOPE) {
        bus(&[
            SCOPE.into(),
            "fail".into(),
            "2".into(),
            "PIDs".into(),
            "au".into(),
            "1".into(),
            pid.to_string(),
            "Description".into(),
            "s".into(),
            "Isolated preserved controller".into(),
            "0".into(),
        ])?;
    }
    ensure!(show(SCOPE)?["ActiveState"] == "active", "scope inactive");
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?.contains(SCOPE),
        "scope attachment missing"
    );
    Ok(())
}
fn open_pipe(parent: u32, pid: u32, fd: u32) -> Result<File> {
    let target = fs::read_link(format!("/proc/{pid}/fd/{fd}"))?;
    ensure!(target.to_string_lossy().starts_with("pipe:["), "not a pipe");
    for e in fs::read_dir(format!("/proc/{parent}/fd"))? {
        let p = e?.path();
        if fs::read_link(&p)? != target {
            continue;
        }
        let info = fs::read_to_string(format!(
            "/proc/{parent}/fdinfo/{}",
            p.file_name().context("fd")?.to_string_lossy()
        ))?;
        let flags = u32::from_str_radix(
            info.lines()
                .find_map(|s| s.strip_prefix("flags:\t"))
                .context("flags")?,
            8,
        )?;
        if flags & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32 {
            continue;
        }
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(p)?;
        ensure!(
            f.metadata()?.ino() == fs::metadata(format!("/proc/{pid}/fd/{fd}"))?.ino(),
            "pipe changed"
        );
        return Ok(f);
    }
    bail!("reader fd missing")
}
pub fn reader() -> Result<()> {
    let i = identity()?;
    let parent = i["parent"].as_u64().context("parent")? as u32;
    let pid = i["pid"].as_u64().context("pid")? as u32;
    let mut handles = vec![];
    let mut inos = vec![];
    for fd in [1, 2] {
        let mut f = open_pipe(parent, pid, fd)?;
        inos.push(f.metadata()?.ino());
        handles.push(thread::spawn(move || -> Result<()> {
            let mut out = OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("/lab/pipe-{fd}.trace"))?;
            let mut buf = [0; 8192];
            loop {
                match f.read(&mut buf) {
                    Ok(0) => bail!("pipe EOF"),
                    Ok(n) => {
                        out.write_all(&buf[..n])?;
                        out.flush()?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }));
    }
    save(
        "readers-ready",
        json!({"pid":std::process::id(),"controller":pid,"pipe_inodes":inos}),
    )?;
    loop {
        ensure!(
            handles.iter().all(|h| !h.is_finished()),
            "reader thread failed"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn checkpoint(stage: &str, cut: &str) -> Result<()> {
    fs::write("/guest/transition-stage", stage)?;
    File::open("/guest/transition-stage")?.sync_all()?;
    if stage == cut {
        unsafe {
            libc::raise(libc::SIGKILL);
        };
        bail!("cut failed");
    }
    Ok(())
}
fn readers_alive() -> Result<()> {
    let i: Value = serde_json::from_slice(&fs::read("/lab/readers-ready.json")?)?;
    let state = show("a2lab-reader.service")?;
    ensure!(
        state["ActiveState"] == "active"
            && state["MainPID"]
                .as_str()
                .context("reader PID")?
                .parse::<u64>()?
                == i["pid"].as_u64().context("saved reader")?,
        "readers not active"
    );
    let pid = i["pid"].as_u64().unwrap() as u32;
    ensure!(
        persistent::ids_in(Path::new(&format!("/proc/{pid}/task")))?.len() >= 3,
        "reader threads missing"
    );
    Ok(())
}
fn close_old(pid: u32) -> Result<()> {
    let mut closed = vec![];
    for p in persistent::old_live(pid)? {
        let before = persistent::start_tick(p)?;
        let fd = persistent::pidfd(p)?;
        ensure!(
            persistent::start_tick(p)? == before && persistent::untrusted_process(p)?,
            "retirement identity changed"
        );
        persistent::signal(&fd, libc::SIGSTOP)?;
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut stopped = true;
            for tid in persistent::ids_in(Path::new(&format!("/proc/{p}/task")))? {
                let (_, s) =
                    persistent::status_at(Path::new(&format!("/proc/{p}/task/{tid}/status")))?;
                stopped &= matches!(s, 'T' | 't' | 'Z' | 'X');
            }
            if stopped {
                break;
            }
            ensure!(Instant::now() < end, "stop timeout");
            thread::sleep(Duration::from_millis(5));
        }
        closed.push((p, fd));
    }
    save(
        "stopped-integrated",
        json!({"pids":closed.iter().map(|(p,_)|*p).collect::<Vec<_>>(),"holders":persistent::holders()?}),
    )?;
    for (_, fd) in &closed {
        persistent::signal(fd, libc::SIGKILL)?;
    }
    for (_, fd) in &closed {
        wait("retired pidfd", || persistent::dead(fd))?;
    }
    integrated::ctl(&["stop", OLD])?;
    persistent::ready(pid)?;
    save(
        "closed-integrated",
        json!({"closed_pids":closed.iter().map(|(p,_)|*p).collect::<Vec<_>>(),"pidfds_terminal":true,"old_live":persistent::old_live(pid)?,"holders":persistent::holders()?,"old_unit":show(OLD)?}),
    )
}
fn permit_successor() -> Result<()> {
    persistent::own_tree(Path::new("/lab/state"))?;
    fs::create_dir_all("/lab/new-codex")?;
    ensure!(
        unsafe {
            libc::chown(
                cs("/lab/new-codex").as_ptr(),
                persistent::NEW_UID,
                persistent::NEW_UID,
            )
        } == 0,
        "new CODEX_HOME"
    );
    ensure!(
        unsafe { libc::chown(cs(P).as_ptr(), 0, 0) } == 0,
        "lab root"
    );
    fs::set_permissions(P, fs::Permissions::from_mode(0o711))?;
    let socket = fs::canonicalize("/lab/native.sock")?;
    ensure!(
        socket.starts_with("/tmp") || socket.starts_with("/lab"),
        "guest socket anchor"
    );
    ensure!(
        unsafe {
            libc::chown(
                cs(socket.to_str().context("socket")?).as_ptr(),
                UID,
                persistent::NEW_UID,
            )
        } == 0,
        "socket group"
    );
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))?;
    let anchor = if socket.starts_with("/tmp") {
        Path::new("/tmp")
    } else {
        Path::new("/lab")
    };
    let mut current = socket.parent();
    while let Some(p) = current {
        if p == anchor {
            break;
        }
        ensure!(p.starts_with(anchor), "anchor");
        let m = fs::metadata(p)?;
        ensure!(
            unsafe {
                libc::chown(
                    cs(p.to_str().context("dir")?).as_ptr(),
                    u32::MAX,
                    persistent::NEW_UID,
                )
            } == 0,
            "socket traverse"
        );
        fs::set_permissions(p, fs::Permissions::from_mode((m.mode() & 0o777) | 0o010))?;
        current = p.parent();
    }
    Ok(())
}
pub fn resume(cut: &str) -> Result<()> {
    let i = identity()?;
    let pid = validate(&i)?;
    let phase = fs::read_to_string("/guest/transition-stage").unwrap_or_default();
    if phase.is_empty() {
        arm(63)?;
        service(
            "a2lab-reader.service",
            "/guest/vm-probe",
            "role reader",
            0,
            false,
            "none",
        )?;
        wait("readers ready", || {
            Path::new("/lab/readers-ready.json").exists()
        })?;
        readers_alive()?;
        attach(pid)?;
        checkpoint("scope-attached", cut)?;
    }
    attach(pid)?;
    readers_alive()?;
    validate(&i)?;
    if !Path::new("/guest/domain-closed").exists() {
        close_old(pid)?;
        fs::write("/guest/domain-closed", b"verified")?;
        checkpoint("before-ownership", cut)?;
    }
    persistent::ready(pid)?;
    readers_alive()?;
    permit_successor()?;
    persistent::ready(pid)?;
    validate(&i)?;
    checkpoint("ownership-transferred", cut)?;
    arm(55)?;
    service(
        NEW,
        "/guest/new-wake",
        "receiver",
        persistent::NEW_UID,
        false,
        cut,
    )?;
    ensure!(show(NEW)?["ActiveState"] == "active", "successor inactive");
    fs::write(
        "/guest/activation-receipt",
        b"closed domain; successor active",
    )?;
    checkpoint("activated", cut)
}
pub fn finish(
    mut ws: WebSocket<UnixStream>,
    pid: u32,
    mut loader: std::process::Child,
) -> Result<()> {
    let d = db()?;
    let uncertain = persistent::uncertain(&d)?;
    // All fixture-admitted requests have explicit response and completion receipts.
    fs::write("/lab/held-release", b"drain")?;
    wait("admitted completion", || {
        Path::new("/lab/held-result.json").exists()
    })?;
    ensure!(
        read("held-result")?["completion_persisted"] == true,
        "drain failed"
    );
    d.execute_batch("BEGIN EXCLUSIVE")?;
    arm(23)?;
    d.execute_batch("COMMIT")?;
    drop(d);
    loader.kill()?;
    loader.wait()?;
    let mut cuts = vec![];
    for cut in [
        "scope-attached",
        "before-ownership",
        "ownership-transferred",
        "successor-unit-partial",
        "successor-unit-written",
        "successor-reloaded",
        "successor-started",
    ] {
        let mut c = Command::new("/guest/vm-probe")
            .args(["role", "transition", cut])
            .spawn()?;
        let status = c.wait()?;
        use std::os::unix::process::ExitStatusExt;
        ensure!(
            status.signal() == Some(libc::SIGKILL),
            "interruption not reached {cut}: {status}"
        );
        ensure!(validate(&identity()?)? == pid, "controller changed");
        ensure!(
            !Path::new("/guest/activation-receipt").exists(),
            "activated prematurely"
        );
        ensure!(
            fs::metadata("/lab/state/codex-wake/state.sqlite3")?.uid()
                == if (cut == "ownership-transferred" || cut.starts_with("successor-")) {
                    persistent::NEW_UID
                } else {
                    UID
                },
            "ownership changed before closure checkpoint"
        );
        ensure!(
            rpc(
                &mut ws,
                40 + cuts.len() as i64,
                "thread/loaded/list",
                json!({})
            )?["data"]
                .is_array(),
            "WS lost at interruption"
        );
        cuts.push(json!({"stage":cut,"coordinator_sigkill":true,"same_websocket":true,"activation_absent":true,"expected_owner":if (cut == "ownership-transferred" || cut.starts_with("successor-")) {persistent::NEW_UID} else {UID}}));
    }
    let status = Command::new("/guest/vm-probe")
        .args(["role", "transition", "none"])
        .status()?;
    ensure!(status.success(), "resume failed");
    validate(&identity()?)?;
    readers_alive()?;
    let successor = show(NEW)?;
    let successor_pid: u32 = successor["MainPID"]
        .as_str()
        .context("successor PID")?
        .parse()?;
    ensure!(
        persistent::status_at(Path::new(&format!("/proc/{successor_pid}/status")))?.0
            == vec![persistent::NEW_UID; 4],
        "successor credentials"
    );
    let exe = fs::metadata(format!("/proc/{successor_pid}/exe"))?;
    let expected = fs::metadata("/guest/new-wake")?;
    ensure!(
        (exe.dev(), exe.ino()) == (expected.dev(), expected.ino()),
        "successor image changed"
    );
    ensure!(
        Command::new("/guest/vm-probe")
            .args(["role", "transition", "none"])
            .status()?
            .success(),
        "idempotent resume"
    );
    ensure!(
        show(NEW)?["InvocationID"] == successor["InvocationID"]
            && show(NEW)?["MainPID"] == successor["MainPID"],
        "resume restarted successor"
    );
    let mut invalid = identity()?;
    invalid["start"] = json!("wrong-start");
    ensure!(
        validate(&invalid).is_err(),
        "controller start identity accepted"
    );
    let mut invalid = identity()?;
    invalid["exe_ino"] = json!(0);
    ensure!(
        validate(&invalid).is_err(),
        "controller image identity accepted"
    );
    let mut invalid = identity()?;
    invalid["socket_ino"] = json!(0);
    ensure!(
        validate(&invalid).is_err(),
        "controller socket identity accepted"
    );
    save(
        "successor-identity",
        json!({"pid":successor_pid,"all_four_credentials":persistent::NEW_UID,"expected_image_inode":expected.ino(),"same_invocation_on_repeated_resume":true,"controller_identity_negative_checks":3}),
    )?;
    let mut command = wake(
        "/guest/new-wake",
        &[
            "subscribe",
            "--kind",
            "artifact",
            "--repo",
            "isolated",
            "--resource",
            "approved-new",
            "--event",
            "available",
            "--thread",
            THREAD,
        ],
    );
    let o = command
        .uid(persistent::NEW_UID)
        .gid(persistent::NEW_UID)
        .output()?;
    ensure!(
        o.status.success(),
        "new write: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let o = Command::new("/guest/vm-probe")
        .args(["actor", "persistent-new-rpc"])
        .uid(persistent::NEW_UID)
        .gid(persistent::NEW_UID)
        .output()?;
    ensure!(
        o.status.success(),
        "new RPC: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let exec = rpc(
        &mut ws,
        100,
        "command/exec",
        json!({"command":["/usr/bin/true"],"cwd":"/lab","sandboxPolicy":{"type":"dangerFullAccess"},"timeoutMs":3000}),
    )?;
    ensure!(exec["exitCode"] == 0, "approved exec");
    let escaped = rpc(
        &mut ws,
        101,
        "command/exec",
        json!({"command":["/guest/legacy","status"],"cwd":"/lab","sandboxPolicy":{"type":"dangerFullAccess"},"timeoutMs":3000}),
    );
    ensure!(escaped.is_err(), "legacy exec escaped");
    // Exercise the actual retained pipes after their original reader has died.
    for fd in [1, 2] {
        let mut f = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/fd/{fd}"))?;
        for _ in 0..32 {
            f.write_all(&[b'p'; 8192])?;
        }
    }
    wait("retained pipe readers", || {
        [1, 2].iter().all(|fd| {
            fs::metadata(format!("/lab/pipe-{fd}.trace")).is_ok_and(|m| m.len() >= 262144)
        })
    })?;
    let d = db()?;
    ensure!(
        persistent::uncertain(&d)? == uncertain,
        "uncertain row changed"
    );
    let integrity: String = d.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure!(integrity == "ok", "integrity");
    let old = show(OLD)?;
    ensure!(
        matches!(old["ActiveState"].as_str(), Some("inactive" | "failed"))
            && old["MainPID"] == "0"
            && old["ControlGroup"] == "",
        "old unit active"
    );
    persistent::ready(pid)?;
    save(
        "transition-result",
        json!({"passed":true,"systemd_pid1":true,"old_unit":old,"scope":show(SCOPE)?,"new_unit":show(NEW)?,"same_controller_pid":pid,"same_controller_start":persistent::start_tick(pid)?,"same_open_websocket":true,"retained_readers_after_old_parent_death":true,"pipe_bytes_each_minimum":262144,"interruptions":cuts,"known_admitted_response_drained":true,"uncertain_sending_row_unchanged":true,"uncertain_delivery_attempts_measured":false,"new_uid":persistent::NEW_UID,"successor_write_and_rpc":true,"legacy_exec_denied_after_loader_death":true,"integrity":integrity,"denial_counters":persistent::counts()?,"production_migration_qualified":false}),
    )?;
    Ok(())
}
