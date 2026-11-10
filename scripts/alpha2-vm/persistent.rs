use super::*;
use anyhow::Context;
use std::{
    collections::BTreeSet,
    os::fd::{FromRawFd, OwnedFd},
};
pub const NEW_UID: u32 = 40001;
pub const FOREIGN_UID: u32 = 40002;
const SIDE: &str = "/lab/state/codex-wake/state.sqlite3-mmap-probe";
#[repr(C)]
struct Identity {
    dev: u64,
    ino: u64,
}
pub fn configure_maps(o: *mut libc::c_void) -> Result<()> {
    let m = unsafe { bpf_object__find_map_by_name(o, cs("allowed_exec").as_ptr()) };
    ensure!(!m.is_null(), "allowed_exec map");
    for (k, p) in [
        "/usr/bin/true",
        "/usr/bin/bash",
        "/usr/bin/bwrap",
        "/usr/bin/false",
    ]
    .iter()
    .enumerate()
    {
        let meta = fs::metadata(p)?;
        ensure!(
            meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "mutable helper: {p}"
        );
        let v = Identity {
            dev: dev(&meta),
            ino: meta.ino(),
        };
        ensure!(
            unsafe {
                bpf_map_update_elem(
                    bpf_map__fd(m),
                    (&(k as u32) as *const u32).cast(),
                    (&v as *const Identity).cast(),
                    0,
                )
            } == 0,
            "helper {p}"
        );
    }
    Ok(())
}
pub fn capture_inventory() -> Result<()> {
    let mut inventory = fs::read_dir("/lab/state/codex-wake")?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    inventory.extend([
        Path::new("/lab/state").to_path_buf(),
        Path::new("/lab/state/codex-wake").to_path_buf(),
    ]);
    ensure!(inventory.len() <= 64, "inventory capacity");
    let mut frozen = vec![];
    let fd = map("protected_inodes")?;
    for (k, p) in inventory.iter().enumerate() {
        let m = fs::metadata(p)?;
        let v = Identity {
            dev: dev(&m),
            ino: m.ino(),
        };
        frozen.push(json!({"path":p,"dev":v.dev,"ino":v.ino}));
        ensure!(
            unsafe {
                bpf_map_update_elem(
                    fd,
                    (&(k as u32) as *const u32).cast(),
                    (&v as *const Identity).cast(),
                    0,
                )
            } == 0,
            "inventory {}",
            p.display()
        );
    }
    unsafe { libc::close(fd) };
    fs::write(
        "/guest/protected-inodes.json",
        serde_json::to_vec_pretty(&frozen)?,
    )?;
    fs::set_permissions(
        "/guest/protected-inodes.json",
        fs::Permissions::from_mode(0o600),
    )?;
    bound_paths()
}
fn remain() -> Result<()> {
    loop {
        thread::sleep(Duration::from_millis(50))
    }
}
fn mapped(prot: i32) -> Result<*mut libc::c_void> {
    let f = OpenOptions::new().read(true).write(true).open(SIDE)?;
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            8192,
            prot,
            libc::MAP_SHARED,
            f.as_raw_fd(),
            0,
        )
    };
    ensure!(p != libc::MAP_FAILED, "initial mapping");
    drop(f);
    Ok(p)
}
pub fn actor(mode: &str) -> Result<()> {
    match mode {
        "persistent-foreign" => {
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    8192,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    0,
                    0,
                )
            };
            ensure!(ptr != libc::MAP_FAILED, "foreign inherited fd mapping");
            unsafe {
                libc::close(0);
            }
            println!("FOREIGN_READY={}", std::process::id());
            remain()
        }
        "persistent-family" => {
            let ptr = mapped(libc::PROT_READ | libc::PROT_WRITE)?;
            let child = unsafe { libc::fork() };
            ensure!(child >= 0, "pre-fence fork");
            if child == 0 {
                fs::write("/lab/family-child-ready", std::process::id().to_string())?;
                wait("inherited mapping write", || {
                    Path::new("/lab/family-write").exists()
                })?;
                unsafe {
                    (ptr as *mut u8).add(4096).write_volatile(165);
                    ensure!(libc::msync(ptr, 8192, libc::MS_SYNC) == 0, "family msync");
                }
                fs::write("/lab/family-wrote", b"165")?;
                remain()
            } else {
                save(
                    "family",
                    json!({"parent":std::process::id(),"child":child,"file_descriptor_closed":true}),
                )?;
                remain()
            }
        }
        "persistent-mapchecks" => {
            let ptr = mapped(libc::PROT_READ)?;
            fs::write("/lab/mapchecks-ready", b"ready")?;
            wait("mapchecks release", || {
                Path::new("/lab/mapchecks-release").exists()
            })?;
            let m = unsafe { libc::mprotect(ptr, 8192, libc::PROT_READ | libc::PROT_WRITE) };
            let me = std::io::Error::last_os_error().raw_os_error();
            ensure!(m < 0 && me == Some(libc::EACCES), "mprotect bypass {me:?}");
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/lab/map-alias")?;
            let fresh = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    8192,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    f.as_raw_fd(),
                    0,
                )
            };
            let fe = std::io::Error::last_os_error().raw_os_error();
            ensure!(
                fresh == libc::MAP_FAILED && fe == Some(libc::EACCES),
                "new shared mapping bypass {fe:?}"
            );
            let private = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    8192,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE,
                    f.as_raw_fd(),
                    0,
                )
            };
            ensure!(
                private != libc::MAP_FAILED,
                "private map must remain usable"
            );
            unsafe {
                (private as *mut u8).add(5000).write_volatile(77);
                libc::munmap(private, 8192);
            }
            drop(f);
            save(
                "mapchecks",
                json!({"mprotect_errno":me,"new_shared_alias_mmap_errno":fe,"private_mapping_allowed":true,"readonly_mapping_retained":true}),
            )?;
            remain()
        }
        "persistent-memfd" => {
            let fd = unsafe { libc::memfd_create(cs("legacy-copy").as_ptr(), 0) };
            ensure!(fd >= 0, "memfd");
            let mut f = unsafe { File::from_raw_fd(fd) };
            use std::io::Write;
            f.write_all(&fs::read("/guest/legacy")?)?;
            fs::write("/lab/memfd-ready", b"ready")?;
            wait("memfd exec", || Path::new("/lab/memfd-release").exists())?;
            let arg = cs("legacy");
            let args = [arg.as_ptr(), std::ptr::null()];
            let vars = [std::ptr::null()];
            let rc = unsafe { libc::fexecve(fd, args.as_ptr(), vars.as_ptr()) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            ensure!(
                rc < 0 && errno == Some(libc::EACCES),
                "memfd executable escaped"
            );
            save("memfd", json!({"denied":true,"errno":errno}))
        }
        "persistent-fork" => {
            fs::write("/lab/fork-ready", b"ready")?;
            wait("fork seal", || Path::new("/lab/fork-release").exists())?;
            let renamed = unsafe {
                libc::rename(cs("/lab/state").as_ptr(), cs("/lab/renamed-state").as_ptr())
            };
            let rename_errno = std::io::Error::last_os_error().raw_os_error();
            ensure!(
                renamed < 0 && rename_errno == Some(libc::EACCES),
                "protected parent rename escaped"
            );
            ensure!(
                map("armed").is_err(),
                "untrusted actor opened policy control map"
            );
            let rc = unsafe { libc::fork() };
            let errno = std::io::Error::last_os_error().raw_os_error();
            if rc == 0 {
                unsafe { libc::_exit(43) }
            }
            ensure!(rc < 0 && errno == Some(libc::EPERM), "fork not fenced");
            save(
                "fork",
                json!({"denied":true,"errno":errno,"untrusted_control_map_open_denied":true,"protected_parent_rename_errno":rename_errno}),
            )?;
            remain()
        }
        "persistent-new-rpc" => {
            let (mut ws, pid) = connect()?;
            let r = rpc(&mut ws, 80, "thread/loaded/list", json!({}))?;
            ensure!(r["data"].is_array(), "successor RPC");
            println!("NEW_RPC_OK={pid}");
            Ok(())
        }
        _ => bail!("persistent actor"),
    }
}
pub(super) fn counts() -> Result<[u64; 7]> {
    let fd = map("counters")?;
    let mut v = [0u64; 7];
    ensure!(
        unsafe { bpf_map_lookup_elem(fd, (&0u32 as *const u32).cast(), v.as_mut_ptr().cast()) }
            == 0,
        "counts"
    );
    unsafe { libc::close(fd) };
    Ok(v)
}
pub(super) fn pidfd(pid: u32) -> Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    ensure!(fd >= 0, "pidfd {pid}: {}", std::io::Error::last_os_error());
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
pub(super) fn signal(fd: &OwnedFd, sig: i32) -> Result<()> {
    ensure!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } == 0,
        "pidfd signal: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
pub(super) fn dead(fd: &OwnedFd) -> bool {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, 0) > 0 && (p.revents & libc::POLLIN) != 0 }
}
fn status(pid: u32) -> Result<(Vec<u32>, char)> {
    status_at(Path::new(&format!("/proc/{pid}/status")))
}
pub(super) fn status_at(path: &Path) -> Result<(Vec<u32>, char)> {
    let s = fs::read_to_string(path)?;
    let ids = s
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .context("missing Uid")?
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<Vec<u32>, _>>()?;
    ensure!(ids.len() == 4, "four credentials required");
    let state = s
        .lines()
        .find_map(|l| l.strip_prefix("State:"))
        .context("missing state")?
        .trim()
        .chars()
        .next()
        .context("empty state")?;
    Ok((ids, state))
}
fn all_pids() -> Result<Vec<u32>> {
    ids_in(Path::new("/proc"))
}
pub fn checked_ids(
    entries: impl Iterator<Item = std::io::Result<std::ffi::OsString>>,
) -> Result<Vec<u32>> {
    let mut ids = vec![];
    for entry in entries {
        if let Ok(id) = entry?.to_string_lossy().parse() {
            ids.push(id);
        }
    }
    Ok(ids)
}
pub(super) fn ids_in(path: &Path) -> Result<Vec<u32>> {
    checked_ids(fs::read_dir(path)?.map(|e| e.map(|e| e.file_name())))
}
fn trusted(ids: &[u32]) -> bool {
    ids.len() == 4 && (ids.iter().all(|u| *u == 0) || ids.iter().all(|u| *u == NEW_UID))
}
fn gone(pid: u32) -> Result<bool> {
    match fs::metadata(format!("/proc/{pid}")) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
pub(super) fn untrusted_process(pid: u32) -> Result<bool> {
    for tid in ids_in(Path::new(&format!("/proc/{pid}/task")))? {
        let (ids, s) = status_at(Path::new(&format!("/proc/{pid}/task/{tid}/status")))?;
        if !trusted(&ids) && !matches!(s, 'Z' | 'X') {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(super) fn old_live(native: u32) -> Result<Vec<u32>> {
    let mut pids = vec![];
    for pid in all_pids()? {
        if pid == native {
            continue;
        }
        match untrusted_process(pid) {
            Ok(true) => pids.push(pid),
            Ok(false) => {}
            Err(_) if gone(pid)? => {}
            Err(e) => return Err(e),
        }
    }
    Ok(pids)
}
fn keys() -> Result<BTreeSet<(u64, u64)>> {
    if Path::new("/guest/protected-inodes.json").exists() {
        let frozen: Value = serde_json::from_slice(&fs::read("/guest/protected-inodes.json")?)?;
        return frozen
            .as_array()
            .context("inode inventory")?
            .iter()
            .map(|v| {
                Ok((
                    v["dev"].as_u64().context("dev")?,
                    v["ino"].as_u64().context("ino")?,
                ))
            })
            .collect();
    }
    fs::read_dir("/lab/state/codex-wake")?
        .map(|e| {
            let m = fs::metadata(e?.path())?;
            Ok((dev(&m), m.ino()))
        })
        .collect()
}
pub(super) fn bound_paths() -> Result<()> {
    let fd = map("policy_cfg")?;
    let mut c: Cfg = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        bpf_map_lookup_elem(
            fd,
            (&0u32 as *const u32).cast(),
            (&mut c as *mut Cfg).cast(),
        )
    };
    unsafe { libc::close(fd) };
    ensure!(ok == 0, "config binding lookup");
    let dir = fs::metadata("/lab/state/codex-wake")?;
    let main = fs::metadata("/lab/state/codex-wake/state.sqlite3")?;
    ensure!(
        dir.ino() == c.directory
            && dev(&dir) == c.dev
            && main.ino() == c.database
            && dev(&main) == c.dev,
        "protected database path was substituted"
    );
    Ok(())
}

fn maps_for(pid: u32, protected: &BTreeSet<(u64, u64)>) -> Result<Vec<String>> {
    let text = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut found = vec![];
    for l in text.lines() {
        let f: Vec<_> = l.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let (devmajor, devminor) = f[3].split_once(':').context("map dev")?;
        let dv = (u64::from_str_radix(devmajor, 16)? << 20) | u64::from_str_radix(devminor, 16)?;
        let ino = f[4].parse()?;
        if protected.contains(&(dv, ino)) {
            found.push(l.to_owned())
        }
    }
    Ok(found)
}
pub(super) fn holders() -> Result<Vec<Value>> {
    let keys = keys()?;
    let mut out = vec![];
    for pid in all_pids()? {
        let (ids, state) = match status(pid) {
            Ok(x) => x,
            Err(_) if gone(pid)? => continue,
            Err(e) => return Err(e.into()),
        };
        if !untrusted_process(pid)? || matches!(state, 'Z' | 'X') {
            continue;
        }
        let mappings = match maps_for(pid, &keys) {
            Ok(v) => v,
            Err(_) if gone(pid)? => continue,
            Err(e) => return Err(e.into()),
        };
        if !mappings.is_empty() {
            out.push(json!({"pid":pid,"uid":ids,"maps":mappings}))
        }
    }
    Ok(out)
}
pub fn native_clean(pid: u32) -> Result<()> {
    let protected = keys()?;
    ensure!(
        maps_for(pid, &protected)?.is_empty(),
        "preserved controller owns protected mappings; cannot retire it"
    );
    for tid in ids_in(Path::new(&format!("/proc/{pid}/task")))? {
        for e in fs::read_dir(format!("/proc/{pid}/task/{tid}/fd"))? {
            let e = e?;
            match fs::metadata(e.path()) {
                Ok(m) => ensure!(
                    !protected.contains(&(dev(&m), m.ino())),
                    "controller holds protected fd"
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}
pub(super) fn ready(native: u32) -> Result<()> {
    ensure!(
        old_live(native)?.is_empty(),
        "old process domain not closed"
    );
    ensure!(holders()?.is_empty(), "protected mappings remain");
    bound_paths()?;
    native_clean(native)
}
fn exec_test(ws: &mut WebSocket<UnixStream>, id: i64, command: Value) -> Result<Value> {
    let before = counts()?[3];
    let started = Instant::now();
    let answer = rpc(
        ws,
        id,
        "command/exec",
        json!({"command":command,"cwd":"/lab","sandboxPolicy":{"type":"dangerFullAccess"},"timeoutMs":3000}),
    );
    let record = match answer {
        Ok(r) => {
            ensure!(r["exitCode"] != 0, "legacy command ran: {r}");
            json!({"response":r})
        }
        Err(e) => {
            let t = e.to_string();
            ensure!(
                t.contains("Permission denied") || t.contains("permission denied"),
                "unexpected RPC failure {t}"
            );
            json!({"rpc_error":t})
        }
    };
    ensure!(
        counts()?[3] > before,
        "denial did not originate at exec seal"
    );
    ensure!(
        started.elapsed() < Duration::from_secs(5),
        "exec denial timed out"
    );
    Ok(record)
}
pub(super) fn own_tree(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink() {
        use std::os::unix::fs::FileTypeExt;
        ensure!(
            path == Path::new("/lab/state/codex-wake/app-server.sock")
                && fs::canonicalize(path)? == fs::canonicalize("/lab/native.sock")?
                && fs::metadata(path)?.file_type().is_socket(),
            "unexpected state symlink"
        );
        ensure!(
            unsafe {
                libc::lchown(
                    cs(path.to_str().context("socket link")?).as_ptr(),
                    NEW_UID,
                    NEW_UID,
                )
            } == 0,
            "socket link owner"
        );
        return Ok(());
    }
    if m.is_dir() {
        for e in fs::read_dir(path)? {
            own_tree(&e?.path())?
        }
    }
    let c = cs(path.to_str().context("path")?);
    ensure!(
        unsafe { libc::chown(c.as_ptr(), NEW_UID, NEW_UID) } == 0,
        "new state owner"
    );
    Ok(())
}
pub(super) fn start_tick(pid: u32) -> Result<String> {
    Ok(fs::read_to_string(format!("/proc/{pid}/stat"))?
        .split(") ")
        .last()
        .context("stat")?
        .split_whitespace()
        .nth(19)
        .context("start")?
        .to_owned())
}
pub(super) fn uncertain(d: &Connection) -> Result<String> {
    Ok(d.query_row("SELECT json_object('id',id,'state',state,'reason',reason,'source_json',source_json,'source_event_key',source_event_key,'thread',thread) FROM subscriptions WHERE resource='sentinel'",[],|r|r.get(0))?)
}
pub fn suite() -> Result<()> {
    guard()?;
    for p in [P, "/lab/codex", "/lab/tmp"] {
        fs::create_dir_all(p)?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
        ensure!(
            unsafe { libc::chown(cs(p).as_ptr(), UID, UID) } == 0,
            "fixture owner"
        );
    }
    ensure!(
        subscribe("/guest/legacy", "sentinel").status.success(),
        "seed"
    );
    let d = db()?;
    d.execute_batch("CREATE TABLE fixture_writes(label TEXT);UPDATE subscriptions SET state='sending',reason='fixture outcome unknown - never retry',source_json='{\"fixture\":true}',source_event_key='uncertain-one' WHERE resource='sentinel'")?;
    let uncertain_before = uncertain(&d)?;
    let f = File::create(SIDE)?;
    f.set_len(8192)?;
    ensure!(
        unsafe { libc::chown(cs(SIDE).as_ptr(), UID, UID) } == 0,
        "side owner"
    );
    fs::hard_link(SIDE, "/lab/map-alias")?;
    fs::copy("/guest/legacy", "/lab/legacy-copy")?;
    fs::set_permissions("/lab/legacy-copy", fs::Permissions::from_mode(0o755))?;
    fs::hard_link("/guest/legacy", "/lab/legacy-hardlink")?;
    let mut native = wake(
        "/guest/codex",
        &["app-server", "--listen", "unix:///lab/native.sock"],
    )
    .stdout(Stdio::null())
    .stderr(Stdio::from(File::create("/lab/native.stderr")?))
    .spawn()?;
    wait("native ready", || {
        UnixStream::connect("/lab/native.sock").is_ok()
    })?;
    let (mut ws, pid) = connect()?;
    ensure!(native.id() == pid, "direct native PID");
    let start = start_tick(pid)?;
    native_clean(pid)?;
    let mut receiver = wake("/guest/legacy", &["receiver"])
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create("/lab/receiver.stderr")?))
        .spawn()?;
    let mut actors = vec![
        child("socket")?,
        child("held")?,
        child("persistent-family")?,
        child("persistent-mapchecks")?,
        child("persistent-memfd")?,
        child("persistent-fork")?,
    ];
    for file in [
        "socket-ready",
        "held-ready",
        "family.json",
        "family-child-ready",
        "mapchecks-ready",
        "memfd-ready",
        "fork-ready",
    ] {
        wait(file, || Path::new(&format!("/lab/{file}")).exists())?;
    }
    let foreign = Command::new("/guest/vm-probe")
        .args(["actor", "persistent-foreign"])
        .uid(FOREIGN_UID)
        .gid(FOREIGN_UID)
        .stdin(Stdio::from(
            OpenOptions::new().read(true).write(true).open(SIDE)?,
        ))
        .stdout(Stdio::from(File::create("/lab/foreign.stdout")?))
        .spawn()?;
    let foreign_pid = foreign.id();
    actors.push(foreign);
    wait("foreign ready", || {
        fs::read_to_string("/lab/foreign.stdout").is_ok_and(|s| s.contains("FOREIGN_READY"))
    })?;
    let original_holders = holders()?;
    ensure!(
        original_holders.iter().any(|v| v["pid"] == foreign_pid),
        "foreign map not inventoried"
    );
    ensure!(
        original_holders.len() >= 3,
        "missing parent, child or readonly mapping"
    );
    save("holders-before", json!(original_holders))?;
    let mut loader = Command::new("/guest/vm-probe")
        .args(["load", &pid.to_string()])
        .spawn()?;
    wait("policy ready", || Path::new("/lab/policy-ready").exists())?;
    arm(1)?;
    fs::write("/lab/socket-release", b"deny")?;
    wait("old socket denied", || {
        Path::new("/lab/socket-result.json").exists()
    })?;
    ensure!(
        read("socket-result")?["blocked"] == true,
        "old socket escaped"
    );
    fs::write("/lab/held-release", b"finish admitted")?;
    wait("admitted completion", || {
        Path::new("/lab/held-result.json").exists()
    })?;
    ensure!(
        read("held-result")?["completion_persisted"] == true,
        "lost admitted completion"
    );
    d.execute_batch("BEGIN EXCLUSIVE")?;
    arm(7)?;
    d.execute_batch("COMMIT")?;
    loader.kill()?;
    loader.wait()?;
    println!("VM_STAGE=persistent_exec_and_map_seals_loader_dead");
    let family = read("family")?;
    let parent = family["parent"].as_u64().context("parent")? as u32;
    let childpid = family["child"].as_u64().context("child")? as u32;
    let parentfd = pidfd(parent)?;
    signal(&parentfd, libc::SIGKILL)?;
    wait("parent dead", || dead(&parentfd))?;
    ensure!(
        holders()?.iter().any(|v| v["pid"] == childpid),
        "inherited mapping disappeared unexpectedly"
    );
    fs::write("/lab/family-write", b"write after parent closed")?;
    wait("inherited write", || {
        Path::new("/lab/family-wrote").exists()
    })?;
    ensure!(
        fs::read(SIDE)?[4096] == 165,
        "missing inherited mmap counterexample"
    );
    save(
        "parent-only-insufficient",
        json!({"parent_pidfd_dead":true,"child_pid":childpid,"child_inherited_mapping_survived":true,"post_gate_readback":165,"open_fd_not_required":true}),
    )?;
    let refusal = ready(pid)
        .err()
        .context("activation unexpectedly allowed with live mapper")?;
    save(
        "refusal-before-closure",
        json!({"activation_refused":true,"reason":refusal.to_string(),"remaining_holders":holders()?}),
    )?;
    fs::write("/lab/mapchecks-release", b"try")?;
    wait("mmap denial checks", || {
        Path::new("/lab/mapchecks.json").exists()
    })?;
    fs::write("/lab/memfd-release", b"exec")?;
    wait("memfd denial", || Path::new("/lab/memfd.json").exists())?;
    let mut exec_results = vec![];
    for (id, command) in [
        (100, json!(["/guest/legacy", "status"])),
        (101, json!(["/lab/legacy-copy", "status"])),
        (102, json!(["/lab/legacy-hardlink", "status"])),
        (
            103,
            json!(["/usr/bin/bash", "-c", "exec /guest/legacy status"]),
        ),
    ] {
        exec_results.push(exec_test(&mut ws, id, command)?)
    }
    save("exec-denials-before", json!(exec_results))?;
    let before_foreign = counts()?[3];
    let foreign_exec = wake("/guest/legacy", &["status"])
        .uid(FOREIGN_UID)
        .gid(FOREIGN_UID)
        .spawn();
    ensure!(
        foreign_exec.as_ref().err().and_then(|e| e.raw_os_error()) == Some(libc::EACCES)
            && counts()?[3] > before_foreign,
        "foreign exec bypass"
    );
    save(
        "foreign-exec",
        json!({"uid":FOREIGN_UID,"errno":libc::EACCES,"kernel_counter_increased":true}),
    )?;
    let count = counts()?[3];
    let attempt = rpc(
        &mut ws,
        104,
        "process/spawn",
        json!({"command":["/guest/legacy","status"],"cwd":"/lab","processHandle":"denied-legacy"}),
    );
    ensure!(
        attempt.is_err() && counts()?[3] > count,
        "process/spawn escaped exec policy"
    );
    save(
        "process-spawn-denied",
        json!({"error":attempt.unwrap_err().to_string(),"kernel_exec_counter_increased":true}),
    )?;
    arm(15)?;
    fs::write("/lab/fork-release", b"fork")?;
    wait("fork denial", || Path::new("/lab/fork.json").exists())?;
    let mut closed = vec![];
    for p in old_live(pid)? {
        let before = start_tick(p)?;
        let fd = pidfd(p)?;
        ensure!(
            start_tick(p)? == before
                && !(status(p)?.0.iter().all(|u| *u == 0)
                    || status(p)?.0.iter().all(|u| *u == NEW_UID)),
            "PID identity changed"
        );
        signal(&fd, libc::SIGSTOP)?;
        wait("all threads stopped", || {
            fs::read_dir(format!("/proc/{p}/task")).is_ok_and(|ts| {
                ts.flatten().all(|t| {
                    fs::read_to_string(t.path().join("status")).is_ok_and(|s| {
                        s.lines().any(|l| {
                            l.starts_with("State:") && (l.contains("T (") || l.contains("t ("))
                        })
                    })
                })
            })
        })?;
        closed.push((p, before, fd));
    }
    save(
        "stopped-domain",
        json!({"pids":closed.iter().map(|(p,s,_)|json!({"pid":p,"start":s})).collect::<Vec<_>>(),"holders":holders()?}),
    )?;
    for (_, _, fd) in &closed {
        signal(fd, libc::SIGKILL)?;
    }
    for (_, _, fd) in &closed {
        wait("pidfd terminal", || dead(fd))?;
    }
    ready(pid)?;
    File::open(SIDE)?.sync_all()?;
    let closure = json!({"all_signalled_via_pidfd":true,"all_threads_stopped_before_kill":true,"all_pidfds_terminal":true,"closed_pids":closed.iter().map(|(p,_,_)|*p).collect::<Vec<_>>(),"old_uid_live_except_controller":old_live(pid)?,"remaining_untrusted_mappings":holders()?,"controller_protected_fd_or_mapping":false});
    save("closure", closure.clone())?;
    // The strict task gate stays closed until ownership and activation are audited.
    own_tree(Path::new("/lab/state"))?;
    ensure!(
        unsafe { libc::chown(cs(P).as_ptr(), 0, 0) } == 0,
        "root parent owner"
    );
    fs::set_permissions(P, fs::Permissions::from_mode(0o711))?;
    ensure!(
        unsafe { libc::chown(cs("/lab/native.sock").as_ptr(), UID, NEW_UID) } == 0,
        "successor socket group"
    );
    fs::set_permissions("/lab/native.sock", fs::Permissions::from_mode(0o660))?;
    let socket_path = fs::canonicalize("/lab/native.sock")?;
    println!("VM_NATIVE_SOCKET={}", socket_path.display());
    let socket_anchor = if socket_path.starts_with("/lab") {
        Path::new("/lab")
    } else {
        ensure!(
            socket_path.starts_with("/tmp"),
            "native socket outside guest allowed roots"
        );
        Path::new("/tmp")
    };
    let mut parents = vec![];
    let mut current = socket_path.parent();
    while let Some(dir) = current {
        if dir == socket_anchor {
            break;
        }
        ensure!(
            dir.starts_with(socket_anchor),
            "socket ancestor outside guest anchor"
        );
        let m = fs::metadata(dir)?;
        ensure!(
            unsafe {
                libc::chown(
                    cs(dir.to_str().context("socket ancestor")?).as_ptr(),
                    u32::MAX,
                    NEW_UID,
                )
            } == 0,
            "socket ancestor group"
        );
        fs::set_permissions(dir, fs::Permissions::from_mode((m.mode() & 0o777) | 0o010))?;
        parents.push(dir.to_string_lossy().into_owned());
        current = dir.parent();
    }
    save(
        "socket-access",
        json!({"canonical_socket":socket_path,"group_traverse_added_only_in_guest":parents,"successor_uid":NEW_UID}),
    )?;
    ready(pid)?;
    fs::write(
        "/lab/activation-receipt",
        b"closure verified; no uncertain replay",
    )?;
    arm(7)?;
    println!("VM_STAGE=closed_domain_and_successor_activated");
    let approved = wake(
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
    )
    .uid(NEW_UID)
    .gid(NEW_UID)
    .output()?;
    ensure!(
        approved.status.success(),
        "new generation failed: {}",
        String::from_utf8_lossy(&approved.stderr)
    );
    ensure!(
        d.query_row(
            "SELECT count(*) FROM subscriptions WHERE resource='approved-new'",
            [],
            |r| r.get::<_, i64>(0)
        )? == 1,
        "new write missing"
    );
    let successor = Command::new("/guest/vm-probe")
        .args(["actor", "persistent-new-rpc"])
        .uid(NEW_UID)
        .gid(NEW_UID)
        .output()?;
    ensure!(
        successor.status.success()
            && String::from_utf8_lossy(&successor.stdout).contains("NEW_RPC_OK"),
        "successor socket permissions failed: {}",
        String::from_utf8_lossy(&successor.stderr)
    );
    save(
        "successor",
        json!({"uid":NEW_UID,"write_allowed":true,"rpc":String::from_utf8_lossy(&successor.stdout)}),
    )?;
    let late = exec_test(&mut ws, 105, json!(["/guest/legacy", "status"]))?;
    save("exec-denial-after-activation", late)?;
    let write_denial = rpc(
        &mut ws,
        108,
        "command/exec",
        json!({"command":["/usr/bin/bash","-c","printf forbidden > /lab/state/codex-wake/state.sqlite3-mmap-probe"],"cwd":"/lab","sandboxPolicy":{"type":"dangerFullAccess"},"timeoutMs":3000}),
    )?;
    ensure!(
        write_denial["exitCode"] != 0
            && write_denial["stderr"]
                .as_str()
                .unwrap_or_default()
                .contains("Permission denied"),
        "approved helper bypassed new state ownership"
    );
    save("helper-write-denied", write_denial)?;
    let cap = fs::read_to_string(format!("/proc/{pid}/status"))?;
    ensure!(
        cap.lines()
            .any(|l| l.starts_with("CapEff:") && l.ends_with("0000000000000000")),
        "controller unexpectedly privileged"
    );
    let ordinary = rpc(
        &mut ws,
        106,
        "command/exec",
        json!({"command":["/usr/bin/true"],"cwd":"/lab","sandboxPolicy":{"type":"dangerFullAccess"},"timeoutMs":3000}),
    )?;
    ensure!(
        ordinary["exitCode"] == 0,
        "approved native execution broken"
    );
    ensure!(
        rpc(&mut ws, 107, "thread/loaded/list", json!({}))?["data"].is_array(),
        "same WS broken"
    );
    ensure!(start_tick(pid)? == start, "controller replaced");
    let before = fs::read(SIDE)?;
    thread::sleep(Duration::from_millis(300));
    ensure!(
        fs::read(SIDE)? == before && before[5000] == 0,
        "post-closure mapping write or private map leaked"
    );
    ensure!(uncertain(&d)? == uncertain_before, "uncertain row changed");
    let integrity: String = d.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure!(integrity == "ok", "integrity");
    let counters = counts()?;
    for i in [2, 3, 4, 5, 6] {
        ensure!(counters[i] > 0, "missing denial counter {i}");
    }
    let report = json!({"passed":true,"scope":"closed disposable VM; untrusted non-root UIDs40000 and40002, successor UID40001, root trusted","guest_boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"kernel":fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),"same_controller_pid":pid,"same_controller_start":start,"same_open_websocket":true,"approved_native_command_still_works":true,"persistent_legacy_exec_denied":true,"copies_hardlinks_shell_memfd_denied":true,"policy_survived_loader_death":true,"approved_helper_inodes_root_owned_and_not_group_or_other_writable":true,"untrusted_policy_control_map_open_denied":true,"inode_inventory_pinned_and_paths_revalidated":true,"protected_parent_rename_denied":true,"new_shared_mmap_and_mprotect_denied":true,"preexisting_mapping_required_closure":true,"parent_only_closure_insufficient":true,"closure":closure,"foreign_uid_holder_detected_and_closed":true,"successor_separate_uid":NEW_UID,"successor_write_and_rpc_allowed":true,"uncertain_sending_row_unchanged":true,"uncertain_before":uncertain_before,"uncertain_delivery_retries":0,"known_admitted_response_drained":true,"denial_counters":counters,"post_closure_bytes_stable":true,"sqlite_integrity":integrity,"legacy_uninstall_invoked":false,"host_policy_loaded":false,"production_migration_qualified":false});
    save("result", report.clone())?;
    println!("VM_RESULT={report}");
    // Keep seals armed through teardown: no interval permits legacy reappearance.
    let _ = receiver.wait();
    for a in &mut actors {
        let _ = a.try_wait();
    }
    native.kill()?;
    native.wait()?;
    Ok(())
}
