mod hazards;
mod integrated;
mod persistent;
mod transition;
// All policy load/attach operations require our PID-1 guest, not a host namespace.
use anyhow::{Result, bail, ensure};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    env,
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket};
const UID: u32 = 40000;
const P: &str = "/lab";
const THREAD: &str = "11111111-1111-4111-8111-111111111111";
#[link(name = "bpf")]
unsafe extern "C" {
    fn bpf_object__open_file(p: *const i8, o: *const libc::c_void) -> *mut libc::c_void;
    fn libbpf_get_error(p: *const libc::c_void) -> libc::c_long;
    fn bpf_object__load(o: *mut libc::c_void) -> i32;
    fn bpf_object__find_map_by_name(o: *const libc::c_void, n: *const i8) -> *mut libc::c_void;
    fn bpf_map__fd(m: *const libc::c_void) -> i32;
    fn bpf_map__pin(m: *mut libc::c_void, p: *const i8) -> i32;
    fn bpf_map_update_elem(fd: i32, k: *const libc::c_void, v: *const libc::c_void, f: u64) -> i32;
    fn bpf_map_lookup_elem(fd: i32, k: *const libc::c_void, v: *mut libc::c_void) -> i32;
    fn bpf_object__next_program(o: *const libc::c_void, p: *mut libc::c_void) -> *mut libc::c_void;
    fn bpf_program__name(p: *const libc::c_void) -> *const i8;
    fn bpf_program__attach_lsm(p: *const libc::c_void) -> *mut libc::c_void;
    fn bpf_link__pin(l: *mut libc::c_void, p: *const i8) -> i32;
    fn bpf_obj_get(p: *const i8) -> i32;
}
fn cs(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}
fn guard() -> Result<()> {
    ensure!(
        fs::read_to_string("/proc/cmdline")?.contains("wake_lab_vm=1"),
        "not the qualification VM"
    );
    if unsafe { libc::geteuid() } == 0 {
        let a = fs::metadata("/proc/1/exe")?;
        let b = fs::metadata("/usr/lib/systemd/systemd")?;
        ensure!(
            a.dev() == b.dev() && a.ino() == b.ino(),
            "PID1 is not our guest init"
        );
    } else {
        ensure!(
            matches!(
                unsafe { libc::geteuid() },
                UID | persistent::NEW_UID | persistent::FOREIGN_UID
            ) && matches!(fs::read_to_string("/proc/1/comm")?.trim(), "systemd"),
            "not a guest actor"
        );
    }
    Ok(())
}
fn wait(label: &str, mut f: impl FnMut() -> bool) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(60);
    while !f() {
        ensure!(Instant::now() < end, "timeout {label}");
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
fn save(n: &str, v: Value) -> Result<()> {
    fs::write(format!("{P}/{n}.json"), serde_json::to_vec_pretty(&v)?)?;
    println!("VM_SAVED={n}:{v}");
    Ok(())
}
fn wake(binary: &str, args: &[&str]) -> Command {
    let mut c = Command::new(binary);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", P)
        .env("CODEX_HOME", "/lab/codex")
        .env("TMPDIR", "/lab/tmp")
        .env("XDG_STATE_HOME", "/lab/state")
        .env("XDG_CONFIG_HOME", "/lab/config")
        .env("XDG_DATA_HOME", "/lab/data")
        .env("XDG_CACHE_HOME", "/lab/cache")
        .env("CODEX_WAKE_CODEX", "/guest/codex")
        .env("CODEX_WAKE_RPC_SOCKET", "/lab/native.sock")
        .env("CODEX_WAKE_GH", "/usr/bin/false")
        .env("CODEX_WAKE_ENABLE_WEBHOOKS", "0")
        .uid(UID)
        .gid(UID)
        .args(args)
        .stdin(Stdio::null());
    c
}
fn subscribe(binary: &str, resource: &str) -> std::process::Output {
    wake(
        binary,
        &[
            "subscribe",
            "--kind",
            "artifact",
            "--repo",
            "isolated",
            "--resource",
            resource,
            "--event",
            "available",
            "--thread",
            THREAD,
        ],
    )
    .output()
    .unwrap()
}
fn db() -> Result<Connection> {
    let d = Connection::open("/lab/state/codex-wake/state.sqlite3")?;
    d.busy_timeout(Duration::from_secs(5))?;
    Ok(d)
}
fn rpc(s: &mut WebSocket<UnixStream>, id: i64, m: &str, p: Value) -> Result<Value> {
    s.send(Message::Text(
        json!({"id":id,"method":m,"params":p}).to_string().into(),
    ))?;
    loop {
        if let Message::Text(t) = s.read()? {
            let v: Value = serde_json::from_str(&t)?;
            if v["id"] == id {
                ensure!(v.get("error").is_none(), "RPC rejected {v}");
                return Ok(v["result"].clone());
            }
        }
    }
}
fn connect() -> Result<(WebSocket<UnixStream>, u32)> {
    let s = UnixStream::connect("/lab/native.sock")?;
    s.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut c: libc::ucred = unsafe { std::mem::zeroed() };
    let mut n = std::mem::size_of_val(&c) as u32;
    ensure!(
        unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut c as *mut libc::ucred).cast(),
                &mut n,
            )
        } == 0,
        "peer"
    );
    let (mut ws, _) =
        tungstenite::client("ws://localhost/", s).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    rpc(
        &mut ws,
        1,
        "initialize",
        json!({"clientInfo":{"name":"vm-fence-probe","version":"1"},"capabilities":{"experimentalApi":true}}),
    )?;
    ws.send(Message::Text(
        json!({"method":"initialized","params":{}})
            .to_string()
            .into(),
    ))?;
    Ok((ws, c.pid as u32))
}
#[repr(C)]
struct Cfg {
    uid: u32,
    controller: u32,
    dev: u64,
    directory: u64,
    database: u64,
    lifecycle_dev: u64,
    lifecycle_inode: u64,
    manager_inode: u64,
    socket_path: [u8; 108],
}
fn dev(m: &fs::Metadata) -> u64 {
    ((libc::major(m.dev()) as u64) << 20) | libc::minor(m.dev()) as u64
}
fn map(n: &str) -> Result<i32> {
    let f = unsafe { bpf_obj_get(cs(&format!("/sys/fs/bpf/fence/{n}")).as_ptr()) };
    ensure!(f >= 0, "open map {n}");
    Ok(f)
}
fn arm(bits: u32) -> Result<()> {
    let fd = map("armed")?;
    ensure!(
        unsafe {
            bpf_map_update_elem(
                fd,
                (&0u32 as *const u32).cast(),
                (&bits as *const u32).cast(),
                0,
            )
        } == 0,
        "arm"
    );
    unsafe { libc::close(fd) };
    Ok(())
}
fn arm_add(bits: u32) -> Result<()> {
    let fd = map("armed")?;
    let mut current = 0;
    ensure!(
        unsafe {
            bpf_map_lookup_elem(
                fd,
                (&0u32 as *const u32).cast(),
                (&mut current as *mut u32).cast(),
            )
        } == 0,
        "read armed bits"
    );
    current |= bits;
    ensure!(
        unsafe {
            bpf_map_update_elem(
                fd,
                (&0u32 as *const u32).cast(),
                (&current as *const u32).cast(),
                0,
            )
        } == 0,
        "add armed bits"
    );
    unsafe { libc::close(fd) };
    Ok(())
}
fn load(controller: u32) -> Result<()> {
    guard()?;
    fs::create_dir_all("/sys/fs/bpf/fence")?;
    fs::set_permissions("/sys/fs/bpf/fence", fs::Permissions::from_mode(0o700))?;
    let o = unsafe { bpf_object__open_file(cs("/guest/fence.bpf.o").as_ptr(), std::ptr::null()) };
    ensure!(
        !o.is_null() && unsafe { libbpf_get_error(o) } == 0,
        "BPF open"
    );
    ensure!(unsafe { bpf_object__load(o) } == 0, "BPF load");
    for name in [
        "policy_cfg",
        "armed",
        "counters",
        "last_denial",
        "allowed_exec",
        "protected_inodes",
    ] {
        let m = unsafe { bpf_object__find_map_by_name(o, cs(name).as_ptr()) };
        ensure!(
            !m.is_null()
                && unsafe { bpf_map__pin(m, cs(&format!("/sys/fs/bpf/fence/{name}")).as_ptr()) }
                    == 0,
            "map pin {name}"
        );
        if name == "policy_cfg" {
            let state = fs::metadata("/lab/state/codex-wake")?;
            let main = fs::metadata("/lab/state/codex-wake/state.sqlite3")?;
            let trusted = fs::metadata("/usr/lib/systemd/systemd-executor")?;
            let mut socket_path = [0u8; 108];
            let resolved = fs::canonicalize("/lab/native.sock")?;
            let raw = resolved.as_os_str().as_encoded_bytes();
            ensure!(raw.len() < 108, "Unix path length");
            socket_path[..raw.len()].copy_from_slice(raw);
            let v = Cfg {
                uid: UID,
                controller,
                dev: dev(&state),
                directory: state.ino(),
                database: main.ino(),
                lifecycle_dev: dev(&trusted),
                lifecycle_inode: trusted.ino(),
                manager_inode: fs::metadata("/usr/lib/systemd/systemd")?.ino(),
                socket_path,
            };
            ensure!(std::mem::size_of::<Cfg>() == 168, "config layout");
            ensure!(
                unsafe {
                    bpf_map_update_elem(
                        bpf_map__fd(m),
                        (&0u32 as *const u32).cast(),
                        (&v as *const Cfg).cast(),
                        0,
                    )
                } == 0,
                "config set"
            );
        }
    }
    persistent::configure_maps(o)?;
    let mut prev = std::ptr::null_mut();
    let mut count = 0;
    loop {
        let p = unsafe { bpf_object__next_program(o, prev) };
        if p.is_null() {
            break;
        }
        let link = unsafe { bpf_program__attach_lsm(p) };
        ensure!(
            !link.is_null() && unsafe { libbpf_get_error(link) } == 0,
            "LSM attach"
        );
        let name = unsafe { std::ffi::CStr::from_ptr(bpf_program__name(p)) }.to_str()?;
        ensure!(
            unsafe { bpf_link__pin(link, cs(&format!("/sys/fs/bpf/fence/{name}")).as_ptr()) } == 0,
            "link pin"
        );
        count += 1;
        prev = p;
    }
    ensure!(count == 16, "all hooks required");
    fs::write("/lab/policy-ready", count.to_string())?;
    loop {
        thread::sleep(Duration::from_secs(1))
    }
}
fn actor(mode: &str) -> Result<()> {
    guard()?;
    match mode {
        "socket" => {
            let (mut s, _) = connect()?;
            fs::write("/lab/socket-ready", b"ready")?;
            wait("socket release", || {
                Path::new("/lab/socket-release").exists()
            })?;
            let denied = rpc(&mut s, 2, "thread/loaded/list", json!({})).is_err();
            save("socket-result", json!({"blocked":denied}))
        }
        "fd" => {
            let d = db()?;
            fs::write("/lab/fd-ready", b"ready")?;
            wait("fd release", || Path::new("/lab/fd-release").exists())?;
            println!("VM_STAGE=old_fd_write_attempt");
            let write = d.execute("INSERT INTO fixture_writes VALUES('old-fd')", []);
            let error = write.as_ref().err().map(ToString::to_string);
            let denied = write.is_err();
            println!("VM_STAGE=old_fd_write_returned_{denied}");
            save("fd-result", json!({"blocked":denied,"sqlite_error":error}))
        }
        "descendant" => {
            fs::write("/lab/descendant-ready", b"ready")?;
            wait("descendant release", || {
                Path::new("/lab/descendant-release").exists()
            })?;
            let o = wake(
                "/usr/bin/strace",
                &[
                    "-f",
                    "-tt",
                    "-s",
                    "160",
                    "-o",
                    "/lab/descendant.trace",
                    "/guest/legacy",
                    "subscribe",
                    "--kind",
                    "artifact",
                    "--repo",
                    "isolated",
                    "--resource",
                    "escaped",
                    "--event",
                    "available",
                    "--thread",
                    THREAD,
                ],
            )
            .output()?;
            save(
                "descendant-result",
                json!({"blocked":!o.status.success(),"exit_code":o.status.code(),"stderr":String::from_utf8_lossy(&o.stderr)}),
            )
        }
        "held" => {
            let (mut s, _) = connect()?;
            let r = rpc(
                &mut s,
                3,
                "command/exec",
                json!({"command":["/guest/vm-probe","actor","remote"],"cwd":"/lab","sandboxPolicy":{"type":"dangerFullAccess"},"timeoutMs":20000}),
            )?;
            ensure!(r["exitCode"] == 0, "held command");
            db()?.execute(
                "INSERT INTO fixture_writes VALUES('completion-before-file-fence')",
                [],
            )?;
            save(
                "held-result",
                json!({"response_consumed":true,"completion_persisted":true}),
            )
        }
        "remote" => {
            fs::write("/lab/held-ready", b"ready")?;
            wait("held release", || Path::new("/lab/held-release").exists())?;
            Ok(())
        }
        "mmap" => {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/lab/state/codex-wake/state.sqlite3-mmap-probe")?;
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    8192,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    f.as_raw_fd(),
                    0,
                )
            };
            ensure!(ptr != libc::MAP_FAILED, "mmap");
            fs::write("/lab/mmap-ready", b"ready")?;
            wait("mmap release", || Path::new("/lab/mmap-release").exists())?;
            unsafe {
                (ptr as *mut u8).add(4096).write_volatile(165);
                ensure!(
                    libc::msync(ptr, 8192, libc::MS_SYNC) == 0,
                    "msync failed: {}",
                    std::io::Error::last_os_error()
                );
                ensure!(libc::munmap(ptr, 8192) == 0, "munmap failed");
            };
            save(
                "mmap-result",
                json!({"preexisting_mapping_store_completed":true,"msync_ok":true,"offset":4096,"before":0,"after":165,"resource":"synthetic sidecar matched by policy, not SQLite main pages"}),
            )
        }
        x if x.starts_with("persistent-") => persistent::actor(x),
        _ => bail!("actor"),
    }
}
fn child(mode: &str) -> Result<std::process::Child> {
    Ok(Command::new("/guest/vm-probe")
        .args(["actor", mode])
        .uid(UID)
        .gid(UID)
        .spawn()?)
}
fn read(n: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(format!(
        "/lab/{n}.json"
    ))?)?)
}

fn mount(t: &str, p: &str) -> Result<()> {
    fs::create_dir_all(p)?;
    ensure!(
        unsafe {
            libc::mount(
                cs(t).as_ptr(),
                cs(p).as_ptr(),
                cs(t).as_ptr(),
                0,
                std::ptr::null(),
            )
        } == 0,
        "mount {t}: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn diagnostics() {
    if let Ok(fd) = map("last_denial") {
        for k in 0..7u32 {
            let mut v = [0u64; 7];
            if unsafe { bpf_map_lookup_elem(fd, (&k as *const u32).cast(), v.as_mut_ptr().cast()) }
                == 0
            {
                println!("VM_LAST_DENIAL={k}:{v:?}");
            }
        }
        unsafe { libc::close(fd) };
    }
    if let Ok(entries) = fs::read_dir("/proc") {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().parse::<u32>().is_ok() {
                let cmd = fs::read(e.path().join("cmdline")).unwrap_or_default();
                if cmd.is_empty() {
                    continue;
                }
                let wchan = fs::read_to_string(e.path().join("wchan")).unwrap_or_default();
                println!(
                    "VM_PROCESS={} cmd={:?} wchan={}",
                    e.file_name().to_string_lossy(),
                    String::from_utf8_lossy(&cmd),
                    wchan.trim()
                );
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/lab") {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.ends_with(".json") || n.ends_with(".trace") || n.ends_with(".stderr") {
                if let Ok(s) = fs::read_to_string(e.path()) {
                    let lines: Vec<_> = s.lines().collect();
                    println!(
                        "VM_DIAGNOSTIC={n}\n{}",
                        lines[lines.len().saturating_sub(90)..].join("\n")
                    );
                }
            }
        }
    }
}
fn main() {
    let result = (|| -> Result<()> {
        if std::process::id() == 1 {
            return integrated::boot();
        }
        let a: Vec<_> = env::args().collect();
        match a.get(1).map(String::as_str) {
            Some("suite") => {
                let r = integrated::driver();
                if r.is_err() {
                    diagnostics();
                }
                r
            }
            Some("role") => integrated::role(&a[2..]),
            Some("actor") => actor(&a[2]),
            Some("load") => load(a[2].parse()?),
            _ => bail!("mode"),
        }
    })();
    if let Err(e) = result {
        eprintln!(
            "VM_ERROR[{:?}]={e:#}",
            env::args().skip(1).collect::<Vec<_>>()
        );
        std::process::exit(1)
    }
}
