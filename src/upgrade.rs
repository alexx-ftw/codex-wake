//! Cooperative-only lifecycle. A pending journal is never resumed automatically.
use crate::manager::{self, Config};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

const UNIT: &str = "codex-wake.service";
const PROTOCOL: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Spec {
    protocol: u32,
    owner: String,
    generation: i64,
    executable: PathBuf,
    binary: String,
    unit: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    phase: String,
    spec: Spec,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn journal(config: &Config) -> PathBuf {
    config.state.join("cooperative-upgrade.json")
}
pub(crate) fn configured(config: &Config) -> bool {
    journal(config).symlink_metadata().is_ok()
}
fn read_record(config: &Config) -> Result<Record> {
    let path = journal(config);
    let meta = fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_file() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "Untrusted cooperative journal"
    );
    let record: Record = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        record.spec.protocol == PROTOCOL && record.spec.generation > 0,
        "Unsupported cooperative protocol; alpha.2 cannot cooperate"
    );
    Ok(record)
}
fn save(config: &Config, phase: &str, spec: &Spec) -> Result<()> {
    manager::atomic_write(
        &journal(config),
        &serde_json::to_vec(&Record {
            phase: phase.into(),
            spec: spec.clone(),
        })?,
        0o600,
    )?;
    fs::File::open(&config.state)?.sync_all()?;
    Ok(())
}
fn unit(config: &Config, spec: &Spec) -> Result<String> {
    let mut generation = config.clone();
    generation.runtime = spec
        .executable
        .parent()
        .context("Missing generation directory")?
        .into();
    Ok(manager::unit(&generation)?
        .replace("Type=simple\n", "Type=exec\nRemainAfterExit=yes\nKillMode=control-group\n")
        .replace("Restart=on-failure\n", "Restart=no\n")
        .replace("[Service]\n", &format!("[Service]\nEnvironment=CODEX_WAKE_COOPERATIVE_RECEIVER=1\nEnvironment=CODEX_WAKE_RECEIVER_LIFECYCLE=1\nEnvironment=CODEX_WAKE_GATE_OWNER={}\nEnvironment=CODEX_WAKE_GATE_GENERATION={}\n", spec.owner, spec.generation)))
}

type Snapshot = BTreeMap<String, String>;
fn field<'a>(s: &'a Snapshot, name: &str) -> Result<&'a str> {
    s.get(name)
        .map(String::as_str)
        .with_context(|| format!("Missing systemd {name}"))
}
fn snapshot() -> Result<Snapshot> {
    let raw = manager::systemctl(&[
        "show",
        UNIT,
        "--property=LoadState,ActiveState,SubState,MainPID,InvocationID,ControlGroup,Result,ExecMainCode,ExecMainStatus,FragmentPath,DropInPaths,Restart,RemainAfterExit,KillMode,NeedDaemonReload",
    ])?;
    let mut result = Snapshot::new();
    for line in raw.lines() {
        let (key, value) = line.split_once('=').context("Invalid systemd snapshot")?;
        ensure!(
            result.insert(key.into(), value.into()).is_none(),
            "Duplicate systemd field"
        );
    }
    Ok(result)
}
fn verify_unit(config: &Config, spec: &Spec, s: &Snapshot) -> Result<()> {
    ensure!(
        spec.protocol == PROTOCOL && digest(unit(config, spec)?.as_bytes()) == spec.unit,
        "Cooperative unit contract changed"
    );
    ensure!(
        field(s, "LoadState")? == "loaded"
            && field(s, "FragmentPath")? == config.unit.to_str().context("Invalid unit path")?
            && field(s, "DropInPaths")?.is_empty()
            && field(s, "Restart")? == "no"
            && field(s, "RemainAfterExit")? == "yes"
            && field(s, "KillMode")? == "control-group"
            && field(s, "NeedDaemonReload")? == "no",
        "Unverified cooperative unit or override; left untouched"
    );
    let meta = fs::symlink_metadata(&config.unit)?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && digest(&fs::read(&config.unit)?) == spec.unit,
        "Cooperative unit file changed"
    );
    Ok(())
}
fn invocation(s: &Snapshot) -> Result<&str> {
    let id = field(s, "InvocationID")?;
    ensure!(
        id.len() == 32
            && id.bytes().all(|b| b.is_ascii_hexdigit())
            && id.bytes().any(|b| b != b'0'),
        "Invalid service invocation"
    );
    Ok(id)
}
fn group(s: &Snapshot) -> Result<&str> {
    let cg = field(s, "ControlGroup")?;
    ensure!(
        cg.starts_with("/user.slice/")
            && cg.ends_with("/codex-wake.service")
            && !cg[1..]
                .split('/')
                .any(|p| p == "." || p == ".." || p.is_empty()),
        "Invalid receiver cgroup"
    );
    Ok(cg)
}
fn process_group(pid: u32) -> Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    Ok(raw
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("Missing cgroup v2 membership")?
        .into())
}
fn outside_receiver(controller: &str, receiver: &str) -> bool {
    controller != receiver && !controller.starts_with(&format!("{receiver}/"))
}
fn running(config: &Config, spec: &Spec) -> Result<Snapshot> {
    let s = snapshot()?;
    verify_unit(config, spec, &s)?;
    invocation(&s)?;
    ensure!(
        field(&s, "ActiveState")? == "active" && field(&s, "SubState")? == "running",
        "Cooperative receiver is not running"
    );
    let pid: u32 = field(&s, "MainPID")?.parse()?;
    ensure!(
        pid > 0 && process_group(pid)? == group(&s)?,
        "Receiver process/cgroup mismatch"
    );
    let actual = fs::metadata(format!("/proc/{pid}/exe"))?;
    let expected = fs::metadata(&spec.executable)?;
    ensure!(
        actual.dev() == expected.dev()
            && actual.ino() == expected.ino()
            && digest(&fs::read(&spec.executable)?) == spec.binary,
        "Receiver executable identity changed"
    );
    Ok(s)
}

// The controller is outside the receiver's cgroup and remains the same peer.
#[derive(PartialEq, Debug)]
struct Controller {
    pid: u32,
    start: u64,
    device: u64,
    inode: u64,
    socket_device: u64,
    socket_inode: u64,
    group: String,
}
fn controller(config: &Config) -> Result<Controller> {
    let socket = UnixStream::connect(&config.rpc_socket)?;
    let endpoint = fs::metadata(&config.rpc_socket)?;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&peer) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut len,
            )
        } == 0
            && peer.pid > 0
            && peer.uid == unsafe { libc::geteuid() },
        "Unverified controller peer"
    );
    let pid = peer.pid as u32;
    let meta = fs::metadata(format!("/proc/{pid}/exe"))?;
    let start =
        crate::obligations::process_start_time(pid).context("Missing controller start time")?;
    Ok(Controller {
        pid,
        start,
        device: meta.dev(),
        inode: meta.ino(),
        socket_device: endpoint.dev(),
        socket_inode: endpoint.ino(),
        group: process_group(pid)?,
    })
}

// Only an authoritative successful exit of this invocation can construct this proof.
pub(crate) struct Drained {
    spec: Spec,
    pid: i64,
    start: i64,
    invocation: String,
    cgroup: String,
}
fn terminal(s: &Snapshot, id: &str) -> Result<bool> {
    ensure!(
        invocation(s)? == id,
        "Receiver invocation changed during drain"
    );
    if field(s, "MainPID")? != "0" {
        return Ok(false);
    }
    ensure!(
        field(s, "ActiveState")? == "active"
            && field(s, "SubState")? == "exited"
            && field(s, "Result")? == "success"
            && field(s, "ExecMainCode")? == "1"
            && field(s, "ExecMainStatus")? == "0",
        "Receiver did not exit successfully; no automatic retry"
    );
    Ok(true)
}
fn empty_group(cg: &str) -> Result<bool> {
    let path = PathBuf::from(format!("/sys/fs/cgroup{cg}"));
    let parent = path.parent().context("Missing cgroup parent")?;
    ensure!(parent.is_dir(), "Cannot verify cgroup parent");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
        Ok(meta) => {
            ensure!(meta.is_dir(), "Untrusted cgroup path");
            Ok(fs::read_to_string(path.join("cgroup.events"))?
                .lines()
                .any(|l| l == "populated 0"))
        }
    }
}
impl Drained {
    pub(crate) fn verify_gate(&self, db: &Connection) -> Result<()> {
        let (pid, start, spec): (i64, i64, String) = db.query_row("SELECT receiver_pid,receiver_start,receiver_lifecycle FROM wake_delivery_claim_gate WHERE id=1", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        ensure!(
            pid == self.pid
                && start == self.start
                && serde_json::from_str::<Spec>(&spec)? == self.spec,
            "Drain proof does not identify the bound receiver"
        );
        let config = Config::from_env()?;
        let s = snapshot()?;
        verify_unit(&config, &self.spec, &s)?;
        ensure!(
            terminal(&s, &self.invocation)? && empty_group(&self.cgroup)?,
            "Receiver exit/drain proof changed"
        );
        Ok(())
    }
}

pub(crate) fn verify_binding(db: &Connection, owner: &str, generation: i64) -> Result<()> {
    let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('wake_delivery_claim_gate') WHERE name='receiver_lifecycle')", [], |r| r.get(0))?;
    if !exists {
        return Ok(());
    }
    let raw: Option<String> = db.query_row(
        "SELECT receiver_lifecycle FROM wake_delivery_claim_gate WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let Some(raw) = raw else { return Ok(()) };
    let spec: Spec = serde_json::from_str(&raw)?;
    ensure!(
        spec.owner == owner && spec.generation == generation,
        "Lifecycle generation mismatch"
    );
    let config = Config::from_env()?;
    let s = running(&config, &spec)?;
    ensure!(
        field(&s, "MainPID")? == std::process::id().to_string()
            && env::var("INVOCATION_ID")? == invocation(&s)?,
        "Receiver invocation is not this process"
    );
    ensure!(
        outside_receiver(&controller(&config)?.group, group(&s)?),
        "Controller shares receiver cgroup"
    );
    Ok(())
}

fn install_spec(db: &Connection, spec: &Spec) -> Result<()> {
    db.execute_batch("ALTER TABLE wake_delivery_claim_gate ADD COLUMN receiver_lifecycle TEXT")?;
    db.execute(
        "UPDATE wake_delivery_claim_gate SET receiver_lifecycle=?1 WHERE id=1",
        [serde_json::to_string(spec)?],
    )?;
    Ok(())
}

pub(crate) fn ensure_receiver(config: &Config) -> Result<Value> {
    manager::require_installed(config)?;
    let _lock = manager::lock(config)?;
    let result = ensure_locked(config);
    if result.is_err()
        && configured(config)
        && let Ok(db) = crate::bridge::open_existing_owned(&config.db)
    {
        db.execute(
            "UPDATE wake_delivery_claim_gate SET is_open=0 WHERE id=1",
            [],
        )?;
    }
    result
}

fn ensure_locked(config: &Config) -> Result<Value> {
    manager::require_installed(config)?;
    ensure!(
        !config.webhooks_enabled && config.rpc_socket != config.state.join("app-server.sock"),
        "Cooperative upgrade requires an independently managed controller and webhook"
    );
    ensure!(
        config.db.is_absolute() && config.codex.is_absolute(),
        "Cooperative paths must be absolute"
    );
    let previous = if configured(config) {
        let r = read_record(config)?;
        ensure!(
            r.phase == "ready",
            "Cooperative transition incomplete; inspect journal, do not retry automatically"
        );
        Some(r.spec)
    } else {
        // Never adopt even a stopped alpha.2 database or installation.
        let s = snapshot()?;
        ensure!(
            field(&s, "LoadState")? == "not-found"
                && !config.unit.exists()
                && !config.db.exists()
                && !config.runtime.exists(),
            "Legacy/unknown installation (including alpha.2) left untouched; planned maintenance required"
        );
        None
    };
    let peer = controller(config)?;
    let bytes = fs::read(env::current_exe()?)?;
    let binary = digest(&bytes);
    let old_snapshot = previous.as_ref().map(|p| running(config, p)).transpose()?;
    if let Some(old) = &previous {
        ensure!(
            outside_receiver(&peer.group, group(old_snapshot.as_ref().unwrap())?),
            "Controller shares receiver cgroup"
        );
        if old.binary == binary {
            return health(config, old);
        }
    }
    let owner = uuid::Uuid::new_v4().to_string();
    let generation = previous
        .as_ref()
        .map_or(Some(1), |p| p.generation.checked_add(1))
        .context("Generation exhausted")?;
    let mut next = Spec {
        protocol: PROTOCOL,
        owner,
        generation,
        executable: config
            .runtime
            .join("generations")
            .join(&binary)
            .join("codex-wake"),
        binary,
        unit: String::new(),
    };
    next.unit = digest(unit(config, &next)?.as_bytes());
    manager::private_dir(next.executable.parent().unwrap())?;
    manager::atomic_write(&next.executable, &bytes, 0o700)?;
    manager::atomic_write(
        &next.executable.parent().unwrap().join("hooks.json.tmpl"),
        include_bytes!("../hooks.json.tmpl"),
        0o600,
    )?;
    ensure!(
        digest(&fs::read(&next.executable)?) == next.binary,
        "Staged binary verification failed"
    );
    // Persist before the first admission/lifecycle side effect. No recovery by guessing.
    save(config, "pending", &next)?;
    let result = (|| -> Result<Value> {
        let mut db = if let Some(old) = &previous {
            let mut db = crate::bridge::open_existing_owned(&config.db)?;
            let s = old_snapshot.as_ref().unwrap();
            let pid: i64 = field(s, "MainPID")?.parse()?;
            let start = crate::obligations::process_start_time(pid as u32)
                .context("Receiver disappeared before close")? as i64;
            ensure!(
                running(config, old)? == *s,
                "Receiver changed before admission closure"
            );
            crate::bridge::control_claim_gate(
                &mut db,
                "close",
                &old.owner,
                Some(old.generation),
                None,
            )?;
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let after = snapshot()?;
                verify_unit(config, old, &after)?;
                if terminal(&after, invocation(s)?)? && empty_group(group(s)?)? {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "Receiver drain deadline; no automatic retry"
                );
                thread::sleep(Duration::from_millis(50));
            }
            let drained = Drained {
                spec: old.clone(),
                pid,
                start,
                invocation: invocation(s)?.into(),
                cgroup: group(s)?.into(),
            };
            ensure!(
                controller(config)? == peer,
                "Controller changed during drain"
            );
            crate::bridge::transfer_receiver_gate(
                &mut db,
                &old.owner,
                old.generation,
                &next.owner,
                &next,
                &drained,
            )?;
            db
        } else {
            let mut db = crate::bridge::connect(&config.db)?;
            crate::bridge::control_claim_gate(&mut db, "init", &next.owner, None, None)?;
            crate::bridge::control_claim_gate(&mut db, "arm", &next.owner, Some(1), None)?;
            let producer = env::var("CODEX_WAKE_PRODUCER_ID").context(
                "Fresh cooperative installation requires a stable CODEX_WAKE_PRODUCER_ID UUID",
            )?;
            crate::bridge::configure_producer(&mut db, &next.owner, 1, &producer)?;
            install_spec(&db, &next)?;
            db
        };
        if previous.is_some() {
            manager::systemctl(&["stop", UNIT])?;
        }
        manager::private_dir(config.unit.parent().context("Missing unit directory")?)?;
        manager::atomic_write(&config.unit, unit(config, &next)?.as_bytes(), 0o600)?;
        manager::systemctl(&["daemon-reload"])?;
        manager::systemctl(&["enable", UNIT])?;
        manager::systemctl(&["start", UNIT])?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let ready = loop {
            match health(config, &next) {
                Ok(ready) => break ready,
                Err(error) if Instant::now() >= deadline => return Err(error),
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        };
        ensure!(
            controller(config)? == peer,
            "Controller changed during activation"
        );
        save(config, "ready", &next)?;
        // Keep the connection alive until activation and journal publication finish.
        let _ = &mut db;
        Ok(ready)
    })();
    if result.is_err() {
        // Closure is safe even if transfer/start/health had an uncertain result.
        if let Ok(db) = crate::bridge::open_existing_owned(&config.db) {
            let _ = db.execute(
                "UPDATE wake_delivery_claim_gate SET is_open=0 WHERE id=1",
                [],
            );
        }
    }
    result
}
fn health(config: &Config, spec: &Spec) -> Result<Value> {
    let s = running(config, spec)?;
    let db = crate::bridge::open_existing_owned(&config.db)?;
    let valid: bool = db.query_row("SELECT is_open=1 AND owner=?1 AND generation=?2 AND receiver_pid=?3 AND receiver_lifecycle=?4 FROM wake_delivery_claim_gate WHERE id=1",params![spec.owner,spec.generation,field(&s,"MainPID")?,serde_json::to_string(spec)?],|r| r.get(0))?;
    ensure!(valid, "Receiver has not bound its lifecycle generation");
    let telemetry = Connection::open_with_flags(
        config.state.join("telemetry.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let heartbeat: bool = telemetry.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE pid=?1 AND operation='receiver.heartbeat' AND outcome='ok')",[field(&s,"MainPID")?],|r|r.get(0))?;
    ensure!(heartbeat, "Receiver has no successful heartbeat");
    ensure!(
        crate::goals::rpc(&config.codex, "thread/loaded/list", json!({}))?["data"].is_array(),
        "Controller readiness failed"
    );
    Ok(
        json!({"local_ready":true,"controller_ready":true,"cooperative_protocol":PROTOCOL,"generation":spec.generation,"invocation":invocation(&s)?}),
    )
}

pub(crate) fn status(config: &Config) -> Result<Value> {
    let record = read_record(config)?;
    ensure!(
        record.phase == "ready",
        "Cooperative transition pending; inspect journal"
    );
    health(config, &record.spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn exited() -> Snapshot {
        [
            ("InvocationID", "11111111111111111111111111111111"),
            ("MainPID", "0"),
            ("ActiveState", "active"),
            ("SubState", "exited"),
            ("Result", "success"),
            ("ExecMainCode", "1"),
            ("ExecMainStatus", "0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    }
    #[test]
    fn successful_exit_is_tied_to_invocation_and_not_just_pid_disappearance() {
        let snapshot = exited();
        let id = invocation(&snapshot).unwrap();
        assert!(terminal(&snapshot, id).unwrap());
        for (key, value) in [
            ("InvocationID", "22222222222222222222222222222222"),
            ("Result", "signal"),
            ("ExecMainCode", "2"),
            ("ExecMainCode", "exited"),
            ("ExecMainStatus", "1"),
            ("SubState", "dead"),
            ("ActiveState", "failed"),
        ] {
            let mut changed = snapshot.clone();
            changed.insert(key.into(), value.into());
            assert!(terminal(&changed, id).is_err(), "accepted {key}={value}");
        }
        let mut running = snapshot.clone();
        running.insert("MainPID".into(), "123".into());
        assert!(!terminal(&running, id).unwrap());
    }
    #[test]
    fn group_paths_cannot_escape_or_alias_the_root() {
        assert!(!outside_receiver(
            "/user.slice/codex-wake.service/child",
            "/user.slice/codex-wake.service"
        ));
        assert!(!outside_receiver(
            "/user.slice/codex-wake.service",
            "/user.slice/codex-wake.service"
        ));
        assert!(outside_receiver(
            "/user.slice/controller.service",
            "/user.slice/codex-wake.service"
        ));
        for value in [
            "",
            "/",
            "/user.slice/../codex-wake.service",
            "/user.slice//codex-wake.service",
            "/user.slice/./codex-wake.service",
            "/system.slice/codex-wake.service",
        ] {
            assert!(group(&Snapshot::from([("ControlGroup".into(), value.into())])).is_err());
        }
        assert!(
            group(&Snapshot::from([(
                "ControlGroup".into(),
                "/user.slice/user-1000.slice/user@1000.service/app.slice/codex-wake.service".into()
            )]))
            .is_ok()
        );
    }
    #[test]
    fn malformed_lifecycle_cannot_bind_or_open() {
        let mut db = Connection::open_in_memory().unwrap();
        let owner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        crate::bridge::control_claim_gate(&mut db, "init", owner, None, None).unwrap();
        crate::bridge::control_claim_gate(&mut db, "arm", owner, Some(1), None).unwrap();
        db.execute_batch("ALTER TABLE wake_delivery_claim_gate ADD COLUMN receiver_lifecycle TEXT; UPDATE wake_delivery_claim_gate SET receiver_lifecycle='{}'").unwrap();
        assert!(crate::bridge::bind_receiver_gate(&mut db, owner, 1).is_err());
        assert!(
            !db.query_row("SELECT is_open FROM wake_delivery_claim_gate", [], |r| r
                .get::<_, bool>(
                0
            ))
            .unwrap()
        );
    }
}
