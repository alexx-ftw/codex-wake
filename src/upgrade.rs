use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, path::Path, process::Command, time::Duration};

type Handoff = (String, String, String, String, String, i64, String, String);

pub(crate) fn managed(db: &Connection) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='wake_cooperative_handoff')",
        [], |row| row.get(0),
    )?)
}

fn install_guard(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TRIGGER IF NOT EXISTS wake_cooperative_gate_guard BEFORE UPDATE ON wake_delivery_claim_gate WHEN ((NEW.owner IS NOT OLD.owner OR NEW.generation IS NOT OLD.generation) AND NOT EXISTS (SELECT 1 FROM wake_cooperative_handoff h WHERE h.id=1 AND h.phase='transfer' AND h.owner=NEW.owner AND h.generation=NEW.generation)) OR (NEW.is_open=1 AND OLD.is_open=0 AND NOT EXISTS (SELECT 1 FROM wake_cooperative_handoff h WHERE h.id=1 AND h.phase='binding' AND h.owner=NEW.owner AND h.generation=NEW.generation AND h.successor_pid=NEW.receiver_pid)) BEGIN SELECT RAISE(ABORT,'managed cooperative gate requires verified handoff'); END;")?;
    Ok(())
}

pub(crate) fn automatic(config: &crate::manager::Config) -> Result<Option<serde_json::Value>> {
    match std::env::var("CODEX_WAKE_COOPERATIVE_AUTO") {
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Ok(value) if value == "1" => (),
        _ => anyhow::bail!("CODEX_WAKE_COOPERATIVE_AUTO must be 1 or unset"),
    }
    crate::manager::require_installed(config)?;
    let db = crate::bridge::open_existing_owned(&config.db)?;
    ensure!(
        managed(&db)?,
        "Automatic upgrades require a managed cooperative receiver"
    );
    ensure!(
        std::env::var_os("CODEX_WAKE_PRODUCER_ID").is_some()
            && crate::bridge::producer_enqueue_allowed(&db)? == Some(true),
        "Automatic upgrades require the stable producer identity"
    );
    let (unit, old_digest): (String, String) = db.query_row(
        "SELECT successor_unit,successor_sha256 FROM wake_cooperative_handoff WHERE id=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let digest = format!("{:x}", Sha256::digest(fs::read("/proc/self/exe")?));
    if digest == old_digest {
        let (open, pid, gate_owner, gate_generation, saved_owner, saved_generation): (bool, i64, String, i64, String, i64) = db.query_row("SELECT g.is_open,g.receiver_pid,g.owner,g.generation,h.owner,h.generation FROM wake_delivery_claim_gate g JOIN wake_cooperative_handoff h ON h.id=g.id WHERE g.id=1 AND h.phase='active'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        let checked = (|| -> Result<()> {
            let active = properties(&unit)?;
            let (start, boot, namespace, token): (i64, String, String, String) = db.query_row("SELECT receiver_start,receiver_boot,receiver_namespace,receiver_token FROM wake_delivery_claim_gate WHERE id=1", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            let current = crate::conditions::current_sender_identity()?;
            ensure!(
                open && gate_owner == saved_owner
                    && gate_generation == saved_generation
                    && field(&active, "ActiveState")? == "active"
                    && field(&active, "MainPID")? == pid.to_string()
                    && u32::try_from(pid)
                        .ok()
                        .and_then(crate::obligations::process_start_time)
                        .and_then(|value| i64::try_from(value).ok())
                        == Some(start)
                    && boot == current.boot
                    && namespace == current.namespace
                    && uuid::Uuid::parse_str(&token)
                        .is_ok_and(|id| !id.is_nil() && id.to_string() == token)
                    && fs::read_link(format!("/proc/{pid}/ns/pid"))?.to_str()
                        == Some(namespace.as_str())
                    && format!(
                        "{:x}",
                        Sha256::digest(fs::read(format!("/proc/{pid}/exe"))?)
                    ) == digest,
                "Current managed receiver is not active and bound"
            );
            Ok(())
        })();
        if checked.is_err() {
            close_generation(&db, &gate_owner, gate_generation)?;
        }
        checked?;
        return Ok(Some(serde_json::json!({"unit":unit,"state":"current"})));
    }
    drop(db);
    Ok(Some(run(config, &unit)?))
}

fn close_generation(db: &Connection, owner: &str, generation: i64) -> Result<()> {
    db.execute(
        "UPDATE wake_delivery_claim_gate SET is_open=0 WHERE id=1 AND owner=?1 AND generation=?2",
        rusqlite::params![owner, generation],
    )
    .context("Could not close uncertain receiver gate")?;
    Ok(())
}

fn properties(unit: &str) -> Result<HashMap<String, String>> {
    ensure!(valid_unit(unit), "Invalid cooperative receiver unit");
    let output = crate::manager::run(
        Command::new("/usr/bin/systemctl").args([
            "--user", "show", unit, "--property=InvocationID,ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,ControlGroup,Restart,KillMode,RemainAfterExit",
        ]), Duration::from_secs(20),
    )?;
    ensure!(
        output.status.success(),
        "Cannot inspect cooperative receiver unit"
    );
    let mut result = HashMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("Invalid systemd property")?;
        ensure!(
            result.insert(key.to_owned(), value.to_owned()).is_none(),
            "Duplicate systemd property"
        );
    }
    Ok(result)
}

fn valid_unit(unit: &str) -> bool {
    unit.starts_with("codex-wake-coop-")
        && unit.ends_with(".service")
        && unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn field<'a>(properties: &'a HashMap<String, String>, name: &str) -> Result<&'a str> {
    properties
        .get(name)
        .map(String::as_str)
        .with_context(|| format!("Missing systemd property {name}"))
}

fn valid_invocation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && value.bytes().any(|b| b != b'0')
}

fn valid_cgroup(value: &str) -> bool {
    value.starts_with("/user.slice/")
        && value.split('/').skip(1).all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-@".contains(&b))
        })
}

fn drained(cgroup: &str) -> Result<bool> {
    ensure!(valid_cgroup(cgroup), "Invalid predecessor cgroup");
    let path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
    let parent = path.parent().context("Missing cgroup parent")?;
    ensure!(
        fs::symlink_metadata(parent)?.is_dir(),
        "Predecessor cgroup parent unavailable"
    );
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
        Ok(meta) => {
            ensure!(meta.is_dir(), "Invalid predecessor cgroup directory");
            let events = path.join("cgroup.events");
            ensure!(
                fs::symlink_metadata(&events)?.is_file(),
                "Invalid predecessor cgroup events"
            );
            let text = fs::read_to_string(events)?;
            Ok(text.lines().any(|line| line == "populated 0"))
        }
    }
}

fn successful_previous(properties: &HashMap<String, String>, invocation: &str) -> Result<()> {
    ensure!(
        valid_invocation(invocation) && field(properties, "InvocationID")? == invocation,
        "Predecessor invocation changed"
    );
    for (key, value) in [
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("Result", "success"),
        ("MainPID", "0"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("RemainAfterExit", "yes"),
    ] {
        ensure!(
            field(properties, key)? == value,
            "Predecessor {key} is not {value}"
        );
    }
    Ok(())
}

pub(crate) fn verify_successor(db: &Connection, owner: &str, generation: i64) -> Result<()> {
    if !managed(db)? {
        return Ok(());
    }
    let row: Option<Handoff> = db.query_row(
        "SELECT previous_unit,previous_invocation,previous_cgroup,successor_unit,successor_sha256,generation,owner,phase FROM wake_cooperative_handoff WHERE id=1",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
    ).optional()?;
    let (
        old_unit,
        invocation,
        old_cgroup,
        new_unit,
        digest,
        expected_generation,
        expected_owner,
        phase,
    ) = row.context("Managed handoff record missing")?;
    ensure!(
        expected_owner == owner && expected_generation == generation && phase == "waiting",
        "Handoff generation changed"
    );
    ensure!(
        old_unit != new_unit && valid_unit(&old_unit) && valid_unit(&new_unit),
        "Invalid handoff units"
    );
    let old = properties(&old_unit)?;
    successful_previous(&old, &invocation)?;
    ensure!(drained(&old_cgroup)?, "Predecessor cgroup still populated");
    let new = properties(&new_unit)?;
    ensure!(
        matches!(field(&new, "ActiveState")?, "active" | "activating")
            && field(&new, "MainPID")? == std::process::id().to_string(),
        "Successor is not the unit main process"
    );
    ensure!(
        field(&new, "Restart")? == "no"
            && field(&new, "KillMode")? == "control-group"
            && field(&new, "RemainAfterExit")? == "yes",
        "Invalid successor unit policy"
    );
    ensure!(
        valid_invocation(field(&new, "InvocationID")?),
        "Invalid successor invocation"
    );
    let new_cgroup = field(&new, "ControlGroup")?;
    ensure!(
        valid_cgroup(new_cgroup)
            && new_cgroup != old_cgroup
            && !new_cgroup.starts_with(&format!("{old_cgroup}/"))
            && !old_cgroup.starts_with(&format!("{new_cgroup}/")),
        "Receiver cgroups overlap"
    );
    let self_cgroup = fs::read_to_string("/proc/self/cgroup")?;
    ensure!(
        self_cgroup
            .lines()
            .any(|line| line.strip_prefix("0::") == Some(new_cgroup)),
        "Successor cgroup identity mismatch"
    );
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "Invalid successor digest"
    );
    ensure!(
        format!("{:x}", Sha256::digest(fs::read("/proc/self/exe")?)) == digest,
        "Successor executable digest mismatch"
    );
    successful_previous(&properties(&old_unit)?, &invocation)?;
    ensure!(drained(&old_cgroup)?, "Predecessor cgroup became populated");
    ensure!(db.execute("UPDATE wake_cooperative_handoff SET phase='binding',successor_pid=?1 WHERE id=1 AND phase='waiting' AND owner=?2 AND generation=?3", rusqlite::params![std::process::id(),owner,generation])? == 1, "Managed handoff state changed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn predecessor_result_requires_exact_invocation_and_success() {
        let id = "11111111111111111111111111111111";
        let mut p: HashMap<String, String> = [
            ("InvocationID", id),
            ("ActiveState", "active"),
            ("SubState", "exited"),
            ("Result", "success"),
            ("MainPID", "0"),
            ("ExecMainCode", "1"),
            ("ExecMainStatus", "0"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("RemainAfterExit", "yes"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        assert!(successful_previous(&p, id).is_ok());
        for (key, bad) in [
            ("InvocationID", "22222222222222222222222222222222"),
            ("ExecMainStatus", "1"),
            ("ExecMainCode", "exited"),
            ("MainPID", "123"),
            ("Restart", "always"),
            ("KillMode", "process"),
        ] {
            let saved = p.insert(key.into(), bad.into()).unwrap();
            assert!(successful_previous(&p, id).is_err(), "{key}");
            p.insert(key.into(), saved);
        }
        assert!(!valid_cgroup("/user.slice/../other"));
        assert!(!valid_unit("codex-wake-coop-../foo.service"));
    }

    #[test]
    fn managed_gate_rejects_manual_transfer_and_unverified_binding() {
        let mut db = Connection::open_in_memory().unwrap();
        let owner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let next = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        crate::bridge::control_claim_gate(&mut db, "init", owner, None, None).unwrap();
        crate::bridge::control_claim_gate(&mut db, "arm", owner, Some(1), None).unwrap();
        db.execute_batch("CREATE TABLE wake_cooperative_handoff(id INTEGER PRIMARY KEY,previous_unit TEXT,previous_invocation TEXT,previous_cgroup TEXT,successor_unit TEXT,successor_sha256 TEXT,owner TEXT,generation INTEGER,phase TEXT,successor_pid INTEGER); INSERT INTO wake_cooperative_handoff VALUES(1,'bad','bad','bad','bad','bad','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',1,'waiting',NULL);").unwrap();
        install_guard(&db).unwrap();
        assert!(
            db.execute(
                "UPDATE wake_delivery_claim_gate SET owner=?1,generation=2 WHERE id=1",
                [next]
            )
            .is_err()
        );
        assert!(
            db.execute(
                "UPDATE wake_delivery_claim_gate SET is_open=1,receiver_pid=?1 WHERE id=1",
                [std::process::id()]
            )
            .is_err()
        );
        assert!(
            crate::bridge::control_claim_gate(&mut db, "transfer", owner, Some(1), Some(next))
                .is_err()
        );
        assert!(crate::bridge::bind_receiver_gate(&mut db, owner, 1).is_err());
        let state: (bool, String, i64) = db
            .query_row(
                "SELECT is_open,owner,generation FROM wake_delivery_claim_gate",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, (false, owner.to_owned(), 1));
    }
}

pub(crate) fn run(config: &crate::manager::Config, unit: &str) -> Result<serde_json::Value> {
    use std::{
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
        time::Instant,
    };
    crate::manager::require_installed(config)?;
    let _guard = crate::manager::lock(config)?;
    crate::manager::require_installed(config)?;
    ensure!(
        !config.webhooks_enabled && config.rpc_socket != config.state.join("app-server.sock"),
        "Cooperative upgrades require an independent controller and webhook"
    );
    ensure!(valid_unit(unit), "Invalid cooperative receiver unit");
    let mut db = crate::bridge::open_existing_owned(&config.db)?;
    let (owner, generation, open, pid, start, boot, namespace, token): (String, i64, bool, i64, i64, String, String, String) = db.query_row(
        "SELECT owner,generation,is_open,receiver_pid,receiver_start,receiver_boot,receiver_namespace,receiver_token FROM wake_delivery_claim_gate WHERE id=1", [],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
    ).context("An active process-bound cooperative receiver is required")?;
    ensure!(
        open && generation > 0 && !token.is_empty(),
        "Receiver is not active and bound"
    );
    let old = match properties(unit).and_then(|old| {
        ensure!(
            field(&old, "ActiveState")? == "active"
                && field(&old, "SubState")? == "running"
                && field(&old, "MainPID")? == pid.to_string(),
            "Predecessor unit does not own the bound receiver"
        );
        Ok(old)
    }) {
        Ok(old) => old,
        Err(error) => {
            close_generation(&db, &owner, generation)?;
            return Err(error);
        }
    };
    ensure!(
        field(&old, "Restart")? == "no"
            && field(&old, "KillMode")? == "control-group"
            && field(&old, "RemainAfterExit")? == "yes",
        "Invalid predecessor unit policy"
    );
    let invocation = field(&old, "InvocationID")?.to_owned();
    let old_cgroup = field(&old, "ControlGroup")?.to_owned();
    ensure!(
        valid_invocation(&invocation) && valid_cgroup(&old_cgroup),
        "Invalid predecessor identity"
    );
    let pid_u32 = u32::try_from(pid)?;
    ensure!(
        crate::obligations::process_start_time(pid_u32).and_then(|n| i64::try_from(n).ok())
            == Some(start),
        "Predecessor process was replaced"
    );
    let current = crate::conditions::current_sender_identity()?;
    ensure!(
        boot == current.boot
            && namespace == current.namespace
            && fs::read_link(format!("/proc/{pid}/ns/pid"))?.to_str() == Some(namespace.as_str()),
        "Predecessor process namespace changed"
    );
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?
            .lines()
            .any(|line| line.strip_prefix("0::") == Some(old_cgroup.as_str())),
        "Predecessor cgroup identity mismatch"
    );
    ensure!(
        fs::metadata(format!("/proc/{pid}"))?.uid() == fs::metadata("/proc/self")?.uid(),
        "Predecessor belongs to another user"
    );
    let executable = fs::read("/proc/self/exe")?;
    let digest = format!("{:x}", Sha256::digest(&executable));
    let old_digest = format!(
        "{:x}",
        Sha256::digest(fs::read(format!("/proc/{pid}/exe"))?)
    );
    if managed(&db)? {
        let (saved_unit, saved_digest, saved_owner, saved_generation): (String, String, String, i64) = db.query_row(
            "SELECT successor_unit,successor_sha256,owner,generation FROM wake_cooperative_handoff WHERE id=1 AND phase='active'", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        )?;
        ensure!(
            saved_unit == unit
                && saved_digest == old_digest
                && saved_owner == owner
                && saved_generation == generation,
            "Active receiver does not match the last managed handoff"
        );
    } else {
        ensure!(
            old_digest == digest,
            "Unmanaged receiver executable is not the verified cooperative version"
        );
    }
    crate::manager::private_dir(&config.runtime)?;
    let executable_path = config.runtime.join(format!("cooperative-{digest}"));
    if !executable_path.try_exists()? {
        let mut file = tempfile::NamedTempFile::new_in(&config.runtime)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o700))?;
        file.write_all(&executable)?;
        file.as_file().sync_all()?;
        if let Err(error) = file.persist_noclobber(&executable_path)
            && error.error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(error.error.into());
        }
    }
    let meta = fs::symlink_metadata(&executable_path)?;
    ensure!(
        meta.is_file()
            && meta.uid() == current_uid()?
            && meta.permissions().mode() & 0o100 != 0
            && meta.permissions().mode() & 0o077 == 0
            && format!("{:x}", Sha256::digest(fs::read(&executable_path)?)) == digest,
        "Staged executable failed verification"
    );
    let new_owner = uuid::Uuid::new_v4().to_string();
    let new_generation = generation
        .checked_add(1)
        .context("Gate generation exhausted")?;
    let new_unit = format!("codex-wake-coop-{}.service", uuid::Uuid::new_v4());
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS wake_cooperative_handoff(id INTEGER PRIMARY KEY CHECK(id=1),previous_unit TEXT NOT NULL,previous_invocation TEXT NOT NULL,previous_cgroup TEXT NOT NULL,successor_unit TEXT NOT NULL,successor_sha256 TEXT NOT NULL,owner TEXT NOT NULL,generation INTEGER NOT NULL,phase TEXT NOT NULL,successor_pid INTEGER)")?;
    tx.execute("INSERT INTO wake_cooperative_handoff(id,previous_unit,previous_invocation,previous_cgroup,successor_unit,successor_sha256,owner,generation,phase) VALUES(1,?1,?2,?3,?4,?5,?6,?7,'transfer') ON CONFLICT(id) DO UPDATE SET previous_unit=excluded.previous_unit,previous_invocation=excluded.previous_invocation,previous_cgroup=excluded.previous_cgroup,successor_unit=excluded.successor_unit,successor_sha256=excluded.successor_sha256,owner=excluded.owner,generation=excluded.generation,phase='transfer',successor_pid=NULL", rusqlite::params![unit,invocation,old_cgroup,new_unit,digest,new_owner,new_generation])?;
    install_guard(&tx)?;
    ensure!(tx.execute("UPDATE wake_delivery_claim_gate SET is_open=0,owner=?1,generation=?2,receiver_pid=NULL,receiver_start=NULL,receiver_boot=NULL,receiver_namespace=NULL,receiver_token=NULL WHERE id=1 AND is_open=1 AND owner=?3 AND generation=?4 AND receiver_pid=?5 AND receiver_start=?6 AND receiver_boot=?7 AND receiver_namespace=?8 AND receiver_token=?9", rusqlite::params![new_owner,new_generation,owner,generation,pid,start,boot,namespace,token])? == 1, "Receiver gate changed during preparation");
    ensure!(
        tx.execute(
            "UPDATE wake_cooperative_handoff SET phase='waiting' WHERE id=1 AND phase='transfer'",
            []
        )? == 1,
        "Managed handoff state changed"
    );
    tx.commit()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let old = properties(unit)?;
        ensure!(
            field(&old, "InvocationID")? == invocation,
            "Predecessor invocation changed after closure"
        );
        if field(&old, "MainPID")? == "0" {
            successful_previous(&old, &invocation)?;
            if drained(&old_cgroup)? {
                break;
            }
        }
        ensure!(
            Instant::now() < deadline,
            "Predecessor did not drain before deadline"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let home = std::env::var_os("HOME").context("HOME missing")?;
    let mut command = Command::new("/usr/bin/systemd-run");
    command
        .args([
            "--user",
            "--quiet",
            &format!("--unit={new_unit}"),
            "--property=Type=exec",
            "--property=Restart=no",
            "--property=RemainAfterExit=yes",
            "--property=KillMode=control-group",
            "--property=StandardOutput=null",
            "--property=StandardError=null",
            "/usr/bin/env",
            "-i",
        ])
        .arg(format!("HOME={}", home.to_string_lossy()))
        .arg("PATH=/usr/bin:/bin")
        .arg(format!("XDG_RUNTIME_DIR=/run/user/{}", current_uid()?))
        .arg(format!(
            "XDG_STATE_HOME={}",
            config
                .state
                .parent()
                .context("Missing state parent")?
                .display()
        ))
        .arg(format!(
            "XDG_DATA_HOME={}",
            config
                .runtime
                .parent()
                .and_then(Path::parent)
                .context("Missing data parent")?
                .display()
        ))
        .arg(format!(
            "XDG_CONFIG_HOME={}",
            config
                .config
                .parent()
                .context("Missing config parent")?
                .display()
        ))
        .arg(format!(
            "XDG_CACHE_HOME={}",
            config
                .cache
                .parent()
                .context("Missing cache parent")?
                .display()
        ))
        .arg(format!("CODEX_HOME={}", config.codex_home.display()))
        .arg(format!("CODEX_WAKE_DB={}", config.db.display()))
        .arg(format!("CODEX_WAKE_CODEX={}", config.codex.display()))
        .arg(format!("CODEX_WAKE_GH={}", config.gh.display()))
        .arg(format!(
            "CODEX_WAKE_RPC_SOCKET={}",
            config.rpc_socket.display()
        ))
        .arg("CODEX_WAKE_ENABLE_WEBHOOKS=0")
        .arg("CODEX_WAKE_COOPERATIVE_RECEIVER=1")
        .arg("CODEX_WAKE_RECEIVER_STANDBY=1")
        .arg("CODEX_WAKE_RECEIVER_AUTO=1")
        .arg(format!("CODEX_WAKE_GATE_OWNER={new_owner}"))
        .arg(format!("CODEX_WAKE_GATE_GENERATION={new_generation}"));
    if let Some(base) = &config.plugin_base {
        command.arg(format!("CODEX_WAKE_PLUGIN_BASE={}", base.display()));
    }
    command.arg(&executable_path).arg("receiver");
    let since = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let result = (|| -> Result<serde_json::Value> {
        let out = crate::manager::run(&mut command, Duration::from_secs(30))?;
        ensure!(out.status.success(), "Cannot start successor unit");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let successor = properties(&new_unit)?;
            let state = field(&successor, "ActiveState")?;
            ensure!(
                state != "failed" && state != "inactive",
                "Successor unit failed before readiness"
            );
            let (open, bound): (bool, Option<i64>) = db.query_row("SELECT is_open,receiver_pid FROM wake_delivery_claim_gate WHERE id=1 AND owner=?1 AND generation=?2", rusqlite::params![new_owner,new_generation], |r| Ok((r.get(0)?,r.get(1)?)))?;
            if let Some(pid) = bound.filter(|pid| {
                open && field(&successor, "MainPID").is_ok_and(|v| v == pid.to_string())
            }) {
                let telemetry = Connection::open_with_flags(
                    config.state.join("telemetry.sqlite3"),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
                );
                if telemetry.and_then(|db| db.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE pid=?1 AND at_ms>=?2 AND operation='receiver.heartbeat' AND outcome='ok')", rusqlite::params![pid,since], |r| r.get::<_,bool>(0))).unwrap_or(false) {
                    let check = properties(&new_unit)?;
                    ensure!(field(&check, "InvocationID")? == field(&successor, "InvocationID")? && field(&check, "MainPID")? == pid.to_string() && field(&check, "ActiveState")? == "active", "Successor changed after readiness");
                    return Ok(serde_json::json!({"unit":new_unit,"owner":new_owner,"generation":new_generation,"state":"ready"}));
                }
            }
            ensure!(
                Instant::now() < deadline,
                "Successor did not become ready before deadline"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    })();
    if result.is_err() {
        db.execute("UPDATE wake_delivery_claim_gate SET is_open=0 WHERE id=1 AND owner=?1 AND generation=?2", rusqlite::params![new_owner,new_generation]).context("Could not close gate after successor failure")?;
    }
    result
}

fn current_uid() -> Result<u32> {
    use std::os::unix::fs::MetadataExt;
    Ok(fs::metadata("/proc/self")?.uid())
}
