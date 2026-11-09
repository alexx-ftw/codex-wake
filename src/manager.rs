use anyhow::{Context, Result, bail, ensure};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::TcpStream,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

const UNIT: &str = "codex-wake.service";
const CLEANUP_UNIT: &str = "codex-wake-cleanup.service";
const CLEANUP_PATH: &str = "codex-wake-cleanup.path";
const MARKER: &str = "# Managed by codex-wake v1\n";
const HOOKS: &str = include_str!("../hooks.json.tmpl");
const ARCHIVE_SHA: &str = "3cdf93f0615f11bfc575c158d0d613666394228f6e830ff6f792178933773f7b";
const WEBHOOK_SHA: &str = "12c895f29250cbc4289ca45838235d334b39af6cf49d8e17fb43d8efed10372d";
const FUNNEL_PATH: &str = "/hooks/codex-wake";
const FUNNEL_PROXY: &str = "http://127.0.0.1:9000/hooks/codex-wake";

fn tailscale(args: &[&str]) -> Result<Value> {
    let out = run(
        Command::new(find_program("tailscale")?).args(args),
        Duration::from_secs(20),
    )?;
    ensure!(
        out.status.success(),
        "Tailscale command failed; inspect tailscaled status"
    );
    if args.contains(&"status") {
        Ok(serde_json::from_slice(&out.stdout)?)
    } else {
        Ok(Value::Null)
    }
}

fn read_funnel(config: &Config) -> Result<Option<String>> {
    let path = config.state.join("funnel.json");
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        meta.is_file()
            && meta.uid() == fs::metadata("/proc/self")?.uid()
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= 4096,
        "Funnel ownership record is not private"
    );
    let record: Value = serde_json::from_slice(&fs::read(path)?)?;
    let server = record["server"].as_str().context("Missing Funnel server")?;
    ensure!(
        record["version"] == 1
            && server.ends_with(".ts.net:443")
            && server
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:".contains(&b)),
        "Invalid Funnel ownership record"
    );
    Ok(Some(server.to_owned()))
}

fn funnel_proxy<'a>(status: &'a Value, server: &str) -> Option<&'a str> {
    status
        .get("Web")?
        .get(server)?
        .get("Handlers")?
        .get(FUNNEL_PATH)?
        .get("Proxy")?
        .as_str()
}

fn current_funnel_server(status: &Value) -> Result<String> {
    let dns = status
        .pointer("/Self/DNSName")
        .and_then(Value::as_str)
        .context("Missing current Tailscale DNS name")?
        .trim_end_matches('.');
    Ok(format!("{dns}:443"))
}

pub fn record_funnel(config: &Config) -> Result<Value> {
    ensure!(
        config.webhooks_enabled,
        "Enable optional webhooks before adopting a Funnel route"
    );
    require_installed(config)?;
    let _guard = lock(config)?;
    require_installed(config)?;
    let status = tailscale(&["funnel", "status", "--json"])?;
    let servers: Vec<_> = status["Web"]
        .as_object()
        .context("No configured Funnel route")?
        .keys()
        .filter(|server| {
            funnel_proxy(&status, server) == Some(FUNNEL_PROXY)
                && status["AllowFunnel"][server.as_str()] == true
        })
        .collect();
    ensure!(
        servers.len() == 1 && status["TCP"]["443"]["HTTPS"] == true,
        "Expected exactly one HTTPS Funnel route for codex-wake"
    );
    let server = servers[0];
    ensure!(
        *server == current_funnel_server(&tailscale(&["status", "--json"])?)?,
        "Funnel route belongs to another node name"
    );
    ensure!(
        server.ends_with(".ts.net:443")
            && server
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:".contains(&b)),
        "Invalid Funnel server"
    );
    if let Some(existing) = read_funnel(config)? {
        ensure!(&existing == server, "Another Funnel route is already owned");
    }
    atomic_write(
        &config.state.join("funnel.json"),
        serde_json::to_vec(&json!({"version":1,"server":server}))?.as_slice(),
        0o600,
    )?;
    Ok(
        json!({"provider":"tailscale","url":format!("https://{}{FUNNEL_PATH}",server.trim_end_matches(":443")),"configured":true,"persistent":true}),
    )
}

fn funnel_status(config: &Config) -> Result<Value> {
    let Some(server) = read_funnel(config)? else {
        return Ok(Value::Null);
    };
    let status = tailscale(&["funnel", "status", "--json"])?;
    let current = current_funnel_server(&tailscale(&["status", "--json"])?)?;
    Ok(
        json!({"provider":"tailscale","url":format!("https://{}{FUNNEL_PATH}",server.trim_end_matches(":443")),"configured":current==server && funnel_proxy(&status,&server)==Some(FUNNEL_PROXY) && status["AllowFunnel"][&server]==true,"persistent":true}),
    )
}

fn remove_funnel_with(server: &str, call: &mut impl FnMut(&[&str]) -> Result<Value>) -> Result<()> {
    let status = call(&["funnel", "status", "--json"])?;
    // A changed target belongs to its new owner; never reset shared Tailscale config.
    if funnel_proxy(&status, server) != Some(FUNNEL_PROXY) {
        return Ok(());
    }
    if current_funnel_server(&call(&["status", "--json"])?)? != server {
        return Ok(());
    }
    call(&[
        "funnel",
        "--bg",
        "--yes",
        "--https=443",
        "--set-path=/hooks/codex-wake",
        "off",
    ])?;
    let after = call(&["funnel", "status", "--json"])?;
    ensure!(
        funnel_proxy(&after, server) != Some(FUNNEL_PROXY),
        "Owned Funnel route was not removed"
    );
    Ok(())
}

pub(crate) fn source_digest() -> String {
    let mut digest = Sha256::new();
    for source in [
        include_bytes!("main.rs").as_slice(),
        include_bytes!("manager.rs").as_slice(),
        include_bytes!("upgrade.rs").as_slice(),
        include_bytes!("coordination_view.rs").as_slice(),
        include_bytes!("conditions.rs").as_slice(),
        include_bytes!("condition_alerts.rs").as_slice(),
        include_bytes!("bridge.rs").as_slice(),
        include_bytes!("circular_waits.rs").as_slice(),
        include_bytes!("delivery_evidence.rs").as_slice(),
        include_bytes!("subscriptions.rs").as_slice(),
        include_bytes!("producers.rs").as_slice(),
        include_bytes!("result_conflicts.rs").as_slice(),
        include_bytes!("probe.rs").as_slice(),
        include_bytes!("goals.rs").as_slice(),
        include_bytes!("templates.rs").as_slice(),
        include_bytes!("execution.rs").as_slice(),
        include_bytes!("rules.rs").as_slice(),
        include_bytes!("uninstall.rs").as_slice(),
        include_bytes!("host_cleanup.rs").as_slice(),
        include_bytes!("observability.rs").as_slice(),
        include_bytes!("obligations.rs").as_slice(),
        include_bytes!("validation_obligations.rs").as_slice(),
        include_bytes!("telemetry.rs").as_slice(),
        include_bytes!("polling.rs").as_slice(),
        include_bytes!("observers.rs").as_slice(),
        include_bytes!("native_poll.rs").as_slice(),
        include_bytes!("steer.rs").as_slice(),
        include_bytes!("status_view.rs").as_slice(),
        include_bytes!("../hooks/hooks.json").as_slice(),
        include_bytes!("../scripts/interrupt.sh").as_slice(),
        include_bytes!("../Cargo.lock").as_slice(),
        HOOKS.as_bytes(),
    ] {
        digest.update(source.len().to_le_bytes());
        digest.update(source);
    }
    format!("{:x}", digest.finalize())
}

fn source_matches(stamp: &Value) -> bool {
    let source = source_digest();
    stamp["source"] == source
        || stamp["compatible_sources"]
            .as_array()
            .is_some_and(|sources| sources.contains(&json!(source)))
}

fn binary_matches_stamp(config: &Config, stamp: &Value) -> bool {
    fs::read(config.runtime.join("codex-wake"))
        .is_ok_and(|binary| stamp["binary"] == format!("{:x}", Sha256::digest(binary)))
}

fn runtime_matches(config: &Config) -> bool {
    (|| -> Result<bool> {
        let stamp: Value = serde_json::from_slice(&fs::read(config.runtime.join("runtime.json"))?)?;
        // Explicit aliases allow reviewed MCP-only updates without replacing a live receiver.
        Ok(source_matches(&stamp)
            && binary_matches_stamp(config, &stamp)
            && fs::read_to_string(config.runtime.join("hooks.json.tmpl"))? == HOOKS)
    })()
    .unwrap_or(false)
}

#[derive(Clone)]
pub struct Config {
    pub state: PathBuf,
    pub runtime: PathBuf,
    pub config: PathBuf,
    pub unit: PathBuf,
    pub db: PathBuf,
    pub codex: PathBuf,
    pub gh: PathBuf,
    pub webhooks_enabled: bool,
    pub codex_home: PathBuf,
    pub rpc_socket: PathBuf,
    pub cache: PathBuf,
    pub plugin_base: Option<PathBuf>,
}

fn xdg(name: &str, default: PathBuf) -> Result<PathBuf> {
    let path = env::var_os(name).map(PathBuf::from).unwrap_or(default);
    ensure!(path.is_absolute(), "{name} must be absolute");
    Ok(path)
}

pub fn find_program(name: &str) -> Result<PathBuf> {
    env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join(name))
        .find(|path| {
            path.is_file() && fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        })
        .with_context(|| format!("Executable {name} is required on PATH"))
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let home = PathBuf::from(env::var_os("HOME").context("HOME is missing")?);
        ensure!(home.is_absolute(), "HOME must be absolute");
        let state = xdg("XDG_STATE_HOME", home.join(".local/state"))?.join("codex-wake");
        let config_home = xdg("XDG_CONFIG_HOME", home.join(".config"))?;
        let runtime = xdg("XDG_DATA_HOME", home.join(".local/share"))?.join("codex-wake/runtime");
        let db = env::var_os("CODEX_WAKE_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|| state.join("state.sqlite3"));
        let codex_home = xdg("CODEX_HOME", home.join(".codex"))?;
        let rpc_socket = xdg("CODEX_WAKE_RPC_SOCKET", state.join("app-server.sock"))?;
        let cache = xdg("XDG_CACHE_HOME", home.join(".cache"))?.join("codex-wake");
        let saved = fs::read(state.join("installation.json"))
            .ok()
            .map(|bytes| serde_json::from_slice::<Value>(&bytes))
            .transpose()?;
        let codex = env::var_os("CODEX_WAKE_CODEX")
            .map(PathBuf::from)
            .or_else(|| saved.as_ref()?.get("codex")?.as_str().map(PathBuf::from))
            .unwrap_or_else(|| find_program("codex").unwrap_or_else(|_| PathBuf::from("codex")));
        let gh = env::var_os("CODEX_WAKE_GH")
            .map(PathBuf::from)
            .or_else(|| saved.as_ref()?.get("gh")?.as_str().map(PathBuf::from))
            .unwrap_or_else(|| find_program("gh").unwrap_or_else(|_| PathBuf::from("gh")));
        let webhooks_enabled = match env::var("CODEX_WAKE_ENABLE_WEBHOOKS").ok().as_deref() {
            Some("1" | "true") => true,
            Some("0" | "false") => false,
            Some(_) => bail!("CODEX_WAKE_ENABLE_WEBHOOKS must be 0 or 1"),
            None => saved
                .as_ref()
                .and_then(|value| value["webhooks_enabled"].as_bool())
                .unwrap_or(false),
        };
        let base = env::var_os("CODEX_WAKE_PLUGIN_BASE")
            .map(PathBuf::from)
            .or_else(|| {
                saved
                    .as_ref()?
                    .get("plugin_base")?
                    .as_str()
                    .map(PathBuf::from)
            });
        let plugin_base = if let Some(root) = env::var_os("CODEX_WAKE_PLUGIN_ROOT")
            .map(PathBuf::from)
            .filter(|root| root.starts_with(codex_home.join("plugins/cache")))
        {
            Some(crate::uninstall::plugin_base(&codex_home, &root)?)
        } else {
            base.map(|base| crate::uninstall::plugin_base(&codex_home, &base.join("installed")))
                .transpose()?
        };
        Ok(Self {
            state,
            runtime,
            config: config_home.join("codex-wake"),
            unit: config_home.join("systemd/user").join(UNIT),
            db,
            codex,
            gh,
            webhooks_enabled,
            codex_home,
            rpc_socket,
            cache,
            plugin_base,
        })
    }
}

pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.uid() == fs::metadata("/proc/self")?.uid(),
        "Directory is not owned by this user"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn run(command: &mut Command, timeout: Duration) -> Result<Output> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()?;
    let status = match child.wait_timeout(timeout)? {
        Some(status) => status,
        None => {
            child.kill()?;
            child.wait()?;
            bail!("Command timed out; inspect state before retrying");
        }
    };
    use std::io::{Seek, SeekFrom};
    let mut stdout = stdout;
    let mut stderr = stderr;
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.take(1024 * 1024).read_to_end(&mut output.stdout)?;
    stderr.take(1024 * 1024).read_to_end(&mut output.stderr)?;
    Ok(output)
}

pub(crate) fn systemctl(args: &[&str]) -> Result<String> {
    let mut command = Command::new("systemctl");
    command.arg("--user").args(args);
    if env::var_os("XDG_RUNTIME_DIR").is_none() {
        let uid = fs::metadata("/proc/self")?.uid();
        let runtime = PathBuf::from(format!("/run/user/{uid}"));
        let meta = fs::symlink_metadata(&runtime)?;
        ensure!(
            meta.is_dir() && meta.uid() == uid,
            "Invalid user runtime directory"
        );
        command.env("XDG_RUNTIME_DIR", runtime);
    }
    let out = run(&mut command, Duration::from_secs(20))?;
    ensure!(
        out.status.success(),
        "systemctl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?)
}

pub(crate) fn lock(config: &Config) -> Result<File> {
    private_dir(&config.state)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(config.state.join("service.lock"))?;
    let meta = fs::symlink_metadata(config.state.join("service.lock"))?;
    ensure!(
        meta.is_file()
            && meta.permissions().mode() & 0o077 == 0
            && meta.uid() == fs::metadata("/proc/self")?.uid(),
        "Service lock is not a private owned file"
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(error) => bail!("Cannot acquire service lock: {error}"),
        }
    }
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(path.parent().context("Missing parent")?)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path)?;
    Ok(())
}

fn quote(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(|c| c.is_control()),
        "Invalid control character in service configuration"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}

pub(crate) fn unit(config: &Config) -> Result<String> {
    let exe = quote(
        config
            .runtime
            .join("codex-wake")
            .to_str()
            .context("Non-UTF8 path")?,
    )?;
    let runtime = config
        .runtime
        .to_str()
        .context("Non-UTF8 path")?
        .replace('%', "%%");
    let db = quote(&format!("CODEX_WAKE_DB={}", config.db.display()))?;
    let codex = quote(&format!("CODEX_WAKE_CODEX={}", config.codex.display()))?;
    let gh = quote(&format!("CODEX_WAKE_GH={}", config.gh.display()))?;
    let cfg_home = config.config.parent().context("Missing config parent")?;
    let cfg_home = quote(&format!("XDG_CONFIG_HOME={}", cfg_home.display()))?;
    let mut extra = [
        ("CODEX_HOME", config.codex_home.as_path()),
        ("CODEX_WAKE_RPC_SOCKET", config.rpc_socket.as_path()),
        (
            "XDG_STATE_HOME",
            config.state.parent().context("Missing state root")?,
        ),
        (
            "XDG_DATA_HOME",
            config
                .runtime
                .parent()
                .and_then(Path::parent)
                .context("Missing data root")?,
        ),
        (
            "XDG_CACHE_HOME",
            config.cache.parent().context("Missing cache root")?,
        ),
    ]
    .iter()
    .map(|(key, value)| {
        quote(&format!("{key}={}", value.display())).map(|value| format!("Environment={value}\n"))
    })
    .collect::<Result<Vec<_>>>()?
    .join("");
    if let Some(base) = &config.plugin_base {
        extra.push_str(&format!(
            "Environment={}\n",
            quote(&format!("CODEX_WAKE_PLUGIN_BASE={}", base.display()))?
        ));
    }
    extra.push_str(&format!(
        "Environment={gh}\nEnvironment=CODEX_WAKE_ENABLE_WEBHOOKS={}\n",
        u8::from(config.webhooks_enabled)
    ));
    Ok(format!(
        "{MARKER}[Unit]\nDescription=Codex Wake shared webhook receiver\nAfter=network.target\n\n[Service]\nType=simple\nWorkingDirectory={runtime}\nExecStart=:{exe} receiver\nEnvironment={db}\nEnvironment={codex}\nEnvironment={cfg_home}\n{extra}Restart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\n\n[Install]\nWantedBy=default.target\n"
    ))
}

fn obtain_webhook(runtime: &Path) -> Result<()> {
    let target = runtime.join("webhook");
    if target.is_file() {
        ensure!(
            format!("{:x}", Sha256::digest(fs::read(&target)?)) == WEBHOOK_SHA,
            "Managed receiver binary checksum mismatch"
        );
        return Ok(());
    }
    ensure!(
        env::consts::OS == "linux" && env::consts::ARCH == "x86_64",
        "Automatic receiver installation currently supports Linux x86_64"
    );
    let staging = tempfile::tempdir_in(runtime)?;
    let archive = staging.path().join("webhook.tar.gz");
    let output = run(Command::new("curl").args(["--fail", "--location", "--silent", "--show-error", "--max-time", "60", "--output"])
        .arg(&archive).arg("https://github.com/adnanh/webhook/releases/download/2.8.3/webhook-linux-amd64.tar.gz"), Duration::from_secs(65))?;
    ensure!(
        output.status.success(),
        "Could not download the verified webhook release"
    );
    ensure!(
        format!("{:x}", Sha256::digest(fs::read(&archive)?)) == ARCHIVE_SHA,
        "Receiver archive checksum mismatch"
    );
    let output = run(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(staging.path())
            .arg("webhook-linux-amd64/webhook"),
        Duration::from_secs(10),
    )?;
    ensure!(
        output.status.success(),
        "Could not extract verified receiver"
    );
    atomic_write(
        &target,
        &fs::read(staging.path().join("webhook-linux-amd64/webhook"))?,
        0o700,
    )
}

pub fn load_secret(path: &Path) -> Result<String> {
    private_dir(path.parent().context("Missing config directory")?)?;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            write!(
                file,
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )?;
            file.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && meta.permissions().mode() & 0o077 == 0
            && meta.uid() == fs::metadata("/proc/self")?.uid(),
        "Webhook secret must be a private file owned by this user"
    );
    let secret = fs::read_to_string(path)?.trim().to_owned();
    ensure!(!secret.is_empty(), "Webhook secret is empty");
    Ok(secret)
}

fn healthy(config: &Config) -> Result<()> {
    let pid = systemctl(&["show", UNIT, "--property=MainPID", "--value"])?;
    let pid: u32 = pid.trim().parse()?;
    ensure!(pid != 0, "Receiver has no running process");
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == config.runtime.join("codex-wake"),
        "Service executable differs from the managed receiver"
    );
    if !config.webhooks_enabled {
        let reply = crate::goals::rpc(&config.codex, "thread/loaded/list", json!({}))?;
        ensure!(
            reply["data"].is_array(),
            "Invalid controller readiness response"
        );
        return Ok(());
    }
    let body = b"{\"action\":\"started\"}";
    let secret = load_secret(&config.config.join("webhook.secret"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
    mac.update(body);
    let sig = format!("{:x}", mac.finalize().into_bytes());
    let mut socket =
        TcpStream::connect_timeout(&"127.0.0.1:9000".parse()?, Duration::from_secs(1))?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    write!(
        socket,
        "POST /hooks/codex-wake HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-GitHub-Event: workflow_run\r\nX-Hub-Signature-256: sha256={sig}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    socket.write_all(body)?;
    let mut response = String::new();
    socket.take(16384).read_to_string(&mut response)?;
    ensure!(
        response.starts_with("HTTP/1.1 403 "),
        "Receiver health signature/filter check failed"
    );
    Ok(())
}

pub fn status(config: &Config) -> Result<Value> {
    if crate::upgrade::configured(config) {
        return crate::upgrade::status(config);
    }
    let properties = systemctl(&[
        "show",
        UNIT,
        "--property=ActiveState,SubState,MainPID,UnitFileState,FragmentPath,DropInPaths",
    ])?;
    let fields: serde_json::Map<String, Value> = properties
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), json!(value)))
        .collect();
    let stamp = fs::read(config.runtime.join("runtime.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or(Value::Null);
    let source_compatible = source_matches(&stamp);
    let binary_verified = binary_matches_stamp(config, &stamp);
    let health = (|| {
        ensure!(
            fs::read_to_string(&config.unit)? == unit(config)?,
            "Service configuration differs from this runtime"
        );
        ensure!(
            fields.get("FragmentPath") == Some(&json!(config.unit.to_string_lossy())),
            "Unexpected systemd service owner"
        );
        ensure!(
            fields.get("DropInPaths") == Some(&json!("")),
            "Service has overrides"
        );
        ensure!(
            binary_verified,
            "Receiver binary does not match its recorded checksum"
        );
        ensure!(
            source_compatible,
            "MCP build differs from receiver source; reconnect MCP before treating this compatibility failure as receiver downtime"
        );
        ensure!(
            fs::read_to_string(config.runtime.join("hooks.json.tmpl"))? == HOOKS,
            "Receiver hook configuration differs"
        );
        if config.webhooks_enabled {
            ensure!(
                format!(
                    "{:x}",
                    Sha256::digest(fs::read(config.runtime.join("webhook"))?)
                ) == WEBHOOK_SHA,
                "Receiver binary checksum mismatch"
            );
        }
        healthy(config)
    })();
    let controller = (|| -> Result<()> {
        let reply = crate::goals::rpc(&config.codex, "thread/loaded/list", json!({}))?;
        ensure!(
            reply["data"].is_array(),
            "Invalid controller readiness response"
        );
        Ok(())
    })();
    let ingress = funnel_status(config)
        .unwrap_or_else(|error| json!({"error_class":crate::observability::error_class(&error)}));
    Ok(
        json!({"service":fields, "local_ready":health.is_ok(), "health_error":health.err().map(|e|e.to_string()),
        "controller_ready":controller.is_ok(),"controller_error":controller.err().map(|e|e.to_string()),
        "runtime":{"client_source":source_digest(),"receiver_source":stamp["source"],"client_source_compatible":source_compatible,"stored_binary_matches_stamp":binary_verified},
        "github_transport":"polling","webhooks_enabled":config.webhooks_enabled,
        "ingress_required":false,"ingress":ingress,"public_ingress_verified":false,"lifecycle":"shared persistent user service; closing MCP does not stop it"}),
    )
}

pub fn ensure_receiver(config: &Config) -> Result<Value> {
    if crate::upgrade::configured(config) || cooperative_receiver_enabled()? {
        return crate::upgrade::ensure_receiver(config);
    }
    ensure!(
        !cooperative_receiver_enabled()?,
        "Cooperative receiver is only available for direct experiments"
    );
    require_installed(config)?;
    let _guard = lock(config)?;
    require_installed(config)?;
    ensure!(
        config.db.is_absolute() && config.codex.is_absolute(),
        "Service database and Codex executable must be absolute paths"
    );
    let expected_unit = unit(config)?;
    let executable = fs::read(env::current_exe()?)?;
    let existing_unit = fs::read_to_string(&config.unit).unwrap_or_default();
    ensure!(
        existing_unit.is_empty() || existing_unit == expected_unit,
        "Existing service configuration is not this plugin's managed configuration; it was left untouched"
    );
    let properties = systemctl(&[
        "show",
        UNIT,
        "--property=ActiveState,FragmentPath,DropInPaths",
    ])?;
    ensure!(
        !properties
            .lines()
            .any(|l| l.starts_with("DropInPaths=") && l != "DropInPaths="),
        "Service has overrides; left untouched"
    );
    if let Some(fragment) = properties
        .lines()
        .find_map(|l| l.strip_prefix("FragmentPath="))
    {
        ensure!(
            fragment.is_empty() || Path::new(fragment) == config.unit,
            "Another service unit owns this name"
        );
    }
    let active = properties
        .lines()
        .any(|l| l == "ActiveState=active" || l == "ActiveState=activating");
    let runtime_matches = runtime_matches(config);
    ensure!(
        !active || (!existing_unit.is_empty() && runtime_matches),
        "Active receiver uses a different runtime; no files were changed or service restarted"
    );
    private_dir(&config.runtime)?;
    if !runtime_matches {
        atomic_write(&config.runtime.join("codex-wake"), &executable, 0o700)?;
        atomic_write(
            &config.runtime.join("hooks.json.tmpl"),
            HOOKS.as_bytes(),
            0o600,
        )?;
        let stamp =
            json!({"source":source_digest(),"binary":format!("{:x}",Sha256::digest(&executable))});
        atomic_write(
            &config.runtime.join("runtime.json"),
            stamp.to_string().as_bytes(),
            0o600,
        )?;
    }
    if config.webhooks_enabled {
        obtain_webhook(&config.runtime)?;
        load_secret(&config.config.join("webhook.secret"))?;
    }
    fs::create_dir_all(config.unit.parent().context("Missing unit directory")?)?;
    if existing_unit.is_empty() {
        atomic_write(&config.unit, expected_unit.as_bytes(), 0o600)?;
        systemctl(&["daemon-reload"])?;
    }
    install_cleanup(config)?;
    systemctl(&["enable", UNIT])?;
    if !active {
        systemctl(&["start", UNIT])?;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match healthy(config) {
            Ok(()) => {
                let result = status(config)?;
                ensure!(
                    result["local_ready"] == true,
                    "Receiver runtime verification failed: {}",
                    result["health_error"]
                );
                return Ok(result);
            }
            Err(error) if Instant::now() >= deadline => {
                return Err(error.context("Receiver did not become ready"));
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    remove_stale_socket_in(path, &env::temp_dir())
}

fn remove_stale_socket_in(path: &Path, temp: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let uid = fs::metadata("/proc/self")?.uid();
    if meta.file_type().is_symlink() && meta.uid() == uid {
        let target = fs::read_link(path)?;
        let daemon_dir = temp.join(format!("codex-daemon-{uid}"));
        let is_daemon_target = target.parent() == Some(daemon_dir.as_path())
            && target
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
        if is_daemon_target {
            match fs::symlink_metadata(&target) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::remove_file(path)?;
                    return Ok(());
                }
                Ok(target_meta)
                    if target_meta.file_type().is_socket() && target_meta.uid() == uid =>
                {
                    let dir = fs::symlink_metadata(&daemon_dir)?;
                    ensure!(
                        dir.is_dir() && dir.uid() == uid && dir.mode() & 0o077 == 0,
                        "Codex daemon directory is not private"
                    );
                    match UnixStream::connect(&target) {
                        Ok(_) => {
                            bail!("Controller socket is already active; it was left untouched")
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                            fs::remove_file(path)?;
                            return Ok(());
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
                _ => {}
            }
        }
    }
    ensure!(
        meta.file_type().is_socket() && meta.uid() == uid,
        "Controller path is not an owned socket"
    );
    match UnixStream::connect(path) {
        Ok(_) => bail!("Controller socket is already active; it was left untouched"),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(path)?
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn cooperative_receiver_enabled() -> Result<bool> {
    match env::var("CODEX_WAKE_COOPERATIVE_RECEIVER") {
        Err(env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        _ => bail!("CODEX_WAKE_COOPERATIVE_RECEIVER must be 0 or 1"),
    }
}

// Linearize each new cycle against closing the cooperative gate. The body of
// a previously admitted cycle may still run and capture new events.
fn receiver_cycle_allowed(config: &Config) -> Result<bool> {
    let mut db = crate::bridge::connect(&config.db)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let allowed = crate::bridge::claims_open(&tx)?;
    tx.commit()?;
    Ok(allowed)
}

fn receiver_start_cycle(config: &Config, cooperative: bool, stop: &Mutex<bool>) -> Result<bool> {
    let mut stopped = stop.lock().unwrap_or_else(|error| error.into_inner());
    if *stopped {
        return Ok(false);
    }
    if cooperative {
        match receiver_cycle_allowed(config) {
            Ok(true) => (),
            Ok(false) => {
                *stopped = true;
                return Ok(false);
            }
            Err(error) => {
                *stopped = true;
                return Err(error);
            }
        }
    }
    Ok(true)
}

// Standby is opt-in and performs no work until a coordinator opens the gate
// and sends a byte over the inherited stdin pipe. EOF is a failed handoff.
fn receiver_standby(config: &Config) -> Result<()> {
    let owner = env::var("CODEX_WAKE_GATE_OWNER").context("Missing gate owner")?;
    let parsed = uuid::Uuid::parse_str(&owner).context("Invalid gate owner")?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == owner,
        "Invalid gate owner"
    );
    let generation = env::var("CODEX_WAKE_GATE_GENERATION")?
        .parse::<i64>()
        .context("Invalid gate generation")?;
    ensure!(generation > 0, "Invalid gate generation");
    let mut db = crate::bridge::connect(&config.db)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let (open, current, current_generation): (bool, String, i64) = tx.query_row(
        "SELECT is_open,owner,generation FROM wake_delivery_claim_gate WHERE id=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    ensure!(
        !open && current == owner && current_generation == generation,
        "Standby requires the closed gate and matching owner and generation"
    );
    tx.commit()?;
    std::io::stdout().write_all(b"receiver-standby-ready-v1\n")?;
    std::io::stdout().flush()?;
    let mut signal = [0];
    std::io::stdin()
        .read_exact(&mut signal)
        .context("Standby control pipe closed")?;
    ensure!(signal[0] == b'G', "Invalid standby activation");
    let mut db = crate::bridge::connect(&config.db)?;
    crate::bridge::bind_receiver_gate(&mut db, &owner, generation)?;
    Ok(())
}

fn wait_receiver_workers(workers: Vec<thread::JoinHandle<Result<()>>>) -> Result<()> {
    let mut failed = false;
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => (),
            Ok(Err(error)) => {
                failed = true;
                crate::observability::emit(
                    "receiver.worker",
                    "error",
                    crate::observability::error_class(&error),
                    None,
                    Duration::ZERO,
                    1,
                );
            }
            Err(_) => {
                failed = true;
                crate::observability::emit(
                    "receiver.worker",
                    "error",
                    "worker_panicked",
                    None,
                    Duration::ZERO,
                    1,
                );
            }
        }
    }
    ensure!(!failed, "Receiver worker failed while stopping");
    Ok(())
}

fn spawn_receiver_worker(
    workers: &mut Vec<thread::JoinHandle<Result<()>>>,
    stop: &Mutex<bool>,
    run: impl FnOnce() -> Result<()> + Send + 'static,
) -> Result<()> {
    match thread::Builder::new().spawn(run) {
        Ok(worker) => {
            workers.push(worker);
            Ok(())
        }
        Err(error) => {
            *stop.lock().unwrap_or_else(|error| error.into_inner()) = true;
            let result = wait_receiver_workers(std::mem::take(workers));
            if result.is_err() {
                return Err(error).context("Start receiver worker; an existing worker also failed");
            }
            Err(error).context("Start receiver worker")
        }
    }
}

pub fn run_receiver(config: &Config) -> Result<()> {
    require_installed(config)?;
    let cooperative = cooperative_receiver_enabled()?;
    let standby = match env::var("CODEX_WAKE_RECEIVER_STANDBY") {
        Err(env::VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        _ => bail!("CODEX_WAKE_RECEIVER_STANDBY must be 1 or unset"),
    };
    ensure!(
        !standby || cooperative,
        "Standby requires cooperative receiver mode"
    );
    if cooperative {
        ensure!(
            config.rpc_socket != config.state.join("app-server.sock") && !config.webhooks_enabled,
            "Cooperative receiver requires an external controller and externally managed webhook"
        );
        ensure!(
            env::var_os("CODEX_WAKE_GATE_OWNER").is_some()
                && env::var_os("CODEX_WAKE_GATE_GENERATION").is_some(),
            "Cooperative receiver requires a gate owner and generation"
        );
        if !standby && env::var_os("CODEX_WAKE_RECEIVER_LIFECYCLE").is_none() {
            ensure!(
                receiver_cycle_allowed(config)?,
                "Cooperative receiver gate is closed or ownership is invalid"
            );
        }
    }
    let root = env::current_exe()?
        .parent()
        .context("Executable has no directory")?
        .to_path_buf();
    let binary = env::var_os("CODEX_WAKE_WEBHOOK")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("webhook"));
    private_dir(&config.state)?;
    let mut controller = if config.rpc_socket == config.state.join("app-server.sock") {
        remove_stale_socket(&config.rpc_socket)?;
        Some(ChildGuard(
            Command::new(&config.codex)
                .args(["app-server", "--listen"])
                .arg(format!("unix://{}", config.rpc_socket.display()))
                .env("CODEX_HOME", &config.codex_home)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        ))
    } else {
        UnixStream::connect(&config.rpc_socket)
            .context("Configured Codex control socket is unavailable")?;
        None
    };
    let mut receiver = if config.webhooks_enabled {
        Some(ChildGuard(
            Command::new(binary)
                .args([
                    "-verbose",
                    "-ip",
                    "127.0.0.1",
                    "-port",
                    "9000",
                    "-template",
                    "-hooks",
                ])
                .arg(root.join("hooks.json.tmpl"))
                .env(
                    "GITHUB_WEBHOOK_SECRET",
                    load_secret(&config.config.join("webhook.secret"))?,
                )
                .env("CODEX_WAKE_EXECUTABLE", env::current_exe()?)
                .env("CODEX_WAKE_DB", &config.db)
                .env("CODEX_WAKE_CODEX", &config.codex)
                .env("CODEX_WAKE_DEFER", "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        ))
    } else {
        None
    };
    if let Some(child) = &mut controller {
        if let Some(pipe) = child.0.stdout.take() {
            crate::observability::capture(pipe, "controller");
        }
        if let Some(pipe) = child.0.stderr.take() {
            crate::observability::capture(pipe, "controller");
        }
    }
    if let Some(child) = &mut receiver
        && let Some(pipe) = child.0.stdout.take()
    {
        crate::observability::capture(pipe, "webhook");
    }
    if let Some(child) = &mut receiver
        && let Some(pipe) = child.0.stderr.take()
    {
        crate::observability::capture(pipe, "webhook");
    }
    if env::var_os("CODEX_WAKE_RECEIVER_LIFECYCLE").is_some() {
        ensure!(
            !standby && cooperative && env::var("CODEX_WAKE_RECEIVER_LIFECYCLE")? == "1",
            "Invalid lifecycle receiver mode"
        );
        let mut db = crate::bridge::open_existing_owned(&config.db)?;
        crate::bridge::bind_receiver_gate(
            &mut db,
            &env::var("CODEX_WAKE_GATE_OWNER")?,
            env::var("CODEX_WAKE_GATE_GENERATION")?.parse()?,
        )?;
        crate::upgrade::await_activation(config)?;
    } else if standby {
        receiver_standby(config)?;
    }
    crate::observability::emit("receiver.start", "ok", "", None, Duration::ZERO, 1);
    // Observation must keep running while accepted deliveries wait on a busy Codex thread.
    let stop = Arc::new(Mutex::new(false));
    let mut workers = Vec::new();
    for source in ["github", "external", "native", "delivery"] {
        let poll_config = config.clone();
        let worker_stop = stop.clone();
        spawn_receiver_worker(&mut workers, &stop, move || {
            let mut history_scans = std::collections::HashMap::new();
            loop {
                if !receiver_start_cycle(&poll_config, cooperative, &worker_stop)? {
                    return Ok(());
                }
                let result = (|| -> Result<()> {
                    let mut db = crate::bridge::connect(&poll_config.db)?;
                    crate::subscriptions::initialize(&db)?;
                    crate::rules::initialize(&db)?;
                    match source {
                        "github" => {
                            crate::polling::tick(&db, &poll_config.gh)?;
                        }
                        "external" => {
                            crate::observers::tick(&db, &poll_config.codex)?;
                        }
                        "delivery" => {
                            crate::delivery_evidence::poll_history(
                                &mut db,
                                &poll_config.codex,
                                &mut history_scans,
                            )?;
                        }
                        _ => {
                            crate::native_poll::tick(&db, &poll_config.codex)?;
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    crate::observability::emit(
                        "poll.cycle",
                        "error",
                        crate::observability::error_class(&error),
                        Some(source),
                        Duration::ZERO,
                        1,
                    );
                }
                thread::sleep(Duration::from_secs(if source == "delivery" {
                    5
                } else {
                    1
                }));
            }
        })?;
    }
    let config = config.clone();
    let worker_stop = stop.clone();
    spawn_receiver_worker(&mut workers, &stop, move || {
        let mut heartbeat = Instant::now() - Duration::from_secs(60);
        let mut obligations_initialized = false;
        loop {
            if !receiver_start_cycle(&config, cooperative, &worker_stop)? {
                return Ok(());
            }
            let result = (|| -> Result<()> {
                let mut db = crate::bridge::connect(&config.db)?;
                crate::subscriptions::initialize(&db)?;
                crate::subscriptions::expiration_tick(
                    &db,
                    &config.codex,
                    Duration::from_secs(120),
                )?;
                crate::subscriptions::dependency_tick(
                    &db,
                    &config.codex,
                    Duration::from_secs(120),
                )?;
                if !obligations_initialized {
                    crate::obligations::initialize(&db)?;
                    obligations_initialized = true;
                }
                crate::process_interrupts(&config, &db)?;
                if let Err(error) = crate::dispatch_direct_pending(&mut db, &config.codex) {
                    crate::observability::emit(
                        "receiver.direct",
                        "error",
                        crate::observability::error_class(&error),
                        None,
                        Duration::ZERO,
                        1,
                    );
                }
                crate::bridge::dispatch(&mut db, &config.codex, Duration::from_secs(120))?;
                crate::subscriptions::dispatch(&mut db, &config.codex, Duration::from_secs(120))?;
                crate::conditions::initialize(&db)?;
                crate::dispatch_conditions(&db, &config.codex)?;
                crate::obligations::dispatch(&mut db, &config.codex, Duration::from_secs(120))?;
                crate::obligations::dispatch_coordinator_alerts(
                    &mut db,
                    &config.codex,
                    Duration::from_secs(30),
                )?;
                crate::circular_waits::initialize(&db)?;
                crate::circular_waits::dispatch(&mut db, &config.codex, Duration::from_secs(120))?;
                crate::rules::initialize(&db)?;
                crate::rules::dispatch(&mut db, &config.codex, &config.state.join("workspaces"))?;
                Ok(())
            })();
            if let Err(error) = result {
                crate::observability::emit(
                    "receiver.dispatch",
                    "error",
                    crate::observability::error_class(&error),
                    None,
                    Duration::ZERO,
                    1,
                );
            }
            if heartbeat.elapsed()
                >= Duration::from_secs(if env::var_os("CODEX_WAKE_RECEIVER_LIFECYCLE").is_some() {
                    5
                } else {
                    60
                })
            {
                if let Err(error) = observe_queues(&config) {
                    crate::observability::emit(
                        "queue.snapshot",
                        "error",
                        crate::observability::error_class(&error),
                        None,
                        Duration::ZERO,
                        1,
                    );
                }
                let started = Instant::now();
                let result = crate::goals::rpc(&config.codex, "thread/loaded/list", json!({}));
                crate::observability::emit(
                    "receiver.heartbeat",
                    if result.is_ok() { "ok" } else { "error" },
                    result
                        .as_ref()
                        .err()
                        .map(crate::observability::error_class)
                        .unwrap_or(""),
                    env::var("INVOCATION_ID").ok().as_deref(),
                    started.elapsed(),
                    1,
                );
                heartbeat = Instant::now();
            }
            thread::sleep(Duration::from_secs(1));
        }
    })?;
    loop {
        if cooperative
            && (*stop.lock().unwrap_or_else(|error| error.into_inner())
                || workers.iter().any(thread::JoinHandle::is_finished))
        {
            *stop.lock().unwrap_or_else(|error| error.into_inner()) = true;
            wait_receiver_workers(workers)?;
            crate::observability::emit(
                "receiver.drain",
                "ok",
                "cycles_finished_outcomes_not_verified",
                None,
                Duration::ZERO,
                1,
            );
            return Ok(());
        }
        if let Some(controller) = &mut controller
            && let Some(status) = controller.0.try_wait()?
        {
            crate::observability::emit(
                "controller.exit",
                "error",
                "child_exited",
                None,
                Duration::ZERO,
                status.code().unwrap_or(255) as u64,
            );
            bail!("Codex controller exited with {status}");
        }
        if let Some(receiver) = &mut receiver
            && let Some(status) = receiver.0.try_wait()?
        {
            crate::observability::emit(
                "webhook.exit",
                "error",
                "child_exited",
                None,
                Duration::ZERO,
                status.code().unwrap_or(255) as u64,
            );
            bail!("Webhook receiver exited with {status}");
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn observe_queues(config: &Config) -> Result<()> {
    let db = crate::bridge::connect(&config.db)?;
    crate::steer::initialize(&db)?;
    crate::circular_waits::initialize(&db)?;
    crate::obligations::initialize(&db)?;
    for (table, operation) in [
        ("waits", "queue.waits"),
        ("subscriptions", "queue.subscriptions"),
        ("rule_deliveries", "queue.rules"),
        ("steers", "queue.steers"),
        ("circular_notices", "queue.circular_notices"),
        ("coordinator_alerts", "queue.coordinator_alerts"),
    ] {
        let mut statement = db.prepare(&format!("SELECT state,count(*),coalesce(max(max(0,unixepoch()-unixepoch(updated))),0) FROM {table} GROUP BY state"))?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (state, count, age) = row?;
            let state = match state.as_str() {
                "waiting" => "waiting",
                "ready" => "ready",
                "sending" => "sending",
                "creating" => "creating",
                "queued" => "queued",
                "needs_attention" => "needs_attention",
                "pending" => "pending",
                "claimed" => "claimed",
                _ => "unknown_state",
            };
            crate::observability::emit(
                operation,
                "snapshot",
                state,
                None,
                Duration::from_secs(age.max(0) as u64),
                count.max(0) as u64,
            );
        }
    }
    Ok(())
}

pub fn require_installed(config: &Config) -> Result<()> {
    if let Some(base) = &config.plugin_base {
        ensure!(
            base.is_dir(),
            "Plugin was uninstalled; refusing to recreate its resources"
        );
    }
    Ok(())
}

fn cleanup_units(config: &Config) -> Result<(String, String)> {
    let base = config
        .plugin_base
        .as_ref()
        .context("Missing installed plugin identity")?;
    let parent = base
        .parent()
        .context("Missing plugin cache parent")?
        .to_str()
        .context("Non-UTF8 plugin path")?;
    ensure!(!parent.chars().any(char::is_control), "Invalid plugin path");
    let environment = unit(config)?
        .lines()
        .filter(|line| line.starts_with("Environment="))
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let executable = quote(
        config
            .runtime
            .join("codex-wake")
            .to_str()
            .context("Non-UTF8 runtime")?,
    )?;
    Ok((
        format!(
            "{MARKER}[Unit]\nDescription=Remove uninstalled Codex Wake resources\nStartLimitIntervalSec=0\n\n[Service]\nType=oneshot\nWorkingDirectory=/\nExecStart=:{executable} cleanup-uninstalled\n{environment}TimeoutStartSec=120\nRestart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\n\n[Install]\nWantedBy=default.target\n"
        ),
        format!(
            "{MARKER}[Unit]\nDescription=Observe Codex Wake plugin removal\n\n[Path]\nPathChanged={}\nUnit={CLEANUP_UNIT}\n\n[Install]\nWantedBy=default.target\n",
            parent.replace('%', "%%")
        ),
    ))
}

fn install_cleanup(config: &Config) -> Result<()> {
    let Some(base) = &config.plugin_base else {
        return Ok(());
    };
    let (service, path) = cleanup_units(config)?;
    let directory = config.unit.parent().context("Missing unit directory")?;
    let mut changed = false;
    for (name, contents) in [(CLEANUP_UNIT, service), (CLEANUP_PATH, path)] {
        let destination = directory.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(meta) => {
                ensure!(
                    meta.is_file() && meta.uid() == fs::metadata("/proc/self")?.uid(),
                    "Cleanup unit is not an owned regular file"
                );
                ensure!(
                    fs::read_to_string(&destination)? == contents,
                    "Cleanup unit belongs to another configuration"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                atomic_write(&destination, contents.as_bytes(), 0o600)?;
                changed = true;
            }
            Err(error) => return Err(error.into()),
        }
    }
    atomic_write(
        &config.state.join("installation.json"),
        serde_json::to_vec(&json!({"plugin_base":base,"codex":config.codex,"gh":config.gh,"webhooks_enabled":config.webhooks_enabled}))?.as_slice(),
        0o600,
    )?;
    if changed {
        systemctl(&["daemon-reload"])?;
    }
    systemctl(&["enable", "--now", CLEANUP_PATH, CLEANUP_UNIT])?;
    Ok(())
}

pub struct ClientRegistration(PathBuf);
impl Drop for ClientRegistration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn process_start(pid: u32) -> Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(stat
        .rsplit_once(") ")
        .context("Invalid process identity")?
        .1
        .split_whitespace()
        .nth(19)
        .context("Missing process start time")?
        .to_owned())
}

pub fn register_client(config: &Config) -> Result<Option<ClientRegistration>> {
    if config.plugin_base.is_none() {
        return Ok(None);
    }
    let _guard = lock(config)?;
    require_installed(config)?;
    let clients = config.state.join("clients");
    private_dir(&clients)?;
    let pid = std::process::id();
    let executable = fs::metadata("/proc/self/exe")?;
    let path = clients.join(format!("{pid}.json"));
    atomic_write(
        &path,
        &serde_json::to_vec(
            &json!({"pid":pid,"start":process_start(pid)?,"dev":executable.dev(),"ino":executable.ino()}),
        )?,
        0o600,
    )?;
    Ok(Some(ClientRegistration(path)))
}

fn stop_clients(config: &Config) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let clients = config.state.join("clients");
    let entries = match fs::read_dir(clients) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        ensure!(entry.file_type()?.is_file(), "Invalid client registration");
        let record: Value = serde_json::from_slice(&fs::read(entry.path())?)?;
        let pid = record["pid"]
            .as_u64()
            .filter(|pid| *pid > 1 && *pid <= i32::MAX as u64)
            .context("Invalid client PID")? as u32;
        // A pidfd cannot be redirected to a different process if a PID gets reused.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error.into());
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
        let Ok(meta) = fs::metadata(format!("/proc/{pid}/exe")) else {
            continue;
        };
        if process_start(pid).ok().as_deref() != record["start"].as_str()
            || record["dev"].as_u64() != Some(meta.dev())
            || record["ino"].as_u64() != Some(meta.ino())
        {
            continue;
        }
        let signal = |signal: libc::c_int| -> Result<()> {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    descriptor.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        };
        signal(libc::SIGTERM)?;
        thread::sleep(Duration::from_millis(100));
        signal(libc::SIGKILL)?;
    }
    Ok(())
}

pub fn cleanup_uninstalled(config: &Config) -> Result<()> {
    let Some(base) = &config.plugin_base else {
        return Ok(());
    };
    if base.try_exists()? {
        return Ok(());
    }
    let _guard = lock(config)?;
    if base.try_exists()? {
        return Ok(());
    }
    let directory = config.unit.parent().context("Missing unit directory")?;
    let (cleanup_service, cleanup_path) = cleanup_units(config)?;
    // Validate every unit before stopping or deleting anything.
    for (path, contents) in [
        (config.unit.clone(), unit(config)?),
        (directory.join(CLEANUP_UNIT), cleanup_service.clone()),
        (directory.join(CLEANUP_PATH), cleanup_path.clone()),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                ensure!(
                    meta.is_file() && meta.uid() == fs::metadata("/proc/self")?.uid(),
                    "Unrelated unit path; cleanup refused"
                );
                ensure!(
                    fs::read_to_string(path)? == contents,
                    "Unrelated service configuration; cleanup refused"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let properties = systemctl(&[
        "show",
        UNIT,
        "--property=FragmentPath,DropInPaths,ActiveState",
    ])?;
    for property in properties.lines() {
        if let Some(fragment) = property.strip_prefix("FragmentPath=") {
            ensure!(
                fragment.is_empty() || Path::new(fragment) == config.unit,
                "Another service owns this name"
            );
        }
        if let Some(overrides) = property.strip_prefix("DropInPaths=") {
            ensure!(
                overrides.is_empty(),
                "Service has unrelated overrides; cleanup refused"
            );
        }
    }
    let marketplace = base
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .context("Missing marketplace identity")?;
    let plugin_id = format!("codex-wake@{marketplace}");
    let plugin_data = config
        .codex_home
        .join("plugins/data")
        .join(marketplace)
        .join("codex-wake");
    let trees = [
        config.cache.as_path(),
        config.config.as_path(),
        config.runtime.parent().context("Missing runtime root")?,
        plugin_data.as_path(),
        config.state.as_path(),
    ];
    for path in trees {
        crate::uninstall::validate_owned_tree(path)?;
    }
    let external_db = config.db.try_exists()?
        && !config
            .db
            .canonicalize()?
            .starts_with(config.state.canonicalize()?);
    if external_db {
        crate::uninstall::validate_external_database(&config.db)?;
    }
    let metadata_socket = config.state.join("cleanup.sock");
    if let Some(server) = read_funnel(config)? {
        remove_funnel_with(&server, &mut tailscale)?;
    }
    remove_stale_socket(&metadata_socket)?;
    let mut metadata = ChildGuard(
        Command::new(&config.codex)
            .args(["app-server", "--listen"])
            .arg(format!("unix://{}", metadata_socket.display()))
            .env("CODEX_HOME", &config.codex_home)
            .stdin(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !metadata_socket.exists() {
        ensure!(
            metadata.0.try_wait()?.is_none(),
            "Metadata controller exited"
        );
        ensure!(
            Instant::now() < deadline,
            "Metadata controller did not start"
        );
        thread::sleep(Duration::from_millis(50));
    }
    crate::host_cleanup::clear_records(&config.codex, &metadata_socket, &plugin_id, &config.cache)?;
    drop(metadata);
    if base.try_exists()? {
        return Ok(());
    }
    systemctl(&["disable", "--now", CLEANUP_PATH])?;
    if config.unit.try_exists()? {
        systemctl(&["disable", "--now", UNIT])?;
    }
    systemctl(&["disable", CLEANUP_UNIT])?;
    stop_clients(config)?;
    // Refuse cleanup while a poll commit is active. Keep this directory lock
    // until the owned tree is gone, so no waiter can commit against it.
    let _poll_guard = if !external_db && config.db.try_exists()? {
        Some(crate::polling::lock_database_parent(
            &config.db.canonicalize()?,
            true,
        )?)
    } else {
        None
    };
    crate::uninstall::remove_unit_file(&config.unit, &unit(config)?)?;
    crate::uninstall::remove_unit_file(&directory.join(CLEANUP_PATH), &cleanup_path)?;
    crate::uninstall::remove_unit_file(&directory.join(CLEANUP_UNIT), &cleanup_service)?;
    systemctl(&["daemon-reload"])?;
    if external_db {
        crate::uninstall::remove_external_database(&config.db)?;
    }
    for path in trees {
        crate::uninstall::remove_owned_tree(path)?;
    }
    for parent in [base.parent(), plugin_data.parent()].into_iter().flatten() {
        match fs::remove_dir(parent) {
            Ok(()) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn remove_service(config: &Config) -> Result<()> {
    let _guard = lock(config)?;
    let contents = fs::read_to_string(&config.unit)?;
    ensure!(
        contents.starts_with(MARKER) && contents == unit(config)?,
        "Refusing to remove a service not owned by this configuration"
    );
    systemctl(&["disable", "--now", UNIT])?;
    fs::remove_file(&config.unit)?;
    systemctl(&["daemon-reload"])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_admission_error_latches_stop() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_path_buf();
        let config = Config {
            state: path.clone(),
            runtime: path.clone(),
            config: path.clone(),
            unit: path.clone(),
            db: path.clone(),
            codex: path.clone(),
            gh: path.clone(),
            webhooks_enabled: false,
            codex_home: path.clone(),
            rpc_socket: path.clone(),
            cache: path,
            plugin_base: None,
        };
        let stop = Mutex::new(false);
        assert!(receiver_start_cycle(&config, true, &stop).is_err());
        assert!(!receiver_start_cycle(&config, false, &stop).unwrap());
    }

    #[test]
    fn receiver_worker_failure_still_waits_for_active_worker() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let active = thread::spawn(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        });
        started_rx.recv().unwrap();
        let failed = thread::spawn(|| -> Result<()> { bail!("test failure") });
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            done_tx
                .send(wait_receiver_workers(vec![failed, active]).is_err())
                .unwrap();
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(200)).is_err());
        release_tx.send(()).unwrap();
        assert!(done_rx.recv_timeout(Duration::from_secs(5)).unwrap());
        waiter.join().unwrap();
    }

    #[test]
    fn funnel_cleanup_removes_only_unchanged_owned_path() {
        let server = "test.tail123.ts.net:443";
        let before = json!({"Web":{server:{"Handlers":{
            FUNNEL_PATH:{"Proxy":FUNNEL_PROXY},"/unrelated":{"Proxy":"http://127.0.0.1:1234"}
        }}}});
        let after =
            json!({"Web":{server:{"Handlers":{"/unrelated":{"Proxy":"http://127.0.0.1:1234"}}}}});
        let mut commands = Vec::new();
        remove_funnel_with(server, &mut |args| {
            commands.push(args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            Ok(match commands.len() {
                1 => before.clone(),
                2 => json!({"Self":{"DNSName":"test.tail123.ts.net."}}),
                3 => Value::Null,
                _ => after.clone(),
            })
        })
        .unwrap();
        assert_eq!(
            commands[2],
            vec![
                "funnel",
                "--bg",
                "--yes",
                "--https=443",
                "--set-path=/hooks/codex-wake",
                "off"
            ]
        );
        assert_eq!(commands.len(), 4);
        assert_eq!(
            after["Web"][server]["Handlers"]["/unrelated"]["Proxy"],
            "http://127.0.0.1:1234"
        );
    }

    #[test]
    fn funnel_cleanup_preserves_changed_or_missing_target() {
        let server = "test.tail123.ts.net:443";
        for status in [
            json!({}),
            json!({"Web":{server:{"Handlers":{FUNNEL_PATH:{"Proxy":"http://127.0.0.1:1234"}}}}}),
        ] {
            let mut calls = 0;
            remove_funnel_with(server, &mut |args| {
                calls += 1;
                assert_eq!(args, ["funnel", "status", "--json"]);
                Ok(status.clone())
            })
            .unwrap();
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn funnel_cleanup_checks_removal_and_rejects_untrusted_record() {
        let server = "test.tail123.ts.net:443";
        let status = json!({"Web":{server:{"Handlers":{FUNNEL_PATH:{"Proxy":FUNNEL_PROXY}}}}});
        assert!(
            remove_funnel_with(server, &mut |args| {
                Ok(if args == ["status", "--json"] {
                    json!({"Self":{"DNSName":"test.tail123.ts.net."}})
                } else {
                    status.clone()
                })
            })
            .is_err()
        );
        let mut calls = 0;
        remove_funnel_with(server, &mut |args| {
            calls += 1;
            Ok(if args == ["status", "--json"] {
                json!({"Self":{"DNSName":"renamed.tail123.ts.net."}})
            } else {
                status.clone()
            })
        })
        .unwrap();
        assert_eq!(
            calls, 2,
            "A renamed node must not remove another server's path"
        );
        let temp = tempfile::tempdir().unwrap();
        let mut config = Config::from_env().unwrap();
        config.state = temp.path().to_path_buf();
        assert!(read_funnel(&config).unwrap().is_none());
        atomic_write(
            &temp.path().join("funnel.json"),
            br#"{"version":1,"server":"invalid;command.ts.net:443"}"#,
            0o600,
        )
        .unwrap();
        assert!(read_funnel(&config).is_err());
        fs::remove_file(temp.path().join("funnel.json")).unwrap();
        std::os::unix::fs::symlink(temp.path().join("missing"), temp.path().join("funnel.json"))
            .unwrap();
        assert!(read_funnel(&config).is_err());
    }
    #[test]
    fn cleanup_stops_only_clients_with_matching_process_identity() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = Config::from_env().unwrap();
        config.state = temp.path().join("codex-wake");
        let clients = config.state.join("clients");
        fs::create_dir_all(&clients).unwrap();
        let mut child = ChildGuard(Command::new("sleep").arg("60").spawn().unwrap());
        let pid = child.0.id();
        let executable = fs::metadata(format!("/proc/{pid}/exe")).unwrap();
        let path = clients.join(format!("{pid}.json"));
        let mut record = json!({"pid":pid,"start":"wrong-start-time","dev":executable.dev(),"ino":executable.ino()});
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        stop_clients(&config).unwrap();
        assert!(child.0.try_wait().unwrap().is_none());
        record["start"] = json!(process_start(pid).unwrap());
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        stop_clients(&config).unwrap();
        assert!(!child.0.wait().unwrap().success());
    }
    #[test]
    fn socket_cleanup_preserves_active_and_unrelated_paths() {
        use std::os::unix::net::UnixListener;
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("controller.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(remove_stale_socket(&socket).is_err());
        assert!(socket.exists());
        // Drain the successful probe so no pending connection retains the listener.
        drop(listener.accept().unwrap());
        drop(listener);
        remove_stale_socket(&socket).unwrap();
        assert!(!socket.exists());
        fs::write(&socket, "unrelated").unwrap();
        assert!(remove_stale_socket(&socket).is_err());
        assert_eq!(fs::read_to_string(&socket).unwrap(), "unrelated");
    }
    #[test]
    fn socket_cleanup_removes_only_stale_codex_daemon_links() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("controller.sock");
        let uid = fs::metadata("/proc/self").unwrap().uid();
        let daemon_dir = temp.path().join(format!("codex-daemon-{uid}"));
        fs::create_dir(&daemon_dir).unwrap();
        fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let target = daemon_dir.join(format!(
            "{}{}",
            "0".repeat(32),
            uuid::Uuid::new_v4().simple()
        ));
        assert!(!target.exists());
        symlink(&target, &socket).unwrap();
        remove_stale_socket_in(&socket, temp.path()).unwrap();
        assert!(fs::symlink_metadata(&socket).is_err());
        let listener = UnixListener::bind(&target).unwrap();
        symlink(&target, &socket).unwrap();
        assert!(remove_stale_socket_in(&socket, temp.path()).is_err());
        drop(listener.accept().unwrap());
        drop(listener);
        fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(remove_stale_socket_in(&socket, temp.path()).is_err());
        fs::set_permissions(&daemon_dir, fs::Permissions::from_mode(0o700)).unwrap();
        remove_stale_socket_in(&socket, temp.path()).unwrap();
        assert!(!socket.exists());
        assert!(
            target.exists(),
            "Codex retains ownership of its target socket"
        );
        symlink(temp.path().join("unrelated"), &socket).unwrap();
        assert!(remove_stale_socket_in(&socket, temp.path()).is_err());
        assert!(
            fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    #[test]
    fn persistent_private_secret() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("config/webhook.secret");
        let secret = load_secret(&file).unwrap();
        assert_eq!(secret.len(), 64);
        assert_eq!(load_secret(&file).unwrap(), secret);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_secret(&file).is_err());
    }
    #[test]
    fn empty_and_symlink_secret_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("secret");
        atomic_write(&file, b"", 0o600).unwrap();
        assert!(load_secret(&file).is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(load_secret(&link).is_err());
    }
    #[test]
    fn compatible_runtime_still_requires_exact_source_binary_and_hooks() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = Config::from_env().unwrap();
        config.runtime = temp.path().to_path_buf();
        let binary = b"verified receiver";
        fs::write(config.runtime.join("codex-wake"), binary).unwrap();
        fs::write(config.runtime.join("hooks.json.tmpl"), HOOKS).unwrap();
        let mut stamp =
            json!({"source":"previous-source","binary":format!("{:x}",Sha256::digest(binary))});
        let save = |stamp: &Value| {
            fs::write(config.runtime.join("runtime.json"), stamp.to_string()).unwrap();
        };
        save(&stamp);
        assert!(binary_matches_stamp(&config, &stamp));
        assert!(!source_matches(&stamp));
        assert!(!runtime_matches(&config));
        stamp["compatible_sources"] = json!(["different-source"]);
        save(&stamp);
        assert!(!runtime_matches(&config));
        stamp["compatible_sources"] = json!([source_digest()]);
        save(&stamp);
        assert!(runtime_matches(&config));
        assert_eq!(stamp["source"], "previous-source");
        fs::write(config.runtime.join("codex-wake"), b"altered receiver").unwrap();
        assert!(!binary_matches_stamp(&config, &stamp));
        assert!(!runtime_matches(&config));
        fs::write(config.runtime.join("codex-wake"), binary).unwrap();
        fs::write(config.runtime.join("hooks.json.tmpl"), "altered hooks").unwrap();
        assert!(!runtime_matches(&config));
        fs::write(config.runtime.join("hooks.json.tmpl"), HOOKS).unwrap();
        stamp = json!({"source":source_digest(),"binary":format!("{:x}",Sha256::digest(binary))});
        save(&stamp);
        assert!(runtime_matches(&config));
        fs::write(config.runtime.join("codex-wake"), b"altered receiver").unwrap();
        assert!(!runtime_matches(&config));
        fs::write(config.runtime.join("codex-wake"), binary).unwrap();
        fs::write(config.runtime.join("hooks.json.tmpl"), "altered hooks").unwrap();
        assert!(!runtime_matches(&config));
    }
    #[test]
    fn installed_codex_survives_a_different_path() {
        const CHILD: &str = "CODEX_WAKE_CONFIG_TEST_CHILD";
        if env::var_os(CHILD).is_some() {
            let config = Config::from_env().unwrap();
            assert_eq!(config.codex, PathBuf::from("/installed/codex"));
            assert_eq!(config.gh, PathBuf::from("/installed/gh"));
            assert!(config.webhooks_enabled);
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("codex-wake")).unwrap();
        fs::write(
            temp.path().join("codex-wake/installation.json"),
            br#"{"codex":"/installed/codex","gh":"/installed/gh","webhooks_enabled":true}"#,
        )
        .unwrap();
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "manager::tests::installed_codex_survives_a_different_path",
            ])
            .env(CHILD, "1")
            .env("XDG_STATE_HOME", temp.path())
            .env("PATH", "/nonexistent")
            .env_remove("CODEX_WAKE_GH")
            .env_remove("CODEX_WAKE_ENABLE_WEBHOOKS")
            .env_remove("CODEX_WAKE_CODEX")
            .env_remove("CODEX_WAKE_PLUGIN_ROOT")
            .env_remove("CODEX_WAKE_PLUGIN_BASE")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn service_persists_explicit_transport_and_github_executable() {
        let mut config = Config::from_env().unwrap();
        config.gh = PathBuf::from("/tools with spaces/gh");
        config.webhooks_enabled = false;
        let disabled = unit(&config).unwrap();
        assert!(disabled.contains("Environment=CODEX_WAKE_ENABLE_WEBHOOKS=0"));
        assert!(disabled.contains("CODEX_WAKE_GH=/tools with spaces/gh"));
        config.webhooks_enabled = true;
        assert!(
            unit(&config)
                .unwrap()
                .contains("Environment=CODEX_WAKE_ENABLE_WEBHOOKS=1")
        );
    }
    #[test]
    fn unit_values_are_quoted_without_line_injection() {
        assert!(quote("/tmp/path\nExecStart=evil").is_err());
        assert_eq!(
            quote("/tmp/path with % and \"").unwrap(),
            "\"/tmp/path with %% and \\\"\""
        );
    }
}
