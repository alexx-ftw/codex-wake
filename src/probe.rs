//! Explicitly opt-in end-to-end smoke probes. These are never run by startup.

use anyhow::{Context, Result, bail, ensure};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

const HOOKS: &str = include_str!("../hooks.json.tmpl");
#[cfg(test)]
const THREAD: &str = "11111111-1111-4111-8111-111111111111";

fn thread_uuid(thread: &str) -> Result<String> {
    Ok(uuid::Uuid::parse_str(thread)
        .context("Invalid test-thread UUID")?
        .to_string())
}

fn output_dir(kind: &str) -> Result<tempfile::TempDir> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".test-results");
    crate::manager::private_dir(&root)?;
    let dir = tempfile::Builder::new()
        .prefix(&format!("{kind}-"))
        .tempdir_in(root)?;
    crate::manager::private_dir(dir.path())?;
    Ok(dir)
}

fn write_report(dir: &tempfile::TempDir, report: &Value) -> Result<()> {
    let path = dir.path().join("result.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn fresh_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={:x}", mac.finalize().into_bytes())
}

fn prepare_webhook_config(db: &Path, secret: &str) -> Result<std::path::PathBuf> {
    let root = db.parent().context("Missing isolated probe directory")?;
    let config_home = root.join("config");
    let config = config_home.join("codex-wake");
    crate::manager::private_dir(&config_home)?;
    crate::manager::private_dir(&config)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(config.join("webhook.secret"))?;
    file.write_all(secret.as_bytes())?;
    file.sync_all()?;
    Ok(config_home)
}

fn launch_receiver(
    webhook: &Path,
    hooks: &Path,
    port: u16,
    db: &Path,
    secret: &str,
    log: &File,
) -> Result<Child> {
    let exe = env::current_exe()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config_home = prepare_webhook_config(db, secret)?;
    let mut command = Command::new(webhook);
    command
        .args(["-ip", "127.0.0.1", "-port"])
        .arg(port.to_string())
        .args(["-template", "-hooks"])
        .arg(hooks)
        .env("CODEX_WAKE_EXECUTABLE", exe)
        .env("CODEX_WAKE_DIR", root)
        .env("CODEX_WAKE_DB", db)
        .env("XDG_CONFIG_HOME", config_home)
        .env("GITHUB_WEBHOOK_SECRET", secret)
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log.try_clone()?));
    command.spawn().context("Start isolated webhook receiver")
}

fn wait_http(url: &str, child: &mut Child, timeout: Duration, wanted: &str) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            bail!("Webhook receiver exited before readiness");
        }
        let output = crate::manager::run(
            Command::new("curl").args([
                "--silent",
                "--show-error",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--max-time",
                "3",
                url,
            ]),
            Duration::from_secs(5),
        );
        if output.is_ok_and(|out| out.status.success() && out.stdout == wanted.as_bytes()) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Webhook readiness timed out");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn stop(child: &mut Option<Child>) -> Result<bool> {
    let Some(process) = child.as_mut() else {
        return Ok(true);
    };
    if process.try_wait()?.is_none() {
        process.kill()?;
        process
            .wait_timeout(Duration::from_secs(5))?
            .context("Wait for stopped process")?;
    }
    Ok(process.try_wait()?.is_some())
}

fn local_post(url: &str, body: &[u8], secret: &str) -> Result<u16> {
    let port: u16 = url
        .rsplit(':')
        .next()
        .context("Invalid loopback URL")?
        .parse()?;
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(145)))?;
    write!(
        stream,
        "POST /hooks/codex-wake HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nX-GitHub-Event: workflow_run\r\nX-Hub-Signature-256: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        signature(secret, body),
        body.len()
    )?;
    stream.write_all(body)?;
    let mut response = Vec::new();
    stream.take(16384).read_to_end(&mut response)?;
    let status = String::from_utf8_lossy(&response)
        .lines()
        .next()
        .context("Empty receiver response")?
        .split_whitespace()
        .nth(1)
        .context("Malformed receiver response")?
        .parse()?;
    Ok(status)
}

/// Exercise the signed receiver with a single synthetic completion in isolated state.
pub fn live(thread: &str, webhook: &Path, attempt: i64) -> Result<Value> {
    let thread = thread_uuid(thread)?;
    ensure!(attempt > 0, "Attempt must be positive");
    ensure!(
        webhook.is_file(),
        "Verified webhook executable does not exist"
    );
    let dir = output_dir("live")?;
    let db_path = dir.path().join("state.sqlite3");
    let db = crate::bridge::connect(&db_path)?;
    crate::bridge::register(&db, "owner/repo", 123, attempt, &thread, &"a".repeat(40))?;
    let secret = fresh_secret();
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let mut report = json!({"thread":thread,"synthetic_event":true,"external_github_delivery":false,
        "visible_resume_verified":false,"port":port});
    let mut receiver = None;
    let result = (|| -> Result<()> {
        let log = File::create(dir.path().join("receiver.log"))?;
        let hooks = dir.path().join("hooks.json.tmpl");
        fs::write(&hooks, HOOKS)?;
        receiver = Some(launch_receiver(
            webhook, &hooks, port, &db_path, &secret, &log,
        )?);
        report["receiver_pid"] = json!(receiver.as_ref().unwrap().id());
        let url = format!("http://127.0.0.1:{port}/hooks/codex-wake");
        wait_http(
            &url,
            receiver.as_mut().unwrap(),
            Duration::from_secs(5),
            "405",
        )?;
        let body = serde_json::to_vec(
            &json!({"action":"completed","repository":{"full_name":"owner/repo"},
            "workflow_run":{"id":123,"run_attempt":attempt,"head_sha":"a".repeat(40),
                "status":"completed","conclusion":"success"}}),
        )?;
        let started = Instant::now();
        let status = local_post(&url, &body, &secret)?;
        report["http_status"] = json!(status);
        report["http_elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
        ensure!(status == 200, "Synthetic webhook returned HTTP {status}");
        let row: (String, Option<String>) =
            db.query_row("SELECT state,reason FROM waits", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        report["state"] = json!(row.0);
        report["reason"] = json!(row.1);
        Ok(())
    })();
    if let Err(error) = &result {
        report["error"] = json!(error.to_string());
    }
    report["receiver_exited"] = json!(stop(&mut receiver).unwrap_or(false));
    report["receiver_exit"] = json!(
        receiver
            .as_mut()
            .and_then(|p| p.try_wait().ok().flatten())
            .and_then(|s| s.code())
    );
    write_report(&dir, &report)?;
    let result_file = dir.path().join("result.json");
    let _ = dir.keep();
    result?;
    Ok(json!({"result_file":result_file,"report":report}))
}

fn gh(path: &str, method: &str, body: Option<&Value>) -> Result<Value> {
    let mut cmd = Command::new("gh");
    cmd.args(["api", path, "--method", method]);
    let input;
    if let Some(body) = body {
        input = tempfile::NamedTempFile::new()?;
        serde_json::to_writer(input.as_file(), body)?;
        cmd.arg("--input").arg(input.path());
    }
    let output = crate::manager::run(&mut cmd, Duration::from_secs(30))?;
    ensure!(
        output.status.success(),
        "GitHub API {method} failed for {path}"
    );
    if output.stdout.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}

fn exact_delivery(delivery: &Value, run_id: i64) -> bool {
    delivery.get("event").and_then(Value::as_str) == Some("workflow_run")
        && delivery.get("action").and_then(Value::as_str) == Some("completed")
        && delivery
            .pointer("/request/payload/workflow_run/id")
            .and_then(Value::as_i64)
            == Some(run_id)
}

/// Dispatch one existing ci.yml workflow and verify the webhook delivery for its exact run.
pub fn github(repo: &str, thread: &str, webhook: &Path) -> Result<Value> {
    let thread = thread_uuid(thread)?;
    ensure!(valid_repo(repo), "Invalid GitHub repository");
    ensure!(
        webhook.is_file(),
        "Verified webhook executable does not exist"
    );
    let dir = output_dir("github")?;
    let db_path = dir.path().join("state.sqlite3");
    let db = crate::bridge::connect(&db_path)?;
    let secret = fresh_secret();
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let mut report = json!({"repo":repo,"thread":thread,"visible_resume_verified":false});
    let mut receiver = None;
    let mut tunnel = None;
    let mut hook_id = None;
    let mut endpoint: Option<String> = None;
    let result = (|| -> Result<()> {
        let receiver_log = File::create(dir.path().join("receiver.log"))?;
        let tunnel_log = File::create(dir.path().join("tunnel.log"))?;
        let hooks = dir.path().join("hooks.json.tmpl");
        fs::write(&hooks, HOOKS)?;
        receiver = Some(launch_receiver(
            webhook,
            &hooks,
            port,
            &db_path,
            &secret,
            &receiver_log,
        )?);
        tunnel = Some(
            Command::new("cloudflared")
                .args([
                    "tunnel",
                    "--config",
                    "/dev/null",
                    "--no-autoupdate",
                    "--protocol",
                    "http2",
                    "--url",
                ])
                .arg(format!("http://127.0.0.1:{port}"))
                .stdout(Stdio::from(tunnel_log.try_clone()?))
                .stderr(Stdio::from(tunnel_log))
                .spawn()?,
        );
        let log_path = dir.path().join("tunnel.log");
        let deadline = Instant::now() + Duration::from_secs(90);
        let tunnel_url = regex::Regex::new(r"https://[a-z0-9-]+\.trycloudflare\.com")?;
        loop {
            ensure!(
                receiver.as_mut().unwrap().try_wait()?.is_none()
                    && tunnel.as_mut().unwrap().try_wait()?.is_none(),
                "Receiver or tunnel exited; inspect private logs"
            );
            let logs = fs::read_to_string(&log_path).unwrap_or_default();
            if let Some(host) = tunnel_url.find(&logs).map(|m| m.as_str()) {
                let url = format!("{host}/hooks/codex-wake");
                let ready = crate::manager::run(
                    Command::new("curl").args([
                        "--silent",
                        "--output",
                        "/dev/null",
                        "--write-out",
                        "%{http_code}",
                        "--max-time",
                        "5",
                        &url,
                    ]),
                    Duration::from_secs(7),
                );
                if ready.is_ok_and(|o| o.status.success() && o.stdout == b"405") {
                    endpoint = Some(url);
                    break;
                }
                let hostname = host.trim_start_matches("https://");
                let dns = crate::manager::run(
                    Command::new("curl")
                        .args(["--fail", "--silent", "--show-error", "--max-time", "5"])
                        .arg(format!("https://dns.google/resolve?name={hostname}&type=A")),
                    Duration::from_secs(7),
                );
                if let Ok(dns) = dns
                    && dns.status.success()
                    && let Some(address) = serde_json::from_slice::<Value>(&dns.stdout)
                        .ok()
                        .and_then(|v| {
                            v.get("Answer")?
                                .as_array()?
                                .iter()
                                .find(|a| a.get("type").and_then(Value::as_i64) == Some(1))?
                                .get("data")?
                                .as_str()
                                .map(str::to_owned)
                        })
                {
                    let resolved = crate::manager::run(
                        Command::new("curl")
                            .args([
                                "--silent",
                                "--output",
                                "/dev/null",
                                "--write-out",
                                "%{http_code}",
                                "--max-time",
                                "5",
                                "--resolve",
                            ])
                            .arg(format!("{hostname}:443:{address}"))
                            .arg(&url),
                        Duration::from_secs(7),
                    );
                    if resolved.is_ok_and(|o| o.status.success() && o.stdout == b"405") {
                        report["resolved_https_probe_status"] = json!(405);
                        endpoint = Some(url);
                        break;
                    }
                }
            }
            if Instant::now() >= deadline {
                bail!("HTTPS tunnel readiness timed out");
            }
            thread::sleep(Duration::from_secs(1));
        }
        let endpoint = endpoint.as_deref().unwrap();
        let hook = gh(
            &format!("repos/{repo}/hooks"),
            "POST",
            Some(
                &json!({"name":"web","active":true,"events":["workflow_run"],
            "config":{"url":endpoint,"content_type":"json","secret":secret,"insecure_ssl":"0"}}),
            ),
        )?;
        let id = hook
            .get("id")
            .and_then(Value::as_i64)
            .context("GitHub did not return webhook ID")?;
        hook_id = Some(id);
        report["hook_id"] = json!(id);
        let workflow = gh(
            &format!("repos/{repo}/actions/workflows/ci.yml"),
            "GET",
            None,
        )?;
        ensure!(
            workflow
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(
                    |p| p.ends_with("/.github/workflows/ci.yml") || p == ".github/workflows/ci.yml"
                ),
            "Repository does not have the expected ci.yml workflow"
        );
        let mut dispatch_command = Command::new("gh");
        dispatch_command
            .args([
                "workflow",
                "run",
                "ci.yml",
                "--repo",
                repo,
                "--ref",
                "main",
                "--raw-field",
            ])
            .arg(format!("probe={nonce}"));
        let dispatch = crate::manager::run(&mut dispatch_command, Duration::from_secs(30))?;
        ensure!(dispatch.status.success(), "Workflow dispatch failed");
        let deadline = Instant::now() + Duration::from_secs(30);
        let run = loop {
            let runs = gh(
                &format!(
                    "repos/{repo}/actions/workflows/ci.yml/runs?event=workflow_dispatch&per_page=10"
                ),
                "GET",
                None,
            )?;
            if let Some(run) = runs
                .get("workflow_runs")
                .and_then(Value::as_array)
                .and_then(|a| {
                    a.iter().find(|r| {
                        r.get("display_title").and_then(Value::as_str)
                            == Some(&format!("codex-wake {nonce}"))
                    })
                })
            {
                break run.clone();
            }
            if Instant::now() >= deadline {
                bail!("Could not discover dispatched run; do not dispatch again blindly");
            }
            thread::sleep(Duration::from_secs(1));
        };
        let run_id = run
            .get("id")
            .and_then(Value::as_i64)
            .context("Missing Actions run ID")?;
        let attempt = run
            .get("run_attempt")
            .and_then(Value::as_i64)
            .context("Missing Actions attempt")?;
        let sha = run
            .get("head_sha")
            .and_then(Value::as_str)
            .context("Missing Actions SHA")?;
        crate::bridge::register(&db, repo, run_id, attempt, &thread, sha)?;
        report["run_id"] = json!(run_id);
        report["attempt"] = json!(attempt);
        report["sha"] = json!(sha);
        report["run_url"] = run.get("html_url").cloned().unwrap_or(Value::Null);
        let watch = crate::manager::run(
            Command::new("gh").args([
                "run",
                "watch",
                &run_id.to_string(),
                "--repo",
                repo,
                "--exit-status",
                "--interval",
                "10",
            ]),
            Duration::from_secs(600),
        )?;
        report["watch_exit"] = json!(watch.status.code());
        ensure!(
            watch.status.success(),
            "GitHub Actions run failed; inspect private report"
        );
        let row_deadline = Instant::now() + Duration::from_secs(60);
        let state = loop {
            let s: (String, Option<String>) = db.query_row(
                "SELECT state,reason FROM waits WHERE run_id=?1 AND attempt=?2",
                [run_id, attempt],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if s.0 == "queued" || s.0 == "needs_attention" {
                break s;
            }
            if Instant::now() >= row_deadline {
                break s;
            }
            thread::sleep(Duration::from_secs(1));
        };
        report["state"] = json!(state.0);
        report["reason"] = json!(state.1);
        let deliveries = gh(
            &format!("repos/{repo}/hooks/{id}/deliveries?per_page=20"),
            "GET",
            None,
        )?;
        for item in deliveries.as_array().into_iter().flatten().filter(|d| {
            d.get("event").and_then(Value::as_str) == Some("workflow_run")
                && d.get("action").and_then(Value::as_str) == Some("completed")
        }) {
            let did = item.get("id").context("Missing hook delivery ID")?;
            let delivery = gh(
                &format!("repos/{repo}/hooks/{id}/deliveries/{did}"),
                "GET",
                None,
            )?;
            if exact_delivery(&delivery, run_id) {
                report["github_delivery"] = json!({"id":delivery.get("id"),"guid":delivery.get("guid"),"status_code":delivery.get("status_code"),"event":delivery.get("event"),"action":delivery.get("action")});
                break;
            }
        }
        let delivered = report
            .pointer("/github_delivery/status_code")
            .and_then(Value::as_i64)
            == Some(200);
        report["http_delivery_verified"] = json!(delivered);
        ensure!(
            report["state"] == "queued" && delivered,
            "Webhook dispatch was not queued with HTTP 200 delivery"
        );
        Ok(())
    })();
    if let Err(error) = &result {
        report["error"] = json!(error.to_string());
    }
    if let (Some(id), Some(url)) = (hook_id, endpoint.as_deref()) {
        let cleanup = (|| -> Result<()> {
            let existing = gh(&format!("repos/{repo}/hooks/{id}"), "GET", None)?;
            ensure!(
                existing.pointer("/config/url").and_then(Value::as_str) == Some(url),
                "Webhook identity changed; refusing deletion"
            );
            gh(&format!("repos/{repo}/hooks/{id}"), "DELETE", None)?;
            Ok(())
        })();
        report["webhook_deleted"] = json!(cleanup.is_ok());
    }
    report["tunnel_exited"] = json!(stop(&mut tunnel).unwrap_or(false));
    report["receiver_exited"] = json!(stop(&mut receiver).unwrap_or(false));
    write_report(&dir, &report)?;
    let result_file = dir.path().join("result.json");
    let _ = dir.keep();
    result?;
    Ok(json!({"result_file":result_file,"report":report}))
}

fn valid_repo(repo: &str) -> bool {
    let mut parts = repo.split('/');
    let valid = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    };
    parts.next().is_some_and(valid) && parts.next().is_some_and(valid) && parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn isolated_webhook_secret_is_private_and_matches_receiver_secret() {
        let dir = tempfile::tempdir().unwrap();
        let config_home =
            prepare_webhook_config(&dir.path().join("state.sqlite3"), "probe-secret").unwrap();
        let config = config_home.join("codex-wake");
        let secret = config.join("webhook.secret");
        assert_eq!(fs::read_to_string(&secret).unwrap(), "probe-secret");
        assert_eq!(
            fs::metadata(config).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn signatures_and_delivery_identity_are_exact() {
        assert_eq!(
            signature("key", b"body"),
            "sha256=515aae133b435d4000956731f68ae5cf5eb85d4f0dc6a546d2bfcd3595ec1ae1"
        );
        let delivery = json!({"event":"workflow_run","action":"completed","request":{"payload":{"workflow_run":{"id":9}}}});
        assert!(exact_delivery(&delivery, 9));
        assert!(!exact_delivery(&delivery, 10));
        assert!(!exact_delivery(
            &json!({"event":"workflow_run","action":"requested","request":{"payload":{"workflow_run":{"id":9}}}}),
            9
        ));
    }
    #[test]
    fn repo_and_thread_inputs_are_validated() {
        assert!(valid_repo("owner/repo"));
        assert!(!valid_repo("owner/repo/extra"));
        assert!(thread_uuid(THREAD).is_ok());
        assert!(thread_uuid("not-a-uuid").is_err());
    }
}
