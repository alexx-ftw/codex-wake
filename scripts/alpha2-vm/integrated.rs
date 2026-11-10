use super::*;
use anyhow::Context;
use std::io::Write;
pub fn boot() -> Result<()> {
    mount("proc", "/proc")?;
    ensure!(
        fs::read_to_string("/proc/cmdline")?
            .split_whitespace()
            .any(|p| p == "wake_lab_vm=1"),
        "not the qualification VM"
    );
    for (t, p) in [
        ("sysfs", "/sys"),
        ("devtmpfs", "/dev"),
        ("tmpfs", "/run"),
        ("securityfs", "/sys/kernel/security"),
        ("bpf", "/sys/fs/bpf"),
        ("cgroup2", "/sys/fs/cgroup"),
    ] {
        mount(t, p)?;
    }
    let error = Command::new("/usr/lib/systemd/systemd")
        .args(["--system", "--unit=lab.target"])
        .env("SYSTEMD_LOG_TARGET", "console")
        .env("SYSTEMD_LOG_LEVEL", "warning")
        .exec();
    Err(error.into())
}
pub fn driver() -> Result<()> {
    guard()?;
    let result = (|| {
        ensure!(
            fs::read_to_string("/proc/1/comm")?.trim() == "systemd",
            "systemd is not PID1"
        );
        let v = ctl(&["--version"])?;
        println!("VM_SYSTEMD={}", v.lines().next().unwrap_or(""));
        ensure!(
            Command::new("/usr/bin/sha256sum")
                .args(["--check", "/guest/inputs.sha256"])
                .status()?
                .success(),
            "guest inputs changed"
        );
        let source: Value = serde_json::from_slice(&fs::read("/guest/source.json")?)?;
        println!(
            "VM_SOURCE_SHA={}",
            source["sha"].as_str().context("source SHA")?
        );
        let cmdline = fs::read_to_string("/proc/cmdline")?;
        let nonce = cmdline
            .split_whitespace()
            .find_map(|p| p.strip_prefix("wake_lab_nonce="))
            .context("run nonce")?;
        println!("VM_NONCE={nonce}");
        if fs::read_to_string("/proc/cmdline")?.contains("wake_lab_restore_baseline=1") {
            crate::hazards::restore_baseline()
        } else {
            crate::hazards::suite()
        }
    })();
    if let Err(e) = &result {
        eprintln!("VM_ERROR[driver]={e:#}");
        diagnostics();
    }
    finish(if result.is_ok() { 0 } else { 1 })
}
pub fn finish(code: i32) -> Result<()> {
    if let Ok(entries) = fs::read_dir("/lab") {
        for e in entries {
            let e = e?;
            let n = e.file_name().to_string_lossy().into_owned();
            if n.ends_with(".json") || n.ends_with(".trace") || n.ends_with(".stderr") {
                if let Ok(data) = fs::read_to_string(e.path()) {
                    println!(
                        "VM_FILE={}",
                        json!({"name":n,"bytes":data.len(),"data":data})
                    );
                }
            }
        }
    }
    println!("VM_EXIT={code}");
    std::io::stdout().flush()?;
    std::io::stderr().flush()?;
    unsafe {
        libc::tcdrain(1);
        libc::tcdrain(2);
    }
    thread::sleep(Duration::from_secs(1));
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF)
    };
    bail!("poweroff failed")
}
pub fn ctl(args: &[&str]) -> Result<String> {
    let o = Command::new("/usr/bin/systemctl").args(args).output()?;
    ensure!(
        o.status.success(),
        "guest systemctl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(String::from_utf8(o.stdout)?)
}
pub fn role(a: &[String]) -> Result<()> {
    guard()?;
    match a.first().map(String::as_str) {
        Some("reader") => return crate::transition::reader(),
        Some("transition") => return crate::transition::resume(&a[1]),
        _ => {}
    }
    crate::hazards::role(a)
}
