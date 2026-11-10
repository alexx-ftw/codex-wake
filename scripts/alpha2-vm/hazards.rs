use super::*;
use anyhow::Context;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
const SIDE: &str = "/lab/state/codex-wake/state.sqlite3-mmap-probe";
pub fn role(a: &[String]) -> Result<()> {
    match a.first().map(String::as_str) {
        Some("dbus-dir") => {
            fs::create_dir_all("/run/dbus")?;
            Ok(())
        }
        Some("hazard") => hazard_actor(&a[1], a.get(2)),
        Some("enumeration-denied") => {
            let error = crate::persistent::ids_in(Path::new("/proc/1/task/1/fd"))
                .err()
                .context("unreadable directory accepted")?;
            save(
                "enumeration-denied",
                json!({"failed_closed":true,"error":error.to_string(),"real_proc_permission_failure":true}),
            )
        }
        _ => bail!("unknown role"),
    }
}
fn hazard_actor(mode: &str, arg: Option<&String>) -> Result<()> {
    if mode == "inventory-target" {
        save("inventory-target-ready", json!({"pid":std::process::id()}))?;
        wait("inventory target release", || {
            Path::new("/lab/inventory-target-release").exists()
        })?;
        return Ok(());
    }
    if mode == "continue-peer" {
        let target: u32 = arg.context("inventory target PID")?.parse()?;
        wait("inventory target stopped", || {
            crate::persistent::status_at(Path::new(&format!("/proc/{target}/status")))
                .is_ok_and(|(_, s)| matches!(s, 'T' | 't'))
        })?;
        let rc = unsafe { libc::kill(target as i32, libc::SIGCONT) };
        let errno = if rc == -1 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        let (_, state) =
            crate::persistent::status_at(Path::new(&format!("/proc/{target}/status")))?;
        ensure!(
            rc == -1 && errno == Some(libc::EACCES) && matches!(state, 'T' | 't'),
            "peer resumed stopped task: rc={rc} errno={errno:?} state={state}"
        );
        save(
            "inventory-peer",
            json!({"target":target,"sigcont_rc":rc,"errno":errno,"target_still_stopped":true}),
        )?;
        wait("inventory peer release", || {
            Path::new("/lab/inventory-peer-release").exists()
        })?;
        return Ok(());
    }
    if mode == "late-create" {
        save("late-create-ready", json!({"pid":std::process::id()}))?;
        wait("late creation release", || {
            Path::new("/lab/late-create-after-boundary").exists()
        })?;
        let path = "/lab/state/codex-wake/state.sqlite3-after-boundary";
        let errno = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .err()
            .and_then(|e| e.raw_os_error());
        ensure!(
            errno == Some(libc::EACCES),
            "new sidecar escaped corrected boundary: {errno:?}"
        );
        return save(
            "late-creation-blocked",
            json!({"errno":errno,"attempted_after_inventory_snapshot":true}),
        );
    }
    if mode == "preopened-fd" {
        let mut fd = OpenOptions::new().write(true).open(SIDE)?;
        save(
            "preopened-fd-ready",
            json!({"opened_before_file_fence":true}),
        )?;
        wait("preopened FD release", || {
            Path::new("/lab/preopened-fd-release").exists()
        })?;
        let truncate_errno = fd.set_len(0).err().and_then(|e| e.raw_os_error());
        let write_errno = fd.write_all(b"bad").err().and_then(|e| e.raw_os_error());
        let size = fs::metadata(SIDE)?.len();
        ensure!(
            truncate_errno == Some(libc::EACCES)
                && write_errno == Some(libc::EACCES)
                && size == 8192,
            "pre-opened FD mutation crossed fence: truncate={truncate_errno:?} write={write_errno:?} size={size}"
        );
        return save(
            "preopened-fd-after-gate",
            json!({"opened_before_file_fence":true,"truncate_errno":truncate_errno,"write_errno":write_errno,"size":size}),
        );
    }
    if mode == "late-mmap" {
        fs::write("/lab/late-waiting", b"ready")?;
        wait("late inventory release", || {
            Path::new("/lab/late-create").exists()
        })?;
        let path = "/lab/state/codex-wake/state.sqlite3-late-mmap";
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        f.set_len(4096)?;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                f.as_raw_fd(),
                0,
            )
        };
        ensure!(ptr != libc::MAP_FAILED, "late mmap");
        drop(f);
        fs::write("/lab/late-mapped", b"fd closed")?;
        wait("late store release", || {
            Path::new("/lab/late-store").exists()
        })?;
        unsafe {
            (ptr as *mut u8).write_volatile(165);
        }
        fs::write("/lab/late-stored", b"written")?;
        wait("late retirement", || Path::new("/lab/late-exit").exists())?;
        return Ok(());
    }
    if mode == "link" {
        fs::write("/lab/tmp/new-inode", b"alias")?;
        let r = fs::hard_link(
            "/lab/tmp/new-inode",
            "/lab/state/codex-wake/state.sqlite3-new-linked",
        );
        let errno = r.err().and_then(|e| e.raw_os_error());
        ensure!(errno == Some(13), "new hardlink escaped: {errno:?}");
        return save(
            "link-blocked",
            json!({"errno":errno,"new_sidecar_hardlink_denied":true}),
        );
    }
    if mode == "mixed-thread" {
        let worker = thread::spawn(|| -> Result<()> {
            ensure!(
                unsafe { libc::syscall(libc::SYS_setresuid, UID, UID, UID) } == 0,
                "thread credentials"
            );
            save(
                "mixed-thread-ready",
                json!({"pid":std::process::id(),"tid":unsafe{libc::syscall(libc::SYS_gettid)},"leader":fs::read_to_string("/proc/self/status")?.lines().find(|l|l.starts_with("Uid:")).context("leader UID")?,"worker":fs::read_to_string("/proc/thread-self/status")?.lines().find(|l|l.starts_with("Uid:")).context("worker UID")?}),
            )?;
            wait("mixed thread retirement", || {
                Path::new("/lab/mixed-thread-release").exists()
            })
        });
        return worker.join().unwrap();
    }
    if mode == "restore" {
        ensure!(
            unsafe { libc::setresuid(40001, 40000, 40001) } == 0,
            "mixed setup"
        );
        let mut file = OpenOptions::new().write(true).open(SIDE)?;
        fs::write("/lab/restore-ready", b"ready")?;
        wait("restore release", || {
            Path::new("/lab/restore-release").exists()
        })?;
        let rc = unsafe { libc::setresuid(40001, 40001, 40001) };
        let errno = if rc == 0 {
            None
        } else {
            std::io::Error::last_os_error().raw_os_error()
        };
        let w = file.write_all(b"bad");
        println!(
            "RESTORE={}",
            json!({"setresuid_rc":rc,"setresuid_errno":errno,"write_rc":if w.is_ok(){0}else{-1},"write_errno":w.err().and_then(|e|e.raw_os_error()),"credentials":fs::read_to_string("/proc/self/status")?.lines().find(|l|l.starts_with("Uid:")).unwrap_or("")})
        );
        return Ok(());
    }
    let mut fd = if mode == "fd" || mode == "mixed-write" {
        Some(OpenOptions::new().write(true).open(SIDE)?)
    } else {
        None
    };
    if mode == "privatefd" {
        let join = thread::spawn(|| -> Result<()> {
            ensure!(
                unsafe { libc::unshare(libc::CLONE_FILES) } == 0,
                "unshare fd table: {}",
                std::io::Error::last_os_error()
            );
            let _f = OpenOptions::new().read(true).write(true).open(SIDE)?;
            save(
                "privatefd-ready",
                json!({"pid":std::process::id(),"tid":unsafe{libc::syscall(libc::SYS_gettid)}}),
            )?;
            wait("private fd stop", || {
                Path::new("/lab/privatefd-release").exists()
            })?;
            Ok(())
        });
        return join.join().unwrap();
    }
    if mode == "mixed" || mode == "mixed-write" {
        ensure!(
            unsafe { libc::setresuid(40001, 40000, 40001) } == 0,
            "mixed credentials"
        );
    }
    fs::write(format!("/lab/{mode}-ready"), b"ready")?;
    wait(mode, || Path::new(&format!("/lab/{mode}-release")).exists())?;
    let (rc, errno) = match mode {
        "fd" => {
            let r = fd.unwrap().set_len(0);
            (
                if r.is_ok() { 0 } else { -1 },
                r.err().and_then(|e| e.raw_os_error()),
            )
        }
        "path" => {
            let r = unsafe { libc::truncate(cs(SIDE).as_ptr(), 0) };
            (
                r,
                if r == 0 {
                    None
                } else {
                    std::io::Error::last_os_error().raw_os_error()
                },
            )
        }
        "open" | "mixed" => {
            let r = OpenOptions::new().write(true).truncate(true).open(SIDE);
            (
                if r.is_ok() { 0 } else { -1 },
                r.err().and_then(|e| e.raw_os_error()),
            )
        }
        "mixed-write" => {
            let r = fd.as_mut().unwrap().write_all(b"bad");
            (
                if r.is_ok() { 0 } else { -1 },
                r.err().and_then(|e| e.raw_os_error()),
            )
        }
        _ => bail!("actor mode"),
    };
    save(
        &format!("truncate-{mode}"),
        json!({"rc":rc,"errno":errno,"size":fs::metadata(SIDE)?.len(),"credentials":fs::read_to_string("/proc/self/status")?.lines().find(|l|l.starts_with("Uid:")).unwrap_or("")}),
    )
}
fn restore_attempt() -> Result<Value> {
    let actor = Command::new("/guest/vm-probe")
        .args(["role", "hazard", "restore"])
        .stdout(Stdio::piped())
        .spawn()?;
    wait("restore ready", || Path::new("/lab/restore-ready").exists())?;
    fs::write("/lab/restore-release", b"try")?;
    let o = actor.wait_with_output()?;
    ensure!(o.status.success(), "restore actor");
    let text = String::from_utf8(o.stdout)?;
    Ok(serde_json::from_str(
        text.lines()
            .find_map(|l| l.strip_prefix("RESTORE="))
            .context("restore result")?,
    )?)
}
pub fn restore_baseline() -> Result<()> {
    for p in [P, "/lab/codex", "/lab/tmp"] {
        fs::create_dir_all(p)?;
        ensure!(
            unsafe { libc::chown(cs(p).as_ptr(), UID, UID) } == 0,
            "owner"
        );
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    }
    ensure!(
        subscribe("/guest/legacy", "sentinel").status.success(),
        "seed"
    );
    fs::write(SIDE, vec![107; 8192])?;
    ensure!(
        unsafe { libc::chown(cs(SIDE).as_ptr(), UID, UID) } == 0,
        "side"
    );
    let _socket = std::os::unix::net::UnixListener::bind("/lab/native.sock")?;
    let mut loader = Command::new("/guest/vm-probe")
        .args(["load", &std::process::id().to_string()])
        .spawn()?;
    wait("load", || Path::new("/lab/policy-ready").exists())?;
    let armed_mask = 2;
    arm(armed_mask)?;
    let r = restore_attempt()?;
    ensure!(
        r["setresuid_rc"] == 0 && r["write_rc"] == 0 && &fs::read(SIDE)?[..3] == b"bad",
        "restoration bypass not reproduced"
    );
    loader.kill()?;
    loader.wait()?;
    let report = json!({"phase":"credential restoration baseline, vulnerable by design","baseline_type":"current BPF with credential-restore protection disabled","bpf_armed_mask":armed_mask,"credential_restore_protection_bit":16,"historical_binary":false,"bypass_reproduced":true,"result":r,"production_migration_qualified":false});
    save("restore-baseline", report.clone())?;
    println!("VM_RESULT={report}");
    Ok(())
}
pub fn suite() -> Result<()> {
    for p in [P, "/lab/codex", "/lab/tmp"] {
        fs::create_dir_all(p)?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
        ensure!(
            unsafe { libc::chown(cs(p).as_ptr(), UID, UID) } == 0,
            "owner"
        );
    }
    ensure!(
        subscribe("/guest/legacy", "sentinel").status.success(),
        "seed"
    );
    fs::write(SIDE, vec![107; 8192])?;
    ensure!(
        unsafe { libc::chown(cs(SIDE).as_ptr(), UID, UID) } == 0,
        "side owner"
    );
    let (ws, native_pid) = crate::transition::start()?;
    let delivery = crate::transition::seed_uncertain()?;
    let d = db()?;
    d.execute_batch("CREATE TABLE fixture_writes(label TEXT)")?;
    drop(d);
    let mut held = child("held")?;
    let mut mapper = child("mmap")?;
    wait("preexisting integration mapping", || {
        Path::new("/lab/mmap-ready").exists()
    })?;
    wait("known admitted operation", || {
        Path::new("/lab/held-ready").exists()
    })?;
    let mut private = Command::new("/guest/vm-probe")
        .args(["role", "hazard", "privatefd"])
        .uid(UID)
        .gid(UID)
        .spawn()?;
    wait("private fd ready", || {
        Path::new("/lab/privatefd-ready.json").exists()
    })?;
    let target = fs::metadata(SIDE)?;
    let mut leader_fds = vec![];
    for e in fs::read_dir(format!("/proc/{}/fd", private.id()))? {
        let e = e?;
        if let Ok(m) = fs::metadata(e.path()) {
            if m.dev() == target.dev() && m.ino() == target.ino() {
                leader_fds.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    let tid: Value = serde_json::from_slice(&fs::read("/lab/privatefd-ready.json")?)?;
    let thread_dir = format!(
        "/proc/{}/task/{}/fd",
        private.id(),
        tid["tid"].as_u64().context("tid")?
    );
    let mut thread_fds = vec![];
    for e in fs::read_dir(&thread_dir)? {
        let e = e?;
        if let Ok(m) = fs::metadata(e.path()) {
            if m.dev() == target.dev() && m.ino() == target.ino() {
                thread_fds.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    ensure!(
        leader_fds.is_empty() && !thread_fds.is_empty(),
        "no private-table counterexample"
    );
    save(
        "private-fd-baseline",
        json!({"leader_fd_scan_misses":true,"leader_fds":leader_fds,"private_thread_fds":thread_fds,"pid":private.id(),"tid":tid["tid"]}),
    )?;
    fs::write("/lab/held-release", b"drain before inventory boundary")?;
    wait("admitted completion before inventory", || {
        Path::new("/lab/held-result.json").exists()
    })?;
    ensure!(
        read("held-result")?["completion_persisted"] == true,
        "admitted response lost"
    );
    let mut late = Command::new("/guest/vm-probe")
        .args(["role", "hazard", "late-mmap"])
        .uid(UID)
        .gid(UID)
        .spawn()?;
    wait("late actor admission", || {
        Path::new("/lab/late-waiting").exists()
    })?;
    let loader = Command::new("/guest/vm-probe")
        .args(["load", &native_pid.to_string()])
        .spawn()?;
    wait("policy load", || Path::new("/lab/policy-ready").exists())?;
    arm(24)?;
    // Reproduce the stale-inventory window before applying the stable boundary.
    crate::persistent::capture_inventory()?;
    fs::write("/lab/late-create", b"after capture")?;
    wait("late mmap established", || {
        Path::new("/lab/late-mapped").exists()
    })?;
    crate::persistent::native_clean(late.id())?;
    let mut preopened_fd = Command::new("/guest/vm-probe")
        .args(["role", "hazard", "preopened-fd"])
        .uid(UID)
        .gid(UID)
        .spawn()?;
    wait("preopened FD ready", || {
        Path::new("/lab/preopened-fd-ready.json").exists()
    })?;
    arm(19)?;
    fs::write(
        "/lab/preopened-fd-release",
        b"test FD admitted before fence",
    )?;
    ensure!(preopened_fd.wait()?.success(), "pre-opened FD actor failed");
    let preopened_result: Value =
        serde_json::from_slice(&fs::read("/lab/preopened-fd-after-gate.json")?)?;
    ensure!(
        preopened_result["truncate_errno"] == libc::EACCES
            && preopened_result["write_errno"] == libc::EACCES
            && preopened_result["size"] == 8192,
        "pre-opened FD regression failed: {preopened_result}"
    );
    save("preopened-fd-regression", preopened_result)?;
    fs::write("/lab/late-store", b"after file fence")?;
    wait("late mapped store", || {
        Path::new("/lab/late-stored").exists()
    })?;
    ensure!(
        fs::read("/lab/state/codex-wake/state.sqlite3-late-mmap")?[0] == 165,
        "stale inventory reproduction"
    );
    save(
        "inventory-window-baseline",
        json!({"new_sidecar_after_snapshot":true,"writable_shared_mapping_fd_closed":true,"frozen_audit_false_negative":true,"store_after_file_fence":165,"ownership_still_old":fs::metadata("/lab/state/codex-wake/state.sqlite3-late-mmap")?.uid()==UID}),
    )?;
    let mut inventory_target = Command::new("/guest/vm-probe")
        .args(["role", "hazard", "inventory-target"])
        .uid(UID)
        .gid(UID)
        .spawn()?;
    wait("inventory target ready", || {
        Path::new("/lab/inventory-target-ready.json").exists()
    })?;
    let target_pid = inventory_target.id();
    let mut inventory_peer = Command::new("/guest/vm-probe")
        .args(["role", "hazard", "continue-peer", &target_pid.to_string()])
        .uid(UID)
        .gid(UID)
        .spawn()?;
    let mut late_create = Command::new("/guest/vm-probe")
        .args(["role", "hazard", "late-create"])
        .uid(UID)
        .gid(UID)
        .spawn()?;
    wait("late creation probe ready", || {
        Path::new("/lab/late-create-ready.json").exists()
    })?;
    arm_add(40)?;
    let target_fd = crate::persistent::pidfd(target_pid)?;
    crate::persistent::signal(&target_fd, libc::SIGSTOP)?;
    wait("inventory target stopped", || {
        crate::persistent::status_at(Path::new(&format!("/proc/{target_pid}/status")))
            .is_ok_and(|(_, s)| matches!(s, 'T' | 't'))
    })?;
    wait("inventory peer attempted SIGCONT", || {
        Path::new("/lab/inventory-peer.json").exists()
    })?;
    let peer_result: Value = serde_json::from_slice(&fs::read("/lab/inventory-peer.json")?)?;
    ensure!(
        peer_result["errno"] == libc::EACCES && peer_result["target_still_stopped"] == true,
        "SIGCONT guard failed: {peer_result}"
    );
    let _frozen = crate::transition::freeze_inventory()?;
    crate::persistent::capture_inventory()?;
    let (_, target_state) =
        crate::persistent::status_at(Path::new(&format!("/proc/{target_pid}/status")))?;
    ensure!(
        matches!(target_state, 'T' | 't'),
        "inventory target resumed during capture"
    );
    save(
        "inventory-resume-guard",
        json!({"untrusted_sigcont_denied":true,"target_stopped_during_capture":true,"target_pid":target_pid,"peer_pid":inventory_peer.id()}),
    )?;
    let refusal = crate::persistent::native_clean(late.id())
        .err()
        .context("late mapping escaped stable capture")?
        .to_string();
    ensure!(
        refusal.contains("protected mappings"),
        "wrong mapping refusal: {refusal}"
    );
    save(
        "inventory-window-corrected",
        json!({"preserved_actor_mapping_refused":refusal,"identities_captured_while_all_untrusted_stopped":true}),
    )?;
    arm(59)?;
    crate::persistent::signal(&crate::persistent::pidfd(native_pid)?, libc::SIGCONT)?;
    fs::write("/lab/late-create-after-boundary", b"run after capture")?;
    crate::persistent::signal(&crate::persistent::pidfd(late_create.id())?, libc::SIGCONT)?;
    ensure!(
        late_create.wait()?.success(),
        "post-snapshot creation actor failed"
    );
    let late_create_result: Value =
        serde_json::from_slice(&fs::read("/lab/late-creation-blocked.json")?)?;
    ensure!(
        late_create_result["errno"] == libc::EACCES
            && late_create_result["attempted_after_inventory_snapshot"] == true,
        "post-snapshot create escaped: {late_create_result}"
    );
    let private_refusal = crate::persistent::native_clean(private.id())
        .err()
        .context("private FD escaped corrected audit")?
        .to_string();
    ensure!(
        private_refusal.contains("protected fd"),
        "wrong audit refusal: {private_refusal}"
    );
    let legacy_flatten = vec![
        Ok(std::ffi::OsString::from("123")),
        Err(std::io::Error::from_raw_os_error(libc::EACCES)),
    ];
    let silenced = legacy_flatten.into_iter().flatten().count();
    let corrected = crate::persistent::checked_ids(
        vec![
            Ok(std::ffi::OsString::from("123")),
            Err(std::io::Error::from_raw_os_error(libc::EACCES)),
        ]
        .into_iter(),
    );
    ensure!(
        silenced == 1 && corrected.is_err(),
        "enumeration failure accepted"
    );
    save(
        "audit-regressions",
        json!({"private_fd_refused":private_refusal,"legacy_flatten_silenced_eacces":true,"corrected_enumeration_propagated_eacces":true,"enumeration_fault_injection":"shared collector iterator; not a kernel proc fault"}),
    )?;
    ensure!(
        Command::new("/guest/vm-probe")
            .args(["role", "hazard", "link"])
            .uid(UID)
            .gid(UID)
            .status()?
            .success(),
        "link regression"
    );
    let mut results = vec![];
    for mode in ["open", "fd", "path", "mixed", "mixed-write"] {
        fs::write(SIDE, vec![107; 8192])?;
        let mut c = Command::new("/guest/vm-probe");
        c.args(["role", "hazard", mode]);
        if !mode.starts_with("mixed") {
            c.uid(UID).gid(UID);
        }
        let mut actor = c.spawn()?;
        wait(mode, || Path::new(&format!("/lab/{mode}-ready")).exists())?;
        fs::write(format!("/lab/{mode}-release"), b"try")?;
        ensure!(actor.wait()?.success(), "actor failed {mode}");
        let r: Value = serde_json::from_slice(&fs::read(format!("/lab/truncate-{mode}.json"))?)?;
        ensure!(
            r["rc"] == -1 && r["errno"] == 13 && r["size"] == 8192,
            "mutation escaped {mode}: {r}"
        );
        ensure!(fs::read(SIDE)? == vec![107; 8192], "bytes changed {mode}");
        ensure!(
            fs::metadata(SIDE)?.uid() == UID,
            "ownership changed before test"
        );
        results.push(json!({"mode":mode,"result":r}));
    }
    let restore = restore_attempt()?;
    ensure!(
        restore["setresuid_rc"] == -1
            && restore["setresuid_errno"] == 13
            && restore["write_rc"] == -1
            && restore["write_errno"] == 13,
        "credential restoration escaped: {restore}"
    );
    ensure!(fs::read(SIDE)? == vec![107; 8192], "restore changed bytes");
    save("restore-blocked", restore)?;
    let mut mixed_thread = Command::new("/guest/vm-probe")
        .args(["role", "hazard", "mixed-thread"])
        .spawn()?;
    wait("mixed thread ready", || {
        Path::new("/lab/mixed-thread-ready.json").exists()
    })?;
    ensure!(
        crate::persistent::old_live(native_pid)?.contains(&mixed_thread.id()),
        "untrusted worker hidden by root leader"
    );
    let status = Command::new("/guest/vm-probe")
        .args(["role", "enumeration-denied"])
        .uid(UID)
        .gid(UID)
        .status()?;
    ensure!(status.success(), "real enumeration error regression");
    crate::transition::finish(ws, native_pid, loader, delivery)?;
    let _ = held.wait();
    let _ = mapper.wait();
    ensure!(
        late.wait()?.signal() == Some(libc::SIGKILL),
        "late mapper was not retired"
    );
    ensure!(
        inventory_target.wait()?.signal() == Some(libc::SIGKILL),
        "inventory target was not retired"
    );
    ensure!(
        inventory_peer.wait()?.signal() == Some(libc::SIGKILL),
        "inventory peer was not retired"
    );
    ensure!(
        private.wait()?.signal() == Some(libc::SIGKILL),
        "private FD holder was not retired"
    );
    let _ = mixed_thread.wait();
    let report = json!({"passed":true,"phase":"corrected hazards and integrated systemd transaction","systemd_pid1":true,"truncate_observations":results,"private_fd_false_negative_reproduced":true,"private_fd_correctly_refused":true,"enumeration_error_fail_closed":true,"transition":read("transition-result")?,"production_migration_qualified":false});
    save("result", report.clone())?;
    println!("VM_RESULT={report}");
    Ok(())
}
