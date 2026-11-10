//! Linux x86-64 fallback for kernels without pidfd group signaling.
#[path = "pr_ci_legacy/fds.rs"]
mod fds;
#[path = "pr_ci_legacy/guard.rs"]
mod guard;
#[path = "pr_ci_legacy/start.rs"]
mod start;
#[path = "pr_ci_legacy/supervisor.rs"]
mod supervisor;

use crate::pr_ci::ApiResponse;
use anyhow::{Context, Result, bail};
use std::{
    ffi::{CString, OsString, c_char},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

struct Prepared {
    program: OsString,
    route: String,
    filter: String,
}

fn send(stream: &UnixStream, value: u8) -> bool {
    unsafe {
        libc::send(
            stream.as_raw_fd(),
            (&value as *const u8).cast(),
            1,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        ) == 1
    }
}

fn reap(fd: std::fs::File, deadline: Instant) -> Result<()> {
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                fd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG,
            )
        };
        if rc == 0 && info.si_signo == libc::SIGCHLD {
            return Ok(());
        }
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                bail!("process cleanup uncertain: waitid: {error}");
            }
        }
        if Instant::now() >= deadline {
            bail!("process cleanup uncertain: reaping timed out");
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn reader(
    stream: UnixStream,
    limit: u64,
    exceeded: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
) -> std::io::Result<thread::JoinHandle<Result<Vec<u8>>>> {
    stream.set_nonblocking(true)?;
    thread::Builder::new().spawn(move || super::read_pipe(stream, limit, exceeded, cancelled))
}

struct Channels {
    control: UnixStream,
    child_control: UnixStream,
    status: UnixStream,
    child_status: UnixStream,
    diagnostics: UnixStream,
    child_diagnostics: UnixStream,
    stdout: UnixStream,
    child_stdout: UnixStream,
    stderr: UnixStream,
    child_stderr: UnixStream,
    input: std::fs::File,
    host: std::fs::File,
}

fn owner(
    prepared: Prepared,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    channels: Channels,
) -> Result<ApiResponse> {
    let Channels {
        control,
        child_control,
        mut status,
        child_status,
        mut diagnostics,
        child_diagnostics,
        stdout,
        child_stdout,
        stderr,
        child_stderr,
        input,
        host,
    } = channels;
    if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
        bail!("GitHub CLI request timed out; process cleanup uncertain");
    }
    let environment: Vec<CString> = std::env::vars_os()
        .map(|(key, value)| {
            let mut bytes = key.as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            CString::new(bytes)
        })
        .collect::<std::result::Result<_, _>>()
        .context("Snapshot gh environment")?;
    let path = environment
        .iter()
        .find_map(|v| v.as_bytes().strip_prefix(b"PATH="))
        .unwrap_or(b"/bin:/usr/bin");
    let program = prepared.program.as_bytes();
    let paths: Vec<CString> = if program.contains(&b'/') {
        vec![CString::new(program)?]
    } else {
        path.split(|b| *b == b':')
            .map(|part| {
                let mut bytes = if part.is_empty() {
                    b".".to_vec()
                } else {
                    part.to_vec()
                };
                bytes.push(b'/');
                bytes.extend_from_slice(program);
                CString::new(bytes)
            })
            .collect::<std::result::Result<_, _>>()?
    };
    let args = [
        CString::new(program)?,
        CString::new("api")?,
        CString::new("--jq")?,
        CString::new(prepared.filter)?,
        CString::new(prepared.route)?,
    ];
    let mut argv: Vec<*mut c_char> = args.iter().map(|s| s.as_ptr() as *mut c_char).collect();
    argv.push(std::ptr::null_mut());
    let mut envp: Vec<*mut c_char> = environment
        .iter()
        .map(|s| s.as_ptr() as *mut c_char)
        .collect();
    envp.push(std::ptr::null_mut());
    let shell = CString::new("sh")?;
    let mut shells: Vec<Vec<*mut c_char>> = paths
        .iter()
        .map(|p| {
            vec![
                shell.as_ptr() as *mut c_char,
                p.as_ptr() as *mut c_char,
                argv[1],
                argv[2],
                argv[3],
                argv[4],
                std::ptr::null_mut(),
            ]
        })
        .collect();
    let mut shell_ptrs: Vec<*mut *mut c_char> = shells.iter_mut().map(|s| s.as_mut_ptr()).collect();
    let mut path_ptrs: Vec<*mut c_char> = paths.iter().map(|p| p.as_ptr() as *mut c_char).collect();
    if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
        bail!("GitHub CLI request timed out; process cleanup uncertain");
    }
    let exceeded = Arc::new(AtomicBool::new(false));
    let out = reader(
        stdout,
        super::GH_OUTPUT_LIMIT,
        exceeded.clone(),
        cancelled.clone(),
    )?;
    let err = reader(
        stderr,
        super::GH_STDERR_LIMIT,
        exceeded.clone(),
        cancelled.clone(),
    )?;
    status.set_nonblocking(true)?;
    diagnostics.set_nonblocking(true)?;
    if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
        bail!("GitHub CLI request timed out; process cleanup uncertain");
    }
    let mut pidfd = -1;
    let mut child_pid = -1;
    let pid = unsafe {
        start::codex_wake_legacy_prototype_start(
            child_control.as_raw_fd(),
            child_status.as_raw_fd(),
            host.as_raw_fd(),
            child_diagnostics.as_raw_fd(),
            input.as_raw_fd(),
            child_stdout.as_raw_fd(),
            child_stderr.as_raw_fd(),
            &mut pidfd,
            path_ptrs.as_mut_ptr(),
            shell_ptrs.as_mut_ptr(),
            path_ptrs.len(),
            argv.as_mut_ptr(),
            envp.as_mut_ptr(),
            &mut child_pid,
        )
    };
    let spawn_error = std::io::Error::last_os_error();
    drop((
        child_control,
        child_status,
        child_diagnostics,
        child_stdout,
        child_stderr,
        input,
        host,
    ));
    if pid <= 0 {
        cancelled.store(true, Ordering::Relaxed);
        if pid == -2 && pidfd >= 0 {
            let fd = unsafe { std::fs::File::from_raw_fd(pidfd) };
            let _ = reap(fd, deadline);
            bail!("Start gh failed; process cleanup uncertain: {spawn_error}");
        }
        return Err(spawn_error).context("Start gh supervisor");
    }
    let supervisor = unsafe { std::fs::File::from_raw_fd(pidfd) };
    let mut bytes = [0u8; 12];
    let mut position = 0;
    let mut prepared_sent = false;
    let mut result: Option<(i32, i32, i32)> = None;
    let mut signal_failed = false;
    loop {
        let mut diag = [0u8; 8];
        match diagnostics.read(&mut diag) {
            Ok(n) if diag[..n].contains(&b'E') => signal_failed = true,
            Err(e)
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::Interrupted =>
            {
                signal_failed = true
            }
            _ => {}
        }
        if cancelled.load(Ordering::Relaxed)
            || exceeded.load(Ordering::Relaxed)
            || Instant::now() >= deadline
        {
            break;
        }
        if result.is_some() && out.is_finished() && err.is_finished() {
            break;
        }
        if result.is_none() {
            match status.read(&mut bytes[position..]) {
                Ok(0) => break,
                Ok(n) => {
                    position += n;
                    if position == bytes.len() {
                        let st = i32::from_ne_bytes(bytes[0..4].try_into()?);
                        let stage = i32::from_ne_bytes(bytes[4..8].try_into()?);
                        let error = i32::from_ne_bytes(bytes[8..12].try_into()?);
                        position = 0;
                        if !prepared_sent && stage == -2 {
                            if !send(&control, b'G') {
                                break;
                            }
                            prepared_sent = true;
                        } else {
                            result = Some((st, stage, error));
                        }
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    let output = if out.is_finished() {
        Some(
            out.join()
                .map_err(|_| anyhow::anyhow!("gh stdout reader panicked"))
                .and_then(|result| result),
        )
    } else {
        None
    };
    let errors = if err.is_finished() {
        Some(
            err.join()
                .map_err(|_| anyhow::anyhow!("gh stderr reader panicked"))
                .and_then(|result| result),
        )
    } else {
        None
    };
    let timed_out = cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline;
    let clean = result.is_some_and(|(_, stage, _)| (0..=6).contains(&stage))
        && output.as_ref().is_some_and(Result::is_ok)
        && errors.as_ref().is_some_and(Result::is_ok)
        && !cancelled.load(Ordering::Relaxed)
        && !exceeded.load(Ordering::Relaxed)
        && Instant::now() < deadline
        && !signal_failed;
    let sent = send(&control, if clean { b'S' } else { b'K' });
    if !clean {
        cancelled.store(true, Ordering::Relaxed);
    }
    let cleanup_deadline = if clean {
        deadline
    } else {
        Instant::now() + Duration::from_millis(100)
    };
    let reaped = reap(supervisor, cleanup_deadline);
    if !sent || !clean {
        if let Some(Err(error)) = &output {
            bail!("gh stdout read failed: {error}; process cleanup uncertain");
        }
        if let Some(Err(error)) = &errors {
            bail!("gh stderr read failed: {error}; process cleanup uncertain");
        }
        if exceeded.load(Ordering::Relaxed) {
            bail!("GitHub CLI output exceeded its size limit; process cleanup uncertain");
        }
        if timed_out {
            bail!("GitHub CLI request timed out; process cleanup uncertain");
        }
        bail!("GitHub CLI request failed; process cleanup uncertain");
    }
    reaped?;
    let mut final_report = [0_u8; 12];
    let mut final_position = 0;
    while final_position < final_report.len() {
        match status.read(&mut final_report[final_position..]) {
            Ok(0) => bail!(
                "gh supervisor closed before guardian confirmation; process cleanup uncertain"
            ),
            Ok(n) => final_position += n,
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted
                    || error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                if Instant::now() >= deadline {
                    bail!("gh guardian confirmation timed out; process cleanup uncertain");
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => {
                bail!("gh guardian confirmation failed: {error}; process cleanup uncertain")
            }
        }
    }
    let guard_status = i32::from_ne_bytes(final_report[0..4].try_into()?);
    let final_stage = i32::from_ne_bytes(final_report[4..8].try_into()?);
    if final_stage != 8 || guard_status != 0 {
        bail!("gh supervisor did not confirm guardian completion; process cleanup uncertain");
    }
    let output = output.context("gh stdout reader did not finish")??;
    let errors = errors.context("gh stderr reader did not finish")??;
    let (wait, stage, error) = result.context("gh supervisor returned no status")?;
    if stage != 0 {
        bail!(
            "Start gh failed at stage {stage}: {}; process cleanup uncertain",
            std::io::Error::from_raw_os_error(error)
        );
    }
    if !libc::WIFEXITED(wait) || libc::WEXITSTATUS(wait) != 0 {
        bail!(
            "GitHub CLI request failed: {}",
            String::from_utf8_lossy(&errors).trim()
        );
    }
    let body = serde_json::from_slice(&output).context("Decode GitHub API response")?;
    Ok(ApiResponse { status: 200, body })
}

#[cfg(test)]
pub(super) fn fail_guard_after_release_for_test() {
    guard::FAIL_AFTER_RELEASE.store(true, Ordering::Relaxed);
}

pub(super) fn gh_api(
    program: &Path,
    route: &str,
    filter: &str,
    deadline: Instant,
) -> Result<ApiResponse> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("GitHub CLI request timed out; process cleanup uncertain");
    }
    let (control, child_control) = UnixStream::pair()?;
    let owner_control = control.try_clone()?;
    let (status, child_status) = UnixStream::pair()?;
    let (diagnostics, child_diagnostics) = UnixStream::pair()?;
    let (stdout, child_stdout) = UnixStream::pair()?;
    let (stderr, child_stderr) = UnixStream::pair()?;
    let input = std::fs::File::open("/dev/null")?;
    let h = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
    if h < 0 {
        return Err(std::io::Error::last_os_error()).context("Open host pidfd");
    }
    let host = unsafe { std::fs::File::from_raw_fd(h) };
    let cancelled = Arc::new(AtomicBool::new(false));
    let owner_cancel = cancelled.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    let prepared = Prepared {
        program: program.as_os_str().to_owned(),
        route: route.to_owned(),
        filter: filter.to_owned(),
    };
    thread::Builder::new()
        .spawn(move || {
            let channels = Channels {
                control: owner_control,
                child_control,
                status,
                child_status,
                diagnostics,
                child_diagnostics,
                stdout,
                child_stdout,
                stderr,
                child_stderr,
                input,
                host,
            };
            let result = owner(prepared, deadline, owner_cancel, channels);
            let _ = tx.send(result);
        })
        .context("Start gh supervisor owner")?;
    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            cancelled.store(true, Ordering::Relaxed);
            let _ = send(&control, b'K');
            bail!("GitHub CLI request timed out; process cleanup uncertain");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            bail!("gh supervisor owner stopped; process cleanup uncertain")
        }
    }
}
