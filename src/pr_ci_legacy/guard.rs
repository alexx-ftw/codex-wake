use super::fds::codex_wake_legacy_guard_close;
use core::ffi::{c_int, c_long, c_void};
type PollFd = libc::pollfd;
unsafe extern "C" {
    fn close(fd: c_int) -> c_int;
    fn write(fd: c_int, p: *const c_void, n: usize) -> isize;
    fn poll(fds: *mut PollFd, n: libc::nfds_t, timeout: c_int) -> c_int;
    fn recv(fd: c_int, p: *mut u8, n: usize, flags: c_int) -> isize;
    fn send(fd: c_int, p: *const u8, n: usize, flags: c_int) -> isize;
    fn syscall(number: c_long, ...) -> c_long;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;
    fn _exit(code: c_int) -> !;
}
const IN: i16 = 1;
const ERR: i16 = 8;
const HUP: i16 = 16;
const NVAL: i16 = 32;
const EINTR: c_int = libc::EINTR;
const ESRCH: c_int = libc::ESRCH;
const PIDFD_SEND_SIGNAL: c_long = libc::SYS_pidfd_send_signal;
const SIGKILL: c_int = libc::SIGKILL;
const NOSIGNAL: c_int = libc::MSG_NOSIGNAL;

#[cfg(test)]
pub(super) static FAIL_AFTER_RELEASE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
pub(super) unsafe extern "C" fn codex_wake_legacy_rust_guard(
    control: c_int,
    ready: c_int,
    release: c_int,
    host: c_int,
    supervisor: c_int,
    member: c_int,
    diag: c_int,
    completion: c_int,
) -> ! {
    unsafe {
        if codex_wake_legacy_guard_close(control, ready, release) != 0 {
            _exit(112)
        }
        if write(ready, b"R".as_ptr().cast(), 1) != 1 {
            _exit(113)
        }
        close(ready);
        let (mut pending, mut joined, mut released, mut quit, mut notified, mut sent) =
            (false, false, false, false, false, false);
        loop {
            let mut f = [
                PollFd {
                    fd: if pending { -1 } else { host },
                    events: IN,
                    revents: 0,
                },
                PollFd {
                    fd: if pending { -1 } else { supervisor },
                    events: IN,
                    revents: 0,
                },
                PollFd {
                    fd: if joined { -1 } else { member },
                    events: IN | HUP,
                    revents: 0,
                },
                PollFd {
                    fd: if released || pending { -1 } else { release },
                    events: IN | HUP,
                    revents: 0,
                },
                PollFd {
                    fd: if released && !pending { control } else { -1 },
                    events: IN | HUP,
                    revents: 0,
                },
            ];
            let pr = loop {
                let r = poll(f.as_mut_ptr(), 5, -1);
                if r < 0 && *__errno_location() == EINTR {
                    continue;
                }
                break r;
            };
            if pr < 1 {
                pending = true
            }
            if f[0].revents & (IN | HUP | ERR | NVAL) != 0
                || f[1].revents & (IN | HUP | ERR | NVAL) != 0
            {
                pending = true
            }
            let mut ch = 0u8;
            if f[3].revents != 0 {
                if recv(release, &mut ch, 1, 0) == 1 && ch == b'R' {
                    released = true
                } else {
                    pending = true
                }
            }
            if f[4].revents != 0 {
                if recv(control, &mut ch, 1, 0) == 1 && ch == b'S' {
                    quit = true
                } else {
                    pending = true
                }
            }
            if f[2].revents != 0 {
                let n = recv(member, &mut ch, 1, 0);
                if (n == 1 && ch == b'J') || n == 0 {
                    joined = true
                } else if n < 0 && *__errno_location() == EINTR {
                } else {
                    pending = true
                }
            }
            if pending && !joined {
                let result = syscall(
                    PIDFD_SEND_SIGNAL,
                    supervisor,
                    SIGKILL,
                    core::ptr::null::<c_void>(),
                    0,
                );
                if result < 0 && *__errno_location() != ESRCH && !notified {
                    send(diag, b"E".as_ptr(), 1, NOSIGNAL);
                    notified = true
                }
            }
            if joined && !sent {
                let result = if pending { b'E' } else { b'A' };
                send(completion, &result, 1, NOSIGNAL);
                sent = true;
            }
            if pending && joined {
                kill(0, SIGKILL);
                _exit(125)
            }
            if quit && joined {
                #[cfg(test)]
                if FAIL_AFTER_RELEASE.load(std::sync::atomic::Ordering::Relaxed) {
                    _exit(42)
                }
                _exit(0)
            }
        }
    }
}
#[repr(C)]
struct ExecError {
    stage: c_int,
    error: c_int,
}
#[repr(C)]
struct Report {
    status: c_int,
    stage: c_int,
    error: c_int,
}
unsafe extern "C" {
    fn read(fd: c_int, p: *mut c_void, n: usize) -> isize;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
}
pub(super) unsafe extern "C" fn codex_wake_legacy_rust_supervisor_finish(
    member: c_int,
    exec_read: c_int,
    exec_write: c_int,
    worker: c_int,
    guard: c_int,
    status_fd: c_int,
    completion: c_int,
) -> c_int {
    unsafe {
        close(member);
        close(exec_write);
        close(0);
        close(1);
        close(2);
        let mut e = ExecError { stage: 0, error: 0 };
        let ep = (&mut e as *mut ExecError).cast::<u8>();
        let n = loop {
            let r = read(exec_read, ep.cast(), core::mem::size_of::<ExecError>());
            if r < 0 && *__errno_location() == EINTR {
                continue;
            }
            break r;
        };
        close(exec_read);
        let mut ws = 0;
        let w = loop {
            let r = waitpid(worker, &mut ws, 0);
            if r < 0 && *__errno_location() == EINTR {
                continue;
            }
            break r;
        };
        if w != worker {
            return 118;
        }
        let mut report = Report {
            status: ws,
            stage: if n == 0 { 0 } else { e.stage },
            error: if n == 0 { 0 } else { e.error },
        };
        if n != 0 && n != core::mem::size_of::<ExecError>() as isize {
            report.stage = -1;
        }
        let mut decision = 0u8;
        let dn = loop {
            let r = recv(completion, &mut decision, 1, 0);
            if r < 0 && *__errno_location() == EINTR {
                continue;
            }
            break r;
        };
        close(completion);
        if dn != 1 || decision != b'A' {
            report.stage = 7;
            report.error = 0;
        }
        let rp = (&report as *const Report).cast::<u8>();
        let len = core::mem::size_of::<Report>();
        send(status_fd, rp, len, NOSIGNAL);
        let mut gs = 0;
        let w = loop {
            let r = waitpid(guard, &mut gs, 0);
            if r < 0 && *__errno_location() == EINTR {
                continue;
            }
            break r;
        };
        let guard_clean = w == guard && libc::WIFEXITED(gs) && libc::WEXITSTATUS(gs) == 0;
        let final_report = Report {
            status: gs,
            stage: if guard_clean { 8 } else { 9 },
            error: if w == guard { 0 } else { *__errno_location() },
        };
        send(
            status_fd,
            (&final_report as *const Report).cast(),
            core::mem::size_of::<Report>(),
            NOSIGNAL,
        );
        close(status_fd);
        if w != guard {
            return 119;
        }
        if !guard_clean {
            return 120;
        }
        if libc::WIFEXITED(ws) {
            libc::WEXITSTATUS(ws)
        } else if libc::WIFSIGNALED(ws) {
            128 + libc::WTERMSIG(ws)
        } else {
            123
        }
    }
}
