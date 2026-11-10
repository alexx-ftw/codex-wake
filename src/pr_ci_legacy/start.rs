use super::{
    fds::{
        GUARD_DIAG, HOST_PIDFD, ORIGINAL_MASK, PREPARED_COUNT, PREPARED_PATHS, PREPARED_SHELL_ARGV,
        WORKER_ARGS, WORKER_ENV, codex_wake_legacy_close_extra,
    },
    supervisor::codex_wake_legacy_helper,
};
use core::{
    ffi::{c_char, c_int, c_long, c_void},
    ptr,
};
// Raw clone has different first-argument order on s390x.
type SigSet = libc::sigset_t;
#[repr(C)]
struct Report {
    status: c_int,
    stage: c_int,
    error: c_int,
}
unsafe extern "C" {
    fn sigfillset(s: *mut SigSet) -> c_int;
    fn pthread_sigmask(how: c_int, set: *const SigSet, old: *mut SigSet) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn dup2(a: c_int, b: c_int) -> c_int;
    fn syscall(num: c_long, ...) -> c_long;
    fn __errno_location() -> *mut c_int;
    fn _exit(code: c_int) -> !;
    fn send(fd: c_int, p: *const u8, n: usize, flags: c_int) -> isize;
}
unsafe fn clone_pidfd(fd: *mut c_int) -> c_int {
    unsafe {
        #[cfg(target_arch = "s390x")]
        {
            syscall(
                libc::SYS_clone,
                0,
                libc::CLONE_PIDFD | libc::SIGCHLD,
                fd,
                0,
                0,
            ) as c_int
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            syscall(
                libc::SYS_clone,
                libc::CLONE_PIDFD | libc::SIGCHLD,
                0,
                fd,
                0,
                0,
            ) as c_int
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "s390x")))]
        {
            let _ = fd;
            *__errno_location() = libc::ENOSYS;
            -1
        }
    }
}
pub(super) unsafe extern "C" fn codex_wake_legacy_prototype_start(
    c: c_int,
    s: c_int,
    h: c_int,
    d: c_int,
    input: c_int,
    out: c_int,
    err: c_int,
    pidfd_out: *mut c_int,
    paths: *mut *mut c_char,
    shells: *mut *mut *mut c_char,
    count: usize,
    args: *mut *mut c_char,
    envp: *mut *mut c_char,
    child_out: *mut c_int,
) -> c_int {
    unsafe {
        let source = [c, s, h, d, input, out, err];
        let mut fds = [-1; 7];
        let mut owned = [false; 7];
        for i in 0..7 {
            if source[i] < 0 {
                for j in 0..i {
                    if owned[j] {
                        close(fds[j]);
                    }
                }
                *__errno_location() = libc::EBADF;
                return -1;
            }
            if source[i] < 3 {
                fds[i] = fcntl(source[i], libc::F_DUPFD_CLOEXEC, 3);
                owned[i] = true;
                if fds[i] < 0 {
                    let e = *__errno_location();
                    for j in 0..i {
                        if owned[j] {
                            close(fds[j]);
                        }
                    }
                    *__errno_location() = e;
                    return -1;
                }
            } else {
                fds[i] = source[i]
            }
        }
        let mut all: SigSet = core::mem::zeroed();
        let mut old: SigSet = core::mem::zeroed();
        sigfillset(&mut all);
        let mut rc = pthread_sigmask(libc::SIG_SETMASK, &all, &mut old);
        if rc != 0 {
            for i in 0..7 {
                if owned[i] {
                    close(fds[i]);
                }
            }
            *__errno_location() = rc;
            return -1;
        }
        let mut pidfd = -1;
        let p = clone_pidfd(&mut pidfd);
        let saved = *__errno_location();
        if p > 0 {
            *child_out = p;
        }
        if p == 0 {
            ORIGINAL_MASK = old;
            HOST_PIDFD = fds[2];
            GUARD_DIAG = fds[3];
            PREPARED_PATHS = paths;
            PREPARED_SHELL_ARGV = shells;
            PREPARED_COUNT = count;
            WORKER_ARGS = args;
            WORKER_ENV = envp;
            if dup2(fds[4], 0) < 0 || dup2(fds[5], 1) < 0 || dup2(fds[6], 2) < 0 {
                _exit(92)
            }
            if codex_wake_legacy_close_extra(fds[0], fds[1]) != 0 {
                let r = Report {
                    status: 0,
                    stage: 6,
                    error: *__errno_location(),
                };
                send(
                    fds[1],
                    (&r as *const Report).cast(),
                    core::mem::size_of::<Report>(),
                    libc::MSG_NOSIGNAL,
                );
                _exit(93)
            }
            _exit(codex_wake_legacy_helper(fds[0], fds[1]));
        }
        for i in 0..7 {
            if owned[i] {
                close(fds[i]);
            }
        }
        rc = pthread_sigmask(libc::SIG_SETMASK, &old, ptr::null_mut());
        if rc != 0 && p > 0 {
            syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                libc::SIGKILL,
                ptr::null::<c_void>(),
                0,
            );
            *pidfd_out = pidfd;
            *__errno_location() = rc;
            return -2;
        }
        if p < 0 {
            *__errno_location() = saved;
            return -1;
        }
        *pidfd_out = pidfd;
        p
    }
}
