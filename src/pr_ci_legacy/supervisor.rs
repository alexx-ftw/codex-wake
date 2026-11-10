use super::{
    fds::{
        GUARD_COMPLETION, GUARD_DIAG, GUARD_MEMBER, GUARD_SUPFD, HOST_PIDFD, ORIGINAL_MASK,
        PREPARED_COUNT, PREPARED_PATHS, PREPARED_SHELL_ARGV, WORKER_ARGS, WORKER_ENV,
    },
    guard::{codex_wake_legacy_rust_guard, codex_wake_legacy_rust_supervisor_finish},
};
use core::{ffi::c_int, mem, ptr};
#[repr(C)]
struct Report {
    status: c_int,
    stage: c_int,
    error: c_int,
}
#[repr(C)]
struct ExecError {
    stage: c_int,
    error: c_int,
}
unsafe fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}
unsafe fn fork_raw() -> c_int {
    unsafe {
        #[cfg(target_arch = "s390x")]
        {
            libc::syscall(libc::SYS_clone, 0, libc::SIGCHLD, 0, 0, 0) as c_int
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) as c_int
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "s390x")))]
        {
            *libc::__errno_location() = libc::ENOSYS;
            -1
        }
    }
}
unsafe fn send_byte(fd: c_int, c: u8) -> isize {
    unsafe { libc::send(fd, (&c as *const u8).cast(), 1, libc::MSG_NOSIGNAL) }
}
unsafe fn failure(fd: c_int, stage: c_int) -> ! {
    unsafe {
        let e = ExecError {
            stage,
            error: errno(),
        };
        libc::write(
            fd,
            (&e as *const ExecError).cast(),
            mem::size_of::<ExecError>(),
        );
        libc::_exit(117)
    }
}
unsafe fn wait_one(pid: c_int) {
    unsafe {
        let mut status = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 && errno() == libc::EINTR {}
    }
}
unsafe fn send_report(fd: c_int, stage: c_int, error: c_int) {
    unsafe {
        let r = Report {
            status: 0,
            stage,
            error,
        };
        libc::send(
            fd,
            (&r as *const Report).cast(),
            mem::size_of::<Report>(),
            libc::MSG_NOSIGNAL,
        );
    }
}
unsafe fn reset_handlers() -> bool {
    unsafe {
        let mut def: libc::sigaction = mem::zeroed();
        def.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut def.sa_mask);
        for signal in 1..65 {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP {
                continue;
            }
            let mut old: libc::sigaction = mem::zeroed();
            if libc::sigaction(signal, ptr::null(), &mut old) != 0 {
                if errno() == libc::EINVAL {
                    continue;
                }
                return false;
            }
            if old.sa_sigaction != libc::SIG_DFL
                && old.sa_sigaction != libc::SIG_IGN
                && libc::sigaction(signal, &def, ptr::null_mut()) != 0
            {
                return false;
            }
        }
        true
    }
}
unsafe fn run_worker(
    guard: c_int,
    member: c_int,
    execfd: c_int,
    completion: c_int,
    status: c_int,
    old: *const libc::sigaction,
) -> ! {
    unsafe {
        libc::close(completion);
        libc::close(HOST_PIDFD);
        libc::close(status);
        if libc::setpgid(0, guard) != 0 {
            failure(execfd, 1)
        }
        if send_byte(member, b'J') != 1 {
            failure(execfd, 6)
        }
        libc::close(member);
        if libc::sigaction(libc::SIGCHLD, old, ptr::null_mut()) != 0
            || !reset_handlers()
            || libc::sigprocmask(
                libc::SIG_SETMASK,
                ptr::addr_of!(ORIGINAL_MASK),
                ptr::null_mut(),
            ) != 0
        {
            failure(execfd, 2)
        }
        let mut denied = false;
        for i in 0..PREPARED_COUNT {
            let path = *PREPARED_PATHS.add(i);
            libc::execve(path, WORKER_ARGS.cast(), WORKER_ENV.cast());
            let e = errno();
            if e == libc::ENOEXEC {
                libc::execve(
                    c"/bin/sh".as_ptr(),
                    (*PREPARED_SHELL_ARGV.add(i)).cast(),
                    WORKER_ENV.cast(),
                );
                failure(execfd, 3)
            }
            if e == libc::EACCES {
                denied = true
            } else if e != libc::ENOENT && e != libc::ENOTDIR {
                failure(execfd, 3)
            }
        }
        *libc::__errno_location() = if denied { libc::EACCES } else { libc::ENOENT };
        failure(execfd, 3)
    }
}
pub(super) unsafe extern "C" fn codex_wake_legacy_helper(control: c_int, status: c_int) -> c_int {
    unsafe {
        let mut old: libc::sigaction = mem::zeroed();
        let mut def: libc::sigaction = mem::zeroed();
        def.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut def.sa_mask);
        if libc::sigaction(libc::SIGCHLD, ptr::null(), &mut old) != 0
            || libc::sigaction(libc::SIGCHLD, &def, ptr::null_mut()) != 0
        {
            return 102;
        }
        let mut ready = [-1; 2];
        let mut release = [-1; 2];
        let mut member = [-1; 2];
        let mut completion = [-1; 2];
        if libc::syscall(libc::SYS_pipe2, ready.as_mut_ptr(), libc::O_CLOEXEC) < 0
            || libc::syscall(
                libc::SYS_socketpair,
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                release.as_mut_ptr(),
            ) < 0
            || libc::syscall(
                libc::SYS_socketpair,
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                member.as_mut_ptr(),
            ) < 0
            || libc::syscall(
                libc::SYS_socketpair,
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                completion.as_mut_ptr(),
            ) < 0
        {
            return 110;
        }
        GUARD_MEMBER = member[0];
        GUARD_COMPLETION = completion[1];
        GUARD_SUPFD = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as c_int;
        if GUARD_SUPFD < 0 {
            return 109;
        }
        let guard = fork_raw();
        if guard < 0 {
            return 111;
        }
        if guard == 0 {
            libc::close(member[1]);
            libc::close(completion[0]);
            if libc::setpgid(0, 0) != 0 {
                libc::_exit(121)
            }
            codex_wake_legacy_rust_guard(
                control,
                ready[1],
                release[1],
                HOST_PIDFD,
                GUARD_SUPFD,
                GUARD_MEMBER,
                GUARD_DIAG,
                GUARD_COMPLETION,
            )
        }
        libc::close(completion[1]);
        libc::close(GUARD_DIAG);
        libc::close(member[0]);
        libc::close(GUARD_SUPFD);
        libc::close(ready[1]);
        libc::close(release[1]);
        let mut f = [
            libc::pollfd {
                fd: control,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: ready[0],
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
        ];
        let p = loop {
            let r = libc::poll(f.as_mut_ptr(), 2, -1);
            if r < 0 && errno() == libc::EINTR {
                continue;
            }
            break r;
        };
        let mut cancel = p < 0
            || f[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            || f[1].revents & libc::POLLIN == 0;
        let mut c = 0u8;
        if !cancel && (libc::read(ready[0], (&mut c as *mut u8).cast(), 1) != 1 || c != b'R') {
            cancel = true
        }
        if !cancel {
            let prepared = Report {
                status: 0,
                stage: -2,
                error: 0,
            };
            if libc::send(
                status,
                (&prepared as *const Report).cast(),
                mem::size_of::<Report>(),
                libc::MSG_NOSIGNAL,
            ) != mem::size_of::<Report>() as isize
            {
                cancel = true
            }
        }
        if !cancel {
            let n = loop {
                let r = libc::recv(control, (&mut c as *mut u8).cast(), 1, 0);
                if r < 0 && errno() == libc::EINTR {
                    continue;
                }
                break r;
            };
            if n != 1 || c != b'G' {
                cancel = true
            }
        }
        if !cancel && send_byte(release[0], b'R') != 1 {
            cancel = true
        }
        libc::close(ready[0]);
        libc::close(release[0]);
        if cancel {
            libc::close(member[1]);
            libc::kill(guard, libc::SIGKILL);
            wait_one(guard);
            send_report(status, 4, libc::ECANCELED);
            libc::close(status);
            libc::close(control);
            return 115;
        }
        libc::close(control);
        let mut ex = [-1; 2];
        if libc::syscall(libc::SYS_pipe2, ex.as_mut_ptr(), libc::O_CLOEXEC) < 0 {
            let e = errno();
            libc::close(member[1]);
            libc::kill(guard, libc::SIGKILL);
            wait_one(guard);
            send_report(status, 5, e);
            libc::close(status);
            return 116;
        }
        let worker = fork_raw();
        if worker < 0 {
            let e = errno();
            libc::close(member[1]);
            libc::close(ex[0]);
            libc::close(ex[1]);
            libc::kill(guard, libc::SIGKILL);
            wait_one(guard);
            send_report(status, 5, e);
            libc::close(status);
            return 116;
        }
        if worker == 0 {
            libc::close(ex[0]);
            run_worker(guard, member[1], ex[1], completion[0], status, &old)
        }
        codex_wake_legacy_rust_supervisor_finish(
            member[1],
            ex[0],
            ex[1],
            worker,
            guard,
            status,
            completion[0],
        )
    }
}
