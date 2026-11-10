use core::{
    ffi::{c_char, c_int},
    mem, ptr,
};
pub(super) static mut ORIGINAL_MASK: libc::sigset_t = unsafe { mem::zeroed() };
pub(super) static mut HOST_PIDFD: c_int = -1;
pub(super) static mut GUARD_DIAG: c_int = -1;
pub(super) static mut GUARD_MEMBER: c_int = -1;
pub(super) static mut GUARD_SUPFD: c_int = -1;
pub(super) static mut GUARD_COMPLETION: c_int = -1;
pub(super) static mut PREPARED_PATHS: *mut *mut c_char = ptr::null_mut();
pub(super) static mut PREPARED_SHELL_ARGV: *mut *mut *mut c_char = ptr::null_mut();
pub(super) static mut PREPARED_COUNT: usize = 0;
pub(super) static mut WORKER_ARGS: *mut *mut c_char = ptr::null_mut();
pub(super) static mut WORKER_ENV: *mut *mut c_char = ptr::null_mut();
#[repr(align(8))]
struct Buffer([u8; 1024]);
unsafe fn proc_close(keep: &[c_int], stdio: bool) -> c_int {
    unsafe {
        let mut all: libc::sigset_t = mem::zeroed();
        libc::sigfillset(&mut all);
        if libc::sigprocmask(libc::SIG_SETMASK, &all, ptr::null_mut()) != 0 {
            return -1;
        }
        let d = libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        ) as c_int;
        if d < 0 {
            return -1;
        }
        let mut fs: libc::statfs = mem::zeroed();
        if libc::syscall(libc::SYS_fstatfs, d, &mut fs as *mut libc::statfs) != 0
            || fs.f_type as u64 != libc::PROC_SUPER_MAGIC as u64
        {
            return -1;
        }
        let mut pipe = [-1; 2];
        if libc::syscall(libc::SYS_pipe2, pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            return -1;
        }
        let mut name = [0u8; 16];
        let mut pos = 15;
        let mut v = pipe[0] as u32;
        loop {
            pos -= 1;
            name[pos] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let mut a: libc::stat = mem::zeroed();
        let mut b: libc::stat = mem::zeroed();
        let ok = libc::syscall(libc::SYS_fstat, pipe[0], &mut a as *mut libc::stat) == 0
            && libc::syscall(
                libc::SYS_newfstatat,
                d,
                name.as_ptr().add(pos),
                &mut b as *mut libc::stat,
                0,
            ) == 0
            && a.st_dev == b.st_dev
            && a.st_ino == b.st_ino
            && a.st_mode == b.st_mode;
        libc::syscall(libc::SYS_close, pipe[0]);
        libc::syscall(libc::SYS_close, pipe[1]);
        if !ok {
            return -1;
        }
        let mut buf = Buffer([0; 1024]);
        loop {
            let n = libc::syscall(libc::SYS_getdents64, d, buf.0.as_mut_ptr(), buf.0.len());
            if n < 0 {
                if *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                return -1;
            }
            if n == 0 {
                break;
            }
            let mut pos = 0usize;
            let mut closed = false;
            let total = n as usize;
            while pos < total {
                if total - pos < 21 {
                    return -1;
                }
                let base = buf.0.as_ptr().add(pos);
                let len = ptr::read_unaligned(base.add(16).cast::<u16>()) as usize;
                if len < 21 || len > total - pos {
                    return -1;
                }
                let mut fd = 0i32;
                let mut numeric = true;
                let mut ended = false;
                for i in 19..len {
                    let ch = *base.add(i);
                    if ch == 0 {
                        ended = true;
                        break;
                    }
                    if !ch.is_ascii_digit() {
                        numeric = false;
                        continue;
                    }
                    if numeric {
                        let x = (ch - b'0') as i32;
                        if fd > (i32::MAX - x) / 10 {
                            return -1;
                        }
                        fd = fd * 10 + x;
                    }
                }
                if !ended {
                    return -1;
                }
                if numeric && (!stdio || fd > 2) && fd != d && !keep.contains(&fd) {
                    let r = libc::syscall(libc::SYS_close, fd);
                    if r == 0 {
                        closed = true
                    } else if *libc::__errno_location() != libc::EBADF {
                        return -1;
                    }
                }
                pos += len;
            }
            if closed && libc::syscall(libc::SYS_lseek, d, 0, libc::SEEK_SET) < 0 {
                return -1;
            }
        }
        libc::syscall(libc::SYS_close, d);
        0
    }
}
unsafe fn close_except<const N: usize>(mut keep: [c_int; N], stdio: bool) -> c_int {
    unsafe {
        // Small fixed arrays; sorting performs no allocation.
        let mut i = 0;
        while i < N {
            let mut j = i + 1;
            while j < N {
                if keep[i] > keep[j] {
                    keep.swap(i, j)
                }
                j += 1
            }
            i += 1
        }
        if keep[0] < 3 {
            return -1;
        }
        for i in 1..N {
            if keep[i - 1] == keep[i] {
                return -1;
            }
        }
        let mut start = if stdio { 3u32 } else { 0u32 };
        for &fd in &keep {
            let end = fd as u32;
            if start < end && libc::syscall(libc::SYS_close_range, start, end - 1, 0u32) != 0 {
                return proc_close(&keep, stdio);
            }
            start = end + 1
        }
        if libc::syscall(libc::SYS_close_range, start, u32::MAX, 0u32) != 0 {
            return proc_close(&keep, stdio);
        }
        0
    }
}
pub(super) unsafe extern "C" fn codex_wake_legacy_close_extra(a: c_int, b: c_int) -> c_int {
    unsafe { close_except([a, b, HOST_PIDFD, GUARD_DIAG], true) }
}
pub(super) unsafe extern "C" fn codex_wake_legacy_guard_close(
    a: c_int,
    b: c_int,
    c: c_int,
) -> c_int {
    unsafe {
        close_except(
            [
                a,
                b,
                c,
                HOST_PIDFD,
                GUARD_MEMBER,
                GUARD_SUPFD,
                GUARD_DIAG,
                GUARD_COMPLETION,
            ],
            false,
        )
    }
}
