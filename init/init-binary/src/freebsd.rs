use std::ffi::CString;
use std::os::fd::AsRawFd;

use nix::fcntl::{self, FcntlArg, OFlag};
use nix::sys::stat::Mode;
use nix::unistd;

unsafe extern "C" {
    fn revoke(path: *const libc::c_char) -> libc::c_int;
}

const KENV_MVALLEN: usize = 128;
const ISO_DEV: &str = "/dev/iso9660/KRUN_CONFIG";
const ISO_MOUNT: &str = "/mnt";
pub const ISO_CONFIG_PATH: &str = "/mnt/krun_config.json";

const KENV_VARS: &[&str] = &[
    "HOSTNAME",
    "KRUN_CONFIG",
    "KRUN_HOME",
    "KRUN_INIT",
    "KRUN_INIT_PID1",
    "KRUN_RLIMITS",
    "KRUN_TERM",
    "KRUN_WORKDIR",
];

fn kenv_get(name: &str) -> Option<String> {
    let c_name = CString::new(name).ok()?;
    let mut buf = vec![0u8; KENV_MVALLEN + 1];
    let ret = unsafe {
        libc::kenv(
            libc::KENV_GET,
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            (KENV_MVALLEN + 1) as i32,
        )
    };
    if ret < 0 {
        return None;
    }
    let s = std::ffi::CStr::from_bytes_until_nul(&buf).ok()?;
    Some(s.to_string_lossy().into_owned())
}

/// Populate the process environment from the FreeBSD kernel environment.
///
/// On FreeBSD, init runs before the process environment is set up, so
/// variables like KRUN_INIT must be read from kenv(2) rather than getenv(3).
pub fn populate_env_from_kenv() {
    for &var in KENV_VARS {
        if let Some(val) = kenv_get(var) {
            unsafe { std::env::set_var(var, val) };
        }
    }
}

/// Open /dev/console and make it the controlling terminal.
///
/// Replicates login_tty(3) inline to avoid a libutil dependency:
/// revoke any existing opens, open the device, create a new session,
/// set the controlling terminal via TIOCSCTTY, then dup2 into stdio.
/// Falls back to /dev/null + /init.log if the console cannot be opened.
pub fn open_console() {
    let console = c"/dev/console";
    unsafe { revoke(console.as_ptr()) };

    let Ok(fd) = fcntl::open(console, OFlag::O_RDWR | OFlag::O_NONBLOCK, Mode::empty()) else {
        fallback_console();
        return;
    };

    if let Ok(flags) = fcntl::fcntl(&fd, FcntlArg::F_GETFL) {
        let _ = fcntl::fcntl(
            &fd,
            FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) & !OFlag::O_NONBLOCK),
        );
    }

    let _ = unistd::setsid();
    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSCTTY, 0) };
    let _ = unistd::dup2_stdin(&fd);
    let _ = unistd::dup2_stdout(&fd);
    let _ = unistd::dup2_stderr(&fd);
    if fd.as_raw_fd() <= libc::STDERR_FILENO {
        // fd is a stdio slot that dup2 just wrote to — don't close it.
        std::mem::forget(fd);
    }
}

fn fallback_console() {
    if let Ok(null_fd) = fcntl::open(c"/dev/null", OFlag::O_RDWR, Mode::empty()) {
        if null_fd.as_raw_fd() != libc::STDIN_FILENO {
            let _ = unistd::dup2_stdin(&null_fd);
        } else {
            std::mem::forget(null_fd);
        }
    }

    match fcntl::open(
        c"/init.log",
        OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_CREAT,
        Mode::from_bits_truncate(0o644),
    ) {
        Ok(fd) => {
            let _ = unistd::dup2_stdout(&fd);
            if fd.as_raw_fd() == libc::STDOUT_FILENO {
                std::mem::forget(fd);
            }
        }
        Err(_) => {
            unsafe { libc::dup2(libc::STDIN_FILENO, libc::STDOUT_FILENO) };
        }
    }
    // stderr always mirrors stdout.
    unsafe { libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO) };
}

/// Mount the KRUN_CONFIG ISO image at /mnt via nmount(2).
/// Returns true on success.
pub fn mount_config_iso() -> bool {
    let _ = std::fs::create_dir_all(ISO_MOUNT);

    let fstype_key = c"fstype";
    let fstype_val = c"cd9660";
    let fspath_key = c"fspath";
    let fspath_cstr = CString::new(ISO_MOUNT).unwrap();
    let from_key = c"from";
    let from_cstr = CString::new(ISO_DEV).unwrap();

    let mut iov = [
        libc::iovec {
            iov_base: fstype_key.as_ptr() as *mut _,
            iov_len: fstype_key.to_bytes_with_nul().len(),
        },
        libc::iovec {
            iov_base: fstype_val.as_ptr() as *mut _,
            iov_len: fstype_val.to_bytes_with_nul().len(),
        },
        libc::iovec {
            iov_base: fspath_key.as_ptr() as *mut _,
            iov_len: fspath_key.to_bytes_with_nul().len(),
        },
        libc::iovec {
            iov_base: fspath_cstr.as_ptr() as *mut _,
            iov_len: fspath_cstr.as_bytes_with_nul().len(),
        },
        libc::iovec {
            iov_base: from_key.as_ptr() as *mut _,
            iov_len: from_key.to_bytes_with_nul().len(),
        },
        libc::iovec {
            iov_base: from_cstr.as_ptr() as *mut _,
            iov_len: from_cstr.as_bytes_with_nul().len(),
        },
    ];

    unsafe { libc::nmount(iov.as_mut_ptr(), iov.len() as u32, libc::MNT_RDONLY) == 0 }
}

pub fn unmount_config_iso() {
    let mount_cstr = CString::new(ISO_MOUNT).unwrap();
    unsafe { libc::unmount(mount_cstr.as_ptr(), 0) };
}
