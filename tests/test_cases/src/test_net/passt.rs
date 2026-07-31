//! Passt backend for virtio-net test

use super::NetBackend;
use crate::{ShouldRun, TestSetup, krun_call, krun_call_u32};
use krun_sys::{COMPAT_NET_FEATURES, KRUN_FEATURE_NET, NET_FLAG_DHCP_CLIENT, krun_has_feature};
use nix::libc;
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::process::{Command, Stdio};

type KrunAddNetUnixstreamFn = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const std::ffi::c_char,
    fd: std::ffi::c_int,
    c_mac: *mut u8,
    features: u32,
    flags: u32,
) -> i32;

fn get_krun_add_net_unixstream() -> KrunAddNetUnixstreamFn {
    let symbol = CString::new("krun_add_net_unixstream").unwrap();
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    assert!(!ptr.is_null(), "krun_add_net_unixstream not found");
    unsafe { std::mem::transmute(ptr) }
}

pub(crate) fn passt_available() -> bool {
    Command::new("which")
        .arg("passt")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn start_passt() -> std::io::Result<RawFd> {
    use std::os::unix::process::CommandExt;

    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (parent_fd, child_fd) = (fds[0], fds[1]);

    let mut cmd = Command::new("passt");
    cmd.args(["-f", "--fd", &child_fd.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null());

    // Safety: clear CLOEXEC on child_fd so passt inherits it, and close the
    // parent end we don't need in the child.
    unsafe {
        cmd.pre_exec(move || {
            // Clear CLOEXEC so the child inherits this fd
            let flags = libc::fcntl(child_fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(child_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(parent_fd);
            Ok(())
        });
    }

    match cmd.spawn() {
        Ok(_child) => {
            unsafe { libc::close(child_fd) };
            Ok(parent_fd)
        }
        Err(e) => {
            unsafe {
                libc::close(child_fd);
                libc::close(parent_fd);
            }
            Err(e)
        }
    }
}

pub(crate) struct Passt;

impl NetBackend for Passt {
    fn should_run(&self) -> ShouldRun {
        if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_NET.into())) }.ok() != Some(1) {
            return ShouldRun::No("libkrun compiled without NET");
        }
        if cfg!(target_os = "macos") {
            return ShouldRun::No("passt not supported on macOS");
        }
        if !passt_available() {
            return ShouldRun::No("passt not installed");
        }
        ShouldRun::Yes
    }

    fn setup_backend(&self, ctx: u32, _test_setup: &TestSetup) -> anyhow::Result<()> {
        let passt_fd = start_passt()?;
        let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

        unsafe {
            krun_call!(get_krun_add_net_unixstream()(
                ctx,
                std::ptr::null(),
                passt_fd,
                mac.as_mut_ptr(),
                COMPAT_NET_FEATURES,
                NET_FLAG_DHCP_CLIENT,
            ))?;
        }
        Ok(())
    }
}
