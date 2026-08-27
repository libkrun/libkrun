//! Passt backend for virtio-net test

use crate::{ShouldRun, TestSetup};
use nix::libc;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};

fn passt_available() -> bool {
    Command::new("which")
        .arg("passt")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn start_passt() -> std::io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
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
            Ok(unsafe { OwnedFd::from_raw_fd(parent_fd) })
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

pub(crate) fn should_run() -> ShouldRun {
    if cfg!(target_os = "macos") {
        return ShouldRun::No("passt not supported on macOS");
    }
    if !passt_available() {
        return ShouldRun::No("passt not installed");
    }
    ShouldRun::Yes
}

pub(crate) fn setup_backend(_test_setup: &TestSetup) -> anyhow::Result<krun::NetDevice> {
    let passt_fd = start_passt()?;
    let mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

    krun::NetDevice::new_unixstream_fd(
        "net0",
        passt_fd,
        &mac,
        crate::test_net::COMPAT_NET_FEATURES,
        krun::NetFlags::empty(),
    )
    .map_err(|e| anyhow::anyhow!("NetDevice: {e:?}"))
}
