//! Vhost-user-net backend using passt --vhost-user
//!
//! Instead of passt's fd-passing mode (socketpair + krun_add_net_unixstream),
//! this backend starts passt in vhost-user mode and connects via
//! krun_add_vhost_user_device with device_type=1 (VIRTIO_ID_NET).

use super::NetBackend;
use crate::test_net::passt::passt_available;
use crate::{ShouldRun, TestSetup, krun_call, krun_call_u32};
use krun_sys::*;
use std::ffi::CString;
use std::process::{Command, Stdio};

/// VIRTIO_ID_NET
const VIRTIO_DEVICE_NET: u32 = 1;

fn passt_supports_vhost_user() -> bool {
    Command::new("passt")
        .arg("--help")
        .output()
        .map(|o| {
            let help = String::from_utf8_lossy(&o.stdout);
            let help_err = String::from_utf8_lossy(&o.stderr);
            help.contains("--vhost-user") || help_err.contains("--vhost-user")
        })
        .unwrap_or(false)
}

/// Start passt in vhost-user mode, listening on a Unix domain socket.
///
/// Returns the socket path and passt's PID.
fn start_passt_vhost_user(test_setup: &TestSetup) -> std::io::Result<(String, u32)> {
    let socket_path = test_setup.tmp_dir.join("passt-vhost-user.sock");
    let socket_path_str = socket_path.to_str().unwrap().to_string();

    let child = Command::new("passt")
        .args(["-f", "--vhost-user", "-s", &socket_path_str])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id();

    // Wait for passt to create the socket
    for _ in 0..50 {
        if socket_path.exists() {
            return Ok((socket_path_str, pid));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "passt --vhost-user did not create socket at {} within 5s",
            socket_path_str
        ),
    ))
}

pub(crate) struct VhostUserPasst;

impl NetBackend for VhostUserPasst {
    fn should_run(&self) -> ShouldRun {
        if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_VHOST_USER.into())) }.ok()
            != Some(1)
        {
            return ShouldRun::No("libkrun compiled without vhost-user support");
        }
        if cfg!(target_os = "macos") {
            return ShouldRun::No("passt not supported on macOS");
        }
        if !passt_available() {
            return ShouldRun::No("passt not installed");
        }
        if !passt_supports_vhost_user() {
            return ShouldRun::No("passt does not support --vhost-user");
        }
        ShouldRun::Yes
    }

    fn setup_backend(&self, ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
        let (socket_path, passt_pid) = start_passt_vhost_user(test_setup)?;
        test_setup.register_cleanup_pid(passt_pid);

        let socket_path_c = CString::new(socket_path)?;
        let name_c = CString::new("vhost-user-net")?;
        let queue_sizes: [u16; 2] = [256, 256];

        unsafe {
            krun_call!(krun_add_vhost_user_device(
                ctx,
                VIRTIO_DEVICE_NET,
                socket_path_c.as_ptr(),
                name_c.as_ptr(),
                2,
                queue_sizes.as_ptr(),
            ))?;
        }
        Ok(())
    }

    fn guest_env(&self) -> &[&'static std::ffi::CStr] {
        // vhost-user-net bypasses the in-process net device, so init
        // doesn't get KRUN_DHCP=1 automatically — pass it explicitly.
        &[c"KRUN_DHCP=1"]
    }
}
