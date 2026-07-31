//! vmnet-helper backend for virtio-net test (macOS only)

use super::NetBackend;
use crate::test_net::get_krun_add_net_unixgram;
use crate::{ShouldRun, TestSetup, krun_call, krun_call_u32};
use krun_sys::{
    KRUN_FEATURE_NET, NET_FEATURE_CSUM, NET_FEATURE_GUEST_CSUM, NET_FEATURE_GUEST_TSO4,
    NET_FEATURE_HOST_TSO4, NET_FLAG_DHCP_CLIENT, krun_has_feature,
};
use nix::libc;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};

const VMNET_HELPER_PATH: &str = match option_env!("VMNET_HELPER_PATH") {
    Some(path) => path,
    None => "/opt/homebrew/opt/vmnet-helper/libexec/vmnet-helper",
};

fn vmnet_helper_path() -> Option<&'static str> {
    std::path::Path::new(VMNET_HELPER_PATH)
        .exists()
        .then_some(VMNET_HELPER_PATH)
}

/// Parse a MAC address string like "1e:d4:d1:27:4b:bf" into 6 bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

struct VmnetConfig {
    fd: i32,
    mac: [u8; 6],
    pid: u32,
}

/// Start vmnet-helper with `--fd 3`, wait for its JSON config on stdout,
/// and return the fd + MAC address from vmnet.
///
/// Creates a `SOCK_DGRAM` socketpair, passes one end to vmnet-helper as fd 3
/// (matching what `vmnet-client` does), and returns the other end for use
/// with `krun_add_net_unixgram`.
fn start_vmnet_helper(log_path: &std::path::Path) -> std::io::Result<VmnetConfig> {
    let helper = vmnet_helper_path().expect("vmnet-helper not found");

    // Create a SOCK_DGRAM socketpair
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (our_fd, helper_fd) = (fds[0], fds[1]);

    // On macOS SOCK_DGRAM, SO_SNDBUF determines the maximum frame size (not
    // buffering). Must be >= 65550 for TSO frames.
    // TODO: SO_RCVBUF at 65550 causes "network unreachable" — DHCP issue?
    const SNDBUF_SIZE: libc::c_int = 65550;
    const RCVBUF_SIZE: libc::c_int = 1024 * 1024;
    for fd in [our_fd, helper_fd] {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &SNDBUF_SIZE as *const _ as *const libc::c_void,
                std::mem::size_of_val(&SNDBUF_SIZE) as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &RCVBUF_SIZE as *const _ as *const libc::c_void,
                std::mem::size_of_val(&RCVBUF_SIZE) as libc::socklen_t,
            );
        }
    }

    let log_file = std::fs::File::create(log_path)?;

    let mut child = Command::new(helper)
        .arg("--fd")
        .arg(helper_fd.to_string())
        .arg("--enable-tso")
        .arg("--enable-checksum-offload")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(log_file)
        .spawn()?;

    // Parent: close helper's end of the socketpair
    unsafe { libc::close(helper_fd) };

    // Read the JSON config line from vmnet-helper's stdout.
    // vmnet-helper writes a single JSON line then keeps running.
    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);
    let mut config_line = String::new();
    reader
        .take(4096)
        .read_line(&mut config_line)
        .map_err(|e| std::io::Error::other(format!("failed to read vmnet-helper config: {e}")))?;

    if config_line.is_empty() {
        return Err(std::io::Error::other(
            "vmnet-helper exited without producing config",
        ));
    }

    eprintln!("vmnet-helper config: {}", config_line.trim());

    // Parse the MAC address from the JSON config.
    let config: serde_json::Value = serde_json::from_str(&config_line)
        .map_err(|e| std::io::Error::other(format!("failed to parse vmnet-helper config: {e}")))?;
    let mac_str = config["vmnet_mac_address"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("vmnet_mac_address not found in config"))?;

    let mac = parse_mac(mac_str)
        .ok_or_else(|| std::io::Error::other(format!("invalid MAC address: {mac_str}")))?;

    Ok(VmnetConfig {
        fd: our_fd,
        mac,
        pid: child.id(),
    })
}

pub(crate) struct VmnetHelper;

impl NetBackend for VmnetHelper {
    fn should_run(&self) -> ShouldRun {
        if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_NET.into())) }.ok() != Some(1) {
            return ShouldRun::No("libkrun compiled without NET");
        }
        #[cfg(not(target_os = "macos"))]
        return ShouldRun::No("vmnet-helper only supported on macOS");

        #[cfg(target_os = "macos")]
        {
            if vmnet_helper_path().is_none() {
                return ShouldRun::No("vmnet-helper not installed");
            }
            ShouldRun::Yes
        }
    }

    fn setup_backend(&self, ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
        let tmp_dir = test_setup
            .tmp_dir
            .canonicalize()
            .unwrap_or_else(|_| test_setup.tmp_dir.clone());
        let vmnet_log = tmp_dir.join("vmnet-helper.log");

        let mut config = start_vmnet_helper(&vmnet_log)?;
        test_setup.register_cleanup_pid(config.pid);

        unsafe {
            krun_call!(get_krun_add_net_unixgram()(
                ctx,
                std::ptr::null(),
                config.fd,
                config.mac.as_mut_ptr(),
                NET_FEATURE_CSUM
                    | NET_FEATURE_GUEST_CSUM
                    | NET_FEATURE_GUEST_TSO4
                    | NET_FEATURE_HOST_TSO4,
                NET_FLAG_DHCP_CLIENT,
            ))?;
        }
        Ok(())
    }
}
