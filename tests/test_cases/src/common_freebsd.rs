/*
//! Host-side utilities for FreeBSD guest tests.

use anyhow::Context;
use nix::libc;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::test_net::get_krun_add_net_unixgram;
use crate::test_net::gvproxy::{Gvproxy, wait_for_socket};
use crate::{TestSetup, krun_call};
use krun_sys::*;

pub struct FreeBsdAssets {
    pub kernel_path: PathBuf,
    pub iso_path: PathBuf,
}

/// Read FreeBSD asset paths from environment variables.
/// Returns `None` if either variable is unset or the referenced files don't exist.
pub fn freebsd_assets() -> Option<FreeBsdAssets> {
    let kernel_path = PathBuf::from(std::env::var_os("KRUN_TEST_FREEBSD_KERNEL_PATH")?);
    let iso_path = PathBuf::from(std::env::var_os("KRUN_TEST_FREEBSD_ISO_PATH")?);
    if !kernel_path.exists() || !iso_path.exists() {
        return None;
    }
    Some(FreeBsdAssets {
        kernel_path,
        iso_path,
    })
}

/// Create a `KRUN_CONFIG`-labelled ISO inside the test's tmp directory and return its path.
///
/// `init-freebsd` identifies the config disk by its ISO volume label (`/dev/iso9660/KRUN_CONFIG`),
/// not by vtbd index, so the label is mandatory.
fn create_config_iso(test_case: &str, tmp_dir: &Path) -> anyhow::Result<PathBuf> {
    let staging = tmp_dir.join("krun_config");
    std::fs::create_dir(&staging).context("create krun_config staging dir")?;

    let json = format!(r#"{{"Cmd":["/guest-agent","{test_case}"]}}"#);
    std::fs::write(staging.join("krun_config.json"), json).context("write krun_config.json")?;

    let iso_path = tmp_dir.join("krun_config.iso");
    let status = Command::new("bsdtar")
        .args([
            "cf",
            iso_path.to_str().context("config iso path is not UTF-8")?,
            "--format=iso9660",
            "--options",
            "volume-id=KRUN_CONFIG",
            "-C",
            staging
                .to_str()
                .context("config staging dir is not UTF-8")?,
            "krun_config.json",
        ])
        .status()
        .context(
            "Failed to run bsdtar — on Linux install libarchive-tools; on macOS bsdtar is built-in",
        )?;

    if !status.success() {
        anyhow::bail!("bsdtar exited with {status}");
    }
    Ok(iso_path)
}

/// Normalize serial-console line endings for FreeBSD output assertions.
///
/// FreeBSD's serial console emits CRLF (`\r\n`); strip the `\r` so that
/// test `check()` overrides can compare against plain `\n`-terminated strings.
pub fn normalize_serial_output(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

/// Generate a random MAC address for virtio-net device.
fn random_mac_address() -> [u8; 6] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    hasher.write_u32(nanos);
    let hash = hasher.finish();

    [
        0x52, // Xen OUI
        0x54,
        0x00,
        ((hash >> 16) & 0xFF) as u8,
        ((hash >> 8) & 0xFF) as u8,
        (hash & 0xFF) as u8,
    ]
}

/// Start gvproxy and attach a virtio-net device for a FreeBSD guest.
///
/// Mirrors `crate::test_net::gvproxy::setup_backend` but with FreeBSD-specific knobs:
/// passes `--listen unix://...` so callers can drive the HTTP API
/// (e.g. `setup_gvproxy_port_forward`), disables gvproxy's default :22 forwarder, and
/// uses a random MAC + `NET_FLAG_VFKIT` only (guest IP is assigned statically).
///
/// Returns the net (HTTP-API) unix socket path so callers can call
/// `setup_gvproxy_port_forward` afterwards.
pub fn setup_gvproxy_backend(ctx: u32, test_setup: &TestSetup) -> anyhow::Result<String> {
    // Short relative names: macOS `sockaddr_un.sun_path` is 104 bytes (max 103 usable chars),
    // so deep tmp paths plus long socket names can overflow.
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let net_sock = tmp_dir.join("gvproxy-net.sock");
    let vfkit_sock = tmp_dir.join("gvproxy-vfkit.sock");
    let gvproxy_log = tmp_dir.join("gvproxy.log");

    let net_sock_str = net_sock
        .to_str()
        .context("gvproxy net-sock path is not valid UTF-8")?
        .to_string();
    let vfkit_sock_str = vfkit_sock
        .to_str()
        .context("gvproxy vfkit-sock path is not valid UTF-8")?;

    let child = Gvproxy::new(vfkit_sock_str, &gvproxy_log)
        .net_sock(&net_sock_str)
        .ssh_port(-1)
        .start()?;
    test_setup.register_cleanup_pid(child.id());

    anyhow::ensure!(
        wait_for_socket(&vfkit_sock, 5000),
        "gvproxy failed to create vfkit socket"
    );

    let vfkit_cstr = CString::new(vfkit_sock.as_os_str().as_bytes())
        .context("CString::new vfkit socket path")?;
    let mut mac = random_mac_address();

    unsafe {
        krun_call!(get_krun_add_net_unixgram()(
            ctx,
            vfkit_cstr.as_ptr(),
            -1,
            mac.as_mut_ptr(),
            COMPAT_NET_FEATURES,
            NET_FLAG_VFKIT,
        ))?;
    }

    Ok(net_sock_str)
}

/// Boot a FreeBSD guest with `init-freebsd` and enter it.
///
/// Parallel to [`crate::common::setup_fs_and_enter`] for Linux guests:
/// - boots from a pre-built rootfs ISO (`vtbd0`) containing `init-freebsd` + `guest-agent`
/// - passes the test-case name via a `KRUN_CONFIG` ISO (`vtbd1`)
/// - uses a serial console (required by FreeBSD; output reaches the runner via the stdout pipe)
pub fn setup_kernel_and_enter(
    ctx: u32,
    test_setup: TestSetup,
    assets: FreeBsdAssets,
) -> anyhow::Result<()> {
    let config_iso = create_config_iso(&test_setup.test_case, &test_setup.tmp_dir)?;

    unsafe { do_setup_and_enter(ctx, &assets.kernel_path, &assets.iso_path, &config_iso) }
}

/// Shared implementation for entering the guest. Handles serial pipe + krun calls.
/// Networking, when needed, is added separately by the caller (e.g. via
/// [`setup_gvproxy_backend`]) before this function is invoked.
unsafe fn do_setup_and_enter(
    ctx: u32,
    kernel_path: &Path,
    rootfs_path: &Path,
    config_iso: &Path,
) -> anyhow::Result<()> {
    unsafe {
        // Create a pipe for serial console input to avoid a kqueue busy-spin on macOS.
        // When the runner's check() calls wait_with_output(), it closes the subprocess's
        // stdin (fd 0). On macOS/kqueue a closed-write-end pipe fires EVFILT_READ
        // continuously, spinning the serial device at ~100% CPU.  Using a fresh pipe
        // whose write end stays open until _exit() is called prevents that.
        // libkrun takes ownership of the read fd via File::from_raw_fd(); we only
        // need to keep the write end alive, which _exit() will close for us.
        let mut pipe_fds: [libc::c_int; 2] = [-1, -1];
        if libc::pipe(pipe_fds.as_mut_ptr()) != 0 {
            anyhow::bail!(
                "Failed to create serial input pipe: {}",
                std::io::Error::last_os_error()
            );
        }
        let serial_read_fd = pipe_fds[0];

        // Build CStrings for krun API.
        let kernel_cstr =
            CString::new(kernel_path.as_os_str().as_bytes()).context("CString::new")?;
        let rootfs_cstr =
            CString::new(rootfs_path.as_os_str().as_bytes()).context("CString::new")?;
        let config_iso_cstr =
            CString::new(config_iso.as_os_str().as_bytes()).context("CString::new")?;

        // FreeBSD requires a serial console; virtio console is not supported.
        krun_call!(krun_add_serial_console_default(ctx, serial_read_fd, 1))?;

        // Kernel cmdline: mount vtbd0 as root via cd9660 and hand off to init-freebsd.
        #[cfg(target_arch = "x86_64")]
        let (kernel_format, cmdline_prefix, flags) = (KRUN_KERNEL_FORMAT_ELF, "", "boot_mute=YES");
        #[cfg(not(target_arch = "x86_64"))]
        let (kernel_format, cmdline_prefix, flags) = (KRUN_KERNEL_FORMAT_RAW, "FreeBSD:", "-mq");

        let cmdline = format!(
            "{cmdline_prefix}vfs.root.mountfrom=cd9660:/dev/vtbd0 {flags} init_path=/init-freebsd"
        );
        let cmdline_cstr = CString::new(cmdline).context("CString::new")?;

        krun_call!(krun_set_kernel(
            ctx,
            kernel_cstr.as_ptr(),
            kernel_format,
            std::ptr::null(),
            cmdline_cstr.as_ptr(),
        ))?;

        // vtbd0: rootfs ISO (init-freebsd + guest-agent)
        krun_call!(krun_add_disk(
            ctx,
            c"vtbd0".as_ptr(),
            rootfs_cstr.as_ptr(),
            true,
        ))?;

        // vtbd1: config ISO (init-freebsd finds it by KRUN_CONFIG volume label, not vtbd index)
        krun_call!(krun_add_disk(
            ctx,
            c"vtbd1".as_ptr(),
            config_iso_cstr.as_ptr(),
            true,
        ))?;

        krun_call!(krun_start_enter(ctx))?;
        unreachable!()
    }
}
*/
