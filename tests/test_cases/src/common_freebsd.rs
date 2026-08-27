//! Host-side utilities for FreeBSD guest tests.

use anyhow::Context;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::TestSetup;
use crate::test_net::gvproxy::{Gvproxy, wait_for_socket};

type ExtraDevicesFn = Box<dyn FnOnce(&mut krun::MmioDeviceManager<'static>) -> anyhow::Result<()>>;

#[cfg(feature = "dynamic-linking")]
pub fn require_freebsd_symbols() -> Result<(), libloading::Error> {
    crate::common::require_vm_symbols()?;
    krun::require(
        None,
        &[
            krun::Symbol::KrunPayloadLoadExternal,
            krun::Symbol::KrunBlockDeviceNew,
            krun::Symbol::KrunBlockDeviceDestroy,
            krun::Symbol::KrunVmmBuilderAddSerialConsole,
            krun::Symbol::KrunVmmBuilderSetKernelConsole,
        ],
    )
}
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
/// `setup_gvproxy_port_forward` afterwards, and the NetDevice to add to the
/// device manager.
pub fn setup_gvproxy_backend(test_setup: &TestSetup) -> anyhow::Result<(String, krun::NetDevice)> {
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

    let mac = random_mac_address();

    let net_device =
        krun::NetDevice::new_unixgram_path("net0", vfkit_sock_str, &mac, 0, krun::NetFlags::VFKIT)
            .map_err(|e| anyhow::anyhow!("NetDevice: {e:?}"))?;

    Ok((net_sock_str, net_device))
}

/// Boot a FreeBSD guest with `init-freebsd` and run the test.
///
/// Parallel to [`crate::common::setup_and_run`] for Linux guests:
/// - boots from a pre-built rootfs ISO (`vtbd0`) containing `init-freebsd` + `guest-agent`
/// - passes the test-case name via a `KRUN_CONFIG` ISO (`vtbd1`)
/// - uses a serial console (required by FreeBSD; output reaches the runner via the stdout pipe)
pub fn setup_kernel_and_enter(
    test_setup: TestSetup,
    assets: FreeBsdAssets,
    extra_devices: Option<ExtraDevicesFn>,
) -> anyhow::Result<()> {
    let config_iso = create_config_iso(&test_setup.test_case, &test_setup.tmp_dir)?;
    do_setup_and_enter(
        &assets.kernel_path,
        &assets.iso_path,
        &config_iso,
        extra_devices,
    )
}

/// Shared implementation for entering the guest. Handles serial pipe + v2 API calls.
fn do_setup_and_enter(
    kernel_path: &Path,
    rootfs_path: &Path,
    config_iso: &Path,
    extra_devices: Option<ExtraDevicesFn>,
) -> anyhow::Result<()> {
    // Create a pipe for serial console input to avoid a kqueue busy-spin on macOS.
    // When the runner's check() calls wait_with_output(), it closes the subprocess's
    // stdin (fd 0). On macOS/kqueue a closed-write-end pipe fires EVFILT_READ
    // continuously, spinning the serial device at ~100% CPU.  Using a fresh pipe
    // whose write end stays open until _exit() is called prevents that.
    let mut pipe_fds: [nix::libc::c_int; 2] = [-1, -1];
    if unsafe { nix::libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!(
            "Failed to create serial input pipe: {}",
            std::io::Error::last_os_error()
        );
    }
    let serial_read_fd = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };

    // Kernel cmdline and format depend on architecture.
    #[cfg(target_arch = "x86_64")]
    let (kernel_format, cmdline) = (
        krun::KernelFormat::Elf,
        "vfs.root.mountfrom=cd9660:/dev/vtbd0 boot_mute=YES init_path=/init-freebsd".to_string(),
    );
    #[cfg(not(target_arch = "x86_64"))]
    let (kernel_format, cmdline) = (
        krun::KernelFormat::Raw,
        "FreeBSD:vfs.root.mountfrom=cd9660:/dev/vtbd0 -mq init_path=/init-freebsd".to_string(),
    );

    let payload = krun::Payload::load_external(
        kernel_path.to_str().context("kernel path not UTF-8")?,
        kernel_format,
        None,
        &cmdline,
    )
    .map_err(|e| anyhow::anyhow!("Payload::load_external: {e:?}"))?;

    let mut console_builder = krun::ConsoleDevice::builder();
    // Use stdout so the runner captures serial output via stdout pipe.
    console_builder
        .add_default_console(
            None,
            Some(
                std::io::stdout()
                    .as_fd()
                    .try_clone_to_owned()
                    .expect("dup stdout"),
            ),
            None,
        )
        .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
    let console = console_builder
        .build()
        .map_err(|e| anyhow::anyhow!("ConsoleDevice::build: {e:?}"))?;

    // vtbd0: rootfs ISO (init-freebsd + guest-agent)
    let mut rootfs_block = krun::BlockDevice::new(
        "vtbd0",
        rootfs_path.to_str().context("rootfs path not UTF-8")?,
        krun::DiskFormat::Raw,
    )
    .map_err(|e| anyhow::anyhow!("BlockDevice vtbd0: {e:?}"))?;
    rootfs_block.set_read_only(true);

    // vtbd1: config ISO (init-freebsd finds it by KRUN_CONFIG volume label)
    let mut config_block = krun::BlockDevice::new(
        "vtbd1",
        config_iso.to_str().context("config iso path not UTF-8")?,
        krun::DiskFormat::Raw,
    )
    .map_err(|e| anyhow::anyhow!("BlockDevice vtbd1: {e:?}"))?;
    config_block.set_read_only(true);

    let mut devices = krun::MmioDeviceManager::new();
    devices.add(console);
    devices.add(rootfs_block);
    devices.add(config_block);

    if let Some(add_extra) = extra_devices {
        add_extra(&mut devices)?;
    }

    let vmm = krun::VmmBuilder::new()
        .vcpus(1)
        .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
        .ram_mib(512)
        .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
        .add_serial_console(
            Some(serial_read_fd),
            Some(
                std::io::stdout()
                    .as_fd()
                    .try_clone_to_owned()
                    .expect("dup stdout"),
            ),
        )
        .payload(payload)
        .devices(devices)
        .build()
        .map_err(|e| anyhow::anyhow!("VmmBuilder::build: {e:?}"))?;

    vmm.run();
    unreachable!()
}
