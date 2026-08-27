//! Common utilities used by multiple tests.

use std::fs::{self, create_dir};
use std::io;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::TestSetup;

fn copy_guest_agent(dir: &Path) -> anyhow::Result<()> {
    let path = std::env::var_os("KRUN_TEST_GUEST_AGENT_PATH")
        .context("KRUN_TEST_GUEST_AGENT_PATH env variable not set")?;

    let output_path = dir.join("guest-agent");
    fs::copy(path, output_path).context("Failed to copy executable into vm")?;
    Ok(())
}

/// Creates the root filesystem directory and copies the guest agent into it.
pub fn setup_rootfs(test_setup: &TestSetup) -> anyhow::Result<PathBuf> {
    let root_dir = test_setup.tmp_dir.join("rootfs");
    if !root_dir.exists() {
        create_dir(&root_dir).context("Failed to create rootfs directory")?;
    }
    copy_guest_agent(&root_dir)?;
    Ok(root_dir)
}

/// Build an init config for running the guest-agent with the given test case.
pub fn build_init_config(test_case: &str, guest_env: &[&str]) -> krun_init::Config {
    krun_init::Config::builder()
        .args(&["/guest-agent", test_case])
        .workdir("/")
        .env(guest_env)
        .build()
}

/// Sets up the root filesystem, builds a VM, and enters it.
pub fn setup_and_run(num_cpus: u8, ram_mib: u32, test_setup: TestSetup) -> anyhow::Result<()> {
    setup_and_run_with_env(num_cpus, ram_mib, test_setup, &[])
}

#[cfg(feature = "dynamic-linking")]
use std::sync::OnceLock;

#[cfg(feature = "dynamic-linking")]
use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_NOW};

#[cfg(feature = "dynamic-linking")]
static LIBKRUN: OnceLock<Library> = OnceLock::new();

/// Load libkrun (dlopen in ffi mode) and initialize logging.
pub fn init_krun() -> anyhow::Result<()> {
    #[cfg(feature = "dynamic-linking")]
    LIBKRUN.get_or_init(|| {
        let name = if cfg!(target_os = "macos") {
            "libkrun.dylib"
        } else {
            "libkrun.so"
        };
        unsafe { Library::open(Some(name), RTLD_NOW | RTLD_GLOBAL) }
            .expect("failed to dlopen libkrun")
    });

    #[cfg(feature = "dynamic-linking")]
    require_vm_symbols().context("failed to load core VM symbols")?;

    krun::init_log(
        None,
        krun::LogLevel::Trace,
        krun::LogStyle::Auto,
        krun::LogOptions::empty(),
    )
    .map_err(|e| anyhow::anyhow!("init_log: {e:?}"))?;
    Ok(())
}

/// Load core VM symbols. Safe to call multiple times.
/// In static mode this is a no-op (if it compiles, symbols are available).
#[cfg(feature = "dynamic-linking")]
pub fn require_vm_symbols() -> Result<(), libloading::Error> {
    LIBKRUN.get_or_init(|| {
        let name = if cfg!(target_os = "macos") {
            "libkrun.dylib"
        } else {
            "libkrun.so"
        };
        unsafe { Library::open(Some(name), RTLD_NOW | RTLD_GLOBAL) }
            .expect("failed to dlopen libkrun")
    });
    use krun::Symbol::*;
    krun::require(
        None,
        &[
            KrunInitLog,
            KrunFsDeviceNew,
            KrunFsDeviceNewReadOnly,
            KrunFsDeviceNewNull,
            KrunFsDeviceDestroy,
            KrunFsDeviceSetOverlay,
            KrunFsOverlayNew,
            KrunFsOverlayDestroy,
            KrunFsOverlayAddFile,
            KrunFsOverlayAddDir,
            KrunPayloadLoadKrunfw,
            KrunPayloadDestroy,
            KrunPayloadAppendCmdline,
            KrunConsoleDeviceBuilder,
            KrunConsoleDeviceDestroy,
            KrunConsoleBuilderDestroy,
            KrunConsoleBuilderAddDefaultConsole,
            KrunConsoleBuilderBuild,
            KrunMmioDeviceManagerNew,
            KrunMmioDeviceManagerDestroy,
            KrunMmioDeviceManagerAdd,
            KrunVmmBuilderNew,
            KrunVmmBuilderDestroy,
            KrunVmmBuilderVcpus,
            KrunVmmBuilderRamMib,
            KrunVmmBuilderPayload,
            KrunVmmBuilderDevices,
            KrunVmmBuilderBuild,
            KrunVmmDestroy,
            KrunVmmRun,
            KrunBalloonDeviceNew,
            KrunBalloonDeviceDestroy,
            KrunRngDeviceNew,
            KrunRngDeviceDestroy,
            KrunErrorPayload,
            KrunErrorDestroy,
        ],
    )
}

pub fn setup_and_run_with_env(
    num_cpus: u8,
    ram_mib: u32,
    test_setup: TestSetup,
    guest_env: &[&str],
) -> anyhow::Result<()> {
    init_krun()?;
    let (devices, payload) = setup_standard_devices(&test_setup, guest_env)?;

    let vmm = krun::VmmBuilder::new()
        .vcpus(num_cpus)
        .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
        .ram_mib(ram_mib)
        .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
        .payload(payload)
        .devices(devices)
        .build()
        .map_err(|e| anyhow::anyhow!("VmmBuilder::build: {e:?}"))?;

    vmm.run();
    unreachable!()
}

/// Set up the standard test VM: rootfs + init config + console + balloon + rng.
/// Returns a device manager and payload ready for the test to add extra devices
/// (vsock, block, net, etc.) before passing to `build_and_run()`.
/// Create a base init config builder for the given test case.
pub fn init_config_builder(test_setup: &TestSetup, guest_env: &[&str]) -> krun_init::Builder {
    krun_init::Config::builder()
        .args(&["/guest-agent", &test_setup.test_case])
        .workdir("/")
        .env(guest_env)
}

pub fn setup_standard_devices(
    test_setup: &TestSetup,
    guest_env: &[&str],
) -> anyhow::Result<(krun::MmioDeviceManager<'static>, krun::Payload)> {
    setup_standard_devices_from(test_setup, init_config_builder(test_setup, guest_env))
}

/// Build standard devices from a pre-configured init config builder.
/// Caller can customize the builder (e.g. `.dhcp(true)`) before passing it.
pub fn setup_standard_devices_from(
    test_setup: &TestSetup,
    builder: krun_init::Builder,
) -> anyhow::Result<(krun::MmioDeviceManager<'static>, krun::Payload)> {
    let root_dir = setup_rootfs(test_setup)?;
    let init_config = builder.build();

    let mut rootfs = krun::FsDevice::new("/dev/root", root_dir.to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
    let mut payload =
        krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("load_krunfw: {e:?}"))?;
    let mut overlay = krun::FsOverlay::new();
    init_config
        .apply(&mut overlay, &mut payload)
        .map_err(|e| anyhow::anyhow!("Config::apply: {e}"))?;
    rootfs.set_overlay(overlay);

    let mut console_builder = krun::ConsoleDevice::builder();
    console_builder
        .add_default_console(
            Some(io::stdin().as_fd().try_clone_to_owned().expect("dup stdin")),
            Some(
                io::stdout()
                    .as_fd()
                    .try_clone_to_owned()
                    .expect("dup stdout"),
            ),
            Some(
                io::stderr()
                    .as_fd()
                    .try_clone_to_owned()
                    .expect("dup stderr"),
            ),
        )
        .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
    let console = console_builder
        .build()
        .map_err(|e| anyhow::anyhow!("ConsoleDevice::build: {e:?}"))?;

    let mut devices = krun::MmioDeviceManager::new();
    devices.add(rootfs);
    devices.add(console);
    devices.add(krun::BalloonDevice::new().map_err(|e| anyhow::anyhow!("BalloonDevice: {e:?}"))?);
    devices.add(krun::RngDevice::new().map_err(|e| anyhow::anyhow!("RngDevice: {e:?}"))?);

    Ok((devices, payload))
}

/// Build a VM with the given rootfs device and payload, add a default console,
/// and run it. Does not return.
pub fn build_and_run(
    num_cpus: u8,
    ram_mib: u32,
    rootfs: krun::FsDevice<'static>,
    payload: krun::Payload,
) -> anyhow::Result<()> {
    let mut console_builder = krun::ConsoleDevice::builder();
    console_builder
        .add_default_console(
            Some(io::stdin().as_fd().try_clone_to_owned().expect("dup stdin")),
            Some(
                io::stdout()
                    .as_fd()
                    .try_clone_to_owned()
                    .expect("dup stdout"),
            ),
            Some(
                io::stderr()
                    .as_fd()
                    .try_clone_to_owned()
                    .expect("dup stderr"),
            ),
        )
        .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
    let console = console_builder
        .build()
        .map_err(|e| anyhow::anyhow!("ConsoleDevice::build: {e:?}"))?;

    let mut devices = krun::MmioDeviceManager::new();
    devices.add(rootfs);
    devices.add(console);
    devices.add(krun::BalloonDevice::new().map_err(|e| anyhow::anyhow!("BalloonDevice: {e:?}"))?);
    devices.add(krun::RngDevice::new().map_err(|e| anyhow::anyhow!("RngDevice: {e:?}"))?);

    let vmm = krun::VmmBuilder::new()
        .vcpus(num_cpus)
        .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
        .ram_mib(ram_mib)
        .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
        .payload(payload)
        .devices(devices)
        .build()
        .map_err(|e| anyhow::anyhow!("VmmBuilder::build: {e:?}"))?;

    vmm.run();
    unreachable!()
}
