//! Common utilities used by multiple tests.

use std::fs::{self, create_dir};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;

use anyhow::Context;

use crate::TestSetup;
use krun_init_blob_via_cdylib as krun_init;
use krun_via_cdylib_weak as krun;

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

use std::sync::OnceLock;

use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_NOW};

static LIBKRUN: OnceLock<Library> = OnceLock::new();

/// Load libkrun into the global namespace and initialize logging.
pub fn init_krun() -> anyhow::Result<()> {
    LIBKRUN.get_or_init(|| {
        unsafe { Library::open(Some("libkrun.so"), RTLD_NOW | RTLD_GLOBAL) }
            .expect("failed to dlopen libkrun.so")
    });

    krun::require(None, &[krun::Symbol::KrunInitLog]).context("failed to load krun_init_log")?;
    krun::init_log(
        krun::LogTarget::Default,
        krun::LogLevel::Trace,
        krun::LogStyle::Auto,
    )
    .map_err(|e| anyhow::anyhow!("init_log: {e:?}"))?;
    Ok(())
}

pub fn setup_and_run_with_env(
    num_cpus: u8,
    ram_mib: u32,
    test_setup: TestSetup,
    guest_env: &[&str],
) -> anyhow::Result<()> {
    init_krun()?;

    use krun::Symbol::*;
    krun::require(
        None,
        &[
            KrunFsDeviceNew,
            KrunFsDeviceDestroy,
            KrunFsDeviceSetOverlay,
            KrunFsOverlayNew,
            KrunFsOverlayDestroy,
            KrunFsOverlayAddFile,
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
            KrunErrorPayload,
            KrunErrorDestroy,
        ],
    )
    .context("failed to load libkrun symbols")?;

    let root_dir = setup_rootfs(&test_setup)?;

    let init_config = build_init_config(&test_setup.test_case, guest_env);

    let mut rootfs = krun::FsDevice::new("/dev/root", root_dir.to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;

    let mut payload =
        krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("Payload::load_krunfw: {e:?}"))?;

    let mut overlay = krun::FsOverlay::new();
    init_config
        .apply(ptr::null_mut(), &mut overlay, &mut payload)
        .map_err(|e| anyhow::anyhow!("Config::apply: {e}"))?;
    rootfs.set_overlay(overlay);

    let mut console_builder = krun::ConsoleDevice::builder();
    console_builder
        .add_default_console(
            io::stdin().as_raw_fd(),
            io::stdout().as_raw_fd(),
            io::stderr().as_raw_fd(),
        )
        .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
    let console = console_builder
        .build()
        .map_err(|e| anyhow::anyhow!("ConsoleDevice::build: {e:?}"))?;

    let mut devices = krun::MmioDeviceManager::new();
    devices.add(rootfs);
    devices.add(console);
    // TODO: devices.add(krun::BalloonDevice::new()?);
    // TODO: devices.add(krun::RngDevice::new()?);

    let mut vmm = krun::VmmBuilder::new()
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
