//! Common utilities used by multiple tests.

use anyhow::Context;
use std::ffi::CString;
use std::fs;
use std::fs::create_dir;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::{TestSetup, krun_call, krun_init};
use krun_sys::*;

fn copy_guest_agent(dir: &Path) -> anyhow::Result<()> {
    let path = std::env::var_os("KRUN_TEST_GUEST_AGENT_PATH")
        .context("KRUN_TEST_GUEST_AGENT_PATH env variable not set")?;

    let output_path = dir.join("guest-agent");
    fs::copy(path, output_path).context("Failed to copy executable into vm")?;
    Ok(())
}

/// Creates the root filesystem directory and copies the guest agent into it.
/// Returns the path to the root directory. Use this when you need to configure the root
/// filesystem yourself (e.g. via `krun_add_virtiofs3` for read-only mounts) rather than
/// using the default `setup_fs_and_enter`.
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

/// Sets up the root filesystem, copies the guest agent into it, and enters the VM.
pub fn setup_fs_and_enter(ctx: u32, test_setup: TestSetup) -> anyhow::Result<()> {
    setup_fs_and_enter_with_env(ctx, test_setup, &[])
}

pub fn setup_fs_and_enter_with_env(
    ctx: u32,
    test_setup: TestSetup,
    guest_env: &[&str],
) -> anyhow::Result<()> {
    let root_dir = setup_rootfs(&test_setup)?;
    let path_str = CString::new(root_dir.as_os_str().as_bytes()).context("CString::new")?;

    let init_config = build_init_config(&test_setup.test_case, guest_env);

    unsafe {
        krun_call!(krun_add_virtiofs3(
            ctx,
            c"/dev/root".as_ptr(),
            path_str.as_ptr(),
            0,
            false,
        ))?;
    }
    init_config
        .apply(std::ptr::null_mut(), ctx, "/dev/root")
        .expect("apply init config");
    unsafe {
        krun_call!(krun_start_enter(ctx))?;
    }
    unreachable!()
}
