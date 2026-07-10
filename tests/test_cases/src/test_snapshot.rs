//! Boot a microVM, trigger an out-of-band snapshot, and verify the on-disk
//! artifacts. macOS/HVF only (the snapshot backend is HVF for now).

use macros::{guest, host};

// Only the host side configures the VM, so the guest build never reads this.
#[cfg_attr(not(feature = "host"), allow(dead_code))]
pub struct TestSnapshot {
    pub(crate) ram_mib: u32,
}

#[host]
mod host {
    use super::*;

    use crate::common::setup_rootfs;
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::ffi::{CString, c_char};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::ptr::null;
    use std::time::Duration;

    impl Test for TestSnapshot {
        fn should_run(&self) -> ShouldRun {
            if cfg!(target_os = "macos") {
                ShouldRun::Yes
            } else {
                ShouldRun::No("snapshot is macOS/HVF only")
            }
        }

        fn timeout_secs(&self) -> u64 {
            30
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = setup_rootfs(&test_setup)?;
            let root_cstr = CString::new(root_dir.as_os_str().as_bytes())?;
            let snapshot_dir = test_setup.tmp_dir.join("snapshot");
            let snapshot_cstr = CString::new(snapshot_dir.as_os_str().as_bytes())?;
            // The guest agent dispatches on the test-case name passed as argv[0].
            let test_case_cstr = CString::new(test_setup.test_case.clone())?;

            unsafe {
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, self.ram_mib))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
                krun_call!(krun_add_virtiofs3(
                    ctx,
                    c"/dev/root".as_ptr(),
                    root_cstr.as_ptr(),
                    0,
                    false,
                ))?;
                krun_call!(krun_set_workdir(ctx, c"/".as_ptr()))?;
                let argv: [*const c_char; 2] = [test_case_cstr.as_ptr(), null()];
                let envp: [*const c_char; 1] = [null()];
                krun_call!(krun_set_exec(
                    ctx,
                    c"/guest-agent".as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                ))?;

                // The ctx registers its control channel only once the VM's event
                // loop is running, so retry past the initial -ENOENT.
                std::thread::spawn(move || {
                    loop {
                        let rc =
                            krun_snapshot_request(ctx, snapshot_cstr.as_ptr(), KRUN_SNAPSHOT_EXIT);
                        if rc == 0 {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                });

                // Blocks; captures on the trigger above, then exits the process.
                let rc = krun_start_enter(ctx);
                anyhow::bail!("krun_start_enter returned unexpectedly: {rc}");
            }
        }

        fn check(self: Box<Self>, _stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            let dir = test_setup.tmp_dir.join("snapshot");
            for name in ["manifest.json", "vmstate", "memory.img"] {
                if !dir.join(name).exists() {
                    return TestOutcome::Fail(format!("missing snapshot file: {name}"));
                }
            }
            let mem_len = std::fs::metadata(dir.join("memory.img")).unwrap().len();
            if mem_len == 0 {
                return TestOutcome::Fail("memory.img is empty".into());
            }
            let manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
            if !manifest.contains("\"backend\": \"hvf\"")
                || !manifest.contains("\"arch\": \"aarch64\"")
            {
                return TestOutcome::Fail(format!("unexpected manifest: {manifest}"));
            }
            TestOutcome::Pass
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    impl Test for TestSnapshot {
        fn in_guest(self: Box<Self>) {
            // Stay alive long enough to be captured; the host snapshots and
            // exits the process well before this returns.
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}
