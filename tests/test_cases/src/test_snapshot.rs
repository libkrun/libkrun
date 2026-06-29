//! Snapshot/restore tests. macOS/HVF only (the snapshot backend is HVF for now).
//!
//! - `snapshot-create` boots a microVM, triggers an out-of-band snapshot, and
//!   verifies the on-disk artifacts.
//! - `snapshot-resume` creates a snapshot in a child process, then restores it
//!   onto a fresh, identically-shaped VM and checks the resumed guest keeps
//!   running: it resumes mid heartbeat-loop, so its stdout carries the tail of
//!   the loop but never restarts at `HEARTBEAT 0` the way a fresh boot would.

use macros::{guest, host};

// Only the host side configures the VM, so the guest build never reads this.
#[cfg_attr(not(feature = "host"), allow(dead_code))]
pub struct TestSnapshot {
    pub(crate) ram_mib: u32,
}

#[cfg_attr(not(feature = "host"), allow(dead_code))]
pub struct TestSnapshotResume {
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
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::ptr::null;
    use std::time::Duration;

    /// Configure a 1-vCPU VM with a virtio-console (wired to the process stdio)
    /// and a virtiofs root, running the guest agent for `test_case`. Shared by
    /// the capture and restore paths so the restored config matches the
    /// snapshot's manifest (arch/mem/vcpu).
    unsafe fn configure_vm(
        ctx: u32,
        ram_mib: u32,
        root: &Path,
        test_case: &str,
    ) -> anyhow::Result<()> {
        let root_cstr = CString::new(root.as_os_str().as_bytes())?;
        let test_case_cstr = CString::new(test_case.to_owned())?;
        unsafe {
            krun_call!(krun_set_vm_config(ctx, 1, ram_mib))?;
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
        }
        Ok(())
    }

    /// Capture a snapshot to `snapshot_dir`: configure the VM, start a thread
    /// that retries the out-of-band trigger past the initial -ENOENT, then enter
    /// the guest. The trigger captures and exits the process.
    unsafe fn capture(
        ctx: u32,
        ram_mib: u32,
        root: &Path,
        test_case: &str,
        snapshot_dir: &Path,
    ) -> anyhow::Result<()> {
        let snapshot_cstr = CString::new(snapshot_dir.as_os_str().as_bytes())?;
        unsafe {
            configure_vm(ctx, ram_mib, root, test_case)?;
            std::thread::spawn(move || {
                // Let the guest finish booting and reach steady state (agent
                // running, console ports open) before capturing — snapshotting
                // mid-boot leaves device state that can't be cleanly restored.
                std::thread::sleep(Duration::from_secs(5));
                loop {
                    let rc = krun_snapshot_request(ctx, snapshot_cstr.as_ptr(), KRUN_SNAPSHOT_EXIT);
                    if rc == 0 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
            let rc = krun_start_enter(ctx);
            anyhow::bail!("krun_start_enter returned unexpectedly: {rc}");
        }
    }

    fn check_snapshot_dir(dir: &Path) -> TestOutcome {
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
        if !manifest.contains("\"backend\": \"hvf\"") || !manifest.contains("\"arch\": \"aarch64\"")
        {
            return TestOutcome::Fail(format!("unexpected manifest: {manifest}"));
        }
        TestOutcome::Pass
    }

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
            let snapshot_dir = test_setup.tmp_dir.join("snapshot");
            let ctx = unsafe { krun_call_u32!(krun_create_ctx())? };
            unsafe {
                capture(
                    ctx,
                    self.ram_mib,
                    &root_dir,
                    &test_setup.test_case,
                    &snapshot_dir,
                )
            }
        }

        fn check(self: Box<Self>, _stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            check_snapshot_dir(&test_setup.tmp_dir.join("snapshot"))
        }
    }

    impl Test for TestSnapshotResume {
        fn should_run(&self) -> ShouldRun {
            if cfg!(target_os = "macos") {
                ShouldRun::Yes
            } else {
                ShouldRun::No("snapshot is macOS/HVF only")
            }
        }

        fn timeout_secs(&self) -> u64 {
            90
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = setup_rootfs(&test_setup)?;
            let snapshot_dir = test_setup.tmp_dir.join("snapshot");

            // A child process (re-exec of this binary with the same test case)
            // captures the snapshot first; HVF allows one VM per process, so the
            // child fully exits before we build the restore VM here. Its guest
            // console goes to a separate file so the stdout the runner captures
            // is exactly the restored guest's output.
            if std::env::var_os("KRUN_TEST_SNAPSHOT_CREATE").is_some() {
                let ctx = unsafe { krun_call_u32!(krun_create_ctx())? };
                return unsafe {
                    capture(
                        ctx,
                        self.ram_mib,
                        &root_dir,
                        &test_setup.test_case,
                        &snapshot_dir,
                    )
                };
            }

            let child_stdout = std::fs::File::create(test_setup.tmp_dir.join("create_stdout.txt"))?;
            let status = Command::new(std::env::current_exe()?)
                .arg("start-vm")
                .arg("--test-case")
                .arg(&test_setup.test_case)
                .arg("--tmp-dir")
                .arg(&test_setup.tmp_dir)
                .env("KRUN_TEST_SNAPSHOT_CREATE", "1")
                .stdin(Stdio::null())
                .stdout(child_stdout)
                .stderr(Stdio::inherit())
                .status()?;
            if !snapshot_dir.join("vmstate").exists() {
                anyhow::bail!("child did not create a snapshot (exit {status:?})");
            }

            // Restore onto a fresh, identically-shaped VM and run it. The guest
            // resumes mid heartbeat-loop, prints the rest to stdout (which the
            // runner captures for check()), runs to completion, and powers off —
            // krun_restore returns like krun_start_enter.
            let ctx = unsafe { krun_call_u32!(krun_create_ctx())? };
            unsafe { configure_vm(ctx, self.ram_mib, &root_dir, &test_setup.test_case)? };
            let snapshot_cstr = CString::new(snapshot_dir.as_os_str().as_bytes())?;
            let rc = unsafe { krun_restore(ctx, snapshot_cstr.as_ptr(), 0) };
            if rc < 0 {
                anyhow::bail!("krun_restore failed: {rc}");
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let out = String::from_utf8_lossy(&stdout);
            if !out.contains("HEARTBEAT") {
                return TestOutcome::Fail(format!(
                    "restored guest produced no heartbeat; stdout: {out:?}"
                ));
            }
            // A real resume picks up mid-loop; a regression that reboots the guest
            // fresh would re-run the loop from the start and print "HEARTBEAT 0".
            if out.lines().any(|l| l.trim() == "HEARTBEAT 0") {
                return TestOutcome::Fail(format!(
                    "restored guest restarted the loop (HEARTBEAT 0 present) instead of resuming; stdout: {out:?}"
                ));
            }
            // ...and it must run the loop to completion, then power off.
            if !out.contains("HEARTBEAT 79") {
                return TestOutcome::Fail(format!(
                    "restored guest did not finish the heartbeat loop; stdout: {out:?}"
                ));
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

    impl Test for TestSnapshotResume {
        fn in_guest(self: Box<Self>) {
            use std::io::Write;
            // Emit heartbeats over a bounded window wide enough that the capture
            // (taken ~5s in, once the guest is at steady state) lands mid-loop.
            // The capture child is killed (KRUN_SNAPSHOT_EXIT) partway through;
            // the restored guest resumes mid-loop, prints the rest, then returns
            // and powers off so krun_restore exits.
            for i in 0..80 {
                println!("HEARTBEAT {i}");
                let _ = std::io::stdout().flush();
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
    }
}
