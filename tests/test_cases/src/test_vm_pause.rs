//! Live pause/resume test. macOS/HVF only (the mechanism is HVF for now).
//!
//! Boots a 2-vCPU microVM running a fixed monotonic-clock workload, then from
//! another thread pauses and resumes it across several cycles while asserting:
//!   - `DONE` present  -> every resume woke the guest (otherwise it hangs paused
//!     forever and the runner times out).
//!   - exactly `WORKLOAD_ITERS` heartbeats -> the guest ran to completion, no
//!     work lost or duplicated across the pauses.
//!   - guest's own elapsed ms stays near the workload length -> the virtual timer
//!     was frozen across each pause (no en-masse catch-up on wake), and the
//!     per-vCPU offsets stayed in lockstep.
//!   - a `resumed` marker file written only after the final `krun_vm_resume` ->
//!     the pauses held the guest well past its natural completion time. A no-op
//!     pause lets the guest power off (which `libc::exit`s the whole process,
//!     killing the pause thread) before the marker is ever written.
//!
//! Two properties are checked by construction rather than by assertion, because
//! a regression makes the whole run hang and trips the timeout:
//!   - With 2 vCPUs, the core not running the workload is parked in WFE at pause
//!     time. It can only acknowledge the pause if the park point also watches the
//!     pause channel -- otherwise `Vmm::pause` blocks forever awaiting its ack.
//!   - The second `krun_vm_pause`/`krun_vm_resume` in each cycle is a no-op that
//!     must return without re-signalling the (already parked) vCPUs; a missing
//!     idempotency guard deadlocks the event loop.
//!   - A pause immediately followed by a resume reaches the event loop in a
//!     single wakeup. Observing them out of order would no-op the resume and
//!     leave the guest frozen.
//!
//! The process exits on guest poweroff, so host timing can't be measured around
//! `krun_start_enter` (it never returns) -- hence the marker rather than a timer.

use macros::{guest, host};

pub struct TestVmPause;

const WORKLOAD_ITERS: u32 = 50;
const WORKLOAD_INTERVAL_MS: u64 = 100;

#[host]
mod host {
    use super::*;

    const NUM_CPUS: u8 = 2;
    const WORKLOAD_MS: u64 = WORKLOAD_ITERS as u64 * WORKLOAD_INTERVAL_MS;
    const CYCLES: u32 = 2;
    // Each pause must outlast the guest's remaining run so the guest can't power
    // off (and exit the process) before the post-resume marker is written.
    const SETTLE_MS: u64 = 1_500;
    const PAUSE_MS: u64 = 5_000;
    const GAP_MS: u64 = 1_500;
    // Long enough that the doubled pause/resume below land as distinct event-loop
    // wakeups rather than coalescing into one, so they exercise the no-op guard.
    const IDEM_GAP_MS: u64 = 200;

    use crate::common::setup_rootfs;
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::ffi::{CString, c_char};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null;
    use std::time::Duration;

    fn sleep_ms(ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    unsafe fn configure_vm(ctx: u32, root: &Path, test_case: &str) -> anyhow::Result<()> {
        let root_cstr = CString::new(root.as_os_str().as_bytes())?;
        let test_case_cstr = CString::new(test_case.to_owned())?;
        unsafe {
            krun_call!(krun_set_vm_config(ctx, NUM_CPUS, 512))?;
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

    impl Test for TestVmPause {
        fn should_run(&self) -> ShouldRun {
            if cfg!(target_os = "macos") {
                ShouldRun::Yes
            } else {
                ShouldRun::No("pause/resume is macOS/HVF only")
            }
        }

        fn timeout_secs(&self) -> u64 {
            60
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = setup_rootfs(&test_setup)?;
            let ctx = unsafe { krun_call_u32!(krun_create_ctx())? };
            unsafe { configure_vm(ctx, &root_dir, &test_setup.test_case)? };

            // Pause/resume the guest several times from another thread, each pause
            // outlasting the guest's remaining run, then drop a marker. The control
            // channel isn't registered until the VM's event loop starts, so retry
            // the first pause past the initial -ENOENT.
            let marker = test_setup.tmp_dir.join("resumed");
            std::thread::spawn(move || {
                sleep_ms(SETTLE_MS);
                while unsafe { krun_vm_pause(ctx) } != 0 {
                    sleep_ms(50);
                }
                // Resume with no sleep in between, so both requests reach the event
                // loop in one wakeup: if it observed them out of order the guest
                // would stay frozen and the runner would time out.
                assert_eq!(unsafe { krun_vm_resume(ctx) }, 0, "tight resume");

                for cycle in 0..CYCLES {
                    assert_eq!(unsafe { krun_vm_pause(ctx) }, 0, "pause");
                    // Pausing an already-paused VM is a no-op; it deadlocks the
                    // event loop if the idempotency guard is missing.
                    sleep_ms(IDEM_GAP_MS);
                    assert_eq!(unsafe { krun_vm_pause(ctx) }, 0, "redundant pause");

                    sleep_ms(PAUSE_MS);

                    assert_eq!(unsafe { krun_vm_resume(ctx) }, 0, "resume");
                    sleep_ms(IDEM_GAP_MS);
                    assert_eq!(unsafe { krun_vm_resume(ctx) }, 0, "redundant resume");

                    if cycle + 1 < CYCLES {
                        sleep_ms(GAP_MS);
                    }
                }
                // Reached only if the guest was still alive after the last resume,
                // i.e. the pauses actually held it; a no-op pause exits first.
                let _ = std::fs::write(&marker, "1");
            });

            let rc = unsafe { krun_start_enter(ctx) };
            if rc < 0 {
                anyhow::bail!("krun_start_enter failed: {rc}");
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            let out = String::from_utf8_lossy(&stdout);

            let done = out.lines().find_map(|l| {
                l.strip_prefix("DONE ")
                    .and_then(|ms| ms.trim().parse::<u64>().ok())
            });
            let Some(guest_done_ms) = done else {
                return TestOutcome::Fail(format!(
                    "restored guest never finished; stdout: {out:?}"
                ));
            };

            let beats = out.lines().filter(|l| l.contains("HEARTBEAT")).count();
            if beats != WORKLOAD_ITERS as usize {
                return TestOutcome::Fail(format!(
                    "expected {WORKLOAD_ITERS} heartbeats, got {beats}"
                ));
            }

            // The guest's own clock must not have absorbed the host pauses: it
            // should report roughly the workload length, not workload + pauses.
            if guest_done_ms > WORKLOAD_MS + PAUSE_MS / 2 {
                return TestOutcome::Fail(format!(
                    "guest clock jumped across pause: {guest_done_ms}ms (workload ~{WORKLOAD_MS}ms)"
                ));
            }

            // The pause thread reaches the marker write only if the guest was
            // still alive long after its natural completion -- i.e. the pauses
            // really halted it. A no-op pause exits the process first.
            if !test_setup.tmp_dir.join("resumed").exists() {
                return TestOutcome::Fail(
                    "no resume marker; pause did not hold the guest past its workload".into(),
                );
            }

            TestOutcome::Pass
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    impl Test for TestVmPause {
        fn in_guest(self: Box<Self>) {
            use std::io::Write;
            use std::time::Instant;

            // Monotonic clock derives from the guest virtual counter, which the
            // host freezes while paused — so this elapsed time excludes the pauses.
            let start = Instant::now();
            for i in 0..WORKLOAD_ITERS {
                println!("HEARTBEAT {i}");
                let _ = std::io::stdout().flush();
                std::thread::sleep(std::time::Duration::from_millis(WORKLOAD_INTERVAL_MS));
            }
            println!("DONE {}", start.elapsed().as_millis());
            let _ = std::io::stdout().flush();
        }
    }
}
