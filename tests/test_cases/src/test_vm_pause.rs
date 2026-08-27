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
//!   - The second pause/resume in each cycle is a no-op that must return without
//!     re-signalling the (already parked) vCPUs; a missing idempotency guard
//!     deadlocks the event loop.
//!   - A pause immediately followed by a resume reaches the event loop in a
//!     single wakeup. Observing them out of order would no-op the resume and
//!     leave the guest frozen.
//!
//! The process exits on guest poweroff, so host timing can't be measured around
//! `vmm.run()` (it never returns) -- hence the marker rather than a timer.

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
    const SETTLE_MS: u64 = 1_500;
    const PAUSE_MS: u64 = 5_000;
    const GAP_MS: u64 = 1_500;
    const IDEM_GAP_MS: u64 = 200;

    use std::io;
    use std::os::fd::AsFd;
    use std::time::Duration;

    use crate::common::{build_init_config, init_krun, setup_rootfs};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    // FIXME: remove once ffier marks generated handle wrappers as Send.
    struct SendHandle(krun::VmmHandle);
    unsafe impl Send for SendHandle {}
    impl SendHandle {
        fn pause(&self) -> Result<(), krun::Error> {
            self.0.pause()
        }
        fn resume(&self) -> Result<(), krun::Error> {
            self.0.resume()
        }
    }

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunVmmHandle,
                krun::Symbol::KrunVmmHandleDestroy,
                krun::Symbol::KrunVmmHandlePause,
                krun::Symbol::KrunVmmHandleResume,
            ],
        )
    }

    fn sleep_ms(ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    impl Test for TestVmPause {
        fn should_run(&self) -> ShouldRun {
            if !cfg!(target_os = "macos") {
                return ShouldRun::No("pause/resume is macOS/HVF only");
            }
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn timeout_secs(&self) -> u64 {
            60
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let root_dir = setup_rootfs(&test_setup)?;
            let init_config = build_init_config(&test_setup.test_case, &[]);

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

            let vmm = krun::VmmBuilder::new()
                .vcpus(NUM_CPUS)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(512)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("VmmBuilder::build: {e:?}"))?;

            let handle = SendHandle(
                vmm.handle()
                    .map_err(|e| anyhow::anyhow!("vmm.handle: {e:?}"))?,
            );

            let marker = test_setup.tmp_dir.join("resumed");
            std::thread::spawn(move || {
                sleep_ms(SETTLE_MS);
                while handle.pause().is_err() {
                    sleep_ms(50);
                }
                handle.resume().expect("tight resume");

                for cycle in 0..CYCLES {
                    handle.pause().expect("pause");
                    sleep_ms(IDEM_GAP_MS);
                    handle.pause().expect("redundant pause");

                    sleep_ms(PAUSE_MS);

                    handle.resume().expect("resume");
                    sleep_ms(IDEM_GAP_MS);
                    handle.resume().expect("redundant resume");

                    if cycle + 1 < CYCLES {
                        sleep_ms(GAP_MS);
                    }
                }
                let _ = std::fs::write(&marker, "1");
            });

            vmm.run();
            unreachable!()
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

            if guest_done_ms > WORKLOAD_MS + PAUSE_MS / 2 {
                return TestOutcome::Fail(format!(
                    "guest clock jumped across pause: {guest_done_ms}ms (workload ~{WORKLOAD_MS}ms)"
                ));
            }

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
