// Test that krun_set_root_disk_remount works with NullFs.
//
// Creates a tiny ext4 disk image containing only the guest-agent binary,
// boots from it via krun_set_root_disk_remount (which uses NullFs for the
// initial virtiofs root with init.krun overlaid), and verifies the guest
// successfully pivoted to the block device root.

use macros::{guest, host};

pub struct TestRootDiskRemount;

#[host]
mod host {
    use super::*;

    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::ptr;

    use krun_via_cdylib_weak as krun;

    use krun_init_blob_via_cdylib as krun_init;

    use crate::common::{self, init_krun};
    use crate::{ShouldRun, Test, TestSetup};

    fn create_disk_image(guest_agent_path: &str, output_path: &str) {
        // Populate from a staging directory using mke2fs -d (no root needed).
        let staging = format!("{output_path}.staging");
        std::fs::create_dir_all(&staging).expect("mkdir staging");

        std::fs::copy(guest_agent_path, format!("{staging}/guest-agent"))
            .expect("copy guest-agent");

        // Marker file to verify the guest booted from the block device.
        std::fs::write(
            format!("{staging}/block-marker"),
            "booted-from-block-device",
        )
        .expect("write marker");

        let status = Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-d", &staging, output_path, "32M"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("mke2fs failed");
        assert!(status.success(), "mke2fs failed");

        std::fs::remove_dir_all(&staging).expect("cleanup staging");
    }

    impl Test for TestRootDiskRemount {
        fn should_run(&self) -> ShouldRun {
            if common::require_vm_symbols().is_err() {
                return ShouldRun::No("core VM symbols not available");
            }
            if krun::require(
                None,
                &[
                    krun::Symbol::KrunBlockDeviceNew,
                    krun::Symbol::KrunBlockDeviceDestroy,
                ],
            )
            .is_err()
            {
                return ShouldRun::No("libkrun compiled without BLK");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            // TODO: duplicated with should_run — see require-in-should-run-broken.md
            krun::require(
                None,
                &[
                    krun::Symbol::KrunBlockDeviceNew,
                    krun::Symbol::KrunBlockDeviceDestroy,
                ],
            )
            .map_err(|e| anyhow::anyhow!("block symbols: {e}"))?;

            let guest_agent_path = std::env::var("KRUN_TEST_GUEST_AGENT_PATH")
                .expect("KRUN_TEST_GUEST_AGENT_PATH not set");

            let disk_path = format!("{}/rootfs.ext4", test_setup.tmp_dir.display());
            create_disk_image(&guest_agent_path, &disk_path);

            let init_config = krun_init::Config::builder()
                .args(&["/guest-agent", &test_setup.test_case])
                .workdir("/")
                .set_root_disk_remount("/dev/vda", Some("ext4"), None)
                .build();

            let mut rootfs = krun::FsDevice::new_null("/dev/root")
                .map_err(|e| anyhow::anyhow!("FsDevice::new_null: {e:?}"))?;
            let mut payload =
                krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("load_krunfw: {e:?}"))?;
            let mut overlay = krun::FsOverlay::new();
            for dir in ["dev", "proc", "sys", "newroot"] {
                overlay.add_dir(dir, 0o040_755);
            }
            init_config
                .apply(ptr::null_mut(), &mut overlay, &mut payload)
                .map_err(|e| anyhow::anyhow!("Config::apply: {e}"))?;
            rootfs.set_overlay(overlay);

            let block = krun::BlockDevice::new("vda", &disk_path, false)
                .map_err(|e| anyhow::anyhow!("BlockDevice: {e:?}"))?;

            let mut console_builder = krun::ConsoleDevice::builder();
            console_builder
                .add_default_console(
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                )
                .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
            let console = console_builder
                .build()
                .map_err(|e| anyhow::anyhow!("ConsoleDevice::build: {e:?}"))?;

            let mut devices = krun::MmioDeviceManager::new();
            devices.add(rootfs);
            devices.add(console);
            devices.add(
                krun::BalloonDevice::new().map_err(|e| anyhow::anyhow!("BalloonDevice: {e:?}"))?,
            );
            devices.add(krun::RngDevice::new().map_err(|e| anyhow::anyhow!("RngDevice: {e:?}"))?);
            devices.add(block);

            let mut vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(512)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("build: {e:?}"))?;

            vmm.run();
            unreachable!()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::fs;
    use std::path::Path;

    impl Test for TestRootDiskRemount {
        fn in_guest(self: Box<Self>) {
            // Verify we're running from the block device root.
            let marker = fs::read_to_string("/block-marker")
                .expect("Failed to read /block-marker — not on block device root?");
            assert_eq!(marker, "booted-from-block-device");

            // The init.krun virtual file should be gone (one-shot, and we
            // pivoted away from the NullFs root anyway).
            assert!(!Path::new("/init.krun").exists());

            // /proc and /dev should be mounted (init re-mounts after pivot).
            assert!(Path::new("/proc/self").exists(), "/proc/self missing");
            assert!(Path::new("/dev/null").exists(), "/dev/null missing");

            println!("OK");
        }
    }
}
