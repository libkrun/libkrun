#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

pub struct TestVirtiofsFixedOwner;

const OWNER_UID: u32 = 1234;
const OWNER_GID: u32 = 5678;
const HOST_FILE: &str = "host-file";
const GUEST_FILE: &str = "guest-file";

#[host]
mod host {
    use super::*;

    use std::fs;

    use crate::common::{build_and_run, build_init_config, init_krun, setup_rootfs};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunFsDeviceSetPermissionSemantics,
                krun::Symbol::KrunFsDeviceSetFixedOwner,
            ],
        )
    }

    impl Test for TestVirtiofsFixedOwner {
        fn should_run(&self) -> ShouldRun {
            if !cfg!(target_os = "macos") {
                return ShouldRun::No("a fixed owner takes effect on macOS hosts only");
            }
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("krun_fs_device_set_fixed_owner not available");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();
            init_krun()?;

            let root_dir = setup_rootfs(&test_setup)?;
            fs::write(root_dir.join(HOST_FILE), b"from the host")?;

            let root_path = root_dir.to_str().unwrap();
            let mut simplified = krun::FsDevice::new("/dev/root", root_path)
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
            simplified
                .set_permission_semantics(krun::PermissionSemantics::LinuxSimplified)
                .map_err(|e| anyhow::anyhow!("set_permission_semantics: {e:?}"))?;
            anyhow::ensure!(
                simplified.set_fixed_owner(OWNER_UID, OWNER_GID).is_err(),
                "set_fixed_owner must fail outside LinuxSimplifiedFixedOwner"
            );

            let mut rootfs = krun::FsDevice::new("/dev/root", root_path)
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
            rootfs
                .set_permission_semantics(krun::PermissionSemantics::LinuxSimplifiedFixedOwner)
                .map_err(|e| anyhow::anyhow!("set_permission_semantics: {e:?}"))?;
            rootfs
                .set_fixed_owner(OWNER_UID, OWNER_GID)
                .map_err(|e| anyhow::anyhow!("set_fixed_owner: {e:?}"))?;

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let mut payload =
                krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("load_krunfw: {e:?}"))?;
            let mut overlay = krun::FsOverlay::new();
            init_config
                .apply(&mut overlay, &mut payload)
                .map_err(|e| anyhow::anyhow!("Config::apply: {e}"))?;
            rootfs.set_overlay(overlay);

            build_and_run(1, 512, rootfs, payload)
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8(stdout).unwrap();
            if output != "OK\n" {
                return TestOutcome::Fail(format!(
                    "expected exactly {:?}, got {:?}",
                    "OK\n", output
                ));
            }
            let guest_file = test_setup.tmp_dir.join("rootfs").join(GUEST_FILE);
            match fs::read(&guest_file) {
                Ok(contents) if contents == b"from the guest" => TestOutcome::Pass,
                other => TestOutcome::Fail(format!(
                    "host: {} should hold the guest's write, got {other:?}",
                    guest_file.display()
                )),
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use std::fs;
    use std::os::unix::fs::{MetadataExt, chown, symlink};

    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    fn assert_owner(path: &str) {
        let meta = fs::symlink_metadata(path).unwrap_or_else(|e| panic!("stat {path}: {e}"));
        assert_eq!(
            (meta.uid(), meta.gid()),
            (OWNER_UID, OWNER_GID),
            "{path} owner"
        );
    }

    impl Test for TestVirtiofsFixedOwner {
        fn in_guest(self: Box<Self>) {
            let host_file = format!("/{HOST_FILE}");
            let guest_file = format!("/{GUEST_FILE}");

            assert_owner(&host_file);
            assert_owner("/");

            fs::write(&guest_file, b"from the guest").expect("write guest file");
            assert_owner(&guest_file);

            chown(&guest_file, Some(0), Some(0)).expect("chown is accepted");
            assert_owner(&guest_file);

            fs::create_dir("/guest-dir").expect("mkdir");
            assert_owner("/guest-dir");
            mkfifo("/guest-fifo", Mode::from_bits_truncate(0o644)).expect("mkfifo");
            assert_owner("/guest-fifo");
            symlink(&guest_file, "/guest-link").expect("symlink");
            assert_owner("/guest-link");

            println!("OK");
        }
    }
}
