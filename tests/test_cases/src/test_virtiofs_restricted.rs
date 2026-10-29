#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

pub struct TestVirtiofsRestricted;

#[host]
mod host {
    use super::*;
    use crate::common::{build_and_run, build_init_config, init_krun, setup_rootfs};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use std::fs;
    use std::os::unix::fs::symlink;

    impl Test for TestVirtiofsRestricted {
        fn should_run(&self) -> ShouldRun {
            if !cfg!(target_os = "macos") {
                return ShouldRun::No("restricted virtiofs requires macOS");
            }
            #[cfg(feature = "dynamic-linking")]
            if crate::common::require_vm_symbols().is_err()
                || krun::require(
                    None,
                    &[
                        krun::Symbol::KrunFsDeviceSetPermissionSemantics,
                        krun::Symbol::KrunFsDeviceSetDaxWindowSize,
                    ],
                )
                .is_err()
            {
                return ShouldRun::No("restricted virtiofs symbol not available");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            krun::require(
                None,
                &[
                    krun::Symbol::KrunFsDeviceSetPermissionSemantics,
                    krun::Symbol::KrunFsDeviceSetDaxWindowSize,
                ],
            )?;
            let root = setup_rootfs(&test_setup)?.canonicalize()?;
            fs::write(test_setup.tmp_dir.join("outside"), b"outside")?;
            fs::write(root.join("blocked"), b"hardlinked")?;
            fs::hard_link(root.join("blocked"), test_setup.tmp_dir.join("hardlink"))?;
            symlink("../outside", root.join("escape"))?;
            let mut rootfs = krun::FsDevice::new("/dev/root", root.to_str().unwrap())
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
            rootfs
                .set_permission_semantics(krun::PermissionSemantics::Restricted)
                .map_err(|e| anyhow::anyhow!("set_permission_semantics: {e:?}"))?;
            assert!(rootfs.set_dax_window_size(4096).is_err());
            {
                let mut dax = krun::FsDevice::new("dax-conflict", root.to_str().unwrap())
                    .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
                dax.set_dax_window_size(4096)
                    .map_err(|e| anyhow::anyhow!("set_dax_window_size: {e:?}"))?;
                assert!(
                    dax.set_permission_semantics(krun::PermissionSemantics::Restricted)
                        .is_err()
                );
            }
            let config = build_init_config(&test_setup.test_case, &[]);
            let mut payload =
                krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("load_krunfw: {e:?}"))?;
            let mut overlay = krun::FsOverlay::new();
            config
                .apply(&mut overlay, &mut payload)
                .map_err(|e| anyhow::anyhow!("Config::apply: {e}"))?;
            rootfs.set_overlay(overlay);
            build_and_run(1, 512, rootfs, payload)
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            assert_eq!(
                fs::read(test_setup.tmp_dir.join("outside")).unwrap(),
                b"outside"
            );
            assert_eq!(
                fs::read(test_setup.tmp_dir.join("hardlink")).unwrap(),
                b"hardlinked"
            );
            if stdout == b"OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(String::from_utf8_lossy(&stdout).into_owned())
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::symlink;

    impl Test for TestVirtiofsRestricted {
        fn in_guest(self: Box<Self>) {
            assert!(fs::read("/blocked").is_err());
            assert!(fs::write("/blocked", b"changed").is_err());
            assert!(fs::read("/escape").is_err());
            fs::write("/file", b"inside").unwrap();
            assert!(fs::hard_link("/file", "/new-hardlink").is_err());
            symlink("file", "/relative").unwrap();
            symlink("/file", "/absolute").unwrap();
            assert_eq!(fs::read("/relative").unwrap(), b"inside");
            assert_eq!(fs::read("/absolute").unwrap(), b"inside");
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/file")
                .unwrap();
            file.write_all(b"edited").unwrap();
            file.sync_all().unwrap();
            fs::rename("/file", "/renamed").unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            assert_eq!(contents, "edited");
            fs::create_dir("/directory").unwrap();
            fs::write("/directory/file", b"child").unwrap();
            assert_eq!(fs::read_dir("/directory").unwrap().count(), 1);
            fs::remove_file("/directory/file").unwrap();
            fs::remove_dir("/directory").unwrap();
            println!("OK");
        }
    }
}
