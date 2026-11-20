#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

pub struct TestVirtiofsFixedOwner;

const OWNER_UID: u32 = 1234;
const OWNER_GID: u32 = 5678;
const HOST_FILE: &str = "host-file";
const GUEST_FILE: &str = "guest-file";
const OWNER_FILE: &str = "owner-file";

#[host]
mod host {
    use super::*;

    use std::fs;

    use crate::common::{build_and_run, build_init_config, setup_rootfs};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    impl Test for TestVirtiofsFixedOwner {
        fn should_run(&self) -> ShouldRun {
            if !cfg!(any(target_os = "macos", target_os = "linux")) {
                return ShouldRun::No("a fixed owner takes effect on macOS and Linux hosts only");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = setup_rootfs(&test_setup)?;
            fs::write(root_dir.join(HOST_FILE), b"from the host")?;

            let root_path = root_dir.to_str().unwrap();
            let mut complete = krun::FsDevice::new("/dev/root", root_path)
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
            complete
                .set_permission_semantics(krun::PermissionSemantics::LinuxComplete)
                .map_err(|e| anyhow::anyhow!("set_permission_semantics: {e:?}"))?;
            anyhow::ensure!(
                complete.set_fixed_owner(OWNER_UID, OWNER_GID).is_err(),
                "set_fixed_owner must fail outside LinuxSimplifiedFixedOwner"
            );

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let mut rootfs = krun::FsDevice::new("/dev/root", root_path)
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
            rootfs
                .set_permission_semantics(krun::PermissionSemantics::LinuxSimplifiedFixedOwner)
                .map_err(|e| anyhow::anyhow!("set_permission_semantics: {e:?}"))?;
            rootfs
                .set_fixed_owner(OWNER_UID, OWNER_GID)
                .map_err(|e| anyhow::anyhow!("set_fixed_owner: {e:?}"))?;

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
            let rootfs = test_setup.tmp_dir.join("rootfs");
            for (file, expected) in [
                (GUEST_FILE, "from the guest"),
                (OWNER_FILE, "from the owner"),
            ] {
                let path = rootfs.join(file);
                match fs::read(&path) {
                    Ok(contents) if contents == expected.as_bytes() => {}
                    other => {
                        return TestOutcome::Fail(format!(
                            "host: {} should hold {expected:?}, got {other:?}",
                            path.display()
                        ));
                    }
                }
            }
            TestOutcome::Pass
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
    use nix::unistd::{Gid, Uid, mkfifo, setresgid, setresuid};

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

            let owner_gid = Gid::from_raw(OWNER_GID);
            let owner_uid = Uid::from_raw(OWNER_UID);
            setresgid(owner_gid, owner_gid, owner_gid).expect("become the owner group");
            setresuid(owner_uid, owner_uid, owner_uid).expect("become the owner");
            let owner_file = format!("/{OWNER_FILE}");
            fs::write(&owner_file, b"from the owner").expect("the owner writes a file");
            assert_owner(&owner_file);

            println!("OK");
        }
    }
}
