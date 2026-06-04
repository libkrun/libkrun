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

    use crate::common;
    use crate::{ShouldRun, krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;
    use nix::libc;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::process::Command;

    type KrunAddDiskFn = unsafe extern "C" fn(
        ctx_id: u32,
        block_id: *const std::ffi::c_char,
        disk_path: *const std::ffi::c_char,
        read_only: bool,
    ) -> i32;

    type KrunSetRootDiskRemountFn = unsafe extern "C" fn(
        ctx_id: u32,
        device: *const std::ffi::c_char,
        fstype: *const std::ffi::c_char,
        options: *const std::ffi::c_char,
    ) -> i32;

    fn get_krun_add_disk() -> KrunAddDiskFn {
        let symbol = CString::new("krun_add_disk").unwrap();
        let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
        assert!(!ptr.is_null(), "krun_add_disk not found");
        unsafe { std::mem::transmute(ptr) }
    }

    fn get_krun_set_root_disk_remount() -> KrunSetRootDiskRemountFn {
        let symbol = CString::new("krun_set_root_disk_remount").unwrap();
        let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
        assert!(!ptr.is_null(), "krun_set_root_disk_remount not found");
        unsafe { std::mem::transmute(ptr) }
    }

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
            if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_BLK.into())) }.ok() != Some(1)
            {
                return ShouldRun::No("libkrun compiled without BLK");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let krun_add_disk = get_krun_add_disk();
            let krun_set_root_disk_remount = get_krun_set_root_disk_remount();

            let guest_agent_path = std::env::var("KRUN_TEST_GUEST_AGENT_PATH")
                .expect("KRUN_TEST_GUEST_AGENT_PATH not set");

            let disk_path = format!("{}/rootfs.ext4", test_setup.tmp_dir.display());
            create_disk_image(&guest_agent_path, &disk_path);

            let c_disk_path = CString::new(disk_path)?;
            let test_case = CString::new(test_setup.test_case)?;

            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;

                // Disable implicit init — we inject explicitly below.
                krun_call!(krun_disable_implicit_init(ctx))?;

                // Add a block device with the ext4 image.
                krun_call!(krun_add_disk(
                    ctx,
                    c"vda".as_ptr(),
                    c_disk_path.as_ptr(),
                    false,
                ))?;

                // Configure block device as root, pivot from NullFs.
                krun_call!(krun_set_root_disk_remount(
                    ctx,
                    c"/dev/vda".as_ptr(),
                    c"ext4".as_ptr(),
                    std::ptr::null(),
                ))?;

                // Inject init config into the NullFs root.
                let init_config = common::build_init_config(test_case.to_str().unwrap(), &[]);
                init_config
                    .apply(std::ptr::null_mut(), ctx, "/dev/root")
                    .expect("apply init config");

                krun_call!(krun_start_enter(ctx))?;
            }
            Ok(())
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
