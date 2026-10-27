use macros::{guest, host};

/// An AugmentFs overlay directory that shadows a real directory in a
/// passthrough root, with a tmpfs mounted on it in the guest.
///
/// Listing the root must not detach that mount: the guest's FUSE client drops
/// a cached dentry whose node id in a READDIRPLUS reply differs from the one
/// LOOKUP returned, and dropping it detaches every mount on it.
pub struct TestAugmentFsShadowedDir;

const SHADOWED_DIR: &str = "shadowed";

#[host]
mod host {
    use super::*;

    use crate::common::{build_and_run, build_init_config, init_krun, setup_rootfs};
    use crate::{ShouldRun, Test, TestSetup};

    impl Test for TestAugmentFsShadowedDir {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if crate::common::require_vm_symbols().is_err() {
                return ShouldRun::No("core VM symbols not available");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;

            let root_dir = setup_rootfs(&test_setup)?;
            std::fs::create_dir(root_dir.join(SHADOWED_DIR))?;

            let mut rootfs = krun::FsDevice::new("/dev/root", root_dir.to_str().unwrap())
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
            let mut payload =
                krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("load_krunfw: {e:?}"))?;
            let mut overlay = krun::FsOverlay::new();
            overlay
                .add_dir(SHADOWED_DIR, 0o040_755)
                .map_err(|e| anyhow::anyhow!("overlay.add_dir: {e:?}"))?;
            let init_config = build_init_config(&test_setup.test_case, &[]);
            init_config
                .apply(&mut overlay, &mut payload)
                .map_err(|e| anyhow::anyhow!("Config::apply: {e}"))?;
            rootfs.set_overlay(overlay);

            build_and_run(1, 512, rootfs, payload)
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use std::fs;
    use std::io::Error;
    use std::ptr;

    use nix::libc;

    impl Test for TestAugmentFsShadowedDir {
        fn in_guest(self: Box<Self>) {
            let ret = unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    c"/shadowed".as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    ptr::null(),
                )
            };
            assert_eq!(
                ret,
                0,
                "mount tmpfs on /shadowed: {}",
                Error::last_os_error()
            );
            fs::write("/shadowed/marker", b"on-tmpfs").expect("write /shadowed/marker");

            let names: Vec<_> = fs::read_dir("/")
                .expect("read_dir /")
                .map(|entry| entry.expect("read_dir / entry").file_name())
                .collect();
            assert!(
                names.iter().any(|name| name == SHADOWED_DIR),
                "/ should list {SHADOWED_DIR}: {names:?}"
            );

            let marker = fs::read("/shadowed/marker")
                .expect("listing / detached the tmpfs mounted on /shadowed");
            assert_eq!(marker, b"on-tmpfs");

            println!("OK");
        }
    }
}
