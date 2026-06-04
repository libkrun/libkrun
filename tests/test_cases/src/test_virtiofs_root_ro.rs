#![cfg(any(feature = "host", target_os = "linux"))]

// NOTE: This is a smoke test that asserts basic mutation operations fail on a read-only
// virtiofs root. It is not exhaustive.For a security sensitive test it would also be better
// to bypass the guest kernel and execute the virtiofs commands directly.

use macros::{guest, host};

pub struct TestVirtiofsRootRo;

const TEST_FILE: &str = "test-file";
const TEST_CONTENT: &[u8] = b"original content";
const EMPTY_DIR: &str = "empty-dir";

#[host]
mod host {
    use super::*;

    use crate::common::setup_rootfs;
    use crate::{Test, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    impl Test for TestVirtiofsRootRo {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = setup_rootfs(&test_setup)?;

            // The guest init needs /dev, /proc, /sys as mount points. With a read-only
            // root these must already exist in the host directory.
            for dir in ["dev", "proc", "sys"] {
                fs::create_dir(root_dir.join(dir))?;
            }
            fs::create_dir(root_dir.join(EMPTY_DIR))?;
            fs::write(root_dir.join(TEST_FILE), TEST_CONTENT)?;
            let root_path = CString::new(root_dir.as_os_str().as_bytes())?;
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

                // Use "/dev/root" tag (KRUN_FS_ROOT_TAG) with read_only=true
                krun_call!(krun_add_virtiofs3(
                    ctx,
                    c"/dev/root".as_ptr(),
                    root_path.as_ptr(),
                    0,
                    true,
                ))?;

                let init_config =
                    crate::common::build_init_config(test_case.to_str().unwrap(), &[]);
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
    use nix::errno::Errno;
    use nix::libc;
    use nix::sys::stat::{Mode, SFlag, mknod, stat};
    use nix::unistd::{mkfifo, truncate};
    use std::fs;
    use std::fs::Permissions;
    use std::io::ErrorKind;
    use std::os::unix::fs::{PermissionsExt, chown, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    fn setxattr(path: &Path, name: &str, value: &[u8]) -> nix::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let c_name = CString::new(name).unwrap();
        let ret = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        };
        Errno::result(ret).map(drop)
    }

    /// Run `op` with `path`, assert it fails with EROFS, then verify `path` is unchanged.
    fn assert_unchanged_after<T, E>(
        description: &str,
        path: &Path,
        snapshot: &nix::sys::stat::FileStat,
        op: impl FnOnce(&Path) -> Result<T, E>,
    ) where
        T: std::fmt::Debug,
        E: Into<std::io::Error>,
    {
        match op(path) {
            Err(e) => {
                let err: std::io::Error = e.into();
                assert_eq!(
                    err.kind(),
                    ErrorKind::ReadOnlyFilesystem,
                    "Expected ReadOnlyFilesystem for {description}, got: {err}",
                );
            }
            Ok(val) => panic!("Expected ReadOnlyFilesystem for {description}, got: Ok({val:?})"),
        }

        let after = stat(path).unwrap_or_else(|e| {
            panic!("stat {} after {description}: {e}", path.display());
        });
        assert_eq!(
            snapshot.st_size, after.st_size,
            "{description}: size changed"
        );
        assert_eq!(
            snapshot.st_mode, after.st_mode,
            "{description}: mode changed"
        );
        assert_eq!(snapshot.st_uid, after.st_uid, "{description}: uid changed");
        assert_eq!(snapshot.st_gid, after.st_gid, "{description}: gid changed");
        assert_eq!(
            snapshot.st_mtime, after.st_mtime,
            "{description}: mtime changed"
        );
        assert_eq!(
            snapshot.st_mtime_nsec, after.st_mtime_nsec,
            "{description}: mtime_nsec changed",
        );
        assert_eq!(
            snapshot.st_ctime, after.st_ctime,
            "{description}: ctime changed"
        );
        assert_eq!(
            snapshot.st_ctime_nsec, after.st_ctime_nsec,
            "{description}: ctime_nsec changed",
        );
        if SFlag::from_bits_truncate(after.st_mode).contains(SFlag::S_IFREG) {
            assert_eq!(
                fs::read(path).unwrap_or_else(|_| panic!("read {}", path.display())),
                TEST_CONTENT,
                "{description}: content changed",
            );
        }
    }

    impl Test for TestVirtiofsRootRo {
        fn in_guest(self: Box<Self>) {
            let test_file = Path::new("/").join(TEST_FILE);
            let empty_dir = Path::new("/").join(EMPTY_DIR);
            let snap = stat(test_file.as_path()).expect("stat test-file");
            let dir_snap = stat(empty_dir.as_path()).expect("stat empty-dir");

            // -- Operations that try to create new entries --
            assert_unchanged_after("write new file", &test_file, &snap, |_| {
                fs::write("/new-file", b"hello")
            });
            assert_unchanged_after("create dir", &test_file, &snap, |_| {
                fs::create_dir("/new-dir")
            });
            assert_unchanged_after("create symlink", &test_file, &snap, |_| {
                symlink(TEST_FILE, "/new-symlink")
            });
            assert_unchanged_after("create hard link", &test_file, &snap, |_| {
                fs::hard_link(TEST_FILE, "/new-hardlink")
            });
            assert_unchanged_after("create unix socket", &test_file, &snap, |_| {
                UnixListener::bind("/new-socket").map(|_| ())
            });
            assert_unchanged_after("mkfifo", &test_file, &snap, |_| {
                mkfifo("/new-fifo", Mode::S_IRUSR)
            });
            assert_unchanged_after("mknod", &test_file, &snap, |_| {
                mknod("/new-node", SFlag::S_IFREG, Mode::S_IRUSR, 0)
            });

            // -- Operations that try to mutate the existing test file --
            assert_unchanged_after("write existing file", &test_file, &snap, |p| {
                fs::write(p, b"overwritten")
            });
            assert_unchanged_after("truncate", &test_file, &snap, |p| truncate(p, 0));
            assert_unchanged_after("chmod", &test_file, &snap, |p| {
                fs::set_permissions(p, Permissions::from_mode(0o777))
            });
            assert_unchanged_after("chown", &test_file, &snap, |p| {
                chown(p, Some(12345), Some(12345))
            });
            assert_unchanged_after("rename", &test_file, &snap, |p| {
                fs::rename(p, "/test-file-renamed")
            });
            assert_unchanged_after("setxattr", &test_file, &snap, |p| {
                setxattr(p, "user.test", b"value")
            });

            // -- Operations that try to remove existing entries --
            assert_unchanged_after("remove file", &test_file, &snap, |p| fs::remove_file(p));
            assert_unchanged_after("remove dir", &empty_dir, &dir_snap, |p| fs::remove_dir(p));

            println!("OK");
        }
    }
}
