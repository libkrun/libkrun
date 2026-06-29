#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

pub struct TestVirtioFsMisc;

/// Name of the file created on the host before VM boot, used by the
/// uid_gid_mapping_preexisting guest subtest.
const HOST_OWNED_FILE: &str = "host_owned_file";

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter_with_env;
    use crate::{Test, TestOutcome, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    impl Test for TestVirtioFsMisc {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Create a host-owned file in the rootfs before entering the VM.
            // Inside the guest it must appear as root-owned: on Linux via user
            // namespace mapping, on macOS via the EUID→0 mapping (PR #734).
            let root_dir = test_setup.tmp_dir.join("rootfs");
            std::fs::create_dir_all(&root_dir)?;
            std::fs::write(root_dir.join(HOST_OWNED_FILE), b"host-data")?;

            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 1024))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;

                // Forward KRUN_NO_UNSHARE to the guest so UID/GID mapping
                // subtests can skip themselves when no user namespace is active.
                let mut guest_env: Vec<&std::ffi::CStr> = Vec::new();
                if std::env::var_os("KRUN_NO_UNSHARE").is_some() {
                    guest_env.push(c"KRUN_NO_UNSHARE=1");
                }
                setup_fs_and_enter_with_env(ctx, test_setup, &guest_env)?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8(stdout).unwrap();
            if output != "OK\n" {
                return TestOutcome::Fail(format!(
                    "expected exactly {:?}, got {:?}",
                    "OK\n", output
                ));
            }

            let root = test_setup.tmp_dir.join("rootfs");

            // Verify fallocate basic: file should be at least 4096 bytes
            let meta = std::fs::metadata(root.join("test_fallocate_basic")).unwrap();
            assert!(
                meta.len() >= 4096,
                "host: file size after allocate: {} (expected >= 4096)",
                meta.len()
            );

            // Verify punch hole: read the file and check the hole is zeroed
            let mut f = std::fs::File::open(root.join("test_fallocate_punch_hole")).unwrap();
            let mut contents = Vec::new();
            f.read_to_end(&mut contents).unwrap();

            assert_eq!(contents.len(), 16384, "host: punch hole file should be 16K");
            assert!(
                contents[..4096].iter().all(|&b| b == 0xAA),
                "host: data before hole should be 0xAA"
            );
            assert!(
                contents[4096..8192].iter().all(|&b| b == 0),
                "host: punched hole region should be zeroed"
            );
            assert!(
                contents[8192..].iter().all(|&b| b == 0xAA),
                "host: data after hole should be 0xAA"
            );

            TestOutcome::Pass
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use std::collections::HashSet;
    use std::ffi::{CStr, CString};
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;
    use std::panic::catch_unwind;

    use nix::fcntl::{FallocateFlags, fallocate};
    use nix::libc;
    use nix::unistd::{Gid, Uid, chown};

    fn run_subtests(tests: &[(&str, fn())]) {
        let mut failed = Vec::new();
        for (name, f) in tests {
            if catch_unwind(f).is_err() {
                eprintln!("FAIL: {name}");
                failed.push(*name);
            } else {
                eprintln!("PASS: {name}");
            }
        }

        if failed.is_empty() {
            println!("OK");
        } else {
            println!("FAILED: {}", failed.join(", "));
        }
    }

    fn test_fallocate_basic() {
        let path = "/test_fallocate_basic";
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        fallocate(f.as_raw_fd(), FallocateFlags::empty(), 0, 4096)
            .expect("fallocate(ALLOCATE_RANGE) failed");

        let meta = f.metadata().unwrap();
        assert!(
            meta.len() >= 4096,
            "file size after allocate: {} (expected >= 4096)",
            meta.len()
        );
    }

    fn test_fallocate_keep_size() {
        let path = "/test_fallocate_keep_size";
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        fallocate(f.as_raw_fd(), FallocateFlags::FALLOC_FL_KEEP_SIZE, 0, 65536)
            .expect("fallocate(KEEP_SIZE) failed");

        let meta = f.metadata().unwrap();
        assert_eq!(meta.len(), 0, "file size should remain 0 with KEEP_SIZE");
        assert!(
            meta.blocks() > 0,
            "blocks should be allocated with KEEP_SIZE"
        );
    }

    fn test_fallocate_punch_hole() {
        let path = "/test_fallocate_punch_hole";
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        // Write 16K of non-zero data
        let data = vec![0xAAu8; 16384];
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();

        let size_before = f.metadata().unwrap().len();

        // Punch a 4K hole in the middle (offset 4096, length 4096)
        fallocate(
            f.as_raw_fd(),
            FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE,
            4096,
            4096,
        )
        .expect("fallocate(PUNCH_HOLE) failed");

        let meta = f.metadata().unwrap();
        assert_eq!(
            meta.len(),
            size_before,
            "file size should not change after PUNCH_HOLE"
        );

        // Verify the hole is zeroed
        f.seek(SeekFrom::Start(4096)).unwrap();
        let mut hole_data = vec![0u8; 4096];
        f.read_exact(&mut hole_data).unwrap();
        assert!(
            hole_data.iter().all(|&b| b == 0),
            "punched region should be zeroed"
        );

        // Verify data around the hole is intact
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut before_hole = vec![0u8; 4096];
        f.read_exact(&mut before_hole).unwrap();
        assert!(
            before_hole.iter().all(|&b| b == 0xAA),
            "data before hole should be intact"
        );

        f.seek(SeekFrom::Start(8192)).unwrap();
        let mut after_hole = vec![0u8; 4096];
        f.read_exact(&mut after_hole).unwrap();
        assert!(
            after_hole.iter().all(|&b| b == 0xAA),
            "data after hole should be intact"
        );
    }

    fn test_fallocate_punch_hole_requires_keep_size() {
        let path = "/test_fallocate_punch_no_keepsize";
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        let ret = fallocate(f.as_raw_fd(), FallocateFlags::FALLOC_FL_PUNCH_HOLE, 0, 4096);
        assert!(ret.is_err(), "PUNCH_HOLE without KEEP_SIZE should fail");
    }

    /// Read all entry names from `dir` (excluding "." and "..").
    unsafe fn read_entries(dir: *mut libc::DIR) -> HashSet<String> {
        let mut names = HashSet::new();
        loop {
            let ent = unsafe { libc::readdir(dir) };
            if ent.is_null() {
                break;
            }
            let name = unsafe {
                CStr::from_ptr((*ent).d_name.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            if name != "." && name != ".." {
                names.insert(name);
            }
        }
        names
    }

    /// Test that files created after an initial readdir are visible after rewinddir.
    fn test_dirstream_create() {
        let dir = "/test_dirstream_create";
        fs::create_dir(dir).expect("mkdir");
        fs::write(format!("{dir}/before"), b"").expect("write before");

        let c_dir = CString::new(dir).unwrap();
        unsafe {
            let dp = libc::opendir(c_dir.as_ptr());
            assert!(!dp.is_null(), "opendir failed");

            let entries1 = read_entries(dp);
            assert!(entries1.contains("before"), "should see 'before' initially");
            assert!(!entries1.contains("after1"), "should not see 'after1' yet");

            fs::write(format!("{dir}/after1"), b"").expect("write after1");
            fs::write(format!("{dir}/after2"), b"").expect("write after2");

            libc::rewinddir(dp);
            let entries2 = read_entries(dp);
            assert!(entries2.contains("before"), "should still see 'before'");
            assert!(
                entries2.contains("after1"),
                "should see 'after1' after rewinddir"
            );
            assert!(
                entries2.contains("after2"),
                "should see 'after2' after rewinddir"
            );

            libc::closedir(dp);
        }
    }

    /// Test that unlinked files disappear from readdir after rewinddir.
    fn test_dirstream_unlink() {
        let dir = "/test_dirstream_unlink";
        fs::create_dir(dir).expect("mkdir");
        fs::write(format!("{dir}/keep"), b"").expect("write keep");
        fs::write(format!("{dir}/remove_me"), b"").expect("write remove_me");

        let c_dir = CString::new(dir).unwrap();
        unsafe {
            let dp = libc::opendir(c_dir.as_ptr());
            assert!(!dp.is_null(), "opendir failed");

            let entries1 = read_entries(dp);
            assert!(
                entries1.contains("remove_me"),
                "should see 'remove_me' initially"
            );

            fs::remove_file(format!("{dir}/remove_me")).expect("unlink");

            libc::rewinddir(dp);
            let entries2 = read_entries(dp);
            assert!(entries2.contains("keep"), "should still see 'keep'");
            assert!(
                !entries2.contains("remove_me"),
                "should not see 'remove_me' after unlink"
            );

            libc::closedir(dp);
        }
    }

    /// Test that mkdir/rmdir are reflected in readdir after rewinddir.
    fn test_dirstream_mkdir_rmdir() {
        let dir = "/test_dirstream_mkdir";
        fs::create_dir(dir).expect("mkdir");

        let c_dir = CString::new(dir).unwrap();
        unsafe {
            let dp = libc::opendir(c_dir.as_ptr());
            assert!(!dp.is_null(), "opendir failed");

            let entries1 = read_entries(dp);
            assert!(entries1.is_empty(), "dir should start empty");

            fs::create_dir(format!("{dir}/subdir")).expect("mkdir subdir");

            libc::rewinddir(dp);
            let entries2 = read_entries(dp);
            assert!(
                entries2.contains("subdir"),
                "should see 'subdir' after mkdir"
            );

            fs::remove_dir(format!("{dir}/subdir")).expect("rmdir subdir");

            libc::rewinddir(dp);
            let entries3 = read_entries(dp);
            assert!(
                !entries3.contains("subdir"),
                "should not see 'subdir' after rmdir"
            );

            libc::closedir(dp);
        }
    }

    /// Test that symlink creation is reflected in readdir after rewinddir.
    fn test_dirstream_symlink() {
        let dir = "/test_dirstream_symlink";
        fs::create_dir(dir).expect("mkdir");
        fs::write("/symlink_target", b"target").expect("write target");

        let c_dir = CString::new(dir).unwrap();
        unsafe {
            let dp = libc::opendir(c_dir.as_ptr());
            assert!(!dp.is_null(), "opendir failed");

            let entries1 = read_entries(dp);
            assert!(entries1.is_empty(), "dir should start empty");

            std::os::unix::fs::symlink("/symlink_target", format!("{dir}/link")).expect("symlink");

            libc::rewinddir(dp);
            let entries2 = read_entries(dp);
            assert!(entries2.contains("link"), "should see symlink 'link'");

            libc::closedir(dp);
        }
    }

    /// Test that hard link creation is reflected in readdir after rewinddir.
    fn test_dirstream_link() {
        let dir = "/test_dirstream_link";
        fs::create_dir(dir).expect("mkdir");
        fs::write(format!("{dir}/original"), b"data").expect("write original");

        let c_dir = CString::new(dir).unwrap();
        unsafe {
            let dp = libc::opendir(c_dir.as_ptr());
            assert!(!dp.is_null(), "opendir failed");

            let entries1 = read_entries(dp);
            assert_eq!(entries1.len(), 1, "should have 1 entry initially");

            fs::hard_link(format!("{dir}/original"), format!("{dir}/hardlink")).expect("hard_link");

            libc::rewinddir(dp);
            let entries2 = read_entries(dp);
            assert!(entries2.contains("hardlink"), "should see 'hardlink'");

            libc::closedir(dp);
        }
    }

    /// Test that rename is reflected in readdir after rewinddir.
    fn test_dirstream_rename() {
        let dir = "/test_dirstream_rename";
        fs::create_dir(dir).expect("mkdir");
        fs::write(format!("{dir}/old_name"), b"data").expect("write old_name");

        let c_dir = CString::new(dir).unwrap();
        unsafe {
            let dp = libc::opendir(c_dir.as_ptr());
            assert!(!dp.is_null(), "opendir failed");

            let entries1 = read_entries(dp);
            assert!(
                entries1.contains("old_name"),
                "should see 'old_name' initially"
            );

            fs::rename(format!("{dir}/old_name"), format!("{dir}/new_name")).expect("rename");

            libc::rewinddir(dp);
            let entries2 = read_entries(dp);
            assert!(
                !entries2.contains("old_name"),
                "should not see 'old_name' after rename"
            );
            assert!(
                entries2.contains("new_name"),
                "should see 'new_name' after rename"
            );

            libc::closedir(dp);
        }
    }

    /// Test rename across directories: both source and dest handles should reflect it.
    fn test_dirstream_rename_cross_dir() {
        let src_dir = "/test_dirstream_rename_src";
        let dst_dir = "/test_dirstream_rename_dst";
        fs::create_dir(src_dir).expect("mkdir src");
        fs::create_dir(dst_dir).expect("mkdir dst");
        fs::write(format!("{src_dir}/moved_file"), b"data").expect("write");

        let c_src = CString::new(src_dir).unwrap();
        let c_dst = CString::new(dst_dir).unwrap();
        unsafe {
            let dp_src = libc::opendir(c_src.as_ptr());
            let dp_dst = libc::opendir(c_dst.as_ptr());
            assert!(!dp_src.is_null() && !dp_dst.is_null(), "opendir failed");

            // Populate caches.
            let _ = read_entries(dp_src);
            let _ = read_entries(dp_dst);

            fs::rename(
                format!("{src_dir}/moved_file"),
                format!("{dst_dir}/moved_file"),
            )
            .expect("rename cross-dir");

            libc::rewinddir(dp_src);
            libc::rewinddir(dp_dst);
            let src_entries = read_entries(dp_src);
            let dst_entries = read_entries(dp_dst);

            assert!(
                !src_entries.contains("moved_file"),
                "source should not contain 'moved_file'"
            );
            assert!(
                dst_entries.contains("moved_file"),
                "dest should contain 'moved_file'"
            );

            libc::closedir(dp_src);
            libc::closedir(dp_dst);
        }
    }

    /// Test rename-overwrite with open file descriptors (PR #700 regression test).
    ///
    /// This verifies the fix for a macOS-specific fd leak when renaming over
    /// an existing file. The macOS virtio-fs implementation uses volfs paths
    /// (/.vol/{dev}/{ino}) which become invalid when the inode's last link is
    /// removed. When rename() replaces a file, the old target loses its link,
    /// breaking operations on still-open fds.
    ///
    /// This pattern broke apt/dpkg atomic writes:
    /// "Problem closing the file /var/lib/dpkg/status - close (2: No such file or directory)"
    fn test_rename_overwrite_fchmod() {
        let target_path = "/test_rename_fstat_target";
        let temp_path = "/test_rename_fstat_temp";

        // Create target with initial content
        let mut target_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(target_path)
            .unwrap();

        target_file.write_all(b"data1\n").unwrap();
        target_file.flush().unwrap();

        // Keep the target file open
        let open_target = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(target_path)
            .unwrap();

        // Create temp file
        let mut temp_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(temp_path)
            .unwrap();

        temp_file.write_all(b"data2\n").unwrap();
        temp_file.flush().unwrap();
        drop(temp_file);

        // Rename temp over target
        fs::rename(temp_path, target_path).expect("rename failed");

        // Try to get file stats via the still-open file descriptor.
        // Before PR #700, this would fail with ENOENT on macOS.
        open_target
            .metadata()
            .expect("fstat on open fd after rename failed - PR #700 regression!");

        // Try to change permission bits via the still-open file descriptor.
        use nix::sys::stat::{Mode, fchmod};
        fchmod(
            open_target.as_raw_fd(),
            Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP,
        )
        .expect("fchmod on open fd after rename failed - PR #700 regression!");
    }

    /// Verify that pre-existing host files appear as owned by root inside the
    /// guest.  Requires UID mapping (user namespace on Linux, always on macOS).
    fn test_uid_gid_mapping_preexisting_files() {
        if std::env::var_os("KRUN_NO_UNSHARE").is_some() {
            eprintln!("SKIP: uid_gid_mapping_preexisting (no user namespace)");
            return;
        }

        let path = format!("/{HOST_OWNED_FILE}");
        let meta = fs::metadata(&path).unwrap_or_else(|e| panic!("stat {path}: {e}"));
        assert_eq!(
            meta.uid(),
            0,
            "{path} uid should be 0 (root), got {}",
            meta.uid()
        );
        assert_eq!(
            meta.gid(),
            0,
            "{path} gid should be 0 (root), got {}",
            meta.gid()
        );
    }

    /// Verify that a UID/GID change is reflected in subsequent stat.
    /// Requires UID mapping (user namespace on Linux, always on macOS).
    fn test_uid_gid_mapping_chown() {
        if std::env::var_os("KRUN_NO_UNSHARE").is_some() {
            eprintln!("SKIP: uid_gid_mapping_chown (no user namespace)");
            return;
        }

        let path = "/test_uid_chown";
        fs::write(path, b"data").expect("write");

        // Newly created file starts as root-owned.
        let meta = fs::metadata(path).expect("stat before chown");
        assert_eq!(meta.uid(), 0, "initial uid should be 0");
        assert_eq!(meta.gid(), 0, "initial gid should be 0");

        // Change to uid=1000, gid=1000.
        chown(path, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000)))
            .expect("chown(1000,1000)");

        let meta = fs::metadata(path).expect("stat after chown");
        assert_eq!(
            meta.uid(),
            1000,
            "uid after chown should be 1000, got {}",
            meta.uid()
        );
        assert_eq!(
            meta.gid(),
            1000,
            "gid after chown should be 1000, got {}",
            meta.gid()
        );

        // Change back to root.
        chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).expect("chown(0,0)");

        let meta = fs::metadata(path).expect("stat after chown back to root");
        assert_eq!(
            meta.uid(),
            0,
            "uid after chown back should be 0, got {}",
            meta.uid()
        );
        assert_eq!(
            meta.gid(),
            0,
            "gid after chown back should be 0, got {}",
            meta.gid()
        );
    }

    /// Test that creating files mid-iteration does not cause duplicates.
    ///
    /// POSIX says readdir behavior is unspecified when the directory is modified
    /// during iteration. In practice (verified on ext4, btrfs, and tmpfs),
    /// entries already returned are not repeated.
    ///
    /// Creates files named `m_*`, reads a few, then inserts `aaa_*` which are
    /// have been observed to land before the already-returned entries in
    /// the directory ordering — maximizing the chance of exposing duplicate entries.
    fn test_dirstream_no_duplicates_on_mid_iteration_create() {
        let dir = "/test_dirstream_mid_iter";
        fs::create_dir(dir).expect("mkdir");

        // Pre-populate with files that sort late so the our instert lands before them.
        for i in 0..10 {
            fs::write(format!("{dir}/m_{i:02}"), b"").expect("write");
        }

        let c_dir = CString::new(dir).unwrap();
        unsafe {
            let dp = libc::opendir(c_dir.as_ptr());
            assert!(!dp.is_null(), "opendir failed");

            // Read a few entries (not all). We ask for 7 readdir calls to
            // get past "." and ".." and read ~5 real entries.
            let mut seen = Vec::new();
            for _ in 0..7 {
                let ent = libc::readdir(dp);
                if ent.is_null() {
                    break;
                }
                let name = CStr::from_ptr((*ent).d_name.as_ptr())
                    .to_string_lossy()
                    .into_owned();
                if name != "." && name != ".." {
                    seen.push(name);
                }
            }

            let before_mutation = seen.clone();

            // Insert files that should sort BEFORE everything we already read.
            // These shift all existing entries to the right in the rebuilt cache.
            for i in 0..3 {
                fs::write(format!("{dir}/aaa_{i:02}"), b"").expect("write aaa");
            }

            // Continue reading the rest.
            let mark = seen.len();
            loop {
                let ent = libc::readdir(dp);
                if ent.is_null() {
                    break;
                }
                let name = CStr::from_ptr((*ent).d_name.as_ptr())
                    .to_string_lossy()
                    .into_owned();
                if name != "." && name != ".." {
                    seen.push(name);
                }
            }

            let after_mutation: Vec<_> = seen[mark..].to_vec();

            // Find duplicates.
            let mut dups = Vec::new();
            for (i, a) in seen.iter().enumerate() {
                for b in &seen[..i] {
                    if a == b {
                        dups.push(a.clone());
                        break;
                    }
                }
            }

            let unique: HashSet<&str> = seen.iter().map(|s| s.as_str()).collect();
            assert!(
                dups.is_empty(),
                "readdir returned {} duplicates: {dups:?}\n\
                 before mutation: {before_mutation:?}\n\
                 after mutation: {after_mutation:?}\n\
                 all seen ({} total): {seen:?}",
                dups.len(),
                seen.len(),
            );

            // All original files should be present (they existed before iteration
            // started and were never removed).
            for i in 0..10 {
                let name = format!("m_{i:02}");
                assert!(
                    unique.contains(name.as_str()),
                    "original file {name} missing from readdir results: {seen:?}"
                );
            }

            libc::closedir(dp);
        }
    }

    impl Test for TestVirtioFsMisc {
        fn in_guest(self: Box<Self>) {
            run_subtests(&[
                ("fallocate_basic", test_fallocate_basic),
                ("fallocate_keep_size", test_fallocate_keep_size),
                ("fallocate_punch_hole", test_fallocate_punch_hole),
                (
                    "fallocate_punch_hole_requires_keep_size",
                    test_fallocate_punch_hole_requires_keep_size,
                ),
                ("rename_overwrite_fchmod", test_rename_overwrite_fchmod),
                ("dirstream_create", test_dirstream_create),
                ("dirstream_unlink", test_dirstream_unlink),
                ("dirstream_mkdir_rmdir", test_dirstream_mkdir_rmdir),
                ("dirstream_symlink", test_dirstream_symlink),
                ("dirstream_link", test_dirstream_link),
                ("dirstream_rename", test_dirstream_rename),
                (
                    "dirstream_rename_cross_dir",
                    test_dirstream_rename_cross_dir,
                ),
                (
                    "dirstream_no_duplicates_mid_iter",
                    test_dirstream_no_duplicates_on_mid_iteration_create,
                ),
                (
                    "uid_gid_mapping_preexisting",
                    test_uid_gid_mapping_preexisting_files,
                ),
                ("uid_gid_mapping_chown", test_uid_gid_mapping_chown),
            ]);
        }
    }
}
