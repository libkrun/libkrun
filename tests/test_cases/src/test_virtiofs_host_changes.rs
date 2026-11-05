#![cfg(any(feature = "host", target_os = "linux"))]

//! A virtiofs share with `set_cache_timeouts(0, 0)` must show changes made on
//! the host right away: a file that grew is read with its new size, a new file
//! appears and a file replaced by rename (as editors save) shows the new
//! contents. With the default 5 s timeouts the guest read the old size and got
//! truncated contents.

use macros::{guest, host};

pub struct TestVirtiofsHostChanges;

/// The guest connects out on this port to synchronize with the host.
const CONTROL_PORT: u32 = 1234;
const TAG: &str = "shared";

const OLD: &str = "abc";
const NEW: &str = "abcdefghijklmnop: grown on the host";
const CREATED: &str = "created on the host";
const REPLACED: &str = "replaced by rename on the host";

#[host]
mod host {
    use super::*;
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;

    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::thread;

    use crate::common::{build_init_config, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestSetup};

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunFsDeviceNew,
                krun::Symbol::KrunFsDeviceSetCacheTimeouts,
                krun::Symbol::KrunVsockDeviceNew,
                krun::Symbol::KrunVsockDeviceDestroy,
                krun::Symbol::KrunVsockDeviceAddUnixPort,
            ],
        )
    }

    fn change_files(dir: &Path) {
        fs::write(dir.join("grow.txt"), NEW).unwrap();
        fs::write(dir.join("new.txt"), CREATED).unwrap();
        fs::write(dir.join("replace.tmp"), REPLACED).unwrap();
        fs::rename(dir.join("replace.tmp"), dir.join("replace.txt")).unwrap();
    }

    fn run(listener: UnixListener, dir: &Path) {
        let (mut control, _) = listener.accept().unwrap();
        // The guest has read the original files.
        control.read_exact(&mut [0]).unwrap();
        change_files(dir);
        control.write_all(&[1]).unwrap();
        // Keep the connection open until the guest is done.
        let _ = control.read(&mut [0]);
    }

    impl Test for TestVirtiofsHostChanges {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn timeout_secs(&self) -> u64 {
            30
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let shared = test_setup.tmp_dir.join("shared");
            fs::create_dir(&shared)?;
            fs::write(shared.join("grow.txt"), OLD)?;
            fs::write(shared.join("replace.txt"), OLD)?;

            let control_sock = test_setup.tmp_dir.join("control.sock");
            let listener = UnixListener::bind(&control_sock)?;
            let shared_clone = shared.clone();
            thread::spawn(move || run(listener, &shared_clone));

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;

            let mut fs_dev = krun::FsDevice::new(TAG, shared.to_str().unwrap())
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
            fs_dev
                .set_cache_timeouts(0, 0)
                .map_err(|e| anyhow::anyhow!("set_cache_timeouts: {e:?}"))?;
            devices.add(fs_dev);

            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::empty())
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock.add_unix_port(CONTROL_PORT, control_sock.to_str().unwrap(), false);
            devices.add(vsock);

            let vmm = krun::VmmBuilder::new()
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
    use nix::libc::{self, VMADDR_CID_HOST};
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, connect, socket};
    use std::ffi::CString;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn mount_share() {
        fs::create_dir_all("/mnt/shared").unwrap();
        let source = CString::new(TAG).unwrap();
        let target = CString::new("/mnt/shared").unwrap();
        let fstype = CString::new("virtiofs").unwrap();
        let ret = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        assert_eq!(ret, 0, "mount: {}", std::io::Error::last_os_error());
    }

    fn read(name: &str) -> String {
        fs::read_to_string(format!("/mnt/shared/{name}")).unwrap()
    }

    impl Test for TestVirtiofsHostChanges {
        fn in_guest(self: Box<Self>) {
            mount_share();

            // Cache the entries and attributes of the original files.
            assert_eq!(read("grow.txt"), OLD);
            assert_eq!(read("replace.txt"), OLD);
            assert!(fs::metadata("/mnt/shared/new.txt").is_err());

            let sock = socket(
                AddressFamily::Vsock,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .unwrap();
            connect(
                sock.as_raw_fd(),
                &VsockAddr::new(VMADDR_CID_HOST, CONTROL_PORT),
            )
            .unwrap();
            let mut control = UnixStream::from(sock);
            control.write_all(&[1]).unwrap();
            control.read_exact(&mut [0]).unwrap();

            assert_eq!(read("grow.txt"), NEW, "grown file read with a stale size");
            assert_eq!(read("new.txt"), CREATED, "new file not visible");
            assert_eq!(read("replace.txt"), REPLACED, "replaced file still old");
            control.write_all(&[1]).unwrap();
            println!("OK");
        }
    }
}
