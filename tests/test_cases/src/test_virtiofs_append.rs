#![cfg(any(feature = "host", target_os = "linux"))]

//! A shared mapping of an `O_APPEND` file must be written back at its offset,
//! and appends must not overwrite data the host appended in the meantime.

use macros::{guest, host};

pub struct TestVirtiofsAppend;

const CONTROL_PORT: u32 = 1234;
const TAG: &str = "shared";

const MAPPED_LEN: usize = 65536;
const MAPPED_DATA: &[u8] = b"mapped";

#[host]
mod host {
    use super::*;
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;

    use std::fs::{self, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::thread;

    use crate::common::{build_init_config, setup_standard_devices};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    const HOST_DATA: &[u8] = b"host";

    fn append_between_guest_writes(listener: UnixListener, dir: &Path) {
        let (mut control, _) = listener.accept().unwrap();
        control.read_exact(&mut [0]).unwrap();
        OpenOptions::new()
            .append(true)
            .open(dir.join("log"))
            .unwrap()
            .write_all(HOST_DATA)
            .unwrap();
        control.write_all(&[1]).unwrap();
        let _ = control.read(&mut [0]);
    }

    impl Test for TestVirtiofsAppend {
        fn should_run(&self) -> ShouldRun {
            ShouldRun::yes_unless_macos("pwrite() on macOS doesn't append to O_APPEND files")
        }

        fn timeout_secs(&self) -> u64 {
            30
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let shared = test_setup.tmp_dir.join("shared");
            fs::create_dir(&shared)?;

            let control_sock = test_setup.tmp_dir.join("control.sock");
            let listener = UnixListener::bind(&control_sock)?;
            let shared_clone = shared.clone();
            thread::spawn(move || append_between_guest_writes(listener, &shared_clone));

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = io::stdin();
            let stdout = io::stdout();
            let stderr = io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;

            let fs_dev = krun::FsDevice::new(TAG, shared.to_str().unwrap())
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
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

        fn check(self: Box<Self>, stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            if stdout != b"OK\n" {
                return TestOutcome::Fail(format!(
                    "guest output: {:?}",
                    String::from_utf8_lossy(&stdout)
                ));
            }
            let shared = test_setup.tmp_dir.join("shared");

            let mapped = fs::read(shared.join("mapped")).unwrap();
            if mapped.len() != MAPPED_LEN || !mapped.starts_with(MAPPED_DATA) {
                return TestOutcome::Fail(format!(
                    "mapped write not at its offset: file is {} bytes",
                    mapped.len()
                ));
            }

            let log = fs::read(shared.join("log")).unwrap();
            let expected = [b"A", HOST_DATA, b"B"].concat();
            if log != expected {
                return TestOutcome::Fail(format!(
                    "expected {:?}, got {:?}",
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&log)
                ));
            }
            TestOutcome::Pass
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
    use std::fs::{self, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::ptr;

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
                ptr::null(),
            )
        };
        assert_eq!(ret, 0, "mount: {}", io::Error::last_os_error());
    }

    fn connect_control() -> UnixStream {
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
        UnixStream::from(sock)
    }

    fn write_through_shared_mapping() {
        let f = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("/mnt/shared/mapped")
            .unwrap();
        f.set_len(MAPPED_LEN as u64).unwrap();
        unsafe {
            let addr = libc::mmap(
                ptr::null_mut(),
                MAPPED_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                f.as_raw_fd(),
                0,
            );
            assert_ne!(addr, libc::MAP_FAILED);
            ptr::copy_nonoverlapping(MAPPED_DATA.as_ptr(), addr.cast(), MAPPED_DATA.len());
            assert_eq!(libc::msync(addr, MAPPED_LEN, libc::MS_SYNC), 0);
            libc::munmap(addr, MAPPED_LEN);
        }
    }

    fn append_around_host_append() {
        let mut control = connect_control();
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open("/mnt/shared/log")
            .unwrap();
        f.write_all(b"A").unwrap();
        control.write_all(&[1]).unwrap();
        control.read_exact(&mut [0]).unwrap();
        f.write_all(b"B").unwrap();
        control.write_all(&[1]).unwrap();
    }

    impl Test for TestVirtiofsAppend {
        fn in_guest(self: Box<Self>) {
            mount_share();
            write_through_shared_mapping();
            append_around_host_append();
            println!("OK");
        }
    }
}
