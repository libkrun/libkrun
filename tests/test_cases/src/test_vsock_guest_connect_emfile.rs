#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

pub struct TestVsockGuestConnectEmfile;

/// Carries the handshake that brackets the window in which the VMM has no free
/// file descriptors.
const CONTROL_PORT: u32 = 1234;
/// Mapped to a live listener, but the VMM cannot create the host socket for the
/// first connection to it.
const SERVICE_PORT: u32 = 1235;

#[host]
mod host {
    use super::*;
    use nix::errno::Errno;
    use nix::libc::{EMFILE, rlim_t};
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::mem;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use crate::common::{build_init_config, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestSetup};

    /// Caps how many files it takes to exhaust the table, since the runner
    /// raises the soft limit to the hard one.
    const FD_LIMIT: rlim_t = 1024;

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunVsockDeviceNew,
                krun::Symbol::KrunVsockDeviceDestroy,
                krun::Symbol::KrunVsockDeviceAddUnixPort,
            ],
        )
    }

    fn exhaust_fds() -> Vec<File> {
        let mut files = Vec::new();
        loop {
            match File::open("/dev/null") {
                Ok(file) => files.push(file),
                Err(e) if e.raw_os_error() == Some(EMFILE) => break,
                Err(e) => panic!("opening /dev/null: {e}"),
            }
        }
        let err = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap_err();
        assert_eq!(err, Errno::EMFILE);
        files
    }

    fn run(control: UnixListener, service: UnixListener) {
        let (mut ctl, _addr) = control.accept().unwrap();

        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        setrlimit(Resource::RLIMIT_NOFILE, soft.min(FD_LIMIT), hard).unwrap();
        let files = exhaust_fds();
        ctl.write_all(b"go").unwrap();
        ctl.read_exact(&mut [0u8; 4]).unwrap();
        drop(files);
        setrlimit(Resource::RLIMIT_NOFILE, soft, hard).unwrap();
        ctl.write_all(b"go").unwrap();

        let (mut stream, _addr) = service.accept().unwrap();
        stream.write_all(b"ping!").unwrap();

        mem::forget(stream);
        mem::forget(ctl);
    }

    impl Test for TestVsockGuestConnectEmfile {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let control_sock = test_setup.tmp_dir.join("control.sock");
            let service_sock = test_setup.tmp_dir.join("service.sock");
            let control = UnixListener::bind(&control_sock)?;
            let service = UnixListener::bind(&service_sock)?;
            thread::spawn(move || run(control, service));

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::empty())
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock.add_unix_port(CONTROL_PORT, control_sock.to_str().unwrap(), false);
            vsock.add_unix_port(SERVICE_PORT, service_sock.to_str().unwrap(), false);
            devices.add(vsock);

            let vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(1024)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("build: {e:?}"))?;

            vmm.run();
            unreachable!()
        }

        fn timeout_secs(&self) -> u64 {
            30
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::errno::Errno;
    use nix::libc::VMADDR_CID_HOST;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, connect, socket};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn vsock_connect(port: u32) -> nix::Result<UnixStream> {
        let sock = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )?;
        connect(sock.as_raw_fd(), &VsockAddr::new(VMADDR_CID_HOST, port))?;
        let stream = UnixStream::from(sock);
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Ok(stream)
    }

    fn expect_msg(stream: &mut UnixStream, expected: &[u8]) {
        let mut buf = vec![0; expected.len()];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, expected);
    }

    impl Test for TestVsockGuestConnectEmfile {
        fn in_guest(self: Box<Self>) {
            let mut ctl = vsock_connect(CONTROL_PORT).unwrap();

            expect_msg(&mut ctl, b"go");
            match vsock_connect(SERVICE_PORT) {
                Ok(_) => panic!("connect succeeded while the VMM had no free fds"),
                Err(e) => assert!(
                    matches!(e, Errno::ECONNRESET | Errno::ECONNREFUSED),
                    "connect while the VMM had no free fds failed with {e}, expected a reset"
                ),
            }
            ctl.write_all(b"done").unwrap();

            expect_msg(&mut ctl, b"go");
            let mut stream = vsock_connect(SERVICE_PORT).unwrap();
            expect_msg(&mut stream, b"ping!");

            println!("OK");
        }
    }
}
