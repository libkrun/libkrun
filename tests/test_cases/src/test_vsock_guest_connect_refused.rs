#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

pub struct TestVsockGuestConnectRefused;

/// Mapped to a socket path that does not exist.
const MISSING_PORT: u32 = 1234;
/// Mapped to a socket file nothing listens on.
const STALE_PORT: u32 = 1235;
/// Mapped to a live listener.
const WORKING_PORT: u32 = 1237;

#[host]
mod host {
    use super::*;
    use std::io::Write;
    use std::mem;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use crate::common::{build_init_config, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestSetup};

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

    fn server(listener: UnixListener) {
        let (mut stream, _addr) = listener.accept().unwrap();
        stream.write_all(b"ping!").unwrap();
        mem::forget(stream);
    }

    impl Test for TestVsockGuestConnectRefused {
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

            let missing_sock = test_setup.tmp_dir.join("missing.sock");
            let stale_sock = test_setup.tmp_dir.join("stale.sock");
            let working_sock = test_setup.tmp_dir.join("working.sock");

            // Dropping the listener leaves the socket file behind, so connect() on it
            // fails with ECONNREFUSED rather than ENOENT.
            drop(UnixListener::bind(&stale_sock)?);
            let listener = UnixListener::bind(&working_sock)?;
            thread::spawn(move || server(listener));

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::empty())
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock.add_unix_port(MISSING_PORT, missing_sock.to_str().unwrap(), false);
            vsock.add_unix_port(STALE_PORT, stale_sock.to_str().unwrap(), false);
            vsock.add_unix_port(WORKING_PORT, working_sock.to_str().unwrap(), false);
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
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    const UNMAPPED_PORT: u32 = 1236;

    /// The guest kernel gives up on an unanswered vsock connect() after 2s, so a
    /// refusal must arrive well before that to count as one.
    const MAX_REFUSE: Duration = Duration::from_millis(1000);

    fn vsock_connect(port: u32) -> nix::Result<UnixStream> {
        let sock = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )?;
        connect(sock.as_raw_fd(), &VsockAddr::new(VMADDR_CID_HOST, port))?;
        Ok(UnixStream::from(sock))
    }

    fn expect_refused(name: &str, port: u32) {
        let start = Instant::now();
        let result = vsock_connect(port);
        let elapsed = start.elapsed();
        match result {
            Ok(_) => panic!("connect to {name} port {port} succeeded, expected a reset"),
            Err(Errno::ECONNRESET | Errno::ECONNREFUSED) => assert!(
                elapsed < MAX_REFUSE,
                "connect to {name} port {port} took {elapsed:?} to be refused, limit is {MAX_REFUSE:?}"
            ),
            Err(e) => panic!("connect to {name} port {port} failed with {e} after {elapsed:?}"),
        }
    }

    impl Test for TestVsockGuestConnectRefused {
        fn in_guest(self: Box<Self>) {
            expect_refused("missing", MISSING_PORT);
            expect_refused("stale", STALE_PORT);
            expect_refused("unmapped", UNMAPPED_PORT);

            let mut stream = vsock_connect(WORKING_PORT).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping!");

            println!("OK");
        }
    }
}
