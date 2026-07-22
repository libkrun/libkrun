#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};
use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct TestVsockGuestConnect;

fn stream_expect_msg(stream: &mut UnixStream, expected: &[u8]) {
    let mut buf = vec![0; expected.len()];
    stream.read_exact(&mut buf[..]).unwrap();
    assert_eq!(&buf[..], expected);
}

fn stream_expect_wouldblock(stream: &mut UnixStream) {
    stream.set_nonblocking(true).unwrap();
    let err = stream.read(&mut [0u8; 1]).unwrap_err();
    stream.set_nonblocking(false).unwrap();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

fn stream_set_timeouts(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
}

const VSOCK_PORT: u32 = 1234;

#[host]
mod host {
    use super::*;

    use std::io::Write;
    use std::mem;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use krun_via_cdylib_weak as krun;

    use crate::common::{self, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestSetup};

    fn server(listener: UnixListener) {
        let (mut stream, _addr) = listener.accept().unwrap();
        stream_set_timeouts(&mut stream);
        stream.write_all(b"ping!").unwrap();
        stream_expect_msg(&mut stream, b"pong!");
        stream_expect_wouldblock(&mut stream);
        stream.write_all(b"bye!").unwrap();
        mem::forget(stream);
    }

    impl Test for TestVsockGuestConnect {
        fn should_run(&self) -> ShouldRun {
            if common::require_vm_symbols().is_err() {
                return ShouldRun::No("core VM symbols not available");
            }
            if krun::require(
                None,
                &[
                    krun::Symbol::KrunVsockDeviceNew,
                    krun::Symbol::KrunVsockDeviceDestroy,
                    krun::Symbol::KrunVsockDeviceAddUnixPort,
                ],
            )
            .is_err()
            {
                return ShouldRun::No("vsock symbols not available");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            // TODO: duplicated with should_run — see require-in-should-run-broken.md
            krun::require(
                None,
                &[
                    krun::Symbol::KrunVsockDeviceNew,
                    krun::Symbol::KrunVsockDeviceDestroy,
                    krun::Symbol::KrunVsockDeviceAddUnixPort,
                ],
            )
            .map_err(|e| anyhow::anyhow!("vsock symbols: {e}"))?;

            let sock_path = test_setup.tmp_dir.join("test.sock");
            let listener = UnixListener::bind(&sock_path).unwrap();
            thread::spawn(move || server(listener));

            let (mut devices, payload) = setup_standard_devices(&test_setup, &[])?;
            let mut vsock =
                krun::VsockDevice::new(3, 0).map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock.add_unix_port(VSOCK_PORT, sock_path.to_str().unwrap(), false);
            devices.add(vsock);

            let mut vmm = krun::VmmBuilder::new()
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
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use nix::libc::VMADDR_CID_HOST;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, connect, socket};
    use std::io::Write;
    use std::os::fd::AsRawFd;

    impl Test for TestVsockGuestConnect {
        fn in_guest(self: Box<Self>) {
            let sock = socket(
                AddressFamily::Vsock,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .unwrap();
            let addr = VsockAddr::new(VMADDR_CID_HOST, VSOCK_PORT);
            connect(sock.as_raw_fd(), &addr).unwrap();
            let mut stream = UnixStream::from(sock);
            stream_set_timeouts(&mut stream);

            stream_expect_msg(&mut stream, b"ping!");
            stream_expect_wouldblock(&mut stream);
            stream.write_all(b"pong!").unwrap();
            stream_expect_msg(&mut stream, b"bye!");

            println!("OK");
        }
    }
}
