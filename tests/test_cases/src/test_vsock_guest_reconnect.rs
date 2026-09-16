#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct TestVsockGuestReconnect;

const HOST_PORT: u32 = 1234;

fn stream_set_timeouts(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
}

#[host]
mod host {
    use super::*;

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
        for _ in 0..2 {
            let (mut stream, _addr) = listener.accept().unwrap();
            stream_set_timeouts(&mut stream);
            stream.write_all(b"ping!").unwrap();

            let mut reply = [0u8; 5];
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"pong!");

            let mut eof = [0u8; 1];
            assert_eq!(stream.read(&mut eof).unwrap(), 0);
        }
    }

    impl Test for TestVsockGuestReconnect {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn timeout_secs(&self) -> u64 {
            20
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let sock_path = test_setup.tmp_dir.join("test.sock");
            let listener = UnixListener::bind(&sock_path).unwrap();
            thread::spawn(move || server(listener));

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::empty())
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock.add_unix_port(HOST_PORT, sock_path.to_str().unwrap(), false);
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
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use nix::libc::{VMADDR_CID_ANY, VMADDR_CID_HOST};
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, bind, connect, socket};
    use std::os::fd::AsRawFd;
    use std::thread;

    const GUEST_PORT: u32 = 2345;
    const REAPER_WAIT: Duration = Duration::from_secs(20);

    fn exchange() {
        let sock = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        bind(
            sock.as_raw_fd(),
            &VsockAddr::new(VMADDR_CID_ANY, GUEST_PORT),
        )
        .unwrap();
        connect(
            sock.as_raw_fd(),
            &VsockAddr::new(VMADDR_CID_HOST, HOST_PORT),
        )
        .unwrap();

        let mut stream = UnixStream::from(sock);
        stream_set_timeouts(&mut stream);

        let mut request = [0u8; 5];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping!");
        stream.write_all(b"pong!").unwrap();
    }

    impl Test for TestVsockGuestReconnect {
        fn in_guest(self: Box<Self>) {
            exchange();
            thread::sleep(REAPER_WAIT);
            exchange();
            println!("OK");
        }
    }
}
