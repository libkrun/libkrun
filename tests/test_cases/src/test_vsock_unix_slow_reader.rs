#![cfg(any(feature = "host", target_os = "linux"))]

//! A host peer that stops reading a unix socket proxy must not stall the other
//! vsock connections. The guest streams `BULK_LEN` bytes on one connection while
//! the host leaves it unread, and the host expects an answer on a second
//! connection meanwhile; then it reads the whole stream and checks it.
//! Writing to the host socket used to block the thread that serves every vsock
//! connection (and the other devices), so the second connection never got its
//! answer.

use macros::{guest, host};
use std::time::Duration;

pub struct TestVsockUnixSlowReader;

/// The guest connects out on this port once its listener is bound, and the
/// host reports the outcome back on the same connection.
const CONTROL_PORT: u32 = 1234;
/// Registered with `listen=true`: the host connects, the guest accepts.
const ACCEPT_PORT: u32 = 1235;

const BULK_LEN: usize = 16 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn byte_at(index: usize) -> u8 {
    (index % 251) as u8
}

#[host]
mod host {
    use super::*;
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;

    use anyhow::{Context, ensure};
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
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
                krun::Symbol::KrunVsockDeviceNew,
                krun::Symbol::KrunVsockDeviceDestroy,
                krun::Symbol::KrunVsockDeviceAddUnixPort,
            ],
        )
    }

    fn run_client(accept_sock: &Path) -> anyhow::Result<()> {
        let mut bulk = UnixStream::connect(accept_sock).context("connect bulk")?;
        // Leave the bulk stream unread long enough for its socket buffer to fill.
        thread::sleep(Duration::from_secs(1));

        let mut ping = UnixStream::connect(accept_sock).context("connect ping")?;
        ping.set_read_timeout(Some(IO_TIMEOUT))?;
        ping.write_all(b"p").context("send ping")?;
        let mut pong = [0; 4];
        ping.read_exact(&mut pong)
            .context("no answer on a second connection while the first is unread")?;
        ensure!(&pong == b"pong", "wrong answer: {pong:?}");

        bulk.set_read_timeout(Some(IO_TIMEOUT))?;
        let mut data = Vec::new();
        bulk.read_to_end(&mut data).context("read bulk stream")?;
        ensure!(
            data.len() == BULK_LEN,
            "bulk stream has {} bytes",
            data.len()
        );
        ensure!(
            data.iter().enumerate().all(|(i, b)| *b == byte_at(i)),
            "bulk stream is corrupted"
        );
        Ok(())
    }

    fn run(control_listener: UnixListener, accept_sock: &Path) {
        // Returns once the guest has bound its listener.
        let (mut control, _) = control_listener.accept().unwrap();

        let status = match run_client(accept_sock) {
            Ok(()) => 1,
            Err(error) => {
                eprintln!("slow reader client failed: {error:#}");
                0
            }
        };
        control.write_all(&[status]).unwrap();
        // Keep the connection open until the guest has read the status.
        let _ = control.read(&mut [0]);
    }

    impl Test for TestVsockUnixSlowReader {
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

            let control_sock = test_setup.tmp_dir.join("control.sock");
            let accept_sock = test_setup.tmp_dir.join("accept.sock");

            let control_listener = UnixListener::bind(&control_sock)?;
            let accept_sock_clone = accept_sock.clone();
            thread::spawn(move || run(control_listener, &accept_sock_clone));

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::empty())
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock.add_unix_port(CONTROL_PORT, control_sock.to_str().unwrap(), false);
            vsock.add_unix_port(ACCEPT_PORT, accept_sock.to_str().unwrap(), true);
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
    use nix::libc::VMADDR_CID_HOST;
    use nix::sys::socket::{
        AddressFamily, Backlog, SockFlag, SockType, VsockAddr, accept, bind, connect, listen,
        socket,
    };
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn vsock_connect(port: u32) -> UnixStream {
        let sock = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        connect(sock.as_raw_fd(), &VsockAddr::new(VMADDR_CID_HOST, port)).unwrap();
        UnixStream::from(sock)
    }

    fn accept_stream(listener: &OwnedFd) -> UnixStream {
        let fd = accept(listener.as_raw_fd()).unwrap();
        // Safe because we've just obtained the FD from the `accept` call above.
        UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    impl Test for TestVsockUnixSlowReader {
        fn in_guest(self: Box<Self>) {
            let listener = socket(
                AddressFamily::Vsock,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .unwrap();
            bind(
                listener.as_raw_fd(),
                &VsockAddr::new(nix::libc::VMADDR_CID_ANY, ACCEPT_PORT),
            )
            .unwrap();
            listen(&listener, Backlog::new(4).unwrap()).unwrap();

            let mut control = vsock_connect(CONTROL_PORT);

            let mut bulk = accept_stream(&listener);
            let writer = thread::spawn(move || {
                let data: Vec<u8> = (0..BULK_LEN).map(byte_at).collect();
                bulk.write_all(&data).unwrap();
            });

            let mut ping = accept_stream(&listener);
            ping.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            let mut byte = [0];
            ping.read_exact(&mut byte).unwrap();
            ping.write_all(b"pong").unwrap();

            writer.join().unwrap();

            let mut status = [0];
            control.read_exact(&mut status).unwrap();
            control.write_all(&[1]).unwrap();
            assert_eq!(
                status,
                [1],
                "host got no answer on a second connection, or a corrupted stream"
            );
            println!("OK");
        }
    }
}
