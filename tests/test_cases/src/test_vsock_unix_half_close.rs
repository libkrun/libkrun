#![cfg(any(feature = "host", target_os = "linux"))]

//! The host side of a unix socket proxy sends a request, shuts down its write
//! side and expects the whole reply followed by EOF, the way the Docker CLI
//! talks to a daemon. This used to reset the connection as soon as the host's
//! EOF reached the proxy, so the guest could never answer. Both directions are
//! covered: the host connecting to a guest listener (`listen=true`) and the
//! guest connecting out to a host listener (`listen=false`).

use macros::{guest, host};
use std::time::Duration;

pub struct TestVsockUnixHalfClose;

/// The guest connects out on this port once its listener is bound, and the
/// host reports the outcome back on the same connection.
const CONTROL_PORT: u32 = 1234;
/// Registered with `listen=true`: the host connects, the guest accepts.
const ACCEPT_PORT: u32 = 1235;
/// Registered with `listen=false`: the guest connects, the host accepts.
const CONNECT_PORT: u32 = 1236;

const EXCHANGES: [(usize, usize); 3] = [(17, 17), (256 * 1024, 256 * 1024), (0, 17)];
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_add(seed))
        .collect()
}

#[host]
mod host {
    use super::*;
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;

    use anyhow::{Context, ensure};
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::thread;
    use std::time::Instant;

    use crate::common::{build_init_config, setup_standard_devices};
    use crate::{Test, TestSetup};

    /// Send the request, half-close it and read the reply up to EOF.
    fn exchange(mut stream: UnixStream, index: usize) -> anyhow::Result<()> {
        let (request_len, response_len) = EXCHANGES[index];
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        stream
            .write_all(&payload(index as u8, request_len))
            .context("send request")?;
        stream
            .shutdown(Shutdown::Write)
            .context("half-close request")?;

        let started = Instant::now();
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .context("receive reply and EOF")?;
        ensure!(
            started.elapsed() < IO_TIMEOUT,
            "reply and EOF took at least {IO_TIMEOUT:?}"
        );
        ensure!(
            response == payload((index as u8).wrapping_add(128), response_len),
            "incorrect reply for exchange {index}: {} bytes",
            response.len()
        );
        Ok(())
    }

    fn run_client(accept_sock: &Path, connect_listener: &UnixListener) -> anyhow::Result<()> {
        for index in 0..EXCHANGES.len() {
            let stream = UnixStream::connect(accept_sock).context("connect to guest")?;
            exchange(stream, index).with_context(|| format!("host-initiated exchange {index}"))?;
        }
        for index in 0..EXCHANGES.len() {
            let (stream, _) = connect_listener.accept().context("accept guest")?;
            exchange(stream, index).with_context(|| format!("guest-initiated exchange {index}"))?;
        }
        Ok(())
    }

    fn run(control_listener: UnixListener, accept_sock: &Path, connect_listener: UnixListener) {
        // Returns once the guest has bound its listener.
        let (mut control, _) = control_listener.accept().unwrap();

        let status = match run_client(accept_sock, &connect_listener) {
            Ok(()) => 1,
            Err(error) => {
                eprintln!("half-close client failed: {error:#}");
                0
            }
        };
        control.write_all(&[status]).unwrap();
        // Keep the connection open until the guest has read the status.
        let _ = control.read(&mut [0]);
    }

    impl Test for TestVsockUnixHalfClose {
        fn timeout_secs(&self) -> u64 {
            30
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let control_sock = test_setup.tmp_dir.join("control.sock");
            let accept_sock = test_setup.tmp_dir.join("accept.sock");
            let connect_sock = test_setup.tmp_dir.join("connect.sock");

            let control_listener = UnixListener::bind(&control_sock)?;
            let connect_listener = UnixListener::bind(&connect_sock)?;
            let accept_sock_clone = accept_sock.clone();
            thread::spawn(move || run(control_listener, &accept_sock_clone, connect_listener));

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
            vsock.add_unix_port(CONNECT_PORT, connect_sock.to_str().unwrap(), false);
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

    /// Read the request up to the host's EOF, then reply and close.
    fn serve(mut stream: UnixStream, index: usize) {
        let (request_len, response_len) = EXCHANGES[index];
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        assert_eq!(request, payload(index as u8, request_len));
        stream
            .write_all(&payload((index as u8).wrapping_add(128), response_len))
            .unwrap();
    }

    impl Test for TestVsockUnixHalfClose {
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

            for index in 0..EXCHANGES.len() {
                let fd = accept(listener.as_raw_fd()).unwrap();
                // Safe because we've just obtained the FD from the `accept` call above.
                let stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
                serve(stream, index);
            }
            for index in 0..EXCHANGES.len() {
                serve(vsock_connect(CONNECT_PORT), index);
            }

            let mut status = [0];
            control.read_exact(&mut status).unwrap();
            control.write_all(&[1]).unwrap();
            assert_eq!(
                status,
                [1],
                "host did not receive the complete replies and EOF"
            );
            println!("OK");
        }
    }
}
