use macros::{guest, host};
use std::net::Ipv4Addr;
use std::time::Duration;

pub struct TestTsiTcpHalfClose;

const DATA_PORT: u16 = 8002;
const STATUS_PORT: u16 = 8003;
const READY: u8 = 1;
const EXCHANGES: [(usize, usize); 3] = [(17, 17), (256 * 1024, 256 * 1024), (0, 17)];
const IO_TIMEOUT: Duration = Duration::from_secs(3);

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
    use std::net::{Shutdown, SocketAddrV4, TcpStream};
    use std::thread;
    use std::time::Instant;

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
                krun::Symbol::KrunVsockDeviceAddPortForward,
            ],
        )
    }

    fn connect_ready() -> anyhow::Result<TcpStream> {
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, DATA_PORT);
        let deadline = Instant::now() + Duration::from_secs(10);

        loop {
            if let Ok(mut stream) = TcpStream::connect(addr) {
                stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                let mut ready = [0];
                if stream.read_exact(&mut ready).is_ok() {
                    ensure!(ready == [READY], "unexpected server greeting: {ready:?}");
                    stream.set_read_timeout(Some(IO_TIMEOUT))?;
                    stream.set_write_timeout(Some(IO_TIMEOUT))?;
                    return Ok(stream);
                }
            }

            ensure!(
                Instant::now() < deadline,
                "guest server did not become ready"
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn run_client() -> anyhow::Result<()> {
        for (index, (request_len, response_len)) in EXCHANGES.into_iter().enumerate() {
            let mut stream = connect_ready().context("connect to guest server")?;
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
                started.elapsed() < Duration::from_secs(5),
                "reply and EOF took at least five seconds"
            );
            ensure!(
                response == payload((index as u8).wrapping_add(128), response_len),
                "incorrect reply for exchange {index}"
            );
        }

        Ok(())
    }

    fn report_result() {
        let status = match run_client() {
            Ok(()) => 1,
            Err(error) => {
                eprintln!("half-close client failed: {error:#}");
                0
            }
        };

        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, STATUS_PORT);
        let mut stream = TcpStream::connect(addr).expect("connect to guest status listener");
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.write_all(&[status]).expect("send guest test status");
        let mut acknowledged = [0];
        stream
            .read_exact(&mut acknowledged)
            .expect("receive guest test status acknowledgment");
        assert_eq!(acknowledged, [1]);
    }

    impl Test for TestTsiTcpHalfClose {
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
            thread::spawn(report_result);

            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::HIJACK_INET)
                .map_err(|error| anyhow::anyhow!("VsockDevice: {error:?}"))?;
            vsock
                .add_port_forward(&format!("{DATA_PORT}:{DATA_PORT}"))
                .map_err(|error| anyhow::anyhow!("add_port_forward: {error:?}"))?;
            vsock
                .add_port_forward(&format!("{STATUS_PORT}:{STATUS_PORT}"))
                .map_err(|error| anyhow::anyhow!("add_port_forward: {error:?}"))?;
            devices.add(vsock);

            let vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|error| anyhow::anyhow!("vcpus: {error:?}"))?
                .ram_mib(512)
                .map_err(|error| anyhow::anyhow!("ram_mib: {error:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|error| anyhow::anyhow!("build: {error:?}"))?;

            vmm.run();
            unreachable!()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddrV4, TcpListener};

    use crate::Test;

    impl Test for TestTsiTcpHalfClose {
        fn in_guest(self: Box<Self>) {
            let data_listener =
                TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DATA_PORT)).unwrap();
            let status_listener =
                TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, STATUS_PORT)).unwrap();

            let mut completed = 0;
            while completed < EXCHANGES.len() {
                let (mut stream, _) = data_listener.accept().unwrap();
                stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
                if stream.write_all(&[READY]).is_err() {
                    continue;
                }

                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                if completed == 0 && request.is_empty() {
                    continue;
                }

                let (request_len, response_len) = EXCHANGES[completed];
                assert_eq!(request, payload(completed as u8, request_len));
                stream
                    .write_all(&payload((completed as u8).wrapping_add(128), response_len))
                    .unwrap();
                completed += 1;
            }

            let (mut status, _) = status_listener.accept().unwrap();
            status.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            let mut result = [0];
            status.read_exact(&mut result).unwrap();
            status.write_all(&[1]).unwrap();
            assert_eq!(
                result,
                [1],
                "host did not receive the complete reply and EOF"
            );
            println!("OK");
        }
    }
}
