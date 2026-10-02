//! Unified virtio-net integration tests
//!
//! All tests follow the same pattern:
//! 1. Host: Start backend + TCP server
//! 2. Guest: Connect to host TCP server (eth0 configured via DHCP by init)

use crate::tcp_tester::TcpTester;
use macros::{guest, host};

#[host]
use crate::{ShouldRun, TestSetup};

// TODO: export this via ffier from libkrun and use the generated constant instead
#[cfg(feature = "host")]
pub(crate) const COMPAT_NET_FEATURES: u32 = (1 << 0)  // CSUM
    | (1 << 1)  // GUEST_CSUM
    | (1 << 7)  // GUEST_TSO4
    | (1 << 10) // GUEST_UFO
    | (1 << 11) // HOST_TSO4
    | (1 << 14); // HOST_UFO

#[cfg(feature = "host")]
pub(crate) mod gvproxy;
#[cfg(feature = "host")]
pub(crate) mod passt;
#[cfg(all(feature = "host", target_os = "linux"))]
pub(crate) mod passt_vhost_user;
#[cfg(feature = "host")]
pub(crate) mod tap;
#[cfg(feature = "host")]
pub(crate) mod vmnet_helper;

/// Virtio-net test with configurable backend
pub struct TestNet {
    tcp_tester: TcpTester,
    test_bulk: bool,
    #[cfg(feature = "host")]
    should_run: fn() -> ShouldRun,
    #[cfg(feature = "host")]
    setup_backend: fn(&TestSetup) -> anyhow::Result<krun::NetDevice>,
    #[cfg(feature = "host")]
    cleanup: Option<fn()>,
}

impl TestNet {
    pub fn new_passt() -> Self {
        Self {
            test_bulk: false,
            tcp_tester: TcpTester::new([169, 254, 2, 2].into(), 9000),
            #[cfg(feature = "host")]
            should_run: passt::should_run,
            #[cfg(feature = "host")]
            setup_backend: passt::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn new_passt_vhost_user(path: bool) -> Self {
        #[cfg(not(feature = "host"))]
        let _ = path;
        Self {
            test_bulk: true,
            #[cfg(feature = "host")]
            should_run: passt_vhost_user::should_run,
            #[cfg(feature = "host")]
            setup_backend: if path {
                passt_vhost_user::setup_path
            } else {
                passt_vhost_user::setup_fd
            },
            ..Self::new_passt()
        }
    }

    pub fn new_tap() -> Self {
        Self {
            test_bulk: false,
            tcp_tester: TcpTester::new([10, 0, 0, 1].into(), 9001),
            #[cfg(feature = "host")]
            should_run: tap::should_run,
            #[cfg(feature = "host")]
            setup_backend: tap::setup_backend,
            #[cfg(feature = "host")]
            cleanup: Some(tap::cleanup),
        }
    }

    pub fn new_gvproxy() -> Self {
        Self {
            test_bulk: false,
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9002),
            #[cfg(feature = "host")]
            should_run: gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: gvproxy::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_vmnet_helper() -> Self {
        Self {
            test_bulk: false,
            tcp_tester: TcpTester::new([192, 168, 105, 1].into(), 9003),
            #[cfg(feature = "host")]
            should_run: vmnet_helper::should_run,
            #[cfg(feature = "host")]
            setup_backend: vmnet_helper::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    /// Gvproxy backend variant with a socket path ≥ 96 bytes, triggering the
    /// ENAMETOOLONG bug when the local socket was derived from the peer path.
    pub fn new_gvproxy_long_path() -> Self {
        Self {
            test_bulk: false,
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9004),
            #[cfg(feature = "host")]
            should_run: gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: gvproxy::setup_backend_long_path,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::{init_config_builder, init_krun, setup_standard_devices_from};
    use crate::{Test, TestOutcome, TestSetup};
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunNetDeviceNewUnixgramPath,
                krun::Symbol::KrunNetDeviceNewUnixgramFd,
                krun::Symbol::KrunNetDeviceNewUnixstreamPath,
                krun::Symbol::KrunNetDeviceNewUnixstreamFd,
                krun::Symbol::KrunNetDeviceNewTap,
                krun::Symbol::KrunNetDeviceDestroy,
            ],
        )
    }

    impl Test for TestNet {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            (self.should_run)()
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            if let Some(cleanup) = self.cleanup {
                cleanup();
            }
            let output = String::from_utf8(stdout).unwrap();
            if output == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!("expected exactly {:?}, got {:?}", "OK\n", output))
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            if self.test_bulk {
                let listener = TcpListener::bind(("0.0.0.0", 9005))?;
                thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut buffer = [0; 65536];
                    for _ in 0..64 {
                        stream.read_exact(&mut buffer).unwrap();
                        stream.write_all(&buffer).unwrap();
                    }
                });
                let socket = UdpSocket::bind(("0.0.0.0", 9000))?;
                thread::spawn(move || {
                    let mut buffer = [0; 65536];
                    while let Ok((len, peer)) = socket.recv_from(&mut buffer) {
                        socket.send_to(&buffer[..len], peer).unwrap();
                    }
                });
            }
            let tcp_tester = self.tcp_tester;
            let listener = tcp_tester.create_server_socket();
            thread::spawn(move || tcp_tester.run_server(listener));

            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let init_config = init_config_builder(&test_setup, &[]).dhcp(true).build();
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices_from(&test_setup, &init_config, &stdin, &stdout, &stderr)?;

            let net_device = (self.setup_backend)(&test_setup)?;
            devices.add(net_device);

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
    use std::io::{Read, Write};
    use std::net::{TcpStream, UdpSocket};
    use std::time::Duration;

    impl Test for TestNet {
        fn in_guest(self: Box<Self>) {
            self.tcp_tester.run_client();
            if self.test_bulk {
                let socket = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket.connect(("169.254.2.2", 9000)).unwrap();
                for size in [0, 1, 1400, 60000] {
                    let payload = vec![0xa5; size];
                    socket.send(&payload).unwrap();
                    let mut received = vec![0; 65536];
                    let len = socket.recv(&mut received).unwrap();
                    assert_eq!(&received[..len], &payload);
                }
                let mut stream = TcpStream::connect(("169.254.2.2", 9005)).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut received = [0; 65536];
                for pattern in 0..64 {
                    let payload = [pattern; 65536];
                    stream.write_all(&payload).unwrap();
                    stream.read_exact(&mut received).unwrap();
                    assert_eq!(received, payload);
                }
            }

            println!("OK");
        }
    }
}
