use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8000;
// gvproxy's default NAT table maps HostIP (192.168.127.254) → 127.0.0.1 on the host.
// The gateway IP (192.168.127.1) is only virtual inside gvproxy's netstack and NOT
// reachable via net.Dial from the host — connecting to it gets a TCP RST.
const HOST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 254);

pub struct TestFreeBsdGvproxyTcpGuestConnect {
    tcp_tester: TcpTester,
}

impl TestFreeBsdGvproxyTcpGuestConnect {
    pub fn new() -> TestFreeBsdGvproxyTcpGuestConnect {
        Self {
            tcp_tester: TcpTester::new(HOST_IP, PORT),
        }
    }
}

#[host]
mod host {
    use super::*;

    use crate::common::init_krun;
    #[cfg(feature = "dynamic-linking")]
    use crate::common_freebsd::require_freebsd_symbols;
    use crate::common_freebsd::{
        freebsd_assets, normalize_serial_output, setup_gvproxy_backend, setup_kernel_and_enter,
    };
    use crate::test_net::gvproxy::gvproxy_path;
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use std::thread;

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        require_freebsd_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunNetDeviceNewUnixgramPath,
                krun::Symbol::KrunNetDeviceDestroy,
            ],
        )
    }

    impl Test for TestFreeBsdGvproxyTcpGuestConnect {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            if freebsd_assets().is_none() {
                return ShouldRun::No("freebsd assets missing");
            }
            match gvproxy_path() {
                Some(_) => ShouldRun::Yes,
                None => ShouldRun::No("gvproxy not installed"),
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let assets = freebsd_assets().expect("freebsd assets must be available");

            // Spawn host-side TCP server. Guest connects to HOST_IP:PORT through gvproxy.
            let listener = self.tcp_tester.create_server_socket();
            thread::spawn(move || self.tcp_tester.run_server(listener));

            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();
            let (_, net_device) = setup_gvproxy_backend(&test_setup)?;
            setup_kernel_and_enter(
                test_setup,
                assets,
                Some(Box::new(move |devices| {
                    devices.add(net_device);
                    Ok(())
                })),
            )
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let output_str = normalize_serial_output(stdout);
            if output_str == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!(
                    "expected exactly {:?}, got {:?}",
                    "OK\n", output_str
                ))
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use crate::freebsd_network::configure_virtio_net_ip;

    impl Test for TestFreeBsdGvproxyTcpGuestConnect {
        fn in_guest(self: Box<Self>) {
            configure_virtio_net_ip();
            self.tcp_tester.run_client();
            println!("OK");
        }
    }
}
