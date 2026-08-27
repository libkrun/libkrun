use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8000;

pub struct TestFreeBsdGvproxyTcpGuestListen {
    tcp_tester: TcpTester,
}

impl TestFreeBsdGvproxyTcpGuestListen {
    pub fn new() -> TestFreeBsdGvproxyTcpGuestListen {
        // The host-side client connects to 127.0.0.1:PORT — gvproxy's port-forward
        // rule maps that to GUEST_IP:PORT inside the virtual network.
        Self {
            tcp_tester: TcpTester::new(Ipv4Addr::new(127, 0, 0, 1), PORT),
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
    use crate::test_net::gvproxy::{gvproxy_path, setup_gvproxy_port_forward};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use std::net::Ipv4Addr;
    use std::thread;

    // Virtual IP assigned to the guest inside gvproxy's network.
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);

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

    impl Test for TestFreeBsdGvproxyTcpGuestListen {
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

            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();
            let (net_sock, net_device) = setup_gvproxy_backend(&test_setup)?;

            // Set up port-forwarding: host :PORT → guest GUEST_IP:PORT.
            // The guest IP (192.168.127.2) is virtual and not reachable directly from
            // the host; gvproxy's forwarder bridges the gap.
            setup_gvproxy_port_forward(&net_sock, PORT, GUEST_IP)?;

            // Spawn host-side client. Runs concurrently with the VM; retries
            // connect+first-read until the guest is listening (see TcpTester::run_client).
            let tcp_tester = self.tcp_tester;
            thread::spawn(move || {
                tcp_tester.run_client();
            });

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

    impl Test for TestFreeBsdGvproxyTcpGuestListen {
        fn in_guest(self: Box<Self>) {
            configure_virtio_net_ip();
            self.tcp_tester
                .run_server(self.tcp_tester.create_server_socket());
            println!("OK");
        }
    }
}
