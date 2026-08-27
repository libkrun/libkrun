use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8001;

pub struct TestTsiTcpGuestListen {
    tcp_tester: TcpTester,
}

impl TestTsiTcpGuestListen {
    pub fn new() -> Self {
        Self {
            tcp_tester: TcpTester::new(Ipv4Addr::LOCALHOST, PORT),
        }
    }
}

#[host]
mod host {
    use super::*;
    use std::thread;

    use crate::common::{init_krun, setup_standard_devices};
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

    const TSI_HIJACK_INET: u32 = 1;

    impl Test for TestTsiTcpGuestListen {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            thread::spawn(move || {
                self.tcp_tester.run_client();
            });

            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let (mut devices, payload) = setup_standard_devices(&test_setup, &[])?;
            let mut vsock = krun::VsockDevice::new(3, TSI_HIJACK_INET)
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock
                .add_port_forward(&format!("{PORT}:{PORT}"))
                .map_err(|e| anyhow::anyhow!("add_port_forward: {e:?}"))?;
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

    impl Test for TestTsiTcpGuestListen {
        fn in_guest(self: Box<Self>) {
            let listener = self.tcp_tester.create_server_socket();
            self.tcp_tester.run_server(listener);
            println!("OK");
        }
    }
}
