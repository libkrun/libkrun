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
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;
    use std::thread;

    use crate::common::{build_init_config, setup_standard_devices};
    use crate::{Test, TestSetup};

    impl Test for TestTsiTcpGuestListen {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            thread::spawn(move || {
                self.tcp_tester.run_client();
            });

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::HIJACK_INET)
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
