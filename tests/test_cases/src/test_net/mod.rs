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
#[cfg(feature = "host")]
pub(crate) mod tap;
#[cfg(all(feature = "host", target_os = "linux"))]
pub(crate) mod vhost_user_passt;
#[cfg(feature = "host")]
pub(crate) mod vmnet_helper;

/// Symbols needed by the in-process (non-vhost-user) net backends.
#[cfg(feature = "dynamic-linking")]
pub(crate) fn require_net_symbols() -> Result<(), libloading::Error> {
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

/// Backend-specific behavior for a virtio-net test.
///
/// Each backend (passt, tap, gvproxy, vhost-user, ...) implements this trait.
/// The generic `TestNet` and `TestNetPerf` structs hold a `Box<dyn NetBackend>`
/// and delegate backend-specific work to it.
#[host]
pub(crate) trait NetBackend {
    /// Check if this backend can run on the current system.
    fn should_run(&self) -> ShouldRun;

    /// Create this backend's network device and add it to the device manager.
    ///
    /// Takes the manager directly because backends produce different device
    /// types (e.g. `NetDevice` vs `VhostUserDevice`).
    fn setup_backend(
        &self,
        devices: &mut krun::MmioDeviceManager<'_>,
        test_setup: &TestSetup,
    ) -> anyhow::Result<()>;

    /// Optional cleanup after the test (e.g. removing persistent TAP devices).
    fn cleanup(&self) {}

    /// Whether the guest must run DHCP to get an address. In-process net
    /// backends do this automatically; vhost-user backends do not.
    fn guest_dhcp(&self) -> bool {
        true
    }

    /// Ensure the libkrun symbols this backend needs are available.
    ///
    /// With static linking a missing feature is a compile error, so this is a
    /// no-op. With dynamic linking it loads the symbols via dlsym.
    #[cfg(feature = "dynamic-linking")]
    fn require_symbols(&self) -> Result<(), libloading::Error> {
        Ok(())
    }
}

/// Virtio-net test with configurable backend
pub struct TestNet {
    tcp_tester: TcpTester,
    #[cfg(feature = "host")]
    backend: Box<dyn NetBackend>,
}

impl TestNet {
    pub fn new_passt() -> Self {
        Self {
            tcp_tester: TcpTester::new([169, 254, 2, 2].into(), 9000),
            #[cfg(feature = "host")]
            backend: Box::new(passt::Passt),
        }
    }

    pub fn new_tap() -> Self {
        Self {
            tcp_tester: TcpTester::new([10, 0, 0, 1].into(), 9001),
            #[cfg(feature = "host")]
            backend: Box::new(tap::Tap),
        }
    }

    pub fn new_gvproxy() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9002),
            #[cfg(feature = "host")]
            backend: Box::new(gvproxy::GvproxyBackend { long_path: false }),
        }
    }

    pub fn new_vmnet_helper() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 105, 1].into(), 9003),
            #[cfg(feature = "host")]
            backend: Box::new(vmnet_helper::VmnetHelper),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn new_vhost_user_passt() -> Self {
        Self {
            tcp_tester: TcpTester::new([169, 254, 2, 2].into(), 9005),
            #[cfg(feature = "host")]
            backend: Box::new(vhost_user_passt::VhostUserPasst),
        }
    }

    /// Gvproxy backend variant with a socket path ≥ 96 bytes, triggering the
    /// ENAMETOOLONG bug when the local socket was derived from the peer path.
    pub fn new_gvproxy_long_path() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9004),
            #[cfg(feature = "host")]
            backend: Box::new(gvproxy::GvproxyBackend { long_path: true }),
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::{init_config_builder, init_krun, setup_standard_devices_from};
    use crate::{Test, TestOutcome, TestSetup};

    use std::thread;

    impl Test for TestNet {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if self.backend.require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            self.backend.should_run()
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            self.backend.cleanup();
            let output = String::from_utf8(stdout).unwrap();
            if output == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!("expected exactly {:?}, got {:?}", "OK\n", output))
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Start TCP server
            let tcp_tester = self.tcp_tester;
            let listener = tcp_tester.create_server_socket();
            thread::spawn(move || tcp_tester.run_server(listener));

            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            self.backend.require_symbols().unwrap();

            let init_config = init_config_builder(&test_setup, &[])
                .dhcp(self.backend.guest_dhcp())
                .build();
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices_from(&test_setup, &init_config, &stdin, &stdout, &stderr)?;

            self.backend.setup_backend(&mut devices, &test_setup)?;

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

    impl Test for TestNet {
        fn in_guest(self: Box<Self>) {
            self.tcp_tester.run_client();

            println!("OK");
        }
    }
}
