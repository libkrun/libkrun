//! Unified virtio-net integration tests
//!
//! All tests follow the same pattern:
//! 1. Host: Start backend + TCP server
//! 2. Guest: Connect to host TCP server (eth0 configured via DHCP by init)

use crate::tcp_tester::TcpTester;
use macros::{guest, host};

#[host]
use crate::{ShouldRun, TestSetup};

#[cfg(feature = "host")]
pub(crate) mod gvproxy;
#[cfg(feature = "host")]
pub(crate) mod passt;
#[cfg(feature = "host")]
pub(crate) mod tap;
#[cfg(feature = "host")]
pub(crate) mod vmnet_helper;

/// Virtio-net test with configurable backend
pub struct TestNet {
    tcp_tester: TcpTester,
    #[cfg(feature = "host")]
    should_run: fn() -> ShouldRun,
    #[cfg(feature = "host")]
    setup_backend: fn(u32, &TestSetup) -> anyhow::Result<()>,
    #[cfg(feature = "host")]
    cleanup: Option<fn()>,
}

impl TestNet {
    pub fn new_passt() -> Self {
        Self {
            tcp_tester: TcpTester::new([169, 254, 2, 2].into(), 9000),
            #[cfg(feature = "host")]
            should_run: passt::should_run,
            #[cfg(feature = "host")]
            setup_backend: passt::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_passt_off_subnet_gateway() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 0, 2, 1].into(), 9005),
            #[cfg(feature = "host")]
            should_run: passt::should_run,
            #[cfg(feature = "host")]
            setup_backend: passt::setup_backend_off_subnet_gateway,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_tap() -> Self {
        Self {
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
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestOutcome, TestSetup};
    use krun_sys::*;
    use std::thread;

    impl Test for TestNet {
        fn should_run(&self) -> ShouldRun {
            if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_NET.into())) }.ok() != Some(1)
            {
                return ShouldRun::No("libkrun compiled without NET");
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
            // Start TCP server
            let tcp_tester = self.tcp_tester;
            let listener = tcp_tester.create_server_socket();
            thread::spawn(move || tcp_tester.run_server(listener));

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;

                // Backend-specific setup
                (self.setup_backend)(ctx, &test_setup)?;

                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
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
