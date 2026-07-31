//! Unified virtio-net integration tests
//!
//! All tests follow the same pattern:
//! 1. Host: Start backend + TCP server
//! 2. Guest: Connect to host TCP server (eth0 configured via DHCP by init)

use crate::tcp_tester::TcpTester;
use macros::{guest, host};

#[host]
use nix::libc;

#[host]
use std::ffi::CString;

#[host]
use crate::{ShouldRun, TestSetup};

#[cfg(feature = "host")]
pub(crate) mod gvproxy;
#[cfg(feature = "host")]
pub(crate) mod passt;
#[cfg(feature = "host")]
pub(crate) mod tap;
#[cfg(feature = "host")]
pub(crate) mod vhost_user_passt;
#[cfg(feature = "host")]
pub(crate) mod vmnet_helper;

/// Backend-specific behavior for a virtio-net test.
///
/// Each backend (passt, tap, gvproxy, ...) implements this trait.
/// The generic `TestNet` and `TestNetPerf` structs hold a `Box<dyn NetBackend>`
/// and delegate backend-specific work to it.
#[host]
pub(crate) trait NetBackend {
    /// Check if this backend can run on the current system.
    fn should_run(&self) -> ShouldRun;

    /// Configure the network device on the VM context.
    fn setup_backend(&self, ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()>;

    /// Optional cleanup after the test (e.g. removing persistent TAP devices).
    fn cleanup(&self) {}

    /// Extra env vars for the guest init (kernel cmdline).
    /// Override this to e.g. pass `KRUN_DHCP=1` for vhost-user backends.
    fn guest_env(&self) -> &[&'static std::ffi::CStr] {
        &[]
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
            backend: Box::new(gvproxy::GvproxyBackend),
        }
    }

    pub fn new_vmnet_helper() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 105, 1].into(), 9003),
            #[cfg(feature = "host")]
            backend: Box::new(vmnet_helper::VmnetHelper),
        }
    }

    pub fn new_vhost_user_passt() -> Self {
        Self {
            tcp_tester: TcpTester::new([169, 254, 2, 2].into(), 9005),
            #[cfg(feature = "host")]
            backend: Box::new(vhost_user_passt::VhostUserPasst),
        }
    }

    /// Gvproxy backend variant with a socket path >= 96 bytes, triggering the
    /// ENAMETOOLONG bug when the local socket was derived from the peer path.
    pub fn new_gvproxy_long_path() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9004),
            #[cfg(feature = "host")]
            backend: Box::new(gvproxy::GvproxyLongPath),
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter_with_env;
    use crate::{Test, TestOutcome, TestSetup, krun_call, krun_call_u32};
    use krun_sys::*;
    use std::os::fd::AsRawFd;
    use std::thread;

    impl Test for TestNet {
        fn should_run(&self) -> ShouldRun {
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

            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;

                // Backend-specific setup
                self.backend.setup_backend(ctx, &test_setup)?;

                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
                setup_fs_and_enter_with_env(ctx, test_setup, self.backend.guest_env())?;
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

#[cfg(feature = "host")]
type KrunAddNetUnixgramFn = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const std::ffi::c_char,
    fd: i32,
    c_mac: *mut u8,
    features: u32,
    flags: u32,
) -> i32;

#[cfg(feature = "host")]
pub(crate) fn get_krun_add_net_unixgram() -> KrunAddNetUnixgramFn {
    let symbol = CString::new("krun_add_net_unixgram").unwrap();
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    assert!(!ptr.is_null(), "krun_add_net_unixgram not found");
    unsafe { std::mem::transmute(ptr) }
}
