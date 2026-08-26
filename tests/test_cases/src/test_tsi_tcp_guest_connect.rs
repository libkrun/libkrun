use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8000;

pub struct TestTsiTcpGuestConnect {
    tcp_tester: TcpTester,
}

impl TestTsiTcpGuestConnect {
    pub fn new() -> TestTsiTcpGuestConnect {
        Self {
            tcp_tester: TcpTester::new(Ipv4Addr::LOCALHOST, PORT),
        }
    }
}

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter;
    use crate::{Test, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::os::fd::AsRawFd;
    use std::thread;

    impl Test for TestTsiTcpGuestConnect {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // The guest connects to the host's own 127.0.0.1, which the default
            // egress floor now blocks. Opt back in so this test exercises the TSI
            // TCP connect path — and doubles as a check that the opt-in works.
            unsafe { std::env::set_var("SMOLVM_ALLOW_HOST_LOOPBACK", "1") };
            let listener = self.tcp_tester.create_server_socket();
            thread::spawn(move || self.tcp_tester.run_server(listener));
            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_add_vsock(ctx, KRUN_TSI_HIJACK_INET))?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
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

    impl Test for TestTsiTcpGuestConnect {
        fn in_guest(self: Box<Self>) {
            self.tcp_tester.run_client();
            println!("OK");
        }
    }
}
