#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

pub struct TestVsockHostConnectRefused;

/// The guest connects out on this port, which tells the host that the guest's
/// vsock stack is up and a request to an unbound port will be answered.
const READY_PORT: u32 = 1234;

/// Registered with `listen=true`, but nothing in the guest ever binds it, so the
/// guest replies OP_RST to libkrun's OP_REQUEST.
const REFUSED_PORT: u32 = 1235;

/// The RST arrives within a few milliseconds. libkrun used to keep the accepted
/// host socket inside a proxy awaiting the vsock reaper's 5s TTL, so the host's
/// read() only returned once that expired.
const MAX_REFUSE_MS: u128 = 1000;

const PROBE_PREFIX: &str = "PROBE ";
const REFUSED: &str = "refused";

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{Test, TestOutcome, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::prelude::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use std::{mem, thread};

    const SOCKET_WAIT: Duration = Duration::from_secs(10);
    const READ_TIMEOUT: Duration = Duration::from_secs(10);

    /// Time a connect+read against a port no guest process listens on. Reports
    /// the outcome on stdout so `check` can assert on it.
    fn probe(sock_path: &Path) -> String {
        let deadline = Instant::now() + SOCKET_WAIT;
        while !sock_path.exists() {
            if Instant::now() > deadline {
                return format!("{PROBE_PREFIX}no-socket 0");
            }
            thread::sleep(Duration::from_millis(10));
        }

        let mut stream = match UnixStream::connect(sock_path) {
            Ok(stream) => stream,
            Err(e) => return format!("{PROBE_PREFIX}connect-error-{} 0", e.kind()),
        };
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

        let start = Instant::now();
        let outcome = match stream.read(&mut [0u8; 1]) {
            Ok(0) => REFUSED.to_string(),
            Ok(n) => format!("unexpected-data-{n}"),
            Err(e) => format!("read-error-{}", e.kind()),
        };

        format!("{PROBE_PREFIX}{outcome} {}", start.elapsed().as_millis())
    }

    fn run(listener: UnixListener, refused_sock: PathBuf) {
        // Returns once the guest has connected, so its vsock stack is up.
        let (mut ready, _addr) = listener.accept().unwrap();

        let mut line = probe(&refused_sock);
        line.push('\n');
        std::io::stdout().write_all(line.as_bytes()).unwrap();

        // Release the guest only after the probe line is out, so it cannot
        // interleave with the guest's console output.
        ready.write_all(b"go").unwrap();

        // Leak the socket fd, to make sure it is not closed early when we exit the thread
        mem::forget(ready);
    }

    impl Test for TestVsockHostConnectRefused {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let ready_sock = test_setup.tmp_dir.join("ready.sock");
            let ready_cstr = CString::new(ready_sock.as_os_str().as_bytes())?;
            // libkrun binds this one itself, so it must not exist yet.
            let refused_sock = test_setup.tmp_dir.join("refused.sock");
            let refused_cstr = CString::new(refused_sock.as_os_str().as_bytes())?;

            let listener = UnixListener::bind(&ready_sock)?;
            thread::spawn(move || run(listener, refused_sock));

            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_add_vsock(ctx, 0))?;
                krun_call!(krun_add_vsock_port(ctx, READY_PORT, ready_cstr.as_ptr()))?;
                krun_call!(krun_add_vsock_port2(
                    ctx,
                    REFUSED_PORT,
                    refused_cstr.as_ptr(),
                    true
                ))?;
                krun_call!(krun_set_vm_config(ctx, 1, 1024))?;
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

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let stdout = String::from_utf8_lossy(&stdout);

            if !stdout.lines().any(|line| line.trim() == "OK") {
                return TestOutcome::Fail(format!("guest did not report OK, stdout: {stdout:?}"));
            }

            let Some(probe) = stdout
                .lines()
                .find_map(|l| l.trim().strip_prefix(PROBE_PREFIX))
            else {
                return TestOutcome::Fail(format!("no probe result, stdout: {stdout:?}"));
            };
            let Some((outcome, elapsed_ms)) = probe.split_once(' ') else {
                return TestOutcome::Fail(format!("malformed probe result: {probe:?}"));
            };
            let Ok(elapsed_ms) = elapsed_ms.parse::<u128>() else {
                return TestOutcome::Fail(format!("malformed probe result: {probe:?}"));
            };

            if outcome != REFUSED {
                return TestOutcome::Fail(format!(
                    "expected the connection to be refused, got {outcome:?}"
                ));
            }
            if elapsed_ms > MAX_REFUSE_MS {
                return TestOutcome::Fail(format!(
                    "connecting to a port no guest process listens on took {elapsed_ms}ms to be \
                     refused, limit is {MAX_REFUSE_MS}ms: libkrun is holding the host socket open \
                     until the vsock reaper reclaims the proxy"
                ));
            }

            TestOutcome::Pass
        }

        fn timeout_secs(&self) -> u64 {
            30
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::libc::VMADDR_CID_HOST;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, connect, socket};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    impl Test for TestVsockHostConnectRefused {
        fn in_guest(self: Box<Self>) {
            let sock = socket(
                AddressFamily::Vsock,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .unwrap();
            let addr = VsockAddr::new(VMADDR_CID_HOST, READY_PORT);
            connect(sock.as_raw_fd(), &addr).unwrap();
            let mut stream = UnixStream::from(sock);

            // Nothing here ever binds REFUSED_PORT: the host probes it while we
            // wait, and releases us once it has its answer.
            stream.read_exact(&mut [0u8; 2]).unwrap();

            println!("OK");
        }
    }
}
