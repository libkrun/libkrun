#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

pub struct TestVsockHostConnectRefused;

/// The guest connects out on this port, which tells the host that the guest's
/// vsock stack is up and a request to an unbound port will be answered.
const READY_PORT: u32 = 1234;

#[host]
mod host {
    use super::*;
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use std::{mem, thread};

    use crate::common::{build_init_config, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunVsockDeviceNew,
                krun::Symbol::KrunVsockDeviceDestroy,
                krun::Symbol::KrunVsockDeviceAddUnixPort,
            ],
        )
    }

    /// Registered with `listen=true`, but nothing in the guest ever binds it, so
    /// the guest replies OP_RST to libkrun's OP_REQUEST.
    const REFUSED_PORT: u32 = 1235;

    /// The RST arrives within a few milliseconds. libkrun used to keep the
    /// accepted host socket inside a proxy awaiting the vsock reaper's 5s TTL, so
    /// the host's read() only returned once that expired.
    const MAX_REFUSE_MS: u128 = 1000;

    const PROBE_PREFIX: &str = "PROBE ";
    const REFUSED: &str = "refused";

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
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let ready_sock = test_setup.tmp_dir.join("ready.sock");
            let refused_sock = test_setup.tmp_dir.join("refused.sock");

            let listener = UnixListener::bind(&ready_sock)?;
            let refused_sock_clone = refused_sock.clone();
            thread::spawn(move || run(listener, refused_sock_clone));

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::empty())
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock.add_unix_port(READY_PORT, ready_sock.to_str().unwrap(), false);
            vsock.add_unix_port(REFUSED_PORT, refused_sock.to_str().unwrap(), true);
            devices.add(vsock);

            let vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(1024)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("build: {e:?}"))?;

            vmm.run();
            unreachable!()
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
