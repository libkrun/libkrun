//! iperf3-based performance tests for virtio-net backends
//!
//! Each test:
//! 1. Host: Start iperf3 server + network backend
//! 2. Guest: Run iperf3 client (eth0 configured via DHCP by init)
//! 3. Host: Parse iperf3 JSON output, produce markdown report
//!
//! Tests are parametrized by backend and direction (TX = guest→host, RX = host→guest).

use macros::{guest, host};

/// Virtio-net performance test with configurable backend and direction
pub struct TestNetPerf {
    #[cfg(feature = "guest")]
    host_ip: [u8; 4],
    port: u16,
    /// If true, run iperf3 with -R (reverse: server sends, client receives = RX)
    reverse: bool,
    #[cfg(feature = "host")]
    backend: Box<dyn crate::test_net::NetBackend>,
}

impl TestNetPerf {
    fn new_perf(
        host_ip: [u8; 4],
        port: u16,
        reverse: bool,
        #[cfg(feature = "host")] backend: Box<dyn crate::test_net::NetBackend>,
    ) -> Self {
        let _ = host_ip; // used only in guest builds
        Self {
            #[cfg(feature = "guest")]
            host_ip,
            port,
            reverse,
            #[cfg(feature = "host")]
            backend,
        }
    }

    pub fn new_passt_tx() -> Self {
        Self::new_perf(
            [169, 254, 2, 2],
            15100,
            false,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::passt::Passt),
        )
    }

    pub fn new_passt_rx() -> Self {
        Self::new_perf(
            [169, 254, 2, 2],
            15110,
            true,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::passt::Passt),
        )
    }

    pub fn new_tap_tx() -> Self {
        Self::new_perf(
            [10, 0, 0, 1],
            15101,
            false,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::tap::Tap),
        )
    }

    pub fn new_tap_rx() -> Self {
        Self::new_perf(
            [10, 0, 0, 1],
            15111,
            true,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::tap::Tap),
        )
    }

    pub fn new_gvproxy_tx() -> Self {
        Self::new_perf(
            [192, 168, 127, 254],
            15102,
            false,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::gvproxy::GvproxyBackend),
        )
    }

    pub fn new_gvproxy_rx() -> Self {
        Self::new_perf(
            [192, 168, 127, 254],
            15112,
            true,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::gvproxy::GvproxyBackend),
        )
    }

    pub fn new_vhost_user_passt_tx() -> Self {
        Self::new_perf(
            [169, 254, 2, 2],
            15104,
            false,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::vhost_user_passt::VhostUserPasst),
        )
    }

    pub fn new_vhost_user_passt_rx() -> Self {
        Self::new_perf(
            [169, 254, 2, 2],
            15114,
            true,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::vhost_user_passt::VhostUserPasst),
        )
    }

    pub fn new_vmnet_helper_tx() -> Self {
        Self::new_perf(
            [192, 168, 105, 1],
            15103,
            false,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::vmnet_helper::VmnetHelper),
        )
    }

    pub fn new_vmnet_helper_rx() -> Self {
        Self::new_perf(
            [192, 168, 105, 1],
            15113,
            true,
            #[cfg(feature = "host")]
            Box::new(crate::test_net::vmnet_helper::VmnetHelper),
        )
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter_with_env;
    use crate::{ShouldRun, Test, TestOutcome, TestSetup, krun_call, krun_call_u32};
    use krun_sys::*;
    use std::os::fd::AsRawFd;
    use std::process::{Child, Command, Stdio};

    const CONTAINERFILE: &str = "\
FROM fedora:43
RUN dnf install -y iperf3 && dnf clean all
";

    fn iperf3_available() -> bool {
        Command::new("iperf3")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn start_iperf_server(port: u16) -> std::io::Result<Child> {
        Command::new("iperf3")
            .arg("-s")
            .arg("-p")
            .arg(port.to_string())
            .arg("-1") // one-off: exit after first client
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }

    #[derive(serde::Deserialize)]
    struct Iperf3Output {
        intervals: Vec<Iperf3Interval>,
        end: Iperf3End,
    }

    #[derive(serde::Deserialize)]
    struct Iperf3Interval {
        sum: Iperf3Sum,
    }

    #[derive(serde::Deserialize)]
    struct Iperf3End {
        sum_sent: Iperf3Sum,
        sum_received: Iperf3Sum,
    }

    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct Iperf3Sum {
        start: f64,
        end: f64,
        seconds: f64,
        bytes: f64,
        bits_per_second: f64,
    }

    struct Iperf3Report {
        output: Iperf3Output,
        reverse: bool,
    }

    impl Iperf3Report {
        fn label(&self) -> &'static str {
            if self.reverse {
                "RX (host→guest)"
            } else {
                "TX (guest→host)"
            }
        }

        fn summary(&self) -> &Iperf3Sum {
            if self.reverse {
                &self.output.end.sum_received
            } else {
                &self.output.end.sum_sent
            }
        }
    }

    fn fmt_throughput(bits_per_second: f64) -> String {
        if bits_per_second >= 1_000_000_000.0 {
            format!("{:.2} Gbit/s", bits_per_second / 1_000_000_000.0)
        } else {
            format!("{:.2} Mbit/s", bits_per_second / 1_000_000.0)
        }
    }

    fn fmt_transferred(bytes: f64) -> String {
        if bytes >= 1024.0 * 1024.0 * 1024.0 {
            format!("{:.2} GiB", bytes / (1024.0 * 1024.0 * 1024.0))
        } else {
            format!("{:.2} MiB", bytes / (1024.0 * 1024.0))
        }
    }

    impl crate::ReportImpl for Iperf3Report {
        fn fmt_text(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let i = f.width().unwrap_or(0);
            writeln!(f, "{:i$}iperf3 — {}\n", "", self.label())?;
            writeln!(
                f,
                "{:i$}{:<9}  {:>18}  {:>14}",
                "", "Interval", "Throughput", "Transferred"
            )?;
            writeln!(f, "{:i$}{:-<9}  {:-<18}  {:-<14}", "", "", "", "")?;
            for interval in &self.output.intervals {
                let s = &interval.sum;
                let iv = format!("{:.0}-{:.0}s", s.start, s.end);
                writeln!(
                    f,
                    "{:i$}{:<9}  {:>18}  {:>14}",
                    "",
                    iv,
                    fmt_throughput(s.bits_per_second),
                    fmt_transferred(s.bytes),
                )?;
            }
            let s = self.summary();
            writeln!(f, "{:i$}{:-<9}  {:-<18}  {:-<14}", "", "", "", "")?;
            write!(
                f,
                "{:i$}{:<9}  {:>18}  {:>14}",
                "",
                "Total",
                fmt_throughput(s.bits_per_second),
                fmt_transferred(s.bytes),
            )
        }

        fn fmt_gh_markdown(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f, "### iperf3 — {}\n", self.label())?;
            writeln!(f, "| Interval | Throughput | Transferred |")?;
            writeln!(f, "|----------|-----------|-------------|")?;
            for interval in &self.output.intervals {
                let s = &interval.sum;
                writeln!(
                    f,
                    "| {:.0}-{:.0}s | {} | {} |",
                    s.start,
                    s.end,
                    fmt_throughput(s.bits_per_second),
                    fmt_transferred(s.bytes),
                )?;
            }
            let s = self.summary();
            write!(
                f,
                "| **Total** | **{}** | **{}** |",
                fmt_throughput(s.bits_per_second),
                fmt_transferred(s.bytes),
            )
        }
    }

    impl Test for TestNetPerf {
        fn should_run(&self) -> ShouldRun {
            if option_env!("IPERF_DURATION").is_none() {
                return ShouldRun::No("IPERF_DURATION not set");
            }
            let backend_result = self.backend.should_run();
            if let ShouldRun::No(_) = backend_result {
                return backend_result;
            }
            if !iperf3_available() {
                return ShouldRun::No("iperf3 not installed on host");
            }
            ShouldRun::Yes
        }

        fn rootfs_image(&self) -> Option<&'static str> {
            Some(CONTAINERFILE)
        }

        fn timeout_secs(&self) -> u64 {
            let iperf_secs: u64 = option_env!("IPERF_DURATION")
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);
            // iperf duration + overhead for VM boot, retries, and network setup
            iperf_secs + 15
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Start iperf3 server on host (one-off, exits after first client)
            let iperf_server = start_iperf_server(self.port)?;
            test_setup.register_cleanup_pid(iperf_server.id());

            // Give iperf3 server a moment to start
            std::thread::sleep(std::time::Duration::from_millis(200));

            // Check it's still running
            let mut iperf_server = iperf_server;
            if let Some(status) = iperf_server.try_wait()? {
                anyhow::bail!("iperf3 server exited early: {status}");
            }

            unsafe {
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

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            self.backend.cleanup();
            let stdout = String::from_utf8_lossy(&stdout).to_string();

            match serde_json::from_str::<Iperf3Output>(&stdout) {
                Ok(iperf_output) => TestOutcome::Report(Box::new(Iperf3Report {
                    output: iperf_output,
                    reverse: self.reverse,
                })),
                Err(e) => TestOutcome::Fail(format!(
                    "expected valid iperf3 JSON, got error: {e}\nstdout: {stdout}"
                )),
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::process::Command;
    use std::time::Duration;

    impl Test for TestNetPerf {
        fn in_guest(self: Box<Self>) {
            let host_ip = format!(
                "{}.{}.{}.{}",
                self.host_ip[0], self.host_ip[1], self.host_ip[2], self.host_ip[3]
            );

            let Some(iperf_duration) = option_env!("IPERF_DURATION") else {
                unreachable!()
            };

            // Run iperf3 client with JSON output, retry up to 5 times
            let mut last_output = None;
            for attempt in 0..5 {
                if attempt > 0 {
                    std::thread::sleep(Duration::from_secs(2));
                }

                let mut cmd = Command::new("/usr/bin/iperf3");
                cmd.arg("-c")
                    .arg(&host_ip)
                    .arg("-p")
                    .arg(self.port.to_string())
                    .arg("-t")
                    .arg(iperf_duration)
                    .arg("-J");

                if self.reverse {
                    cmd.arg("-R");
                }

                let output = cmd.output().expect("Failed to run iperf3");

                if output.status.success() {
                    // Print JSON output to stdout (host will read it)
                    let stdout = String::from_utf8(output.stdout).expect("iperf3 output not UTF-8");
                    print!("{}", stdout);
                    return;
                }

                last_output = Some(output);
            }

            let output = last_output.unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "iperf3 failed after 5 attempts (exit={}):\nstderr: {}\nstdout: {}",
                output.status, stderr, stdout
            );
        }
    }
}
