//! iperf3-based performance tests for virtio-net backends
//!
//! Each test:
//! 1. Host: Start iperf3 server + network backend
//! 2. Guest: Run iperf3 client (eth0 configured via DHCP by init)
//! 3. Host: Parse iperf3 JSON output, produce markdown report
//!
//! Tests are parametrized by backend and direction (TX = guest→host, RX = host→guest).

use macros::{guest, host};

#[host]
use crate::{ShouldRun, TestSetup};

/// Virtio-net performance test with configurable backend and direction
pub struct TestNetPerf {
    #[cfg(feature = "guest")]
    host_ip: [u8; 4],
    port: u16,
    /// If true, run iperf3 with -R (reverse: server sends, client receives = RX)
    reverse: bool,
    #[cfg(feature = "host")]
    should_run: fn() -> ShouldRun,
    #[cfg(feature = "host")]
    setup_backend: fn(&TestSetup) -> anyhow::Result<krun::NetDevice>,
    #[cfg(feature = "host")]
    cleanup: Option<fn()>,
}

impl TestNetPerf {
    pub fn new_passt_tx() -> Self {
        Self {
            #[cfg(feature = "guest")]
            host_ip: [169, 254, 2, 2],
            port: 15100,
            reverse: false,
            #[cfg(feature = "host")]
            should_run: crate::test_net::passt::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::passt::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_passt_rx() -> Self {
        Self {
            #[cfg(feature = "guest")]
            host_ip: [169, 254, 2, 2],
            port: 15110,
            reverse: true,
            #[cfg(feature = "host")]
            should_run: crate::test_net::passt::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::passt::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_tap_tx() -> Self {
        Self {
            #[cfg(feature = "guest")]
            host_ip: [10, 0, 0, 1],
            port: 15101,
            reverse: false,
            #[cfg(feature = "host")]
            should_run: crate::test_net::tap::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::tap::setup_backend,
            #[cfg(feature = "host")]
            cleanup: Some(crate::test_net::tap::cleanup),
        }
    }

    pub fn new_tap_rx() -> Self {
        Self {
            #[cfg(feature = "guest")]
            host_ip: [10, 0, 0, 1],
            port: 15111,
            reverse: true,
            #[cfg(feature = "host")]
            should_run: crate::test_net::tap::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::tap::setup_backend,
            #[cfg(feature = "host")]
            cleanup: Some(crate::test_net::tap::cleanup),
        }
    }

    pub fn new_gvproxy_tx() -> Self {
        Self {
            #[cfg(feature = "guest")]
            host_ip: [192, 168, 127, 254],
            port: 15102,
            reverse: false,
            #[cfg(feature = "host")]
            should_run: crate::test_net::gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::gvproxy::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_gvproxy_rx() -> Self {
        Self {
            #[cfg(feature = "guest")]
            host_ip: [192, 168, 127, 254],
            port: 15112,
            reverse: true,
            #[cfg(feature = "host")]
            should_run: crate::test_net::gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::gvproxy::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_vmnet_helper_tx() -> Self {
        Self {
            #[cfg(feature = "guest")]
            host_ip: [192, 168, 105, 1],
            port: 15103,
            reverse: false,
            #[cfg(feature = "host")]
            should_run: crate::test_net::vmnet_helper::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::vmnet_helper::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_vmnet_helper_rx() -> Self {
        Self {
            #[cfg(feature = "guest")]
            host_ip: [192, 168, 105, 1],
            port: 15113,
            reverse: true,
            #[cfg(feature = "host")]
            should_run: crate::test_net::vmnet_helper::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::vmnet_helper::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::{init_config_builder, init_krun, setup_standard_devices_from};

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunNetDeviceNewUnixgramPath,
                krun::Symbol::KrunNetDeviceNewUnixgramFd,
                krun::Symbol::KrunNetDeviceNewTap,
                krun::Symbol::KrunNetDeviceDestroy,
            ],
        )
    }
    use crate::{Test, TestOutcome, TestSetup};

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
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            let backend_result = (self.should_run)();
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
            let iperf_server = start_iperf_server(self.port)?;
            test_setup.register_cleanup_pid(iperf_server.id());

            std::thread::sleep(std::time::Duration::from_millis(200));

            let mut iperf_server = iperf_server;
            if let Some(status) = iperf_server.try_wait()? {
                anyhow::bail!("iperf3 server exited early: {status}");
            }

            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let builder = init_config_builder(&test_setup, &[]).dhcp(true);
            let (mut devices, payload) = setup_standard_devices_from(&test_setup, builder)?;

            let net_device = (self.setup_backend)(&test_setup)?;
            devices.add(net_device);

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

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            if let Some(cleanup) = self.cleanup {
                cleanup();
            }
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
