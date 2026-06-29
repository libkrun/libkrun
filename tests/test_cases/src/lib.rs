mod test_vm_config;
use test_vm_config::TestVmConfig;

mod test_vm_pause;
use test_vm_pause::TestVmPause;

#[cfg(any(feature = "host", target_os = "linux"))]
mod test_vsock_guest_connect;
#[cfg(any(feature = "host", target_os = "linux"))]
use test_vsock_guest_connect::TestVsockGuestConnect;

mod test_tsi_tcp_guest_connect;
use test_tsi_tcp_guest_connect::TestTsiTcpGuestConnect;

mod test_tsi_tcp_guest_listen;
use test_tsi_tcp_guest_listen::TestTsiTcpGuestListen;

pub(crate) mod test_net;
use test_net::TestNet;

mod test_net_perf;
use test_net_perf::TestNetPerf;

mod test_multiport_console;
use test_multiport_console::TestMultiportConsole;

#[cfg(any(feature = "host", target_os = "linux"))]
mod test_virtiofs_root_ro;
#[cfg(any(feature = "host", target_os = "linux"))]
use test_virtiofs_root_ro::TestVirtiofsRootRo;

mod test_augmentfs;
use test_augmentfs::TestAugmentFs;

mod test_root_disk_remount;
use test_root_disk_remount::TestRootDiskRemount;

mod test_pjdfstest;
use test_pjdfstest::TestPjdfstest;

#[cfg(any(feature = "host", target_os = "linux"))]
mod test_virtiofs_misc;
#[cfg(any(feature = "host", target_os = "linux"))]
use test_virtiofs_misc::TestVirtioFsMisc;

pub enum TestOutcome {
    Pass,
    Fail(String),
    Timeout,
    Skip(&'static str),
    Report(Box<dyn ReportImpl>),
}

mod test_freebsd_boot;
use test_freebsd_boot::TestFreeBsdBoot;

mod test_freebsd_gvproxy_tcp_guest_connect;
use test_freebsd_gvproxy_tcp_guest_connect::TestFreeBsdGvproxyTcpGuestConnect;

mod test_freebsd_gvproxy_tcp_guest_listen;
use test_freebsd_gvproxy_tcp_guest_listen::TestFreeBsdGvproxyTcpGuestListen;

pub mod freebsd_guest;

pub enum ShouldRun {
    Yes,
    No(&'static str),
}

impl ShouldRun {
    /// Returns Yes unless on macOS, in which case returns No with the given reason.
    pub fn yes_unless_macos(reason: &'static str) -> Self {
        if cfg!(target_os = "macos") {
            ShouldRun::No(reason)
        } else {
            ShouldRun::Yes
        }
    }
}

pub fn test_cases() -> Vec<TestCase> {
    // Register your test here:
    vec![
        TestCase::new(
            "configure-vm-1cpu-256MiB",
            Box::new(TestVmConfig {
                num_cpus: 1,
                ram_mib: 256,
            }),
        ),
        TestCase::new(
            "configure-vm-2cpu-1GiB",
            Box::new(TestVmConfig {
                num_cpus: 2,
                ram_mib: 1024,
            }),
        ),
        TestCase::new("vm-pause", Box::new(TestVmPause)),
        #[cfg(any(feature = "host", target_os = "linux"))]
        TestCase::new("vsock-guest-connect", Box::new(TestVsockGuestConnect)),
        TestCase::new(
            "tsi-tcp-guest-connect",
            Box::new(TestTsiTcpGuestConnect::new()),
        ),
        TestCase::new(
            "tsi-tcp-guest-listen",
            Box::new(TestTsiTcpGuestListen::new()),
        ),
        TestCase::new("net-passt", Box::new(TestNet::new_passt())),
        TestCase::new("net-tap", Box::new(TestNet::new_tap())),
        TestCase::new("net-gvproxy", Box::new(TestNet::new_gvproxy())),
        TestCase::new(
            "net-gvproxy-long-path",
            Box::new(TestNet::new_gvproxy_long_path()),
        ),
        TestCase::new("net-vmnet-helper", Box::new(TestNet::new_vmnet_helper())),
        TestCase::new("multiport-console", Box::new(TestMultiportConsole)),
        #[cfg(any(feature = "host", target_os = "linux"))]
        TestCase::new("virtiofs-root-ro", Box::new(TestVirtiofsRootRo)),
        TestCase::new("augmentfs", Box::new(TestAugmentFs)),
        TestCase::new("root-disk-remount", Box::new(TestRootDiskRemount)),
        #[cfg(any(feature = "host", target_os = "linux"))]
        TestCase::new("virtiofs-misc", Box::new(TestVirtioFsMisc)),
        TestCase::new("pjdfstest", Box::new(TestPjdfstest)),
        TestCase::new("perf-net-passt-tx", Box::new(TestNetPerf::new_passt_tx())),
        TestCase::new("perf-net-passt-rx", Box::new(TestNetPerf::new_passt_rx())),
        TestCase::new("perf-net-tap-tx", Box::new(TestNetPerf::new_tap_tx())),
        TestCase::new("perf-net-tap-rx", Box::new(TestNetPerf::new_tap_rx())),
        TestCase::new(
            "perf-net-gvproxy-tx",
            Box::new(TestNetPerf::new_gvproxy_tx()),
        ),
        TestCase::new(
            "perf-net-gvproxy-rx",
            Box::new(TestNetPerf::new_gvproxy_rx()),
        ),
        TestCase::new(
            "perf-net-vmnet-helper-tx",
            Box::new(TestNetPerf::new_vmnet_helper_tx()),
        ),
        TestCase::new(
            "perf-net-vmnet-helper-rx",
            Box::new(TestNetPerf::new_vmnet_helper_rx()),
        ),
        TestCase::new("freebsd-boot", Box::new(TestFreeBsdBoot)),
        TestCase::new(
            "freebsd-gvproxy-tcp-guest-connect",
            Box::new(TestFreeBsdGvproxyTcpGuestConnect::new()),
        ),
        TestCase::new(
            "freebsd-gvproxy-tcp-guest-listen",
            Box::new(TestFreeBsdGvproxyTcpGuestListen::new()),
        ),
    ]
}

////////////////////
// Implementation details:
//////////////////

pub trait ReportImpl {
    fn fmt_text(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
    fn fmt_gh_markdown(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

pub trait Report: ReportImpl {
    fn text(&self) -> ReportText<'_, Self> {
        ReportText(self)
    }

    fn gh_markdown(&self) -> ReportGhMarkdown<'_, Self> {
        ReportGhMarkdown(self)
    }
}

impl<T: ReportImpl + ?Sized> Report for T {}

pub struct ReportText<'a, T: ReportImpl + ?Sized>(pub &'a T);

impl<T: ReportImpl + ?Sized> std::fmt::Display for ReportText<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_text(f)
    }
}

pub struct ReportGhMarkdown<'a, T: ReportImpl + ?Sized>(pub &'a T);

impl<T: ReportImpl + ?Sized> std::fmt::Display for ReportGhMarkdown<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_gh_markdown(f)
    }
}

use macros::{guest, host};
#[host]
use std::path::PathBuf;

#[cfg(all(feature = "guest", feature = "host"))]
compile_error!("Cannot enable both guest and host in the same binary!");

#[cfg(feature = "host")]
mod common;

#[cfg(feature = "host")]
pub mod common_freebsd;

#[cfg(feature = "host")]
mod krun;

#[cfg(feature = "host")]
pub mod rootfs;
mod tcp_tester;

#[cfg(feature = "guest")]
pub mod freebsd_network;

#[host]
#[derive(Clone, Debug)]
pub struct TestSetup {
    pub test_case: String,
    // A tmp directory for misc. artifacts used be the test (e.g. sockets)
    pub tmp_dir: PathBuf,
}

#[host]
impl TestSetup {
    /// Register a PID to be killed after the test finishes.
    ///
    /// The runner will SIGKILL these PIDs after check() returns, even if the
    /// test crashed. Use this for background processes (e.g. gvproxy) that
    /// outlive the VM.
    pub fn register_cleanup_pid(&self, pid: u32) {
        use std::io::Write;
        let path = self.tmp_dir.join("cleanup.pids");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open cleanup.pids");
        writeln!(file, "{}", pid).expect("Failed to write cleanup PID");
    }
}

#[host]
pub trait Test {
    /// Start the VM
    fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()>;

    /// Checks the output of the (host) process which started the VM
    fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
        let output = String::from_utf8(stdout).unwrap();
        if output == "OK\n" {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail(format!("expected exactly {:?}, got {:?}", "OK\n", output))
        }
    }

    /// Check if this test should run on this platform.
    fn should_run(&self) -> ShouldRun {
        ShouldRun::Yes
    }

    /// Return Containerfile content if this test needs a custom rootfs image.
    /// The runner will build the image via podman and extract it before launching the VM.
    /// If podman is unavailable, the test is skipped.
    fn rootfs_image(&self) -> Option<&'static str> {
        None
    }

    /// Per-test timeout in seconds. The runner kills the test if it exceeds this.
    fn timeout_secs(&self) -> u64 {
        15
    }
}

#[guest]
pub trait Test {
    /// This will be executed in the guest, you can panic! if the test failed!
    fn in_guest(self: Box<Self>) {}
}

pub struct TestCase {
    pub name: &'static str,
    pub test: Box<dyn Test>,
}

impl TestCase {
    // Your test can be parametrized, so you can add the same test multiple times constructed with
    // different parameters with and specify a different name here.
    pub fn new(name: &'static str, test: Box<dyn Test>) -> Self {
        Self { name, test }
    }

    /// Check if this test should run on this platform.
    #[host]
    pub fn should_run(&self) -> ShouldRun {
        self.test.should_run()
    }

    #[host]
    pub fn rootfs_image(&self) -> Option<&'static str> {
        self.test.rootfs_image()
    }

    #[host]
    pub fn timeout_secs(&self) -> u64 {
        self.test.timeout_secs()
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_testcases_have_unique_names() {
        let test_cases = test_cases();
        let mut names: HashSet<&str> = HashSet::new();

        for test_case in test_cases {
            let name = test_case.name();
            let was_inserted = names.insert(name);
            if !was_inserted {
                panic!("test_cases() contains multiple items named `{name}`")
            }

            if name == "all" {
                panic!("test_cases() contains test named {name}, but the name is reseved")
            }
        }
    }
}
