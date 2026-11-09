#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};

/// Exercises the init control server: the host starts a second copy of the
/// guest agent inside the running VM through the controller, checks what it
/// saw, then stops the workload with a SIGTERM delivered through the same
/// channel.
pub struct TestInitControl;

/// Set by the host on the process it starts; the guest agent then acts as
/// that child instead of as the workload.
const CHILD_ROLE_VAR: &str = "KRUN_TEST_INIT_CONTROL_CHILD";
const CHILD_EXIT_CODE: i32 = 7;

#[host]
mod host {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::Path;
    use std::thread;

    use crate::common::{init_config_builder, init_krun, setup_standard_devices_with_vsock};
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

    const CONTROL_TIMEOUT_MS: u32 = 30_000;
    const CHILD_UID: u32 = 1000;
    const EXEC_PREFIX: &str = "EXEC ";

    fn pipe() -> anyhow::Result<(OwnedFd, OwnedFd)> {
        let (r, w) = nix::unistd::pipe()?;
        Ok((r, w))
    }

    fn read_all(fd: OwnedFd) -> String {
        let mut out = String::new();
        let _ = File::from(fd).read_to_string(&mut out);
        out
    }

    /// Run the guest agent as a child through the control socket and report
    /// its exit code and output on one stdout line for `check`.
    fn exec_child(control_sock: &Path, test_case: &str) -> anyhow::Result<String> {
        let controller =
            krun_init::Controller::open(control_sock.to_str().unwrap(), CONTROL_TIMEOUT_MS)
                .map_err(|e| anyhow::anyhow!("Controller::open: {e}"))?;

        let request = krun_init::ExecRequest::new("/guest-agent")
            .arg("/guest-agent")
            .arg(test_case)
            .env_var(&format!("{CHILD_ROLE_VAR}=1"))
            .env_var("FOO=bar")
            .cwd("/")
            .uid(CHILD_UID)
            .gid(CHILD_UID);

        let (out_r, out_w) = pipe()?;
        let (err_r, err_w) = pipe()?;
        let mut process = controller
            .exec_pipes(&request, None, out_w.as_fd(), err_w.as_fd())
            .map_err(|e| anyhow::anyhow!("exec_pipes: {e}"))?;
        let code = process
            .wait(None)
            .map_err(|e| anyhow::anyhow!("Process::wait: {e}"))?;
        drop(process);
        drop(out_w);
        drop(err_w);

        let stdout = read_all(out_r).trim().replace('\n', " ");
        let stderr = read_all(err_r).trim().replace('\n', " ");
        Ok(format!(
            "{EXEC_PREFIX}code={code} out=[{stdout}] err=[{stderr}]"
        ))
    }

    fn run(control_sock: &Path, test_case: &str) {
        let line = match exec_child(control_sock, test_case) {
            Ok(line) => line,
            Err(e) => format!("{EXEC_PREFIX}error {e}"),
        };
        let mut stdout = std::io::stdout();
        stdout.write_all(format!("{line}\n").as_bytes()).unwrap();
        stdout.flush().unwrap();

        // Printed before the signal: once the workload exits the VM is gone.
        let result =
            krun_init::Controller::open(control_sock.to_str().unwrap(), CONTROL_TIMEOUT_MS)
                .and_then(|controller| controller.signal_entrypoint(nix::libc::SIGTERM));
        if let Err(e) = result {
            stdout
                .write_all(format!("SIGNAL error {e}\n").as_bytes())
                .unwrap();
            stdout.flush().unwrap();
        }
    }

    impl Test for TestInitControl {
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

            let control_sock = test_setup.tmp_dir.join("control.sock");
            let init_config = init_config_builder(&test_setup, &[])
                .control_socket(control_sock.to_str().unwrap())
                .build();

            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::empty())
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            let (mut devices, payload) = setup_standard_devices_with_vsock(
                &test_setup,
                &init_config,
                &stdin,
                &stdout,
                &stderr,
                &mut vsock,
            )?;
            devices.add(vsock);

            let test_case = test_setup.test_case.clone();
            thread::spawn(move || run(&control_sock, &test_case));

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

            if !stdout.lines().any(|line| line.trim() == "READY") {
                return TestOutcome::Fail(format!(
                    "workload never reported READY, stdout: {stdout:?}"
                ));
            }

            let Some(exec) = stdout
                .lines()
                .find_map(|l| l.trim().strip_prefix(EXEC_PREFIX))
            else {
                return TestOutcome::Fail(format!("no exec result, stdout: {stdout:?}"));
            };
            let expected =
                format!("code={CHILD_EXIT_CODE} out=[CHILD cwd=/ FOO=bar uid={CHILD_UID}] err=[]");
            if exec != expected {
                return TestOutcome::Fail(format!("exec result {exec:?}, expected {expected:?}"));
            }

            if !stdout.lines().any(|line| line.trim() == "SIGTERM") {
                return TestOutcome::Fail(format!(
                    "workload did not receive SIGTERM through the control socket, stdout: {stdout:?}"
                ));
            }

            TestOutcome::Pass
        }

        fn timeout_secs(&self) -> u64 {
            90
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::sys::signal::{SigSet, Signal};
    use std::env;

    impl Test for TestInitControl {
        fn in_guest(self: Box<Self>) {
            if env::var_os(CHILD_ROLE_VAR).is_some() {
                let cwd = env::current_dir().unwrap();
                let foo = env::var("FOO").unwrap_or_default();
                println!(
                    "CHILD cwd={} FOO={foo} uid={}",
                    cwd.display(),
                    nix::unistd::getuid()
                );
                std::process::exit(CHILD_EXIT_CODE);
            }

            let mut set = SigSet::empty();
            set.add(Signal::SIGTERM);
            set.thread_block().unwrap();
            println!("READY");

            let signal = set.wait().unwrap();
            println!("{signal:?}");
        }
    }
}
