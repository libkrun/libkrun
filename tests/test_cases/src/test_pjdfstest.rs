use macros::{guest, host};

pub struct TestPjdfstest;

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter_with_env;
    use crate::{ShouldRun, Test, TestOutcome, TestSetup, krun_call, krun_call_u32};
    use krun_sys::*;
    use std::os::fd::AsRawFd;

    use macros::env_or_default;

    // Set PJDFSTEST_REPO and PJDFSTEST_COMMIT at build time to enable this test.
    const CONTAINERFILE: &str = concat!(
        "FROM fedora:43\n",
        "RUN dnf install -y autoconf automake gcc make perl-Test-Harness git openssl && dnf clean all\n",
        "RUN git init /pjdfstest \\\n",
        " && git -C /pjdfstest fetch --depth 1 ",
        env_or_default!("PJDFSTEST_REPO", ""),
        " ",
        env_or_default!("PJDFSTEST_COMMIT", ""),
        " \\\n",
        " && git -C /pjdfstest checkout FETCH_HEAD\n",
        "WORKDIR /pjdfstest\n",
        "RUN autoreconf -ifs && ./configure && make pjdfstest\n",
    );

    impl Test for TestPjdfstest {
        fn should_run(&self) -> ShouldRun {
            if option_env!("PJDFSTEST_REPO").is_none() || option_env!("PJDFSTEST_COMMIT").is_none()
            {
                return ShouldRun::No("PJDFSTEST_REPO/PJDFSTEST_COMMIT not set");
            }
            ShouldRun::Yes
        }

        fn rootfs_image(&self) -> Option<&'static str> {
            Some(CONTAINERFILE)
        }

        fn timeout_secs(&self) -> u64 {
            1800
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let host_os = if cfg!(target_os = "macos") {
                "Darwin"
            } else {
                "Linux"
            };
            let host_os_env = format!("PJDFSTEST_HOST_OS={host_os}");
            unsafe {
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 2, 1024))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
                setup_fs_and_enter_with_env(ctx, test_setup, &[host_os_env.as_str()])?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let stdout = String::from_utf8_lossy(&stdout);

            if stdout.contains("Result: PASS") {
                TestOutcome::Pass
            } else if stdout.contains("Result: FAIL") || stdout.contains("Result: NOTESTS") {
                TestOutcome::Fail(stdout.to_string())
            } else if stdout.trim() == "OK" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(stdout.to_string())
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::process::Command;

    impl Test for TestPjdfstest {
        fn in_guest(self: Box<Self>) {
            // Create a test directory on the filesystem under test
            std::fs::create_dir_all("/tmp/pjdfstest-work").expect("Failed to create test dir");

            let status = Command::new("/usr/bin/prove")
                .arg("-rv")
                .arg("/pjdfstest/tests")
                .current_dir("/tmp/pjdfstest-work")
                .status()
                .expect("Failed to run prove");

            if !status.success() {
                panic!("prove exited with status: {}", status.code().unwrap_or(-1));
            }
        }
    }
}
