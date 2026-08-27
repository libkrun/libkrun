use macros::{guest, host};

pub struct TestFreeBsdBoot;

#[host]
mod host {
    use super::*;

    use crate::common::init_krun;
    #[cfg(feature = "dynamic-linking")]
    use crate::common_freebsd::require_freebsd_symbols;
    use crate::common_freebsd::{freebsd_assets, normalize_serial_output, setup_kernel_and_enter};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    impl Test for TestFreeBsdBoot {
        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let output_str = normalize_serial_output(stdout);
            if output_str == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!(
                    "expected exactly {:?}, got {:?}",
                    "OK\n", output_str
                ))
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let assets = freebsd_assets().expect("FreeBSD assets must be present when test runs");
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_freebsd_symbols().unwrap();
            setup_kernel_and_enter(test_setup, assets, None)
        }

        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_freebsd_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            match freebsd_assets() {
                Some(_) => ShouldRun::Yes,
                None => ShouldRun::No("freebsd assets missing"),
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;

    use crate::Test;

    impl Test for TestFreeBsdBoot {
        fn in_guest(self: Box<Self>) {
            println!("OK");
        }
    }
}
