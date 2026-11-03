use macros::{guest, host};

pub struct TestInvariantTsc {
    pub(crate) enabled: Option<bool>,
}

fn has_invariant_tsc() -> bool {
    use std::arch::x86_64::__cpuid;

    __cpuid(0x8000_0000).eax >= 0x8000_0007 && __cpuid(0x8000_0007).edx & (1 << 8) != 0
}

#[host]
mod host {
    use super::*;
    use crate::common::{init_config_builder, init_krun, setup_standard_devices_from};
    use crate::{ShouldRun, Test, TestSetup};

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(None, &[krun::Symbol::KrunVmmBuilderInvariantTsc])
    }

    impl Test for TestInvariantTsc {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("invariant TSC configuration not available");
            }
            if self.enabled == Some(true) && !has_invariant_tsc() {
                return ShouldRun::No("host does not support invariant TSC");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols()?;
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let init_config = init_config_builder(&test_setup, &[]).build();
            let (devices, payload) =
                setup_standard_devices_from(&test_setup, &init_config, &stdin, &stdout, &stderr)?;

            let mut builder = krun::VmmBuilder::new();
            if let Some(enabled) = self.enabled {
                builder = builder
                    .invariant_tsc(enabled)
                    .map_err(|e| anyhow::anyhow!("invariant_tsc: {e:?}"))?;
            }
            let vmm = builder
                .vcpus(2)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(256)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("VmmBuilder::build: {e:?}"))?;

            vmm.run();
            unreachable!()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    impl Test for TestInvariantTsc {
        fn in_guest(self: Box<Self>) {
            assert_eq!(has_invariant_tsc(), self.enabled.unwrap_or(false));
            println!("OK");
        }
    }
}
