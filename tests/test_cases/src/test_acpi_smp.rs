use macros::{guest, host};

pub struct TestAcpiSmp {
    pub(crate) num_cpus: u8,
}

#[host]
mod host {
    use super::*;
    use crate::common::{init_config_builder, init_krun, setup_standard_devices_from};
    use crate::{ShouldRun, Test, TestSetup};

    impl Test for TestAcpiSmp {
        fn should_run(&self) -> ShouldRun {
            if cfg!(target_arch = "x86_64") {
                ShouldRun::No("disabled until libkrunfw ACPI is released")
            } else {
                ShouldRun::No("ACPI table generation is x86_64-only")
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let init_config = init_config_builder(&test_setup, &[]).build();
            let (devices, payload) =
                setup_standard_devices_from(&test_setup, &init_config, &stdin, &stdout, &stderr)?;

            let vmm = krun::VmmBuilder::new()
                .vcpus(self.num_cpus)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(256)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .acpi(true)
                .map_err(|e| anyhow::anyhow!("acpi: {e:?}"))?
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
    use std::fs;
    use std::path::Path;
    use std::str::FromStr;

    fn detect_num_cpus() -> u32 {
        let cpus = fs::read_to_string("/sys/devices/system/cpu/online").unwrap();
        let mut parts = cpus.split("-");
        let low = u32::from_str(parts.next().unwrap().trim()).unwrap();
        if let Some(high) = parts.next() {
            let high = u32::from_str(high.trim()).unwrap();
            high - low + 1
        } else {
            low + 1
        }
    }

    impl Test for TestAcpiSmp {
        fn in_guest(self: Box<Self>) {
            assert!(
                Path::new("/sys/firmware/acpi/tables/APIC").exists(),
                "kernel did not parse the MADT -- ACPI was not used for boot"
            );
            assert!(
                Path::new("/sys/firmware/acpi/tables/FACP").exists(),
                "kernel did not parse the FADT"
            );

            assert_eq!(
                detect_num_cpus(),
                self.num_cpus as u32,
                "not all configured vCPUs came online via the ACPI MADT path"
            );

            println!("OK");
        }
    }
}
