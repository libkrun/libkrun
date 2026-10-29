use macros::{guest, host};

pub struct TestVirtioRtc {
    pub enabled: bool,
}

#[host]
mod host {
    use super::*;

    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;

    use crate::common::{init_config_builder, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    #[cfg(feature = "dynamic-linking")]
    fn require_rtc_symbols() -> Result<(), libloading::Error> {
        krun::require(
            None,
            &[
                krun::Symbol::KrunRtcDeviceNew,
                krun::Symbol::KrunRtcDeviceDestroy,
            ],
        )
    }

    impl Test for TestVirtioRtc {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if crate::common::require_vm_symbols().is_err() {
                return ShouldRun::No("core VM symbols not available");
            }
            #[cfg(feature = "dynamic-linking")]
            if self.enabled && require_rtc_symbols().is_err() {
                return ShouldRun::No("virtio-rtc API is unavailable in this library build");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let init_config = init_config_builder(&test_setup, &[]).build();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            if self.enabled {
                #[cfg(feature = "dynamic-linking")]
                require_rtc_symbols()?;

                devices
                    .add(krun::RtcDevice::new().map_err(|e| anyhow::anyhow!("RtcDevice: {e:?}"))?);
            }
            let vmm = krun::VmmBuilder::new()
                .vcpus(1)
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

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8(stdout).unwrap();
            match output.as_str() {
                "OK\n" => TestOutcome::Pass,
                _ => TestOutcome::Fail(format!("expected exactly {:?}, got {:?}", "OK\n", output)),
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::fs;
    #[cfg(target_arch = "aarch64")]
    use std::path::Path;

    fn virtio_rtc_count() -> usize {
        fs::read_dir("/sys/bus/virtio/devices")
            .expect("virtio sysfs is missing")
            .filter(|entry| {
                let device = entry.as_ref().unwrap().path();
                let id = fs::read_to_string(device.join("device")).unwrap();
                u32::from_str_radix(id.trim().trim_start_matches("0x"), 16).unwrap() == 17
            })
            .count()
    }

    #[cfg(target_arch = "aarch64")]
    fn check_pl031(expected: bool) {
        fn contains_pl031(dir: &Path) -> bool {
            fs::read_dir(dir).unwrap().any(|entry| {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    contains_pl031(&path)
                } else if path.file_name().is_some_and(|name| name == "compatible") {
                    fs::read(path)
                        .unwrap()
                        .split(|byte| *byte == 0)
                        .any(|value| value == b"arm,pl031")
                } else {
                    false
                }
            })
        }
        assert_eq!(
            contains_pl031(Path::new("/sys/firmware/devicetree/base")),
            expected
        );
    }

    impl Test for TestVirtioRtc {
        fn in_guest(self: Box<Self>) {
            let expected = usize::from(self.enabled || cfg!(target_arch = "riscv64"));
            assert_eq!(virtio_rtc_count(), expected);
            #[cfg(target_arch = "aarch64")]
            check_pl031(!self.enabled);
            println!("OK");
        }
    }
}
