use macros::{guest, host};

pub struct TestVirtioPci;

#[host]
mod host {
    use super::*;

    use std::os::fd::AsFd;

    use crate::common::{build_init_config, init_krun, setup_rootfs};
    use crate::{ShouldRun, Test, TestSetup};

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunPciDeviceManagerNew,
                krun::Symbol::KrunPciDeviceManagerDestroy,
                krun::Symbol::KrunPciDeviceManagerAdd,
                krun::Symbol::KrunVmmBuilderPciDevices,
                krun::Symbol::KrunVmmBuilderAcpi,
            ],
        )
    }

    impl Test for TestVirtioPci {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("virtio-pci API is unavailable in this library build");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let root_dir = setup_rootfs(&test_setup)?;
            let init_config = build_init_config(&test_setup.test_case, &[]);
            let mut rootfs = krun::FsDevice::new("/dev/root", root_dir.to_str().unwrap())
                .map_err(|err| anyhow::anyhow!("FsDevice::new: {err:?}"))?;
            let mut payload = krun::Payload::load_krunfw()
                .map_err(|err| anyhow::anyhow!("load_krunfw: {err:?}"))?;
            let mut overlay = krun::FsOverlay::new();
            init_config
                .apply(&mut overlay, &mut payload)
                .map_err(|err| anyhow::anyhow!("Config::apply: {err}"))?;
            rootfs.set_overlay(overlay);

            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut console_builder = krun::ConsoleDevice::builder();
            console_builder
                .add_default_console(
                    Some(stdin.as_fd()),
                    Some(stdout.as_fd()),
                    Some(stderr.as_fd()),
                )
                .map_err(|err| anyhow::anyhow!("add_default_console: {err:?}"))?;
            let console = console_builder
                .build()
                .map_err(|err| anyhow::anyhow!("ConsoleDevice::build: {err:?}"))?;

            let mut devices = krun::PciDeviceManager::new();
            devices.add(rootfs);
            devices.add(console);
            devices.add(
                krun::BalloonDevice::new()
                    .map_err(|err| anyhow::anyhow!("BalloonDevice: {err:?}"))?,
            );
            devices
                .add(krun::RngDevice::new().map_err(|err| anyhow::anyhow!("RngDevice: {err:?}"))?);

            let vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|err| anyhow::anyhow!("vcpus: {err:?}"))?
                .ram_mib(512)
                .map_err(|err| anyhow::anyhow!("ram_mib: {err:?}"))?
                .payload(payload)
                .acpi(true)
                .map_err(|err| anyhow::anyhow!("acpi: {err:?}"))?
                .pci_devices(devices)
                .build()
                .map_err(|err| anyhow::anyhow!("VmmBuilder::build: {err:?}"))?;

            vmm.run();
            unreachable!()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::collections::BTreeSet;
    use std::fs;

    impl Test for TestVirtioPci {
        fn in_guest(self: Box<Self>) {
            let mut virtio_devices = BTreeSet::new();
            for entry in fs::read_dir("/sys/bus/pci/devices").expect("PCI sysfs is missing") {
                let device = entry.expect("failed to read PCI device entry").path();
                let vendor = fs::read_to_string(device.join("vendor")).unwrap();
                if vendor.trim() != "0x1af4" {
                    continue;
                }

                let id = fs::read_to_string(device.join("device")).unwrap();
                virtio_devices
                    .insert(u16::from_str_radix(id.trim().trim_start_matches("0x"), 16).unwrap());
                let driver =
                    fs::read_link(device.join("driver")).expect("virtio-pci driver did not bind");
                assert_eq!(driver.file_name().unwrap(), "virtio-pci");
            }

            for id in [0x1043, 0x1044, 0x1045, 0x105a] {
                assert!(
                    virtio_devices.contains(&id),
                    "virtio PCI device {id:#06x} missing"
                );
            }
            println!("OK");
        }
    }
}
