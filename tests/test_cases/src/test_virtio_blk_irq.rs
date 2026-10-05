use macros::{guest, host};

pub struct TestVirtioBlkIrq {
    pub acpi: bool,
}

#[host]
mod host {
    use super::*;

    use std::fs::File;

    use crate::common::{build_init_config, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestSetup};

    const DISK_SIZE: u64 = 1024 * 1024 * 1024;

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunBlockDeviceNew,
                krun::Symbol::KrunBlockDeviceDestroy,
                krun::Symbol::KrunVmmBuilderAcpi,
            ],
        )
    }

    impl Test for TestVirtioBlkIrq {
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

            let disk_path = test_setup.tmp_dir.join("disk.raw");
            File::create(&disk_path)?.set_len(DISK_SIZE)?;

            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let init_config = build_init_config(&test_setup.test_case, &[]);
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            devices.add(
                krun::BlockDevice::new("vda", disk_path.to_str().unwrap(), krun::DiskFormat::Raw)
                    .map_err(|e| anyhow::anyhow!("BlockDevice: {e:?}"))?,
            );

            let vmm = krun::VmmBuilder::new()
                .vcpus(2)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(512)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .acpi(self.acpi)
                .map_err(|e| anyhow::anyhow!("acpi: {e:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("build: {e:?}"))?;

            vmm.run();
            unreachable!()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use std::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::slice;

    impl Test for TestVirtioBlkIrq {
        fn in_guest(self: Box<Self>) {
            assert_eq!(
                Path::new("/sys/firmware/acpi/tables/APIC").exists(),
                self.acpi,
                "guest ACPI state does not match test configuration"
            );
            const BLOCK_SIZE: usize = 4 * 1024 * 1024;
            const BLOCK_COUNT: usize = 256;
            const PASSES: usize = 3;

            let mut disk = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_DIRECT)
                .open("/dev/vda")
                .expect("open /dev/vda");
            let layout = Layout::from_size_align(BLOCK_SIZE, 4096).unwrap();
            let ptr = unsafe { alloc_zeroed(layout) };
            if ptr.is_null() {
                handle_alloc_error(layout);
            }
            let buffer = unsafe { slice::from_raw_parts_mut(ptr, BLOCK_SIZE) };

            for _ in 0..PASSES {
                disk.seek(SeekFrom::Start(0)).expect("seek /dev/vda");
                for _ in 0..BLOCK_COUNT {
                    disk.read_exact(buffer).expect("direct read from /dev/vda");
                }
            }

            unsafe { dealloc(ptr, layout) };
            println!("OK");
        }
    }
}
