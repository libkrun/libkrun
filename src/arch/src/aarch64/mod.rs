// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::borrowed_box)]

/// Layout for this aarch64 system.
pub mod layout;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::*;

use std::fmt::Debug;
use std::ops::Range;

use crate::{
    ArchMemoryInfo,
    aarch64::layout::{
        DRAM_MEM_MAX_SIZE, DRAM_MEM_START_EFI, DRAM_MEM_START_KERNEL, FIRMWARE_START,
    },
};
use vm_memory::{GuestAddress, GuestMemoryMmap};
use vmm_sys_util::align_upwards;

use smbios;

/// Errors thrown while configuring aarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to compute the initrd address.
    InitrdAddress,

    /// SMBIOS Error
    Smbios(smbios::Error),
}

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;

impl ArchMemoryInfo {
    /// The guest physical addresses of the memory that the VMM locks into host memory, if any.
    pub fn locked_range(&self) -> Option<Range<u64>> {
        (self.locked_size != 0)
            .then(|| self.locked_start_addr..self.locked_start_addr + self.locked_size)
    }
}

fn next_1gib_boundary(addr: u64) -> u64 {
    ((addr / 0x4000_0000) + 1) * 0x4000_0000
}

/// Returns a Vec of the valid memory addresses for aarch64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
///
/// `locked_size` bytes of guest memory that the VMM locks into host memory get a region of their
/// own, at the first 1 GiB boundary above RAM. That is where the SHM regions start without it;
/// they move up to the first 1 GiB boundary above the locked region. Nothing else moves, so a
/// `locked_size` of 0 gives the same layout as before locked guest memory existed.
pub fn arch_memory_regions(
    size: usize,
    locked_size: usize,
    initrd_size: u64,
    firmware_size: Option<usize>,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    let ram_start_addr = if firmware_size.is_some() {
        DRAM_MEM_START_EFI
    } else {
        DRAM_MEM_START_KERNEL
    };
    let page_size: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
    let mut dram_size = align_upwards!(size, page_size);
    if dram_size > DRAM_MEM_MAX_SIZE as usize {
        dram_size = DRAM_MEM_MAX_SIZE as usize;
    }
    let ram_last_addr = ram_start_addr + (dram_size as u64);
    let locked_size = align_upwards!(locked_size, page_size);
    let locked_start_addr = next_1gib_boundary(ram_last_addr);
    let shm_start_addr = if locked_size == 0 {
        locked_start_addr
    } else {
        next_1gib_boundary(locked_start_addr + locked_size as u64)
    };
    let fdt_addr = if firmware_size.is_some() {
        DRAM_MEM_START_EFI
    } else {
        ram_last_addr - layout::FDT_MAX_SIZE as u64
    };

    let info = ArchMemoryInfo {
        ram_start_addr,
        ram_last_addr,
        shm_start_addr,
        // To be filled later using GuestMemory.
        guest_last_addr: 0,
        page_size,
        fdt_addr,
        initrd_addr: fdt_addr - initrd_size,
        firmware_addr: FIRMWARE_START,
        #[cfg(target_os = "macos")]
        ipa_size: 0,
        locked_start_addr,
        locked_size: locked_size as u64,
    };
    let mut regions = if let Some(firmware_size) = firmware_size {
        vec![
            // Space for loading the firmware
            (GuestAddress(0u64), align_upwards!(firmware_size, page_size)),
            (GuestAddress(ram_start_addr), dram_size),
        ]
    } else {
        vec![(GuestAddress(ram_start_addr), dram_size)]
    };
    if locked_size != 0 {
        // A region of its own, so that the VMM can lock it without locking anything else.
        regions.push((GuestAddress(locked_start_addr), locked_size));
    }

    (info, regions)
}

/// Configures the system and should be called once per vm before starting vcpu threads.
/// For aarch64, we only setup SMBIOS.
#[allow(clippy::too_many_arguments)]
pub fn configure_system(
    guest_mem: &GuestMemoryMmap,
    mem_info: &ArchMemoryInfo,
    smbios_oem_strings: &Option<Vec<String>>,
) -> super::Result<()> {
    // When booting EFI, RAM starts at 0x4000_0000, while when doing a direct kernel
    // boot RAM starts at 0x8000_0000. Only write SMBIOS in the former case.
    if mem_info.ram_start_addr < layout::SMBIOS_START {
        smbios::setup_smbios(guest_mem, layout::SMBIOS_START, smbios_oem_strings)
            .map_err(Error::Smbios)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regions_lt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 29, 0, 0, None);
        assert_eq!(1, regions.len());
        assert_eq!(
            GuestAddress(super::layout::DRAM_MEM_START_KERNEL),
            regions[0].0
        );
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn test_regions_gt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 41, 0, 0, None);
        assert_eq!(1, regions.len());
        assert_eq!(
            GuestAddress(super::layout::DRAM_MEM_START_KERNEL),
            regions[0].0
        );
        assert_eq!(super::layout::DRAM_MEM_MAX_SIZE, regions[0].1 as u64);
    }

    const MIB: usize = 1 << 20;
    const GIB: usize = 1 << 30;

    /// What a layout puts where: (ram_start_addr, ram_last_addr, shm_start_addr, fdt_addr,
    /// initrd_addr, firmware_addr), the locked range, and the regions.
    type Layout = (
        (u64, u64, u64, u64, u64, u64),
        Option<Range<u64>>,
        Vec<(GuestAddress, usize)>,
    );

    fn layout(
        size: usize,
        locked_size: usize,
        initrd_size: u64,
        firmware_size: Option<usize>,
    ) -> Layout {
        let (info, regions) = arch_memory_regions(size, locked_size, initrd_size, firmware_size);
        (
            (
                info.ram_start_addr,
                info.ram_last_addr,
                info.shm_start_addr,
                info.fdt_addr,
                info.initrd_addr,
                info.firmware_addr,
            ),
            info.locked_range(),
            regions,
        )
    }

    // The layouts that arch_memory_regions() returned before locked guest memory existed. The
    // sizes are multiples of 64 KiB, so that they don't depend on the page size of the host.

    /// EFI boot with 1 GiB of RAM.
    fn golden_efi_1g() -> Layout {
        (
            (
                0x4000_0000,
                0x8000_0000,
                0xc000_0000,
                0x4000_0000,
                0x4000_0000,
                0,
            ),
            None,
            vec![(GuestAddress(0), 2 * MIB), (GuestAddress(0x4000_0000), GIB)],
        )
    }

    /// Direct kernel boot with 512 MiB of RAM and a 1 MiB initrd.
    fn golden_kernel_512m() -> Layout {
        (
            (
                0x8000_0000,
                0xa000_0000,
                0xc000_0000,
                0x9fe0_0000,
                0x9fd0_0000,
                0,
            ),
            None,
            vec![(GuestAddress(0x8000_0000), 512 * MIB)],
        )
    }

    /// EFI boot with RAM that ends right on a 1 GiB boundary.
    fn golden_efi_3g() -> Layout {
        (
            (
                0x4000_0000,
                0x1_0000_0000,
                0x1_4000_0000,
                0x4000_0000,
                0x4000_0000,
                0,
            ),
            None,
            vec![
                (GuestAddress(0), 2 * MIB),
                (GuestAddress(0x4000_0000), 3 * GIB),
            ],
        )
    }

    #[test]
    fn test_layout_without_locked_memory_is_unchanged() {
        assert_eq!(layout(GIB, 0, 0, Some(2 * MIB)), golden_efi_1g());
        assert_eq!(layout(512 * MIB, 0, MIB as u64, None), golden_kernel_512m());
        assert_eq!(layout(3 * GIB, 0, 0, Some(2 * MIB)), golden_efi_3g());
    }

    /// `golden` with `locked_size` bytes of locked memory at `locked_start`, and the SHM regions
    /// starting at `shm_start`.
    fn with_locked(
        golden: Layout,
        locked_start: u64,
        locked_size: usize,
        shm_start: u64,
    ) -> Layout {
        let ((ram_start, ram_last, _, fdt, initrd, firmware), locked, mut regions) = golden;
        assert_eq!(locked, None);
        regions.push((GuestAddress(locked_start), locked_size));
        (
            (ram_start, ram_last, shm_start, fdt, initrd, firmware),
            Some(locked_start..locked_start + locked_size as u64),
            regions,
        )
    }

    #[test]
    fn test_locked_memory_goes_where_shm_started_and_moves_shm_up() {
        assert_eq!(
            layout(GIB, 256 * MIB, 0, Some(2 * MIB)),
            with_locked(golden_efi_1g(), 0xc000_0000, 256 * MIB, 0x1_0000_0000)
        );
        assert_eq!(
            layout(GIB, 2 * MIB, 0, Some(2 * MIB)),
            with_locked(golden_efi_1g(), 0xc000_0000, 2 * MIB, 0x1_0000_0000)
        );
        // Like RAM, a locked region that ends on a 1 GiB boundary leaves the next GiB free.
        assert_eq!(
            layout(GIB, GIB, 0, Some(2 * MIB)),
            with_locked(golden_efi_1g(), 0xc000_0000, GIB, 0x1_4000_0000)
        );
        assert_eq!(
            layout(512 * MIB, 128 * MIB, MIB as u64, None),
            with_locked(golden_kernel_512m(), 0xc000_0000, 128 * MIB, 0x1_0000_0000)
        );
        assert_eq!(
            layout(3 * GIB, 1536 * MIB, 0, Some(2 * MIB)),
            with_locked(golden_efi_3g(), 0x1_4000_0000, 1536 * MIB, 0x1_c000_0000)
        );
    }

    #[test]
    fn test_locked_region_is_aligned_and_apart_from_ram_and_shm() {
        for size in [512 * MIB, GIB, 3 * GIB, 5 * GIB + 64 * MIB] {
            for locked_size in [2 * MIB, 254 * MIB, GIB, 3 * GIB + 2 * MIB] {
                for firmware_size in [None, Some(2 * MIB)] {
                    let (info, regions) = arch_memory_regions(size, locked_size, 0, firmware_size);
                    let locked = info.locked_range().unwrap();
                    assert_eq!(locked.start % GIB as u64, 0);
                    assert_eq!(locked.end - locked.start, locked_size as u64);
                    assert!(locked.start > info.ram_last_addr);
                    assert!(info.shm_start_addr > locked.end);
                    assert_eq!(info.shm_start_addr % GIB as u64, 0);
                    assert!(info.shm_start_addr - locked.end <= GIB as u64);
                    assert_eq!(
                        regions.last(),
                        Some(&(GuestAddress(locked.start), locked_size))
                    );
                    // Everything but the SHM start and the locked region is as without it.
                    let (unlocked, unlocked_regions) =
                        arch_memory_regions(size, 0, 0, firmware_size);
                    assert_eq!(locked.start, unlocked.shm_start_addr);
                    assert_eq!(info.ram_start_addr, unlocked.ram_start_addr);
                    assert_eq!(info.ram_last_addr, unlocked.ram_last_addr);
                    assert_eq!(info.fdt_addr, unlocked.fdt_addr);
                    assert_eq!(info.initrd_addr, unlocked.initrd_addr);
                    assert_eq!(regions[..regions.len() - 1], unlocked_regions[..]);
                }
            }
        }
    }
}
