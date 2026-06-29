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

/// Returns a Vec of the valid memory addresses for aarch64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
pub fn arch_memory_regions(
    size: usize,
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
    let shm_start_addr = ((ram_last_addr / 0x4000_0000) + 1) * 0x4000_0000;
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
    };
    let regions = if let Some(firmware_size) = firmware_size {
        vec![
            // Space for loading the firmware
            (GuestAddress(0u64), align_upwards!(firmware_size, page_size)),
            (GuestAddress(ram_start_addr), dram_size),
        ]
    } else {
        vec![(GuestAddress(ram_start_addr), dram_size)]
    };

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
        let (_mem_info, regions) = arch_memory_regions(1usize << 29, 0, None);
        assert_eq!(1, regions.len());
        assert_eq!(
            GuestAddress(super::layout::DRAM_MEM_START_KERNEL),
            regions[0].0
        );
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn test_regions_gt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 41, 0, None);
        assert_eq!(1, regions.len());
        assert_eq!(
            GuestAddress(super::layout::DRAM_MEM_START_KERNEL),
            regions[0].0
        );
        assert_eq!(super::layout::DRAM_MEM_MAX_SIZE, regions[0].1 as u64);
    }
}
