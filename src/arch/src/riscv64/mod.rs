// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Layout for this riscv64 system.
pub mod layout;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;

use std::fmt::Debug;

use crate::{ArchMemoryInfo, riscv64::layout::FIRMWARE_START};
use vm_memory::{Address, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};
use vmm_sys_util::align_upwards;

/// Errors thrown while configuring riscv64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to compute the initrd address.
    InitrdAddress,
}

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;

/// Returns a Vec of the valid memory addresses for riscv64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
pub fn arch_memory_regions(
    size: usize,
    initrd_size: u64,
    _firmware_size: Option<usize>,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    let page_size: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
    let dram_size = align_upwards!(size, page_size);
    let ram_last_addr = layout::DRAM_MEM_START + (dram_size as u64);
    let shm_start_addr = ((ram_last_addr / 0x4000_0000) + 1) * 0x4000_0000;

    let info = ArchMemoryInfo {
        ram_last_addr,
        shm_start_addr,
        page_size,
        initrd_addr: ram_last_addr - layout::FDT_MAX_SIZE as u64 - initrd_size,
        firmware_addr: FIRMWARE_START,
    };
    let regions = vec![(GuestAddress(layout::DRAM_MEM_START), dram_size)];

    (info, regions)
}

/// Configures the system and should be called once per vm before starting vcpu threads.
/// For riscv64, we only setup the FDT.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_cstring` - The kernel commandline.
/// * `device_info` - A hashmap containing the attached devices for building FDT device nodes.
/// * `aia_device` - The AIA device.
/// * `initrd` - Information about an optional initrd.
#[allow(clippy::too_many_arguments)]
pub fn configure_system(
    _guest_mem: &GuestMemoryMmap,
    _smbios_oem_strings: &Option<Vec<String>>,
) -> super::Result<()> {
    Ok(())
}

// Auxiliary function to get the address where the device tree blob is loaded.
pub fn get_fdt_addr(_mem: &GuestMemoryMmap) -> u64 {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    if let Some(addr) = _mem
        .last_addr()
        .checked_sub(layout::FDT_MAX_SIZE as u64 - 1)
    {
        if _mem.address_in_range(addr) {
            return addr.raw_value();
        }
    }

    layout::DRAM_MEM_START
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regions_lt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 29, 0);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn test_regions_gt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 41, 0);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(super::layout::DRAM_MEM_MAX_SIZE, regions[0].1 as u64);
    }

    #[test]
    fn test_get_fdt_addr() {
        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE - 0x1000, 0);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE, 0);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000, 0);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), 0x1000 + layout::DRAM_MEM_START);
    }
}
