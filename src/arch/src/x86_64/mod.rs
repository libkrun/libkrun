// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod acpi;
mod gdt;
/// Contains logic for setting up Advanced Programmable Interrupt Controller (local version).
pub mod interrupts;
/// Layout for the x86_64 system.
pub mod layout;
#[cfg(any(not(feature = "tee"), feature = "tdx"))]
mod mptable;
/// Logic for configuring x86_64 model specific registers (MSRs).
pub mod msr;
/// Logic for configuring x86_64 registers.
pub mod regs;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
use std::mem::MaybeUninit;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use crate::x86_64::layout::{EBDA_START, FIRST_ADDR_PAST_32BITS, MMIO_MEM_START};
#[cfg(feature = "tee")]
use crate::x86_64::layout::{FIRMWARE_SIZE, FIRMWARE_START};
use crate::{ArchMemoryInfo, InitrdConfig};
#[cfg(all(not(feature = "tee"), target_os = "linux"))]
use arch_gen::x86::bootparam::E820_RESERVED;
use arch_gen::x86::bootparam::{E820_RAM, boot_params};
use vm_memory::Bytes;
use vm_memory::{Address, ByteValued, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::align_upwards;

#[cfg(all(not(feature = "tee"), target_os = "linux"))]
use linux_loader::configurator::{BootConfigurator, BootParams, pvh::PvhBootConfigurator};
#[cfg(all(not(feature = "tee"), target_os = "linux"))]
use linux_loader::loader::elf::start_info::{
    hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info,
};

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `ByteValued`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct BootParamsWrapper(boot_params);

// It is safe to initialize BootParamsWrap which is a wrapper over `boot_params` (a series of ints).
unsafe impl ByteValued for BootParamsWrapper {}

/// Errors thrown while configuring x86_64 system.
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid e820 setup params.
    E820Configuration,
    /// Error writing MP table to memory.
    #[cfg(any(not(feature = "tee"), feature = "tdx"))]
    MpTableSetup(mptable::Error),
    /// Error writing hvm_start_info to guest memory.
    #[cfg(all(not(feature = "tee"), target_os = "linux"))]
    StartInfoSetup,
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
    /// Failed to compute initrd address.
    InitrdAddress,
}

#[cfg(unix)]
fn get_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() }
}
#[cfg(windows)]
fn get_page_size() -> usize {
    let sysinfo = unsafe {
        let mut info = MaybeUninit::<SYSTEM_INFO>::uninit();
        GetSystemInfo(info.as_mut_ptr());
        info.assume_init()
    };

    sysinfo.dwPageSize as usize
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemoryMmap structure for the platform.
/// Make a hole for the kernel region that will be injected directly from libkrunfw's
/// mapping, and reserve an SHM region for virtio-fs.
#[cfg(not(feature = "tee"))]
pub fn arch_memory_regions(
    size: usize,
    kernel_load_addr: Option<u64>,
    kernel_size: usize,
    initrd_size: u64,
    firmware_size: Option<usize>,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    let page_size: usize = get_page_size();

    let size = align_upwards!(size, page_size);

    // It's safe to cast MMIO_MEM_START to usize because it fits in a u32 variable
    // (It points to an address in the 32 bit space).
    let (ram_below_gap, ram_above_gap, ram_last_addr, shm_start_addr, regions, firmware_addr) =
        match size.checked_sub(MMIO_MEM_START as usize) {
            // case1: guest memory fits before the gap
            None | Some(0) => {
                let shm_start_addr = FIRST_ADDR_PAST_32BITS;

                let (ram_last_addr, mut regions) = if let Some(kernel_load_addr) = kernel_load_addr
                {
                    if size < (kernel_load_addr + kernel_size as u64) as usize {
                        panic!("Kernel doesn't fit in RAM");
                    }

                    let ram_last_addr = kernel_load_addr + kernel_size as u64 + size as u64;
                    (
                        ram_last_addr,
                        vec![
                            (GuestAddress(0), kernel_load_addr as usize),
                            (GuestAddress(kernel_load_addr + kernel_size as u64), size),
                        ],
                    )
                } else {
                    let ram_last_addr = size as u64;
                    (ram_last_addr, vec![(GuestAddress(0), size)])
                };

                let firmware_addr = if let Some(firmware_size) = firmware_size {
                    let firmware_start = layout::FIRST_ADDR_PAST_32BITS - firmware_size as u64;
                    regions.push((GuestAddress(firmware_start), firmware_size));
                    firmware_start
                } else {
                    0
                };

                (
                    size as u64,
                    0,
                    ram_last_addr,
                    shm_start_addr,
                    regions,
                    firmware_addr,
                )
            }

            // case2: guest memory extends beyond the gap
            Some(remaining) => {
                let ram_last_addr = FIRST_ADDR_PAST_32BITS + remaining as u64;
                let shm_start_addr = ((ram_last_addr / 0x4000_0000) + 1) * 0x4000_0000;

                let mut regions = if let Some(kernel_load_addr) = kernel_load_addr {
                    vec![
                        (GuestAddress(0), kernel_load_addr as usize),
                        (
                            GuestAddress(kernel_load_addr + kernel_size as u64),
                            (MMIO_MEM_START - (kernel_load_addr + kernel_size as u64)) as usize,
                        ),
                        (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
                    ]
                } else {
                    vec![
                        (GuestAddress(0), MMIO_MEM_START as usize),
                        (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
                    ]
                };

                let firmware_addr = if let Some(firmware_size) = firmware_size {
                    let firmware_start = layout::FIRST_ADDR_PAST_32BITS - firmware_size as u64;
                    regions.insert(
                        regions.len() - 1,
                        (GuestAddress(firmware_start), firmware_size),
                    );
                    firmware_start
                } else {
                    0
                };

                (
                    MMIO_MEM_START,
                    remaining as u64,
                    ram_last_addr,
                    shm_start_addr,
                    regions,
                    firmware_addr,
                )
            }
        };
    let info = ArchMemoryInfo {
        ram_below_gap,
        ram_above_gap,
        ram_last_addr,
        shm_start_addr,
        page_size,
        initrd_addr: ram_last_addr.min(MMIO_MEM_START) - initrd_size,
        firmware_addr,
    };
    (info, regions)
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemoryMmap structure for the platform.
/// For SEV, don't make a hole for the kernel, as it needs to be copied instead of injected,
/// don't reserve an SHM region, as virtio-fs is not supported, and reserve a small 64K
/// region for the BIOS.
#[cfg(feature = "tee")]
pub fn arch_memory_regions(
    size: usize,
    kernel_load_addr: Option<u64>,
    kernel_size: usize,
    _initrd_size: u64,
    firmware_range: Option<(u64, usize)>,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    let page_size: usize = get_page_size();

    let size = align_upwards!(size, page_size);
    if let Some(kernel_load_addr) = kernel_load_addr
        && size < (kernel_load_addr + kernel_size as u64) as usize
    {
        panic!("Kernel doesn't fit in RAM");
    }

    // It's safe to cast MMIO_MEM_START to usize because it fits in a u32 variable
    // (It points to an address in the 32 bit space).
    let (ram_below_gap, ram_above_gap, ram_last_addr, shm_start_addr, regions) =
        match size.checked_sub(MMIO_MEM_START as usize) {
            // case1: guest memory fits before the gap
            None | Some(0) => {
                let ram_last_addr = size as u64;
                let shm_start_addr = 0u64;
                let (fw_addr, fw_sz) =
                    firmware_range.unwrap_or((FIRMWARE_START, FIRMWARE_SIZE as usize));
                (
                    size as u64,
                    0,
                    ram_last_addr,
                    shm_start_addr,
                    vec![(GuestAddress(0), size), (GuestAddress(fw_addr), fw_sz)],
                )
            }
            // case2: guest memory extends beyond the gap
            Some(remaining) => {
                let ram_last_addr = FIRST_ADDR_PAST_32BITS + remaining as u64;
                let shm_start_addr = 0u64;
                let (fw_addr, fw_sz) =
                    firmware_range.unwrap_or((FIRMWARE_START, FIRMWARE_SIZE as usize));
                (
                    MMIO_MEM_START,
                    remaining as u64,
                    ram_last_addr,
                    shm_start_addr,
                    vec![
                        (GuestAddress(0), MMIO_MEM_START as usize),
                        (GuestAddress(fw_addr), fw_sz),
                        (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
                    ],
                )
            }
        };
    let info = ArchMemoryInfo {
        ram_below_gap,
        ram_above_gap,
        ram_last_addr,
        shm_start_addr,
        page_size,
        initrd_addr: layout::INITRD_SEV_START,
        firmware_addr: 0,
    };
    (info, regions)
}

/// Writes an MP table to guest memory. Only needed for the TD-Shim path: TD-Shim's
/// ACPI MADT has no IOAPIC entry, so without an MP table the kernel never programs
/// the IOAPIC and virtio-mmio IRQs stop working after the PIC→APIC transition.
#[cfg(feature = "tdx")]
pub fn setup_mptable_for_tdshim(guest_mem: &GuestMemoryMmap, num_cpus: u8) -> super::Result<()> {
    mptable::setup_mptable(guest_mem, num_cpus).map_err(Error::MpTableSetup)
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `initrd` - Information about where the ramdisk image was loaded in the `guest_mem`.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
/// * `pvh` - Whether to use the PVH boot protocol.
#[allow(unused_variables)]
pub fn configure_system(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
    num_cpus: u8,
    pvh: bool,
) -> super::Result<()> {
    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    #[cfg(not(feature = "tee"))]
    mptable::setup_mptable(guest_mem, num_cpus).map_err(Error::MpTableSetup)?;

    if pvh {
        #[cfg(all(not(feature = "tee"), target_os = "linux"))]
        configure_pvh(guest_mem, arch_memory_info, cmdline_addr, initrd)?;
    } else {
        configure_64bit_boot(
            guest_mem,
            arch_memory_info,
            cmdline_addr,
            cmdline_size,
            initrd,
            num_cpus,
        )?;
    }
    Ok(())
}

#[cfg(all(not(feature = "tee"), target_os = "linux"))]
fn configure_pvh(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    cmdline_addr: GuestAddress,
    initrd: &Option<InitrdConfig>,
) -> Result<(), Error> {
    const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336e_c578;
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);
    let himem_start = GuestAddress(layout::HIMEM_START);
    let mut modules: Vec<hvm_modlist_entry> = Vec::new();
    if let Some(initrd_config) = initrd {
        modules.push(hvm_modlist_entry {
            paddr: initrd_config.address.raw_value(),
            size: initrd_config.size as u64,
            ..Default::default()
        });
    }
    let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();
    add_memmap_entry(&mut memmap, 0, mptable::MPTABLE_START, E820_RAM);
    add_memmap_entry(
        &mut memmap,
        mptable::MPTABLE_START,
        layout::RSDP_ADDR - mptable::MPTABLE_START,
        E820_RESERVED,
    );
    let last_addr = GuestAddress(arch_memory_info.ram_last_addr);
    if last_addr < end_32bit_gap_start {
        add_memmap_entry(
            &mut memmap,
            himem_start.raw_value(),
            last_addr.unchecked_offset_from(himem_start),
            E820_RAM,
        );
    } else {
        add_memmap_entry(
            &mut memmap,
            himem_start.raw_value(),
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        );
        if last_addr > first_addr_past_32bits {
            add_memmap_entry(
                &mut memmap,
                first_addr_past_32bits.raw_value(),
                last_addr.unchecked_offset_from(first_addr_past_32bits),
                E820_RAM,
            );
        }
    }
    let mut start_info = hvm_start_info {
        magic: XEN_HVM_START_MAGIC_VALUE,
        version: 1,
        cmdline_paddr: cmdline_addr.raw_value(),
        memmap_paddr: layout::MEMMAP_START,
        memmap_entries: memmap.len() as u32,
        nr_modules: modules.len() as u32,
        ..Default::default()
    };
    if !modules.is_empty() {
        start_info.modlist_paddr = layout::MODLIST_START;
    }
    let mut boot_params =
        BootParams::new::<hvm_start_info>(&start_info, GuestAddress(layout::PVH_INFO_START));
    boot_params.set_sections::<hvm_memmap_table_entry>(&memmap, GuestAddress(layout::MEMMAP_START));
    boot_params.set_modules::<hvm_modlist_entry>(&modules, GuestAddress(layout::MODLIST_START));
    PvhBootConfigurator::write_bootparams(&boot_params, guest_mem)
        .map_err(|_| Error::StartInfoSetup)
}

#[cfg(all(not(feature = "tee"), target_os = "linux"))]
fn add_memmap_entry(memmap: &mut Vec<hvm_memmap_table_entry>, addr: u64, size: u64, mem_type: u32) {
    memmap.push(hvm_memmap_table_entry {
        addr,
        size,
        type_: mem_type,
        reserved: 0,
    });
}

fn configure_64bit_boot(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
    #[allow(unused_variables)] num_cpus: u8,
) -> super::Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);

    let himem_start = GuestAddress(layout::HIMEM_START);

    let mut params: BootParamsWrapper = BootParamsWrapper(boot_params::default());

    params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.0.hdr.header = KERNEL_HDR_MAGIC;
    params.0.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.0.hdr.cmdline_size = cmdline_size as u32;

    params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(initrd_config) = initrd {
        params.0.hdr.ramdisk_image = initrd_config.address.raw_value() as u32;
        params.0.hdr.ramdisk_size = initrd_config.size as u32;
    }

    if cfg!(feature = "tdx") {
        // number of 4k pages
        params.0.hdr.syssize = (arch_memory_info.ram_last_addr / 4096) as u32;
        // nuymber of vCPUs
        params.0.hdr.root_flags = num_cpus as u16;

        add_e820_entry(&mut params.0, 0, EBDA_START - 0x10000, E820_RAM)?;
    } else {
        if cfg!(feature = "tee") {
            params.0.hdr.syssize = num_cpus as u32;
        }
        add_e820_entry(&mut params.0, 0, EBDA_START, E820_RAM)?;
    }

    let last_addr = GuestAddress(arch_memory_info.ram_last_addr);
    if last_addr < end_32bit_gap_start {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // mem_end > himem_start
            last_addr.unchecked_offset_from(himem_start),
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // end_32bit_gap_start > himem_start
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        )?;

        if last_addr > first_addr_past_32bits {
            add_e820_entry(
                &mut params.0,
                first_addr_past_32bits.raw_value(),
                // it's safe to use unchecked_offset_from because
                // mem_end > first_addr_past_32bits
                last_addr.unchecked_offset_from(first_addr_past_32bits),
                E820_RAM,
            )?;
        }
    }

    let zero_page_addr = GuestAddress(layout::ZERO_PAGE_START);
    guest_mem
        .write_obj(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> super::Result<()> {
    if params.e820_entries >= params.e820_map.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_map[params.e820_entries as usize].addr = addr;
    params.e820_map[params.e820_entries as usize].size = size;
    params.e820_map[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arch_gen::x86::bootparam::e820entry;

    const KERNEL_LOAD_ADDR: u64 = 0x0100_0000;
    const KERNEL_SIZE: usize = 0x01E0_0000;

    #[test]
    fn regions_lt_4gb() {
        let (_info, regions) =
            arch_memory_regions(1usize << 29, Some(KERNEL_LOAD_ADDR), KERNEL_SIZE, 0, None);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(KERNEL_LOAD_ADDR as usize, regions[0].1);
        assert_eq!(
            GuestAddress(KERNEL_LOAD_ADDR + KERNEL_SIZE as u64),
            regions[1].0
        );
        assert_eq!(1usize << 29, regions[1].1);
    }

    #[test]
    fn regions_gt_4gb() {
        let (_info, regions) = arch_memory_regions(
            (1usize << 32) + 0x8000,
            Some(KERNEL_LOAD_ADDR),
            KERNEL_SIZE,
            0,
            None,
        );
        assert_eq!(3, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(KERNEL_LOAD_ADDR as usize, regions[0].1);
        assert_eq!(
            GuestAddress(KERNEL_LOAD_ADDR + KERNEL_SIZE as u64),
            regions[1].0
        );
        assert_eq!(GuestAddress(1u64 << 32), regions[2].0);
    }

    #[cfg(not(feature = "tee"))]
    fn assert_initrd_in_low_ram(memory_size: usize, initrd_size: u64) {
        let (info, regions) = arch_memory_regions(
            memory_size,
            Some(KERNEL_LOAD_ADDR),
            KERNEL_SIZE,
            initrd_size,
            None,
        );
        let initrd_end = info.initrd_addr + initrd_size;

        assert_eq!(info.initrd_addr, MMIO_MEM_START - initrd_size);
        assert!(regions.iter().any(|(start, size)| {
            let start = start.raw_value();
            let end = start + *size as u64;

            info.initrd_addr >= start && initrd_end <= end
        }));
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn initrd_stays_in_low_ram_when_memory_crosses_mmio_gap() {
        const INITRD_SIZE: u64 = 32 << 20;

        assert_initrd_in_low_ram(3330usize << 20, INITRD_SIZE);
        assert_initrd_in_low_ram(4096usize << 20, INITRD_SIZE);
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let info = ArchMemoryInfo::default();
        let config_err = configure_system(&gm, &info, GuestAddress(0), 0, &None, 1, false);
        assert!(config_err.is_err());
        #[cfg(not(feature = "tee"))]
        assert_eq!(
            config_err.unwrap_err(),
            super::Error::MpTableSetup(mptable::Error::NotEnoughMemory)
        );

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let (arch_mem_info, arch_mem_regions) =
            arch_memory_regions(mem_size, Some(KERNEL_LOAD_ADDR), KERNEL_SIZE, 0, None);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(
            &gm,
            &arch_mem_info,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            false,
        )
        .unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let (arch_mem_info, arch_mem_regions) =
            arch_memory_regions(mem_size, Some(KERNEL_LOAD_ADDR), KERNEL_SIZE, 0, None);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(
            &gm,
            &arch_mem_info,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            false,
        )
        .unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let (arch_mem_info, arch_mem_regions) =
            arch_memory_regions(mem_size, Some(KERNEL_LOAD_ADDR), KERNEL_SIZE, 0, None);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(
            &gm,
            &arch_mem_info,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            false,
        )
        .unwrap();
    }

    #[cfg(feature = "tee")]
    #[test]
    fn test_arch_memory_regions_tee_dynamic_firmware_hole() {
        let fw_start = 0xfffe_0000u64;
        let fw_size = 0x2_0000usize;
        let (_info, regions) =
            arch_memory_regions(1usize << 29, None, 0, 0, Some((fw_start, fw_size)));
        let has_fw_region = regions
            .iter()
            .any(|&(addr, size)| addr.0 == fw_start && size == fw_size);
        assert!(has_fw_region, "firmware region not found in memory regions");
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_map = [(e820entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_map,
            e820_entries: 1,
            ..Default::default()
        };

        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_map[0]),
            format!("{:?}", expected_params.e820_map[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = params.e820_map.len() as u8 + 1;
        assert!(
            add_e820_entry(
                &mut params,
                e820_map[0].addr,
                e820_map[0].size,
                e820_map[0].type_
            )
            .is_err()
        );
    }
}
