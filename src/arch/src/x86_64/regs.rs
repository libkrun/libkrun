// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem;

use super::gdt::{SegmentDescriptor, gdt_entry, segment_from_gdt};

use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

// Initial pagetables.
pub const PML4_START: u64 = 0x9000;
pub const PDPTE_START: u64 = 0xa000;
pub const PDE_START: u64 = 0xb000;

/// Errors thrown while setting up x86_64 registers.
#[derive(Debug)]
pub enum Error {
    #[cfg(target_os = "linux")]
    /// Failed to get SREGs for this CPU.
    GetStatusRegisters(kvm_ioctls::Error),
    #[cfg(target_os = "linux")]
    /// Failed to set base registers for this CPU.
    SetBaseRegisters(kvm_ioctls::Error),
    #[cfg(target_os = "linux")]
    /// Failed to configure the FPU.
    SetFPURegisters(kvm_ioctls::Error),
    #[cfg(target_os = "linux")]
    /// Failed to set SREGs for this CPU.
    SetStatusRegisters(kvm_ioctls::Error),
    #[cfg(target_os = "windows")]
    /// Failed to get WHP registers.
    GetWhpRegisters(whp::Error),
    #[cfg(target_os = "windows")]
    /// Failed to set WHP registers.
    SetWhpRegisters(whp::Error),
    /// Writing the GDT to RAM failed.
    WriteGDT,
    /// Writing the IDT to RAM failed.
    WriteIDT,
    /// Writing PDPTE to RAM failed.
    WritePDPTEAddress,
    /// Writing PDE to RAM failed.
    WritePDEAddress,
    /// Writing PML4 to RAM failed.
    WritePML4Address,
}
type Result<T> = std::result::Result<T, Error>;

// Re-export platform-specific register setup functions so callers can
// continue to use `regs::setup_fpu`, `regs::setup_regs`, etc.
#[cfg(target_os = "linux")]
pub use super::linux::regs::*;
#[cfg(target_os = "windows")]
pub use super::windows::regs::*;

pub(crate) const BOOT_GDT_OFFSET: u64 = 0x500;
pub(crate) const BOOT_IDT_OFFSET: u64 = 0x520;

pub(crate) const BOOT_GDT_MAX: usize = 4;

pub(crate) const EFER_LMA: u64 = 0x400;
pub(crate) const EFER_LME: u64 = 0x100;

#[cfg(target_os = "linux")]
pub(crate) const X86_CR0_ET: u64 = 0x10;
pub(crate) const X86_CR0_PE: u64 = 0x1;
pub(crate) const X86_CR0_PG: u64 = 0x8000_0000;
pub(crate) const X86_CR4_PAE: u64 = 0x20;

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(Error::WriteGDT)?;
        guest_mem
            .write_obj(*entry, addr)
            .map_err(|_| Error::WriteGDT)?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_obj(val, boot_idt_addr)
        .map_err(|_| Error::WriteIDT)
}

/// Holds the agnostic segment/descriptor table configuration produced by
/// `compute_segments()`.
pub struct BootSegments {
    pub code_seg: SegmentDescriptor,
    pub data_seg: SegmentDescriptor,
    pub tss_seg: SegmentDescriptor,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub idt_base: u64,
    pub idt_limit: u16,
}

/// Holds the page-table configuration produced by `compute_page_tables()`.
pub struct BootPageTables {
    pub cr3: u64,
    pub cr4_bits: u64,
    pub cr0_bits: u64,
}

/// Writes the GDT and IDT to guest memory and returns the agnostic boot
/// segment configuration.
pub fn compute_segments(mem: &GuestMemoryMmap, pvh: bool) -> Result<BootSegments> {
    let gdt_table: [u64; BOOT_GDT_MAX] = if pvh {
        [
            gdt_entry(0, 0, 0),                // NULL
            gdt_entry(0xc09b, 0, 0xffff_ffff), // CODE (32-bit protected mode)
            gdt_entry(0xc093, 0, 0xffff_ffff), // DATA
            gdt_entry(0x008b, 0, 0x67),        // TSS
        ]
    } else {
        [
            gdt_entry(0, 0, 0),            // NULL
            gdt_entry(0xa09b, 0, 0xfffff), // CODE (64-bit long mode)
            gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt_entry(0x808b, 0, 0xfffff), // TSS
        ]
    };

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;

    write_idt_value(0, mem)?;

    Ok(BootSegments {
        code_seg: segment_from_gdt(gdt_table[1], 1),
        data_seg: segment_from_gdt(gdt_table[2], 2),
        tss_seg: segment_from_gdt(gdt_table[3], 3),
        gdt_base: BOOT_GDT_OFFSET,
        gdt_limit: mem::size_of_val(&gdt_table) as u16 - 1,
        idt_base: BOOT_IDT_OFFSET,
        idt_limit: mem::size_of::<u64>() as u16 - 1,
    })
}

/// Writes the identity-mapped page tables to guest memory and returns the
/// agnostic page-table configuration.
pub fn compute_page_tables(mem: &GuestMemoryMmap) -> Result<BootPageTables> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(PML4_START);
    let boot_pdpte_addr = GuestAddress(PDPTE_START);
    let boot_pde_addr = GuestAddress(PDE_START);

    // Entry covering VA [0..512GB)
    mem.write_obj(boot_pdpte_addr.raw_value() | 0x03, boot_pml4_addr)
        .map_err(|_| Error::WritePML4Address)?;

    // Entry covering VA [0..1GB)
    mem.write_obj(boot_pde_addr.raw_value() | 0x03, boot_pdpte_addr)
        .map_err(|_| Error::WritePDPTEAddress)?;
    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(|_| Error::WritePDEAddress)?;
    }

    Ok(BootPageTables {
        cr3: boot_pml4_addr.raw_value(),
        cr4_bits: X86_CR4_PAE,
        cr0_bits: X86_CR0_PG,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemoryMmap, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj(read_addr).unwrap()
    }

    fn validate_page_tables(gm: &GuestMemoryMmap, cr3: u64, cr4: u64, cr0: u64) {
        assert_eq!(0xa003, read_u64(gm, PML4_START));
        assert_eq!(0xb003, read_u64(gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!((i << 21) + 0x83u64, read_u64(gm, PDE_START + (i * 8)));
        }

        assert_eq!(PML4_START, cr3);
        assert!(cr4 & X86_CR4_PAE != 0);
        assert!(cr0 & X86_CR0_PG != 0);
    }

    #[test]
    fn test_compute_page_tables() {
        let gm = create_guest_mem();
        let page_tables = compute_page_tables(&gm).unwrap();
        validate_page_tables(
            &gm,
            page_tables.cr3,
            page_tables.cr4_bits,
            page_tables.cr0_bits,
        );
    }

    #[test]
    fn test_compute_segments() {
        let gm = create_guest_mem();
        let segs = compute_segments(&gm, false).unwrap();
        assert_eq!(0, segs.code_seg.base);
        assert_eq!(0xffffffff, segs.data_seg.limit);
        assert_eq!(0x10, segs.data_seg.selector);
    }
}
