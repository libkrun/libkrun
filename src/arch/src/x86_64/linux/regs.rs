// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_segment, kvm_sregs};
use kvm_ioctls::VcpuFd;
use vm_memory::GuestMemoryMmap;

use super::super::gdt::SegmentDescriptor;
use super::super::layout::{
    BOOT_STACK_POINTER, PVH_INFO_START, RESET_VECTOR_SEV_AP, ZERO_PAGE_START,
};
use super::super::regs::{
    EFER_LMA, EFER_LME, Error, X86_CR0_ET, X86_CR0_PE, compute_page_tables, compute_segments,
};

type Result<T> = std::result::Result<T, Error>;

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<()> {
    let fpu: kvm_fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };

    vcpu.set_fpu(&fpu).map_err(Error::SetFPURegisters)
}

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `boot_ip` - Starting instruction pointer.
/// * `pvh` - Whether to use the PVH boot protocol.
pub fn setup_regs(vcpu: &VcpuFd, boot_ip: u64, id: u8, pvh: bool) -> Result<()> {
    let regs: kvm_regs = if id == 0 || cfg!(not(feature = "tee")) {
        if pvh {
            kvm_regs {
                rflags: 0x0000_0000_0000_0002u64,
                rip: boot_ip,
                // PVH ABI: rbx points to hvm_start_info
                rbx: PVH_INFO_START,
                ..Default::default()
            }
        } else {
            kvm_regs {
                rflags: 0x0000_0000_0000_0002u64,
                rip: boot_ip,
                // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments are
                // made to rsp (i.e. reserving space for local variables or pushing values on to the stack),
                // local variables and function parameters are still accessible from a constant offset from rbp.
                rsp: BOOT_STACK_POINTER,
                // Starting stack pointer.
                rbp: BOOT_STACK_POINTER,
                // Must point to zero page address per Linux ABI. This is x86_64 specific.
                rsi: ZERO_PAGE_START,
                ..Default::default()
            }
        }
    } else {
        kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: RESET_VECTOR_SEV_AP,
            ..Default::default()
        }
    };

    vcpu.set_regs(&regs).map_err(Error::SetBaseRegisters)
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `pvh` - Whether to use the PVH boot protocol.
pub fn setup_sregs(mem: &GuestMemoryMmap, vcpu: &VcpuFd, id: u8, pvh: bool) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;

    if cfg!(not(feature = "tee")) {
        configure_segments_and_sregs(mem, &mut sregs, pvh)?;
        if !pvh {
            setup_page_tables(mem, &mut sregs)?; // TODO(dgreid) - Can this be done once per system instead
        }
    } else if id != 0 {
        //sregs.cs.selector = 0x9100;
        //sregs.cs.base = 0x91000;
    }

    vcpu.set_sregs(&sregs).map_err(Error::SetStatusRegisters)
}

fn kvm_segment_from(seg: &SegmentDescriptor) -> kvm_segment {
    kvm_segment {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector,
        type_: seg.type_,
        present: seg.present,
        dpl: seg.dpl,
        db: seg.db,
        s: seg.s,
        l: seg.l,
        g: seg.g,
        avl: seg.avl,
        padding: 0,
        unusable: seg.unusable,
    }
}

fn configure_segments_and_sregs(
    mem: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
    pvh: bool,
) -> Result<()> {
    let segs = compute_segments(mem, pvh)?;

    let code_seg = kvm_segment_from(&segs.code_seg);
    let data_seg = kvm_segment_from(&segs.data_seg);
    let tss_seg = kvm_segment_from(&segs.tss_seg);

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    sregs.gdt.base = segs.gdt_base;
    sregs.gdt.limit = segs.gdt_limit;
    sregs.idt.base = segs.idt_base;
    sregs.idt.limit = segs.idt_limit;

    if pvh {
        sregs.cr0 = X86_CR0_PE | X86_CR0_ET;
        sregs.cr4 = 0;
    } else {
        /* 64-bit protected mode */
        sregs.cr0 |= X86_CR0_PE;
        sregs.efer |= EFER_LME | EFER_LMA;
    }

    Ok(())
}

fn setup_page_tables(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    let pt = compute_page_tables(mem)?;
    sregs.cr3 = pt.cr3;
    sregs.cr4 |= pt.cr4_bits;
    sregs.cr0 |= pt.cr0_bits;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::regs::{
        BOOT_GDT_OFFSET, BOOT_IDT_OFFSET, PDE_START, PDPTE_START, PML4_START, X86_CR0_PE,
        X86_CR0_PG, X86_CR4_PAE,
    };
    use super::*;
    use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    use kvm_ioctls::Kvm;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemoryMmap, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj(read_addr).unwrap()
    }

    fn validate_segments_and_sregs(gm: &GuestMemoryMmap, sregs: &kvm_sregs) {
        assert_eq!(0x0, read_u64(gm, BOOT_GDT_OFFSET));
        assert_eq!(0xaf_9b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 8));
        assert_eq!(0xcf_9300_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 16));
        assert_eq!(0x8f_8b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 24));
        assert_eq!(0x0, read_u64(gm, BOOT_IDT_OFFSET));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xffffffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0xffffffff, sregs.tr.limit);
        assert_eq!(0, sregs.tr.avl);
        assert!(sregs.cr0 & X86_CR0_PE != 0);
        assert!(sregs.efer & EFER_LME != 0 && sregs.efer & EFER_LMA != 0);
    }

    #[test]
    fn test_configure_segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = create_guest_mem();
        configure_segments_and_sregs(&gm, &mut sregs, false).unwrap();

        validate_segments_and_sregs(&gm, &sregs);
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

    #[test]
    fn test_setup_fpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_fpu(&vcpu).unwrap();

        let expected_fpu: kvm_fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        let actual_fpu: kvm_fpu = vcpu.get_fpu().unwrap();
        // TODO: auto-generate kvm related structures with PartialEq on.
        assert_eq!(expected_fpu.fcw, actual_fpu.fcw);
        // Setting the mxcsr register from kvm_fpu inside setup_fpu does not influence anything.
        // See 'kvm_arch_vcpu_ioctl_set_fpu' from arch/x86/kvm/x86.c.
        // The mxcsr will stay 0 and the assert below fails. Decide whether or not we should
        // remove it at all.
        // assert!(expected_fpu.mxcsr == actual_fpu.mxcsr);
    }

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let expected_regs: kvm_regs = kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: 1,
            rsp: BOOT_STACK_POINTER,
            rbp: BOOT_STACK_POINTER,
            rsi: ZERO_PAGE_START,
            ..Default::default()
        };

        setup_regs(&vcpu, expected_regs.rip, 1, false).unwrap();

        let actual_regs: kvm_regs = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }

    #[test]
    fn test_setup_sregs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let gm = create_guest_mem();

        // KVM validates EFER against guest CPUID, so expose long mode first.
        let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
        vcpu.set_cpuid2(&cpuid).unwrap();

        assert!(vcpu.set_sregs(&Default::default()).is_ok());
        setup_sregs(&gm, &vcpu, 1, false).unwrap();

        let mut sregs: kvm_sregs = vcpu.get_sregs().unwrap();
        // for AMD KVM_GET_SREGS returns g = 0 for each kvm_segment.
        // We set it to 1, otherwise the test will fail.
        sregs.gs.g = 1;

        validate_segments_and_sregs(&gm, &sregs);
        validate_page_tables(&gm, sregs.cr3, sregs.cr4, sregs.cr0);
    }
}
