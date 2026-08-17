// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::GuestMemoryMmap;

use super::super::gdt::SegmentDescriptor;
use super::super::layout::{
    AP_TRAMPOLINE_START, BOOT_STACK_POINTER, RESET_VECTOR_SEV_AP, ZERO_PAGE_START,
};
use super::super::regs::{
    EFER_LMA, EFER_LME, Error, X86_CR0_PE, compute_page_tables, compute_segments,
};
use windows_sys::Win32::System::Hypervisor::*;

type Result<T> = std::result::Result<T, Error>;

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the WHP VCPU.
/// * `boot_ip` - Starting instruction pointer.
pub fn setup_regs(vcpu: &whp::WhpVcpu, boot_ip: u64) -> Result<()> {
    if vcpu.index() == 0 {
        vcpu.set_registers64([
            (WHvX64RegisterRflags, 0x0000_0000_0000_0002u64),
            (WHvX64RegisterRip, boot_ip),
            (WHvX64RegisterRsp, BOOT_STACK_POINTER),
            (WHvX64RegisterRbp, BOOT_STACK_POINTER),
            (WHvX64RegisterRsi, ZERO_PAGE_START),
        ])
        .map_err(Error::SetWhpRegisters)
    } else {
        let rip = if cfg!(feature = "tee") {
            RESET_VECTOR_SEV_AP
        } else {
            AP_TRAMPOLINE_START
        };

        vcpu.set_registers64([
            (WHvX64RegisterRflags, 0x0000_0000_0000_0002u64),
            (WHvX64RegisterRip, rip),
        ])
        .map_err(Error::SetWhpRegisters)
    }
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the WHP VCPU.
pub fn setup_sregs(mem: &GuestMemoryMmap, vcpu: &whp::WhpVcpu) -> Result<()> {
    if vcpu.index() != 0 {
        if cfg!(feature = "tee") {
            return Ok(());
        }
        return setup_ap_segments(vcpu);
    }

    let segs = compute_segments(mem, false)?;
    let pt = compute_page_tables(mem)?;

    let to_segment = |seg: &SegmentDescriptor| -> WHV_REGISTER_VALUE {
        let mut v: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
        let s = unsafe { &mut v.Segment };
        s.Base = seg.base;
        s.Limit = seg.limit;
        s.Selector = seg.selector;
        s.Anonymous.Anonymous._bitfield = (seg.type_ as u16)
            | ((seg.s as u16) << 4)
            | ((seg.dpl as u16) << 5)
            | ((seg.present as u16) << 7)
            | ((seg.avl as u16) << 12)
            | ((seg.l as u16) << 13)
            | ((seg.db as u16) << 14)
            | ((seg.g as u16) << 15);
        v
    };

    let to_table = |base: u64, limit: u16| -> WHV_REGISTER_VALUE {
        let mut v: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
        let t = unsafe { &mut v.Table };
        t.Base = base;
        t.Limit = limit;
        v
    };

    let to_reg64 = |val: u64| -> WHV_REGISTER_VALUE {
        let mut v: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
        v.Reg64 = val;
        v
    };

    let [cr0, cr4, efer] = vcpu
        .get_registers64([WHvX64RegisterCr0, WHvX64RegisterCr4, WHvX64RegisterEfer])
        .map_err(Error::GetWhpRegisters)?;
    vcpu.set_registers([
        (WHvX64RegisterCs, to_segment(&segs.code_seg)),
        (WHvX64RegisterDs, to_segment(&segs.data_seg)),
        (WHvX64RegisterEs, to_segment(&segs.data_seg)),
        (WHvX64RegisterFs, to_segment(&segs.data_seg)),
        (WHvX64RegisterGs, to_segment(&segs.data_seg)),
        (WHvX64RegisterSs, to_segment(&segs.data_seg)),
        (WHvX64RegisterTr, to_segment(&segs.tss_seg)),
        (WHvX64RegisterGdtr, to_table(segs.gdt_base, segs.gdt_limit)),
        (WHvX64RegisterIdtr, to_table(segs.idt_base, segs.idt_limit)),
        (WHvX64RegisterCr0, to_reg64(cr0 | X86_CR0_PE | pt.cr0_bits)),
        (WHvX64RegisterCr3, to_reg64(pt.cr3)),
        (WHvX64RegisterCr4, to_reg64(cr4 | pt.cr4_bits)),
        (WHvX64RegisterEfer, to_reg64(efer | EFER_LME | EFER_LMA)),
    ])
    .map_err(Error::SetWhpRegisters)
}

/// Reset CS.base to 0 for an AP vCPU so that RIP addresses land in low
/// memory rather than at the default reset CS.base of 0xFFFF_0000.
/// All other segment registers and control registers stay at their
/// power-on defaults (real mode).
fn setup_ap_segments(vcpu: &whp::WhpVcpu) -> Result<()> {
    let [mut value] = vcpu
        .get_registers([WHvX64RegisterCs])
        .map_err(Error::GetWhpRegisters)?;
    value.Segment.Base = 0;
    value.Segment.Selector = 0;
    vcpu.set_registers([(WHvX64RegisterCs, value)])
        .map_err(Error::SetWhpRegisters)
}

#[cfg(test)]
mod tests {
    use super::super::super::regs::{BOOT_GDT_OFFSET, BOOT_IDT_OFFSET, X86_CR0_PG, X86_CR4_PAE};
    use super::*;
    use std::ffi::c_void;
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};
    use whp::{WhpVcpu, WhpVm};

    const GUEST_MEM_SIZE: usize = 0x10000;

    fn create_vm_and_vcpu(vcpu_count: u32) -> (Arc<WhpVm>, WhpVcpu) {
        let vm = Arc::new(WhpVm::new(vcpu_count).unwrap());
        let vcpu = WhpVcpu::new(vm.clone(), 0).unwrap();
        (vm, vcpu)
    }

    fn create_vm_with_memory() -> (Arc<WhpVm>, WhpVcpu, GuestMemoryMmap) {
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE)]).unwrap();
        let vm = Arc::new(WhpVm::new(1).unwrap());

        let host_addr = gm.get_host_address(GuestAddress(0)).unwrap();
        unsafe {
            vm.map_memory(host_addr as *mut c_void, 0, GUEST_MEM_SIZE as u64)
                .unwrap();
        }

        let vcpu = WhpVcpu::new(vm.clone(), 0).unwrap();
        (vm, vcpu, gm)
    }

    #[test]
    fn test_setup_regs_bsp() {
        let (_vm, vcpu) = create_vm_and_vcpu(1);
        let boot_ip: u64 = 0x1_0000;
        setup_regs(&vcpu, boot_ip).unwrap();

        let [rflags, rip, rsp, rbp, rsi] = vcpu
            .get_registers64([
                WHvX64RegisterRflags,
                WHvX64RegisterRip,
                WHvX64RegisterRsp,
                WHvX64RegisterRbp,
                WHvX64RegisterRsi,
            ])
            .unwrap();

        assert_eq!(rflags & 0x2, 0x2);
        assert_eq!(rip, boot_ip);
        assert_eq!(rsp, BOOT_STACK_POINTER);
        assert_eq!(rbp, BOOT_STACK_POINTER);
        assert_eq!(rsi, ZERO_PAGE_START);
    }

    #[test]
    fn test_setup_regs_ap() {
        let vm = Arc::new(WhpVm::new(2).unwrap());
        let _bsp = WhpVcpu::new(vm.clone(), 0).unwrap();
        let ap = WhpVcpu::new(vm.clone(), 1).unwrap();

        setup_regs(&ap, 0).unwrap();

        let [rflags, rip] = ap
            .get_registers64([WHvX64RegisterRflags, WHvX64RegisterRip])
            .unwrap();

        assert_eq!(rflags & 0x2, 0x2);
        let expected_rip = if cfg!(feature = "tee") {
            RESET_VECTOR_SEV_AP
        } else {
            AP_TRAMPOLINE_START
        };
        assert_eq!(rip, expected_rip);
    }

    #[test]
    fn test_setup_sregs() {
        let (_vm, vcpu, gm) = create_vm_with_memory();
        setup_sregs(&gm, &vcpu).unwrap();

        let read_u64 = |offset: u64| -> u64 { gm.read_obj(GuestAddress(offset)).unwrap() };

        // Verify GDT was written to guest memory
        assert_eq!(0x0, read_u64(BOOT_GDT_OFFSET));
        assert_eq!(0xaf_9b00_0000_ffff, read_u64(BOOT_GDT_OFFSET + 8));
        assert_eq!(0xcf_9300_0000_ffff, read_u64(BOOT_GDT_OFFSET + 16));
        assert_eq!(0x8f_8b00_0000_ffff, read_u64(BOOT_GDT_OFFSET + 24));
        assert_eq!(0x0, read_u64(BOOT_IDT_OFFSET));

        // Verify control registers
        let [cr0, cr3, cr4, efer] = vcpu
            .get_registers64([
                WHvX64RegisterCr0,
                WHvX64RegisterCr3,
                WHvX64RegisterCr4,
                WHvX64RegisterEfer,
            ])
            .unwrap();

        assert!(cr0 & X86_CR0_PE != 0, "Protected mode not enabled");
        assert!(cr0 & X86_CR0_PG != 0, "Paging not enabled");
        assert_eq!(cr3, 0x9000, "CR3 should point to PML4");
        assert!(cr4 & X86_CR4_PAE != 0, "PAE not enabled");
        assert!(efer & EFER_LME != 0, "Long mode not enabled");
        assert!(efer & EFER_LMA != 0, "Long mode not active");

        // Verify CS segment via structured register read
        let [cs_val] = vcpu.get_registers([WHvX64RegisterCs]).unwrap();
        let cs = unsafe { cs_val.Segment };
        assert_eq!(cs.Base, 0);
        assert_eq!(cs.Selector, 0x08);

        // Verify page tables in guest memory
        assert_eq!(0xa003, read_u64(0x9000)); // PML4 -> PDPTE
        assert_eq!(0xb003, read_u64(0xa000)); // PDPTE -> PDE
        for i in 0..512u64 {
            assert_eq!((i << 21) + 0x83, read_u64(0xb000 + (i * 8)));
        }
    }

    #[test]
    fn test_setup_ap_segments() {
        let vm = Arc::new(WhpVm::new(2).unwrap());
        let _bsp = WhpVcpu::new(vm.clone(), 0).unwrap();
        let ap = WhpVcpu::new(vm.clone(), 1).unwrap();

        setup_ap_segments(&ap).unwrap();

        let [cs_val] = ap.get_registers([WHvX64RegisterCs]).unwrap();
        let cs = unsafe { cs_val.Segment };
        assert_eq!(cs.Base, 0);
        assert_eq!(cs.Selector, 0);
    }
}
