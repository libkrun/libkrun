// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::{mem, mem::offset_of, num::TryFromIntError, result};

use crate::ArchMemoryInfo;

use kvm_bindings::{
    KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_MASK,
    KVM_REG_ARM64_SYSREG_CRM_SHIFT, KVM_REG_ARM64_SYSREG_CRN_MASK, KVM_REG_ARM64_SYSREG_CRN_SHIFT,
    KVM_REG_ARM64_SYSREG_OP0_MASK, KVM_REG_ARM64_SYSREG_OP0_SHIFT, KVM_REG_ARM64_SYSREG_OP1_MASK,
    KVM_REG_ARM64_SYSREG_OP1_SHIFT, KVM_REG_ARM64_SYSREG_OP2_MASK, KVM_REG_ARM64_SYSREG_OP2_SHIFT,
    KVM_REG_SIZE_U64, kvm_regs, user_pt_regs,
};
use kvm_ioctls::VcpuFd;

/// Errors thrown while setting aarch64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to set core register (PC, PSTATE or general purpose ones).
    SetCoreRegister(kvm_ioctls::Error),
    /// Failed to get a system register.
    GetSysRegister(kvm_ioctls::Error),
    /// The value returned for the MPIDR register is bigger than 64 bits.
    MpidrTooBig(TryFromIntError),
}
type Result<T> = result::Result<T, Error>;

#[allow(non_upper_case_globals)]
// PSR (Processor State Register) bits.
// Taken from arch/arm64/include/uapi/asm/ptrace.h.
const PSR_MODE_EL1h: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
// Taken from arch/arm64/kvm/inject_fault.c.
const PSTATE_FAULT_BITS_64: u64 = PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

// This is a macro that helps with getting the ID of a aarch64 core register.
// The core register are represented by the user_pt_regs structure. Look for it in
// arch/arm64/include/uapi/asm/ptrace.h.
macro_rules! arm64_core_reg {
    ($reg: tt) => {
        // As per `kvm_arm_copy_reg_indices`, the id of a core register can be obtained like this:
        // `const u64 core_reg = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | i`, where i is obtained with:
        // `for (i = 0; i < sizeof(struct kvm_regs) / sizeof(__u32); i++) {`
        // We are using here `user_pt_regs` since this structure contains the core register and it is at
        // the start of `kvm_regs`.
        // struct kvm_regs {
        //	struct user_pt_regs regs;	/* sp = sp_el0 */
        //
        //	__u64	sp_el1;
        //	__u64	elr_el1;
        //
        //	__u64	spsr[KVM_NR_SPSR];
        //
        //	struct user_fpsimd_state fp_regs;
        //};
        // struct user_pt_regs {
        //	__u64		regs[31];
        //	__u64		sp;
        //	__u64		pc;
        //	__u64		pstate;
        //};
        // In our implementation we need: pc, pstate and user_pt_regs->regs[0].
        KVM_REG_ARM64 as u64
            | KVM_REG_SIZE_U64 as u64
            | u64::from(KVM_REG_ARM_CORE)
            | (((offset_of!(kvm_regs, regs) + offset_of!(user_pt_regs, $reg)) / mem::size_of::<u32>()) as u64)
    };
}

// This macro computes the ID of a specific ARM64 system register similar to how
// the kernel C macro does.
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/uapi/asm/kvm.h#L203
macro_rules! arm64_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $crn: tt, $crm: tt, $op2: tt) => {
        const $name: u64 = KVM_REG_ARM64 as u64
            | KVM_REG_SIZE_U64 as u64
            | KVM_REG_ARM64_SYSREG as u64
            | ((($op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
            | ((($op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
            | ((($crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
            | ((($crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
            | ((($op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP2_MASK as u64);
    };
}

// Constant imported from the Linux kernel:
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/asm/sysreg.h#L135
arm64_sys_reg!(MPIDR_EL1, 3, 0, 0, 0, 5);

// KVM_REG_ARM_TIMER_CNT: the guest's virtual counter (CNTVCT_EL0) as exposed by KVM's
// userspace timer API. NOTE the deliberately non-architectural encoding (op0=3, op1=3,
// CRn=14, CRm=3, op2=2): this is KVM's legacy UAPI id (see kvm/api.rst and
// arch/arm64/include/uapi/asm/kvm.h), NOT the CNTVCT_EL0 sysreg encoding. Writing it
// makes KVM recompute the virtual counter offset so the guest observes the written
// value — the sanctioned way for userspace to move guest time. CNTVOFF_EL2 itself is
// an EL2 register that mainline KVM only exposes to nested-virt guests; get/set on an
// ordinary guest fails with ENOENT, which is why the previous CNTVOFF-based adjuster
// broke every pause/resume (and fork rollback) on aarch64 KVM hosts.
arm64_sys_reg!(KVM_REG_ARM_TIMER_CNT, 3, 3, 14, 3, 2);

/// Read the guest's virtual counter (`CNTVCT`) via KVM's userspace timer register.
///
/// Captured when a vCPU pauses; writing the same value back at resume freezes guest
/// time across the pause (KVM derives the new counter offset from the written value).
pub fn read_virtual_timer_count(vcpu: &VcpuFd) -> Result<u64> {
    let mut data = [0u8; 8];
    vcpu.get_one_reg(KVM_REG_ARM_TIMER_CNT, &mut data)
        .map_err(Error::GetSysRegister)?;
    Ok(u64::from_le_bytes(data))
}

/// Write the guest's virtual counter (`CNTVCT`) via KVM's userspace timer register.
///
/// On kernels with a per-VM counter offset (6.4+) any vCPU's write retargets the whole
/// VM; on older per-vCPU-offset kernels each vCPU needs its own write. Writing every
/// vCPU's pause-time capture back satisfies both: the captures are taken at the same
/// pause instant, so the per-VM case converges on the last writer's near-identical
/// value instead of compounding (which a delta-based read-modify-write would do).
pub fn write_virtual_timer_count(vcpu: &VcpuFd, count: u64) -> Result<()> {
    vcpu.set_one_reg(KVM_REG_ARM_TIMER_CNT, &count.to_le_bytes())
        .map_err(Error::SetCoreRegister)?;
    Ok(())
}

/// Configure core registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `cpu_id` - Index of current vcpu.
/// * `boot_ip` - Starting instruction pointer.
/// * `mem_info` - Structure with information about the memory layout.
pub fn setup_regs(
    vcpu: &VcpuFd,
    cpu_id: u8,
    boot_ip: u64,
    mem_info: &ArchMemoryInfo,
) -> Result<()> {
    // Get the register index of the PSTATE (Processor State) register.
    vcpu.set_one_reg(arm64_core_reg!(pstate), &PSTATE_FAULT_BITS_64.to_le_bytes())
        .map_err(Error::SetCoreRegister)?;

    // Other vCPUs are powered off initially awaiting PSCI wakeup.
    if cpu_id == 0 {
        // Setting the PC (Processor Counter) to the current program address (kernel address).
        vcpu.set_one_reg(arm64_core_reg!(pc), &boot_ip.to_le_bytes())
            .map_err(Error::SetCoreRegister)?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
        // For direct kernel boot, we place it at the end of DRAM.
        vcpu.set_one_reg(arm64_core_reg!(regs), &mem_info.fdt_addr.to_le_bytes())
            .map_err(Error::SetCoreRegister)?;
    }
    Ok(())
}

/// Read the MPIDR - Multiprocessor Affinity Register.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn read_mpidr(vcpu: &VcpuFd) -> Result<u64> {
    let mut data = [0u8; 8];
    vcpu.get_one_reg(MPIDR_EL1, &mut data)
        .map_err(Error::GetSysRegister)?;
    Ok(u64::from_le_bytes(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{arch_memory_regions, layout};
    use kvm_ioctls::Kvm;

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let (mem_info, _regions) = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000, 0, None);

        match setup_regs(&vcpu, 0, 0x0, &mem_info).unwrap_err() {
            Error::SetCoreRegister(ref e) => assert_eq!(e.errno(), libc::ENOEXEC),
            _ => panic!("Expected to receive Error::SetCoreRegister"),
        }
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();

        assert!(setup_regs(&vcpu, 0, 0x0, &mem_info).is_ok());
    }
    #[test]
    fn test_read_mpidr() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        assert!(read_mpidr(&vcpu).is_err());

        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(read_mpidr(&vcpu).unwrap(), 0x80000000);
    }
}
