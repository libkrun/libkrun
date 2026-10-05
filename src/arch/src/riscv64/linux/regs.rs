// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::offset_of;
use std::result;

use super::super::get_fdt_addr;
use kvm_bindings::{KVM_REG_RISCV_CORE, KVM_REG_RISCV_TIMER, kvm_riscv_core, kvm_riscv_timer};
use kvm_ioctls::VcpuFd;

use vm_memory::GuestMemoryMmap;

/// Errors thrown while setting riscv64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to set core register (PC, A0, A1 or general purpose ones).
    SetCoreRegister(kvm_ioctls::Error),
    /// Failed to get the timer frequency register.
    GetTimerFrequency(kvm_ioctls::Error),
}
type Result<T> = result::Result<T, Error>;

// Following are macros that help with getting the ID of a riscv64 register,
// including config registers, core registers and timer registers.
//
// The register of core registers are wrapped in the `user_regs_struct` structure. See:
// https://elixir.bootlin.com/linux/v6.10/source/arch/riscv/include/uapi/asm/kvm.h#L62

// Get the ID of a register
#[macro_export]
macro_rules! riscv64_core_reg {
    ($reg_type: tt, $offset: tt) => {
        // The id of a core register can be obtained like this: offset = id &
        // ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_RISCV_CORE). Thus,
        // id = KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CORE | offset
        //
        // To generalize, the id of a register can be obtained by:
        // id = KVM_REG_RISCV | KVM_REG_SIZE_U64 |
        //      KVM_REG_RISCV_CORE/KVM_REG_RISCV_CONFIG/KVM_REG_RISCV_TIMER |
        //      offset
        kvm_bindings::KVM_REG_RISCV as u64
            | u64::from($reg_type)
            | u64::from(kvm_bindings::KVM_REG_SIZE_U64)
            | (($offset / std::mem::size_of::<u64>()) as u64)
    };
}

/// Configure core registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `cpu_id` - Index of current vcpu.
/// * `boot_ip` - Starting instruction pointer.
/// * `mem` - Reserved DRAM for current VM.
pub fn setup_regs(vcpu: &VcpuFd, cpu_id: u8, boot_ip: u64, mem: &GuestMemoryMmap) -> Result<()> {
    // Setting the A0 to the current `cpu_id`.
    let offset = offset_of!(kvm_riscv_core, regs.a0);
    vcpu.set_one_reg(
        riscv64_core_reg!(KVM_REG_RISCV_CORE, offset),
        &u64::from(cpu_id).to_le_bytes(),
    )
    .map_err(Error::SetCoreRegister)?;

    // Setting the PC (Processor Counter) to the current program address (kernel address).
    let offset = offset_of!(kvm_riscv_core, regs.pc);
    vcpu.set_one_reg(
        riscv64_core_reg!(KVM_REG_RISCV_CORE, offset),
        &boot_ip.to_le_bytes(),
    )
    .map_err(Error::SetCoreRegister)?;

    // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
    // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
    let offset = offset_of!(kvm_riscv_core, regs.a1);
    vcpu.set_one_reg(
        riscv64_core_reg!(KVM_REG_RISCV_CORE, offset),
        &get_fdt_addr(mem).to_le_bytes(),
    )
    .map_err(Error::SetCoreRegister)?;
    Ok(())
}

/// Reads the `time` CSR frequency (in Hz) of a vCPU
pub fn read_timer_frequency(vcpu: &VcpuFd) -> Result<u64> {
    let offset = offset_of!(kvm_riscv_timer, frequency);
    let mut data = [0u8; 8];
    vcpu.get_one_reg(riscv64_core_reg!(KVM_REG_RISCV_TIMER, offset), &mut data)
        .map_err(Error::GetTimerFrequency)?;
    Ok(u64::from_le_bytes(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::riscv64::{arch_memory_regions, layout};
    use kvm_ioctls::Kvm;

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000, 0, None);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");

        match setup_regs(&vcpu, 0, 0x0, &mem).unwrap_err() {
            Error::SetCoreRegister(ref e) => assert_eq!(e.errno(), libc::ENOEXEC),
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_read_timer_frequency() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let freq = read_timer_frequency(&vcpu).unwrap();
        assert_ne!(freq, 0);
    }
}
