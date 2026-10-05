// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use crate::Error as DeviceError;
use crate::bus::BusDevice;
use crate::legacy::aia::AIADevice;
use crate::legacy::irqchip::IrqChipT;

use kvm_bindings::kvm_irq_level;
use kvm_ioctls::{DeviceFd, VmFd};
use utils::eventfd::EventFd;
use vmm_sys_util::ioctl_iow_nr;

const KVMIO: u32 = 0xAE; // KVM's ioctl type/magic number
const KVM_IRQ_LINE_NR: u32 = 0x61; // KVM_IRQ_LINE request number (include/uapi/linux/kvm.h)

// kvm-ioctls keeps its own copy of this ioctl private to `VmFd`, so it is
// redefined here (via the same macro kvm-ioctls itself uses) for direct use
// on the VM's raw fd.
ioctl_iow_nr!(KVM_IRQ_LINE, KVMIO, KVM_IRQ_LINE_NR, kvm_irq_level);

pub struct KvmAia {
    _device_fd: DeviceFd,
    /// Raw fd of the KVM VM this device belongs to.
    vm_fd: RawFd,

    /// Number of CPUs handled by the device
    vcpu_count: u32,
}

impl KvmAia {
    pub fn new(vm: &VmFd, vcpu_count: u32) -> Result<Self, DeviceError> {
        // Create a KVM AIA device
        let mut aia_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_RISCV_AIA,
            fd: 0,
            flags: 0,
        };
        let device_fd = vm.create_device(&mut aia_device).unwrap();

        // Setting up the number of wired interrupt sources
        let nr_irqs: u32 = arch::riscv64::layout::IRQ_MAX + 1;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_SRCS),
            addr: nr_irqs_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        // Setting up hart_bits
        let max_hart_index = vcpu_count as u64 - 1;
        let hart_bits = std::cmp::max(64 - max_hart_index.leading_zeros(), 1);
        let hart_bits_ptr = &hart_bits as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_HART_BITS),
            addr: hart_bits_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        // Designate addresses of APLIC and IMSICS

        // Setting up RISC-V APLIC
        let aplic_addr = arch::riscv64::layout::APLIC_START;
        let aplic_addr_ptr = &aplic_addr as *const u64;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_ADDR_APLIC),
            addr: aplic_addr_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        // Setting up RISC-V IMSICs
        for cpu_index in 0..vcpu_count {
            let cpu_imsic_addr = arch::riscv64::layout::IMSIC_START
                + (cpu_index * kvm_bindings::KVM_DEV_RISCV_IMSIC_SIZE) as u64;
            let cpu_imsic_addr_ptr = &cpu_imsic_addr as *const u64;
            let attr = kvm_bindings::kvm_device_attr {
                group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
                attr: cpu_index as u64 + 1,
                addr: cpu_imsic_addr_ptr as u64,
                flags: 0,
            };
            device_fd.set_device_attr(&attr).unwrap();
        }

        // Finalizing the AIA device
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CTRL_INIT),
            addr: 0,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        Ok(Self {
            _device_fd: device_fd,
            vm_fd: vm.as_raw_fd(),
            vcpu_count,
        })
    }

    /// Issues a KVM_IRQ_LINE ioctl, setting `irq` to `active`.
    ///
    /// This talks directly to KVM's in-kernel AIA/APLIC emulation
    /// (`kvm_riscv_aia_aplic_inject()`), which treats the source as a
    /// level signal: injecting an MSI only on an actual low-to-high
    /// transition for level-triggered sources.
    fn set_irq_line(&self, irq: u32, active: bool) -> Result<(), DeviceError> {
        let mut irq_level = kvm_irq_level::default();
        irq_level.__bindgen_anon_1.irq = irq;
        irq_level.level = u32::from(active);

        // SAFETY: `self.vm_fd` is the raw fd of the KVM VM that owns this
        // device; it is guaranteed to stay open and valid for at least as
        // long as `self` exists. `KVM_IRQ_LINE()` is the request number for
        // a `kvm_irq_level`-sized argument, and we pass a valid pointer to
        // one.
        let ret = unsafe { libc::ioctl(self.vm_fd, KVM_IRQ_LINE() as _, &irq_level as *const _) };
        if ret == 0 {
            Ok(())
        } else {
            Err(DeviceError::FailedSignalingUsedQueue(
                io::Error::last_os_error(),
            ))
        }
    }
}

impl IrqChipT for KvmAia {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        let Some(irq_line) = irq_line else {
            error!("IRQ line not configured");
            return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::NotFound,
                "IRQ line not configured".to_string(),
            )));
        };
        self.set_irq_line(irq_line, true)
    }

    fn clear_irq(&self, irq_line: Option<u32>) -> Result<(), DeviceError> {
        let Some(irq_line) = irq_line else {
            return Ok(());
        };
        self.set_irq_line(irq_line, false)
    }
}

impl BusDevice for KvmAia {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl AIADevice for KvmAia {
    fn aplic_compatibility(&self) -> &str {
        "riscv,aplic"
    }

    fn aplic_properties(&self) -> [u32; 4] {
        [
            0,
            arch::riscv64::layout::APLIC_START as u32,
            0,
            kvm_bindings::KVM_DEV_RISCV_APLIC_SIZE,
        ]
    }

    fn imsic_compatibility(&self) -> &str {
        "riscv,imsics"
    }

    fn imsic_properties(&self) -> [u32; 4] {
        [
            0,
            arch::riscv64::layout::IMSIC_START as u32,
            0,
            kvm_bindings::KVM_DEV_RISCV_IMSIC_SIZE * self.vcpu_count,
        ]
    }

    fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    fn msi_compatible(&self) -> bool {
        true
    }
}
