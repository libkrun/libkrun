// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::fd::AsRawFd;

use crate::Error as DeviceError;
use crate::bus::BusDevice;
use crate::legacy::irqchip::IrqChipT;

use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config, kvm_reinject_control};
use kvm_ioctls::{Error, VmFd};
use utils::eventfd::EventFd;

nix::ioctl_write_ptr_bad!(
    set_pit_reinject,
    nix::request_code_none!(0xae, 0x71),
    kvm_reinject_control
);

pub struct KvmIoapic {}

impl KvmIoapic {
    pub fn new(vm: &VmFd) -> Result<Self, Error> {
        vm.create_irq_chip()?;
        let pit_config = kvm_pit_config {
            // We need to enable the emulation of a dummy speaker port stub so that writing to port
            // 0x61 (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        vm.create_pit2(pit_config)?;

        // PIT reinjection inhibits KVM APIC acceleration, including
        // acceleration of unrelated inter-vCPU interrupts.
        let reinject = kvm_reinject_control {
            pit_reinject: 0,
            ..Default::default()
        };
        // SAFETY: the VM owns the fd and the initialized structure lives
        // through this synchronous ioctl, which copies its input.
        unsafe { set_pit_reinject(vm.as_raw_fd(), &reinject) }
            .map_err(|error| Error::new(error as i32))?;

        Ok(Self {})
    }
}

impl IrqChipT for KvmIoapic {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(interrupt_evt) = interrupt_evt {
            if let Err(e) = interrupt_evt.write(1) {
                error!("Failed to signal used queue: {e:?}");
                return Err(DeviceError::FailedSignalingUsedQueue(e));
            }
        } else {
            error!("EventFd not set up for irq line");
            return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::NotFound,
                "EventFd not set up for irq line",
            )));
        }
        Ok(())
    }
}

impl BusDevice for KvmIoapic {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}
