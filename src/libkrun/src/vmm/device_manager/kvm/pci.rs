// Copyright 2026 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! PCI root and virtio-pci registration for the x86_64 KVM backend.

use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use devices::Bus;
use devices::pci::{
    BarWindow, ConfigMechanism1, Ecam, PciAddress, PciFunction, PciIntxLine, PciRootError,
};
use devices::virtio::{
    CreatePciTransportError, VIRTIO_PCI_BAR0_SIZE, VirtioDevice, VirtioPciTransport,
};
use kvm_ioctls::VmFd;
use vm_memory::GuestMemoryMmap;

use crate::vmm::device_manager::irq::IrqAllocator;

const PCI_BUS0: u8 = 0;

#[derive(Debug)]
pub enum Error {
    Bus(devices::BusError),
    CreateTransport(CreatePciTransportError),
    IrqsExhausted,
    PciRoot(PciRootError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bus(err) => write!(f, "failed to register PCI bus device: {err}"),
            Self::CreateTransport(err) => write!(f, "failed to create virtio-pci transport: {err}"),
            Self::IrqsExhausted => write!(f, "no more GSIs are available for PCI INTx"),
            Self::PciRoot(err) => write!(f, "failed to register PCI function: {err}"),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Owns the bus-0 PCI functions and their guest address windows.
pub struct PciHostManager {
    root: devices::pci::SharedPciRoot,
    next_device: u8,
    irqs: IrqAllocator,
    functions: Vec<arch::x86_64::PciFunctionInfo>,
}

struct KvmPciIntxLine {
    vm: Arc<VmFd>,
    gsi: u32,
}

impl PciIntxLine for KvmPciIntxLine {
    fn set_level(&self, asserted: bool) -> std::io::Result<()> {
        self.vm
            .set_irq_line(self.gsi, asserted)
            .map_err(|err| std::io::Error::from_raw_os_error(err.errno()))
    }
}

impl PciHostManager {
    pub fn new(irqs: IrqAllocator) -> Self {
        Self {
            root: devices::pci::PciRoot::shared(),
            next_device: 1,
            irqs,
            functions: Vec::new(),
        }
    }

    pub fn register_config_io(&self, bus: &mut Bus) -> Result<()> {
        bus.insert(
            Arc::new(Mutex::new(ConfigMechanism1::new(self.root.clone()))),
            devices::pci::CONFIG_MECHANISM_1_ADDRESS,
            devices::pci::CONFIG_MECHANISM_1_SIZE,
        )
        .map_err(Error::Bus)
    }

    pub fn register_mmio(&self, bus: &mut Bus) -> Result<()> {
        bus.insert(
            Arc::new(Mutex::new(Ecam::new(self.root.clone()))),
            arch::x86_64::layout::PCI_ECAM_START,
            arch::x86_64::layout::PCI_ECAM_SIZE,
        )
        .map_err(Error::Bus)?;
        bus.insert(
            Arc::new(Mutex::new(BarWindow::new(
                self.root.clone(),
                arch::x86_64::layout::PCI_BAR_START,
            ))),
            arch::x86_64::layout::PCI_BAR_START,
            arch::x86_64::layout::PCI_BAR_END - arch::x86_64::layout::PCI_BAR_START,
        )
        .map_err(Error::Bus)
    }

    pub fn register_virtio_device(
        &mut self,
        vm: Arc<VmFd>,
        guest_memory: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<arch::x86_64::PciFunctionInfo> {
        if self.next_device > 31 {
            return Err(Error::IrqsExhausted);
        }

        let address = PciAddress::new(PCI_BUS0, self.next_device, 0);
        let bar_base = arch::x86_64::layout::PCI_BAR_START
            + u64::from(self.next_device - 1) * VIRTIO_PCI_BAR0_SIZE;
        if bar_base + VIRTIO_PCI_BAR0_SIZE > arch::x86_64::layout::PCI_BAR_END {
            return Err(Error::IrqsExhausted);
        }
        let irq = self.irqs.alloc().map_err(|_| Error::IrqsExhausted)?;
        let intx_line = Arc::new(KvmPciIntxLine { vm, gsi: irq });
        let transport =
            VirtioPciTransport::new(guest_memory, device, irq as u8, intx_line, bar_base as u32)
                .map_err(Error::CreateTransport)?;

        let function: Arc<Mutex<dyn PciFunction>> = Arc::new(Mutex::new(transport));
        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .insert(address, function)
            .map_err(Error::PciRoot)?;

        let info = arch::x86_64::PciFunctionInfo {
            device: address.device,
            function: address.function,
            gsi: irq,
        };
        self.functions.push(info);
        self.next_device += 1;
        Ok(info)
    }

    pub fn acpi_info(&self) -> arch::x86_64::PciHostInfo {
        arch::x86_64::PciHostInfo {
            ecam_base: arch::x86_64::layout::PCI_ECAM_START,
            bar_start: arch::x86_64::layout::PCI_BAR_START,
            bar_size: arch::x86_64::layout::PCI_BAR_END - arch::x86_64::layout::PCI_BAR_START,
            functions: self.functions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::builder;
    use super::*;
    use crate::vmm::device_manager::mmio::MMIODeviceManager;
    use devices::legacy::{DummyIrqChip, KvmIoapic};
    use devices::virtio::{
        ActivateResult, DeviceQueue, InterruptTransport, MmioTransport, QueueConfig,
    };
    use vm_memory::GuestAddress;

    /// VIRTIO_F_VERSION_1 feature bit, required by the PCI transport.
    const VIRTIO_F_VERSION_1: u32 = 32;
    const QUEUE_CONFIG: &[QueueConfig] = &[QueueConfig::new(64)];

    struct DummyDevice;

    impl VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            1u64 << VIRTIO_F_VERSION_1
        }

        fn acked_features(&self) -> u64 {
            0
        }

        fn set_acked_features(&mut self, _: u64) {}

        fn device_type(&self) -> u32 {
            0
        }

        fn device_name(&self) -> &str {
            "dummy"
        }

        fn queue_config(&self) -> &[QueueConfig] {
            QUEUE_CONFIG
        }

        fn config_len(&self) -> Option<u32> {
            Some(0)
        }

        fn read_config(&self, _offset: u64, _data: &mut [u8]) {}

        fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _intc: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            Ok(())
        }

        fn is_activated(&self) -> bool {
            false
        }
    }

    fn dummy_device() -> Arc<Mutex<dyn VirtioDevice>> {
        Arc::new(Mutex::new(DummyDevice))
    }

    #[test]
    fn test_mmio_and_pci_devices_get_distinct_irqs() {
        let guest_mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x0), 0x1000),
            (GuestAddress(0x1000), 0x1000),
        ])
        .unwrap();
        let mut arch_mem_info = arch::ArchMemoryInfo::default();
        let vm = builder::setup_vm(&guest_mem, &mut arch_mem_info, false).unwrap();
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();

        let irqs = IrqAllocator::new(arch::IRQ_BASE, arch::IRQ_MAX);
        let mut mmio = MMIODeviceManager::new(&mut 0xd000_0000, irqs.clone());
        let mut pci = PciHostManager::new(irqs);

        // Same order as build_microvm(): an MMIO device (the RTC) is attached
        // before the PCI devices.
        let transport = MmioTransport::new(
            guest_mem.clone(),
            DummyIrqChip::new().into(),
            dummy_device(),
        )
        .unwrap();
        let (_, mmio_irq) = mmio
            .register_mmio_device(vm.fd(), transport, 0, "rtc".to_string())
            .unwrap();
        let first = pci
            .register_virtio_device(vm.fd_shared(), guest_mem.clone(), dummy_device())
            .unwrap();
        let second = pci
            .register_virtio_device(vm.fd_shared(), guest_mem, dummy_device())
            .unwrap();

        assert_eq!(mmio_irq, arch::IRQ_BASE);
        assert_eq!(first.gsi, arch::IRQ_BASE + 1);
        assert_eq!(second.gsi, arch::IRQ_BASE + 2);
    }

    #[test]
    fn test_pci_reports_exhausted_shared_irqs() {
        let guest_mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), 0x1000)]).unwrap();
        let mut arch_mem_info = arch::ArchMemoryInfo::default();
        let vm = builder::setup_vm(&guest_mem, &mut arch_mem_info, false).unwrap();

        let irqs = IrqAllocator::new(arch::IRQ_BASE, arch::IRQ_BASE);
        // Another manager already took the only IRQ.
        irqs.alloc().unwrap();
        let mut pci = PciHostManager::new(irqs);

        let err = pci
            .register_virtio_device(vm.fd_shared(), guest_mem, dummy_device())
            .unwrap_err();
        assert!(matches!(err, Error::IrqsExhausted));
    }
}
