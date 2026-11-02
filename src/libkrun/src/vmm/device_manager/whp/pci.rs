// Copyright 2026 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! PCI root and virtio-pci registration for the x86_64 WHP backend.

use std::fmt::{Display, Formatter};
use std::io;
use std::sync::{Arc, Mutex};

use devices::Bus;
use devices::legacy::IrqChip;
use devices::pci::{
    BarWindow, ConfigMechanism1, Ecam, PciAddress, PciFunction, PciIntxLine, PciMsiSender,
    PciRootError,
};
use devices::virtio::{
    CreatePciTransportError, VIRTIO_PCI_BAR0_SIZE, VirtioDevice, VirtioPciTransport,
};
use vm_memory::GuestMemoryMmap;
use whp::{InterruptDestinationMode, InterruptRequest, InterruptTriggerMode, InterruptType, WhpVm};

use crate::vmm::device_manager::irq::IrqAllocator;

const PCI_BUS0: u8 = 0;

const MSI_ADDRESS_DESTINATION_SHIFT: u64 = 12;
const MSI_ADDRESS_DESTINATION_MASK: u64 = 0xff;
const MSI_ADDRESS_DESTINATION_MODE_LOGICAL: u64 = 1 << 2;
const MSI_DATA_VECTOR_MASK: u32 = 0xff;
const MSI_DATA_DELIVERY_MODE_SHIFT: u32 = 8;
const MSI_DATA_DELIVERY_MODE_MASK: u32 = 0x7;
const MSI_DATA_TRIGGER_LEVEL: u32 = 1 << 15;

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

pub struct PciHostManager {
    root: devices::pci::SharedPciRoot,
    vm: Arc<WhpVm>,
    next_device: u8,
    irqs: IrqAllocator,
    functions: Vec<arch::x86_64::PciFunctionInfo>,
}

struct WhpPciIntxLine {
    intc: IrqChip,
    gsi: u32,
}

impl PciIntxLine for WhpPciIntxLine {
    fn set_level(&self, asserted: bool) -> io::Result<()> {
        // The WHP IOAPIC consumes each assertion and clears its IRR bit; the
        // transport's deassertion only rearms its next call to this method.
        if asserted {
            self.intc
                .lock()
                .expect("Poisoned interrupt controller lock")
                .set_irq(Some(self.gsi), None)
                .map_err(|err| io::Error::other(format!("failed to assert GSI: {err:?}")))?;
        }
        Ok(())
    }
}

struct WhpPciMsiSender {
    vm: Arc<WhpVm>,
}

impl PciMsiSender for WhpPciMsiSender {
    fn send(&self, address: u64, data: u32) -> io::Result<()> {
        self.vm
            .request_interrupt(&msi_to_interrupt_request(address, data))
            .map_err(|err| io::Error::other(err.to_string()))
    }
}

fn msi_to_interrupt_request(address: u64, data: u32) -> InterruptRequest {
    InterruptRequest {
        interrupt_type: match (data >> MSI_DATA_DELIVERY_MODE_SHIFT) & MSI_DATA_DELIVERY_MODE_MASK {
            1 => InterruptType::LowestPriority,
            4 => InterruptType::Nmi,
            5 => InterruptType::Init,
            6 => InterruptType::Sipi,
            _ => InterruptType::Fixed,
        },
        destination_mode: if address & MSI_ADDRESS_DESTINATION_MODE_LOGICAL != 0 {
            InterruptDestinationMode::Logical
        } else {
            InterruptDestinationMode::Physical
        },
        trigger_mode: if data & MSI_DATA_TRIGGER_LEVEL != 0 {
            InterruptTriggerMode::Level
        } else {
            InterruptTriggerMode::Edge
        },
        destination: ((address >> MSI_ADDRESS_DESTINATION_SHIFT) & MSI_ADDRESS_DESTINATION_MASK)
            as u32,
        vector: data & MSI_DATA_VECTOR_MASK,
    }
}

impl PciHostManager {
    pub fn new(vm: Arc<WhpVm>, irqs: IrqAllocator) -> Self {
        Self {
            root: devices::pci::PciRoot::shared(),
            vm,
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
        intc: IrqChip,
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
        let intx_line = Arc::new(WhpPciIntxLine { intc, gsi: irq });
        let msi_sender = Arc::new(WhpPciMsiSender {
            vm: self.vm.clone(),
        });
        let transport = VirtioPciTransport::new(
            guest_memory,
            device,
            irq as u8,
            intx_line,
            Some(msi_sender),
            bar_base as u32,
        )
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
    use super::*;

    #[test]
    fn msi_message_decodes_to_whp_interrupt_request() {
        let physical = msi_to_interrupt_request(0xfee0_3000, 0x0041);
        assert!(matches!(physical.interrupt_type, InterruptType::Fixed));
        assert!(matches!(
            physical.destination_mode,
            InterruptDestinationMode::Physical
        ));
        assert!(matches!(physical.trigger_mode, InterruptTriggerMode::Edge));
        assert_eq!(physical.destination, 3);
        assert_eq!(physical.vector, 0x41);

        let logical = msi_to_interrupt_request(0xfee0_1004, 0x8142);
        assert!(matches!(
            logical.interrupt_type,
            InterruptType::LowestPriority
        ));
        assert!(matches!(
            logical.destination_mode,
            InterruptDestinationMode::Logical
        ));
        assert!(matches!(logical.trigger_mode, InterruptTriggerMode::Level));
        assert_eq!(logical.destination, 1);
        assert_eq!(logical.vector, 0x42);
    }
}
