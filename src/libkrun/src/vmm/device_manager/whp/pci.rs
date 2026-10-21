// Copyright 2026 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! PCI root and virtio-pci registration for the x86_64 WHP backend.

use std::fmt::{Display, Formatter};
use std::io;
use std::sync::{Arc, Mutex};

use devices::Bus;
use devices::legacy::IrqChip;
use devices::pci::{
    BarWindow, ConfigMechanism1, Ecam, PciAddress, PciFunction, PciIntxLine, PciRootError,
};
use devices::virtio::{
    CreatePciTransportError, VIRTIO_PCI_BAR0_SIZE, VirtioDevice, VirtioPciTransport,
};
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

pub struct PciHostManager {
    root: devices::pci::SharedPciRoot,
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
