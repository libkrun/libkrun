// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::{Arc, Mutex};

use crossbeam_channel::Sender;
use devices::Bus;
use devices::pci::{
    MsixRouteContext, MsixVector, PciBdf, PciBus, PciEcam, x86_default_irqchip_routes,
};
use devices::virtio::{
    CAPABILITY_BAR_SIZE, CreatePciTransportError, NOTIFICATION_BAR_OFFSET, NOTIFY_OFF_MULTIPLIER,
    PciTransport, VirtioDevice,
};
use kvm_ioctls::{IoEventAddress, VmFd};
use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;
use vm_memory::GuestMemoryMmap;

/// Errors for PCI device manager.
#[derive(Debug)]
pub enum Error {
    CreatePciTransport(CreatePciTransportError),
    BusError(devices::BusError),
    EventFd(std::io::Error),
    RegisterIoEvent(kvm_ioctls::Error),
    MsixRouting(kvm_ioctls::Error),
    IrqsExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::CreatePciTransport(e) => write!(f, "failed to create pci transport: {e}"),
            Error::BusError(e) => write!(f, "failed to perform bus operation: {e}"),
            Error::EventFd(e) => write!(f, "failed to create event descriptor: {e}"),
            Error::RegisterIoEvent(e) => write!(f, "failed to register IO event: {e}"),
            Error::MsixRouting(e) => write!(f, "failed to set MSI routing: {e}"),
            Error::IrqsExhausted => write!(f, "no more IRQs are available"),
        }
    }
}

impl From<CreatePciTransportError> for Error {
    fn from(e: CreatePciTransportError) -> Self {
        Self::CreatePciTransport(e)
    }
}

type Result<T> = std::result::Result<T, Error>;

pub const ECAM_SIZE: u64 = 256 * 1024 * 1024;

pub struct PciDeviceManager {
    pci_bus: Arc<Mutex<PciBus>>,
    pci_mmio_base: u64,
    next_gsi: u32,
    last_gsi: u32,
    irq_routes: Arc<Mutex<Vec<kvm_bindings::kvm_irq_routing_entry>>>,
    irq_sender: Sender<WorkerMessage>,
    /// When true, MSI-X GSI updates keep KVM's default PIC/IOAPIC routes
    /// (`!split_irqchip`).
    preserve_irqchip_routes: bool,
    ecam_registered: bool,
}

impl PciDeviceManager {
    pub fn new(
        pci_mmio_base: u64,
        gsi_range: (u32, u32),
        irq_sender: Sender<WorkerMessage>,
        preserve_irqchip_routes: bool,
    ) -> Self {
        Self {
            pci_bus: Arc::new(Mutex::new(PciBus::new())),
            pci_mmio_base,
            next_gsi: gsi_range.0,
            last_gsi: gsi_range.1,
            irq_routes: Arc::new(Mutex::new(Vec::new())),
            irq_sender,
            preserve_irqchip_routes,
            ecam_registered: false,
        }
    }

    pub fn register_ecam(&mut self, bus: &mut Bus, ecam_base: u64) -> Result<()> {
        if self.ecam_registered {
            return Ok(());
        }
        let ecam = PciEcam::new(self.pci_bus.clone());
        bus.insert(Arc::new(Mutex::new(ecam)), ecam_base, ECAM_SIZE)
            .map_err(Error::BusError)?;
        self.ecam_registered = true;
        Ok(())
    }

    pub fn register_pci_device(
        &mut self,
        vm: &VmFd,
        bus: &mut Bus,
        guest_mem: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
        _type_id: u32,
        _device_id: String,
    ) -> Result<PciBdf> {
        let num_queues = device.lock().unwrap().queue_config().len();
        let num_vectors = num_queues + 1;
        let vectors_needed = num_vectors as u32;
        if self.next_gsi + vectors_needed - 1 > self.last_gsi {
            return Err(Error::IrqsExhausted);
        }

        let mut msix_vectors = Vec::with_capacity(num_vectors);
        for _ in 0..num_vectors {
            let gsi = self.next_gsi;
            self.next_gsi += 1;
            let eventfd = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
            msix_vectors.push(MsixVector { eventfd, gsi });
        }

        let bdf = self.pci_bus.lock().unwrap().allocate_bdf();
        let bar_address = self.pci_mmio_base;
        self.pci_mmio_base += CAPABILITY_BAR_SIZE;

        let msix_route_ctx = Some(MsixRouteContext::new(
            self.irq_routes.clone(),
            self.irq_sender.clone(),
            self.preserve_irqchip_routes,
        ));

        let pci_device = PciTransport::new(
            guest_mem,
            device,
            bdf,
            bar_address,
            msix_vectors,
            msix_route_ctx,
        )?;

        for (i, queue_evt) in pci_device.queue_evts().iter().enumerate() {
            let notify_offset =
                u64::from(NOTIFICATION_BAR_OFFSET) + (i as u64) * u64::from(NOTIFY_OFF_MULTIPLIER);
            let io_addr = IoEventAddress::Mmio(bar_address + notify_offset);
            // Guest virtio-pci uses iowrite16 for notifies.
            vm.register_ioevent(queue_evt, &io_addr, i as u16)
                .map_err(Error::RegisterIoEvent)?;
        }

        {
            let mut routes = self.irq_routes.lock().unwrap();
            pci_device
                .msix_config()
                .lock()
                .unwrap()
                .push_routes(&mut routes);
            // Device registration runs before the VMM worker exists, so commit
            // routes via VmFd. Preserve PIC/IOAPIC defaults for in-kernel irqchip.
            let msi_snapshot = routes.clone();
            drop(routes);
            let full_routes = if self.preserve_irqchip_routes {
                let mut full = x86_default_irqchip_routes();
                full.extend(msi_snapshot);
                full
            } else {
                msi_snapshot
            };
            let mut routing =
                kvm_bindings::KvmIrqRouting::new(full_routes.len()).map_err(|_| {
                    Error::MsixRouting(kvm_ioctls::Error::from(std::io::Error::other(
                        "KvmIrqRouting::new failed",
                    )))
                })?;
            routing.as_mut_slice().copy_from_slice(&full_routes);
            vm.set_gsi_routing(&routing).map_err(Error::MsixRouting)?;
        }
        pci_device
            .msix_config()
            .lock()
            .unwrap()
            .register_irqfds(vm)
            .map_err(Error::MsixRouting)?;

        let bar_size = pci_device.bar_size();
        let bar_addr = pci_device.bar_address();
        let bdf = pci_device.bdf();

        let pci_device_arc = Arc::new(Mutex::new(pci_device));
        self.pci_bus
            .lock()
            .unwrap()
            .add_device(pci_device_arc.clone());

        bus.insert(pci_device_arc, bar_addr, bar_size)
            .map_err(Error::BusError)?;

        Ok(bdf)
    }
}
