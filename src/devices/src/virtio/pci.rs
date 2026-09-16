// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::io;
use std::sync::{Arc, Mutex};

use utils::byte_order;
use utils::eventfd::EFD_NONBLOCK;
use utils::eventfd::EventFd;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::GuestMemoryMmap;

use super::pci_common::{PciCommonAction, VirtioPciCommonConfig};
use super::*;
use crate::bus::BusDevice;
use crate::pci::{
    BarPrefetchable, Bars, MsixCap, MsixConfig, MsixRouteContext, MsixVector, PciBdf,
    PciCapability, PciCapabilityId, PciClassCode, PciConfiguration, PciDevice,
    VIRTIO_PCI_DEVICE_ID_BASE, VIRTIO_PCI_VENDOR_ID,
};

const VIRTIO_BAR_INDEX: u8 = 0;
const COMMON_CONFIG_BAR_OFFSET: u32 = 0x0000;
const COMMON_CONFIG_SIZE: u32 = 56;
const ISR_CONFIG_BAR_OFFSET: u32 = 0x2000;
const ISR_CONFIG_SIZE: u32 = 1;
const DEVICE_CONFIG_BAR_OFFSET: u32 = 0x4000;
const DEVICE_CONFIG_SIZE: u32 = 0x1000;
pub const NOTIFICATION_BAR_OFFSET: u32 = 0x6000;
const NOTIFICATION_SIZE: u32 = 0x1000;
const MSIX_TABLE_BAR_OFFSET: u32 = 0x8000;
const MSIX_TABLE_SIZE: u32 = 0x40000;
const MSIX_PBA_BAR_OFFSET: u32 = 0x48000;
const MSIX_PBA_SIZE: u32 = 0x800;
pub const CAPABILITY_BAR_SIZE: u64 = 0x80000;
pub const NOTIFY_OFF_MULTIPLIER: u32 = 4;
const VIRTIO_PCI_CAP_LEN_OFFSET: u8 = 2;

enum PciCapabilityType {
    Common = 1,
    Notify = 2,
    Isr = 3,
    Device = 4,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciCap {
    cap_len: u8,
    cfg_type: u8,
    pci_bar: u8,
    id: u8,
    padding: [u8; 2],
    offset: u32,
    length: u32,
}

impl PciCapability for VirtioPciCap {
    fn bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Self).cast::<u8>(),
                std::mem::size_of::<Self>(),
            )
        }
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciCap {
    fn new(cfg_type: PciCapabilityType, offset: u32, length: u32) -> Self {
        Self {
            cap_len: u8::try_from(std::mem::size_of::<Self>()).unwrap() + VIRTIO_PCI_CAP_LEN_OFFSET,
            cfg_type: cfg_type as u8,
            pci_bar: VIRTIO_BAR_INDEX,
            id: 0,
            padding: [0; 2],
            offset,
            length,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: u32,
}

impl PciCapability for VirtioPciNotifyCap {
    fn bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Self).cast::<u8>(),
                std::mem::size_of::<Self>(),
            )
        }
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciNotifyCap {
    fn new(offset: u32, length: u32) -> Self {
        let mut cap = VirtioPciCap::new(PciCapabilityType::Notify, offset, length);
        // PCI capability header (2) is prepended by PciConfiguration::add_capability.
        cap.cap_len =
            u8::try_from(std::mem::size_of::<Self>()).unwrap() + VIRTIO_PCI_CAP_LEN_OFFSET;
        Self {
            cap,
            notify_off_multiplier: NOTIFY_OFF_MULTIPLIER,
        }
    }
}

#[derive(Debug)]
pub enum CreatePciTransportError {
    CreateEventFd(io::Error),
}

impl Display for CreatePciTransportError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            CreatePciTransportError::CreateEventFd(err) => {
                write!(f, "failed to create eventfd: {err}")
            }
        }
    }
}

pub struct PciTransport {
    device: Arc<Mutex<dyn VirtioDevice>>,
    bdf: PciBdf,
    bar_address: u64,
    configuration: PciConfiguration,
    common_config: VirtioPciCommonConfig,
    msix_config: Arc<Mutex<MsixConfig>>,
    msix_config_cap_offset: u16,
    mem: GuestMemoryMmap,
    queues: Option<Vec<Queue>>,
    queue_evts: Vec<Arc<EventFd>>,
    queue_config: Vec<QueueConfig>,
    interrupt: InterruptTransport,
    isr_status: u8,
}

impl PciTransport {
    pub fn new(
        mem: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
        bdf: PciBdf,
        bar_address: u64,
        msix_vectors: Vec<MsixVector>,
        msix_route_ctx: Option<MsixRouteContext>,
    ) -> Result<Self, CreatePciTransportError> {
        let locked = device
            .try_lock()
            .expect("Mutex of VirtioDevice should not be locked when calling PciTransport::new");

        let device_type = locked.device_type();
        let device_name = locked.device_name().to_string();
        let debug_log_target = format!("{}[{}]", module_path!(), device_name);
        let queue_config: Vec<QueueConfig> = locked.queue_config().to_vec();
        let num_queues = queue_config.len();
        drop(locked);

        let (class, subclass) = match device_type {
            TYPE_NET => (PciClassCode::NetworkController, 0x00),
            TYPE_BLOCK => (PciClassCode::MassStorageController, 0x00),
            _ => (PciClassCode::UnassignedClass, 0xff),
        };

        let pci_device_id = VIRTIO_PCI_DEVICE_ID_BASE + device_type as u16;
        let mut configuration = PciConfiguration::new_type0(
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            0x1,
            class,
            subclass,
            VIRTIO_PCI_VENDOR_ID,
            device_type as u16,
        );

        let mut bars = Bars::default();
        bars.set_bar_64(
            VIRTIO_BAR_INDEX,
            bar_address,
            CAPABILITY_BAR_SIZE,
            BarPrefetchable::No,
        );
        *configuration.bars_mut() = bars;

        let msix_table_size = msix_vectors.len() as u16;
        let msix_config = Arc::new(Mutex::new(MsixConfig::new(
            msix_vectors,
            bdf,
            MSIX_TABLE_BAR_OFFSET,
            MSIX_PBA_BAR_OFFSET,
            msix_route_ctx,
        )));

        let msix_cap = MsixCap::new(
            VIRTIO_BAR_INDEX,
            msix_table_size,
            MSIX_TABLE_BAR_OFFSET,
            VIRTIO_BAR_INDEX,
            MSIX_PBA_BAR_OFFSET,
        );
        configuration.add_capability(Box::new(msix_cap));
        let msix_config_cap_offset = configuration.msix_cap_offset().unwrap_or(0);

        let common_config = VirtioPciCommonConfig::new(num_queues);
        let interrupt = InterruptTransport::new_pci(
            msix_config.clone(),
            common_config.msix_config.clone(),
            common_config.msix_queues.clone(),
            debug_log_target,
        )
        .map_err(|e| {
            CreatePciTransportError::CreateEventFd(std::io::Error::other(e.to_string()))
        })?;

        let mut transport = Self {
            device,
            bdf,
            bar_address,
            configuration,
            common_config,
            msix_config,
            msix_config_cap_offset,
            mem,
            queues: None,
            queue_evts: Vec::new(),
            queue_config,
            interrupt,
            isr_status: 0,
        };

        transport.add_pci_capabilities();
        transport.queues = Some(Self::create_queues(&transport.queue_config));
        transport.queue_evts = Self::create_queue_evts(num_queues)?;

        Ok(transport)
    }

    fn add_pci_capabilities(&mut self) {
        self.configuration
            .add_capability(Box::new(VirtioPciCap::new(
                PciCapabilityType::Common,
                COMMON_CONFIG_BAR_OFFSET,
                COMMON_CONFIG_SIZE,
            )));
        self.configuration
            .add_capability(Box::new(VirtioPciCap::new(
                PciCapabilityType::Isr,
                ISR_CONFIG_BAR_OFFSET,
                ISR_CONFIG_SIZE,
            )));
        self.configuration
            .add_capability(Box::new(VirtioPciCap::new(
                PciCapabilityType::Device,
                DEVICE_CONFIG_BAR_OFFSET,
                DEVICE_CONFIG_SIZE,
            )));
        self.configuration
            .add_capability(Box::new(VirtioPciNotifyCap::new(
                NOTIFICATION_BAR_OFFSET,
                NOTIFICATION_SIZE,
            )));
    }

    fn create_queues(queue_config: &[QueueConfig]) -> Vec<Queue> {
        queue_config.iter().map(|c| Queue::new(c.size)).collect()
    }

    fn create_queue_evts(count: usize) -> Result<Vec<Arc<EventFd>>, CreatePciTransportError> {
        (0..count)
            .map(|_| {
                EventFd::new(EFD_NONBLOCK)
                    .map(Arc::new)
                    .map_err(CreatePciTransportError::CreateEventFd)
            })
            .collect()
    }

    pub fn bdf(&self) -> PciBdf {
        self.bdf
    }

    pub fn bar_address(&self) -> u64 {
        self.bar_address
    }

    pub fn bar_size(&self) -> u64 {
        CAPABILITY_BAR_SIZE
    }

    pub fn queue_evts(&self) -> &[Arc<EventFd>] {
        &self.queue_evts
    }

    pub fn msix_config(&self) -> Arc<Mutex<MsixConfig>> {
        self.msix_config.clone()
    }

    pub fn locked_device(&self) -> std::sync::MutexGuard<'_, dyn VirtioDevice + 'static> {
        self.device.lock().expect("Poisoned device lock")
    }

    fn activate(&mut self) {
        let Some(queues) = self.queues.take() else {
            return;
        };

        let pci_interrupt = self.interrupt.clone();
        let mut device_queues: Vec<DeviceQueue> = queues
            .into_iter()
            .zip(self.queue_evts.iter().cloned())
            .map(|(queue, event)| DeviceQueue::new(queue, event))
            .collect();

        let mut locked_device = self.locked_device();
        let event_idx_enabled =
            (locked_device.acked_features() & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        for dq in &mut device_queues {
            dq.queue.set_event_idx(event_idx_enabled);
        }
        locked_device
            .activate(self.mem.clone(), pci_interrupt, device_queues)
            .expect("Failed to activate device");
    }

    fn reset(&mut self) {
        let reset_ok = {
            let mut device = self.locked_device();
            !device.is_activated() || device.reset()
        };
        if !reset_ok {
            // Backend refused reset; mirror MMIO and mark FAILED.
            self.common_config.mark_failed();
            return;
        }
        self.common_config.reset_state();
        self.isr_status = 0;
        self.queues = Some(Self::create_queues(&self.queue_config));
    }

    fn read_bar(&mut self, offset: u64, data: &mut [u8]) {
        if !self.configuration.command_memory_space_enabled() {
            data.fill(0xff);
            return;
        }

        match offset {
            o if o < u64::from(COMMON_CONFIG_SIZE) => {
                let device = self.locked_device();
                match self.queues.as_ref() {
                    Some(queues) => self.common_config.read(o, data, queues, &*device),
                    None => {
                        // Queues move into the device on activate; status and similar
                        // common-config fields remain readable.
                        self.common_config.read_activated(
                            o,
                            data,
                            self.queue_config.len(),
                            &*device,
                        );
                    }
                }
            }
            o if o >= u64::from(ISR_CONFIG_BAR_OFFSET)
                && o < u64::from(ISR_CONFIG_BAR_OFFSET) + u64::from(ISR_CONFIG_SIZE) =>
            {
                if !data.is_empty() {
                    data[0] = self.isr_status;
                }
            }
            o if o >= u64::from(DEVICE_CONFIG_BAR_OFFSET)
                && o < u64::from(DEVICE_CONFIG_BAR_OFFSET) + u64::from(DEVICE_CONFIG_SIZE) =>
            {
                let config_offset = o - u64::from(DEVICE_CONFIG_BAR_OFFSET);
                self.locked_device().read_config(config_offset, data);
            }
            o if o >= u64::from(MSIX_TABLE_BAR_OFFSET)
                && o < u64::from(MSIX_TABLE_BAR_OFFSET) + u64::from(MSIX_TABLE_SIZE) =>
            {
                let table_offset = o - u64::from(MSIX_TABLE_BAR_OFFSET);
                self.msix_config
                    .lock()
                    .unwrap()
                    .read_table(table_offset, data);
            }
            o if o >= u64::from(MSIX_PBA_BAR_OFFSET)
                && o < u64::from(MSIX_PBA_BAR_OFFSET) + u64::from(MSIX_PBA_SIZE) =>
            {
                let pba_offset = o - u64::from(MSIX_PBA_BAR_OFFSET);
                self.msix_config.lock().unwrap().read_pba(pba_offset, data);
            }
            _ => data.fill(0),
        }
    }

    fn write_bar(&mut self, offset: u64, data: &[u8]) {
        if !self.configuration.command_memory_space_enabled() {
            return;
        }

        if offset >= u64::from(NOTIFICATION_BAR_OFFSET)
            && offset < u64::from(NOTIFICATION_BAR_OFFSET) + u64::from(NOTIFICATION_SIZE)
            && !data.is_empty()
        {
            let queue_index = ((offset - u64::from(NOTIFICATION_BAR_OFFSET))
                / u64::from(NOTIFY_OFF_MULTIPLIER)) as usize;
            if let Some(eventfd) = self.queue_evts.get(queue_index) {
                let _ = eventfd.write(1);
            }
            return;
        }

        match offset {
            o if o < u64::from(COMMON_CONFIG_SIZE) => {
                let device_activated = self.locked_device().is_activated();
                let Some(queues) = self.queues.as_mut() else {
                    // After activate, only DEVICE_STATUS (reset) is meaningful.
                    if data.len() == 1 && o == super::pci_common::DEVICE_STATUS {
                        let mut locked_device = self.device.lock().unwrap();
                        let action = self.common_config.write(
                            o,
                            data,
                            &mut [],
                            &mut *locked_device,
                            device_activated,
                        );
                        drop(locked_device);
                        if let Some(PciCommonAction::Reset) = action {
                            self.reset();
                        }
                    }
                    return;
                };
                let mut locked_device = self.device.lock().unwrap();
                let action = self.common_config.write(
                    o,
                    data,
                    queues,
                    &mut *locked_device,
                    device_activated,
                );
                drop(locked_device);
                match action {
                    Some(PciCommonAction::Activate) => self.activate(),
                    Some(PciCommonAction::Reset) => self.reset(),
                    None => {}
                }
            }
            o if o >= u64::from(ISR_CONFIG_BAR_OFFSET)
                && o < u64::from(ISR_CONFIG_BAR_OFFSET) + u64::from(ISR_CONFIG_SIZE)
                && !data.is_empty() =>
            {
                self.isr_status &= !data[0];
            }
            o if o >= u64::from(DEVICE_CONFIG_BAR_OFFSET)
                && o < u64::from(DEVICE_CONFIG_BAR_OFFSET) + u64::from(DEVICE_CONFIG_SIZE) =>
            {
                let config_offset = o - u64::from(DEVICE_CONFIG_BAR_OFFSET);
                self.locked_device().write_config(config_offset, data);
            }
            o if o >= u64::from(MSIX_TABLE_BAR_OFFSET)
                && o < u64::from(MSIX_TABLE_BAR_OFFSET) + u64::from(MSIX_TABLE_SIZE) =>
            {
                let table_offset = o - u64::from(MSIX_TABLE_BAR_OFFSET);
                self.msix_config
                    .lock()
                    .unwrap()
                    .write_table(table_offset, data);
            }
            o if o >= u64::from(MSIX_PBA_BAR_OFFSET)
                && o < u64::from(MSIX_PBA_BAR_OFFSET) + u64::from(MSIX_PBA_SIZE) =>
            {
                let pba_offset = o - u64::from(MSIX_PBA_BAR_OFFSET);
                self.msix_config.lock().unwrap().write_pba(pba_offset, data);
            }
            _ => {}
        }
    }
}

impl BusDevice for PciTransport {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(offset, data);
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        self.write_bar(offset, data);
    }
}

impl PciDevice for PciTransport {
    fn bdf(&self) -> PciBdf {
        self.bdf
    }

    fn read_config(&self, offset: u16, data: &mut [u8]) {
        // Live MSI-X Message Control (table size is RO; enable/mask are RW).
        // Handle word and unaligned dword reads that cover the msg_ctl field.
        if let Some(rel) = offset.checked_sub(self.msix_config_cap_offset)
            && rel < 12
        {
            let msg_ctl_off = 2u16;
            let msg_ctl_end = 4u16;
            let access_end = offset as usize + data.len();
            let ctl_start = (self.msix_config_cap_offset + msg_ctl_off) as usize;
            let ctl_end = (self.msix_config_cap_offset + msg_ctl_end) as usize;
            if (offset as usize) < ctl_end && access_end > ctl_start {
                let value = self.msix_config.lock().unwrap().msix_enable_value();
                let value_bytes = value.to_le_bytes();
                for (i, byte) in data.iter_mut().enumerate() {
                    let abs = offset as usize + i;
                    if (ctl_start..ctl_end).contains(&abs) {
                        *byte = value_bytes[abs - ctl_start];
                    } else {
                        let reg_idx = abs / 4;
                        let byte_off = (abs % 4) as u8;
                        let mut tmp = [0u8];
                        self.configuration
                            .read_config_register(reg_idx, byte_off, &mut tmp);
                        *byte = tmp[0];
                    }
                }
                return;
            }
        }
        let reg_idx = (offset / 4) as usize;
        let byte_off = (offset % 4) as u8;
        self.configuration
            .read_config_register(reg_idx, byte_off, data);
    }

    fn write_config(&mut self, offset: u16, data: &[u8]) {
        // Accept word or dword writes that touch Message Control at cap+2.
        if let Some(rel) = offset.checked_sub(self.msix_config_cap_offset) {
            let access_end = rel as usize + data.len();
            if rel <= 2 && access_end > 2 {
                let start = 2usize.saturating_sub(rel as usize);
                if data.len() >= start + 2 {
                    let value = byte_order::read_le_u16(&data[start..start + 2]);
                    self.msix_config.lock().unwrap().set_msix_enable(value);
                } else if data.len() > start {
                    let mut cur = self.msix_config.lock().unwrap().msix_enable_value();
                    let mut bytes = cur.to_le_bytes();
                    for (i, b) in data[start..].iter().enumerate() {
                        if start + i < 2 {
                            bytes[start + i] = *b;
                        }
                    }
                    cur = u16::from_le_bytes(bytes);
                    self.msix_config.lock().unwrap().set_msix_enable(cur);
                }
            }
        }
        let reg_idx = (offset / 4) as usize;
        let byte_off = (offset % 4) as u8;
        self.configuration
            .write_config_register(reg_idx, byte_off, data);
    }

    fn bar_address(&self) -> u64 {
        self.bar_address
    }

    fn bar_size(&self) -> u64 {
        CAPABILITY_BAR_SIZE
    }
}
