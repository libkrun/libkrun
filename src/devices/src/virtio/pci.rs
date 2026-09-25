// SPDX-License-Identifier: Apache-2.0

//! Modern virtio-pci transport.

use std::fmt::{Display, Formatter};
use std::io;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::pci::{
    PCI_CONVENTIONAL_CONFIG_SPACE_SIZE, PCI_UNIMPLEMENTED_READ_BYTE, PciBarAccess, PciFunction,
    PciIntxLine,
};
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

use super::device::{InterruptHandler, InterruptType, VirtioTransportState};
use super::{InterruptTransport, VirtioDevice, device_status};

const PCI_VENDOR_ID_VIRTIO: u16 = 0x1af4;
const PCI_DEVICE_ID_VIRTIO_MODERN: u16 = 0x1040;
const PCI_CAPABILITY_ID_VENDOR_SPECIFIC: u8 = 0x09;
const PCI_CAPABILITY_LIST_STATUS: u16 = 1 << 4;
const PCI_STATUS_INTERRUPT: u16 = 1 << 3;
const PCI_COMMAND_MEMORY: u16 = 1 << 1;
const PCI_COMMAND_MASTER: u16 = 1 << 2;
const PCI_COMMAND_INTX_DISABLE: u16 = 1 << 10;
const PCI_INTERRUPT_PIN_INTA: u8 = 1;
const PCI_REVISION_MODERN: u8 = 1;
const PCI_HEADER_TYPE_ENDPOINT: u8 = 0;
const PCI_BAR0_INDEX: u8 = 0;
const PCI_SUBSYSTEM_DEVICE_ID_BASE: u16 = 0x40;
const VIRTIO_PCI_CAPABILITY_LENGTH: u8 = 16;
const VIRTIO_PCI_NOTIFY_CAPABILITY_LENGTH: u8 = 20;
const PCI_CFG_DATA_SIZE: usize = size_of::<u32>();
const BYTE_SIZE: usize = size_of::<u8>();
const WORD_SIZE: usize = size_of::<u16>();
const DWORD_SIZE: usize = size_of::<u32>();
const QWORD_SIZE: usize = size_of::<u64>();
const VIRTIO_QUEUE_READY: u16 = 1;
const QUEUE_ADDRESS_HALF_MASK: u64 = u32::MAX as u64;
const QUEUE_EVENT_SIGNAL: u64 = 1;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;

const PCI_CONFIG_SIZE: usize = PCI_CONVENTIONAL_CONFIG_SPACE_SIZE;
const PCI_BAR0_OFFSET: usize = pci_config::BAR0;
const PCI_BAR0_SIZE: usize = size_of::<u32>();
const PCI_BAR0_END: usize = PCI_BAR0_OFFSET + PCI_BAR0_SIZE - 1;
const PCI_STATUS_LAST_BYTE: usize = pci_config::STATUS + WORD_SIZE - 1;
const PCI_COMMAND_LAST_BYTE: usize = pci_config::COMMAND + WORD_SIZE - 1;
pub const VIRTIO_PCI_BAR0_SIZE: u64 = 0x8000;
const VIRTIO_PCI_BAR0_ADDRESS_MASK: u32 = !(VIRTIO_PCI_BAR0_SIZE as u32 - 1);
const PCI_BAR_ATTRIBUTE_MASK: u32 = 0x0f;
const PCI_BAR_ADDRESS_MASK: u32 = !PCI_BAR_ATTRIBUTE_MASK;
const PCI_BAR_PROBE_VALUE: u32 = u32::MAX;

const COMMON_CFG_OFFSET: u64 = 0x0000;
const NOTIFY_CFG_OFFSET: u64 = 0x1000;
const NOTIFY_CFG_LEN: u32 = 0x1000;
const NOTIFY_OFF_MULTIPLIER: u32 = 4;
const ISR_CFG_OFFSET: u64 = 0x2000;
const DEVICE_CFG_OFFSET: u64 = 0x3000;
const COMMON_CFG_LEN: u32 = (common_cfg::QUEUE_RESET_OFFSET + size_of::<u16>() as u64) as u32;
const COMMON_CFG_DWORD_SIZE: u64 = size_of::<u32>() as u64;

const VIRTIO_ISR_QUEUE: u8 = 1;
const VIRTIO_ISR_CONFIG: u8 = 2;
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

mod pci_config {
    pub const VENDOR_ID: usize = 0x00;
    pub const DEVICE_ID: usize = 0x02;
    pub const COMMAND: usize = 0x04;
    pub const STATUS: usize = 0x06;
    pub const REVISION_ID: usize = 0x08;
    pub const HEADER_TYPE: usize = 0x0e;
    pub const BAR0: usize = 0x10;
    pub const SUBSYSTEM_VENDOR_ID: usize = 0x2c;
    pub const SUBSYSTEM_DEVICE_ID: usize = 0x2e;
    pub const CAPABILITY_POINTER: usize = 0x34;
    pub const INTERRUPT_LINE: usize = 0x3c;
    pub const INTERRUPT_PIN: usize = 0x3d;
    pub const CAPABILITIES_START: usize = 0x40;
}

mod vendor_cap {
    pub const VENDOR_SPECIFIC_CAPABILITY_ID: usize = 0x00;
    pub const NEXT: usize = 0x01;
    pub const LENGTH: usize = 0x02;
    pub const CONFIG_TYPE: usize = 0x03;
    pub const BAR: usize = 0x04;
    pub const REGION_ID: usize = 0x05;
    pub const REGION_OFFSET: usize = 0x08;
    pub const REGION_LENGTH: usize = 0x0c;
    pub const NOTIFY_MULTIPLIER: usize = 0x10;
    pub const PCI_CONFIG_DATA: usize = 0x10;
}

mod common_cfg {
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    pub const DEVICE_FEATURE: u64 = 0x04;
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    pub const DRIVER_FEATURE: u64 = 0x0c;
    pub const MSIX_CONFIG: u64 = 0x10;
    pub const NUMBER_OF_QUEUES: u64 = 0x12;
    pub const DEVICE_STATUS: u64 = 0x14;
    pub const CONFIG_GENERATION: u64 = 0x15;
    pub const QUEUE_SELECT: u64 = 0x16;
    pub const QUEUE_SIZE: u64 = 0x18;
    pub const QUEUE_MSIX_VECTOR: u64 = 0x1a;
    pub const QUEUE_ENABLE: u64 = 0x1c;
    pub const QUEUE_NOTIFY_OFFSET: u64 = 0x1e;
    pub const QUEUE_DESCRIPTOR: u64 = 0x20;
    pub const QUEUE_DESCRIPTOR_HIGH: u64 = QUEUE_DESCRIPTOR + super::COMMON_CFG_DWORD_SIZE;
    pub const QUEUE_DRIVER: u64 = 0x28;
    pub const QUEUE_DRIVER_HIGH: u64 = QUEUE_DRIVER + super::COMMON_CFG_DWORD_SIZE;
    pub const QUEUE_DEVICE: u64 = 0x30;
    pub const QUEUE_DEVICE_HIGH: u64 = QUEUE_DEVICE + super::COMMON_CFG_DWORD_SIZE;
    pub const QUEUE_NOTIFY_DATA: u64 = 0x38;
    pub const QUEUE_RESET_OFFSET: u64 = 0x3a;
}

#[derive(Debug)]
pub enum CreatePciTransportError {
    EventFd(io::Error),
    DeviceConfigTooLarge(u32),
    InvalidBarBase(u32),
    MissingVersion1,
    UnknownDeviceConfigLength,
    SharedMemoryNotSupported,
}

impl Display for CreatePciTransportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EventFd(err) => write!(f, "failed to create queue eventfd: {err}"),
            Self::DeviceConfigTooLarge(size) => {
                write!(
                    f,
                    "virtio device configuration is too large for BAR0: {size}"
                )
            }
            Self::InvalidBarBase(base) => write!(f, "invalid BAR0 base address: 0x{base:x}"),
            Self::MissingVersion1 => {
                write!(
                    f,
                    "modern virtio-pci device does not offer VIRTIO_F_VERSION_1"
                )
            }
            Self::UnknownDeviceConfigLength => {
                write!(
                    f,
                    "virtio device did not report its configuration space length"
                )
            }
            Self::SharedMemoryNotSupported => {
                write!(f, "virtio-pci shared-memory regions are not supported")
            }
        }
    }
}

impl std::error::Error for CreatePciTransportError {}

struct PciInterruptInner {
    state: Mutex<PciInterruptState>,
    line: Arc<dyn PciIntxLine>,
    log_target: String,
}

struct PciInterruptState {
    isr: u8,
    intx_disabled: bool,
}

#[derive(Clone)]
struct PciInterrupt(Arc<PciInterruptInner>);

impl PciInterrupt {
    fn new(line: Arc<dyn PciIntxLine>, log_target: String) -> Self {
        Self(Arc::new(PciInterruptInner {
            state: Mutex::new(PciInterruptState {
                isr: 0,
                intx_disabled: false,
            }),
            line,
            log_target,
        }))
    }

    fn read_isr(&self) -> u8 {
        let mut state = self.0.state.lock().unwrap();
        let isr = state.isr;
        state.isr = 0;
        if isr != 0
            && !state.intx_disabled
            && let Err(err) = self.0.line.set_level(false)
        {
            warn!("failed to deassert virtio-pci INTx: {err}");
        }
        isr
    }

    fn is_pending(&self) -> bool {
        self.0.state.lock().unwrap().isr != 0
    }

    fn reset(&self) {
        let mut state = self.0.state.lock().unwrap();
        if state.isr != 0
            && !state.intx_disabled
            && let Err(err) = self.0.line.set_level(false)
        {
            warn!("failed to deassert virtio-pci INTx during reset: {err}");
        }
        state.isr = 0;
    }

    fn set_intx_disabled(&self, disabled: bool) {
        let mut state = self.0.state.lock().unwrap();
        if state.intx_disabled == disabled {
            return;
        }
        state.intx_disabled = disabled;
        if state.isr != 0
            && let Err(err) = self.0.line.set_level(!disabled)
        {
            warn!("failed to update virtio-pci INTx disable state: {err}");
        }
    }

    fn signal(&self, bit: u8) -> Result<(), crate::Error> {
        let mut state = self.0.state.lock().unwrap();
        let was_pending = state.isr != 0;
        state.isr |= bit;
        if state.intx_disabled || was_pending {
            return Ok(());
        }
        self.0
            .line
            .set_level(true)
            .map_err(crate::Error::FailedSignalingUsedQueue)
    }
}

impl InterruptHandler for PciInterrupt {
    fn try_signal(&self, interrupt: InterruptType) -> Result<(), crate::Error> {
        let (bit, description) = match interrupt {
            InterruptType::UsedQueue => (VIRTIO_ISR_QUEUE, "used queue"),
            InterruptType::ConfigChange => (VIRTIO_ISR_CONFIG, "configuration change"),
        };
        debug!(target: &self.0.log_target, "interrupt: {description}");
        self.signal(bit)
    }
}

#[derive(Clone, Copy)]
struct Capability {
    offset: u8,
    len: u8,
    cfg_type: u8,
    bar_offset: u32,
    bar_len: u32,
}

#[derive(Clone, Copy)]
struct PciQueueRegisters {
    size: u16,
    enabled: bool,
    notification_pending: bool,
}

impl PciQueueRegisters {
    fn new(max_size: u16) -> Self {
        Self {
            size: max_size,
            enabled: false,
            notification_pending: false,
        }
    }
}

struct PciConfigSpace([u8; PCI_CONFIG_SIZE]);

impl Default for PciConfigSpace {
    fn default() -> Self {
        Self([0; PCI_CONFIG_SIZE])
    }
}

impl PciConfigSpace {
    fn read_bytes(&self, offset: usize, length: usize) -> Option<&[u8]> {
        self.0.get(offset..offset.checked_add(length)?)
    }

    fn write_bytes(&mut self, offset: usize, data: &[u8]) {
        let end = offset
            .checked_add(data.len())
            .expect("PCI config-space write range overflowed");
        self.0
            .get_mut(offset..end)
            .expect("PCI config-space write is within bounds")
            .copy_from_slice(data);
    }

    fn read_u8(&self, offset: usize) -> Option<u8> {
        self.read_bytes(offset, size_of::<u8>())?.first().copied()
    }

    fn read_u16(&self, offset: usize) -> Option<u16> {
        let bytes = self.read_bytes(offset, size_of::<u16>())?.try_into().ok()?;
        Some(u16::from_le_bytes(bytes))
    }

    fn read_u32(&self, offset: usize) -> Option<u32> {
        let bytes = self.read_bytes(offset, size_of::<u32>())?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn write_u8(&mut self, offset: usize, value: u8) {
        self.write_bytes(offset, &[value]);
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        self.write_bytes(offset, &value.to_le_bytes());
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.write_bytes(offset, &value.to_le_bytes());
    }
}

pub struct VirtioPciTransport {
    state: VirtioTransportState,
    config: PciConfigSpace,
    bar_base: u32,
    bar_probe: bool,
    interrupt: PciInterrupt,
    device_interrupt: InterruptTransport,
    capabilities: Vec<Capability>,
    pci_cfg_cap_offset: Option<usize>,
    device_config_len: u32,
    queue_registers: Vec<PciQueueRegisters>,
    bus_master_enabled: Arc<AtomicBool>,
}

impl VirtioPciTransport {
    pub fn new(
        mem: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
        interrupt_line: u8,
        intx_line: Arc<dyn PciIntxLine>,
        bar_base: u32,
    ) -> Result<Self, CreatePciTransportError> {
        let (device_type, device_name, avail_features, device_config_len, has_shm) = {
            let locked = device.try_lock().expect(
                "Mutex of VirtioDevice should not be locked when creating virtio-pci transport",
            );
            (
                locked.device_type(),
                locked.device_name().to_string(),
                locked.avail_features(),
                locked.config_len(),
                locked.shm_region().is_some(),
            )
        };

        if avail_features & (1u64 << VIRTIO_F_VERSION_1) == 0 {
            return Err(CreatePciTransportError::MissingVersion1);
        }
        if has_shm {
            return Err(CreatePciTransportError::SharedMemoryNotSupported);
        }
        let device_config_len =
            device_config_len.ok_or(CreatePciTransportError::UnknownDeviceConfigLength)?;
        if u64::from(device_config_len) > VIRTIO_PCI_BAR0_SIZE - DEVICE_CFG_OFFSET {
            return Err(CreatePciTransportError::DeviceConfigTooLarge(
                device_config_len,
            ));
        }
        if u64::from(bar_base) % VIRTIO_PCI_BAR0_SIZE != 0
            || u64::from(bar_base) + VIRTIO_PCI_BAR0_SIZE > (1u64 << 32)
        {
            return Err(CreatePciTransportError::InvalidBarBase(bar_base));
        }

        let mut state =
            VirtioTransportState::new(mem, device).map_err(CreatePciTransportError::EventFd)?;
        let bus_master_enabled = Arc::new(AtomicBool::new(false));
        state.set_bus_master_gate(bus_master_enabled.clone());
        let queue_registers = state
            .queue_config
            .iter()
            .map(|queue| PciQueueRegisters::new(queue.size))
            .collect();
        let interrupt = PciInterrupt::new(intx_line, format!("{}[{device_name}]", module_path!()));
        let device_interrupt = InterruptTransport::from_handler(Arc::new(interrupt.clone()));
        let (config, capabilities, pci_cfg_cap_offset) =
            Self::build_config(device_type, device_config_len, interrupt_line);

        Ok(Self {
            state,
            config,
            bar_base,
            bar_probe: false,
            interrupt,
            device_interrupt,
            capabilities,
            pci_cfg_cap_offset,
            device_config_len,
            queue_registers,
            bus_master_enabled,
        })
    }

    pub fn device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.state.device()
    }

    fn build_config(
        device_type: u32,
        device_config_len: u32,
        interrupt_line: u8,
    ) -> (PciConfigSpace, Vec<Capability>, Option<usize>) {
        let mut config = PciConfigSpace::default();
        let mut capabilities = vec![
            Capability {
                offset: 0,
                len: VIRTIO_PCI_CAPABILITY_LENGTH,
                cfg_type: VIRTIO_PCI_CAP_COMMON_CFG,
                bar_offset: COMMON_CFG_OFFSET as u32,
                bar_len: COMMON_CFG_LEN,
            },
            Capability {
                offset: 0,
                len: VIRTIO_PCI_NOTIFY_CAPABILITY_LENGTH,
                cfg_type: VIRTIO_PCI_CAP_NOTIFY_CFG,
                bar_offset: NOTIFY_CFG_OFFSET as u32,
                bar_len: NOTIFY_CFG_LEN,
            },
            Capability {
                offset: 0,
                len: VIRTIO_PCI_CAPABILITY_LENGTH,
                cfg_type: VIRTIO_PCI_CAP_ISR_CFG,
                bar_offset: ISR_CFG_OFFSET as u32,
                bar_len: 1,
            },
        ];
        if device_config_len != 0 {
            capabilities.push(Capability {
                offset: 0,
                len: VIRTIO_PCI_CAPABILITY_LENGTH,
                cfg_type: VIRTIO_PCI_CAP_DEVICE_CFG,
                bar_offset: DEVICE_CFG_OFFSET as u32,
                bar_len: device_config_len,
            });
        }
        capabilities.push(Capability {
            offset: 0,
            len: VIRTIO_PCI_NOTIFY_CAPABILITY_LENGTH,
            cfg_type: VIRTIO_PCI_CAP_PCI_CFG,
            bar_offset: 0,
            bar_len: 0,
        });

        let mut next_offset = pci_config::CAPABILITIES_START;
        for capability in &mut capabilities {
            capability.offset = next_offset as u8;
            next_offset += usize::from(capability.len);
        }

        let device_id = PCI_DEVICE_ID_VIRTIO_MODERN.wrapping_add(device_type as u16);
        config.write_u16(pci_config::VENDOR_ID, PCI_VENDOR_ID_VIRTIO);
        config.write_u16(pci_config::DEVICE_ID, device_id);
        config.write_u16(pci_config::COMMAND, PCI_COMMAND_MEMORY);
        config.write_u16(pci_config::STATUS, PCI_CAPABILITY_LIST_STATUS);
        config.write_u8(pci_config::REVISION_ID, PCI_REVISION_MODERN);
        config.write_u8(pci_config::HEADER_TYPE, PCI_HEADER_TYPE_ENDPOINT);
        config.write_u16(pci_config::SUBSYSTEM_VENDOR_ID, PCI_VENDOR_ID_VIRTIO);
        config.write_u16(
            pci_config::SUBSYSTEM_DEVICE_ID,
            PCI_SUBSYSTEM_DEVICE_ID_BASE.wrapping_add(device_type as u16),
        );
        config.write_u8(
            pci_config::CAPABILITY_POINTER,
            capabilities
                .first()
                .map_or(0, |capability| capability.offset),
        );
        config.write_u8(pci_config::INTERRUPT_LINE, interrupt_line);
        config.write_u8(pci_config::INTERRUPT_PIN, PCI_INTERRUPT_PIN_INTA);

        let mut pci_cfg_cap_offset = None;
        for (index, capability) in capabilities.iter().enumerate() {
            let offset = usize::from(capability.offset);
            let next = capabilities
                .get(index + 1)
                .map_or(0, |next_capability| next_capability.offset);
            config.write_u8(
                offset + vendor_cap::VENDOR_SPECIFIC_CAPABILITY_ID,
                PCI_CAPABILITY_ID_VENDOR_SPECIFIC,
            );
            config.write_u8(offset + vendor_cap::NEXT, next);
            config.write_u8(offset + vendor_cap::LENGTH, capability.len);
            config.write_u8(offset + vendor_cap::CONFIG_TYPE, capability.cfg_type);
            config.write_u8(offset + vendor_cap::BAR, PCI_BAR0_INDEX);
            config.write_u8(offset + vendor_cap::REGION_ID, 0);
            config.write_u32(offset + vendor_cap::REGION_OFFSET, capability.bar_offset);
            config.write_u32(offset + vendor_cap::REGION_LENGTH, capability.bar_len);

            if capability.cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG {
                config.write_u32(
                    offset + vendor_cap::NOTIFY_MULTIPLIER,
                    NOTIFY_OFF_MULTIPLIER,
                );
            }
            if capability.cfg_type == VIRTIO_PCI_CAP_PCI_CFG {
                config.write_u32(offset + vendor_cap::REGION_LENGTH, PCI_CFG_DATA_SIZE as u32);
                pci_cfg_cap_offset = Some(offset);
            }
        }

        (config, capabilities, pci_cfg_cap_offset)
    }

    fn config_status(&self) -> u16 {
        let mut status = self
            .config
            .read_u16(pci_config::STATUS)
            .expect("PCI status register fits in configuration space")
            & !PCI_STATUS_INTERRUPT;
        if self.interrupt.is_pending() {
            status |= PCI_STATUS_INTERRUPT;
        }
        status
    }

    fn bar0_value(&self) -> u32 {
        if self.bar_probe {
            (!(VIRTIO_PCI_BAR0_SIZE as u32 - 1)) & PCI_BAR_ADDRESS_MASK
        } else {
            self.bar_base
        }
    }

    fn config_byte(&self, offset: usize) -> u8 {
        match offset {
            pci_config::STATUS..=PCI_STATUS_LAST_BYTE => self
                .config_status()
                .to_le_bytes()
                .get(offset - pci_config::STATUS)
                .copied()
                .unwrap_or(PCI_UNIMPLEMENTED_READ_BYTE),
            PCI_BAR0_OFFSET..=PCI_BAR0_END => self
                .bar0_value()
                .to_le_bytes()
                .get(offset - PCI_BAR0_OFFSET)
                .copied()
                .unwrap_or(PCI_UNIMPLEMENTED_READ_BYTE),
            _ => self
                .config
                .read_u8(offset)
                .unwrap_or(PCI_UNIMPLEMENTED_READ_BYTE),
        }
    }

    fn pci_cfg_selection(&self) -> Option<(u8, u32, usize)> {
        let offset = self.pci_cfg_cap_offset?;
        let bar = self.config.read_u8(offset + vendor_cap::BAR)?;
        let bar_offset = self.config.read_u32(offset + vendor_cap::REGION_OFFSET)?;
        let length = self.config.read_u32(offset + vendor_cap::REGION_LENGTH)? as usize;
        if bar != PCI_BAR0_INDEX
            || !matches!(length, BYTE_SIZE | WORD_SIZE | DWORD_SIZE)
            || !(bar_offset as usize).is_multiple_of(length)
        {
            return None;
        }
        let end = bar_offset.checked_add(length as u32)?;
        if !self.capabilities.iter().any(|capability| {
            capability.cfg_type != VIRTIO_PCI_CAP_PCI_CFG
                && bar_offset >= capability.bar_offset
                && capability
                    .bar_offset
                    .checked_add(capability.bar_len)
                    .is_some_and(|capability_end| end <= capability_end)
        }) {
            return None;
        }
        Some((bar, bar_offset, length))
    }

    fn read_bar_region(&mut self, offset: u64, data: &mut [u8]) -> PciBarAccess {
        if offset + data.len() as u64 <= u64::from(COMMON_CFG_LEN) {
            self.read_common_config(offset, data);
            return PciBarAccess::Handled;
        }
        if offset >= NOTIFY_CFG_OFFSET
            && offset + data.len() as u64 <= NOTIFY_CFG_OFFSET + u64::from(NOTIFY_CFG_LEN)
        {
            data.fill(0);
            return PciBarAccess::Handled;
        }
        if offset == ISR_CFG_OFFSET && data.len() == BYTE_SIZE {
            data.copy_from_slice(&[self.interrupt.read_isr()]);
            return PciBarAccess::Handled;
        }
        if offset >= DEVICE_CFG_OFFSET
            && offset + data.len() as u64 <= DEVICE_CFG_OFFSET + u64::from(self.device_config_len)
        {
            if data.is_empty() {
                return PciBarAccess::Handled;
            }
            self.state
                .locked_device()
                .read_config(offset - DEVICE_CFG_OFFSET, data);
            return PciBarAccess::Handled;
        }
        data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
        PciBarAccess::Unhandled
    }

    fn write_bar_region(&mut self, offset: u64, data: &[u8]) -> PciBarAccess {
        if offset + data.len() as u64 <= u64::from(COMMON_CFG_LEN) {
            self.write_common_config(offset, data);
            return PciBarAccess::Handled;
        }
        if offset >= NOTIFY_CFG_OFFSET && offset < NOTIFY_CFG_OFFSET + u64::from(NOTIFY_CFG_LEN) {
            self.notify_queue(offset, data);
            return PciBarAccess::Handled;
        }
        if offset >= DEVICE_CFG_OFFSET
            && offset + data.len() as u64 <= DEVICE_CFG_OFFSET + u64::from(self.device_config_len)
        {
            if self.state.device_status & (device_status::DRIVER | device_status::FAILED)
                == device_status::DRIVER
            {
                self.state
                    .locked_device()
                    .write_config(offset - DEVICE_CFG_OFFSET, data);
            }
            return PciBarAccess::Handled;
        }
        PciBarAccess::Unhandled
    }

    fn read_common_config(&mut self, offset: u64, data: &mut [u8]) {
        let queue_select = self.state.queue_select;
        let value = match offset {
            common_cfg::DEVICE_FEATURE_SELECT if data.len() == DWORD_SIZE => {
                Some(self.state.features_select.to_le_bytes().to_vec())
            }
            common_cfg::DEVICE_FEATURE if data.len() == DWORD_SIZE => Some(
                self.state
                    .locked_device()
                    .avail_features_by_page(self.state.features_select)
                    .to_le_bytes()
                    .to_vec(),
            ),
            common_cfg::DRIVER_FEATURE_SELECT if data.len() == DWORD_SIZE => {
                Some(self.state.acked_features_select.to_le_bytes().to_vec())
            }
            common_cfg::DRIVER_FEATURE if data.len() == DWORD_SIZE => {
                let page = self.state.acked_features_select;
                let feature_words = u64::BITS / u32::BITS;
                let features = if page < feature_words {
                    (self.state.locked_device().acked_features() >> (page * u32::BITS)) as u32
                } else {
                    0
                };
                Some(features.to_le_bytes().to_vec())
            }
            common_cfg::MSIX_CONFIG if data.len() == WORD_SIZE => {
                Some(VIRTIO_MSI_NO_VECTOR.to_le_bytes().to_vec())
            }
            common_cfg::NUMBER_OF_QUEUES if data.len() == WORD_SIZE => Some(
                (self.state.queue_config.len() as u16)
                    .to_le_bytes()
                    .to_vec(),
            ),
            common_cfg::DEVICE_STATUS if data.len() == BYTE_SIZE => {
                Some(vec![self.state.device_status as u8])
            }
            common_cfg::CONFIG_GENERATION if data.len() == BYTE_SIZE => {
                Some(vec![self.state.config_generation as u8])
            }
            common_cfg::QUEUE_SELECT if data.len() == WORD_SIZE => {
                Some((queue_select as u16).to_le_bytes().to_vec())
            }
            common_cfg::QUEUE_SIZE if data.len() == WORD_SIZE => Some(
                self.queue_registers
                    .get(queue_select as usize)
                    .map_or(0, |registers| registers.size)
                    .to_le_bytes()
                    .to_vec(),
            ),
            common_cfg::QUEUE_MSIX_VECTOR if data.len() == WORD_SIZE => {
                Some(VIRTIO_MSI_NO_VECTOR.to_le_bytes().to_vec())
            }
            common_cfg::QUEUE_ENABLE if data.len() == WORD_SIZE => Some(
                if self
                    .queue_registers
                    .get(queue_select as usize)
                    .is_some_and(|registers| registers.enabled)
                {
                    VIRTIO_QUEUE_READY
                } else {
                    0
                }
                .to_le_bytes()
                .to_vec(),
            ),
            common_cfg::QUEUE_NOTIFY_OFFSET if data.len() == WORD_SIZE => Some(
                (if self.state.queue_max_size(queue_select) == 0 {
                    0
                } else {
                    queue_select as u16
                })
                .to_le_bytes()
                .to_vec(),
            ),
            common_cfg::QUEUE_DESCRIPTOR
            | common_cfg::QUEUE_DESCRIPTOR_HIGH
            | common_cfg::QUEUE_DRIVER
            | common_cfg::QUEUE_DRIVER_HIGH
            | common_cfg::QUEUE_DEVICE
            | common_cfg::QUEUE_DEVICE_HIGH
                if data.len() == DWORD_SIZE =>
            {
                let (base, address) = self.queue_address(offset, queue_select);
                let word = address
                    .map(|address| address.wrapping_shr(((offset - base) as u32) * u8::BITS) as u32)
                    .unwrap_or(0);
                Some(word.to_le_bytes().to_vec())
            }
            common_cfg::QUEUE_DESCRIPTOR | common_cfg::QUEUE_DRIVER | common_cfg::QUEUE_DEVICE
                if data.len() == QWORD_SIZE =>
            {
                let (_, address) = self.queue_address(offset, queue_select);
                Some(address.unwrap_or(0).to_le_bytes().to_vec())
            }
            common_cfg::QUEUE_NOTIFY_DATA | common_cfg::QUEUE_RESET_OFFSET
                if data.len() == WORD_SIZE =>
            {
                Some(0u16.to_le_bytes().to_vec())
            }
            _ => None,
        };
        if let Some(value) = value {
            data.copy_from_slice(&value);
        } else {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
        }
    }

    fn reset_queue_registers(&mut self) {
        for (registers, queue_config) in self
            .queue_registers
            .iter_mut()
            .zip(&self.state.queue_config)
        {
            *registers = PciQueueRegisters::new(queue_config.size);
        }
    }

    fn queue_address(&self, offset: u64, queue_select: u32) -> (u64, Option<u64>) {
        let base = match offset {
            common_cfg::QUEUE_DESCRIPTOR | common_cfg::QUEUE_DESCRIPTOR_HIGH => {
                common_cfg::QUEUE_DESCRIPTOR
            }
            common_cfg::QUEUE_DRIVER | common_cfg::QUEUE_DRIVER_HIGH => common_cfg::QUEUE_DRIVER,
            common_cfg::QUEUE_DEVICE | common_cfg::QUEUE_DEVICE_HIGH => common_cfg::QUEUE_DEVICE,
            _ => offset,
        };
        let address = self.state.with_queue(queue_select, None, |queue| {
            Some(match base {
                common_cfg::QUEUE_DESCRIPTOR => queue.desc_table.raw_value(),
                common_cfg::QUEUE_DRIVER => queue.avail_ring.raw_value(),
                common_cfg::QUEUE_DEVICE => queue.used_ring.raw_value(),
                _ => 0,
            })
        });
        (base, address)
    }

    fn write_common_config(&mut self, offset: u64, data: &[u8]) {
        if offset == common_cfg::DEVICE_STATUS && data.len() == BYTE_SIZE {
            let status = u32::from(u8::from_le_bytes(data.try_into().unwrap()));
            let was_activated = self.state.locked_device().is_activated();
            if self.state.set_device_status(
                status,
                self.device_interrupt.clone(),
                self.bus_master_enabled.load(Ordering::Acquire),
            ) {
                self.interrupt.reset();
                self.reset_queue_registers();
            } else if !was_activated && self.state.locked_device().is_activated() {
                self.replay_pending_queue_notifications();
            }
            return;
        }

        let queue_select = self.state.queue_select;
        match (offset, data.len()) {
            (common_cfg::DEVICE_FEATURE_SELECT, DWORD_SIZE) => {
                self.state.features_select = u32::from_le_bytes(data.try_into().unwrap())
            }
            (common_cfg::DRIVER_FEATURE_SELECT, DWORD_SIZE) => {
                self.state.acked_features_select = u32::from_le_bytes(data.try_into().unwrap())
            }
            (common_cfg::DRIVER_FEATURE, DWORD_SIZE)
                if self.state.device_status
                    & (device_status::DRIVER
                        | device_status::FEATURES_OK
                        | device_status::FAILED)
                    == device_status::DRIVER =>
            {
                self.state.locked_device().ack_features_by_page(
                    self.state.acked_features_select,
                    u32::from_le_bytes(data.try_into().unwrap()),
                );
            }
            (common_cfg::QUEUE_SELECT, WORD_SIZE) => {
                self.state.queue_select = u16::from_le_bytes(data.try_into().unwrap()) as u32
            }
            (common_cfg::QUEUE_SIZE, WORD_SIZE) if self.can_configure_queue(queue_select) => {
                let size = u16::from_le_bytes(data.try_into().unwrap());
                if self
                    .state
                    .with_queue_mut(queue_select, |queue| queue.size = size)
                    && let Some(registers) = self.queue_registers.get_mut(queue_select as usize)
                {
                    registers.size = size;
                }
            }
            (common_cfg::QUEUE_ENABLE, WORD_SIZE)
                if u16::from_le_bytes(data.try_into().unwrap()) == VIRTIO_QUEUE_READY
                    && self.can_configure_queue(queue_select) =>
            {
                if self
                    .state
                    .with_queue_mut(queue_select, |queue| queue.ready = true)
                    && let Some(registers) = self.queue_registers.get_mut(queue_select as usize)
                {
                    registers.enabled = true;
                }
            }
            (
                common_cfg::QUEUE_DESCRIPTOR
                | common_cfg::QUEUE_DESCRIPTOR_HIGH
                | common_cfg::QUEUE_DRIVER
                | common_cfg::QUEUE_DRIVER_HIGH
                | common_cfg::QUEUE_DEVICE
                | common_cfg::QUEUE_DEVICE_HIGH,
                DWORD_SIZE,
            ) => {
                let value = u32::from_le_bytes(data.try_into().unwrap());
                self.write_queue_address(offset, queue_select, value);
            }
            (
                common_cfg::QUEUE_DESCRIPTOR | common_cfg::QUEUE_DRIVER | common_cfg::QUEUE_DEVICE,
                QWORD_SIZE,
            ) => {
                let value = u64::from_le_bytes(data.try_into().unwrap());
                self.write_queue_address_full(offset, queue_select, value);
            }
            _ => {}
        }
    }

    fn can_configure_queue(&self, queue_select: u32) -> bool {
        self.state.device_status & (device_status::FEATURES_OK | device_status::FAILED)
            == device_status::FEATURES_OK
            && !self
                .state
                .with_queue(queue_select, false, |queue| queue.ready)
    }

    fn write_queue_address(&mut self, offset: u64, queue_select: u32, value: u32) {
        let base = match offset {
            common_cfg::QUEUE_DESCRIPTOR | common_cfg::QUEUE_DESCRIPTOR_HIGH => {
                common_cfg::QUEUE_DESCRIPTOR
            }
            common_cfg::QUEUE_DRIVER | common_cfg::QUEUE_DRIVER_HIGH => common_cfg::QUEUE_DRIVER,
            common_cfg::QUEUE_DEVICE | common_cfg::QUEUE_DEVICE_HIGH => common_cfg::QUEUE_DEVICE,
            _ => return,
        };
        let shift = ((offset - base) as u32) * u8::BITS;
        if self.can_configure_queue(queue_select) {
            self.state.with_queue_mut(queue_select, |queue| {
                let address = match base {
                    common_cfg::QUEUE_DESCRIPTOR => &mut queue.desc_table,
                    common_cfg::QUEUE_DRIVER => &mut queue.avail_ring,
                    _ => &mut queue.used_ring,
                };
                address.0 =
                    (address.0 & !(QUEUE_ADDRESS_HALF_MASK << shift)) | (u64::from(value) << shift);
            });
        }
    }

    fn write_queue_address_full(&mut self, offset: u64, queue_select: u32, value: u64) {
        if !self.can_configure_queue(queue_select) {
            return;
        }
        self.state
            .with_queue_mut(queue_select, |queue| match offset {
                common_cfg::QUEUE_DESCRIPTOR => queue.desc_table = GuestAddress(value),
                common_cfg::QUEUE_DRIVER => queue.avail_ring = GuestAddress(value),
                common_cfg::QUEUE_DEVICE => queue.used_ring = GuestAddress(value),
                _ => {}
            });
    }

    fn notify_queue(&mut self, offset: u64, data: &[u8]) {
        let relative = offset - NOTIFY_CFG_OFFSET;
        if data.len() != WORD_SIZE || !relative.is_multiple_of(u64::from(NOTIFY_OFF_MULTIPLIER)) {
            warn!("invalid virtio-pci queue notification at 0x{offset:x}");
            return;
        }
        let queue_index = (relative / u64::from(NOTIFY_OFF_MULTIPLIER)) as usize;
        let Some(registers) = self.queue_registers.get_mut(queue_index) else {
            return;
        };
        if !self.bus_master_enabled.load(Ordering::Acquire) {
            registers.notification_pending = true;
            return;
        }
        if let Some(event) = self.state.queue_evts().get(queue_index)
            && let Err(err) = event.write(QUEUE_EVENT_SIGNAL)
        {
            warn!("failed to notify virtio-pci queue {queue_index}: {err}");
        }
    }

    fn activate_if_ready(&mut self) {
        if !self.bus_master_enabled.load(Ordering::Acquire)
            || self.state.device_status & device_status::DRIVER_OK == 0
        {
            return;
        }

        if !self.state.locked_device().is_activated() {
            self.state.activate(self.device_interrupt.clone());
        }
        self.replay_pending_queue_notifications();
    }

    fn replay_pending_queue_notifications(&mut self) {
        if !self.bus_master_enabled.load(Ordering::Acquire) {
            return;
        }
        for (queue_index, (registers, event)) in self
            .queue_registers
            .iter_mut()
            .zip(self.state.queue_evts())
            .enumerate()
        {
            if registers.notification_pending {
                registers.notification_pending = false;
                if let Err(err) = event.write(QUEUE_EVENT_SIGNAL) {
                    warn!("failed to notify virtio-pci queue {queue_index}: {err}");
                }
            }
        }
    }

    fn read_pci_cfg_region(&mut self, data: &mut [u8]) {
        if let Some((PCI_BAR0_INDEX, selected_offset, len)) = self.pci_cfg_selection()
            && data.len() == len
        {
            self.read_bar_region(u64::from(selected_offset), data);
        } else {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
        }
    }

    fn write_pci_cfg_region(&mut self, data: &[u8]) {
        if let Some((PCI_BAR0_INDEX, selected_offset, len)) = self.pci_cfg_selection()
            && data.len() == len
        {
            self.write_bar_region(u64::from(selected_offset), data);
        }
    }
}

impl PciFunction for VirtioPciTransport {
    fn read_config(&mut self, offset: u16, data: &mut [u8]) {
        let start = usize::from(offset);
        let Some(end) = start.checked_add(data.len()) else {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
            return;
        };
        if end > PCI_CONFIG_SIZE {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
            return;
        }

        if let Some(cap_offset) = self.pci_cfg_cap_offset {
            let data_start = cap_offset + vendor_cap::PCI_CONFIG_DATA;
            if start >= data_start && end <= data_start + PCI_CFG_DATA_SIZE {
                if start == data_start {
                    self.read_pci_cfg_region(data);
                } else {
                    data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
                }
                return;
            }
        }

        for (index, byte) in data.iter_mut().enumerate() {
            *byte = self.config_byte(start + index);
        }
    }

    fn write_config(&mut self, offset: u16, data: &[u8]) {
        let start = usize::from(offset);
        let Some(end) = start.checked_add(data.len()) else {
            return;
        };
        if end > PCI_CONFIG_SIZE {
            return;
        }

        if let Some(pci_cfg_cap_offset) = self.pci_cfg_cap_offset {
            let data_start = pci_cfg_cap_offset + vendor_cap::PCI_CONFIG_DATA;
            if start >= data_start && end <= data_start + PCI_CFG_DATA_SIZE {
                if start == data_start {
                    self.write_pci_cfg_region(data);
                }
                return;
            }
        }

        if start == pci_config::BAR0 && data.len() == PCI_BAR0_SIZE {
            let value = u32::from_le_bytes(data.try_into().unwrap());
            if value == PCI_BAR_PROBE_VALUE {
                self.bar_probe = true;
                return;
            }
        }

        let command_end = pci_config::COMMAND + WORD_SIZE;
        let command_register_touched = start < command_end && end > pci_config::COMMAND;
        let bus_master_was_enabled = self.bus_master_enabled.load(Ordering::Acquire);
        for (index, value) in data.iter().copied().enumerate() {
            let register = start + index;
            match register {
                pci_config::COMMAND..=PCI_COMMAND_LAST_BYTE => {
                    self.config.write_u8(register, value)
                }
                pci_config::BAR0..=PCI_BAR0_END => {
                    self.bar_probe = false;
                    let mut bytes = self.bar_base.to_le_bytes();
                    let byte_offset = register - pci_config::BAR0;
                    if let Some(byte) = bytes.get_mut(byte_offset) {
                        *byte = value;
                    }
                    self.bar_base = u32::from_le_bytes(bytes) & VIRTIO_PCI_BAR0_ADDRESS_MASK;
                }
                _ => {
                    if let Some(cap_offset) = self.pci_cfg_cap_offset {
                        let cap_field = register.checked_sub(cap_offset);
                        if cap_field.is_some_and(|field| {
                            field == vendor_cap::BAR
                                || (vendor_cap::REGION_OFFSET
                                    ..vendor_cap::REGION_OFFSET + DWORD_SIZE)
                                    .contains(&field)
                                || (vendor_cap::REGION_LENGTH
                                    ..vendor_cap::REGION_LENGTH + DWORD_SIZE)
                                    .contains(&field)
                        }) {
                            self.config.write_u8(register, value);
                        }
                    }
                }
            }
        }

        if command_register_touched {
            let command = self
                .config
                .read_u16(pci_config::COMMAND)
                .expect("PCI command register fits in configuration space");
            let bus_master_enabled = command & PCI_COMMAND_MASTER != 0;
            self.bus_master_enabled
                .store(bus_master_enabled, Ordering::Release);
            self.interrupt
                .set_intx_disabled(command & PCI_COMMAND_INTX_DISABLE != 0);
            if !bus_master_was_enabled && bus_master_enabled {
                self.activate_if_ready();
            }
        }
    }

    fn read_bar(&mut self, address: u64, data: &mut [u8]) -> PciBarAccess {
        let command = self
            .config
            .read_u16(pci_config::COMMAND)
            .expect("PCI command register fits in configuration space");
        if command & PCI_COMMAND_MEMORY == 0 || self.bar_base == 0 {
            return PciBarAccess::Unhandled;
        }
        let base = u64::from(self.bar_base);
        let Some(offset) = address.checked_sub(base) else {
            return PciBarAccess::Unhandled;
        };
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > VIRTIO_PCI_BAR0_SIZE)
        {
            return PciBarAccess::Unhandled;
        }
        self.read_bar_region(offset, data)
    }

    fn write_bar(&mut self, address: u64, data: &[u8]) -> PciBarAccess {
        let command = self
            .config
            .read_u16(pci_config::COMMAND)
            .expect("PCI command register fits in configuration space");
        if command & PCI_COMMAND_MEMORY == 0 || self.bar_base == 0 {
            return PciBarAccess::Unhandled;
        }
        let base = u64::from(self.bar_base);
        let Some(offset) = address.checked_sub(base) else {
            return PciBarAccess::Unhandled;
        };
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > VIRTIO_PCI_BAR0_SIZE)
        {
            return PciBarAccess::Unhandled;
        }
        self.write_bar_region(offset, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BusDevice;
    use crate::virtio::{ActivateResult, DeviceQueue, QueueConfig};
    use std::sync::atomic::{AtomicBool, Ordering};
    use vm_memory::GuestAddress;

    const TEST_DEVICE_TYPE: u32 = 1;
    const TEST_QUEUE_SIZE: u16 = 8;
    const TEST_SELECTED_QUEUE_SIZE: u16 = 4;
    const TEST_BAR_BASE: u32 = 0xe100_0000;
    const TEST_RELOCATED_BAR_BASE: u32 = TEST_BAR_BASE + VIRTIO_PCI_BAR0_SIZE as u32;
    const TEST_GUEST_MEMORY_SIZE: usize = 0x10000;
    const TEST_DESCRIPTOR_ADDRESS: u32 = 0x1000;
    const TEST_DRIVER_ADDRESS: u32 = 0x2000;
    const TEST_DEVICE_ADDRESS: u32 = 0x3000;

    static QUEUE_CONFIG: [QueueConfig; 1] = [QueueConfig::new(TEST_QUEUE_SIZE)];
    static MULTI_QUEUE_CONFIG: [QueueConfig; 2] = [
        QueueConfig::new(TEST_QUEUE_SIZE),
        QueueConfig::new(TEST_QUEUE_SIZE),
    ];
    const DEVICE_CONFIG: [u8; DWORD_SIZE] = [0x12, 0x34, 0x56, 0x78];
    const TEST_PCI_ADDRESS: crate::pci::PciAddress = crate::pci::PciAddress {
        bus: 0,
        device: 1,
        function: 0,
    };

    #[derive(Default)]
    struct DummyIntxLine(AtomicBool);

    impl PciIntxLine for DummyIntxLine {
        fn set_level(&self, asserted: bool) -> io::Result<()> {
            self.0.store(asserted, Ordering::SeqCst);
            Ok(())
        }
    }

    struct DummyDevice {
        acked_features: u64,
        activated: bool,
        queue_config: &'static [QueueConfig],
    }

    impl VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            1u64 << VIRTIO_F_VERSION_1
        }

        fn acked_features(&self) -> u64 {
            self.acked_features
        }

        fn set_acked_features(&mut self, features: u64) {
            self.acked_features = features;
        }

        fn device_type(&self) -> u32 {
            TEST_DEVICE_TYPE
        }

        fn device_name(&self) -> &str {
            "pci-test"
        }

        fn queue_config(&self) -> &[QueueConfig] {
            self.queue_config
        }

        fn config_len(&self) -> Option<u32> {
            Some(DEVICE_CONFIG.len() as u32)
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let start = offset as usize;
            let end = start + data.len();
            let config = DEVICE_CONFIG
                .get(start..end)
                .expect("test device configuration read is in bounds");
            data.copy_from_slice(config);
        }

        fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _interrupt: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            self.activated = true;
            Ok(())
        }

        fn is_activated(&self) -> bool {
            self.activated
        }

        fn reset(&mut self) -> bool {
            self.activated = false;
            true
        }
    }

    fn transport_with_queue_config(
        queue_config: &'static [QueueConfig],
    ) -> (VirtioPciTransport, Arc<DummyIntxLine>) {
        let mem =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), TEST_GUEST_MEMORY_SIZE)]).unwrap();
        let intx_line = Arc::new(DummyIntxLine::default());
        let transport = VirtioPciTransport::new(
            mem,
            Arc::new(Mutex::new(DummyDevice {
                acked_features: 0,
                activated: false,
                queue_config,
            })),
            5,
            intx_line.clone(),
            0,
        )
        .unwrap();
        (transport, intx_line)
    }

    fn transport_with_line() -> (VirtioPciTransport, Arc<DummyIntxLine>) {
        transport_with_queue_config(&QUEUE_CONFIG)
    }

    fn transport() -> VirtioPciTransport {
        transport_with_line().0
    }

    fn read_config(transport: &mut VirtioPciTransport, offset: u16, data: &mut [u8]) {
        PciFunction::read_config(transport, offset, data);
    }

    fn write_config(transport: &mut VirtioPciTransport, offset: u16, data: &[u8]) {
        PciFunction::write_config(transport, offset, data);
    }

    fn enable_memory_bar(transport: &mut VirtioPciTransport) -> u64 {
        let bar = TEST_BAR_BASE;
        write_config(
            transport,
            pci_config::COMMAND as u16,
            &(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER).to_le_bytes(),
        );
        write_config(transport, pci_config::BAR0 as u16, &bar.to_le_bytes());
        u64::from(bar)
    }

    fn write_bar(transport: &mut VirtioPciTransport, base: u64, offset: u64, data: &[u8]) {
        assert_eq!(
            PciFunction::write_bar(transport, base + offset, data),
            PciBarAccess::Handled
        );
    }

    fn read_bar(transport: &mut VirtioPciTransport, address: u64, data: &mut [u8]) {
        assert_eq!(
            PciFunction::read_bar(transport, address, data),
            PciBarAccess::Handled
        );
    }

    #[test]
    fn advertises_modern_virtio_identity_and_capabilities() {
        let mut transport = transport();
        let mut vendor_id = [0; WORD_SIZE];
        read_config(&mut transport, pci_config::VENDOR_ID as u16, &mut vendor_id);
        assert_eq!(u16::from_le_bytes(vendor_id), PCI_VENDOR_ID_VIRTIO);
        let mut device_id = [0; WORD_SIZE];
        read_config(&mut transport, pci_config::DEVICE_ID as u16, &mut device_id);
        assert_eq!(
            u16::from_le_bytes(device_id),
            PCI_DEVICE_ID_VIRTIO_MODERN.wrapping_add(TEST_DEVICE_TYPE as u16)
        );

        let mut pointer = transport
            .config
            .read_u8(pci_config::CAPABILITY_POINTER)
            .unwrap();
        let mut cfg_types = Vec::new();
        while pointer != 0 {
            let offset = usize::from(pointer);
            cfg_types.push(
                transport
                    .config
                    .read_u8(offset + vendor_cap::CONFIG_TYPE)
                    .unwrap(),
            );
            pointer = transport.config.read_u8(offset + vendor_cap::NEXT).unwrap();
        }
        assert_eq!(
            cfg_types,
            [
                VIRTIO_PCI_CAP_COMMON_CFG,
                VIRTIO_PCI_CAP_NOTIFY_CFG,
                VIRTIO_PCI_CAP_ISR_CFG,
                VIRTIO_PCI_CAP_DEVICE_CFG,
                VIRTIO_PCI_CAP_PCI_CFG,
            ]
        );
    }

    #[test]
    fn bar_probe_and_device_configuration_are_routed() {
        let mut transport = transport();
        write_config(
            &mut transport,
            pci_config::BAR0 as u16,
            &PCI_BAR_PROBE_VALUE.to_le_bytes(),
        );
        let mut bar = [0; DWORD_SIZE];
        read_config(&mut transport, pci_config::BAR0 as u16, &mut bar);
        let expected_probe = (!(VIRTIO_PCI_BAR0_SIZE as u32 - 1)) & PCI_BAR_ADDRESS_MASK;
        assert_eq!(u32::from_le_bytes(bar), expected_probe);

        let bar_base = enable_memory_bar(&mut transport);
        let mut config = [0; 4];
        read_bar(&mut transport, bar_base + DEVICE_CFG_OFFSET, &mut config);
        assert_eq!(config, DEVICE_CONFIG);
    }

    #[test]
    fn bar_router_follows_config_space_relocation() {
        let function: Arc<Mutex<dyn PciFunction>> = Arc::new(Mutex::new(transport()));
        let root = crate::pci::PciRoot::shared();
        root.lock()
            .unwrap()
            .insert(TEST_PCI_ADDRESS, function)
            .unwrap();
        let mut config = crate::pci::ConfigMechanism1::new(root.clone());
        let mut bars = crate::pci::BarWindow::new(root, u64::from(TEST_BAR_BASE));
        let first_bar = TEST_BAR_BASE;
        let second_bar = TEST_RELOCATED_BAR_BASE;
        let selector = TEST_PCI_ADDRESS.config_mechanism_1_selector(pci_config::BAR0 as u16);
        config.write(
            0,
            crate::pci::CONFIG_MECHANISM_1_ADDRESS_PORT_OFFSET,
            &selector.to_le_bytes(),
        );
        config.write(
            0,
            crate::pci::CONFIG_MECHANISM_1_DATA_PORT_OFFSET,
            &first_bar.to_le_bytes(),
        );

        let mut value = [0; 4];
        bars.read(0, u64::from(DEVICE_CFG_OFFSET), &mut value);
        assert_eq!(value, DEVICE_CONFIG);

        config.write(
            0,
            crate::pci::CONFIG_MECHANISM_1_DATA_PORT_OFFSET,
            &second_bar.to_le_bytes(),
        );
        bars.read(0, u64::from(DEVICE_CFG_OFFSET), &mut value);
        assert_eq!(value, [PCI_UNIMPLEMENTED_READ_BYTE; DWORD_SIZE]);
        bars.read(
            0,
            u64::from(second_bar - first_bar) + u64::from(DEVICE_CFG_OFFSET),
            &mut value,
        );
        assert_eq!(value, DEVICE_CONFIG);
    }

    #[test]
    fn pci_cfg_capability_proxies_bar_accesses() {
        let mut transport = transport();
        let pci_cfg = transport
            .capabilities
            .iter()
            .find(|capability| capability.cfg_type == VIRTIO_PCI_CAP_PCI_CFG)
            .unwrap()
            .offset;
        write_config(
            &mut transport,
            u16::from(pci_cfg) + vendor_cap::REGION_OFFSET as u16,
            &(DEVICE_CFG_OFFSET as u32).to_le_bytes(),
        );
        write_config(
            &mut transport,
            u16::from(pci_cfg) + vendor_cap::REGION_LENGTH as u16,
            &(PCI_CFG_DATA_SIZE as u32).to_le_bytes(),
        );

        let mut config = [0; PCI_CFG_DATA_SIZE];
        read_config(
            &mut transport,
            u16::from(pci_cfg) + vendor_cap::PCI_CONFIG_DATA as u16,
            &mut config,
        );
        assert_eq!(config, DEVICE_CONFIG);
    }

    #[test]
    fn queue_notifications_and_isr_follow_pci_bar_accesses() {
        let (mut transport, intx_line) = transport_with_line();
        let bar_base = enable_memory_bar(&mut transport);
        let queue_event = transport.state.queue_evts().first().unwrap().clone();

        assert_eq!(
            PciFunction::write_bar(&mut transport, bar_base + NOTIFY_CFG_OFFSET, &[0, 0]),
            PciBarAccess::Handled
        );
        assert_eq!(queue_event.read().unwrap(), QUEUE_EVENT_SIGNAL);

        transport.device_interrupt.try_signal_used_queue().unwrap();
        transport
            .device_interrupt
            .try_signal_config_change()
            .unwrap();
        assert!(intx_line.0.load(Ordering::SeqCst));
        let mut pci_status = [0; WORD_SIZE];
        read_config(&mut transport, pci_config::STATUS as u16, &mut pci_status);
        assert_ne!(u16::from_le_bytes(pci_status) & PCI_STATUS_INTERRUPT, 0);

        let mut isr = [0; BYTE_SIZE];
        read_bar(&mut transport, bar_base + ISR_CFG_OFFSET, &mut isr);
        assert_eq!(isr, [VIRTIO_ISR_QUEUE | VIRTIO_ISR_CONFIG]);
        assert!(!intx_line.0.load(Ordering::SeqCst));

        pci_status = [0; 2];
        read_config(&mut transport, pci_config::STATUS as u16, &mut pci_status);
        assert_eq!(u16::from_le_bytes(pci_status) & PCI_STATUS_INTERRUPT, 0);
    }

    #[test]
    fn intx_disable_masks_and_replays_pending_interrupts() {
        let (mut transport, intx_line) = transport_with_line();
        let command = PCI_COMMAND_MEMORY | PCI_COMMAND_INTX_DISABLE;
        write_config(&mut transport, 4, &command.to_le_bytes());
        transport.device_interrupt.try_signal_used_queue().unwrap();
        assert!(!intx_line.0.load(Ordering::SeqCst));

        write_config(&mut transport, 4, &PCI_COMMAND_MEMORY.to_le_bytes());
        assert!(intx_line.0.load(Ordering::SeqCst));

        let bar_base = u64::from(TEST_BAR_BASE);
        write_config(
            &mut transport,
            pci_config::BAR0 as u16,
            &(bar_base as u32).to_le_bytes(),
        );
        let mut isr = [0; BYTE_SIZE];
        read_bar(&mut transport, bar_base + ISR_CFG_OFFSET, &mut isr);
        assert_eq!(isr, [VIRTIO_ISR_QUEUE]);
        assert!(!intx_line.0.load(Ordering::SeqCst));
    }

    #[test]
    fn queue_common_configuration_uses_virtio_register_widths() {
        let mut transport = transport();
        let bar_base = enable_memory_bar(&mut transport);
        let mut value = [0; WORD_SIZE];
        read_bar(
            &mut transport,
            bar_base + common_cfg::NUMBER_OF_QUEUES,
            &mut value,
        );
        assert_eq!(u16::from_le_bytes(value), 1);

        let mut wrong_width = [0; DWORD_SIZE];
        read_bar(
            &mut transport,
            bar_base + common_cfg::NUMBER_OF_QUEUES,
            &mut wrong_width,
        );
        assert_eq!(wrong_width, [PCI_UNIMPLEMENTED_READ_BYTE; DWORD_SIZE]);
    }

    #[test]
    fn queue_setup_activation_and_device_reset_use_shared_state() {
        let mut transport = transport();
        let bar_base = enable_memory_bar(&mut transport);
        let queue_event = transport.state.queue_evts().first().unwrap().clone();
        let mut queue_size = [0; WORD_SIZE];
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_SIZE,
            &mut queue_size,
        );
        assert_eq!(u16::from_le_bytes(queue_size), TEST_QUEUE_SIZE);

        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[device_status::ACKNOWLEDGE as u8],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[(device_status::ACKNOWLEDGE | device_status::DRIVER) as u8],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[
                (device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK)
                    as u8,
            ],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_SELECT,
            &0u16.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_SIZE,
            &TEST_SELECTED_QUEUE_SIZE.to_le_bytes(),
        );
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_SIZE,
            &mut queue_size,
        );
        assert_eq!(u16::from_le_bytes(queue_size), TEST_SELECTED_QUEUE_SIZE);
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_DESCRIPTOR,
            &TEST_DESCRIPTOR_ADDRESS.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_DRIVER,
            &TEST_DRIVER_ADDRESS.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_DEVICE,
            &TEST_DEVICE_ADDRESS.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_ENABLE,
            &VIRTIO_QUEUE_READY.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[(device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK) as u8],
        );

        assert!(transport.state.locked_device().is_activated());
        assert!(queue_event.read().is_err());
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_SIZE,
            &mut queue_size,
        );
        assert_eq!(u16::from_le_bytes(queue_size), TEST_SELECTED_QUEUE_SIZE);
        let mut queue_enable = [0; WORD_SIZE];
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_ENABLE,
            &mut queue_enable,
        );
        assert_eq!(u16::from_le_bytes(queue_enable), VIRTIO_QUEUE_READY);

        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[device_status::INIT as u8],
        );
        assert_eq!(transport.state.device_status, device_status::INIT);
        assert!(!transport.state.locked_device().is_activated());
        assert!(transport.state.queues.is_some());
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_SIZE,
            &mut queue_size,
        );
        assert_eq!(u16::from_le_bytes(queue_size), TEST_QUEUE_SIZE);
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_ENABLE,
            &mut queue_enable,
        );
        assert_eq!(u16::from_le_bytes(queue_enable), 0);
    }

    #[test]
    fn bus_master_enable_gates_pci_queue_activation_and_notifications() {
        let (mut transport, _) = transport_with_queue_config(&MULTI_QUEUE_CONFIG);
        let bar_base = u64::from(TEST_BAR_BASE);
        write_config(
            &mut transport,
            pci_config::COMMAND as u16,
            &PCI_COMMAND_MEMORY.to_le_bytes(),
        );
        write_config(
            &mut transport,
            pci_config::BAR0 as u16,
            &(bar_base as u32).to_le_bytes(),
        );
        let queue_events = transport.state.queue_evts().to_vec();

        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[device_status::ACKNOWLEDGE as u8],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[(device_status::ACKNOWLEDGE | device_status::DRIVER) as u8],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[
                (device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK)
                    as u8,
            ],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[(device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK) as u8],
        );
        assert!(!transport.state.locked_device().is_activated());

        write_bar(
            &mut transport,
            bar_base,
            NOTIFY_CFG_OFFSET + u64::from(NOTIFY_OFF_MULTIPLIER),
            &0u16.to_le_bytes(),
        );
        assert!(queue_events[0].read().is_err());
        assert!(queue_events[1].read().is_err());

        write_config(
            &mut transport,
            pci_config::COMMAND as u16,
            &(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER).to_le_bytes(),
        );
        assert!(transport.state.locked_device().is_activated());
        assert!(queue_events[0].read().is_err());
        assert_eq!(queue_events[1].read().unwrap(), QUEUE_EVENT_SIGNAL);

        write_config(
            &mut transport,
            pci_config::COMMAND as u16,
            &PCI_COMMAND_MEMORY.to_le_bytes(),
        );

        write_bar(
            &mut transport,
            bar_base,
            NOTIFY_CFG_OFFSET,
            &0u16.to_le_bytes(),
        );
        assert!(queue_events[0].read().is_err());
        assert!(queue_events[1].read().is_err());

        write_config(
            &mut transport,
            pci_config::COMMAND as u16,
            &(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER).to_le_bytes(),
        );
        assert_eq!(queue_events[0].read().unwrap(), QUEUE_EVENT_SIGNAL);
        assert!(queue_events[1].read().is_err());
    }
}
