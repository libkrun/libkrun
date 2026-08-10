// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Minimal PCI host bridge and VFIO cdev/IOMMUFD backend.
//!
//! This is deliberately a cold-plug-only boundary. It provides PCI mechanism
//! #1 config space, fixed BAR assignment, MSI-X delivery, reset, and identity
//! DMA mappings. Confidential guests get no initial DMA mappings: ranges are
//! added only when the guest converts those pages to shared state.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use devices::{BusDevice, BusError};
use iommufd_ioctls::IommuFd;
use kvm_bindings::{KVMIO, kvm_create_device, kvm_device_type_KVM_DEV_TYPE_VFIO, kvm_msi};
use kvm_ioctls::VmFd;
use vfio_bindings::bindings::vfio::{
    VFIO_PCI_CONFIG_REGION_INDEX, VFIO_REGION_INFO_FLAG_READ, VFIO_REGION_INFO_FLAG_WRITE,
};
use vfio_ioctls::{VfioDevice, VfioDeviceFd, VfioIommufd, VfioOps};
use vm_memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};
use vmm_sys_util::ioctl::ioctl_with_ref;

use crate::device_manager::legacy::PortIODeviceManager;
use crate::device_manager::mmio::MMIODeviceManager;
use crate::resources::VfioDeviceConfig;

const PCI_CONFIG_ADDRESS: u64 = 0xcf8;
const PCI_CONFIG_PORT_SIZE: u64 = 8;
const PCI_CONFIG_ENABLE: u32 = 1 << 31;
const PCI_BAR0: usize = 0x10;
const PCI_HEADER_TYPE: usize = 0x0e;
const PCI_CAP_PTR: usize = 0x34;
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;
const PCI_CAP_ID_MSIX: u8 = 0x11;
const PCI_MSIX_ENABLE: u16 = 1 << 15;
const PCI_MSIX_FUNCTION_MASK: u16 = 1 << 14;
const PCI_MSIX_TABLE_ENTRY_SIZE: u64 = 16;
const PCI_MMIO32_START: u64 = 0xe000_0000;
const PCI_MMIO32_END: u64 = 0xfebf_ffff;
const PCI_MMIO64_MIN: u64 = 1 << 40;
const PAGE_SIZE: u64 = 4096;

ioctl_iow_nr!(kvm_signal_msi, KVMIO, 0xa5, kvm_msi);

#[derive(Debug)]
pub enum Error {
    KvmDevice(kvm_ioctls::Error),
    Iommufd(iommufd_ioctls::IommufdError),
    Vfio(vfio_ioctls::VfioError),
    DuplicateBdf(u8, u8),
    InvalidConfigSpace,
    IoBarUnsupported(u8),
    InvalidBarSize(u8, u64),
    Mmio32Exhausted(u64),
    AddressOverflow,
    Bus(BusError),
    File(io::Error),
    EventFd(io::Error),
    Thread(io::Error),
    DmaRange,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KvmDevice(e) => write!(f, "failed to create KVM VFIO device: {e}"),
            Self::Iommufd(e) => write!(f, "failed to create IOMMUFD address space: {e}"),
            Self::Vfio(e) => write!(f, "VFIO operation failed: {e}"),
            Self::DuplicateBdf(d, fun) => write!(f, "duplicate guest PCI BDF 00:{d:02x}.{fun}"),
            Self::InvalidConfigSpace => write!(f, "VFIO device has invalid PCI config space"),
            Self::IoBarUnsupported(bar) => write!(f, "VFIO PCI I/O BAR {bar} is unsupported"),
            Self::InvalidBarSize(bar, size) => {
                write!(f, "VFIO PCI BAR {bar} has invalid size {size:#x}")
            }
            Self::Mmio32Exhausted(size) => {
                write!(
                    f,
                    "32-bit PCI MMIO aperture cannot fit BAR of size {size:#x}"
                )
            }
            Self::AddressOverflow => write!(f, "PCI MMIO address allocation overflowed"),
            Self::Bus(e) => write!(f, "failed to register PCI bus range: {e}"),
            Self::File(e) => write!(f, "failed to duplicate VFIO/KVM descriptor: {e}"),
            Self::EventFd(e) => write!(f, "failed to create VFIO interrupt eventfd: {e}"),
            Self::Thread(e) => write!(f, "failed to start VFIO interrupt worker: {e}"),
            Self::DmaRange => write!(f, "invalid or overlapping VFIO DMA range"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Shared IOMMU address-space owner. Its mappings have IOVA equal to GPA.
pub struct VfioDmaManager {
    ops: Arc<VfioIommufd>,
    mappings: Mutex<BTreeMap<u64, u64>>,
}

impl VfioDmaManager {
    fn new(ops: Arc<VfioIommufd>) -> Self {
        Self {
            ops,
            mappings: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn map_range(&self, iova: u64, size: u64, host_addr: *mut u8) -> Result<()> {
        validate_dma_range(iova, size)?;
        let end = iova.checked_add(size).ok_or(Error::DmaRange)?;
        let mut mappings = self.mappings.lock().unwrap();
        if mappings
            .range(..end)
            .next_back()
            .is_some_and(|(&start, &len)| {
                start.checked_add(len).is_none_or(|old_end| old_end > iova)
            })
        {
            return Err(Error::DmaRange);
        }

        // SAFETY: the guest-memory mapping outlives this manager and remains
        // pinned by IOMMUFD until the identical IOVA range is unmapped.
        unsafe {
            self.ops
                .vfio_dma_map(iova, size as usize, host_addr)
                .map_err(Error::Vfio)?;
        }
        mappings.insert(iova, size);
        Ok(())
    }

    #[cfg(feature = "tee")]
    pub fn unmap_range(&self, iova: u64, size: u64) -> Result<()> {
        validate_dma_range(iova, size)?;
        let mut mappings = self.mappings.lock().unwrap();
        if mappings.get(&iova).copied() != Some(size) {
            return Err(Error::DmaRange);
        }
        self.ops
            .vfio_dma_unmap(iova, size as usize)
            .map_err(Error::Vfio)?;
        mappings.remove(&iova);
        Ok(())
    }

    fn map_guest_memory(&self, memory: &GuestMemoryMmap) -> Result<()> {
        for region in memory.iter() {
            let start = region.start_addr().raw_value();
            let host = region.as_ptr();
            self.map_range(start, region.len(), host)?;
        }
        Ok(())
    }
}

fn validate_dma_range(iova: u64, size: u64) -> Result<()> {
    if size == 0 || !iova.is_multiple_of(PAGE_SIZE) || !size.is_multiple_of(PAGE_SIZE) {
        return Err(Error::DmaRange);
    }
    Ok(())
}

trait PciFunction: Send {
    fn read_config(&mut self, offset: usize, data: &mut [u8]);
    fn write_config(&mut self, offset: usize, data: &[u8]);
    fn set_multifunction(&mut self, multifunction: bool);
}

struct HostBridge {
    config: [u8; 256],
}

impl HostBridge {
    fn new() -> Self {
        let mut config = [0_u8; 256];
        config[0..2].copy_from_slice(&0x8086_u16.to_le_bytes());
        config[2..4].copy_from_slice(&0x1237_u16.to_le_bytes());
        config[0x0a] = 0x00;
        config[0x0b] = 0x06;
        Self { config }
    }
}

impl PciFunction for HostBridge {
    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        copy_config_read(&self.config, offset, data);
    }

    fn write_config(&mut self, _offset: usize, _data: &[u8]) {}

    fn set_multifunction(&mut self, _multifunction: bool) {}
}

struct PciConfigIo {
    address: u32,
    functions: BTreeMap<(u8, u8), Arc<Mutex<dyn PciFunction>>>,
}

impl PciConfigIo {
    fn new(functions: BTreeMap<(u8, u8), Arc<Mutex<dyn PciFunction>>>) -> Self {
        Self {
            address: 0,
            functions,
        }
    }

    fn selected(&self, data_port_offset: u64) -> Option<(&(u8, u8), usize)> {
        if self.address & PCI_CONFIG_ENABLE == 0 {
            return None;
        }
        let bus = ((self.address >> 16) & 0xff) as u8;
        if bus != 0 {
            return None;
        }
        let device = ((self.address >> 11) & 0x1f) as u8;
        let function = ((self.address >> 8) & 0x07) as u8;
        let register = (self.address & 0xfc) as usize + data_port_offset as usize;
        self.functions
            .get_key_value(&(device, function))
            .map(|(key, _)| (key, register))
    }
}

impl BusDevice for PciConfigIo {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        data.fill(0xff);
        if offset < 4 {
            let bytes = self.address.to_le_bytes();
            copy_config_read(&bytes, offset as usize, data);
            return;
        }
        let Some((key, register)) = self.selected(offset - 4) else {
            return;
        };
        if let Some(function) = self.functions.get(key) {
            function.lock().unwrap().read_config(register, data);
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if offset < 4 {
            if offset as usize + data.len() <= 4 {
                let mut bytes = self.address.to_le_bytes();
                bytes[offset as usize..offset as usize + data.len()].copy_from_slice(data);
                self.address = u32::from_le_bytes(bytes);
            }
            return;
        }
        let Some((key, register)) = self.selected(offset - 4) else {
            return;
        };
        if let Some(function) = self.functions.get(key) {
            function.lock().unwrap().write_config(register, data);
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PciBar {
    index: u8,
    address: u64,
    size: u64,
    flags: u32,
    is_64bit: bool,
    prefetchable: bool,
}

struct BarAllocator {
    mmio32: u64,
    mmio64: u64,
}

impl BarAllocator {
    fn new(memory: &GuestMemoryMmap) -> Result<Self> {
        let memory_end = memory
            .iter()
            .map(|region| region.last_addr().raw_value().saturating_add(1))
            .max()
            .unwrap_or(0);
        let mmio64 = align_up(memory_end.max(PCI_MMIO64_MIN), 1 << 30)?;
        Ok(Self {
            mmio32: PCI_MMIO32_START,
            mmio64,
        })
    }

    fn allocate(&mut self, size: u64, is_64bit: bool) -> Result<u64> {
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::InvalidBarSize(0, size));
        }
        if is_64bit {
            let address = align_up(self.mmio64, size)?;
            self.mmio64 = address.checked_add(size).ok_or(Error::AddressOverflow)?;
            Ok(address)
        } else {
            let address = align_up(self.mmio32, size)?;
            let end = address.checked_add(size).ok_or(Error::AddressOverflow)?;
            if end.saturating_sub(1) > PCI_MMIO32_END {
                return Err(Error::Mmio32Exhausted(size));
            }
            self.mmio32 = end;
            Ok(address)
        }
    }
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    let mask = alignment.checked_sub(1).ok_or(Error::AddressOverflow)?;
    value
        .checked_add(mask)
        .map(|aligned| aligned & !mask)
        .ok_or(Error::AddressOverflow)
}

#[derive(Clone, Default)]
struct MsixEntry {
    bytes: [u8; 16],
}

impl MsixEntry {
    fn message(&self) -> kvm_msi {
        kvm_msi {
            address_lo: u32::from_le_bytes(self.bytes[0..4].try_into().unwrap()),
            address_hi: u32::from_le_bytes(self.bytes[4..8].try_into().unwrap()),
            data: u32::from_le_bytes(self.bytes[8..12].try_into().unwrap()),
            ..Default::default()
        }
    }

    fn masked(&self) -> bool {
        u32::from_le_bytes(self.bytes[12..16].try_into().unwrap()) & 1 != 0
    }
}

struct MsixRuntime {
    entries: Vec<MsixEntry>,
    pending: Vec<bool>,
    enabled: bool,
    function_masked: bool,
}

struct InterruptWorker {
    stop: EventFd,
    thread: Option<JoinHandle<()>>,
}

impl InterruptWorker {
    fn start(vm: &VmFd, events: &[EventFd], runtime: Arc<Mutex<MsixRuntime>>) -> Result<Self> {
        let stop = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
        let stop_thread = stop.try_clone().map_err(Error::EventFd)?;
        let event_clones = events
            .iter()
            .map(EventFd::try_clone)
            .collect::<io::Result<Vec<_>>>()
            .map_err(Error::EventFd)?;
        let raw_vm = unsafe { libc::fcntl(vm.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if raw_vm < 0 {
            return Err(Error::File(io::Error::last_os_error()));
        }
        // SAFETY: raw_vm is a fresh descriptor owned by the worker thread.
        let vm_file = unsafe { File::from_raw_fd(raw_vm) };
        let thread = thread::Builder::new()
            .name("krun-vfio-msix".to_string())
            .spawn(move || interrupt_loop(vm_file, stop_thread, event_clones, runtime))
            .map_err(Error::Thread)?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for InterruptWorker {
    fn drop(&mut self) {
        let _ = self.stop.write(1);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn interrupt_loop(vm: File, stop: EventFd, events: Vec<EventFd>, runtime: Arc<Mutex<MsixRuntime>>) {
    let mut pollfds = Vec::with_capacity(events.len() + 1);
    pollfds.push(libc::pollfd {
        fd: stop.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    });
    pollfds.extend(events.iter().map(|event| libc::pollfd {
        fd: event.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }));

    loop {
        // SAFETY: pollfds points to initialized pollfd values for this call.
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, -1) };
        if ready <= 0 {
            if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if pollfds[0].revents & libc::POLLIN != 0 {
            let _ = stop.read();
            return;
        }
        for (index, event) in events.iter().enumerate() {
            if pollfds[index + 1].revents & libc::POLLIN == 0 {
                continue;
            }
            let _ = event.read();
            let message = {
                let mut state = runtime.lock().unwrap();
                if !state.enabled || state.function_masked || state.entries[index].masked() {
                    state.pending[index] = true;
                    None
                } else {
                    state.pending[index] = false;
                    Some(state.entries[index].message())
                }
            };
            if let Some(message) = message {
                // SAFETY: this is KVM_SIGNAL_MSI on a duplicated live VM fd.
                let result = unsafe { ioctl_with_ref(&vm, kvm_signal_msi(), &message) };
                if result < 0 {
                    error!(
                        "failed to inject VFIO MSI-X vector {index}: {}",
                        io::Error::last_os_error()
                    );
                }
            }
        }
    }
}

struct MsixState {
    cap_offset: usize,
    table_bar: u8,
    table_offset: u64,
    pba_bar: u8,
    pba_offset: u64,
    runtime: Arc<Mutex<MsixRuntime>>,
    events: Vec<EventFd>,
    _worker: InterruptWorker,
}

struct VfioPciDevice {
    vfio: Arc<VfioDevice>,
    config: Vec<u8>,
    bars: [Option<PciBar>; 6],
    bar_owner: [Option<(u8, bool)>; 6],
    probing: [bool; 6],
    msix: Option<MsixState>,
}

impl VfioPciDevice {
    fn new(vfio: VfioDevice, vm: &VmFd, allocator: &mut BarAllocator) -> Result<Self> {
        vfio.reset();
        let vfio = Arc::new(vfio);
        let config_size = vfio.get_region_size(VFIO_PCI_CONFIG_REGION_INDEX).min(4096) as usize;
        if config_size < 256 {
            return Err(Error::InvalidConfigSpace);
        }
        let mut config = vec![0_u8; config_size];
        vfio.region_read(VFIO_PCI_CONFIG_REGION_INDEX, &mut config, 0);
        let vendor = u16::from_le_bytes(config[0..2].try_into().unwrap());
        if vendor == 0 || vendor == u16::MAX {
            return Err(Error::InvalidConfigSpace);
        }

        let mut bars = [None; 6];
        let mut bar_owner = [None; 6];
        let mut bar = 0_u8;
        while bar < 6 {
            let offset = PCI_BAR0 + usize::from(bar) * 4;
            let raw = u32::from_le_bytes(config[offset..offset + 4].try_into().unwrap());
            let size = vfio.get_region_size(u32::from(bar));
            if size == 0 {
                bar += 1;
                continue;
            }
            if raw & 1 != 0 {
                return Err(Error::IoBarUnsupported(bar));
            }
            if !size.is_power_of_two() {
                return Err(Error::InvalidBarSize(bar, size));
            }
            let kind = (raw >> 1) & 0x3;
            let is_64bit = kind == 0x2;
            if kind != 0 && !is_64bit {
                return Err(Error::InvalidBarSize(bar, size));
            }
            if is_64bit && bar == 5 {
                return Err(Error::InvalidBarSize(bar, size));
            }
            let address = allocator.allocate(size, is_64bit)?;
            let pci_bar = PciBar {
                index: bar,
                address,
                size,
                flags: vfio.get_region_flags(u32::from(bar)),
                is_64bit,
                prefetchable: raw & 0x8 != 0,
            };
            bars[usize::from(bar)] = Some(pci_bar);
            bar_owner[usize::from(bar)] = Some((bar, false));
            write_bar_address(&vfio, &mut config, pci_bar);
            if is_64bit {
                bar_owner[usize::from(bar + 1)] = Some((bar, true));
                bar += 2;
            } else {
                bar += 1;
            }
        }

        let msix = parse_msix(&config)
            .map(|parsed| {
                let events = (0..parsed.vectors)
                    .map(|_| EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd))
                    .collect::<Result<Vec<_>>>()?;
                let runtime = Arc::new(Mutex::new(MsixRuntime {
                    entries: vec![MsixEntry::default(); parsed.vectors],
                    pending: vec![false; parsed.vectors],
                    enabled: false,
                    function_masked: true,
                }));
                let worker = InterruptWorker::start(vm, &events, Arc::clone(&runtime))?;
                Ok(MsixState {
                    cap_offset: parsed.cap_offset,
                    table_bar: parsed.table_bar,
                    table_offset: parsed.table_offset,
                    pba_bar: parsed.pba_bar,
                    pba_offset: parsed.pba_offset,
                    runtime,
                    events,
                    _worker: worker,
                })
            })
            .transpose()?;

        Ok(Self {
            vfio,
            config,
            bars,
            bar_owner,
            probing: [false; 6],
            msix,
        })
    }

    fn read_bar(&mut self, bar: u8, offset: u64, data: &mut [u8]) {
        if self.msix_read(bar, offset, data) {
            return;
        }
        let flags = self.bars[usize::from(bar)].map_or(0, |region| region.flags);
        if flags & VFIO_REGION_INFO_FLAG_READ != 0 {
            self.vfio.region_read(u32::from(bar), data, offset);
        } else {
            data.fill(0xff);
        }
    }

    fn write_bar(&mut self, bar: u8, offset: u64, data: &[u8]) {
        if self.msix_write(bar, offset, data) {
            return;
        }
        let flags = self.bars[usize::from(bar)].map_or(0, |region| region.flags);
        if flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
            self.vfio.region_write(u32::from(bar), data, offset);
        }
    }

    fn msix_read(&self, bar: u8, offset: u64, data: &mut [u8]) -> bool {
        let Some(msix) = &self.msix else { return false };
        let table_size =
            msix.runtime.lock().unwrap().entries.len() as u64 * PCI_MSIX_TABLE_ENTRY_SIZE;
        if bar == msix.table_bar
            && range_contains(msix.table_offset, table_size, offset, data.len())
        {
            let state = msix.runtime.lock().unwrap();
            let relative = (offset - msix.table_offset) as usize;
            for (position, byte) in data.iter_mut().enumerate() {
                let absolute = relative + position;
                *byte = state.entries[absolute / 16].bytes[absolute % 16];
            }
            return true;
        }
        let pba_size = (msix.runtime.lock().unwrap().entries.len().div_ceil(64) * 8) as u64;
        if bar == msix.pba_bar && range_contains(msix.pba_offset, pba_size, offset, data.len()) {
            data.fill(0);
            let state = msix.runtime.lock().unwrap();
            let relative = (offset - msix.pba_offset) as usize;
            for (vector, pending) in state.pending.iter().copied().enumerate() {
                if pending {
                    let byte = vector / 8;
                    if byte >= relative && byte < relative + data.len() {
                        data[byte - relative] |= 1 << (vector % 8);
                    }
                }
            }
            return true;
        }
        false
    }

    fn msix_write(&mut self, bar: u8, offset: u64, data: &[u8]) -> bool {
        let Some(msix) = &self.msix else { return false };
        let table_size =
            msix.runtime.lock().unwrap().entries.len() as u64 * PCI_MSIX_TABLE_ENTRY_SIZE;
        if bar != msix.table_bar
            || !range_contains(msix.table_offset, table_size, offset, data.len())
        {
            return bar == msix.pba_bar
                && range_contains(
                    msix.pba_offset,
                    (msix.runtime.lock().unwrap().entries.len().div_ceil(64) * 8) as u64,
                    offset,
                    data.len(),
                );
        }
        let relative = (offset - msix.table_offset) as usize;
        let mut kick = BTreeSet::new();
        {
            let mut state = msix.runtime.lock().unwrap();
            for (position, byte) in data.iter().copied().enumerate() {
                let absolute = relative + position;
                let vector = absolute / 16;
                let was_masked = state.entries[vector].masked();
                state.entries[vector].bytes[absolute % 16] = byte;
                if was_masked
                    && !state.entries[vector].masked()
                    && state.pending[vector]
                    && state.enabled
                    && !state.function_masked
                {
                    kick.insert(vector);
                }
            }
        }
        for vector in kick {
            let _ = msix.events[vector].write(1);
        }
        true
    }

    fn update_msix_control(&mut self, old: u16, new: u16) {
        let Some(msix) = &self.msix else { return };
        let was_enabled = old & PCI_MSIX_ENABLE != 0;
        let enabled = new & PCI_MSIX_ENABLE != 0;
        if enabled && !was_enabled {
            let event_refs = msix.events.iter().collect();
            if let Err(error) = self.vfio.enable_msix(event_refs) {
                error!("failed to enable VFIO MSI-X: {error}");
                let control = u16::from_le_bytes(
                    self.config[msix.cap_offset + 2..msix.cap_offset + 4]
                        .try_into()
                        .unwrap(),
                ) & !PCI_MSIX_ENABLE;
                self.config[msix.cap_offset + 2..msix.cap_offset + 4]
                    .copy_from_slice(&control.to_le_bytes());
                return;
            }
        } else if !enabled
            && was_enabled
            && let Err(error) = self.vfio.disable_msix()
        {
            warn!("failed to disable VFIO MSI-X: {error}");
        }
        let mut state = msix.runtime.lock().unwrap();
        state.enabled = enabled;
        state.function_masked = new & PCI_MSIX_FUNCTION_MASK != 0;
    }
}

impl PciFunction for VfioPciDevice {
    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        let mut config = self.config.clone();
        for register in 0..6 {
            let Some((owner, high)) = self.bar_owner[register] else {
                continue;
            };
            if !self.probing[usize::from(owner)] {
                continue;
            }
            let Some(bar) = self.bars[usize::from(owner)] else {
                continue;
            };
            let mask64 = !(bar.size - 1);
            let value = if high {
                (mask64 >> 32) as u32
            } else {
                (mask64 as u32 & 0xffff_fff0)
                    | if bar.is_64bit { 0x4 } else { 0 }
                    | if bar.prefetchable { 0x8 } else { 0 }
            };
            let bar_offset = PCI_BAR0 + register * 4;
            config[bar_offset..bar_offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        copy_config_read(&config, offset, data);
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        if offset
            .checked_add(data.len())
            .is_none_or(|end| end > self.config.len())
        {
            return;
        }
        let old_msix = self.msix.as_ref().map(|msix| {
            u16::from_le_bytes(
                self.config[msix.cap_offset + 2..msix.cap_offset + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        self.config[offset..offset + data.len()].copy_from_slice(data);

        let write_end = offset + data.len();
        for register in 0..6 {
            let bar_offset = PCI_BAR0 + register * 4;
            if offset <= bar_offset && write_end >= bar_offset + 4 {
                if let Some((owner, _)) = self.bar_owner[register] {
                    self.probing[usize::from(owner)] = data.len() == 4
                        && offset == bar_offset
                        && u32::from_le_bytes(data.try_into().unwrap()) == u32::MAX;
                    if !self.probing[usize::from(owner)]
                        && let Some(bar) = self.bars[usize::from(owner)]
                    {
                        write_bar_address(&self.vfio, &mut self.config, bar);
                    }
                }
                return;
            }
        }

        let msix_transition = if let (Some(msix), Some(old)) = (&self.msix, old_msix) {
            let control_offset = msix.cap_offset + 2;
            if offset < control_offset + 2 && write_end > control_offset {
                let new = u16::from_le_bytes(
                    self.config[control_offset..control_offset + 2]
                        .try_into()
                        .unwrap(),
                );
                Some((old, new))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((old, new)) = msix_transition
            && old & PCI_MSIX_ENABLE == 0
            && new & PCI_MSIX_ENABLE != 0
        {
            // Install VFIO eventfds before the physical function can emit MSI-X.
            self.update_msix_control(old, new);
        }

        self.vfio.region_write(
            VFIO_PCI_CONFIG_REGION_INDEX,
            &self.config[offset..write_end],
            offset as u64,
        );

        if let Some((old, new)) = msix_transition
            && !(old & PCI_MSIX_ENABLE == 0 && new & PCI_MSIX_ENABLE != 0)
        {
            // On disable, quiesce the physical function before tearing down eventfds.
            self.update_msix_control(old, new);
        }
    }

    fn set_multifunction(&mut self, multifunction: bool) {
        if multifunction {
            self.config[PCI_HEADER_TYPE] |= 0x80;
        } else {
            self.config[PCI_HEADER_TYPE] &= 0x7f;
        }
    }
}

impl Drop for VfioPciDevice {
    fn drop(&mut self) {
        if self.msix.is_some() {
            let _ = self.vfio.disable_msix();
        }
        self.vfio.reset();
    }
}

struct VfioBarDevice {
    function: Arc<Mutex<VfioPciDevice>>,
    bar: u8,
}

impl BusDevice for VfioBarDevice {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        self.function
            .lock()
            .unwrap()
            .read_bar(self.bar, offset, data);
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        self.function
            .lock()
            .unwrap()
            .write_bar(self.bar, offset, data);
    }
}

struct ParsedMsix {
    cap_offset: usize,
    vectors: usize,
    table_bar: u8,
    table_offset: u64,
    pba_bar: u8,
    pba_offset: u64,
}

fn parse_msix(config: &[u8]) -> Option<ParsedMsix> {
    let status = u16::from_le_bytes(config.get(6..8)?.try_into().ok()?);
    if status & PCI_STATUS_CAP_LIST == 0 {
        return None;
    }
    let mut offset = usize::from(*config.get(PCI_CAP_PTR)? & !0x3);
    let mut visited = BTreeSet::new();
    while offset >= 0x40 && offset + 12 <= config.len() && visited.insert(offset) {
        if config[offset] == PCI_CAP_ID_MSIX {
            let control = u16::from_le_bytes(config[offset + 2..offset + 4].try_into().ok()?);
            let table = u32::from_le_bytes(config[offset + 4..offset + 8].try_into().ok()?);
            let pba = u32::from_le_bytes(config[offset + 8..offset + 12].try_into().ok()?);
            return Some(ParsedMsix {
                cap_offset: offset,
                vectors: usize::from((control & 0x07ff) + 1),
                table_bar: (table & 0x7) as u8,
                table_offset: u64::from(table & !0x7),
                pba_bar: (pba & 0x7) as u8,
                pba_offset: u64::from(pba & !0x7),
            });
        }
        offset = usize::from(config[offset + 1] & !0x3);
    }
    None
}

fn write_bar_address(vfio: &VfioDevice, config: &mut [u8], bar: PciBar) {
    let offset = PCI_BAR0 + usize::from(bar.index) * 4;
    let low = (bar.address as u32 & 0xffff_fff0)
        | if bar.is_64bit { 0x4 } else { 0 }
        | if bar.prefetchable { 0x8 } else { 0 };
    config[offset..offset + 4].copy_from_slice(&low.to_le_bytes());
    vfio.region_write(
        VFIO_PCI_CONFIG_REGION_INDEX,
        &low.to_le_bytes(),
        offset as u64,
    );
    if bar.is_64bit {
        let high = (bar.address >> 32) as u32;
        config[offset + 4..offset + 8].copy_from_slice(&high.to_le_bytes());
        vfio.region_write(
            VFIO_PCI_CONFIG_REGION_INDEX,
            &high.to_le_bytes(),
            (offset + 4) as u64,
        );
    }
}

fn copy_config_read(config: &[u8], offset: usize, data: &mut [u8]) {
    data.fill(0xff);
    if let Some(source) = config.get(offset..offset.saturating_add(data.len())) {
        data.copy_from_slice(source);
    }
}

fn range_contains(base: u64, size: u64, offset: u64, length: usize) -> bool {
    offset >= base
        && offset
            .checked_add(length as u64)
            .is_some_and(|end| end <= base.saturating_add(size))
}

/// Creates one IOMMU address space for the VM and attaches all configured PCI
/// functions. The returned manager must live for the VM lifetime.
pub fn attach_devices(
    vm: &VmFd,
    memory: &GuestMemoryMmap,
    configs: &[VfioDeviceConfig],
    pio: &mut PortIODeviceManager,
    mmio: &mut MMIODeviceManager,
    confidential: bool,
) -> Result<Option<Arc<VfioDmaManager>>> {
    if configs.is_empty() {
        return Ok(None);
    }

    let mut kvm_device = kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
        fd: 0,
        flags: 0,
    };
    let kvm_vfio = vm
        .create_device(&mut kvm_device)
        .map_err(Error::KvmDevice)?;
    let duplicated = unsafe { libc::fcntl(kvm_vfio.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(Error::File(io::Error::last_os_error()));
    }
    // SAFETY: both kvm-ioctls versions wrap the same kernel device fd ABI;
    // `duplicated` is a fresh descriptor transferred to the 0.25 wrapper.
    let kvm_vfio = unsafe { kvm_ioctls_vfio::DeviceFd::from_raw_fd(duplicated) };
    let kvm_vfio = Arc::new(VfioDeviceFd::new_from_kvm(kvm_vfio));
    let iommufd = Arc::new(IommuFd::new().map_err(Error::Iommufd)?);
    let ops = Arc::new(VfioIommufd::new(iommufd, None, Some(kvm_vfio)).map_err(Error::Vfio)?);
    let dma = Arc::new(VfioDmaManager::new(Arc::clone(&ops)));
    if !confidential {
        dma.map_guest_memory(memory)?;
    }

    let mut allocator = BarAllocator::new(memory)?;
    let mut functions: BTreeMap<(u8, u8), Arc<Mutex<dyn PciFunction>>> = BTreeMap::new();
    functions.insert((0, 0), Arc::new(Mutex::new(HostBridge::new())));
    let mut concrete = Vec::with_capacity(configs.len());
    for config in configs {
        let key = (config.guest_device, config.guest_function);
        if functions.contains_key(&key) {
            return Err(Error::DuplicateBdf(key.0, key.1));
        }
        let file = config.device.try_clone().map_err(Error::File)?;
        let vfio = VfioDevice::new_from_fd(file, Arc::clone(&ops) as Arc<dyn VfioOps>)
            .map_err(Error::Vfio)?;
        let function = Arc::new(Mutex::new(VfioPciDevice::new(vfio, vm, &mut allocator)?));
        functions.insert(key, Arc::clone(&function) as Arc<Mutex<dyn PciFunction>>);
        concrete.push(function);
    }

    let multifunction_slots: BTreeSet<u8> = configs
        .iter()
        .filter(|candidate| {
            configs.iter().any(|other| {
                other.guest_device == candidate.guest_device
                    && other.guest_function != candidate.guest_function
            })
        })
        .map(|config| config.guest_device)
        .collect();
    for ((device, function), pci_function) in &functions {
        pci_function
            .lock()
            .unwrap()
            .set_multifunction(*function == 0 && multifunction_slots.contains(device));
    }

    for function in &concrete {
        let bars = function.lock().unwrap().bars;
        for bar in bars.into_iter().flatten() {
            mmio.bus
                .insert(
                    Arc::new(Mutex::new(VfioBarDevice {
                        function: Arc::clone(function),
                        bar: bar.index,
                    })),
                    bar.address,
                    bar.size,
                )
                .map_err(Error::Bus)?;
        }
    }
    pio.io_bus
        .insert(
            Arc::new(Mutex::new(PciConfigIo::new(functions))),
            PCI_CONFIG_ADDRESS,
            PCI_CONFIG_PORT_SIZE,
        )
        .map_err(Error::Bus)?;

    Ok(Some(dma))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFunction {
        config: [u8; 256],
    }

    impl PciFunction for TestFunction {
        fn read_config(&mut self, offset: usize, data: &mut [u8]) {
            copy_config_read(&self.config, offset, data);
        }

        fn write_config(&mut self, offset: usize, data: &[u8]) {
            self.config[offset..offset + data.len()].copy_from_slice(data);
        }

        fn set_multifunction(&mut self, multifunction: bool) {
            self.config[PCI_HEADER_TYPE] = u8::from(multifunction) << 7;
        }
    }

    #[test]
    fn config_mechanism_routes_multifunction_accesses() {
        let function = Arc::new(Mutex::new(TestFunction { config: [0; 256] }));
        function.lock().unwrap().config[0..4].copy_from_slice(&0x1234_10de_u32.to_le_bytes());
        let mut functions: BTreeMap<(u8, u8), Arc<Mutex<dyn PciFunction>>> = BTreeMap::new();
        functions.insert((3, 2), function);
        let mut config = PciConfigIo::new(functions);
        config.write(
            0,
            0,
            &(PCI_CONFIG_ENABLE | (3 << 11) | (2 << 8)).to_le_bytes(),
        );
        let mut value = [0_u8; 4];
        config.read(0, 4, &mut value);
        assert_eq!(u32::from_le_bytes(value), 0x1234_10de);
        config.write(0, 4, &0xabcd_10de_u32.to_le_bytes());
        config.read(0, 4, &mut value);
        assert_eq!(u32::from_le_bytes(value), 0xabcd_10de);
    }

    #[test]
    fn disabled_and_absent_config_reads_all_ones() {
        let mut config = PciConfigIo::new(BTreeMap::new());
        let mut value = [0_u8; 4];
        config.read(0, 4, &mut value);
        assert_eq!(value, [0xff; 4]);
        config.write(0, 0, &(PCI_CONFIG_ENABLE | (1 << 11)).to_le_bytes());
        config.read(0, 4, &mut value);
        assert_eq!(value, [0xff; 4]);
    }

    #[test]
    fn parses_msix_capability_and_stops_on_cycles() {
        let mut config = vec![0_u8; 256];
        config[6..8].copy_from_slice(&PCI_STATUS_CAP_LIST.to_le_bytes());
        config[PCI_CAP_PTR] = 0x50;
        config[0x50] = PCI_CAP_ID_MSIX;
        config[0x51] = 0x50;
        config[0x52..0x54].copy_from_slice(&7_u16.to_le_bytes());
        config[0x54..0x58].copy_from_slice(&0x2003_u32.to_le_bytes());
        config[0x58..0x5c].copy_from_slice(&0x3003_u32.to_le_bytes());
        let parsed = parse_msix(&config).unwrap();
        assert_eq!(parsed.vectors, 8);
        assert_eq!(parsed.table_bar, 3);
        assert_eq!(parsed.table_offset, 0x2000);
        assert_eq!(parsed.pba_offset, 0x3000);
    }

    #[test]
    fn allocates_large_64bit_bars_above_guest_ram() {
        let memory =
            GuestMemoryMmap::from_ranges(&[(vm_memory::GuestAddress(0), 1 << 30)]).unwrap();
        let mut allocator = BarAllocator::new(&memory).unwrap();
        let first = allocator.allocate(1 << 38, true).unwrap();
        let second = allocator.allocate(1 << 38, true).unwrap();
        assert!(first >= PCI_MMIO64_MIN);
        assert_eq!(first % (1 << 38), 0);
        assert_eq!(second, first + (1 << 38));
    }

    #[test]
    fn rejects_unaligned_dma_ranges() {
        assert!(validate_dma_range(1, PAGE_SIZE).is_err());
        assert!(validate_dma_range(0, PAGE_SIZE - 1).is_err());
        assert!(validate_dma_range(0, PAGE_SIZE).is_ok());
    }
}
