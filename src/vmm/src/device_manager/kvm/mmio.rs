// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use devices::fdt::DeviceInfoForFDT;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use devices::legacy::IrqChip;
use devices::virtio::persist::{VmDevicesState, restore_device, snapshot_device};
use devices::{BusDevice, DeviceType};
use kernel::cmdline as kernel_cmdline;
use kvm_ioctls::{IoEventAddress, VmFd};
#[cfg(target_arch = "aarch64")]
use utils::eventfd::EventFd;

#[cfg(all(feature = "blk", target_arch = "x86_64"))]
pub(crate) struct BlockPivotSpec {
    pub id: String,
    pub path: String,
    pub format: devices::virtio::block::ImageType,
}

#[cfg(all(feature = "blk", target_arch = "x86_64"))]
pub(crate) struct BlockPivotsRollback {
    pivots: Vec<(
        Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
        devices::virtio::block::device::DiskPivotRollback,
    )>,
}

/// Errors for MMIO device manager.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum Error {
    /// Failed to create MmioTransport
    CreateMmioTransport(devices::virtio::CreateMmioTransportError),
    /// Failed to perform an operation on the bus.
    BusError(devices::BusError),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// Failure in creating or cloning an event fd.
    EventFd(io::Error),
    /// No more IRQs are available.
    IrqsExhausted,
    /// Registering an IO Event failed.
    RegisterIoEvent(kvm_ioctls::Error),
    /// Registering an IRQ FD failed.
    RegisterIrqFd(kvm_ioctls::Error),
    /// The device couldn't be found
    DeviceNotFound,
    /// Failed to update the mmio device.
    UpdateFailed,
    /// Failed to create vhost-user device.
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    VhostUserDevice(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CreateMmioTransport(ref e) => {
                write!(f, "failed to create mmio transport for the device {e}")
            }
            Error::BusError(ref e) => write!(f, "failed to perform bus operation: {e}"),
            Error::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {e}")
            }
            Error::EventFd(ref e) => write!(f, "failed to create or clone event descriptor: {e}"),
            Error::IrqsExhausted => write!(f, "no more IRQs are available"),
            Error::RegisterIoEvent(ref e) => write!(f, "failed to register IO event: {e}"),
            Error::RegisterIrqFd(ref e) => write!(f, "failed to register irqfd: {e}"),
            Error::DeviceNotFound => write!(f, "the device couldn't be found"),
            Error::UpdateFailed => write!(f, "failed to update the mmio device"),
            #[cfg(all(feature = "vhost-user", target_os = "linux"))]
            Error::VhostUserDevice(ref e) => write!(f, "failed to create vhost-user device: {e}"),
        }
    }
}

impl From<devices::virtio::CreateMmioTransportError> for Error {
    fn from(e: devices::virtio::CreateMmioTransportError) -> Self {
        Self::CreateMmioTransport(e)
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// This represents the size of the mmio device specified to the kernel as a cmdline option
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K.
const MMIO_LEN: u64 = 0x1000;

/// Manages the complexities of registering a MMIO device.
pub struct MMIODeviceManager {
    pub bus: devices::Bus,
    mmio_base: u64,
    irq: u32,
    last_irq: u32,
    id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
    /// Handles to the registered virtio devices, kept so checkpoint/fork can
    /// capture/restore their state without downcasting through the bus's
    /// `dyn BusDevice` (which the `AsAny`/`'static` rules make awkward).
    virtio_devices: Vec<Arc<Mutex<dyn devices::virtio::VirtioDevice>>>,
    /// MMIO transports, kept so a restored clone can re-activate each device
    /// from saved queue state (the guest won't redo the virtio handshake).
    mmio_transports: Vec<Arc<Mutex<devices::virtio::MmioTransport>>>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new(mmio_base: &mut u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
        if cfg!(any(target_arch = "aarch64", target_arch = "riscv64")) {
            *mmio_base += MMIO_LEN;
        }
        MMIODeviceManager {
            mmio_base: *mmio_base,
            irq: irq_interval.0,
            last_irq: irq_interval.1,
            bus: devices::Bus::new(),
            id_to_dev_info: HashMap::new(),
            virtio_devices: Vec::new(),
            mmio_transports: Vec::new(),
        }
    }

    /// Register a MMIO IOAPIC device.
    #[cfg(target_arch = "x86_64")]
    pub fn register_mmio_ioapic(
        &mut self,
        intc: Option<Arc<Mutex<devices::legacy::IrqChipDevice>>>,
    ) -> Result<()> {
        if let Some(intc) = intc {
            let (addr, size) = {
                let intc = intc.lock().unwrap();
                (intc.get_mmio_addr(), intc.get_mmio_size())
            };
            self.bus.insert(intc, addr, size).map_err(Error::BusError)?;
        }

        Ok(())
    }

    /// Register an already created MMIO device to be used via MMIO transport.
    pub fn register_mmio_device(
        &mut self,
        vm: &VmFd,
        mut mmio_device: devices::virtio::MmioTransport,
        type_id: u32,
        device_id: String,
    ) -> Result<(u64, u32)> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(
                self.mmio_base + u64::from(devices::virtio::NOTIFY_REG_OFFSET),
            );

            vm.register_ioevent(queue_evt, &io_addr, i as u32)
                .map_err(Error::RegisterIoEvent)?;
        }

        vm.register_irqfd(mmio_device.interrupt_evt(), self.irq)
            .map_err(Error::RegisterIrqFd)?;

        mmio_device.set_irq_line(self.irq);

        // Track the underlying virtio device + transport for checkpoint/fork
        // (the transport is what re-activates the device from saved state).
        self.virtio_devices.push(mmio_device.device());
        let transport = Arc::new(Mutex::new(mmio_device));
        self.mmio_transports.push(transport.clone());

        self.bus
            .insert(transport, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        let ret = (self.mmio_base, self.irq);
        self.id_to_dev_info.insert(
            (DeviceType::Virtio(type_id), device_id),
            MMIODeviceInfo {
                addr: self.mmio_base,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );
        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(ret)
    }

    /// Append a registered MMIO device to the kernel cmdline.
    #[cfg(target_arch = "x86_64")]
    pub fn add_device_to_cmdline(
        &mut self,
        cmdline: &mut kernel_cmdline::Cmdline,
        mmio_base: u64,
        irq: u32,
    ) -> Result<()> {
        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", MMIO_LEN / 1024, mmio_base, irq),
            )
            .map_err(Error::Cmdline)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Register an early console at some MMIO address.
    pub fn register_mmio_serial(
        &mut self,
        vm: &VmFd,
        cmdline: &mut kernel_cmdline::Cmdline,
        intc: IrqChip,
        serial: Arc<Mutex<devices::legacy::Serial>>,
    ) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        vm.register_irqfd(serial.lock().unwrap().interrupt_evt(), self.irq)
            .map_err(Error::RegisterIrqFd)?;

        {
            let mut serial = serial.lock().unwrap();
            serial.set_intc(intc);
            serial.set_irq_line(self.irq);
        }

        self.bus
            .insert(serial, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        cmdline
            .insert(
                "earlycon",
                #[cfg(target_arch = "aarch64")]
                &format!("pl011,mmio32,0x{:08x}", self.mmio_base),
                #[cfg(target_arch = "riscv64")]
                &format!("uart,mmio,0x{:08x}", self.mmio_base),
            )
            .map_err(Error::Cmdline)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Serial, DeviceType::Serial.to_string()),
            MMIODeviceInfo {
                addr: ret,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO RTC device.
    pub fn register_mmio_rtc(&mut self, vm: &VmFd) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        // Attaching the RTC device.
        let rtc_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let device = devices::legacy::RTC::new(rtc_evt.try_clone().map_err(Error::EventFd)?);
        vm.register_irqfd(&rtc_evt, self.irq)
            .map_err(Error::RegisterIrqFd)?;

        self.bus
            .insert(Arc::new(Mutex::new(device)), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::RTC, "rtc".to_string()),
            MMIODeviceInfo {
                addr: ret,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MMIODeviceInfo> {
        &self.id_to_dev_info
    }

    /// Gets the the specified device.
    pub fn get_device(
        &self,
        device_type: DeviceType,
        device_id: &str,
    ) -> Option<&Mutex<dyn BusDevice>> {
        if let Some(dev_info) = self
            .id_to_dev_info
            .get(&(device_type, device_id.to_string()))
            && let Some((_, device)) = self.bus.get_device(dev_info.addr)
        {
            return Some(device);
        }
        None
    }

    /// Capture the runtime state of every snapshot-supporting virtio device
    /// for VM checkpoint/fork, aggregating per-device snapshots via
    /// [`VmDevicesState::capture`]. Iterates the device handles kept at
    /// registration; not-yet-supported device types are skipped.
    pub fn snapshot_devices(&self) -> VmDevicesState {
        let mut snapshots = Vec::new();
        for dev in &self.virtio_devices {
            let guard = dev.lock().expect("poisoned virtio device lock");
            if let Some(snap) = snapshot_device(&*guard) {
                snapshots.push(snap);
            }
        }
        VmDevicesState { devices: snapshots }
    }

    /// Re-activate devices on a freshly-built clone from a checkpoint: for each
    /// saved device snapshot, find a not-yet-consumed transport of the matching
    /// device type and re-activate it from the saved queue state + features
    /// (bypassing the guest handshake). Used by restore-into-a-fresh-VM (fork).
    /// Errors if a snapshot has no matching transport.
    pub fn restore_activate_devices(
        &self,
        state: &VmDevicesState,
    ) -> std::result::Result<(), String> {
        let mut used = vec![false; self.mmio_transports.len()];
        for snap in &state.devices {
            let want = snap.device_type();
            let queue_states = snap.queue_states();
            let acked = snap.acked_features();
            let mut applied = false;
            for (i, transport) in self.mmio_transports.iter().enumerate() {
                if used[i] {
                    continue;
                }
                let mut t = transport.lock().expect("poisoned transport lock");
                if t.locked_device().device_type() != want {
                    continue;
                }
                // Restore device-level runtime state (e.g. the virtiofs FUSE
                // inode/handle maps) onto the not-yet-activated device first, so
                // the subsequent `activate` rebuilds its worker from that state.
                restore_device(&mut *t.locked_device(), snap)?;
                t.restore_and_activate(&queue_states, acked)?;
                // Devices that defer worker startup past `activate` (the console
                // starts each port's worker only on the guest's PORT_OPEN, which
                // a restored guest never re-sends) restart their workers here.
                t.locked_device().finish_restore_activation();
                used[i] = true;
                applied = true;
                break;
            }
            if !applied {
                return Err(format!(
                    "no matching transport to restore device type {want}"
                ));
            }
        }
        Ok(())
    }

    /// Quiesce every virtio device to a clean boundary before snapshotting
    /// (drains block/net workers + reclaims their queues). Call with vCPUs
    /// already paused. Pair with [`Self::rearm_devices`].
    pub fn quiesce_devices(&self) {
        for dev in &self.virtio_devices {
            dev.lock()
                .expect("poisoned virtio device lock")
                .quiesce_for_snapshot();
        }
    }

    /// Re-arm every virtio device quiesced by [`Self::quiesce_devices`]
    /// (restarts block/net workers from their current/restored queue indices).
    pub fn rearm_devices(&self) {
        for dev in &self.virtio_devices {
            dev.lock()
                .expect("poisoned virtio device lock")
                .rearm_after_snapshot();
        }
    }

    /// Replace every requested quiesced block device as one transaction.
    ///
    /// All images are opened and validated before the first device changes.
    /// The returned old backings stay live until the caller either drops the
    /// token after committing the RAM generation or explicitly rolls back.
    #[cfg(all(feature = "blk", target_arch = "x86_64"))]
    pub(crate) fn pivot_block_devices(
        &self,
        specs: &[BlockPivotSpec],
    ) -> std::result::Result<BlockPivotsRollback, String> {
        use std::collections::HashSet;

        let mut requested = HashSet::with_capacity(specs.len());
        let mut prepared = Vec::with_capacity(specs.len());
        for spec in specs {
            if !requested.insert(spec.id.as_str()) {
                return Err(format!("duplicate block pivot id '{}'", spec.id));
            }
            let mut matched = None;
            for device in &self.virtio_devices {
                let guard = device.lock().expect("poisoned virtio device lock");
                let Some(block) = guard.as_any().downcast_ref::<devices::virtio::Block>() else {
                    continue;
                };
                if block.id() != &spec.id {
                    continue;
                }
                if matched.is_some() {
                    return Err(format!("multiple block devices have id '{}'", spec.id));
                }
                let pivot = block
                    .prepare_live_disk_pivot(&spec.path, spec.format)
                    .map_err(|error| format!("prepare block '{}': {error}", spec.id))?;
                matched = Some((Arc::clone(device), pivot));
            }
            prepared.push(matched.ok_or_else(|| format!("block '{}' not found", spec.id))?);
        }

        let mut applied = Vec::with_capacity(prepared.len());
        for (device, prepared) in prepared {
            let apply = {
                let mut guard = device.lock().expect("poisoned virtio device lock");
                let block = guard
                    .as_mut_any()
                    .downcast_mut::<devices::virtio::Block>()
                    .expect("prepared block device changed type");
                block.apply_live_disk_pivot(prepared)
            };
            match apply {
                Ok(rollback) => applied.push((device, rollback)),
                Err(error) => {
                    let rollback = BlockPivotsRollback { pivots: applied };
                    let rollback_error = self.rollback_block_pivots(rollback).err();
                    return Err(match rollback_error {
                        Some(rollback_error) => {
                            format!("apply block pivot: {error}; rollback: {rollback_error}")
                        }
                        None => format!("apply block pivot: {error}"),
                    });
                }
            }
        }
        Ok(BlockPivotsRollback { pivots: applied })
    }

    #[cfg(all(feature = "blk", target_arch = "x86_64"))]
    pub(crate) fn rollback_block_pivots(
        &self,
        rollback: BlockPivotsRollback,
    ) -> std::result::Result<(), String> {
        let mut errors = Vec::new();
        for (device, rollback) in rollback.pivots.into_iter().rev() {
            let mut guard = device.lock().expect("poisoned virtio device lock");
            let block = guard
                .as_mut_any()
                .downcast_mut::<devices::virtio::Block>()
                .expect("pivoted block device changed type");
            if let Err(error) = block.rollback_live_disk_pivot(rollback) {
                errors.push(format!("block '{}': {error}", block.id()));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join(", "))
        }
    }

    /// Restore device runtime state captured by [`Self::snapshot_devices`] onto
    /// the (freshly-constructed, not-yet-activated) devices. Each snapshot is
    /// applied to the device of the matching type (the first whose
    /// `restore_device` accepts it). Errors if a snapshot matches no device.
    pub fn restore_devices(&self, state: &VmDevicesState) -> std::result::Result<(), String> {
        for snap in &state.devices {
            let mut applied = false;
            for dev in &self.virtio_devices {
                let mut guard = dev.lock().expect("poisoned virtio device lock");
                if restore_device(&mut *guard, snap).is_ok() {
                    applied = true;
                    break;
                }
            }
            if !applied {
                return Err(format!("no matching device to restore snapshot {snap:?}"));
            }
        }
        Ok(())
    }
}

/// Private structure for storing information about the MMIO device registered at some address on the bus.
#[derive(Clone, Debug)]
pub struct MMIODeviceInfo {
    addr: u64,
    _irq: u32,
    _len: u64,
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self._irq
    }
    fn length(&self) -> u64 {
        self._len
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::builder;
    use super::*;
    use arch;
    use devices::legacy::DummyIrqChip;
    #[cfg(target_arch = "aarch64")]
    use devices::legacy::KvmGicV3;
    #[cfg(target_arch = "x86_64")]
    use devices::legacy::KvmIoapic;
    use devices::virtio::{
        ActivateResult, DeviceQueue, InterruptTransport, QueueConfig, VirtioDevice,
    };
    use std::sync::Arc;
    use utils::errno;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const QUEUE_CONFIG: &[QueueConfig] = &[QueueConfig::new(64)];

    impl MMIODeviceManager {
        fn register_virtio_device(
            &mut self,
            vm: &VmFd,
            guest_mem: GuestMemoryMmap,
            device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
            _cmdline: &mut kernel_cmdline::Cmdline,
            type_id: u32,
            device_id: &str,
        ) -> Result<u64> {
            self.virtio_devices.push(device.clone());
            let mmio_device =
                devices::virtio::MmioTransport::new(guest_mem, DummyIrqChip::new().into(), device)
                    .unwrap();
            let (mmio_base, _irq) =
                self.register_mmio_device(vm, mmio_device, type_id, device_id.to_string())?;
            #[cfg(target_arch = "x86_64")]
            self.add_device_to_cmdline(_cmdline, mmio_base, _irq)?;
            Ok(mmio_base)
        }
    }

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice { dummy: 0 }
        }
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            0
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

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let _ = offset;
            let _ = data;
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let _ = offset;
            let _ = data;
        }

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

    #[test]
    fn test_register_virtio_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        assert!(
            device_manager
                .register_virtio_device(vm.fd(), guest_mem, dummy, &mut cmdline, 0, "dummy")
                .is_ok()
        );
    }

    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);

        for _i in arch::IRQ_BASE..=arch::IRQ_MAX {
            device_manager
                .register_virtio_device(
                    vm.fd(),
                    guest_mem.clone(),
                    Arc::new(Mutex::new(DummyDevice::new())),
                    &mut cmdline,
                    0,
                    "dummy1",
                )
                .unwrap();
        }
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .register_virtio_device(
                        vm.fd(),
                        guest_mem,
                        Arc::new(Mutex::new(DummyDevice::new())),
                        &mut cmdline,
                        0,
                        "dummy2"
                    )
                    .unwrap_err()
            ),
            "no more IRQs are available".to_string()
        );
    }

    #[test]
    fn test_dummy_device() {
        let dummy = DummyDevice::new();
        assert_eq!(dummy.device_type(), 0);
        assert_eq!(dummy.queue_config().len(), QUEUE_CONFIG.len());
    }

    #[test]
    fn test_error_messages() {
        let device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let e = Error::Cmdline(
            cmdline
                .insert(
                    "virtio_mmio=device",
                    &format!(
                        "{}K@0x{:08x}:{}",
                        MMIO_LEN / 1024,
                        device_manager.mmio_base,
                        device_manager.irq
                    ),
                )
                .unwrap_err(),
        );
        assert_eq!(
            format!("{e}"),
            format!(
                "unable to add device to kernel command line: {}",
                kernel_cmdline::Error::HasEquals
            ),
        );
        assert_eq!(
            format!("{}", Error::UpdateFailed),
            "failed to update the mmio device"
        );
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "failed to perform bus operation: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::IrqsExhausted),
            "no more IRQs are available"
        );
        assert_eq!(
            format!("{}", Error::RegisterIoEvent(errno::Error::new(0))),
            format!("failed to register IO event: {}", errno::Error::new(0))
        );
        assert_eq!(
            format!("{}", Error::RegisterIrqFd(errno::Error::new(0))),
            format!("failed to register irqfd: {}", errno::Error::new(0))
        );
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = 0;
        let id = String::from("foo");
        if let Ok(addr) = device_manager.register_virtio_device(
            vm.fd(),
            guest_mem,
            dummy,
            &mut cmdline,
            type_id,
            &id,
        ) {
            assert!(
                device_manager
                    .get_device(DeviceType::Virtio(type_id), &id)
                    .is_some()
            );
            assert_eq!(
                addr,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].addr
            );
            assert_eq!(
                arch::IRQ_BASE,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())]._irq
            );
        }
        let id = "bar";
        assert!(
            device_manager
                .get_device(DeviceType::Virtio(type_id), id)
                .is_none()
        );
    }
}
