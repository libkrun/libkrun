// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! MMIO device manager for the Windows Hypervisor Platform backend.
//!
//! Mirrors `kvm/mmio.rs` (x86_64) but without KVM's `ioeventfd`/`irqfd`: WHP
//! traps every guest MMIO access into the vCPU run loop (so the notify-register
//! write reaches the bus directly, no ioeventfd), and device interrupts are
//! injected with `WhpVm::request_interrupt` rather than wired through an irqfd.
//!
//! The device→guest interrupt path is wired in `builder::attach_mmio_device`: a
//! per-device watcher thread waits on the device's `interrupt_evt` and raises the
//! IOAPIC line (`IrqChipDevice::set_irq`), which injects via `request_interrupt`.
//! Registration here records the IRQ line and places the device on the bus.

// Some manager methods (snapshot/restore/fork) are present for parity but not yet
// exercised on Windows; allow until the snapshot/fork path is ported.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

use devices::virtio::persist::{VmDevicesState, restore_device, snapshot_device};
use devices::{BusDevice, DeviceType};
use kernel::cmdline as kernel_cmdline;

/// Errors for the MMIO device manager.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum Error {
    /// Failed to create MmioTransport.
    CreateMmioTransport(devices::virtio::CreateMmioTransportError),
    /// Failed to perform an operation on the bus.
    BusError(devices::BusError),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// Failure in creating or cloning an event fd.
    EventFd(io::Error),
    /// No more IRQs are available.
    IrqsExhausted,
    /// The device couldn't be found.
    DeviceNotFound,
    /// Failed to update the mmio device.
    UpdateFailed,
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
            Error::DeviceNotFound => write!(f, "the device couldn't be found"),
            Error::UpdateFailed => write!(f, "failed to update the mmio device"),
        }
    }
}

impl From<devices::virtio::CreateMmioTransportError> for Error {
    fn from(e: devices::virtio::CreateMmioTransportError) -> Self {
        Self::CreateMmioTransport(e)
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// Size of the MMIO device window passed to the kernel cmdline (must exceed
/// 0x100 + the virtio config space; hardcoded to 4K like the other backends).
const MMIO_LEN: u64 = 0x1000;

/// Manages the complexities of registering an MMIO device on WHP.
pub struct MMIODeviceManager {
    pub bus: devices::Bus,
    mmio_base: u64,
    irq: u32,
    last_irq: u32,
    id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
    /// Handles to registered virtio devices, kept so checkpoint/fork can
    /// capture/restore their state without downcasting through the bus.
    virtio_devices: Vec<Arc<Mutex<dyn devices::virtio::VirtioDevice>>>,
    /// MMIO transports, kept so a restored clone can re-activate each device
    /// from saved queue state.
    mmio_transports: Vec<Arc<Mutex<devices::virtio::MmioTransport>>>,
}

impl MMIODeviceManager {
    /// Create a new device manager for MMIO virtio devices.
    pub fn new(mmio_base: &mut u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
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

    /// Register an MMIO IOAPIC device (places its window on the bus).
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

    /// Register an already-created MMIO device behind an MMIO transport.
    ///
    /// Unlike KVM there is no `register_ioevent`/`register_irqfd`: WHP traps the
    /// guest's notify-register write into the run loop (delivered to the bus),
    /// and the IRQ is injected via `WhpVm::request_interrupt`. See the
    /// `TODO(whp-host)` at the top of this file.
    pub fn register_mmio_device(
        &mut self,
        mut mmio_device: devices::virtio::MmioTransport,
        type_id: u32,
        device_id: String,
    ) -> Result<(u64, u32)> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        mmio_device.set_irq_line(self.irq);

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
    pub fn add_device_to_cmdline(
        &mut self,
        cmdline: &mut kernel_cmdline::Cmdline,
        mmio_base: u64,
        irq: u32,
    ) -> Result<()> {
        // virtio_mmio.device=<size>K@<baseaddr>:<irq>
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", MMIO_LEN / 1024, mmio_base, irq),
            )
            .map_err(Error::Cmdline)
    }

    /// Get the specified device off the bus.
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

    /// Grow the writable backing and signal the existing WHP config interrupt.
    /// The caller must serialize growth with snapshots and backing-layer pivots.
    #[cfg(feature = "blk")]
    pub(crate) fn grow_block_device(
        &self,
        id: &str,
        bytes: u64,
    ) -> std::result::Result<(), String> {
        let mut matched = None;
        for device in &self.virtio_devices {
            let guard = device.lock().expect("poisoned virtio device lock");
            let Some(block) = guard.as_any().downcast_ref::<devices::virtio::Block>() else {
                continue;
            };
            if block.id() == id {
                if matched.is_some() {
                    return Err(format!("multiple block devices have id '{id}'"));
                }
                matched = Some(Arc::clone(device));
            }
        }
        let device = matched.ok_or_else(|| format!("block '{id}' not found"))?;
        let mut guard = device.lock().expect("poisoned virtio device lock");
        let block = guard
            .as_mut_any()
            .downcast_mut::<devices::virtio::Block>()
            .expect("matched block device changed type");
        block
            .grow(bytes)
            .map_err(|error| format!("grow block '{id}': {error}"))
    }

    /// Capture the runtime state of every snapshot-supporting virtio device.
    pub fn snapshot_devices(&self) -> VmDevicesState {
        // Read transport status before locking devices, matching the restore
        // lock order. A completion can be pending at the checkpoint boundary
        // even after the device workers have been quiesced.
        let status_of: Vec<_> = self
            .mmio_transports
            .iter()
            .map(|transport| {
                let transport = transport.lock().expect("poisoned transport lock");
                (transport.device(), transport.interrupt_status())
            })
            .collect();
        let mut snapshots = Vec::new();
        let mut interrupt_status = Vec::new();
        for dev in &self.virtio_devices {
            let guard = dev.lock().expect("poisoned virtio device lock");
            if let Some(snap) = snapshot_device(&*guard) {
                snapshots.push(snap);
                interrupt_status.push(
                    status_of
                        .iter()
                        .find(|(device, _)| Arc::ptr_eq(device, dev))
                        .map_or(0, |(_, status)| *status),
                );
            }
        }
        VmDevicesState {
            devices: snapshots,
            interrupt_status,
        }
    }

    /// Re-activate devices on a freshly-built clone from a checkpoint.
    pub fn restore_activate_devices(
        &self,
        state: &VmDevicesState,
    ) -> std::result::Result<(), String> {
        let mut used = vec![false; self.mmio_transports.len()];
        for (index, snap) in state.devices.iter().enumerate() {
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
                restore_device(&mut *t.locked_device(), snap)?;
                t.restore_and_activate(&queue_states, acked)?;
                t.set_restored_interrupt_status(
                    state.interrupt_status.get(index).copied().unwrap_or(0),
                );
                t.locked_device().finish_restore_activation()?;
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

    /// Re-inject pending device IRQs only after the restored LAPIC state is in
    /// place. This also covers interrupts posted while devices re-activated.
    pub fn replay_restored_interrupts(&self) {
        for transport in &self.mmio_transports {
            transport
                .lock()
                .expect("poisoned transport lock")
                .replay_restored_interrupt();
        }
    }

    /// Quiesce every virtio device before snapshotting.
    pub fn quiesce_devices(&self) {
        for dev in &self.virtio_devices {
            dev.lock()
                .expect("poisoned virtio device lock")
                .quiesce_for_snapshot();
        }
    }

    /// Validate only after all workers have stopped, including after a previous
    /// failed attempt that left the devices quiesced.
    pub fn validate_snapshot_boundary(&self) -> std::result::Result<(), String> {
        for dev in &self.virtio_devices {
            let guard = dev.lock().expect("poisoned virtio device lock");
            if let Some(error) = guard.snapshot_error() {
                return Err(format!("{}: {error}", guard.device_name()));
            }
        }
        Ok(())
    }

    /// Re-arm every virtio device quiesced by [`Self::quiesce_devices`].
    pub fn rearm_devices(&self) {
        for dev in &self.virtio_devices {
            dev.lock()
                .expect("poisoned virtio device lock")
                .rearm_after_snapshot();
        }
    }

    /// Restore runtime state onto the existing quiesced devices.
    pub fn restore_devices(&self, state: &VmDevicesState) -> std::result::Result<(), String> {
        crate::device_manager::restore_devices_in_place(&self.mmio_transports, state)
    }
}

/// Information about an MMIO device registered at some bus address.
#[derive(Clone, Debug)]
pub struct MMIODeviceInfo {
    addr: u64,
    _irq: u32,
    _len: u64,
}
