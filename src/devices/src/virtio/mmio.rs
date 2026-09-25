// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::{Display, Formatter};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use super::device::{InterruptHandler, InterruptType, VirtioTransportState};
use super::*;
use crate::bus::BusDevice;
use crate::legacy::IrqChip;
use utils::{byte_order, eventfd::EventFd};
use vm_memory::{GuestAddress, GuestMemoryMmap};

//TODO crosvm uses 0 here, but IIRC virtio specified some other vendor id that should be used
const VENDOR_ID: u32 = 0;

//required by the virtio mmio device register layout at offset 0 from base
const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;

//current version specified by the mmio standard (legacy devices used 1 here)
const MMIO_VERSION: u32 = 2;

#[derive(Debug)]
pub enum CreateMmioTransportError {
    CreateInterruptEventFd(io::Error),
}

impl Display for CreateMmioTransportError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            CreateMmioTransportError::CreateInterruptEventFd(err) => {
                write!(f, "failed to create interrupt eventfd: {err}")
            }
        }
    }
}

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOTIFY_REG_OFFSET` offset from the MMIO
///    base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
///    is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioTransport {
    state: VirtioTransportState,
    shm_region_select: u32,
    interrupt: MmioInterrupt,
    device_interrupt: InterruptTransport,
}

struct MmioInterruptInner {
    log_target: String,
    status: AtomicUsize,
    event: EventFd,
    intc: IrqChip,
    irq_line: Mutex<Option<u32>>,
}

#[derive(Clone)]
struct MmioInterrupt(Arc<MmioInterruptInner>);

impl MmioInterrupt {
    fn new(intc: IrqChip, log_target: String) -> Result<Self, CreateMmioTransportError> {
        Ok(Self(Arc::new(MmioInterruptInner {
            log_target,
            status: AtomicUsize::new(0),
            event: EventFd::new(0).map_err(CreateMmioTransportError::CreateInterruptEventFd)?,
            intc,
            irq_line: Mutex::new(None),
        })))
    }

    fn device_interrupt(&self) -> InterruptTransport {
        InterruptTransport::from_handler(Arc::new(self.clone()))
    }

    fn status(&self) -> &AtomicUsize {
        &self.0.status
    }

    fn event(&self) -> &EventFd {
        &self.0.event
    }

    fn intc(&self) -> &IrqChip {
        &self.0.intc
    }

    fn irq_line(&self) -> Option<u32> {
        *self.0.irq_line.lock().unwrap()
    }

    fn set_irq_line(&mut self, irq_line: u32) {
        debug!(target: &self.0.log_target, "set_irq_line: {irq_line}");
        *self.0.irq_line.lock().unwrap() = Some(irq_line);
    }

    fn try_signal_status(&self, status: u32) -> Result<(), crate::Error> {
        self.status().fetch_or(status as usize, Ordering::SeqCst);
        self.intc()
            .lock()
            .unwrap()
            .set_irq(self.irq_line(), Some(&self.0.event))?;
        Ok(())
    }

    fn reset_status(&self) {
        self.status().store(0, Ordering::SeqCst);
    }

    fn signal_bus_interrupt(&self, irq_mask: u32) -> io::Result<()> {
        self.status().fetch_or(irq_mask as usize, Ordering::SeqCst);
        self.event().write(1)
    }
}

impl InterruptHandler for MmioInterrupt {
    fn try_signal(&self, interrupt: InterruptType) -> Result<(), crate::Error> {
        let (status, name) = match interrupt {
            InterruptType::UsedQueue => (VIRTIO_MMIO_INT_VRING, "signal_used_queue"),
            InterruptType::ConfigChange => (VIRTIO_MMIO_INT_CONFIG, "signal_config_change"),
        };
        debug!(target: &self.0.log_target, "interrupt: {name}");
        self.try_signal_status(status)
    }
}

impl InterruptTransport {
    pub fn new(intc: IrqChip, log_target: String) -> Result<Self, CreateMmioTransportError> {
        Ok(MmioInterrupt::new(intc, log_target)?.device_interrupt())
    }
}

impl MmioTransport {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(
        mem: GuestMemoryMmap,
        intc: IrqChip,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<MmioTransport, CreateMmioTransportError> {
        let device_name = device
            .try_lock()
            .expect("Mutex of VirtioDevice should not be locked when calling MmioTransport::new")
            .device_name()
            .to_string();
        let debug_log_target = format!("{}[{device_name}]", module_path!());
        let state = VirtioTransportState::new(mem, device)
            .map_err(CreateMmioTransportError::CreateInterruptEventFd)?;
        let interrupt = MmioInterrupt::new(intc, debug_log_target)?;
        let device_interrupt = interrupt.device_interrupt();

        Ok(MmioTransport {
            state,
            interrupt,
            device_interrupt,
            shm_region_select: 0,
        })
    }

    /// Set the irq line for the device.
    /// NOTE: Can only be called when the device is not activated
    pub fn set_irq_line(&mut self, irq_line: u32) {
        self.interrupt.set_irq_line(irq_line);
    }

    pub fn interrupt_evt(&self) -> &EventFd {
        self.interrupt.event()
    }

    pub fn locked_device(&self) -> MutexGuard<'_, dyn VirtioDevice + 'static> {
        self.state.locked_device()
    }

    // Gets the encapsulated VirtioDevice.
    pub fn device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.state.device()
    }

    /// Returns a reference to the queue eventfds. Used by the VMM to register
    /// queue notifications with KVM.
    pub fn queue_evts(&self) -> &[Arc<EventFd>] {
        self.state.queue_evts()
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.state.device_status & (set | clr) == set
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        self.state.with_queue_mut(self.state.queue_select, f)
    }

    fn update_queue_field<F: FnOnce(&mut Queue)>(&mut self, f: F) {
        if self.check_device_status(device_status::FEATURES_OK, device_status::FAILED) {
            // FIXME: check if activated!
            self.with_queue_mut(f);
        } else {
            warn!(
                "update virtio queue in invalid state 0x{:x}",
                self.state.device_status
            );
        }
    }

    /// Update device status according to the state machine defined by VirtIO Spec 1.0.
    /// Please refer to VirtIO Spec 1.0, section 2.1.1 and 3.1.1.
    ///
    /// The driver MUST update device status, setting bits to indicate the completed steps
    /// of the driver initialization sequence specified in 3.1. The driver MUST NOT clear
    /// a device status bit. If the driver sets the FAILED bit, the driver MUST later reset
    /// the device before attempting to re-initialize.
    fn set_device_status(&mut self, status: u32) {
        if self
            .state
            .set_device_status(status, self.device_interrupt.clone(), true)
        {
            self.interrupt.reset_status();
        }
    }
}

impl BusDevice for MmioTransport {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.locked_device().device_type(),
                    0x0c => VENDOR_ID, // vendor id
                    0x10 => {
                        let mut features = self
                            .locked_device()
                            .avail_features_by_page(self.state.features_select);
                        if self.state.features_select == 1 {
                            features |= 0x1; // enable support of VirtIO Version 1
                        }
                        features
                    }
                    0x34 => self.state.queue_max_size(self.state.queue_select) as u32,
                    0x44 => self
                        .state
                        .with_queue(self.state.queue_select, 0, |q| q.ready as u32),
                    0x60 => self.interrupt.status().load(Ordering::SeqCst) as u32,
                    0x70 => self.state.device_status,
                    0xfc => self.state.config_generation,
                    0xb0..=0xbc => {
                        // For no SHM region or invalid region the kernel looks for length of -1
                        let (shm_base, shm_len) = if self.shm_region_select > 1 {
                            (0, !0)
                        } else {
                            match self.locked_device().shm_region() {
                                Some(region) => (region.guest_addr, region.size as u64),
                                None => (0, !0),
                            }
                        };
                        match offset {
                            0xb0 => shm_len as u32,
                            0xb4 => (shm_len >> 32) as u32,
                            0xb8 => shm_base as u32,
                            0xbc => (shm_base >> 32) as u32,
                            _ => {
                                error!("invalid shm region offset");
                                0
                            }
                        }
                    }
                    _ => {
                        warn!("unknown virtio mmio register read: 0x{offset:x}");
                        return;
                    }
                };
                byte_order::write_le_u32(data, v);
            }
            0x100..=0xfff => self.locked_device().read_config(offset - 0x100, data),
            _ => {
                warn!(
                    "invalid virtio mmio read: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                match offset {
                    0x14 => self.state.features_select = v,
                    0x20 => {
                        if self.check_device_status(
                            device_status::DRIVER,
                            device_status::FEATURES_OK | device_status::FAILED,
                        ) {
                            self.locked_device()
                                .ack_features_by_page(self.state.acked_features_select, v);
                        } else {
                            warn!(
                                "ack virtio features in invalid state 0x{:x}",
                                self.state.device_status
                            );
                        }
                    }
                    0x24 => self.state.acked_features_select = v,
                    0x30 => self.state.queue_select = v,
                    0x38 => self.update_queue_field(|q| q.size = v as u16),
                    0x44 => self.update_queue_field(|q| q.ready = v == 1),
                    0x50 => {
                        // Queue notification - write to the eventfd for the specified queue.
                        if let Some(eventfd) = self.state.queue_evts().get(v as usize) {
                            eventfd.write(1).unwrap();
                        } else {
                            warn!("invalid queue index for notification: {v}");
                        }
                    }
                    0x64 => {
                        if self.check_device_status(device_status::DRIVER_OK, 0) {
                            self.interrupt
                                .status()
                                .fetch_and(!(v as usize), Ordering::SeqCst);
                        }
                    }
                    0x70 => self.set_device_status(v),
                    0x80 => self.update_queue_field(|q| lo(&mut q.desc_table, v)),
                    0x84 => self.update_queue_field(|q| hi(&mut q.desc_table, v)),
                    0x90 => self.update_queue_field(|q| lo(&mut q.avail_ring, v)),
                    0x94 => self.update_queue_field(|q| hi(&mut q.avail_ring, v)),
                    0xa0 => self.update_queue_field(|q| lo(&mut q.used_ring, v)),
                    0xa4 => self.update_queue_field(|q| hi(&mut q.used_ring, v)),
                    0xac => self.shm_region_select = v,
                    _ => {
                        warn!("unknown virtio mmio register write: 0x{offset:x}");
                    }
                }
            }
            0x100..=0xfff => {
                if self.check_device_status(device_status::DRIVER, device_status::FAILED) {
                    self.locked_device().write_config(offset - 0x100, data)
                } else {
                    warn!("can not write to device config data area before driver is ready");
                }
            }
            _ => {
                warn!(
                    "invalid virtio mmio write: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        }
    }

    fn interrupt(&self, irq_mask: u32) -> std::io::Result<()> {
        self.interrupt.signal_bus_interrupt(irq_mask)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use utils::byte_order::{read_le_u32, write_le_u32};

    use super::*;
    use crate::legacy::DummyIrqChip;
    use vm_memory::GuestMemoryMmap;

    static QUEUE_CONFIG: [QueueConfig; 2] = [QueueConfig::new(16), QueueConfig::new(32)];

    pub(crate) struct DummyDevice {
        acked_features: u64,
        avail_features: u64,
        device_activated: bool,
        config_bytes: [u8; 0xeff],
    }

    impl DummyDevice {
        pub(crate) fn new() -> Self {
            DummyDevice {
                acked_features: 0,
                avail_features: 0,
                device_activated: false,
                config_bytes: [0; 0xeff],
            }
        }

        fn set_avail_features(&mut self, avail_features: u64) {
            self.avail_features = avail_features;
        }
    }

    impl VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            123
        }

        fn device_name(&self) -> &str {
            "dummy"
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            data.copy_from_slice(&self.config_bytes[offset as usize..]);
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            for (i, item) in data.iter().enumerate() {
                self.config_bytes[offset as usize + i] = *item;
            }
        }

        fn avail_features(&self) -> u64 {
            self.avail_features
        }

        fn acked_features(&self) -> u64 {
            self.acked_features
        }

        fn set_acked_features(&mut self, acked_features: u64) {
            self.acked_features = acked_features;
        }

        fn queue_config(&self) -> &[QueueConfig] {
            &QUEUE_CONFIG
        }

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _interrupt: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            self.device_activated = true;
            Ok(())
        }

        fn is_activated(&self) -> bool {
            self.device_activated
        }
    }

    fn set_device_status(d: &mut MmioTransport, status: u32) {
        let mut buf = [0; 4];
        write_le_u32(&mut buf[..], status);
        d.write(0, 0x70, &buf[..]);
    }

    #[test]
    fn test_new() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let dummy = DummyDevice::new();
        let mut d =
            MmioTransport::new(m, DummyIrqChip::new().into(), Arc::new(Mutex::new(dummy))).unwrap();

        // We just make sure here that the implementation of a mmio device behaves as we expect,
        // given a known virtio device implementation (the dummy device).

        // Transport now owns the queue_evts.
        assert_eq!(d.queue_evts().len(), 2);

        d.state.queue_select = 0;
        assert_eq!(
            d.state
                .with_queue(d.state.queue_select, 0, Queue::get_max_size),
            16
        );
        assert!(d.with_queue_mut(|q| q.size = 16));
        assert_eq!(
            d.state.queues.as_ref().unwrap()[d.state.queue_select as usize].size,
            16
        );

        d.state.queue_select = 1;
        assert_eq!(
            d.state
                .with_queue(d.state.queue_select, 0, Queue::get_max_size),
            32
        );
        assert!(d.with_queue_mut(|q| q.size = 16));
        assert_eq!(
            d.state.queues.as_ref().unwrap()[d.state.queue_select as usize].size,
            16
        );

        d.state.queue_select = 2;
        assert_eq!(
            d.state
                .with_queue(d.state.queue_select, 0, Queue::get_max_size),
            0
        );
        assert!(!d.with_queue_mut(|q| q.size = 16));
    }

    #[test]
    fn interrupt_transport_forwards_notifications_to_mmio() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let transport = MmioTransport::new(
            mem,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
        )
        .unwrap();

        transport.device_interrupt.try_signal_used_queue().unwrap();
        assert_eq!(
            transport.interrupt.status().load(Ordering::SeqCst),
            VIRTIO_MMIO_INT_VRING as usize
        );

        transport
            .device_interrupt
            .try_signal_config_change()
            .unwrap();
        assert_eq!(
            transport.interrupt.status().load(Ordering::SeqCst),
            (VIRTIO_MMIO_INT_VRING | VIRTIO_MMIO_INT_CONFIG) as usize
        );
    }

    #[test]
    fn test_bus_device_read() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
        )
        .unwrap();

        let mut buf = vec![0xff, 0, 0xfe, 0];
        let buf_copy = buf.to_vec();

        // The following read shouldn't be valid, because the length of the buf is not 4.
        buf.push(0);
        d.read(0, 0, &mut buf[..]);
        assert_eq!(buf[..4], buf_copy[..]);

        // the length is ok again
        buf.pop();

        // Now we test that reading at various predefined offsets works as intended.

        d.read(0, 0, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), MMIO_MAGIC_VALUE);

        d.read(0, 0x04, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), MMIO_VERSION);

        d.read(0, 0x08, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), d.locked_device().device_type());

        d.read(0, 0x0c, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), VENDOR_ID);

        d.state.features_select = 0;
        d.read(0, 0x10, &mut buf[..]);
        assert_eq!(
            read_le_u32(&buf[..]),
            d.locked_device().avail_features_by_page(0)
        );

        d.state.features_select = 1;
        d.read(0, 0x10, &mut buf[..]);
        assert_eq!(
            read_le_u32(&buf[..]),
            d.locked_device().avail_features_by_page(0) | 0x1
        );

        d.read(0, 0x34, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 16);

        d.read(0, 0x44, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), false as u32);

        d.interrupt.status().store(111, Ordering::SeqCst);
        d.read(0, 0x60, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 111);

        d.read(0, 0x70, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 0);

        d.state.config_generation = 5;
        d.read(0, 0xfc, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 5);

        // This read shouldn't do anything, as it's past the readable generic registers, and
        // before the device specific configuration space. Btw, reads from the device specific
        // conf space are going to be tested a bit later, alongside writes.
        buf = buf_copy.to_vec();
        d.read(0, 0xfd, &mut buf[..]);
        assert_eq!(buf[..], buf_copy[..]);

        // Read from an invalid address in generic register range.
        d.read(0, 0xfb, &mut buf[..]);
        assert_eq!(buf[..], buf_copy[..]);

        // Read from an invalid length in generic register range.
        d.read(0, 0xfc, &mut buf[..3]);
        assert_eq!(buf[..], buf_copy[..]);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_bus_device_write() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let dummy_dev = Arc::new(Mutex::new(DummyDevice::new()));
        let mut d = MmioTransport::new(m, DummyIrqChip::new().into(), dummy_dev.clone()).unwrap();
        let mut buf = vec![0; 5];
        write_le_u32(&mut buf[..4], 1);

        // Nothing should happen, because the slice len > 4.
        d.state.features_select = 0;
        d.write(0, 0x14, &buf[..]);
        assert_eq!(d.state.features_select, 0);

        buf.pop();

        assert_eq!(d.state.device_status, device_status::INIT);
        set_device_status(&mut d, device_status::ACKNOWLEDGE);

        // Acking features in invalid state shouldn't take effect.
        assert_eq!(d.locked_device().acked_features(), 0x0);
        d.state.acked_features_select = 0x0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x0);

        // Write to device specific configuration space should be ignored before setting device_status::DRIVER
        let buf1 = vec![1; 0xeff];
        for i in (0..0xeff).rev() {
            let mut buf2 = vec![0; 0xeff];

            d.write(0, 0x100 + i as u64, &buf1[i..]);
            d.read(0, 0x100, &mut buf2[..]);

            for item in buf2.iter().take(0xeff) {
                assert_eq!(*item, 0);
            }
        }

        set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        assert_eq!(
            d.state.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        // now writes should work
        d.state.features_select = 0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x14, &buf[..]);
        assert_eq!(d.state.features_select, 1);

        // Test acknowledging features on bus.
        d.state.acked_features_select = 0;
        write_le_u32(&mut buf[..], 0x124);

        // Set the device available features in order to make acknowledging possible.
        dummy_dev.lock().unwrap().set_avail_features(0x124);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x124);

        d.state.acked_features_select = 0;
        write_le_u32(&mut buf[..], 2);
        d.write(0, 0x24, &buf[..]);
        assert_eq!(d.state.acked_features_select, 2);
        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );

        // Acking features in invalid state shouldn't take effect.
        assert_eq!(d.locked_device().acked_features(), 0x124);
        d.state.acked_features_select = 0x0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x124);

        // Setup queues
        d.state.queue_select = 0;
        write_le_u32(&mut buf[..], 3);
        d.write(0, 0x30, &buf[..]);
        assert_eq!(d.state.queue_select, 3);

        d.state.queue_select = 0;
        assert_eq!(d.state.queues.as_ref().unwrap()[0].size, 0);
        write_le_u32(&mut buf[..], 16);
        d.write(0, 0x38, &buf[..]);
        assert_eq!(d.state.queues.as_ref().unwrap()[0].size, 16);

        assert!(!d.state.queues.as_ref().unwrap()[0].ready);
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x44, &buf[..]);
        assert!(d.state.queues.as_ref().unwrap()[0].ready);

        assert_eq!(d.state.queues.as_ref().unwrap()[0].desc_table.0, 0);
        write_le_u32(&mut buf[..], 123);
        d.write(0, 0x80, &buf[..]);
        assert_eq!(d.state.queues.as_ref().unwrap()[0].desc_table.0, 123);
        d.write(0, 0x84, &buf[..]);
        assert_eq!(
            d.state.queues.as_ref().unwrap()[0].desc_table.0,
            123 + (123 << 32)
        );

        assert_eq!(d.state.queues.as_ref().unwrap()[0].avail_ring.0, 0);
        write_le_u32(&mut buf[..], 124);
        d.write(0, 0x90, &buf[..]);
        assert_eq!(d.state.queues.as_ref().unwrap()[0].avail_ring.0, 124);
        d.write(0, 0x94, &buf[..]);
        assert_eq!(
            d.state.queues.as_ref().unwrap()[0].avail_ring.0,
            124 + (124 << 32)
        );

        assert_eq!(d.state.queues.as_ref().unwrap()[0].used_ring.0, 0);
        write_le_u32(&mut buf[..], 125);
        d.write(0, 0xa0, &buf[..]);
        assert_eq!(d.state.queues.as_ref().unwrap()[0].used_ring.0, 125);
        d.write(0, 0xa4, &buf[..]);
        assert_eq!(
            d.state.queues.as_ref().unwrap()[0].used_ring.0,
            125 + (125 << 32)
        );

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );

        d.interrupt.status().store(0b10_1010, Ordering::Relaxed);
        write_le_u32(&mut buf[..], 0b111);
        d.write(0, 0x64, &buf[..]);
        assert_eq!(d.interrupt.status().load(Ordering::Relaxed), 0b10_1000);

        // Write to an invalid address in generic register range.
        write_le_u32(&mut buf[..], 0xf);
        d.state.config_generation = 0;
        d.write(0, 0xfb, &buf[..]);
        assert_eq!(d.state.config_generation, 0);

        // Write to an invalid length in generic register range.
        d.write(0, 0xfc, &buf[..2]);
        assert_eq!(d.state.config_generation, 0);

        // Here we test writes/read into/from the device specific configuration space.
        let buf1 = vec![1; 0xeff];
        for i in (0..0xeff).rev() {
            let mut buf2 = vec![0; 0xeff];

            d.write(0, 0x100 + i as u64, &buf1[i..]);
            d.read(0, 0x100, &mut buf2[..]);

            for item in buf2.iter().take(i) {
                assert_eq!(*item, 0);
            }

            assert_eq!(buf1[i..], buf2[i..]);
        }
    }

    #[test]
    fn test_bus_device_activate() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
        )
        .unwrap();

        assert!(!d.locked_device().is_activated());
        assert_eq!(d.state.device_status, device_status::INIT);

        set_device_status(&mut d, device_status::ACKNOWLEDGE);
        set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        assert_eq!(
            d.state.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        // invalid state transition should have no effect
        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.state.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );
        assert_eq!(
            d.state.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK
        );

        let mut buf = [0; 4];
        let queue_len = d.state.queues.as_ref().unwrap().len();
        for q in 0..queue_len {
            d.state.queue_select = q as u32;
            write_le_u32(&mut buf[..], 16);
            d.write(0, 0x38, &buf[..]);
            write_le_u32(&mut buf[..], 1);
            d.write(0, 0x44, &buf[..]);
        }
        assert!(!d.locked_device().is_activated());

        // Device should be ready for activation now.

        // A couple of invalid writes; will trigger warnings; shouldn't activate the device.
        d.write(0, 0xa8, &buf[..]);
        d.write(0, 0x1000, &buf[..]);
        assert!(!d.locked_device().is_activated());

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.state.device_status,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK
        );
        assert!(d.locked_device().is_activated());
    }

    fn activate_device(d: &mut MmioTransport) {
        set_device_status(d, device_status::ACKNOWLEDGE);
        set_device_status(d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        set_device_status(
            d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );

        // Setup queue data structures
        let mut buf = [0; 4];
        let queues_count = d.state.queues.as_ref().unwrap().len();
        for q in 0..queues_count {
            d.state.queue_select = q as u32;
            write_le_u32(&mut buf[..], 16);
            d.write(0, 0x38, &buf[..]);
            write_le_u32(&mut buf[..], 1);
            d.write(0, 0x44, &buf[..]);
        }
        assert!(!d.locked_device().is_activated());

        // Device should be ready for activation now.
        set_device_status(
            d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.state.device_status,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK
        );
        assert!(d.locked_device().is_activated());
    }

    #[test]
    fn test_bus_device_reset() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
        )
        .unwrap();
        let mut buf = [0; 4];

        assert!(!d.locked_device().is_activated());
        assert_eq!(d.state.device_status, 0);
        activate_device(&mut d);

        // Marking device as FAILED should not affect device_activated state
        write_le_u32(&mut buf[..], 0x8f);
        d.write(0, 0x70, &buf[..]);
        assert_eq!(d.state.device_status, 0x8f);
        assert!(d.locked_device().is_activated());

        // Nothing happens when backend driver doesn't support reset
        write_le_u32(&mut buf[..], 0x0);
        d.write(0, 0x70, &buf[..]);
        assert_eq!(d.state.device_status, 0x8f);
        assert!(d.locked_device().is_activated());
    }

    #[test]
    fn test_get_avail_features() {
        let dummy_dev = DummyDevice::new();
        assert_eq!(dummy_dev.avail_features(), dummy_dev.avail_features);
    }

    #[test]
    fn test_get_acked_features() {
        let dummy_dev = DummyDevice::new();
        assert_eq!(dummy_dev.acked_features(), dummy_dev.acked_features);
    }

    #[test]
    fn test_set_acked_features() {
        let mut dummy_dev = DummyDevice::new();

        assert_eq!(dummy_dev.acked_features(), 0);
        dummy_dev.set_acked_features(16);
        assert_eq!(dummy_dev.acked_features(), dummy_dev.acked_features);
    }

    #[test]
    fn test_ack_features_by_page() {
        let mut dummy_dev = DummyDevice::new();
        dummy_dev.set_acked_features(16);
        dummy_dev.set_avail_features(8);
        dummy_dev.ack_features_by_page(0, 8);
        assert_eq!(dummy_dev.acked_features(), 24);
    }
}
