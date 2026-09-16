// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use utils::byte_order;
use vm_memory::GuestAddress;

use super::VirtioDevice;
use super::queue::Queue;

pub const VIRTQ_MSI_NO_VECTOR: u16 = 0xffff;

const DS_INIT: u8 = 0;
const DS_ACKNOWLEDGE: u8 = 1;
const DS_DRIVER: u8 = 2;
const DS_FEATURES_OK: u8 = 8;
const DS_DRIVER_OK: u8 = 4;
const DS_FAILED: u8 = 128;

const DEVICE_FEATURE_SELECT: u64 = 0x00;
const DEVICE_FEATURE: u64 = 0x04;
const DRIVER_FEATURE_SELECT: u64 = 0x08;
const DRIVER_FEATURE: u64 = 0x0c;
const MSIX_CONFIG: u64 = 0x10;
const NUM_QUEUES: u64 = 0x12;
pub(crate) const DEVICE_STATUS: u64 = 0x14;
const CONFIG_GENERATION: u64 = 0x15;
const QUEUE_SELECT: u64 = 0x16;
const QUEUE_SIZE: u64 = 0x18;
const QUEUE_MSIX_VECTOR: u64 = 0x1a;
const QUEUE_ENABLE: u64 = 0x1c;
const QUEUE_NOTIFY_OFF: u64 = 0x1e;
const QUEUE_DESC_LO: u64 = 0x20;
const QUEUE_DESC_HI: u64 = 0x24;
const QUEUE_AVAIL_LO: u64 = 0x28;
const QUEUE_AVAIL_HI: u64 = 0x2c;
const QUEUE_USED_LO: u64 = 0x30;
const QUEUE_USED_HI: u64 = 0x34;

pub enum PciCommonAction {
    Activate,
    Reset,
}

pub struct VirtioPciCommonConfig {
    pub driver_status: u8,
    pub config_generation: u8,
    pub device_feature_select: u32,
    pub driver_feature_select: u32,
    pub queue_select: u16,
    pub msix_config: Arc<AtomicU16>,
    pub msix_queues: Arc<Mutex<Vec<u16>>>,
}

impl VirtioPciCommonConfig {
    pub fn new(num_queues: usize) -> Self {
        Self {
            driver_status: DS_INIT,
            config_generation: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            queue_select: 0,
            msix_config: Arc::new(AtomicU16::new(VIRTQ_MSI_NO_VECTOR)),
            msix_queues: Arc::new(Mutex::new(vec![VIRTQ_MSI_NO_VECTOR; num_queues])),
        }
    }

    pub fn read(&self, offset: u64, data: &mut [u8], queues: &[Queue], device: &dyn VirtioDevice) {
        self.read_inner(offset, data, queues, queues.len(), device);
    }

    /// Common-config reads after the queues have been handed to the device.
    pub fn read_activated(
        &self,
        offset: u64,
        data: &mut [u8],
        num_queues: usize,
        device: &dyn VirtioDevice,
    ) {
        self.read_inner(offset, data, &[], num_queues, device);
    }

    fn read_inner(
        &self,
        offset: u64,
        data: &mut [u8],
        queues: &[Queue],
        num_queues: usize,
        device: &dyn VirtioDevice,
    ) {
        match data.len() {
            1 => {
                let v = match offset {
                    DEVICE_STATUS => self.driver_status,
                    CONFIG_GENERATION => self.config_generation,
                    _ => 0,
                };
                data[0] = v;
            }
            2 => {
                let v = match offset {
                    MSIX_CONFIG => self.msix_config.load(Ordering::Acquire),
                    NUM_QUEUES => num_queues as u16,
                    QUEUE_SELECT => self.queue_select,
                    QUEUE_SIZE => {
                        // Until the driver programs size, report the queue maximum.
                        self.queue_field(queues, |q| {
                            if q.size == 0 {
                                q.get_max_size()
                            } else {
                                q.size
                            }
                        })
                        .unwrap_or(0)
                    }
                    QUEUE_MSIX_VECTOR => self
                        .msix_queues
                        .lock()
                        .unwrap()
                        .get(self.queue_select as usize)
                        .copied()
                        .unwrap_or(VIRTQ_MSI_NO_VECTOR),
                    QUEUE_ENABLE => {
                        u16::from(self.queue_field(queues, |q| q.ready).unwrap_or(false))
                    }
                    QUEUE_NOTIFY_OFF => self.queue_select,
                    _ => 0,
                };
                byte_order::write_le_u16(data, v);
            }
            4 => {
                let v = match offset {
                    DEVICE_FEATURE_SELECT => self.device_feature_select,
                    DEVICE_FEATURE => match self.device_feature_select {
                        select if select < 2 => {
                            ((device.avail_features() >> (select * 32)) & 0xffff_ffff) as u32
                        }
                        _ => 0,
                    },
                    DRIVER_FEATURE_SELECT => self.driver_feature_select,
                    DRIVER_FEATURE => match self.driver_feature_select {
                        select if select < 2 => {
                            ((device.acked_features() >> (select * 32)) & 0xffff_ffff) as u32
                        }
                        _ => 0,
                    },
                    QUEUE_DESC_LO => self
                        .queue_field(queues, |q| (q.desc_table.0 & 0xffff_ffff) as u32)
                        .unwrap_or(0),
                    QUEUE_DESC_HI => self
                        .queue_field(queues, |q| (q.desc_table.0 >> 32) as u32)
                        .unwrap_or(0),
                    QUEUE_AVAIL_LO => self
                        .queue_field(queues, |q| (q.avail_ring.0 & 0xffff_ffff) as u32)
                        .unwrap_or(0),
                    QUEUE_AVAIL_HI => self
                        .queue_field(queues, |q| (q.avail_ring.0 >> 32) as u32)
                        .unwrap_or(0),
                    QUEUE_USED_LO => self
                        .queue_field(queues, |q| (q.used_ring.0 & 0xffff_ffff) as u32)
                        .unwrap_or(0),
                    QUEUE_USED_HI => self
                        .queue_field(queues, |q| (q.used_ring.0 >> 32) as u32)
                        .unwrap_or(0),
                    _ => 0,
                };
                byte_order::write_le_u32(data, v);
            }
            _ => data.fill(0),
        }
    }

    pub fn write(
        &mut self,
        offset: u64,
        data: &[u8],
        queues: &mut [Queue],
        device: &mut dyn VirtioDevice,
        device_activated: bool,
    ) -> Option<PciCommonAction> {
        match data.len() {
            1 if offset == DEVICE_STATUS => {
                return self.set_device_status(data[0], device_activated, queues, device);
            }
            2 => {
                let value = byte_order::read_le_u16(data);
                match offset {
                    MSIX_CONFIG => {
                        let nr_vectors = self.msix_queues.lock().unwrap().len() + 1;
                        if (value as usize) < nr_vectors {
                            self.msix_config.store(value, Ordering::Release);
                        } else {
                            self.msix_config
                                .store(VIRTQ_MSI_NO_VECTOR, Ordering::Release);
                        }
                    }
                    QUEUE_SELECT => self.queue_select = value,
                    QUEUE_SIZE => self.update_queue_field(queues, |q| q.size = value),
                    QUEUE_MSIX_VECTOR => {
                        let nr_vectors = self.msix_queues.lock().unwrap().len() + 1;
                        if let Some(queue) = self
                            .msix_queues
                            .lock()
                            .unwrap()
                            .get_mut(self.queue_select as usize)
                        {
                            *queue = if (value as usize) < nr_vectors {
                                value
                            } else {
                                VIRTQ_MSI_NO_VECTOR
                            };
                        }
                    }
                    QUEUE_ENABLE => {
                        self.update_queue_field(queues, |q| q.ready = value == 1);
                    }
                    _ => {}
                }
            }
            4 => {
                let value = byte_order::read_le_u32(data);
                match offset {
                    DEVICE_FEATURE_SELECT => self.device_feature_select = value,
                    DRIVER_FEATURE_SELECT => self.driver_feature_select = value,
                    DRIVER_FEATURE if self.driver_status == DS_ACKNOWLEDGE | DS_DRIVER => {
                        device.ack_features_by_page(self.driver_feature_select, value);
                    }
                    QUEUE_DESC_LO => self.update_queue_field(queues, |q| {
                        q.desc_table = GuestAddress(
                            (q.desc_table.0 & 0xffff_ffff_0000_0000) | u64::from(value),
                        )
                    }),
                    QUEUE_DESC_HI => self.update_queue_field(queues, |q| {
                        q.desc_table =
                            GuestAddress((q.desc_table.0 & 0xffff_ffff) | (u64::from(value) << 32))
                    }),
                    QUEUE_AVAIL_LO => self.update_queue_field(queues, |q| {
                        q.avail_ring = GuestAddress(
                            (q.avail_ring.0 & 0xffff_ffff_0000_0000) | u64::from(value),
                        )
                    }),
                    QUEUE_AVAIL_HI => self.update_queue_field(queues, |q| {
                        q.avail_ring =
                            GuestAddress((q.avail_ring.0 & 0xffff_ffff) | (u64::from(value) << 32))
                    }),
                    QUEUE_USED_LO => self.update_queue_field(queues, |q| {
                        q.used_ring =
                            GuestAddress((q.used_ring.0 & 0xffff_ffff_0000_0000) | u64::from(value))
                    }),
                    QUEUE_USED_HI => self.update_queue_field(queues, |q| {
                        q.used_ring =
                            GuestAddress((q.used_ring.0 & 0xffff_ffff) | (u64::from(value) << 32))
                    }),
                    _ => {}
                }
            }
            _ => {}
        }
        None
    }

    pub fn reset_state(&mut self) {
        self.driver_status = DS_INIT;
        self.config_generation = self.config_generation.wrapping_add(1);
        self.device_feature_select = 0;
        self.driver_feature_select = 0;
        self.queue_select = 0;
        self.msix_config
            .store(VIRTQ_MSI_NO_VECTOR, Ordering::Release);
        for vector in self.msix_queues.lock().unwrap().iter_mut() {
            *vector = VIRTQ_MSI_NO_VECTOR;
        }
    }

    pub fn mark_failed(&mut self) {
        self.driver_status |= DS_FAILED;
    }

    fn set_device_status(
        &mut self,
        status: u8,
        device_activated: bool,
        _queues: &mut [Queue],
        _device: &mut dyn VirtioDevice,
    ) -> Option<PciCommonAction> {
        const VALID_TRANSITIONS: &[(u8, u8)] = &[
            (DS_INIT, DS_ACKNOWLEDGE),
            (DS_ACKNOWLEDGE, DS_ACKNOWLEDGE | DS_DRIVER),
            (
                DS_ACKNOWLEDGE | DS_DRIVER,
                DS_ACKNOWLEDGE | DS_DRIVER | DS_FEATURES_OK,
            ),
            (
                DS_ACKNOWLEDGE | DS_DRIVER | DS_FEATURES_OK,
                DS_ACKNOWLEDGE | DS_DRIVER | DS_FEATURES_OK | DS_DRIVER_OK,
            ),
        ];

        if (status & DS_FAILED) != 0 {
            self.driver_status |= DS_FAILED;
            return None;
        }

        if status == DS_INIT {
            self.driver_status = DS_INIT;
            return Some(PciCommonAction::Reset);
        }

        for &(from, to) in VALID_TRANSITIONS {
            if self.driver_status == from && status == to && !device_activated {
                self.driver_status = status;
                if to == DS_ACKNOWLEDGE | DS_DRIVER | DS_FEATURES_OK | DS_DRIVER_OK {
                    return Some(PciCommonAction::Activate);
                }
                return None;
            }
        }

        None
    }

    fn update_queue_field<F: FnOnce(&mut Queue)>(&mut self, queues: &mut [Queue], f: F) {
        let status = self.driver_status;
        if status == DS_ACKNOWLEDGE | DS_DRIVER | DS_FEATURES_OK {
            self.queue_field_mut(queues, f);
        }
    }

    fn queue_field<T, F: FnOnce(&Queue) -> T>(&self, queues: &[Queue], f: F) -> Option<T> {
        queues.get(self.queue_select as usize).map(f)
    }

    fn queue_field_mut<F: FnOnce(&mut Queue)>(&mut self, queues: &mut [Queue], f: F) {
        if let Some(q) = queues.get_mut(self.queue_select as usize) {
            f(q);
        }
    }
}
