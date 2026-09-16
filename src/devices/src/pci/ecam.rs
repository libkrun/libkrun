// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::BusDevice;

use super::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PciBdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciBdf {
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    pub fn ecam_offset(&self) -> u64 {
        (u64::from(self.bus) << 20)
            | (u64::from(self.device) << 15)
            | (u64::from(self.function) << 12)
    }
}

impl fmt::Display for PciBdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

pub trait PciDevice: BusDevice {
    fn bdf(&self) -> PciBdf;
    fn read_config(&self, offset: u16, data: &mut [u8]);
    fn write_config(&mut self, offset: u16, data: &[u8]);
    fn bar_address(&self) -> u64;
    fn bar_size(&self) -> u64;
}

pub struct PciBus {
    devices: HashMap<PciBdf, Arc<Mutex<dyn PciDevice + Send>>>,
    next_device: u8,
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}

impl PciBus {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            next_device: 1,
        }
    }

    pub fn allocate_bdf(&mut self) -> PciBdf {
        let bdf = PciBdf::new(0, self.next_device, 0);
        self.next_device += 1;
        bdf
    }

    pub fn add_device(&mut self, device: Arc<Mutex<dyn PciDevice + Send>>) -> PciBdf {
        let bdf = device.lock().unwrap().bdf();
        self.devices.insert(bdf, device);
        bdf
    }

    pub fn devices(&self) -> &HashMap<PciBdf, Arc<Mutex<dyn PciDevice + Send>>> {
        &self.devices
    }

    pub fn ecam_read(&self, ecam_offset: u64, data: &mut [u8]) {
        let (bdf, config_offset) = Self::decode_ecam(ecam_offset);
        let found = self.devices.contains_key(&bdf);
        if let Some(device) = self.devices.get(&bdf) {
            device.lock().unwrap().read_config(config_offset, data);
        } else {
            data.fill(0xff);
        }
        trace::ecam_access(&bdf, config_offset, false, data, found);
    }

    pub fn ecam_write(&mut self, ecam_offset: u64, data: &[u8]) {
        let (bdf, config_offset) = Self::decode_ecam(ecam_offset);
        let found = self.devices.contains_key(&bdf);
        trace::ecam_access(&bdf, config_offset, true, data, found);
        if let Some(device) = self.devices.get(&bdf) {
            device.lock().unwrap().write_config(config_offset, data);
        }
    }

    fn decode_ecam(ecam_offset: u64) -> (PciBdf, u16) {
        let bus = ((ecam_offset >> 20) & 0xff) as u8;
        let device = ((ecam_offset >> 15) & 0x1f) as u8;
        let function = ((ecam_offset >> 12) & 0x7) as u8;
        let offset = (ecam_offset & 0xfff) as u16;
        (PciBdf::new(bus, device, function), offset)
    }
}

pub struct PciEcam {
    pub bus: Arc<Mutex<PciBus>>,
}

impl PciEcam {
    pub fn new(bus: Arc<Mutex<PciBus>>) -> Self {
        Self { bus }
    }
}

impl BusDevice for PciEcam {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        self.bus.lock().unwrap().ecam_read(offset, data);
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        self.bus.lock().unwrap().ecam_write(offset, data);
    }
}
