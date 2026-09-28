// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![cfg(target_arch = "x86_64")]

use std::fmt;
use std::sync::{Arc, Mutex};

use devices;
use utils::eventfd::EventFd;

#[cfg(windows)]
use devices::BusDevice;

/// Errors corresponding to the `PortIODeviceManager`.
#[derive(Debug)]
pub enum Error {
    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),
    /// Cannot create EventFd.
    EventFd(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            BusError(ref err) => write!(f, "Failed to add legacy device to Bus: {err}"),
            EventFd(ref err) => write!(f, "Failed to create EventFd: {err}"),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// The `PortIODeviceManager` is a wrapper that is used for registering legacy devices
/// on an I/O Bus. It currently manages the uart and i8042 devices.
/// The `LegacyDeviceManger` should be initialized only by using the constructor.
pub struct PortIODeviceManager {
    pub io_bus: devices::Bus,
    pub cmos: Arc<Mutex<devices::legacy::Cmos>>,
    pub stdio_serial: Vec<Arc<Mutex<devices::legacy::Serial>>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,
    #[cfg(windows)]
    pub pit: Arc<Mutex<devices::legacy::Pit>>,
    #[cfg(not(windows))]
    pub com_evt_1: EventFd,
    pub com_evt_2: EventFd,
    pub com_evt_3: EventFd,
    pub com_evt_4: EventFd,
    #[cfg(not(windows))]
    pub kbd_evt: EventFd,
}

#[cfg(windows)]
struct PcControlPorts {
    i8042: Arc<Mutex<devices::legacy::I8042Device>>,
    pit: Arc<Mutex<devices::legacy::Pit>>,
}

#[cfg(windows)]
impl BusDevice for PcControlPorts {
    fn read(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        match offset {
            0 | 4 => self.i8042.lock().unwrap().read(vcpuid, offset, data),
            1 if data.len() == 1 => data[0] = self.pit.lock().unwrap().read_speaker_port(),
            _ => {}
        }
    }

    fn write(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        match offset {
            0 | 4 => self.i8042.lock().unwrap().write(vcpuid, offset, data),
            1 if data.len() == 1 => self.pit.lock().unwrap().write_speaker_port(data[0]),
            _ => {}
        }
    }
}

impl PortIODeviceManager {
    /// Create a new DeviceManager handling legacy devices (uart, i8042).
    pub fn new(
        cmos: Arc<Mutex<devices::legacy::Cmos>>,
        stdio_serial: Vec<Arc<Mutex<devices::legacy::Serial>>>,
        i8042_reset_evfd: EventFd,
    ) -> Result<Self> {
        let io_bus = devices::Bus::new();
        let mut evts: Vec<EventFd> = Vec::new();
        for i in 0..4 {
            let com_evt = match stdio_serial.get(i) {
                Some(s) => s
                    .lock()
                    .unwrap()
                    .interrupt_evt()
                    .try_clone()
                    .map_err(Error::EventFd)?,
                None => EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?,
            };
            evts.push(com_evt);
        }

        let kbd_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;

        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            i8042_reset_evfd,
            kbd_evt.try_clone().map_err(Error::EventFd)?,
        )));

        #[cfg(windows)]
        let pit = {
            let pit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
            Arc::new(Mutex::new(devices::legacy::Pit::new(pit_evt)))
        };

        Ok(PortIODeviceManager {
            io_bus,
            cmos,
            stdio_serial,
            i8042,
            #[cfg(windows)]
            pit,
            #[cfg(not(windows))]
            com_evt_1: evts[0].try_clone().map_err(Error::EventFd)?,
            com_evt_2: evts[1].try_clone().map_err(Error::EventFd)?,
            com_evt_3: evts[2].try_clone().map_err(Error::EventFd)?,
            com_evt_4: evts[3].try_clone().map_err(Error::EventFd)?,
            #[cfg(not(windows))]
            kbd_evt,
        })
    }

    /// Register supported legacy devices.
    pub fn register_devices(&mut self) -> Result<()> {
        self.io_bus
            .insert(self.cmos.clone(), 0x70, 0x8)
            .map_err(Error::BusError)?;

        if let Some(serial) = self.stdio_serial.first() {
            self.io_bus
                .insert(serial.clone(), 0x3f8, 0x8)
                .map_err(Error::BusError)?;
        }
        #[cfg(windows)]
        self.io_bus
            .insert(self.pit.clone(), 0x40, 4)
            .map_err(Error::BusError)?;
        #[cfg(windows)]
        self.io_bus
            .insert(
                Arc::new(Mutex::new(PcControlPorts {
                    i8042: self.i8042.clone(),
                    pit: self.pit.clone(),
                })),
                0x60,
                5,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                self.stdio_serial
                    .get(1)
                    .unwrap_or(&Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                        self.com_evt_2.try_clone().map_err(Error::EventFd)?,
                    ))))
                    .clone(),
                0x2f8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                self.stdio_serial
                    .get(2)
                    .unwrap_or(&Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                        self.com_evt_3.try_clone().map_err(Error::EventFd)?,
                    ))))
                    .clone(),
                0x3e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                self.stdio_serial
                    .get(3)
                    .unwrap_or(&Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                        self.com_evt_4.try_clone().map_err(Error::EventFd)?,
                    ))))
                    .clone(),
                0x2e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        #[cfg(not(windows))]
        self.io_bus
            .insert(self.i8042.clone(), 0x060, 0x5)
            .map_err(Error::BusError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_legacy_devices() {
        let serial =
            devices::legacy::Serial::new_sink(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
        let cmos = devices::legacy::Cmos::new(0, 0);
        let ldm = PortIODeviceManager::new(
            Arc::new(Mutex::new(cmos)),
            vec![Arc::new(Mutex::new(serial))],
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        );
        assert!(ldm.is_ok());
        assert!(&ldm.unwrap().register_devices().is_ok());
    }

    #[test]
    fn test_debug_error() {
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "Failed to add legacy device to Bus: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::EventFd(std::io::Error::from_raw_os_error(1))),
            format!(
                "Failed to create EventFd: {}",
                std::io::Error::from_raw_os_error(1)
            )
        );
    }
}
