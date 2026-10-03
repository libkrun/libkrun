// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Minimal hardware-reduced ACPI sleep registers for guest S5 poweroff requests.

use utils::eventfd::EventFd;

use crate::bus::BusDevice;

const SLP_TYP_MASK: u8 = 0x1c;
const SLP_EN: u8 = 1 << 5;
const SLP_TYP_S5: u8 = 0;

pub struct AcpiPm {
    sleep_control: u8,
    sleep_status: u8,
    exit_evt: EventFd,
}

impl AcpiPm {
    pub fn new(exit_evt: EventFd) -> Self {
        Self {
            sleep_control: 0,
            sleep_status: 0,
            exit_evt,
        }
    }
}

impl BusDevice for AcpiPm {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if offset > 1 || data.len() > 2 - offset as usize {
            return;
        }

        for (index, byte) in data.iter_mut().enumerate() {
            *byte = match offset + index as u64 {
                0 => self.sleep_control,
                1 => self.sleep_status,
                _ => return,
            };
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if offset > 1 || data.len() > 2 - offset as usize {
            return;
        }

        for (index, byte) in data.iter().enumerate() {
            match offset + index as u64 {
                0 => {
                    self.sleep_control = *byte;
                    if self.sleep_control & SLP_EN != 0
                        && self.sleep_control & SLP_TYP_MASK == SLP_TYP_S5
                    {
                        if let Err(e) = self.exit_evt.write(1) {
                            error!("failed to signal ACPI S5 shutdown: {e}");
                        }
                    }
                }
                1 => self.sleep_status &= !byte,
                _ => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::eventfd::EFD_NONBLOCK;

    #[test]
    fn s5_poweroff_signals_exit_event() {
        let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut pm = AcpiPm::new(exit_evt.try_clone().unwrap());

        pm.write(0, 0, &[SLP_EN]);

        assert_eq!(exit_evt.read().unwrap(), 1);
    }

    #[test]
    fn non_s5_sleep_type_does_not_signal_exit_event() {
        let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut pm = AcpiPm::new(exit_evt.try_clone().unwrap());

        pm.write(0, 0, &[SLP_EN | (1 << 2)]);

        assert!(exit_evt.read().is_err());
    }

    #[test]
    fn sleep_status_write_does_not_signal_exit_event() {
        let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut pm = AcpiPm::new(exit_evt.try_clone().unwrap());

        pm.write(0, 1, &[SLP_EN]);

        assert!(exit_evt.read().is_err());
    }

    #[test]
    fn out_of_bounds_accesses_do_not_partially_apply() {
        let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut pm = AcpiPm::new(exit_evt.try_clone().unwrap());
        let mut data = [0xaa; 3];

        pm.read(0, 0, &mut data);
        pm.write(0, 0, &[SLP_EN, 0, 0]);

        assert_eq!(data, [0xaa; 3]);
        assert!(exit_evt.read().is_err());
    }
}
