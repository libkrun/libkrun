// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Goldfish virtual platform RTC

use std::io;
use std::time::Instant;

use crate::BusDevice;
use crate::legacy::IrqChip;
use utils::byte_order;

// See drivers/rtc/rtc-goldfish.c and clocksource/timer-goldfish.h.
const TIME_LOW: u64 = 0x00;
const TIME_HIGH: u64 = 0x04;
const ALARM_LOW: u64 = 0x08;
const ALARM_HIGH: u64 = 0x0c;
const IRQ_ENABLED: u64 = 0x10;
const CLEAR_ALARM: u64 = 0x14;
const ALARM_STATUS: u64 = 0x18;
const CLEAR_INTERRUPT: u64 = 0x1c;

/// A RTC device following the Goldfish virtual platform specification.
pub struct GoldfishRtc {
    // This is used only for duration measuring purposes.
    previous_now: Instant,
    // Nanoseconds since the epoch at `previous_now`.
    tick_offset: i128,
    // High half of the last `TIME_LOW` read, returned by a subsequent
    // `TIME_HIGH` read (see the kernel driver: it reads TIME_LOW then
    // TIME_HIGH to assemble a 64-bit nanosecond timestamp).
    time_high: u32,
    alarm: u64,
    alarm_enabled: bool,
    irq_pending: bool,
    intc: Option<IrqChip>,
    irq_line: Option<u32>,
}

impl GoldfishRtc {
    pub fn new() -> GoldfishRtc {
        GoldfishRtc {
            previous_now: Instant::now(),
            tick_offset: utils::time::get_time(utils::time::ClockType::Real) as i128,
            time_high: 0,
            alarm: 0,
            alarm_enabled: false,
            irq_pending: false,
            intc: None,
            irq_line: None,
        }
    }

    pub fn set_intc(&mut self, intc: IrqChip) {
        self.intc = Some(intc);
    }

    pub fn set_irq_line(&mut self, irq: u32) {
        self.irq_line = Some(irq);
    }

    fn now_ns(&self) -> u64 {
        let ts =
            self.tick_offset + Instant::now().duration_since(self.previous_now).as_nanos() as i128;
        ts as u64
    }

    fn update_irq(&mut self) -> io::Result<()> {
        let Some(intc) = &self.intc else {
            return Ok(());
        };
        let intc = intc.lock().unwrap();
        let res = if self.irq_pending {
            intc.set_irq(self.irq_line, None)
        } else {
            intc.clear_irq(self.irq_line)
        };
        res.map_err(|e| io::Error::other(format!("{e:?}")))
    }

    fn handle_read(&mut self, offset: u64) -> u32 {
        match offset {
            TIME_LOW => {
                let now = self.now_ns();
                self.time_high = (now >> 32) as u32;
                now as u32
            }
            TIME_HIGH => self.time_high,
            ALARM_LOW => self.alarm as u32,
            ALARM_HIGH => (self.alarm >> 32) as u32,
            ALARM_STATUS => u32::from(self.alarm_enabled),
            _ => 0,
        }
    }

    fn handle_write(&mut self, offset: u64, val: u32, high: u32) -> io::Result<()> {
        match offset {
            TIME_LOW => {
                let now = (u64::from(high) << 32) | u64::from(val);
                self.previous_now = Instant::now();
                self.tick_offset = now as i128;
            }
            ALARM_LOW => {
                self.alarm = (u64::from(high) << 32) | u64::from(val);
            }
            IRQ_ENABLED => {
                self.alarm_enabled = val != 0;
            }
            CLEAR_ALARM => {
                self.alarm_enabled = false;
            }
            CLEAR_INTERRUPT => {
                self.irq_pending = false;
                self.update_irq()?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl Default for GoldfishRtc {
    fn default() -> Self {
        Self::new()
    }
}

impl BusDevice for GoldfishRtc {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 4 {
            warn!(
                "Invalid goldfish-rtc read: offset {}, data length {}",
                offset,
                data.len()
            );
            return;
        }
        let v = self.handle_read(offset);
        byte_order::write_le_u32(data, v);
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 4 {
            warn!(
                "Invalid goldfish-rtc write: offset {}, data length {}",
                offset,
                data.len()
            );
            return;
        }
        let v = byte_order::read_le_u32(data);
        // ALARM_HIGH/TIME_HIGH writes stage the upper 32 bits for the
        // following ALARM_LOW/TIME_LOW write, matching the kernel driver's
        // write order (it always writes the HIGH half first).
        let high = match offset {
            TIME_HIGH | ALARM_HIGH => {
                self.time_high = v;
                return;
            }
            _ => self.time_high,
        };
        if let Err(e) = self.handle_write(offset, v, high) {
            warn!("Failed to write to goldfish-rtc device: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;

    #[test]
    fn test_goldfish_rtc_read_write_and_event() {
        let mut rtc = GoldfishRtc::new();
        rtc.set_intc(DummyIrqChip::new().into());
        rtc.set_irq_line(0);
        let mut data = [0; 4];

        // TIME_LOW should reflect roughly "now" in nanoseconds; just check
        // it's non-zero and TIME_HIGH gets populated as a side effect.
        rtc.read(0, TIME_LOW, &mut data);
        let low = byte_order::read_le_u32(&data[..]);
        rtc.read(0, TIME_HIGH, &mut data);
        let high = byte_order::read_le_u32(&data[..]);
        assert!(low != 0 || high != 0);

        // Write and read back an alarm value.
        byte_order::write_le_u32(&mut data, 0x1234);
        rtc.write(0, ALARM_HIGH, &mut data);
        byte_order::write_le_u32(&mut data, 0x5678);
        rtc.write(0, ALARM_LOW, &mut data);
        rtc.read(0, ALARM_LOW, &mut data);
        assert_eq!(byte_order::read_le_u32(&data[..]), 0x5678);
        rtc.read(0, ALARM_HIGH, &mut data);
        assert_eq!(byte_order::read_le_u32(&data[..]), 0x1234);

        // Enabling the alarm interrupt and signaling it should raise, then
        // clearing it should lower, the interrupt line (exercised via the
        // DummyIrqChip no-op backend; we're only checking this doesn't
        // panic/error here).
        byte_order::write_le_u32(&mut data, 1);
        rtc.write(0, IRQ_ENABLED, &mut data);
        rtc.irq_pending = true;
        rtc.update_irq().unwrap();

        byte_order::write_le_u32(&mut data, 0);
        rtc.write(0, CLEAR_INTERRUPT, &mut data);
        rtc.read(0, ALARM_STATUS, &mut data);
    }
}
