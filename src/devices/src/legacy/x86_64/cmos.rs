// Copyright 2025 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;
#[cfg(target_os = "windows")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bus::BusDevice;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;

#[cfg(target_os = "windows")]
fn bcd(value: u64) -> u8 {
    ((value / 10) << 4 | value % 10) as u8
}

#[cfg(target_os = "windows")]
fn rtc_data(index: u8, epoch_secs: u64) -> Option<u8> {
    let days = (epoch_secs / 86_400) as i64;
    let seconds_of_day = epoch_secs % 86_400;

    // Convert days since the Unix epoch to a proleptic Gregorian date.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    match index {
        0x00 => Some(bcd(seconds_of_day % 60)),
        0x02 => Some(bcd((seconds_of_day / 60) % 60)),
        0x04 => Some(bcd(seconds_of_day / 3_600)),
        0x06 => Some(bcd(((days + 4).rem_euclid(7) + 1) as u64)),
        0x07 => Some(bcd(day as u64)),
        0x08 => Some(bcd(month as u64)),
        0x09 => Some(bcd((year % 100) as u64)),
        0x0a => Some(0x26), // Oscillator enabled, no update in progress.
        0x0b => Some(0x02), // 24-hour, BCD mode.
        0x0c => Some(0),
        0x0d => Some(0x80), // RTC has valid power.
        0x32 => Some(bcd((year / 100) as u64)),
        _ => None,
    }
}

pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
}

impl Cmos {
    pub fn new(mem_below_4g: u64, mem_above_4g: u64) -> Cmos {
        debug!("cmos: mem_below_4g={mem_below_4g} mem_above_4g={mem_above_4g}");

        let mut data = [0u8; DATA_LEN];

        // Extended memory from 16 MB to 4 GB in units of 64 KB
        let ext_mem = min(
            0xFFFF,
            mem_below_4g.saturating_sub(16 * 1024 * 1024) / (64 * 1024),
        );
        data[0x34] = ext_mem as u8;
        data[0x35] = (ext_mem >> 8) as u8;

        // High memory (> 4GB) in units of 64 KB
        let high_mem = min(0xFFFFFF, mem_above_4g / (64 * 1024));
        data[0x5b] = high_mem as u8;
        data[0x5c] = (high_mem >> 8) as u8;
        data[0x5d] = (high_mem >> 16) as u8;

        Cmos { index: 0, data }
    }
}

impl BusDevice for Cmos {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported read length");
            return;
        }

        data[0] = match offset {
            INDEX_OFFSET => {
                debug!("cmos: read index offset");
                self.index
            }
            DATA_OFFSET => {
                debug!("cmos: read data offset from index={:x}", self.index);
                let index = self.index & INDEX_MASK;
                #[cfg(target_os = "windows")]
                {
                    let epoch_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    rtc_data(index, epoch_secs).unwrap_or(self.data[index as usize])
                }
                #[cfg(not(target_os = "windows"))]
                {
                    self.data[index as usize]
                }
            }
            _ => {
                debug!("cmos: unsupported read offset");
                0
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported write length");
            return;
        }

        match offset {
            INDEX_OFFSET => {
                debug!("cmos: update index");
                self.index = data[0] & INDEX_MASK;
            }
            _ => debug!("cmos: ignoring unsupported write to CMOS"),
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn rtc_reports_unix_epoch() {
        assert_eq!(rtc_data(0x00, 0), Some(0x00));
        assert_eq!(rtc_data(0x04, 0), Some(0x00));
        assert_eq!(rtc_data(0x06, 0), Some(0x05));
        assert_eq!(rtc_data(0x07, 0), Some(0x01));
        assert_eq!(rtc_data(0x08, 0), Some(0x01));
        assert_eq!(rtc_data(0x09, 0), Some(0x70));
        assert_eq!(rtc_data(0x32, 0), Some(0x19));
    }

    #[test]
    fn rtc_reports_leap_day() {
        let epoch_secs = 951_782_400; // 2000-02-29 00:00:00 UTC
        assert_eq!(rtc_data(0x07, epoch_secs), Some(0x29));
        assert_eq!(rtc_data(0x08, epoch_secs), Some(0x02));
        assert_eq!(rtc_data(0x09, epoch_secs), Some(0x00));
        assert_eq!(rtc_data(0x32, epoch_secs), Some(0x20));
    }
}
