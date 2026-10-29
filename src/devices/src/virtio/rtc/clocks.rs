// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Derived from vhost-device-rtc (https://github.com/rust-vmm/vhost-device,
// tag vhost-device-media-v0.1.1), which is available under Apache-2.0 or
// BSD-3-Clause and is used here under Apache-2.0:
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

//! The clocks that the device offers to the guest: UTC, TAI and monotonic.
//!
//! Only the UTC clock supports an alarm. It is a `CLOCK_REALTIME` clock,
//! which is what the alarm timer (see `timer.rs`) runs on.

use std::io;
use std::mem::zeroed;

use super::protocol::{
    VIRTIO_RTC_CLOCK_MONOTONIC, VIRTIO_RTC_CLOCK_TAI, VIRTIO_RTC_CLOCK_UTC_SMEARED,
    VIRTIO_RTC_SMEAR_UNSPECIFIED,
};

/// The alarm of a clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Alarm {
    /// Alarm time in nanoseconds, in the time domain of the clock.
    pub time: u64,
    pub enabled: bool,
    /// The alarm expired for its current time and settings.
    pub fired: bool,
    /// The expiration is not yet reported to the guest through the alarmq.
    pub pending: bool,
}

#[derive(Debug)]
pub(crate) struct Clock {
    pub clock_type: u8,
    pub leap_second_smearing: u8,
    pub alarm: Option<Alarm>,
    clock_id: libc::clockid_t,
}

impl Clock {
    fn new(clock_id: libc::clockid_t, clock_type: u8, has_alarm: bool) -> io::Result<Self> {
        // SAFETY: timespec is plain old data, all-zero is a valid value.
        let mut resolution: libc::timespec = unsafe { zeroed() };
        // SAFETY: `resolution` is a valid pointer for the duration of the call.
        if unsafe { libc::clock_getres(clock_id, &mut resolution) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            clock_type,
            leap_second_smearing: VIRTIO_RTC_SMEAR_UNSPECIFIED,
            alarm: has_alarm.then(Alarm::default),
            clock_id,
        })
    }

    /// UTC (`CLOCK_REALTIME`), the only clock with an alarm.
    pub fn new_utc() -> io::Result<Self> {
        Self::new(libc::CLOCK_REALTIME, VIRTIO_RTC_CLOCK_UTC_SMEARED, true)
    }

    pub fn new_tai() -> io::Result<Self> {
        Self::new(libc::CLOCK_TAI, VIRTIO_RTC_CLOCK_TAI, false)
    }

    pub fn new_monotonic() -> io::Result<Self> {
        Self::new(libc::CLOCK_MONOTONIC, VIRTIO_RTC_CLOCK_MONOTONIC, false)
    }

    /// Reads the clock in nanoseconds.
    pub fn read(&self) -> io::Result<u64> {
        // SAFETY: timespec is plain old data, all-zero is a valid value.
        let mut spec: libc::timespec = unsafe { zeroed() };
        // SAFETY: `spec` is a valid pointer for the duration of the call.
        if unsafe { libc::clock_gettime(self.clock_id, &mut spec) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let sec = u64::try_from(spec.tv_sec)
            .unwrap_or(0)
            .saturating_mul(1_000_000_000);
        let nsec = u64::try_from(spec.tv_nsec).unwrap_or(0);
        Ok(sec.saturating_add(nsec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_types_and_alarm_support() {
        let utc = Clock::new_utc().unwrap();
        assert_eq!(utc.clock_type, VIRTIO_RTC_CLOCK_UTC_SMEARED);
        assert_eq!(utc.leap_second_smearing, VIRTIO_RTC_SMEAR_UNSPECIFIED);
        assert_eq!(utc.alarm, Some(Alarm::default()));

        let tai = Clock::new_tai().unwrap();
        assert_eq!(tai.clock_type, VIRTIO_RTC_CLOCK_TAI);
        assert_eq!(tai.alarm, None);

        let monotonic = Clock::new_monotonic().unwrap();
        assert_eq!(monotonic.clock_type, VIRTIO_RTC_CLOCK_MONOTONIC);
        assert_eq!(monotonic.alarm, None);
    }

    #[test]
    fn utc_clock_reads_wall_time() {
        let utc = Clock::new_utc().unwrap();
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let reading = utc.read().unwrap();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        assert!(before <= reading && reading <= after);
    }

    #[test]
    fn monotonic_clock_does_not_go_backwards() {
        let monotonic = Clock::new_monotonic().unwrap();
        let first = monotonic.read().unwrap();
        let second = monotonic.read().unwrap();
        assert!(second >= first);
    }

    #[test]
    fn tai_is_not_behind_utc() {
        let utc = Clock::new_utc().unwrap().read().unwrap();
        let tai = Clock::new_tai().unwrap().read().unwrap();
        assert!(tai >= utc);
    }
}
