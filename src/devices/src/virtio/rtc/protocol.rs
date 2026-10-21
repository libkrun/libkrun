// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Derived from vhost-device-rtc (https://github.com/rust-vmm/vhost-device,
// tag vhost-device-media-v0.1.1), which is available under Apache-2.0 or
// BSD-3-Clause and is used here under Apache-2.0:
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

//! virtio-rtc wire format (virtio specification, "RTC Device").
//!
//! The definitions follow the specification completely, including values
//! that the device does not use (e.g. unsupported clock types).

#![allow(dead_code)]

use vm_memory::{ByteValued, Le16, Le64};

// Virtqueues.

pub const REQUEST_QUEUE_IDX: usize = 0;
pub const ALARM_QUEUE_IDX: usize = 1;
pub const NUM_QUEUES: usize = 2;

/// Feature bit: the device supports alarms.
pub const VIRTIO_RTC_F_ALARM: u32 = 0;

/// Common request header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqHead {
    pub msg_type: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqHead {}

/// Common response header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespHead {
    pub status: u8,
    pub reserved: [u8; 7],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespHead {}

pub const VIRTIO_RTC_S_OK: u8 = 0;
pub const VIRTIO_RTC_S_EOPNOTSUPP: u8 = 2;
pub const VIRTIO_RTC_S_ENODEV: u8 = 3;
pub const VIRTIO_RTC_S_EINVAL: u8 = 4;
pub const VIRTIO_RTC_S_EIO: u8 = 5;

// Clock types.

pub const VIRTIO_RTC_CLOCK_UTC: u8 = 0;
pub const VIRTIO_RTC_CLOCK_TAI: u8 = 1;
pub const VIRTIO_RTC_CLOCK_MONOTONIC: u8 = 2;
pub const VIRTIO_RTC_CLOCK_UTC_SMEARED: u8 = 3;
pub const VIRTIO_RTC_CLOCK_UTC_MAYBE_SMEARED: u8 = 4;

// Leap second smearing variants.

pub const VIRTIO_RTC_SMEAR_UNSPECIFIED: u8 = 0;
pub const VIRTIO_RTC_SMEAR_NOON_LINEAR: u8 = 1;
pub const VIRTIO_RTC_SMEAR_UTC_SLS: u8 = 2;

// Hardware counters.

/// Arm Generic Timer virtual count register (`CNTVCT_EL0`).
pub const VIRTIO_RTC_COUNTER_ARM_VCT: u8 = 0;
/// x86 time-stamp counter.
pub const VIRTIO_RTC_COUNTER_X86_TSC: u8 = 1;
pub const VIRTIO_RTC_COUNTER_INVALID: u8 = 0xFF;

// Control requests.

/// Discovers the number of clocks.
pub const VIRTIO_RTC_REQ_CFG: u16 = 0x1000;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespCfg {
    pub head: VirtioRtcRespHead,
    pub num_clocks: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespCfg {}

/// Discovers the capabilities of the clock identified by `clock_id`.
pub const VIRTIO_RTC_REQ_CLOCK_CAP: u16 = 0x1001;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqClockCap {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqClockCap {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespClockCap {
    pub head: VirtioRtcRespHead,
    pub r#type: u8,
    pub leap_second_smearing: u8,
    pub flags: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespClockCap {}

/// With `VIRTIO_RTC_F_ALARM` negotiated, the clock supports an alarm.
pub const VIRTIO_RTC_FLAG_ALARM_CAP: u8 = 1;

/// Discovers whether a clock and hardware counter pair supports
/// cross-timestamping.
pub const VIRTIO_RTC_REQ_CROSS_CAP: u16 = 0x1002;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqCrossCap {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub hw_counter: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqCrossCap {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespCrossCap {
    pub head: VirtioRtcRespHead,
    pub flags: u8,
    pub reserved: [u8; 7],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespCrossCap {}

pub const VIRTIO_RTC_FLAG_CROSS_CAP: u8 = 1;

// Read requests.

/// Reads the clock identified by `clock_id`.
pub const VIRTIO_RTC_REQ_READ: u16 = 0x0001;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqRead {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqRead {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespRead {
    pub head: VirtioRtcRespHead,
    pub clock_reading: Le64,
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespRead {}

/// Returns a cross-timestamp for the clock identified by `clock_id`.
pub const VIRTIO_RTC_REQ_READ_CROSS: u16 = 0x0002;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqReadCross {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub hw_counter: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqReadCross {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespReadCross {
    pub head: VirtioRtcRespHead,
    pub clock_reading: Le64,
    pub counter_cycles: Le64,
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespReadCross {}

// Alarm notifications (alarmq).

/// Common notification header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcNotifHead {
    pub msg_type: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcNotifHead {}

/// Notification message type: an alarm expired.
pub const VIRTIO_RTC_NOTIF_ALARM: u16 = 0x2000;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcNotifAlarm {
    pub head: VirtioRtcNotifHead,
    pub clock_id: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcNotifAlarm {}

// Alarm control requests.

pub const VIRTIO_RTC_REQ_READ_ALARM: u16 = 0x1003;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqReadAlarm {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqReadAlarm {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespReadAlarm {
    pub head: VirtioRtcRespHead,
    pub alarm_time: Le64,
    pub flags: u8,
    pub reserved: [u8; 7],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespReadAlarm {}

pub const VIRTIO_RTC_FLAG_ALARM_ENABLED: u8 = 1 << 0;

pub const VIRTIO_RTC_REQ_SET_ALARM: u16 = 0x1004;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqSetAlarm {
    pub head: VirtioRtcReqHead,
    pub alarm_time: Le64,
    pub clock_id: Le16,
    /// `VIRTIO_RTC_FLAG_ALARM_ENABLED`.
    pub flags: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqSetAlarm {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespSetAlarm {
    pub head: VirtioRtcRespHead,
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespSetAlarm {}

pub const VIRTIO_RTC_REQ_SET_ALARM_ENABLED: u16 = 0x1005;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqSetAlarmEnabled {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    /// `VIRTIO_RTC_FLAG_ALARM_ENABLED`.
    pub flags: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqSetAlarmEnabled {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespSetAlarmEnabled {
    pub head: VirtioRtcRespHead,
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespSetAlarmEnabled {}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn struct_sizes_match_the_specification() {
        assert_eq!(size_of::<VirtioRtcReqHead>(), 8);
        assert_eq!(size_of::<VirtioRtcRespHead>(), 8);
        assert_eq!(size_of::<VirtioRtcRespCfg>(), 16);
        assert_eq!(size_of::<VirtioRtcReqClockCap>(), 16);
        assert_eq!(size_of::<VirtioRtcRespClockCap>(), 16);
        assert_eq!(size_of::<VirtioRtcReqCrossCap>(), 16);
        assert_eq!(size_of::<VirtioRtcRespCrossCap>(), 16);
        assert_eq!(size_of::<VirtioRtcReqRead>(), 16);
        assert_eq!(size_of::<VirtioRtcRespRead>(), 16);
        assert_eq!(size_of::<VirtioRtcReqReadCross>(), 16);
        assert_eq!(size_of::<VirtioRtcRespReadCross>(), 24);
        assert_eq!(size_of::<VirtioRtcNotifHead>(), 8);
        assert_eq!(size_of::<VirtioRtcNotifAlarm>(), 16);
        assert_eq!(size_of::<VirtioRtcReqReadAlarm>(), 16);
        assert_eq!(size_of::<VirtioRtcRespReadAlarm>(), 24);
        assert_eq!(size_of::<VirtioRtcReqSetAlarm>(), 24);
        assert_eq!(size_of::<VirtioRtcRespSetAlarm>(), 8);
        assert_eq!(size_of::<VirtioRtcReqSetAlarmEnabled>(), 16);
        assert_eq!(size_of::<VirtioRtcRespSetAlarmEnabled>(), 8);
    }

    #[test]
    fn wire_layout_is_little_endian() {
        let req = VirtioRtcReqSetAlarm {
            head: VirtioRtcReqHead {
                msg_type: VIRTIO_RTC_REQ_SET_ALARM.into(),
                ..Default::default()
            },
            alarm_time: 0x0102_0304_0506_0708u64.into(),
            clock_id: 0x0a0bu16.into(),
            flags: VIRTIO_RTC_FLAG_ALARM_ENABLED,
            ..Default::default()
        };
        let bytes = req.as_slice();
        assert_eq!(&bytes[..2], &[0x04, 0x10]);
        assert_eq!(&bytes[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&bytes[16..18], &[0x0b, 0x0a]);
        assert_eq!(bytes[18], 1);
    }
}
