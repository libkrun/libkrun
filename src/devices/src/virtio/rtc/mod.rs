// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! virtio-rtc: the default RTC device on Linux/KVM.
//!
//! The device offers three clocks to the guest: UTC (with an alarm), TAI
//! and monotonic. It supports the virtio-rtc requests for reading the
//! clocks and for setting alarms, and it reports expired alarms through
//! the alarm queue. It does not support cross-timestamping.
//!
//! The protocol handling is derived from `vhost-device-rtc` of the
//! rust-vmm `vhost-device` project.

mod clocks;
mod device;
mod event_handler;
mod protocol;
mod timer;

#[cfg(test)]
mod tests;

pub use self::defs::uapi::VIRTIO_ID_CLOCK as TYPE_RTC;
pub use self::device::Rtc;

mod defs {
    use super::protocol::NUM_QUEUES;
    use crate::virtio::QueueConfig;

    pub const RTC_DEV_ID: &str = "virtio_rtc";
    /// Matches the queue size of `vhost-device-rtc`.
    const QUEUE_SIZE: u16 = 1024;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_ID_CLOCK: u32 = 17;
    }
}

#[derive(Debug)]
pub enum RtcError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// The UTC clock is not available.
    Clock(std::io::Error),
    /// Failed to create the alarm timer.
    Timer(std::io::Error),
}

type Result<T> = std::result::Result<T, RtcError>;
