// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{io, mem, result};
use virtio_bindings::virtio_net::virtio_net_hdr_v1;

use super::QueueConfig;

/// Each frame forwarded to a unixstream backend is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
/// In order to avoid unnecessary allocations and copies, the TX buffer is allocated with extra
/// space to accommodate this header.
const FRAME_HEADER_LEN: usize = 4;
pub const MAX_BUFFER_SIZE: usize = 65562 + FRAME_HEADER_LEN;
const QUEUE_SIZE: u16 = 4096;
pub const NUM_QUEUES: usize = 2;
pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

mod backend;
pub mod device;
#[cfg(target_os = "macos")]
mod socket_x;
#[cfg(target_os = "linux")]
mod tap;
mod unixgram;
mod unixstream;
mod worker;

fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

/// Default zeroed virtio_net_hdr_v1 (12 bytes) - used as prefix when receiving from backends
/// that don't include vnet headers (e.g., passt/unixstream)
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006
static DEFAULT_VNET_HDR: [u8; 12] = [0u8; 12];

pub use self::device::Net;
#[derive(Debug)]
pub enum Error {
    /// EventFd error.
    EventFd(io::Error),
}

pub type Result<T> = result::Result<T, Error>;
