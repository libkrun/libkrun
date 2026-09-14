// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{io, mem, result};
use virtio_bindings::virtio_net::virtio_net_hdr_v1;

use super::QueueConfig;

pub const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 1024;
pub const NUM_QUEUES: usize = 2;
pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

mod backend;
pub mod device;
#[cfg(target_os = "linux")]
mod tap;
#[cfg(unix)]
mod unixgram;
mod unixstream;
mod worker;

// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006
const VNET_HDR_LEN: usize = mem::size_of::<virtio_net_hdr_v1>();

// This initializes to all 0 the virtio_net_hdr part of a buf and return the length of the header
#[cfg(unix)]
fn write_virtio_net_hdr(buf: &mut [u8]) -> usize {
    buf[0..VNET_HDR_LEN].fill(0);
    VNET_HDR_LEN
}

pub use self::device::Net;
#[derive(Debug)]
pub enum Error {
    /// EventFd error.
    EventFd(io::Error),
}

pub type Result<T> = result::Result<T, Error>;
