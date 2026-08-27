// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "blk")]
pub mod device;
#[cfg(feature = "blk")]
mod worker;

#[cfg(feature = "blk")]
pub use self::device::{Block, CacheType};

use vm_memory::GuestMemoryError;

use super::QueueConfig;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = (0x01_u64) << SECTOR_SHIFT;
const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE)];

#[derive(Debug)]
pub enum Error {
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    GetFileMetadata(std::io::Error),
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
}

/// Supported disk image formats
#[cfg_attr(feature = "ffi", ffier::export)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskFormat {
    Raw = 0,
    Qcow2 = 1,
    Vmdk = 2,
}

pub type ImageType = DiskFormat;

impl TryFrom<u32> for DiskFormat {
    type Error = ();

    fn try_from(disk_format: u32) -> Result<Self, Self::Error> {
        match disk_format {
            0 => Ok(DiskFormat::Raw),
            1 => Ok(DiskFormat::Qcow2),
            2 => Ok(DiskFormat::Vmdk),
            _ => {
                // Do not continue if the user cannot specify a valid disk format
                Err(())
            }
        }
    }
}

/// Supported synchronization modes for disk flushes.
#[cfg_attr(feature = "ffi", ffier::export)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncMode {
    /// Ignore VIRTIO_BLK_F_FLUSH.
    ///
    /// WARNING: may lead to loss of data.
    None = 0,
    /// Honor VIRTIO_BLK_F_FLUSH requests, but relax strict hardware syncing on macOS.
    /// This is the recommended mode.
    ///
    /// On macOS this flushes OS buffers, but does not ask the drive to flush
    /// its buffered data, which significantly improves performance.
    /// On Linux this is the same as full sync.
    #[default]
    Relaxed = 1,
    /// Honor VIRTIO_BLK_F_FLUSH, strictly flushing buffers to physical disk.
    Full = 2,
}

impl TryFrom<u32> for SyncMode {
    type Error = ();

    fn try_from(sync_mode: u32) -> Result<Self, Self::Error> {
        match sync_mode {
            0 => Ok(SyncMode::None),
            1 => Ok(SyncMode::Relaxed),
            2 => Ok(SyncMode::Full),
            _ => {
                // Do not continue if the user cannot specify a valid sync mode
                Err(())
            }
        }
    }
}
