//! The experimental VIRTIO_FS_F_SYNC feature (bit 1) appends per-CPU queues
//! after the hiprio and normal request queues. Its little-endian queue count
//! follows num_request_queues in device configuration. Synchronous queue i has
//! index 1 + num_request_queues + i and completes in the notifying vCPU thread.
//! Hiprio and normal requests use a worker and retain interrupt completions.

mod augment_fs;
mod device;
#[allow(dead_code)]
mod filesystem;
pub mod fuse;
mod inode_alloc;
#[allow(dead_code)]
mod multikey;
mod null_fs;
mod read_only;
mod server;
pub mod virtual_entry;
mod worker;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::fs_utils;
#[cfg(target_os = "linux")]
pub use linux::passthrough;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::fs_utils;
#[cfg(target_os = "macos")]
pub use macos::passthrough;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::fs_utils;
#[cfg(target_os = "windows")]
pub use windows::passthrough;

use super::bindings;
use super::descriptor_utils;

pub use self::defs::uapi::VIRTIO_ID_FS as TYPE_FS;
pub use self::device::Fs;
pub use self::filesystem::ExportTable;

mod defs {
    pub const FS_DEV_ID: &str = "virtio_fs";
    pub const QUEUE_SIZE: u16 = 1024;
    // High priority queue.
    #[allow(dead_code)]
    pub const HPQ_INDEX: usize = 0;
    // Request queue.
    pub const REQ_INDEX: usize = 1;

    pub mod uapi {
        pub const VIRTIO_ID_FS: u32 = 26;
        pub const VIRTIO_FS_F_SYNC: u32 = 1;
    }
}

use std::ffi::{FromBytesWithNulError, FromVecWithNulError};
use std::io;

use descriptor_utils::Error as DescriptorError;

#[derive(Debug)]
pub enum FsError {
    /// Failed to decode protocol messages.
    DecodeMessage(io::Error),
    /// Failed to encode protocol messages.
    EncodeMessage(io::Error),
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// The guest failed to send a require extensions.
    MissingExtension,
    /// One or more parameters are missing.
    MissingParameter,
    /// A C string parameter is invalid.
    InvalidCString(FromBytesWithNulError),
    InvalidCString2(FromVecWithNulError),
    /// The `len` field of the header is too small.
    InvalidHeaderLength,
    /// The `size` field of the `SetxattrIn` message does not match the length
    /// of the decoded value.
    InvalidXattrSize((u32, usize)),
    QueueReader(DescriptorError),
    QueueWriter(DescriptorError),
}

type Result<T> = std::result::Result<T, FsError>;
