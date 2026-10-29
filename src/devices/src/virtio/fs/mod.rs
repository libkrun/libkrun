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

/// Guest file-data caching policy for a host-backed virtio-fs filesystem.
#[cfg_attr(
    feature = "ffi",
    ffier::export(cfg = "not(any(feature = \"tee\", feature = \"aws-nitro\"))")
)]
#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// Forward file-data I/O to the server without caching it in the guest. Use this when
    /// file contents may change outside the guest.
    Never = 0,
    /// Let the guest cache file data with close-to-open consistency: cached contents are
    /// invalidated when the file is opened again.
    #[default]
    Auto = 1,
    /// Keep cached file data across opens. Use this only when the filesystem has exclusive
    /// access to the shared directory.
    Always = 2,
}

impl FromStr for CachePolicy {
    type Err = &'static str;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        match s {
            "never" | "Never" | "NEVER" => Ok(CachePolicy::Never),
            "auto" | "Auto" | "AUTO" => Ok(CachePolicy::Auto),
            "always" | "Always" | "ALWAYS" => Ok(CachePolicy::Always),
            _ => Err("invalid cache policy"),
        }
    }
}

/// Permission semantics used by a host-backed virtio-fs filesystem.
#[cfg_attr(
    feature = "ffi",
    ffier::export(cfg = "not(any(feature = \"tee\", feature = \"aws-nitro\"))")
)]
#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PermissionSemantics {
    /// Emulate Linux ownership and permission semantics as closely as possible.
    #[default]
    LinuxComplete = 0,
    /// Report ownership as the requesting guest process's uid and gid, ignore ownership
    /// changes, and store permission bits on the host without extended attributes or idmaps.
    /// Unsupported on Linux hosts.
    LinuxSimplified = 1,
}

mod defs {
    use super::super::QueueConfig;

    pub const FS_DEV_ID: &str = "virtio_fs";
    pub const NUM_QUEUES: usize = 2;
    pub const QUEUE_SIZE: u16 = 1024;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];
    // High priority queue.
    pub const HPQ_INDEX: usize = 0;
    // Request queue.
    pub const REQ_INDEX: usize = 1;

    pub mod uapi {
        pub const VIRTIO_ID_FS: u32 = 26;
    }
}

use std::ffi::{FromBytesWithNulError, FromVecWithNulError};
use std::io;
use std::result;
use std::str::FromStr;

use descriptor_utils::Error as DescriptorError;

#[derive(Debug)]
pub enum FsError {
    /// The host does not implement the selected permission semantics.
    UnsupportedPermissionSemantics,
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
