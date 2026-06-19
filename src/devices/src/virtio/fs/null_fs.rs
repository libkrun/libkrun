// A minimal filesystem that serves an empty root directory.
//
// Used with AugmentFs to provide a virtual-only filesystem (e.g. for
// booting from a block device where the virtiofs root only needs init.krun).

use std::ffi::CStr;
use std::io;
use std::mem;
use std::time::Duration;

use super::filesystem::{Context, Entry, FileSystem, FsOptions};
use super::fuse;
use super::virtual_entry::VIRTUAL_BLKSIZE;
use crate::virtio::bindings;

/// An empty filesystem with just a root directory and nothing in it.
pub struct NullFs;

type Inode = u64;
type Handle = u64;

impl FileSystem for NullFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        Ok(FsOptions::empty())
    }

    fn lookup(&self, _ctx: Context, _parent: Inode, _name: &CStr) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        if inode == fuse::ROOT_ID {
            let mut st: bindings::stat64 = unsafe { mem::zeroed() };
            st.st_ino = fuse::ROOT_ID;
            #[cfg(not(target_os = "windows"))]
            let ifdir = libc::S_IFDIR;
            #[cfg(target_os = "windows")]
            let ifdir = libc::S_IFDIR as u32;
            st.st_mode = ifdir | 0o755;
            st.st_nlink = 2;
            st.st_blksize = VIRTUAL_BLKSIZE as _;
            return Ok((st, Duration::MAX));
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }
}
