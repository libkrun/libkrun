// Virtual entry types for the virtiofs overlay.

use std::ffi::CString;

/// Block size reported by virtual entries in st_blksize.
pub const VIRTUAL_BLKSIZE: i64 = 4096;

/// A synthetic filesystem entry that exists only in memory.
#[derive(Clone, Debug)]
pub struct VirtualEntry<'a> {
    /// Permission bits. File type bits (S_IFMT) are ignored — the type
    /// is derived from the `content` variant.
    pub mode: u32,
    /// If true, the entry can only be looked up once.
    pub one_shot: bool,
    pub content: VirtualEntryContent<'a>,
}

#[derive(Clone, Debug)]
pub enum VirtualEntryContent<'a> {
    /// A read-only file backed by a borrowed byte slice.
    File { data: &'a [u8] },
    /// A directory containing other virtual entries.
    Dir { children: Vec<VirtualDirEntry<'a>> },
}

impl<'a> VirtualEntry<'a> {
    pub fn is_dir(&self) -> bool {
        matches!(self.content, VirtualEntryContent::Dir { .. })
    }

    /// Returns the full st_mode: file type bits from the variant OR'd
    /// with the permission bits from self.mode.
    #[allow(clippy::unnecessary_cast)] // libc::S_IF* is u16 on macOS, u32 on Linux
    pub fn st_mode(&self) -> u32 {
        let file_type = match self.content {
            VirtualEntryContent::File { .. } => libc::S_IFREG as u32,
            VirtualEntryContent::Dir { .. } => libc::S_IFDIR as u32,
        };
        file_type | (self.mode & !(libc::S_IFMT as u32))
    }

    /// Returns the directory entry type (`DT_*`) that matches `st_mode()`.
    pub fn dirent_type(&self) -> u32 {
        self.st_mode() >> 12
    }

    pub fn data(&self) -> Option<&'a [u8]> {
        match &self.content {
            VirtualEntryContent::File { data } => Some(data),
            VirtualEntryContent::Dir { .. } => None,
        }
    }
}

/// A named entry in a virtual directory.
#[derive(Clone, Debug)]
pub struct VirtualDirEntry<'a> {
    pub name: CString,
    pub entry: VirtualEntry<'a>,
}
