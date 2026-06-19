// Windows passthrough filesystem — inspired by the macOS implementation.
// Uses NTFS file index + volume serial for inode identity and
// Alternate Data Streams (ADS) for extended-attribute emulation.

use super::super::inode_alloc::InodeAllocator;
use std::collections::BTreeMap;
use std::ffi::{CStr, OsString};
use std::fs::{self, File};
use std::io;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use libc::S_IFREG;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::FILE_NON_DIRECTORY_FILE;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_ACCESS_INFORMATION, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION,
    FILE_ID_BOTH_DIR_INFORMATION, FILE_OPEN, FILE_OPEN_BY_FILE_ID, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT,
    FileAccessInformation, FileDispositionInformation, FileIdBothDirectoryInformation,
    NtCreateFile, NtQueryDirectoryFile, NtQueryInformationFile, NtSetInformationFile, NtWriteFile,
    RtlNtStatusToDosErrorNoTeb,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
    STATUS_NO_MORE_FILES, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DeleteFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_DATA, GetFileInformationByHandle,
};
use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetVolumePathNameW};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use super::super::bindings::stat64;

use super::super::super::bindings::{
    self, LINUX_O_APPEND, LINUX_O_CREAT, LINUX_O_DIRECTORY, LINUX_O_EXCL, LINUX_O_NOFOLLOW,
    LINUX_O_TRUNC, LINUX_RENAME_EXCHANGE, LINUX_RENAME_NOREPLACE,
};
use super::super::super::linux_errno::{linux_errno_raw, linux_error};
use super::super::filesystem::*;
use super::super::fuse;
use super::super::multikey::MultikeyBTreeMap;
use super::fs_utils::{ebadf, einval, enosys, win_err_to_linux};

use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, WIN32_FIND_DATAW};

const OVERRIDE_STAT_STREAM: &str = ":user.containers.override_stat";
const SECURITY_CAPABILITY_STREAM: &str = ":security.capability";

const UID_MAX: u32 = u32::MAX - 1;

const SYNCHRONIZE: u32 = 0x0010_0000;
const DELETE: u32 = 0x0001_0000;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

const S_ISUID: u32 = 0o04_000;
const S_IXGRP: u32 = 0o00_010;
const S_ISGID: u32 = 0o02_000;
const S_IFLNK: i32 = 0o12_0000;

// Linux file types for d_type
pub const DT_UNKNOWN: u32 = 0;
pub const DT_FIFO: u32 = 1;
pub const DT_CHR: u32 = 2;
pub const DT_DIR: u32 = 4;
pub const DT_BLK: u32 = 6;
pub const DT_REG: u32 = 8;
pub const DT_LNK: u32 = 10;
pub const DT_SOCK: u32 = 12;

// Linux xattr flags
pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

// Handle guard ensures CloseHandle on all exit paths
struct HandleGuard(HANDLE);

impl HandleGuard {
    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Convert a Win32 path to an NT object-manager path (`\??\C:\...`) as a
/// null-terminated wide string.
fn path_to_nt_wide(path: &Path) -> Vec<u16> {
    let prefix: [u16; 4] = [b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16];
    let path_wide: Vec<u16> = path.as_os_str().encode_wide().collect();

    // Already has \\?\ prefix convert to \??\
    if path_wide.starts_with(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]) {
        let mut result = Vec::with_capacity(path_wide.len() + 1);
        result.extend_from_slice(&prefix);
        result.extend_from_slice(&path_wide[4..]);
        result.push(0);
        result
    } else {
        let mut result = Vec::with_capacity(prefix.len() + path_wide.len() + 1);
        result.extend_from_slice(&prefix);
        result.extend_from_slice(&path_wide);
        result.push(0);
        result
    }
}

fn nt_status_to_io_error(status: NTSTATUS) -> io::Error {
    let win32_err = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
    io::Error::from_raw_os_error(win32_err as i32)
}

type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
struct InodeAltKey {
    file_index: u64,
    volume_serial: u32,
}

struct InodeData {
    inode: Inode,
    parent_inode: Inode,
    file_index: u64,
    path: RwLock<Arc<PathBuf>>,
    wide_path: RwLock<Arc<Vec<u16>>>,
    refcount: AtomicU64,
}

impl InodeData {
    fn get_path(&self) -> Arc<PathBuf> {
        Arc::clone(&self.path.read().unwrap())
    }

    fn get_wide_path(&self) -> Arc<Vec<u16>> {
        Arc::clone(&self.wide_path.read().unwrap())
    }

    fn update_path_if_changed(&self, new_path: &Path) {
        if **self.path.read().unwrap() != *new_path {
            *self.path.write().unwrap() = Arc::new(new_path.to_path_buf());
            *self.wide_path.write().unwrap() = Arc::new(path_to_wide(new_path));
        }
    }
}

struct CachedDirEntry {
    ino: u64,
    name: Vec<u8>,
    type_: u32,
}

// CachePolicy — mirrors the macOS version
#[derive(Debug, Default, Clone)]
pub enum CachePolicy {
    Never,
    #[default]
    Auto,
    Always,
}

impl FromStr for CachePolicy {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" | "Never" | "NEVER" => Ok(CachePolicy::Never),
            "auto" | "Auto" | "AUTO" => Ok(CachePolicy::Auto),
            "always" | "Always" | "ALWAYS" => Ok(CachePolicy::Always),
            _ => Err("invalid cache policy"),
        }
    }
}

/// Options that configure the behavior of the file system.
#[derive(Debug, Clone)]
pub struct Config {
    /// How long the FUSE client should consider directory entries to be valid. If the contents of a
    /// directory can only be modified by the FUSE client (i.e., the file system has exclusive
    /// access), then this should be a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub entry_timeout: Duration,

    /// How long the FUSE client should consider file and directory attributes to be valid. If the
    /// attributes of a file or directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be set to a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub attr_timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as it
    /// allows the FUSE client to cache and coalesce multiple writes before sending them to the file
    /// system. However, enabling this option can increase the risk of data corruption if the file
    /// contents can change without the knowledge of the FUSE client (i.e., the server does **NOT**
    /// have exclusive access). Additionally, the file system should have read access to all files
    /// in the directory it is serving as the FUSE client may send read requests even for files
    /// opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions for
    /// all files in that directory.
    ///
    /// The default value for this option is `false`.
    pub writeback: bool,

    /// The path of the root directory.
    ///
    /// The default is `C:\\`.
    pub root_dir: String,

    /// Whether the file system should support Extended Attributes (xattr). Enabling this feature may
    /// have a significant impact on performance, especially on write parallelism. This is the result
    /// of FUSE attempting to remove the special file privileges after each write request.
    ///
    /// The default value for this options is `false`.
    pub xattr: bool,

    /// ID of this filesystem to uniquely identify exports.
    pub export_fsid: u64,
    /// Table of exported FDs to share with other subsystems.
    pub export_table: Option<ExportTable>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            root_dir: String::from("C:\\"),
            xattr: true,
            export_fsid: 0,
            export_table: None,
        }
    }
}

fn path_to_wide(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn cstr_to_path(name: &CStr) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(name.to_bytes()).as_ref())
}

const FILETIME_UNIX_EPOCH_DIFF: i64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SEC: i64 = 10_000_000;
const FILETIME_NSEC_PER_TICK: i64 = 100;

fn filetime_to_unix_secs(ft: u64) -> i64 {
    let ft = ft as i64;
    (ft - FILETIME_UNIX_EPOCH_DIFF) / FILETIME_TICKS_PER_SEC
}

fn filetime_to_unix_nsec(ft: u64) -> u32 {
    let ft = ft as i64;

    // rem_euclid guarantees a positive result between 0 and 9,999,999
    let ticks = (ft - FILETIME_UNIX_EPOCH_DIFF).rem_euclid(FILETIME_TICKS_PER_SEC);

    // 9,999,999 * 100 = 999,999,900, which easily fits in a u32 without panicking
    (ticks * FILETIME_NSEC_PER_TICK) as u32
}

fn unix_to_filetime(secs: i64, nsec: u32) -> u64 {
    let ticks = secs * FILETIME_TICKS_PER_SEC + (nsec as i64) / FILETIME_NSEC_PER_TICK;
    (ticks + FILETIME_UNIX_EPOCH_DIFF) as u64
}

struct FileInfo {
    file_index: u64,
    volume_serial: u32,
    n_number_of_links: u32,
}

/// Query NTFS file-index and volume serial via a temporary handle.
fn get_file_info(path: &Path) -> io::Result<FileInfo> {
    let flags = OpenFlags {
        desired_access: FILE_READ_ATTRIBUTES,
        create_disposition: FILE_OPEN,
        create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    };
    let h = open_handle(path, &flags)?;
    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = mem::zeroed();
        if GetFileInformationByHandle(h, &mut info) == 0 {
            CloseHandle(h);
            return Err(io::Error::last_os_error());
        }
        CloseHandle(h);
        let idx = (info.nFileIndexHigh as u64) << 32 | info.nFileIndexLow as u64;
        Ok(FileInfo {
            file_index: idx,
            volume_serial: info.dwVolumeSerialNumber,
            n_number_of_links: info.nNumberOfLinks,
        })
    }
}

pub fn is_handle_read_only(handle: u64) -> bool {
    // Ignore directory entries
    if handle == 0 || (handle & (1 << 63)) != 0 {
        return true;
    }

    let raw_handle = handle as windows_sys::Win32::Foundation::HANDLE;
    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let mut access_info: FILE_ACCESS_INFORMATION = unsafe { mem::zeroed() };

    let status = unsafe {
        NtQueryInformationFile(
            raw_handle,
            &mut iosb,
            &mut access_info as *mut _ as *mut core::ffi::c_void,
            mem::size_of::<FILE_ACCESS_INFORMATION>() as u32,
            FileAccessInformation,
        )
    };

    if status >= 0 {
        // If the handle lacks both standard WRITE and APPEND permissions, it was opened Read-Only
        (access_info.AccessFlags & (FILE_WRITE_DATA | FILE_APPEND_DATA)) == 0
    } else {
        // Fallback: If the kernel query fails for some reason, assume it's writable
        // to let standard error handling catch any violations later.
        false
    }
}

fn get_reparse_tag(path: &Path) -> u32 {
    let wide = path_to_wide(path);
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };

    let handle = unsafe { FindFirstFileW(wide.as_ptr(), &mut data) };
    if handle != INVALID_HANDLE_VALUE {
        unsafe { FindClose(handle) };
        if data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return data.dwReserved0; // This field holds the exact reparse tag!
        }
    }
    0
}

/// Build a `stat64` from Windows `Metadata`, applying override_stat xattr when available.
fn metadata_to_stat64(meta: &fs::Metadata, ino: u64, path: &Path, n_link: u32) -> stat64 {
    let file_attributes = meta.file_attributes();

    let is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    let mut is_symlink = meta.file_type().is_symlink();
    if is_symlink && (file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0) {
        let tag = get_reparse_tag(path);
        if tag == IO_REPARSE_TAG_MOUNT_POINT {
            is_symlink = false; // It's a Volume Mount! Force it to be a native directory.
        }
    }
    let (base_mode, nlink) = if is_symlink {
        (S_IFLNK | 0o777, 1)
    } else if is_directory {
        (libc::S_IFDIR | 0o755, 2u32)
    } else {
        (libc::S_IFREG | 0o644, n_link)
    };

    let size = meta.len() as i64;

    let creation = meta.creation_time();
    let access = meta.last_access_time();
    let write = meta.last_write_time();

    let mut st = stat64 {
        st_dev: 0,
        st_ino: ino,
        st_nlink: nlink,
        st_mode: base_mode as u32,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: size,
        st_atime: filetime_to_unix_secs(access),
        st_atime_nsec: filetime_to_unix_nsec(access),
        st_mtime: filetime_to_unix_secs(write),
        st_mtime_nsec: filetime_to_unix_nsec(write),
        st_ctime: filetime_to_unix_secs(creation),
        st_ctime_nsec: filetime_to_unix_nsec(creation),
        st_blksize: 4096,
        st_blocks: (size + 511) / 512,
    };

    if let Ok((uid, gid, mode)) = read_override_stat(path) {
        if let Some(uid) = uid {
            st.st_uid = uid;
        }
        if let Some(gid) = gid {
            st.st_gid = gid;
        }
        if let Some(mode) = mode {
            if mode & libc::S_IFMT as u32 == 0 {
                st.st_mode = (st.st_mode & libc::S_IFMT as u32) | mode;
            } else {
                st.st_mode = mode;
            }
        }
    }

    st
}

// ADS-backed override_stat helpers  (uid:gid:0mode)
fn item_to_value(item: &[u8], radix: u32) -> Option<u32> {
    std::str::from_utf8(item)
        .ok()
        .and_then(|s| u32::from_str_radix(s, radix).ok())
}

fn ads_stream_path(base: &Path, stream_suffix: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(stream_suffix);
    PathBuf::from(s)
}

fn read_override_stat(path: &Path) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let ads = ads_stream_path(path, OVERRIDE_STAT_STREAM);
    let data = match fs::read(&ads) {
        Ok(d) => d,
        Err(_) => return Ok((None, None, None)),
    };
    parse_override_stat(&data)
}

fn parse_override_stat(buf: &[u8]) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut items = buf.split(|c| *c == b':');
    let uid = items.next().and_then(|i| item_to_value(i, 10));
    let gid = items.next().and_then(|i| item_to_value(i, 10));
    let mode = items.next().and_then(|i| item_to_value(i, 8));
    Ok((uid, gid, mode))
}

fn write_override_stat(
    path: &Path,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
) -> io::Result<()> {
    let buf = if is_valid_owner(owner) && mode.is_some() {
        let (uid, gid) = owner.unwrap();
        format!("{}:{}:0{:o}", uid, gid, mode.unwrap())
    } else {
        let (orig_uid, orig_gid, orig_mode) = read_override_stat(path)?;
        let (uid, gid) = match owner {
            Some((u, g)) => {
                let uid = if u < UID_MAX { Some(u) } else { orig_uid };
                let gid = if g < UID_MAX { Some(g) } else { orig_gid };
                (uid, gid)
            }
            None => (orig_uid, orig_gid),
        };

        let mut s = String::new();
        match uid {
            Some(u) => s.push_str(&u.to_string()),
            None => s.push('x'),
        }
        s.push(':');
        match gid {
            Some(g) => s.push_str(&g.to_string()),
            None => s.push('x'),
        }
        s.push(':');
        match mode.or(orig_mode) {
            Some(m) => s.push_str(&format!("0{:o}", m)),
            None => s.push('x'),
        }
        s
    };

    let ads = ads_stream_path(path, OVERRIDE_STAT_STREAM);
    fs::write(&ads, buf.as_bytes()).map_err(win_err_to_linux)
}

fn is_valid_owner(owner: Option<(u32, u32)>) -> bool {
    matches!(owner, Some((u, g)) if u < UID_MAX && g < UID_MAX)
}

/// Delete the ADS stream that emulates `security.capability`.
fn remove_security_capability(path: &Path) {
    let ads = ads_stream_path(path, SECURITY_CAPABILITY_STREAM);
    let wide: Vec<u16> = ads
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let ret = unsafe { DeleteFileW(wide.as_ptr()) };
    if ret == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(2) {
            warn!("remove security.capability ADS: {e}");
        }
    }
}

/// Write data to an ADS stream relative to an open file/directory handle.
/// `stream_suffix` must include the leading colon, e.g. `":stat"`.
fn write_ads_by_handle(file_handle: HANDLE, stream_suffix: &str, data: &[u8]) -> io::Result<()> {
    let mut wide: Vec<u16> = stream_suffix.encode_utf16().collect();
    wide.push(0);
    let byte_len = (wide.len() - 1) * 2;

    let mut us = UNICODE_STRING {
        Length: byte_len as u16,
        MaximumLength: (byte_len + 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };

    let oa = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: file_handle,
        ObjectName: &mut us,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let mut h: HANDLE = INVALID_HANDLE_VALUE;

    let status = unsafe {
        NtCreateFile(
            &mut h,
            GENERIC_WRITE | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };

    if status < 0 {
        return Err(nt_status_to_io_error(status));
    }

    let mut write_iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let write_status = unsafe {
        NtWriteFile(
            h,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            &mut write_iosb,
            data.as_ptr() as *const core::ffi::c_void,
            data.len() as u32,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    unsafe { CloseHandle(h) };

    if write_status >= 0 {
        Ok(())
    } else {
        Err(nt_status_to_io_error(write_status))
    }
}

/// Clear suid/sgid bits from mode.
/// sgid is cleared only if group executable bit is set.
fn clear_suid_sgid(mode: u32) -> u32 {
    let mut new_mode = mode;

    // Clear suid bit
    new_mode &= !S_ISUID;

    // Clear sgid bit only if group executable bit is set
    if (mode & S_IXGRP) != 0 {
        new_mode &= !S_ISGID;
    }

    new_mode
}

#[derive(Clone, Copy)]
struct OpenFlags {
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
}

fn parse_linux_open_flags(linux_flags: i32, writeback: bool) -> OpenFlags {
    let mut access = 0u32;
    let mut disposition = FILE_OPEN;
    let mut options = FILE_SYNCHRONOUS_IO_NONALERT;

    let mut flags = linux_flags;

    // When writeback caching is on the kernel may read from O_WRONLY files.
    // However on Windows, we need to open the file for reading and writing.
    if writeback && (flags & 0b11) == 1 {
        flags = (flags & !0b11) | 2;
    }
    // If writeback is on and O_APPEND is set, we need to clear it.
    // Otherwise Windows will just append the contents at the end of the file when it should be written at a specific offset
    if writeback && (flags & LINUX_O_APPEND) != 0 {
        flags &= !LINUX_O_APPEND;
    }

    match flags & 0b11 {
        0 => access |= GENERIC_READ,
        1 => access |= GENERIC_WRITE,
        2 => access |= GENERIC_READ | GENERIC_WRITE,
        _ => {}
    }

    if flags & LINUX_O_CREAT != 0 {
        if flags & LINUX_O_EXCL != 0 {
            disposition = FILE_CREATE;
        } else if flags & LINUX_O_TRUNC != 0 {
            disposition = FILE_OVERWRITE_IF;
        } else {
            disposition = FILE_OPEN_IF;
        }
    } else if flags & LINUX_O_TRUNC != 0 {
        disposition = FILE_OVERWRITE;
        access |= GENERIC_WRITE;
    }

    if flags & LINUX_O_APPEND != 0 {
        access |= FILE_APPEND_DATA;
    }
    if flags & LINUX_O_NOFOLLOW != 0 {
        options |= FILE_OPEN_REPARSE_POINT;
    }
    if flags & LINUX_O_DIRECTORY != 0 {
        options |= FILE_DIRECTORY_FILE;
    }

    OpenFlags {
        desired_access: access,
        create_disposition: disposition,
        create_options: options,
    }
}

/// Open a file via NtCreateFile with case-sensitive semantics.
fn open_handle(path: &Path, flags: &OpenFlags) -> io::Result<HANDLE> {
    let mut nt_path = path_to_nt_wide(path);
    let byte_len = (nt_path.len() - 1) * 2; // excluding null terminator

    let mut us = UNICODE_STRING {
        Length: byte_len as u16,
        MaximumLength: (byte_len + 2) as u16,
        Buffer: nt_path.as_mut_ptr(),
    };

    let oa = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut us,
        Attributes: 0, // no OBJ_CASE_INSENSITIVE → case-sensitive
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let mut handle: HANDLE = INVALID_HANDLE_VALUE;

    let status = unsafe {
        NtCreateFile(
            &mut handle,
            flags.desired_access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            flags.create_disposition,
            flags.create_options,
            std::ptr::null(),
            0,
        )
    };

    if status >= 0 {
        Ok(handle)
    } else {
        Err(nt_status_to_io_error(status))
    }
}

/// Open an existing file by its NTFS file index, using a volume-relative handle
/// as the root directory
fn open_by_id(root_handle: HANDLE, file_index: u64, flags: &OpenFlags) -> io::Result<HANDLE> {
    let id_bytes = file_index.to_le_bytes();
    let mut us = UNICODE_STRING {
        Length: 8,
        MaximumLength: 8,
        Buffer: id_bytes.as_ptr() as *mut u16,
    };

    let oa = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root_handle,
        ObjectName: &mut us,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let mut handle: HANDLE = INVALID_HANDLE_VALUE;

    let status = unsafe {
        NtCreateFile(
            &mut handle,
            flags.desired_access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            flags.create_disposition,
            flags.create_options | FILE_OPEN_BY_FILE_ID,
            std::ptr::null(),
            0,
        )
    };

    if status >= 0 {
        Ok(handle)
    } else {
        Err(nt_status_to_io_error(status))
    }
}

/// Open a child entry relative to a parent handle by name.
fn open_relative(parent_handle: HANDLE, name: &CStr, flags: &OpenFlags) -> io::Result<HANDLE> {
    let name_path = cstr_to_path(name);
    let mut wide: Vec<u16> = name_path.as_os_str().encode_wide().collect();
    wide.push(0);
    let byte_len = (wide.len() - 1) * 2;

    let mut us = UNICODE_STRING {
        Length: byte_len as u16,
        MaximumLength: (byte_len + 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };

    let oa = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent_handle,
        ObjectName: &mut us,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let mut handle: HANDLE = INVALID_HANDLE_VALUE;

    let status = unsafe {
        NtCreateFile(
            &mut handle,
            flags.desired_access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            flags.create_disposition,
            flags.create_options,
            std::ptr::null(),
            0,
        )
    };

    if status >= 0 {
        Ok(handle)
    } else {
        Err(nt_status_to_io_error(status))
    }
}

/// Mark an open handle for deletion. The actual removal happens on close.
fn set_delete_disposition(handle: HANDLE) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };

    let status = unsafe {
        NtSetInformationFile(
            handle,
            &mut iosb,
            &info as *const _ as *const core::ffi::c_void,
            mem::size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    };

    if status >= 0 {
        Ok(())
    } else {
        Err(nt_status_to_io_error(status))
    }
}

/// Validate that a path is not a reparse point (symlink / junction) before use.
pub fn openat(path: &str) -> io::Result<HANDLE> {
    let p = Path::new(path);
    let flags = OpenFlags {
        desired_access: FILE_READ_ATTRIBUTES,
        create_disposition: FILE_OPEN,
        create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    };
    let h = open_handle(p, &flags)?;

    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = mem::zeroed();
        if GetFileInformationByHandle(h, &mut info) == 0 {
            CloseHandle(h);
            return Err(io::Error::last_os_error());
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            CloseHandle(h);
            return Err(linux_error(io::Error::new(
                io::ErrorKind::Other,
                "Reparse point detected — path is not safe",
            )));
        }
    }
    Ok(h)
}

fn set_file_times(path: &Path, atime: Option<u64>, mtime: Option<u64>) -> io::Result<()> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Storage::FileSystem::SetFileTime;

    let flags = OpenFlags {
        desired_access: FILE_WRITE_ATTRIBUTES,
        create_disposition: FILE_OPEN,
        create_options: FILE_SYNCHRONOUS_IO_NONALERT,
    };
    let h = open_handle(path, &flags).map_err(win_err_to_linux)?;

    let to_ft = |v: u64| -> FILETIME {
        FILETIME {
            dwLowDateTime: v as u32,
            dwHighDateTime: (v >> 32) as u32,
        }
    };

    let a_ft = atime.map(to_ft);
    let m_ft = mtime.map(to_ft);

    let res = unsafe {
        SetFileTime(
            h,
            std::ptr::null(),
            a_ft.as_ref().map_or(std::ptr::null(), |f| f as *const _),
            m_ft.as_ref().map_or(std::ptr::null(), |f| f as *const _),
        )
    };
    unsafe { CloseHandle(h) };
    if res == 0 {
        Err(win_err_to_linux(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn forget_one(
    inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    inode: Inode,
    count: u64,
) {
    if let Some(data) = inodes.get(&inode) {
        // Acquiring the write lock on the inode map prevents new lookups from incrementing the
        // refcount but there is the possibility that a previous lookup already acquired a
        // reference to the inode data and is in the process of updating the refcount so we need
        // to loop here until we can decrement successfully.
        loop {
            let refcount = data.refcount.load(Ordering::Relaxed);

            // Saturating sub because it doesn't make sense for a refcount to go below zero and
            // we don't want misbehaving clients to cause integer overflow.
            let new_count = refcount.saturating_sub(count);

            // Synchronizes with the acquire load in `do_lookup`.
            if data
                .refcount
                .compare_exchange(refcount, new_count, Ordering::Release, Ordering::Relaxed)
                .unwrap()
                == refcount
            {
                if new_count == 0 {
                    // We just removed the last refcount for this inode. There's no need for an
                    // acquire fence here because we hold a write lock on the inode map and any
                    // thread that is waiting to do a forget on the same inode will have to wait
                    // until we release the lock. So there's is no other release store for us to
                    // synchronize with before deleting the entry.
                    inodes.remove(&inode);
                }
                break;
            }
        }
    }
}

pub struct PassthroughFs {
    inodes: RwLock<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>>,
    inode_alloc: Arc<InodeAllocator>,

    next_handle: AtomicU64,

    dir_caches: RwLock<BTreeMap<Handle, Mutex<Vec<CachedDirEntry>>>>,

    /// Handle to the root directory, kept open for FILE_OPEN_BY_FILE_ID.
    root_handle: RwLock<HANDLE>,

    writeback: AtomicBool,
    announce_submounts: AtomicBool,
    cfg: Config,
}

// Windows HANDLEs (*mut c_void) are thread-safe to move and share across OS threads.
unsafe impl Send for PassthroughFs {}
unsafe impl Sync for PassthroughFs {}

impl PassthroughFs {
    pub fn new(cfg: Config, inode_alloc: Arc<InodeAllocator>) -> io::Result<Self> {
        let root_handle = openat(&cfg.root_dir)?;

        Ok(PassthroughFs {
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            inode_alloc,
            next_handle: AtomicU64::new(1),
            dir_caches: RwLock::new(BTreeMap::new()),
            root_handle: RwLock::new(root_handle),
            writeback: AtomicBool::new(false),
            announce_submounts: AtomicBool::new(false),
            cfg,
        })
    }

    fn inode_data(&self, inode: Inode) -> io::Result<Arc<InodeData>> {
        self.inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)
    }

    fn inode_path(&self, inode: Inode) -> io::Result<Arc<PathBuf>> {
        Ok(self.inode_data(inode)?.get_path())
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let parent_data = self.inode_data(parent)?;
        let child_name = cstr_to_path(name);
        let child_path = parent_data.get_path().join(&child_name);

        let file_info = get_file_info(&child_path).map_err(win_err_to_linux)?;
        let alt_key = InodeAltKey {
            file_index: file_info.file_index,
            volume_serial: file_info.volume_serial,
        };

        let inode = {
            let handle_existing = |existing: &Arc<InodeData>| {
                existing.refcount.fetch_add(1, Ordering::Acquire);
                existing.update_path_if_changed(&child_path);
                existing.inode
            };

            let map = self.inodes.read().unwrap();
            if let Some(existing) = map.get_alt(&alt_key) {
                handle_existing(existing)
            } else {
                drop(map);

                let mut write_map = self.inodes.write().unwrap();

                // To avoid a potential race when 2 threads tries to lookup for the same file
                // we check again the existance of the entry after acquiring the write lock
                if let Some(existing) = write_map.get_alt(&alt_key) {
                    handle_existing(existing)
                } else {
                    // Safe to create a new one now
                    let inode = self.inode_alloc.next();
                    write_map.insert(
                        inode,
                        alt_key,
                        Arc::new(InodeData {
                            inode,
                            parent_inode: parent,
                            file_index: file_info.file_index,
                            path: RwLock::new(Arc::new(child_path.clone())),
                            wide_path: RwLock::new(Arc::new(path_to_wide(&child_path))),
                            refcount: AtomicU64::new(1),
                        }),
                    );
                    inode
                }
            }
        };

        let meta = fs::symlink_metadata(&child_path).map_err(win_err_to_linux)?;
        let st = metadata_to_stat64(&meta, inode, &child_path, file_info.n_number_of_links);

        let mut attr_flags = 0u32;
        if st.st_mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
            && self.announce_submounts.load(Ordering::Relaxed)
        {
            // Different volume ⟹ submount
            if let Ok(parent_file_info) = get_file_info(&parent_data.get_path()) {
                if file_info.volume_serial != parent_file_info.volume_serial {
                    attr_flags |= fuse::ATTR_SUBMOUNT;
                }
            }
        }

        Ok(Entry {
            inode,
            generation: 0,
            attr: st,
            attr_flags,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    fn do_getattr(&self, inode: Inode, handle: Option<Handle>) -> io::Result<(stat64, Duration)> {
        let path = self.inode_path(inode)?;

        if let Some(h) = handle {
            if h != 0 && (h & (1 << 63)) == 0 {
                if let Ok(file) = self.reopen_inode(inode, h, FILE_READ_ATTRIBUTES) {
                    if let Ok(meta) = file.metadata() {
                        let mut n_link = 1;
                        unsafe {
                            let mut info: BY_HANDLE_FILE_INFORMATION = mem::zeroed();
                            if GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info)
                                != 0
                            {
                                n_link = info.nNumberOfLinks;
                            }
                        }
                        let st = metadata_to_stat64(&meta, inode, &path, n_link);
                        return Ok((st, self.cfg.attr_timeout));
                    }
                }
            }
        }

        let meta = fs::symlink_metadata(&*path).map_err(win_err_to_linux)?;
        let file_info = get_file_info(&path).map_err(win_err_to_linux)?;
        let st = metadata_to_stat64(&meta, inode, &path, file_info.n_number_of_links);
        Ok((st, self.cfg.attr_timeout))
    }

    // To avoid global lookup maps we reuse Win32 HANDLE for file descriptors and
    // a sequential incremental integer token for directories.
    //
    // 1. REGULAR FILES: The FUSE Handle ID returned to the guest is simply the
    //    raw user-space pointer address of the active Win32 HANDLE itself (h as u64).
    //
    // 2. DIRECTORIES: Directories are read entirely into a RAM vector cache (`dir_caches`)
    //    immediately upon `opendir`, and their physical Win32 handles are dropped to
    //    prevent Windows host-side Directory Locking violations. They are tracked via a
    //    fake, sequential incremental integer token.
    //
    // On 64-bit Windows architectures, user-space memory pointers are strictly partitioned
    // by the OS kernel into the lower half of the virtual address space (ranging from
    // 0x00000000'00000000 to 0x00007FFF'FFFFFFFF). This guarantees that bit 63 (the highest bit)
    // of a real file HANDLE pointer is always 0.
    //
    // By manually bitwise-OR tagging directory integer tokens with the highest bit set to 1
    // (`| (1 << 63)`), we force directory handle tokens into a completely separate value space
    // (0x80000000'00000000+). This allows to avoid collisions between files and directories
    fn do_open(
        &self,
        inode: Inode,
        kill_priv: bool,
        linux_flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let wb = self.writeback.load(Ordering::Relaxed);
        let oflags = parse_linux_open_flags(linux_flags as i32, wb);

        let is_dir = oflags.create_options & FILE_DIRECTORY_FILE != 0;

        // Virtual addresses
        // If it's a directory, generate a handle ID for the cache map
        if is_dir {
            let handle_id = self.next_handle.fetch_add(1, Ordering::Relaxed) | (1 << 63);
            let mut opts = OpenOptions::empty();
            match self.cfg.cache_policy {
                CachePolicy::Always => opts |= OpenOptions::CACHE_DIR,
                _ => {}
            }
            return Ok((Some(handle_id), opts));
        }

        let data = self.inode_data(inode)?;
        let root_h = *self.root_handle.read().unwrap();
        let h = open_by_id(root_h, data.file_index, &oflags)
            .or_else(|_| open_handle(&data.get_path(), &oflags))
            .map_err(win_err_to_linux)?;

        if kill_priv {
            let path = data.get_path();
            remove_security_capability(&path);
            if let Ok((_, _, Some(mode))) = read_override_stat(&path) {
                let new_mode = clear_suid_sgid(mode);
                if new_mode != mode {
                    if let Err(e) = write_override_stat(&path, None, Some(new_mode)) {
                        error!("clear suid/sgid for inode {inode}: {e}");
                    }
                }
            }
        }

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts.set(OpenOptions::DIRECT_IO, !is_dir),
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        }

        Ok((Some(h as u64), opts))
    }

    fn do_release(&self, _inode: Inode, handle: Handle) -> io::Result<()> {
        // Check if it's a tagged directory handle or a raw file handle
        if handle & (1 << 63) != 0 {
            self.dir_caches.write().unwrap().remove(&handle);
        } else {
            let h = handle as HANDLE;
            if h != INVALID_HANDLE_VALUE && !h.is_null() {
                unsafe { CloseHandle(h) };
            }
        }
        Ok(())
    }

    /// Open a fresh file handle via `open_by_id` (falling back to
    /// path-based open).  The caller owns the returned `File`; the
    /// underlying handle is closed on drop.
    fn reopen_inode(&self, inode: Inode, handle: Handle, desired_access: u32) -> io::Result<File> {
        // If the handle is a valid persistent raw file handle (not zero, and no directory tag bit)
        if handle != 0 && (handle & (1 << 63)) == 0 {
            const DUPLICATE_SAME_ACCESS: u32 = 2;
            let current_process =
                unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
            let mut dup_h: HANDLE = INVALID_HANDLE_VALUE;

            let res = unsafe {
                windows_sys::Win32::Foundation::DuplicateHandle(
                    current_process,
                    handle as HANDLE,
                    current_process,
                    &mut dup_h,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };

            if res != 0 {
                return Ok(unsafe { File::from_raw_handle(dup_h as RawHandle) });
            } else {
                return Err(win_err_to_linux(io::Error::last_os_error()));
            }
        }

        let data = self.inode_data(inode)?;
        let root_h = *self.root_handle.read().unwrap();
        let flags = OpenFlags {
            desired_access,
            create_disposition: FILE_OPEN,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT,
        };
        let h = open_by_id(root_h, data.file_index, &flags)
            .or_else(|_| open_handle(&data.get_path(), &flags))?;
        Ok(unsafe { File::from_raw_handle(h as RawHandle) })
    }

    fn fill_dir_cache(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        // Fast path: cache already populated
        if self.dir_caches.read().unwrap().contains_key(&handle) {
            return Ok(());
        }

        let inode_data = self.inode_data(inode)?;
        let root_h = *self.root_handle.read().unwrap();

        let dir_flags = OpenFlags {
            desired_access: GENERIC_READ,
            create_disposition: FILE_OPEN,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
        };
        let dir_g = HandleGuard(
            open_by_id(root_h, inode_data.file_index, &dir_flags)
                .or_else(|_| open_handle(&inode_data.get_path(), &dir_flags))
                .map_err(win_err_to_linux)?,
        );

        let mut entries = Vec::new();

        entries.push(CachedDirEntry {
            ino: inode,
            name: b".".to_vec(),
            type_: DT_DIR,
        });

        let parent_ino = inode_data.parent_inode;
        entries.push(CachedDirEntry {
            ino: parent_ino,
            name: b"..".to_vec(),
            type_: DT_DIR,
        });

        let mut buf = vec![0u8; 64 * 1024];
        let mut first = true;
        loop {
            let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
            let status = unsafe {
                NtQueryDirectoryFile(
                    dir_g.as_raw(),
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null(),
                    &mut iosb,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    buf.len() as u32,
                    FileIdBothDirectoryInformation,
                    false,
                    std::ptr::null(),
                    first,
                )
            };
            first = false;

            if status == STATUS_NO_MORE_FILES {
                break;
            }
            if status < 0 {
                return Err(nt_status_to_io_error(status));
            }

            let mut offset = 0usize;
            loop {
                let entry_ptr =
                    buf.as_ptr().wrapping_add(offset) as *const FILE_ID_BOTH_DIR_INFORMATION;
                let entry = unsafe { &*entry_ptr };

                let name_len_bytes = entry.FileNameLength as usize;
                let name_slice = unsafe {
                    std::slice::from_raw_parts(entry.FileName.as_ptr(), name_len_bytes / 2)
                };
                let name_os = OsString::from_wide(name_slice);
                let name_bytes = name_os.to_string_lossy().into_owned().into_bytes();

                if name_bytes != b"." && name_bytes != b".." {
                    let attrs = entry.FileAttributes;
                    let d_type = if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0
                        && entry.EaSize == IO_REPARSE_TAG_SYMLINK
                    {
                        DT_LNK
                    } else if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                        DT_DIR
                    } else {
                        DT_REG
                    };

                    entries.push(CachedDirEntry {
                        ino: entry.FileId as u64,
                        name: name_bytes,
                        type_: d_type,
                    });
                }

                if entry.NextEntryOffset == 0 {
                    break;
                }
                offset += entry.NextEntryOffset as usize;
            }
        }

        self.dir_caches
            .write()
            .unwrap()
            .insert(handle, Mutex::new(entries));
        Ok(())
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let root_path = PathBuf::from(&self.cfg.root_dir);
        let file_info = get_file_info(&root_path).map_err(win_err_to_linux)?;

        let alt_key = InodeAltKey {
            file_index: file_info.file_index,
            volume_serial: file_info.volume_serial,
        };

        let mut inodes = self.inodes.write().unwrap();
        inodes.insert(
            fuse::ROOT_ID,
            alt_key,
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                parent_inode: fuse::ROOT_ID,
                file_index: file_info.file_index,
                path: RwLock::new(Arc::new(root_path.clone())),
                wide_path: RwLock::new(Arc::new(path_to_wide(&root_path))),
                refcount: AtomicU64::new(2),
            }),
        );

        // Windows is notoriously "chatty" when it comes to filesystem metadata
        // By enabling READDIRPLUS we allow the filesystem to return both the name and the metadata in a single response.
        // READDIRPLUS_AUTO allows the kernel to decide when to use READDIRPLUS or READDIR.
        let mut opts = FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;

        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }
        if capable.contains(FsOptions::SUBMOUNTS) {
            opts |= FsOptions::SUBMOUNTS;
            self.announce_submounts.store(true, Ordering::Relaxed);
        }

        Ok(opts)
    }

    fn destroy(&self) {
        self.dir_caches.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
        let h = std::mem::replace(
            &mut *self.root_handle.write().unwrap(),
            INVALID_HANDLE_VALUE,
        );
        if h != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(h) };
        }
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        let data = self.inode_data(inode)?;
        let wide_path = data.get_wide_path();

        // Dynamically size the buffer based on the input path.
        // Add +1 to safely handle cases like "C:" expanding to "C:\"
        let mut volume_root = vec![0u16; wide_path.len() + 1];
        // Resolve any input path down to its absolute host volume
        // GetDiskFreeSpaceExW only expects a directory but on linux we could
        // execute commands on simple files (e.g. df -h file)
        // which would fail if we directly call GetDiskFreeSpaceExW
        let vol_ok = unsafe {
            GetVolumePathNameW(
                wide_path.as_ptr(),
                volume_root.as_mut_ptr(),
                volume_root.len() as u32,
            )
        };

        let fallback_buffer;
        let path_to_query = if vol_ok != 0 {
            volume_root.as_ptr()
        } else {
            fallback_buffer = path_to_wide(Path::new(&self.cfg.root_dir));
            fallback_buffer.as_ptr()
        };

        let (mut free_avail, mut total, mut total_free) = (0u64, 0u64, 0u64);
        let ok = unsafe {
            GetDiskFreeSpaceExW(path_to_query, &mut free_avail, &mut total, &mut total_free)
        };
        if ok == 0 {
            return Err(win_err_to_linux(io::Error::last_os_error()));
        }

        let bsize: u64 = 4096;
        Ok(bindings::statvfs64 {
            f_bsize: bsize,
            f_frsize: bsize,
            f_blocks: total / bsize,
            f_bfree: total_free / bsize,
            f_bavail: free_avail / bsize,
            f_files: i64::MAX as u64,
            f_ffree: i64::MAX as u64,
            f_favail: i64::MAX as u64,
            f_fsid: self.cfg.export_fsid,
            f_flag: 0,
            f_namemax: 255,
        })
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(parent, name)
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let mut inodes = self.inodes.write().unwrap();
        forget_one(&mut inodes, inode, count);
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.write().unwrap();
        for (inode, count) in requests {
            forget_one(&mut inodes, inode, count);
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, false, flags | LINUX_O_DIRECTORY as u32)
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        // Colon is used to define a stream name in the ADS, so we need to prevent it from being used in the filename
        if name.to_bytes().contains(&b':') {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::EINVAL)));
        }

        let parent_data = self.inode_data(parent)?;
        let root_h = *self.root_handle.read().unwrap();
        let parent_g = HandleGuard(
            open_by_id(
                root_h,
                parent_data.file_index,
                &OpenFlags {
                    desired_access: GENERIC_READ,
                    create_disposition: FILE_OPEN,
                    create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
                },
            )
            .map_err(win_err_to_linux)?,
        );

        let child_g = HandleGuard(
            open_relative(
                parent_g.as_raw(),
                name,
                &OpenFlags {
                    desired_access: GENERIC_READ | GENERIC_WRITE,
                    create_disposition: FILE_CREATE,
                    create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
                },
            )
            .map_err(win_err_to_linux)?,
        );

        if let Some(secctx) = extensions.secctx {
            let stream_name = format!(":{}", secctx.name.to_string_lossy());
            write_ads_by_handle(child_g.as_raw(), &stream_name, &secctx.secctx)?;
        }

        let stat_str = format!("{}:{}:0{:o}", ctx.uid, ctx.gid, mode & !umask);
        write_ads_by_handle(child_g.as_raw(), OVERRIDE_STAT_STREAM, stat_str.as_bytes())?;
        self.do_lookup(parent, name)
    }

    fn rmdir(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        let parent_data = self.inode_data(parent)?;
        let root_h = *self.root_handle.read().unwrap();
        let parent_g = HandleGuard(
            open_by_id(
                root_h,
                parent_data.file_index,
                &OpenFlags {
                    desired_access: GENERIC_READ,
                    create_disposition: FILE_OPEN,
                    create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
                },
            )
            .map_err(win_err_to_linux)?,
        );

        let child_g = HandleGuard(
            open_relative(
                parent_g.as_raw(),
                name,
                &OpenFlags {
                    desired_access: DELETE,
                    create_disposition: FILE_OPEN,
                    create_options: FILE_SYNCHRONOUS_IO_NONALERT
                        | FILE_DIRECTORY_FILE
                        | FILE_OPEN_REPARSE_POINT,
                },
            )
            .map_err(win_err_to_linux)?,
        );

        set_delete_disposition(child_g.as_raw()).map_err(win_err_to_linux)
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.fill_dir_cache(inode, handle)?;
        let caches = self.dir_caches.read().unwrap();
        let entries = caches.get(&handle).ok_or_else(ebadf)?;
        let entries = entries.lock().unwrap();

        for (i, de) in entries.iter().enumerate().skip(offset as usize) {
            let entry = DirEntry {
                ino: de.ino,
                offset: (i + 1) as u64,
                type_: de.type_,
                name: &de.name,
            };
            match add_entry(entry) {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "virtio-fs: error adding entry {}: {:?}",
                        String::from_utf8_lossy(&de.name),
                        e
                    );
                    break;
                }
            }
        }
        Ok(())
    }

    fn readdirplus<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.fill_dir_cache(inode, handle)?;
        let caches = self.dir_caches.read().unwrap();
        let entries = caches.get(&handle).ok_or_else(ebadf)?;
        let entries = entries.lock().unwrap();

        for (i, de) in entries.iter().enumerate().skip(offset as usize) {
            let name_cstr = match std::ffi::CString::new(de.name.clone()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let entry = match self.do_lookup(inode, &name_cstr) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let written = add_entry(
                DirEntry {
                    ino: entry.inode,
                    offset: (i + 1) as u64,
                    type_: de.type_,
                    name: &de.name,
                },
                entry,
            )?;
            if written == 0 {
                break;
            }
        }
        Ok(())
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(stat64, Duration)> {
        self.do_getattr(inode, handle)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        let path = self.inode_path(inode)?;

        // Extract or read current cached state cleanly to avoid overwriting conflicts
        let (mut current_uid, mut current_gid, mut current_mode) =
            read_override_stat(&path).unwrap_or((Some(u32::MAX), Some(u32::MAX), None));

        let mut override_changed = false;

        if valid.contains(SetattrValid::MODE) {
            current_mode = Some(attr.st_mode);
            override_changed = true;
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            if valid.contains(SetattrValid::UID) {
                current_uid = Some(attr.st_uid);
            }
            if valid.contains(SetattrValid::GID) {
                current_gid = Some(attr.st_gid);
            };

            remove_security_capability(&path);

            if !valid.contains(SetattrValid::MODE) {
                if let Some(mode) = current_mode {
                    let new_mode = clear_suid_sgid(mode);
                    current_mode = Some(new_mode);
                }
            }

            override_changed = true;
        }

        if valid.contains(SetattrValid::SIZE) {
            if let Some(h) = handle {
                // POSIX Compliance: Allocating space on a Read-Only FD should return EBADF
                if is_handle_read_only(h) {
                    return Err(ebadf());
                }

                let file = self
                    .reopen_inode(inode, h, GENERIC_READ | GENERIC_WRITE)
                    .map_err(win_err_to_linux)?;
                file.set_len(attr.st_size as u64)
                    .map_err(win_err_to_linux)?;
            } else {
                let file = fs::OpenOptions::new()
                    .write(true)
                    .open(&*path)
                    .map_err(win_err_to_linux)?;
                file.set_len(attr.st_size as u64)
                    .map_err(win_err_to_linux)?;
            }

            remove_security_capability(&path);

            if let Some(mode) = current_mode {
                let new_mode = clear_suid_sgid(mode);
                if new_mode != mode {
                    current_mode = Some(new_mode);
                    override_changed = true;
                }
            }
        }

        if override_changed {
            let owner_param = match (current_uid, current_gid) {
                (Some(u), Some(g)) => Some((u, g)),
                _ => None,
            };
            write_override_stat(&path, owner_param, current_mode)?;
        }

        if valid.intersects(
            SetattrValid::ATIME
                | SetattrValid::MTIME
                | SetattrValid::ATIME_NOW
                | SetattrValid::MTIME_NOW,
        ) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let now_ft = unix_to_filetime(now.as_secs() as i64, now.subsec_nanos());

            let atime = if valid.contains(SetattrValid::ATIME_NOW) {
                Some(now_ft)
            } else if valid.contains(SetattrValid::ATIME) {
                Some(unix_to_filetime(attr.st_atime, attr.st_atime_nsec))
            } else {
                None
            };

            let mtime = if valid.contains(SetattrValid::MTIME_NOW) {
                Some(now_ft)
            } else if valid.contains(SetattrValid::MTIME) {
                Some(unix_to_filetime(attr.st_mtime, attr.st_mtime_nsec))
            } else {
                None
            };
            set_file_times(&path, atime, mtime).map_err(win_err_to_linux)?;
        }

        self.do_getattr(inode, handle)
    }
}
