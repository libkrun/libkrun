// Windows passthrough filesystem — inspired by the macOS implementation.
// Uses NTFS file index + volume serial for inode identity and
// Alternate Data Streams (ADS) for extended-attribute emulation.

use super::super::inode_alloc::InodeAllocator;
pub use super::super::{CachePolicy, PermissionSemantics};
use std::collections::BTreeMap;
use std::ffi::{CStr, OsString};
use std::fs::{self, File};
use std::io;
use std::mem::{self, ManuallyDrop};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::S_IFREG;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_ACCESS_INFORMATION, FILE_ALL_INFORMATION, FILE_CREATE, FILE_DIRECTORY_FILE,
    FILE_DISPOSITION_INFORMATION, FILE_ID_BOTH_DIR_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_BY_FILE_ID, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_OVERWRITE, FILE_OVERWRITE_IF,
    FILE_STAT_INFORMATION, FILE_STAT_LX_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    FileAccessInformation, FileAllInformation, FileAttributeTagInformation,
    FileDispositionInformation, FileIdBothDirectoryInformation, FileStatInformation,
    FileStatLxInformation, IO_REPARSE_TAG_LX_SYMLINK, LX_FILE_METADATA_HAS_GID,
    LX_FILE_METADATA_HAS_MODE, LX_FILE_METADATA_HAS_UID, NtCreateFile, NtQueryDirectoryFile,
    NtQueryInformationByName, NtQueryInformationFile, NtSetEaFile, NtSetInformationFile,
    NtWriteFile, RtlNtStatusToDosErrorNoTeb,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME,
    ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
    STATUS_BUFFER_OVERFLOW, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER, STATUS_NO_MORE_FILES, STATUS_NOT_IMPLEMENTED, STATUS_NOT_SUPPORTED,
    UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DeleteFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_BASIC_INFO, FILE_END_OF_FILE_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    FileBasicInfo, FileEndOfFileInfo, GetDiskFreeSpaceExW, GetVolumeInformationByHandleW,
    GetVolumePathNameW, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
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

const OVERRIDE_STAT_STREAM: &str = ":user.containers.override_stat";
const SECURITY_CAPABILITY_STREAM: &str = ":security.capability";

const UID_MAX: u32 = u32::MAX - 1;

const SYNCHRONIZE: u32 = 0x0010_0000;
const DELETE: u32 = 0x0001_0000;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
// IO_STATUS_BLOCK.Information after NtCreateFile made a new file.
const FILE_CREATED: usize = 2;

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
    volume_serial: u32,
    // Children of a junction or volume mount point may live on another volume.
    is_mount_point: bool,
    path: RwLock<Arc<PathBuf>>,
    wide_path: RwLock<Arc<Vec<u16>>>,
    refcount: AtomicU64,
    // Set once a write has dropped the capability stream and the suid/sgid bits, so the
    // guest's kill-priv flag on every later write costs no host I/O. Only this server
    // writes `override_stat` and the guest cannot set `security.capability`, so only
    // `setattr` can bring them back; a host process editing the streams directly is
    // not noticed until the inode is forgotten.
    privs_dropped: AtomicBool,
    // The stored owner and mode as last read, with the entry's ChangeTime then.
    override_stat: Mutex<Option<(i64, OverrideStat)>>,
}

impl InodeData {
    /// The stored owner and mode of this entry, whose ChangeTime is `change_time`, calling
    /// `read` when it has to be read from the host.
    fn override_stat(&self, change_time: i64, read: impl FnOnce() -> OverrideStat) -> OverrideStat {
        let mut cached = self.override_stat.lock().unwrap();
        if let Some((cached_at, value)) = *cached
            && cached_at == change_time
        {
            return value;
        }
        let value = read();
        // Writing metadata moves ChangeTime only to the next timestamp tick, so a change
        // made in the tick this was read in would go unnoticed: keep only what was read
        // once ChangeTime had settled.
        *cached =
            (filetime_now() - change_time >= SETTLED_CHANGE_TIME).then_some((change_time, value));
        value
    }

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

    /// The permission semantics to be emulated. See the documentation for `PermissionSemantics` for
    /// more details.
    pub semantics: PermissionSemantics,
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
            semantics: PermissionSemantics::LinuxComplete,
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

/// Refuse a name a request carried that is not a single entry of a directory.
///
/// Windows reads `\` as a path separator, and `Path::join` keeps only the drive of a name that
/// has a root, so a name holding one reaches an entry the request did not name — one outside
/// the shared directory at that. A `:` names an alternate data stream of another entry rather
/// than an entry of its own.
fn check_name(name: &CStr) -> io::Result<()> {
    let bytes = name.to_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|b| matches!(b, b'\\' | b'/' | b':'))
    {
        return Err(einval());
    }
    Ok(())
}

fn child_path(parent: &Path, name: &CStr) -> io::Result<PathBuf> {
    check_name(name)?;
    Ok(parent.join(cstr_to_path(name)))
}

/// Refuse a symlink target that resolves outside the shared directory from a link made `depth`
/// directories below the shared root.
///
/// A host program that opens the link follows it, reading the target as a Windows path: `\` is
/// a separator, `:` names a drive or a stream, a target starting with `/` starts at the root of
/// a drive, and Win32 drops the trailing dots and spaces of a component, so a component made
/// only of them does not name what it spells.
fn check_symlink_target(target: &CStr, mut depth: usize) -> io::Result<()> {
    let bytes = target.to_bytes();
    if bytes.first() == Some(&b'/') || bytes.iter().any(|b| matches!(b, b'\\' | b':')) {
        return Err(einval());
    }
    for component in bytes.split(|b| *b == b'/') {
        match component {
            b"" | b"." => {}
            b".." => depth = depth.checked_sub(1).ok_or_else(einval)?,
            _ if component.iter().all(|b| matches!(b, b'.' | b' ')) => return Err(einval()),
            _ => depth += 1,
        }
    }
    Ok(())
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

type FileInfo = FILE_STAT_INFORMATION;

/// `(uid, gid, mode)` as stored for an entry.
type OverrideStat = (Option<u32>, Option<u32>, Option<u32>);

/// What a caller already knows of an entry's stored ownership and mode.
#[derive(Clone, Copy)]
enum Stored {
    /// Just written, or queried along with the entry's attributes.
    Known(OverrideStat),
    /// The entry has no WSL metadata extended attributes, so only the override_stat stream,
    /// written where those cannot be, can hold them.
    NotInAttributes,
    Unknown,
}

/// How long after its last change an entry's stored owner and mode are trusted to stay as read:
/// one second, in FILETIME units.
const SETTLED_CHANGE_TIME: i64 = 10_000_000;

fn filetime_now() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    unix_to_filetime(now.as_secs() as i64, now.subsec_nanos()) as i64
}

fn query_information<T>(handle: HANDLE, info: &mut T, class: i32) -> NTSTATUS {
    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    unsafe {
        NtQueryInformationFile(
            handle,
            &mut iosb,
            info as *mut T as *mut core::ffi::c_void,
            mem::size_of::<T>() as u32,
            class,
        )
    }
}

// Borrows the handle. The caller is responsible for closing it.
fn get_file_info_by_handle(handle: HANDLE) -> io::Result<FileInfo> {
    let mut info = FileInfo::default();
    match query_information(handle, &mut info, FileStatInformation) {
        status if status >= 0 => Ok(info),
        // FAT, exFAT and some network redirectors don't implement FileStatInformation.
        STATUS_INVALID_INFO_CLASS
        | STATUS_NOT_IMPLEMENTED
        | STATUS_NOT_SUPPORTED
        | STATUS_INVALID_PARAMETER => get_file_info_by_handle_compat(handle),
        status => Err(nt_status_to_io_error(status)),
    }
}

/// Query `path` without opening it, which costs a fraction of an open, query and close.
/// Like an open with `FILE_OPEN_REPARSE_POINT`, a reparse point describes itself, not its
/// target. `None` when the file system cannot answer by name.
fn get_file_info_by_name(path: &Path) -> io::Result<Option<FileInfo>> {
    query_information_by_name(path, FileStatInformation)
}

/// As `get_file_info_by_name`, with the WSL metadata extended attributes.
fn get_lx_info_by_name(path: &Path) -> io::Result<Option<FILE_STAT_LX_INFORMATION>> {
    query_information_by_name(path, FileStatLxInformation)
}

/// `path`'s attributes and the ownership and mode its WSL metadata extended attributes hold,
/// queried by name. `None` when the file system cannot answer by name.
fn query_by_name(path: &Path) -> io::Result<Option<(FileInfo, Option<OverrideStat>)>> {
    let lx = match get_lx_info_by_name(path) {
        Ok(lx) => lx,
        // A missing name is the common failure and the plain query would only repeat it;
        // any other may be the file system refusing just this information class.
        Err(e) if is_missing(&e) => return Err(e),
        Err(_) => None,
    };
    if let Some(lx) = lx {
        let info = FileInfo {
            FileId: lx.FileId,
            CreationTime: lx.CreationTime,
            LastAccessTime: lx.LastAccessTime,
            LastWriteTime: lx.LastWriteTime,
            ChangeTime: lx.ChangeTime,
            AllocationSize: lx.AllocationSize,
            EndOfFile: lx.EndOfFile,
            FileAttributes: lx.FileAttributes,
            ReparseTag: lx.ReparseTag,
            NumberOfLinks: lx.NumberOfLinks,
            EffectiveAccess: lx.EffectiveAccess,
        };
        return Ok(Some((info, lx_metadata(&lx))));
    }
    Ok(get_file_info_by_name(path)?.map(|info| (info, None)))
}

fn is_missing(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(code)
        if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32)
}

/// `T` must be the plain-data structure `class` fills.
fn query_information_by_name<T>(path: &Path, class: i32) -> io::Result<Option<T>> {
    let mut nt_path = path_to_nt_wide(path);
    let byte_len = (nt_path.len() - 1) * 2;
    let mut us = UNICODE_STRING {
        Length: byte_len as u16,
        MaximumLength: (byte_len + 2) as u16,
        Buffer: nt_path.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut us,
        Attributes: 0,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let mut info: T = unsafe { mem::zeroed() };
    let status = unsafe {
        NtQueryInformationByName(
            &oa,
            &mut iosb,
            &mut info as *mut T as *mut core::ffi::c_void,
            mem::size_of::<T>() as u32,
            class,
        )
    };
    match status {
        status if status >= 0 => Ok(Some(info)),
        // Network redirectors and third-party file systems refuse an unsupported class
        // with any of these.
        STATUS_INVALID_INFO_CLASS
        | STATUS_NOT_IMPLEMENTED
        | STATUS_NOT_SUPPORTED
        | STATUS_INVALID_PARAMETER
        | STATUS_INVALID_DEVICE_REQUEST => Ok(None),
        status => Err(nt_status_to_io_error(status)),
    }
}

fn get_file_info_by_handle_compat(handle: HANDLE) -> io::Result<FileInfo> {
    let mut all: FILE_ALL_INFORMATION = unsafe { mem::zeroed() };
    // The trailing file name never fits; the fixed-size parts are still filled in.
    let status = query_information(handle, &mut all, FileAllInformation);
    if status < 0 && status != STATUS_BUFFER_OVERFLOW {
        return Err(nt_status_to_io_error(status));
    }

    let basic = &all.BasicInformation;
    let standard = &all.StandardInformation;
    let mut tag_info: FILE_ATTRIBUTE_TAG_INFO = unsafe { mem::zeroed() };
    if basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        let status = query_information(handle, &mut tag_info, FileAttributeTagInformation);
        if status < 0 {
            return Err(nt_status_to_io_error(status));
        }
    }

    Ok(FileInfo {
        FileId: all.InternalInformation.IndexNumber,
        CreationTime: basic.CreationTime,
        LastAccessTime: basic.LastAccessTime,
        LastWriteTime: basic.LastWriteTime,
        ChangeTime: basic.ChangeTime,
        AllocationSize: standard.AllocationSize,
        EndOfFile: standard.EndOfFile,
        FileAttributes: basic.FileAttributes,
        ReparseTag: tag_info.ReparseTag,
        NumberOfLinks: standard.NumberOfLinks,
        EffectiveAccess: all.AccessInformation.AccessFlags,
    })
}

fn get_volume_serial_by_handle(handle: HANDLE) -> io::Result<u32> {
    let mut serial = 0u32;
    let res = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            ptr::null_mut(),
            0,
            &mut serial,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    };
    if res == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(serial)
    }
}

fn as_file_handle(handle: Handle) -> Option<HANDLE> {
    (handle != 0 && (handle & (1 << 63)) == 0).then_some(handle as HANDLE)
}

/// The access rights granted to `handle`.
fn handle_access(handle: HANDLE) -> Option<u32> {
    let mut access_info: FILE_ACCESS_INFORMATION = unsafe { mem::zeroed() };
    (query_information(handle, &mut access_info, FileAccessInformation) >= 0)
        .then_some(access_info.AccessFlags)
}

pub fn is_handle_read_only(handle: u64) -> bool {
    // Ignore directory entries
    let Some(raw_handle) = as_file_handle(handle) else {
        return true;
    };

    // If the handle lacks both standard WRITE and APPEND permissions, it was opened Read-Only.
    // If the kernel query fails for some reason, assume it's writable to let standard error
    // handling catch any violations later.
    handle_access(raw_handle)
        .is_some_and(|access| access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == 0)
}

fn build_stat64(
    ctx: &Context,
    semantics: PermissionSemantics,
    info: &FileInfo,
    ino: u64,
    handle: Option<HANDLE>,
    override_stat: Option<OverrideStat>,
) -> stat64 {
    let file_attributes = info.FileAttributes;

    let is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    let is_reparse = (file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

    // If it's a reparse point and not a mount point, it's a symlink
    let is_symlink = is_reparse && info.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT;

    let mut size = info.EndOfFile;

    let stored_mode = override_stat.and_then(|(_, _, mode)| mode);

    let (base_mode, nlink) = if is_symlink {
        if let Some(Ok(target)) = handle.map(read_lx_symlink_by_handle) {
            // st_size MUST match the exact length returned by readlink()
            size = target.len() as i64;
        }
        (S_IFLNK as u32 | 0o777, 1u32)
    } else if is_directory {
        let mode_bits = match semantics {
            PermissionSemantics::LinuxSimplified
            | PermissionSemantics::LinuxSimplifiedFixedOwner => {
                stored_mode.map_or(0o755, |mode| mode & 0o777)
            }
            PermissionSemantics::LinuxComplete => 0o755,
        };
        (libc::S_IFDIR as u32 | mode_bits, 2u32)
    } else {
        let is_readonly = (file_attributes & FILE_ATTRIBUTE_READONLY) != 0;
        let mode_bits = match semantics {
            PermissionSemantics::LinuxSimplified
            | PermissionSemantics::LinuxSimplifiedFixedOwner => {
                // The Read-Only attribute decides writability, so the stored
                // owner-write bit gives way to it; every other permission bit
                // a chmod keeps is reported as stored.
                let write = if is_readonly { 0 } else { 0o200 };
                match stored_mode {
                    Some(mode) => write | (mode & 0o777 & !0o200),
                    None if is_readonly => 0o444,
                    None => 0o644,
                }
            }
            PermissionSemantics::LinuxComplete => 0o644,
        };
        (libc::S_IFREG as u32 | mode_bits, info.NumberOfLinks)
    };

    let access = info.LastAccessTime as u64;
    let write = info.LastWriteTime as u64;
    let change = info.ChangeTime as u64;

    let mut st = stat64 {
        st_dev: 0,
        st_ino: ino,
        st_nlink: nlink,
        st_mode: base_mode,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: size,
        st_atime: filetime_to_unix_secs(access),
        st_atime_nsec: filetime_to_unix_nsec(access),
        st_mtime: filetime_to_unix_secs(write),
        st_mtime_nsec: filetime_to_unix_nsec(write),
        st_ctime: filetime_to_unix_secs(change),
        st_ctime_nsec: filetime_to_unix_nsec(change),
        st_blksize: 4096,
        st_blocks: (size + 511) / 512,
    };

    match semantics {
        PermissionSemantics::LinuxSimplified | PermissionSemantics::LinuxSimplifiedFixedOwner => {
            st.st_uid = ctx.uid;
            st.st_gid = ctx.gid;
        }
        PermissionSemantics::LinuxComplete => {
            if let Some((uid, gid, mode)) = override_stat {
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
        }
    }

    st
}

fn read_lx_symlink_by_handle(handle: HANDLE) -> io::Result<Vec<u8>> {
    let mut buffer = [0u8; 16384];
    let mut bytes_returned = 0u32;

    let result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if result == 0 || bytes_returned < 8 {
        return Err(io::Error::last_os_error());
    }

    // Inspect ReparseTag (first 4 bytes)
    let tag = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    if tag != IO_REPARSE_TAG_LX_SYMLINK as u32 {
        return Err(io::Error::other("Not an LX_SYMLINK reparse point"));
    }

    let data_len = u16::from_le_bytes(buffer[4..6].try_into().unwrap()) as usize;
    if bytes_returned < (8 + data_len) as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Truncated LX_SYMLINK payload",
        ));
    }

    // Target UTF-8 bytes start at offset 8
    Ok(buffer[8..8 + data_len].to_vec())
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

fn format_override_stat((uid, gid, mode): OverrideStat) -> String {
    let field = |value: Option<u32>, format: fn(u32) -> String| value.map_or("x".into(), format);
    format!(
        "{}:{}:{}",
        field(uid, |u| u.to_string()),
        field(gid, |g| g.to_string()),
        field(mode, |m| format!("0{m:o}")),
    )
}

fn write_override_stream(path: &Path, stat: OverrideStat) -> io::Result<()> {
    let ads = ads_stream_path(path, OVERRIDE_STAT_STREAM);
    fs::write(&ads, format_override_stat(stat)).map_err(win_err_to_linux)
}

/// Where an entry's ownership and mode are stored.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StoredIn {
    Attributes,
    Stream,
    Nowhere,
}

/// The ownership and mode the WSL metadata extended attributes of `lx` hold, if any.
fn lx_metadata(lx: &FILE_STAT_LX_INFORMATION) -> Option<OverrideStat> {
    let has = |flag| lx.LxFlags & flag != 0;
    (has(LX_FILE_METADATA_HAS_UID)
        || has(LX_FILE_METADATA_HAS_GID)
        || has(LX_FILE_METADATA_HAS_MODE))
    .then(|| {
        (
            has(LX_FILE_METADATA_HAS_UID).then_some(lx.LxUid),
            has(LX_FILE_METADATA_HAS_GID).then_some(lx.LxGid),
            has(LX_FILE_METADATA_HAS_MODE).then_some(lx.LxMode),
        )
    })
}

/// The ownership and mode stored for the entry at `path`: its WSL metadata extended
/// attributes, or else the override_stat stream that keeps them where those cannot be written.
fn read_metadata(path: &Path) -> (OverrideStat, StoredIn) {
    if let Ok(Some(lx)) = get_lx_info_by_name(path)
        && let Some(stored) = lx_metadata(&lx)
    {
        return (stored, StoredIn::Attributes);
    }
    match read_override_stat(path).unwrap_or((None, None, None)) {
        (None, None, None) => ((None, None, None), StoredIn::Nowhere),
        stored => (stored, StoredIn::Stream),
    }
}

/// Set the WSL metadata extended attributes of the entry at `path` for the values given,
/// leaving the others alone.
fn write_lx_metadata(path: &Path, stat: OverrideStat) -> io::Result<()> {
    let h = HandleGuard(open_handle(
        path,
        &OpenFlags {
            desired_access: FILE_WRITE_EA,
            create_disposition: FILE_OPEN,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        },
    )?);
    set_lx_metadata(h.as_raw(), stat)
}

/// As `write_lx_metadata`, through `handle`, which needs `FILE_WRITE_EA` access.
fn set_lx_metadata(handle: HANDLE, (uid, gid, mode): OverrideStat) -> io::Result<()> {
    let attributes: Vec<(&[u8], u32)> = [
        (b"$LXUID".as_slice(), uid),
        (b"$LXGID".as_slice(), gid),
        (b"$LXMOD".as_slice(), mode),
    ]
    .into_iter()
    .filter_map(|(name, value)| Some((name, value?)))
    .collect();

    // A FILE_FULL_EA_INFORMATION list: each entry is NextEntryOffset, Flags, EaNameLength,
    // EaValueLength, the NUL-terminated name and the value, padded to 4 bytes but the last.
    let mut buf = Vec::new();
    for (i, (name, value)) in attributes.iter().enumerate() {
        let start = buf.len();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0);
        buf.push(name.len() as u8);
        buf.extend_from_slice(&(mem::size_of::<u32>() as u16).to_le_bytes());
        buf.extend_from_slice(name);
        buf.push(0);
        buf.extend_from_slice(&value.to_le_bytes());
        if i + 1 < attributes.len() {
            buf.resize(buf.len().next_multiple_of(4), 0);
            let next = (buf.len() - start) as u32;
            buf[start..start + 4].copy_from_slice(&next.to_le_bytes());
        }
    }

    let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let status = unsafe {
        NtSetEaFile(
            handle,
            &mut iosb,
            buf.as_ptr() as *const core::ffi::c_void,
            buf.len() as u32,
        )
    };
    if status < 0 {
        Err(nt_status_to_io_error(status))
    } else {
        Ok(())
    }
}

/// Store ownership and mode for the entry at `path`, whose current ones were read as
/// `stored_in`. They go to the WSL metadata extended attributes, which the by-name query a
/// lookup makes returns for free. When those cannot be written, the override_stat stream
/// keeps them instead, unless extended attributes already hold values it would not override.
fn write_metadata(path: &Path, stat: OverrideStat, stored_in: StoredIn) -> io::Result<()> {
    match write_lx_metadata(path, stat) {
        Ok(()) => Ok(()),
        Err(e) if stored_in == StoredIn::Attributes => Err(win_err_to_linux(e)),
        Err(e) => {
            debug!("WSL metadata of {}: {e}, using the stream", path.display());
            write_override_stream(path, stat)
        }
    }
}

/// As `write_metadata`, for an entry just created at `path`, and still open as `handle` when
/// given.
fn write_new_metadata(path: &Path, handle: Option<HANDLE>, stat: OverrideStat) -> io::Result<()> {
    let result = match handle {
        Some(h) => match set_lx_metadata(h, stat) {
            // A handle opened for reading only lacks FILE_WRITE_EA.
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                write_lx_metadata(path, stat)
            }
            result => result,
        },
        None => write_lx_metadata(path, stat),
    };
    let Err(e) = result else { return Ok(()) };
    debug!("WSL metadata of {}: {e}, using the stream", path.display());
    match handle {
        Some(h) => write_ads_by_handle(
            h,
            OVERRIDE_STAT_STREAM,
            format_override_stat(stat).as_bytes(),
        ),
        None => write_override_stream(path, stat),
    }
}

/// Delete the ADS stream that emulates `security.capability`. Returns whether the stream
/// is gone, including when it never existed.
fn remove_security_capability(path: &Path) -> bool {
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
            return false;
        }
    }
    true
}

/// Open an ADS stream relative to an open file/directory handle, which spares resolving the
/// entry's path again. `stream_suffix` must include the leading colon, e.g. `":stat"`.
fn open_ads_by_handle(
    file_handle: HANDLE,
    stream_suffix: &str,
    desired_access: u32,
    create_disposition: u32,
) -> io::Result<HANDLE> {
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
            desired_access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            create_disposition,
            FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };

    if status < 0 {
        Err(nt_status_to_io_error(status))
    } else {
        Ok(h)
    }
}

/// Write data to an ADS stream relative to an open file/directory handle.
/// `stream_suffix` must include the leading colon, e.g. `":stat"`.
fn write_ads_by_handle(file_handle: HANDLE, stream_suffix: &str, data: &[u8]) -> io::Result<()> {
    let h = open_ads_by_handle(file_handle, stream_suffix, GENERIC_WRITE, FILE_OVERWRITE_IF)?;

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

/// Store a security context as an ADS named after `secctx.name`.
/// When `symlink` is true, opens with `FILE_OPEN_REPARSE_POINT` so the
/// ADS is placed on the symlink itself rather than following to the target.
fn write_secctx(path: &Path, secctx: SecContext, symlink: bool) -> io::Result<()> {
    let stream_name = format!(":{}", secctx.name.to_string_lossy());
    let ads = ads_stream_path(path, &stream_name);

    if symlink {
        let h = open_handle(
            &ads,
            &OpenFlags {
                desired_access: GENERIC_WRITE,
                create_disposition: FILE_OVERWRITE_IF,
                create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            },
        )
        .map_err(win_err_to_linux)?;

        let mut iosb: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
        let status = unsafe {
            NtWriteFile(
                h,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                &mut iosb,
                secctx.secctx.as_ptr() as *const core::ffi::c_void,
                secctx.secctx.len() as u32,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        unsafe { CloseHandle(h) };

        if status >= 0 {
            Ok(())
        } else {
            Err(nt_status_to_io_error(status))
        }
    } else {
        fs::write(&ads, &secctx.secctx).map_err(win_err_to_linux)
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

// ADS-backed generic xattr helpers
fn ads_xattr_path(base: &Path, name: &CStr) -> PathBuf {
    let attr_name = name.to_string_lossy();
    let mut s = base.as_os_str().to_os_string();
    s.push(format!(":{}", attr_name));
    PathBuf::from(s)
}

/// Refuse an xattr name that does not name a stream of its own.
///
/// An xattr is a stream appended to the entry's path after a `:`, so a name holding one more
/// reaches a stream the request did not name — `:$DATA` is the entry's own contents — and a name
/// holding a separator reaches the streams of another entry. Windows drops the dots and spaces
/// that end a path before NTFS sees it, so a name ending in either reaches the stream named
/// without them.
fn check_xattr_name(name: &CStr) -> io::Result<()> {
    let bytes = name.to_bytes();
    if bytes.is_empty()
        || bytes.iter().any(|b| matches!(b, b'\\' | b'/' | b':'))
        || matches!(bytes.last(), Some(b'.' | b' '))
    {
        return Err(einval());
    }
    Ok(())
}

/// Whether a name reaches a stream this backend keeps for itself. NTFS matches a stream name
/// without regard to case, so this comparison cannot either.
fn is_reserved_xattr(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"user.containers.override_stat")
        || name.eq_ignore_ascii_case(b"security.capability")
}

fn ads_list_streams(path: &Path) -> io::Result<Vec<String>> {
    use windows_sys::Win32::Storage::FileSystem::*;

    let wide = path_to_wide(path);
    let mut fsd: WIN32_FIND_STREAM_DATA = unsafe { mem::zeroed() };
    let h = unsafe {
        FindFirstStreamW(
            wide.as_ptr(),
            FindStreamInfoStandard,
            &mut fsd as *mut _ as *mut _,
            0,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(38) {
            return Ok(Vec::new());
        }
        return Err(e);
    }

    let mut out = Vec::new();
    loop {
        let len = fsd
            .cStreamName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(fsd.cStreamName.len());
        let name = OsString::from_wide(&fsd.cStreamName[..len])
            .to_string_lossy()
            .to_string();

        if name != "::$DATA"
            && let Some(stripped) = name.strip_prefix(':')
            && let Some(attr) = stripped.strip_suffix(":$DATA")
            && !attr.is_empty()
        {
            out.push(attr.to_string());
        }

        if unsafe { FindNextStreamW(h, &mut fsd as *mut _ as *mut _) } == 0 {
            break;
        }
    }
    unsafe {
        FindClose(h);
    }
    Ok(out)
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
        1 => access |= GENERIC_WRITE | FILE_READ_ATTRIBUTES,
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
    open_handle_reporting_creation(path, flags).map(|(h, _)| h)
}

/// Like `open_handle`, also telling whether the call created the file.
fn open_handle_reporting_creation(path: &Path, flags: &OpenFlags) -> io::Result<(HANDLE, bool)> {
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
        Ok((handle, iosb.Information == FILE_CREATED))
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
    // The callers pass this function's errors through win_err_to_linux, so a refused name is
    // reported as the Windows code that it maps to EINVAL.
    if check_name(name).is_err() {
        return Err(io::Error::from_raw_os_error(ERROR_INVALID_NAME as i32));
    }
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

/// Duplicate a handle within this process, with the same access rights.
fn duplicate_handle(handle: HANDLE) -> io::Result<HANDLE> {
    const DUPLICATE_SAME_ACCESS: u32 = 2;
    let current_process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
    let mut dup_h: HANDLE = INVALID_HANDLE_VALUE;

    let res = unsafe {
        windows_sys::Win32::Foundation::DuplicateHandle(
            current_process,
            handle,
            current_process,
            &mut dup_h,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };

    if res != 0 {
        Ok(dup_h)
    } else {
        Err(io::Error::last_os_error())
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

    let info = match get_file_info_by_handle(h) {
        Ok(info) => info,
        Err(e) => {
            unsafe { CloseHandle(h) };
            return Err(e);
        }
    };
    if (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        unsafe { CloseHandle(h) };
        return Err(linux_error(io::Error::other(
            "Reparse point detected — path is not safe",
        )));
    }
    Ok(h)
}

/// Set file attributes together with access and modification times in a
/// single metadata update. `None` leaves the corresponding field untouched.
fn set_file_basic_info(
    h: HANDLE,
    attributes: Option<u32>,
    atime: Option<u64>,
    mtime: Option<u64>,
) -> io::Result<()> {
    let info = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: atime.map_or(0, |v| v as i64),
        LastWriteTime: mtime.map_or(0, |v| v as i64),
        ChangeTime: 0,
        // Zero means "unchanged" here, so an empty attribute set must be
        // spelled FILE_ATTRIBUTE_NORMAL.
        FileAttributes: match attributes {
            Some(0) => FILE_ATTRIBUTE_NORMAL,
            Some(attrs) => attrs,
            None => 0,
        },
    };

    let res = unsafe {
        SetFileInformationByHandle(
            h,
            FileBasicInfo,
            &info as *const _ as *const core::ffi::c_void,
            mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if res == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_file_size_by_handle(h: HANDLE, size: i64) -> io::Result<()> {
    let info = FILE_END_OF_FILE_INFO { EndOfFile: size };
    let res = unsafe {
        SetFileInformationByHandle(
            h,
            FileEndOfFileInfo,
            &info as *const _ as *const core::ffi::c_void,
            mem::size_of::<FILE_END_OF_FILE_INFO>() as u32,
        )
    };
    if res == 0 {
        Err(io::Error::last_os_error())
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
    /// File IDs only resolve on this volume.
    root_volume_serial: u32,

    writeback: AtomicBool,
    announce_submounts: AtomicBool,
    cfg: Config,

    /// Guest file handles currently open, per inode.
    open_files: Mutex<BTreeMap<Inode, Vec<Handle>>>,
}

// Windows HANDLEs (*mut c_void) are thread-safe to move and share across OS threads.
unsafe impl Send for PassthroughFs {}
unsafe impl Sync for PassthroughFs {}

impl PassthroughFs {
    pub fn new(cfg: Config, inode_alloc: Arc<InodeAllocator>) -> io::Result<Self> {
        let root_handle = openat(&cfg.root_dir)?;
        let root_volume_serial = match get_volume_serial_by_handle(root_handle) {
            Ok(serial) => serial,
            Err(e) => {
                unsafe { CloseHandle(root_handle) };
                return Err(e);
            }
        };

        Ok(PassthroughFs {
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            inode_alloc,
            next_handle: AtomicU64::new(1),
            dir_caches: RwLock::new(BTreeMap::new()),
            root_handle: RwLock::new(root_handle),
            root_volume_serial,
            writeback: AtomicBool::new(false),
            announce_submounts: AtomicBool::new(false),
            cfg,
            open_files: Mutex::new(BTreeMap::new()),
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

    /// Open an inode by file ID when it lives on the root's volume, by path
    /// otherwise.
    fn open_inode(&self, data: &InodeData, flags: &OpenFlags) -> io::Result<HANDLE> {
        if data.volume_serial == self.root_volume_serial {
            let root_h = *self.root_handle.read().unwrap();
            open_by_id(root_h, data.file_index, flags)
                .or_else(|_| open_handle(&data.get_path(), flags))
        } else {
            open_handle(&data.get_path(), flags)
        }
    }

    fn inode_path(&self, inode: Inode) -> io::Result<Arc<PathBuf>> {
        Ok(self.inode_data(inode)?.get_path())
    }

    /// The attributes of `data`, from `info` queried on `handle`, or by name when there is no
    /// handle.
    fn attr_of(
        &self,
        ctx: &Context,
        data: &InodeData,
        info: &FileInfo,
        handle: Option<HANDLE>,
        stored: Stored,
    ) -> stat64 {
        let override_stat = match stored {
            Stored::Known(stat) => Some(stat),
            Stored::NotInAttributes => Some(data.override_stat(info.ChangeTime, || {
                read_override_stat(&data.get_path()).unwrap_or((None, None, None))
            })),
            Stored::Unknown => {
                Some(data.override_stat(info.ChangeTime, || read_metadata(&data.get_path()).0))
            }
        };
        build_stat64(
            ctx,
            self.cfg.semantics,
            info,
            data.inode,
            handle,
            override_stat,
        )
    }

    /// Drop the capability stream and the suid/sgid bits, as a write or truncating open by
    /// an unprivileged guest process requires.
    fn kill_priv(&self, data: &InodeData) {
        if !matches!(self.cfg.semantics, PermissionSemantics::LinuxComplete)
            || data.privs_dropped.swap(true, Ordering::Relaxed)
        {
            return;
        }

        let path = data.get_path();
        let mut dropped = remove_security_capability(&path);
        if let ((uid, gid, Some(mode)), stored_in) = read_metadata(&path) {
            let new_mode = clear_suid_sgid(mode);
            if new_mode != mode
                && let Err(e) = write_metadata(&path, (uid, gid, Some(new_mode)), stored_in)
            {
                error!("clear suid/sgid for inode {}: {e}", data.inode);
                dropped = false;
            }
        }
        if !dropped {
            data.privs_dropped.store(false, Ordering::Relaxed);
        }
    }

    fn do_lookup(&self, ctx: &Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let name_bytes = name.to_bytes();
        if name_bytes == b"." {
            let (attr, _) = self.do_getattr(ctx, parent, None)?;
            return Ok(Entry {
                inode: parent,
                generation: 0,
                attr,
                attr_flags: 0,
                attr_timeout: self.cfg.attr_timeout,
                entry_timeout: self.cfg.entry_timeout,
            });
        }
        if name_bytes == b".." {
            let parent_data = self.inode_data(parent)?;
            let grand_parent = parent_data.parent_inode;
            let (attr, _) = self.do_getattr(ctx, grand_parent, None)?;
            return Ok(Entry {
                inode: grand_parent,
                generation: 0,
                attr,
                attr_flags: 0,
                attr_timeout: self.cfg.attr_timeout,
                entry_timeout: self.cfg.entry_timeout,
            });
        }
        let parent_data = self.inode_data(parent)?;
        let child_path = child_path(parent_data.get_path().as_path(), name)?;

        // A child of a mount point needs a handle to learn its volume, and a symlink one to
        // read its target.
        if !parent_data.is_mount_point
            && let Some((info, stored)) = query_by_name(&child_path).map_err(win_err_to_linux)?
            && info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        {
            return self.entry_from_info(
                ctx,
                parent,
                &parent_data,
                &child_path,
                &info,
                parent_data.volume_serial,
                None,
                stored.map_or(Stored::NotInAttributes, Stored::Known),
            );
        }

        let flags = OpenFlags {
            desired_access: FILE_READ_ATTRIBUTES,
            create_disposition: FILE_OPEN,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        };
        let handle = HandleGuard(open_handle(&child_path, &flags).map_err(win_err_to_linux)?);
        self.entry_from_handle(
            ctx,
            parent,
            &parent_data,
            &child_path,
            handle.as_raw(),
            None,
        )
    }

    /// Register the child opened as `handle` and build its entry. `handle`
    /// must refer to `child_path` itself, not to a reparse point's target.
    /// `known_override` spares reading back an override_stat just written.
    fn entry_from_handle(
        &self,
        ctx: &Context,
        parent: Inode,
        parent_data: &InodeData,
        child_path: &Path,
        handle: HANDLE,
        known_override: Option<OverrideStat>,
    ) -> io::Result<Entry> {
        let file_info = get_file_info_by_handle(handle).map_err(win_err_to_linux)?;
        let volume_serial = if parent_data.is_mount_point {
            // Fail rather than guess: a wrong serial would let file indexes
            // from two volumes collide in the inode map.
            get_volume_serial_by_handle(handle).map_err(win_err_to_linux)?
        } else {
            parent_data.volume_serial
        };
        self.entry_from_info(
            ctx,
            parent,
            parent_data,
            child_path,
            &file_info,
            volume_serial,
            Some(handle),
            known_override.map_or(Stored::Unknown, Stored::Known),
        )
    }

    /// Register the child described by `file_info` and build its entry.
    #[allow(clippy::too_many_arguments)]
    fn entry_from_info(
        &self,
        ctx: &Context,
        parent: Inode,
        parent_data: &InodeData,
        child_path: &Path,
        file_info: &FileInfo,
        volume_serial: u32,
        handle: Option<HANDLE>,
        stored: Stored,
    ) -> io::Result<Entry> {
        let alt_key = InodeAltKey {
            file_index: file_info.FileId as u64,
            volume_serial,
        };

        let data = {
            let handle_existing = |existing: &Arc<InodeData>| {
                existing.refcount.fetch_add(1, Ordering::Acquire);
                existing.update_path_if_changed(child_path);
                Arc::clone(existing)
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
                    let data = Arc::new(InodeData {
                        inode,
                        parent_inode: parent,
                        file_index: file_info.FileId as u64,
                        volume_serial,
                        is_mount_point: file_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
                            != 0
                            && file_info.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT,
                        path: RwLock::new(Arc::new(child_path.to_path_buf())),
                        wide_path: RwLock::new(Arc::new(path_to_wide(child_path))),
                        refcount: AtomicU64::new(1),
                        privs_dropped: AtomicBool::new(false),
                        override_stat: Mutex::new(None),
                    });
                    write_map.insert(inode, alt_key, Arc::clone(&data));
                    data
                }
            }
        };
        let inode = data.inode;

        let st = self.attr_of(ctx, &data, file_info, handle, stored);

        let mut attr_flags = 0u32;
        if st.st_mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
            && self.announce_submounts.load(Ordering::Relaxed)
        {
            // Different volume ⟹ submount
            if volume_serial != parent_data.volume_serial {
                attr_flags |= fuse::ATTR_SUBMOUNT;
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

    fn open_for_setattr(&self, data: &InodeData, desired_access: u32) -> io::Result<HandleGuard> {
        // A setattr on a symlink inode targets the link itself.
        let flags = OpenFlags {
            desired_access,
            create_disposition: FILE_OPEN,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        };
        self.open_inode(data, &flags)
            .map(HandleGuard)
            .map_err(win_err_to_linux)
    }

    fn do_getattr(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(stat64, Duration)> {
        let data = self.inode_data(inode)?;
        let path = data.get_path();

        let (raw_h, _guard) = match handle.and_then(as_file_handle) {
            Some(h) => (h as HANDLE, None),
            None if let Some(guard) = self.dup_open_file(inode, FILE_READ_ATTRIBUTES) => {
                (guard.as_raw(), Some(guard))
            }
            _ => {
                // A symlink needs a handle to read its target.
                if let Some((info, stored)) = query_by_name(&path).map_err(win_err_to_linux)?
                    && info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                {
                    let stored = stored.map_or(Stored::NotInAttributes, Stored::Known);
                    let stat = self.attr_of(ctx, &data, &info, None, stored);
                    return Ok((stat, self.cfg.attr_timeout));
                }
                let h = open_handle(
                    &path,
                    &OpenFlags {
                        desired_access: FILE_READ_ATTRIBUTES,
                        create_disposition: FILE_OPEN,
                        create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                    },
                )
                .map_err(win_err_to_linux)?;
                // HandleGuard will call CloseHandle automatically when dropped at end of scope!
                (h, Some(HandleGuard(h)))
            }
        };

        let info = get_file_info_by_handle(raw_h).map_err(win_err_to_linux)?;

        let stat = self.attr_of(ctx, &data, &info, Some(raw_h), Stored::Unknown);
        Ok((stat, self.cfg.attr_timeout))
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
            if let CachePolicy::Always = self.cfg.cache_policy {
                opts |= OpenOptions::CACHE_DIR;
            }
            return Ok((Some(handle_id), opts));
        }

        let data = self.inode_data(inode)?;
        let h = self.open_inode(&data, &oflags).map_err(win_err_to_linux)?;

        if kill_priv {
            self.kill_priv(&data);
        }

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts.set(OpenOptions::DIRECT_IO, !is_dir),
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        }

        self.register_open_file(inode, h as u64);
        Ok((Some(h as u64), opts))
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        // Check if it's a tagged directory handle or a raw file handle
        if handle & (1 << 63) != 0 {
            self.dir_caches.write().unwrap().remove(&handle);
        } else {
            self.unregister_open_file(inode, handle);
            let h = handle as HANDLE;
            if h != INVALID_HANDLE_VALUE && !h.is_null() {
                unsafe { CloseHandle(h) };
            }
        }
        Ok(())
    }

    fn register_open_file(&self, inode: Inode, handle: Handle) {
        self.open_files
            .lock()
            .unwrap()
            .entry(inode)
            .or_default()
            .push(handle);
    }

    fn unregister_open_file(&self, inode: Inode, handle: Handle) {
        let mut open_files = self.open_files.lock().unwrap();
        if let Some(handles) = open_files.get_mut(&inode) {
            handles.retain(|&h| h != handle);
            if handles.is_empty() {
                open_files.remove(&inode);
            }
        }
    }

    /// Duplicate a guest file handle of `inode` that grants `desired_access`.
    ///
    /// Requests without a file handle (e.g. utimensat() or stat() by path)
    /// often target a file the guest still holds open: close(2) returns
    /// before the kernel sends RELEASE, so an extractor restoring timestamps
    /// right after writing a file races its own release. Reopening such a
    /// file is expensive, as filter drivers (e.g. antivirus) process the new
    /// open and closing it is the last-handle close that commits NTFS
    /// metadata. A duplicate shares the open file instead, and closing it is
    /// cheap since the guest's handle keeps the file open.
    fn dup_open_file(&self, inode: Inode, desired_access: u32) -> Option<HandleGuard> {
        let open_files = self.open_files.lock().unwrap();
        let handle = open_files
            .get(&inode)?
            .iter()
            .map(|&h| h as HANDLE)
            .find(|&h| handle_access(h).is_some_and(|a| a & desired_access == desired_access))?;
        duplicate_handle(handle).ok().map(HandleGuard)
    }

    /// Open a fresh file handle via `open_by_id` (falling back to
    /// path-based open).  The caller owns the returned `File`; the
    /// underlying handle is closed on drop.
    fn reopen_inode(&self, inode: Inode, handle: Handle, desired_access: u32) -> io::Result<File> {
        // If the handle is a valid persistent raw file handle (not zero, and no directory tag bit)
        if let Some(raw_handle) = as_file_handle(handle) {
            return duplicate_handle(raw_handle)
                .map(|dup_h| unsafe { File::from_raw_handle(dup_h as RawHandle) })
                .map_err(win_err_to_linux);
        }

        let data = self.inode_data(inode)?;
        let flags = OpenFlags {
            desired_access,
            create_disposition: FILE_OPEN,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT,
        };
        let h = self.open_inode(&data, &flags)?;
        Ok(unsafe { File::from_raw_handle(h as RawHandle) })
    }

    fn fill_dir_cache(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        // Fast path: cache already populated
        if self.dir_caches.read().unwrap().contains_key(&handle) {
            return Ok(());
        }

        let inode_data = self.inode_data(inode)?;

        let dir_flags = OpenFlags {
            desired_access: GENERIC_READ,
            create_disposition: FILE_OPEN,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
        };
        let dir_g = HandleGuard(
            self.open_inode(&inode_data, &dir_flags)
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
        let file_info = {
            let mut root_h = self.root_handle.write().unwrap();
            // destroy() closes the root handle; a later init() remounts.
            if *root_h == INVALID_HANDLE_VALUE {
                *root_h = openat(&self.cfg.root_dir)?;
            }
            get_file_info_by_handle(*root_h).map_err(win_err_to_linux)?
        };

        let alt_key = InodeAltKey {
            file_index: file_info.FileId as u64,
            volume_serial: self.root_volume_serial,
        };

        let mut inodes = self.inodes.write().unwrap();
        inodes.insert(
            fuse::ROOT_ID,
            alt_key,
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                parent_inode: fuse::ROOT_ID,
                file_index: file_info.FileId as u64,
                volume_serial: self.root_volume_serial,
                // openat() refuses a reparse point as the shared root.
                is_mount_point: false,
                path: RwLock::new(Arc::new(root_path.clone())),
                wide_path: RwLock::new(Arc::new(path_to_wide(&root_path))),
                refcount: AtomicU64::new(2),
                privs_dropped: AtomicBool::new(false),
                override_stat: Mutex::new(None),
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
        self.open_files.lock().unwrap().clear();
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

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(&ctx, parent, name)
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
        let parent_data = self.inode_data(parent)?;
        let parent_g = HandleGuard(
            self.open_inode(
                &parent_data,
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

        let dir_mode = mode & !umask;
        let child_path = child_path(parent_data.get_path().as_path(), name)?;
        match self.cfg.semantics {
            PermissionSemantics::LinuxComplete => {
                if let Some(secctx) = extensions.secctx {
                    let stream_name = format!(":{}", secctx.name.to_string_lossy());
                    write_ads_by_handle(child_g.as_raw(), &stream_name, &secctx.secctx)?;
                }

                write_new_metadata(
                    &child_path,
                    Some(child_g.as_raw()),
                    (
                        Some(ctx.uid),
                        Some(ctx.gid),
                        Some(libc::S_IFDIR as u32 | dir_mode),
                    ),
                )?;
            }
            _ => {
                if let Err(e) = write_new_metadata(
                    &child_path,
                    Some(child_g.as_raw()),
                    (None, None, Some(libc::S_IFDIR as u32 | dir_mode)),
                ) {
                    debug!("keep the mode of {}: {e}", child_path.display());
                }
            }
        }

        self.entry_from_handle(
            &ctx,
            parent,
            &parent_data,
            &child_path,
            child_g.as_raw(),
            Some((Some(ctx.uid), Some(ctx.gid), Some(dir_mode))),
        )
    }

    fn rmdir(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        let parent_data = self.inode_data(parent)?;
        let parent_g = HandleGuard(
            self.open_inode(
                &parent_data,
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
        ctx: Context,
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
            let entry = match self.do_lookup(&ctx, inode, &name_cstr) {
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
        ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(stat64, Duration)> {
        self.do_getattr(&ctx, inode, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: Inode,
        attr: stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        let data = self.inode_data(inode)?;
        let path = data.get_path();

        let mut mode_writable: Option<bool> = None;
        let mut known_override: Option<OverrideStat> = None;
        match self.cfg.semantics {
            PermissionSemantics::LinuxSimplified
            | PermissionSemantics::LinuxSimplifiedFixedOwner => {
                // In LinuxSimplified mode:
                // 1. UID/GID changes (chown) are ignored since ownership is dynamically returned as ctx.uid/gid.
                // 2. Extended attribute (ADS) overrides are not written.
                // 3. permission bits are saved in the WSL metadata
                if valid.contains(SetattrValid::MODE) {
                    mode_writable = Some((attr.st_mode & 0o200) != 0);
                    let mode = attr.st_mode & !0o7000;
                    match write_lx_metadata(&path, (None, None, Some(mode))) {
                        Ok(()) => known_override = Some((None, None, Some(mode))),
                        Err(e) => debug!("keep the mode of {}: {e}", path.display()),
                    }
                }
            }
            PermissionSemantics::LinuxComplete => {
                // In LinuxComplete mode, preserve permissions and ownership using the ADS stream.
                // Check if any state mutation requires updating the ADS metadata
                let needs_suid_clear = valid.contains(SetattrValid::SIZE)
                    || valid.intersects(SetattrValid::UID | SetattrValid::GID);

                if valid.intersects(SetattrValid::MODE | SetattrValid::UID | SetattrValid::GID)
                    || needs_suid_clear
                {
                    // Single read to inspect current state
                    let ((mut current_uid, mut current_gid, mut current_mode), stored_in) =
                        read_metadata(&path);

                    let mut override_changed = false;

                    if valid.contains(SetattrValid::MODE) {
                        current_mode = Some(attr.st_mode);
                        override_changed = true;
                    }

                    // An out-of-range id keeps the stored one.
                    if valid.contains(SetattrValid::UID) {
                        if attr.st_uid < UID_MAX {
                            current_uid = Some(attr.st_uid);
                        }
                        override_changed = true;
                    }

                    if valid.contains(SetattrValid::GID) {
                        if attr.st_gid < UID_MAX {
                            current_gid = Some(attr.st_gid);
                        }
                        override_changed = true;
                    }

                    // If size or ownership changed, clear capabilities and suid/sgid
                    if needs_suid_clear {
                        remove_security_capability(&path);

                        if !valid.contains(SetattrValid::MODE)
                            && let Some(mode) = current_mode
                        {
                            let new_mode = clear_suid_sgid(mode);
                            if new_mode != mode {
                                current_mode = Some(new_mode);
                                override_changed = true;
                            }
                        }
                    }

                    // Single unified write if metadata changed
                    if override_changed {
                        write_metadata(&path, (current_uid, current_gid, current_mode), stored_in)?;
                        data.privs_dropped.store(false, Ordering::Relaxed);
                    }

                    // The stored metadata now holds these values, so the reply can
                    // skip reading it back.
                    known_override = Some((current_uid, current_gid, current_mode));
                }
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
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

        // Every field is applied on a single handle whose metadata is queried
        // once and patched into the reply.
        let (h, owned_handle) = match handle.and_then(as_file_handle) {
            Some(h) => (h, None),
            None => {
                let mut desired_access = FILE_READ_ATTRIBUTES;
                if mode_writable.is_some() || atime.is_some() || mtime.is_some() {
                    desired_access |= FILE_WRITE_ATTRIBUTES;
                }
                if valid.contains(SetattrValid::SIZE) {
                    desired_access |= FILE_WRITE_DATA;
                }
                let guard = match self.dup_open_file(inode, desired_access) {
                    Some(guard) => guard,
                    None => self.open_for_setattr(&data, desired_access)?,
                };
                (guard.as_raw(), Some(guard))
            }
        };

        let mut info = get_file_info_by_handle(h).map_err(win_err_to_linux)?;
        let mut changed = false;

        // Truncating to the current size is a no-op
        if valid.contains(SetattrValid::SIZE) && info.EndOfFile != attr.st_size {
            set_file_size_by_handle(h, attr.st_size).map_err(|e| {
                // POSIX: truncating through an fd not open for writing is EBADF.
                if owned_handle.is_none() && e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                    ebadf()
                } else {
                    win_err_to_linux(e)
                }
            })?;
            info.EndOfFile = attr.st_size;
            changed = true;
        }

        let new_attrs = mode_writable
            .map(|is_writable| {
                if is_writable {
                    info.FileAttributes & !FILE_ATTRIBUTE_READONLY
                } else {
                    info.FileAttributes | FILE_ATTRIBUTE_READONLY
                }
            })
            .filter(|&attrs| attrs != info.FileAttributes);

        if new_attrs.is_some() || atime.is_some() || mtime.is_some() {
            match set_file_basic_info(h, new_attrs, atime, mtime) {
                // Linux allows fchmod/futimens through an O_RDONLY fd, whose
                // handle lacks FILE_WRITE_ATTRIBUTES.
                Err(e)
                    if owned_handle.is_none()
                        && e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) =>
                {
                    let guard = self.open_for_setattr(&data, FILE_WRITE_ATTRIBUTES)?;
                    set_file_basic_info(guard.as_raw(), new_attrs, atime, mtime)
                }
                res => res,
            }
            .map_err(win_err_to_linux)?;
            if let Some(attrs) = new_attrs {
                info.FileAttributes = attrs;
            }
            if let Some(atime) = atime {
                info.LastAccessTime = atime as i64;
            }
            if let Some(mtime) = mtime {
                info.LastWriteTime = mtime as i64;
            }
            changed = true;
        }

        if changed {
            info.ChangeTime = now_ft as i64;
        }

        let stat = self.attr_of(
            &ctx,
            &data,
            &info,
            Some(h),
            known_override.map_or(Stored::Unknown, Stored::Known),
        );
        Ok((stat, self.cfg.attr_timeout))
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let path = data.get_path();

        let handle = HandleGuard(open_handle(
            &path,
            &OpenFlags {
                desired_access: FILE_READ_ATTRIBUTES,
                create_disposition: FILE_OPEN,
                create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            },
        )?);

        let mut buf = match read_lx_symlink_by_handle(handle.as_raw()) {
            Ok(buf) => buf,
            _ => {
                let target = fs::read_link(&*path).map_err(win_err_to_linux)?;
                target.to_string_lossy().into_owned().into_bytes()
            }
        };

        // Convert Windows path formatting back to a Linux-friendly format.
        // Windows symlinks use '\', but the FUSE Linux guest expects '/'
        buf.iter_mut().for_each(|b| {
            if *b == b'\\' {
                *b = b'/'
            }
        });

        // Cap to PATH_MAX (4096) to match Linux parity exactly.
        // While Windows NT paths can be 32k, FUSE/Linux expects a max of 4096 bytes.
        buf.truncate(4096);

        Ok(buf)
    }

    /*
     * Current implementation relies on standard Windows symlink APIs,
     * which enforce host-side path validation.
     *
     * The Limitation is that absolute paths from the guest (e.g., "/etc/passwd") are treated as drive-relative
     * on Windows, so they are refused with EINVAL.
     *
     * TODO:
     * To support true absolute guest symlinks, we need to bypass the Win32 API
     * and manually set an IO_REPARSE_TAG_LX_SYMLINK reparse point using
     * DeviceIoControl. This will allow storing arbitrary Linux-style paths
     * without host-side resolution.
     */
    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let parent_path = self.inode_path(parent)?;
        let link_path = child_path(parent_path.as_path(), name)?;
        let depth = parent_path
            .strip_prefix(&self.cfg.root_dir)
            .map_or(0, |below| below.components().count());
        check_symlink_target(linkname, depth)?;
        let target = cstr_to_path(linkname);

        // Windows requires knowing if a symlink target is a file or a directory.
        // FUSE doesn't provide this distinction upfront, so we try file first,
        // and safely fall back to directory if it fails.
        std::os::windows::fs::symlink_file(&target, &link_path)
            .or_else(|_| std::os::windows::fs::symlink_dir(&target, &link_path))
            .map_err(win_err_to_linux)?;

        if matches!(self.cfg.semantics, PermissionSemantics::LinuxComplete) {
            if let Some(secctx) = extensions.secctx {
                write_secctx(&link_path, secctx, true)?;
            }

            write_new_metadata(
                &link_path,
                None,
                (Some(ctx.uid), Some(ctx.gid), Some(S_IFLNK as u32 | 0o777)),
            )?;
        }

        self.do_lookup(&ctx, parent, name)
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        _rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let parent_data = self.inode_data(parent)?;

        // Open parent directory securely (matching Linux mknodat's dirfd behavior)
        let parent_g = HandleGuard(
            self.open_inode(
                &parent_data,
                &OpenFlags {
                    desired_access: GENERIC_READ,
                    create_disposition: FILE_OPEN,
                    create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
                },
            )
            .map_err(win_err_to_linux)?,
        );

        // Create the child file/node case-sensitively via NtCreateFile
        let child_g = HandleGuard(
            open_relative(
                parent_g.as_raw(),
                name,
                &OpenFlags {
                    desired_access: GENERIC_READ | GENERIC_WRITE,
                    create_disposition: FILE_CREATE,
                    // Ensure FILE_DIRECTORY_FILE is NOT set, as mknod creates files/device nodes
                    create_options: FILE_SYNCHRONOUS_IO_NONALERT,
                },
            )
            .map_err(win_err_to_linux)?,
        );

        let node_mode = mode & !umask;
        let child_path = child_path(parent_data.get_path().as_path(), name)?;
        match self.cfg.semantics {
            PermissionSemantics::LinuxComplete => {
                // Write security context via the active handle
                if let Some(secctx) = extensions.secctx {
                    let stream_name = format!(":{}", secctx.name.to_string_lossy());
                    write_ads_by_handle(child_g.as_raw(), &stream_name, &secctx.secctx)?;
                }

                // The mode carries the node's type (S_IFIFO, S_IFCHR, S_IFSOCK, ...), which only
                // the stored metadata records: on the host it is an empty file.
                write_new_metadata(
                    &child_path,
                    Some(child_g.as_raw()),
                    (Some(ctx.uid), Some(ctx.gid), Some(node_mode)),
                )?;
            }
            _ => {
                if let Err(e) = write_new_metadata(
                    &child_path,
                    Some(child_g.as_raw()),
                    (None, None, Some(node_mode & 0o777)),
                ) {
                    debug!("keep the mode of {}: {e}", child_path.display());
                }
            }
        }

        self.entry_from_handle(
            &ctx,
            parent,
            &parent_data,
            &child_path,
            child_g.as_raw(),
            Some((Some(ctx.uid), Some(ctx.gid), Some(node_mode))),
        )
    }

    // There is one minor edge-case to be aware of
    // Windows explicitly blocks DELETE access on files marked with the Windows READONLY attribute, returning an Access Denied error
    // Linux does not care if the file itself is read-only; Linux unlink succeeds as long as the parent directory has write permissions
    // This means that a Linux guest attempting to unlink a readonly file will fail with Access Denied, even if the parent directory is writable
    fn unlink(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        let parent_data = self.inode_data(parent)?;
        let parent_g = HandleGuard(
            self.open_inode(
                &parent_data,
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
                        | FILE_OPEN_REPARSE_POINT
                        | FILE_NON_DIRECTORY_FILE,
                },
            )
            .map_err(win_err_to_linux)?,
        );

        set_delete_disposition(child_g.as_raw()).map_err(win_err_to_linux)
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let old_path = child_path(self.inode_path(olddir)?.as_path(), oldname)?;
        let new_path = child_path(self.inode_path(newdir)?.as_path(), newname)?;

        // RENAME_EXCHANGE (Swap two files)
        if (flags as i32 & LINUX_RENAME_EXCHANGE) != 0 {
            // Atomic exchange is not natively supported by the base Win32 API without TxF;
            // emulate via a temporary file exchange sequence.
            let tmp = new_path.with_extension(".__exchange_tmp__");
            fs::rename(&new_path, &tmp).map_err(win_err_to_linux)?;
            if let Err(e) = fs::rename(&old_path, &new_path) {
                let _ = fs::rename(&tmp, &new_path); // Rollback
                return Err(win_err_to_linux(e));
            }
            fs::rename(&tmp, &old_path).map_err(win_err_to_linux)?;
            return Ok(());
        }

        // RENAME_NOREPLACE (Strictly do not overwrite)
        if (flags as i32 & LINUX_RENAME_NOREPLACE) != 0 {
            use windows_sys::Win32::Storage::FileSystem::MoveFileW;

            let old_wide = path_to_wide(&old_path);
            let new_wide = path_to_wide(&new_path);

            // MoveFileW inherently fails atomically if the target exists
            let res = unsafe { MoveFileW(old_wide.as_ptr(), new_wide.as_ptr()) };
            if res == 0 {
                return Err(win_err_to_linux(io::Error::last_os_error()));
            }
            return Ok(());
        }

        fs::rename(&old_path, &new_path).map_err(win_err_to_linux)
    }

    fn link(
        &self,
        ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let existing = self.inode_path(inode)?;
        let new_path = child_path(self.inode_path(newparent)?.as_path(), newname)?;

        // Note: fs::hard_link wraps CreateHardLinkW. If the target already exists,
        // it fails with an error that win_err_to_linux perfectly maps to EEXIST.
        // Because NTFS shares MFT records for hard links, the existing ADS
        // permissions are natively shared with the new link!
        fs::hard_link(&*existing, &new_path).map_err(win_err_to_linux)?;
        self.do_lookup(&ctx, newparent, newname)
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, kill_priv, flags)
    }

    fn release(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        let parent_data = self.inode_data(parent)?;
        let child_path = child_path(parent_data.get_path().as_path(), name)?;

        let wb = self.writeback.load(Ordering::Relaxed);
        let mut oflags = parse_linux_open_flags(flags as i32 | LINUX_O_CREAT, wb);
        // The entry of a created file is built from this handle's metadata.
        oflags.desired_access |= FILE_READ_ATTRIBUTES;
        let (h, created) =
            open_handle_reporting_creation(&child_path, &oflags).map_err(win_err_to_linux)?;
        let guard = HandleGuard(h);
        let linux_complete = matches!(self.cfg.semantics, PermissionSemantics::LinuxComplete);

        let entry = if created {
            let file_mode = S_IFREG as u32 | (mode & !(umask & 0o777));
            if linux_complete {
                if let Some(secctx) = extensions.secctx {
                    let stream_name = format!(":{}", secctx.name.to_string_lossy());
                    write_ads_by_handle(h, &stream_name, &secctx.secctx)?;
                }

                write_new_metadata(
                    &child_path,
                    Some(h),
                    (Some(ctx.uid), Some(ctx.gid), Some(file_mode)),
                )?;
            } else {
                if let Err(e) =
                    write_new_metadata(&child_path, Some(h), (None, None, Some(file_mode)))
                {
                    debug!("keep the mode of {}: {e}", child_path.display());
                }
            }

            self.entry_from_handle(
                &ctx,
                parent,
                &parent_data,
                &child_path,
                h,
                Some((Some(ctx.uid), Some(ctx.gid), Some(file_mode))),
            )?
        } else {
            if linux_complete && (flags as i32 & LINUX_O_TRUNC) != 0 && kill_priv {
                remove_security_capability(&child_path);
            }

            // An existing name may be a symlink, in which case `h` refers to
            // its target while the entry must describe the link itself.
            self.do_lookup(&ctx, parent, name)?
        };
        mem::forget(guard);

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        }

        self.register_open_file(entry.inode, h as u64);
        Ok((entry, Some(h as u64), opts))
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        debug!("read: {inode:?}");

        // Borrowed, not owned: release() closes the guest handle.
        let borrowed_file = as_file_handle(handle)
            .map(|raw_h| ManuallyDrop::new(unsafe { File::from_raw_handle(raw_h as _) }));

        let opened_file;
        let file_ref: &File = match &borrowed_file {
            Some(file) => file,
            None => {
                opened_file = self
                    .reopen_inode(inode, handle, GENERIC_READ)
                    .map_err(win_err_to_linux)?;
                &opened_file
            }
        };

        w.write_from(file_ref, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        // POSIX Compliance: Writing to a Read-Only FD should return EBADF
        let raw_h = match as_file_handle(handle) {
            Some(raw_h) if !is_handle_read_only(handle) => raw_h,
            _ => return Err(ebadf()),
        };

        // Borrowed, not owned: release() closes the guest handle.
        let file = ManuallyDrop::new(unsafe { File::from_raw_handle(raw_h as _) });
        let result = r.read_to(&file, size as usize, offset);

        if result.is_ok() && kill_priv {
            let data = self.inode_data(inode)?;
            self.kill_priv(&data);
        }

        result
    }

    fn flush(
        &self,
        _ctx: Context,
        _inode: Inode,
        _handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        // FUSE `flush` is called on every guest close(2) to give userspace filesystems
        // a chance to flush internal process buffers and return write errors (e.g., ENOSPC).
        // POSIX close(2) carries no durability guarantees; it only expects dirty userspace
        // buffers to reach the OS page cache.
        //
        // Because all guest writes are already dispatched directly to host Windows handles
        // via WriteFile(), there are no uncommitted user-mode buffers held in this VMM process.
        // We intentionally do NOT call FlushFileBuffers() here, as forcing a physical disk sync
        // on every file close adds severe millisecond-level latency. Guests requiring data
        // durability issue fsync(2), which is properly handled by FlushFileBuffers() in `fsync`.
        //
        // With nothing to do, ENOSYS makes the guest kernel stop sending FLUSH altogether,
        // saving a full round trip on every close(2). POSIX locks are not supported either,
        // so no lock owner state needs to be released here
        Err(enosys())
    }

    fn fsync(&self, _ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        if is_handle_read_only(handle) {
            // A read-only handle has no pending write buffers, so fsync is a no-op!
            return Ok(());
        }

        let file = self
            .reopen_inode(inode, handle, GENERIC_READ | GENERIC_WRITE)
            .map_err(win_err_to_linux)?;

        // Respect the datasync flag just like Linux fdatasync vs fsync
        if datasync {
            file.sync_data().map_err(win_err_to_linux)
        } else {
            file.sync_all().map_err(win_err_to_linux)
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        // POSIX access mode constants (since Windows libc doesn't define them)
        const F_OK: u32 = 0;
        const X_OK: u32 = 1;
        const W_OK: u32 = 2;
        const R_OK: u32 = 4;

        // Get the emulated POSIX stats from the ADS override stream
        let (st, _) = self.do_getattr(&ctx, inode, None)?;

        let mode = mask & (R_OK | W_OK | X_OK);

        if mode == F_OK {
            // The file exists since we were able to call `do_getattr` on it.
            return Ok(());
        }

        // Emulate Linux's POSIX access checks based on Context UID/GID
        if (mode & R_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o400 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o040 == 0)
            && st.st_mode & 0o004 == 0
        {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::EACCES)));
        }

        if (mode & W_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o200 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o020 == 0)
            && st.st_mode & 0o002 == 0
        {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::EACCES)));
        }

        if (mode & X_OK) != 0
            && (ctx.uid != 0 || st.st_mode & 0o111 == 0)
            && (st.st_uid != ctx.uid || st.st_mode & 0o100 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o010 == 0)
            && st.st_mode & 0o001 == 0
        {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::EACCES)));
        }

        Ok(())
    }

    fn setxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        if matches!(self.cfg.semantics, PermissionSemantics::LinuxSimplified) || !self.cfg.xattr {
            return Err(enosys());
        }

        check_xattr_name(name)?;

        // Prevent the guest from directly modifying these attributes
        // If the guest could directly modify this xattr, it could bypass security boundaries or corrupt the emulation.
        if is_reserved_xattr(name.to_bytes()) {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::EACCES)));
        }

        let path = self.inode_path(inode)?;
        let stream = ads_xattr_path(&path, name);

        if flags & XATTR_CREATE != 0 && stream.exists() {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::EEXIST)));
        }
        if flags & XATTR_REPLACE != 0 && !stream.exists() {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::ENODATA)));
        }

        fs::write(&stream, value).map_err(win_err_to_linux)
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        if matches!(self.cfg.semantics, PermissionSemantics::LinuxSimplified) || !self.cfg.xattr {
            return Err(enosys());
        }

        check_xattr_name(name)?;

        // Prevent the guest from reading them directly.
        // The guest should only see these values through standard stat calls, not raw getxattr queries
        if is_reserved_xattr(name.to_bytes()) {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::EACCES)));
        }

        let path = self.inode_path(inode)?;
        let stream = ads_xattr_path(&path, name);

        let data = fs::read(&stream).map_err(|e| {
            let code = e.raw_os_error().unwrap_or(0) as u32;
            if code == 2 || code == 3 || code == 123 {
                // Windows treats ADS as part of the path. If the ADS is missing (2, 3)
                // or the guest requested an xattr name that is an illegal Windows name (123)
                // We map them to ENODATA instead to match Linux behavior.
                // If we return ENOENT, the guest will think the file does not exist, which is not what we want.
                io::Error::from_raw_os_error(linux_errno_raw(libc::ENODATA))
            } else {
                win_err_to_linux(e)
            }
        })?;

        if size == 0 {
            Ok(GetxattrReply::Count(data.len() as u32))
        } else if size < data.len() as u32 {
            Err(io::Error::from_raw_os_error(linux_errno_raw(libc::ERANGE)))
        } else {
            Ok(GetxattrReply::Value(data))
        }
    }

    fn listxattr(&self, _ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if matches!(self.cfg.semantics, PermissionSemantics::LinuxSimplified) || !self.cfg.xattr {
            return Err(enosys());
        }

        let path = self.inode_path(inode)?;
        let streams = ads_list_streams(&path).unwrap_or_default();

        let mut buf = Vec::new();
        for s in &streams {
            if is_reserved_xattr(s.as_bytes()) {
                continue;
            }
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }

        if size == 0 {
            Ok(ListxattrReply::Count(buf.len() as u32))
        } else if size < buf.len() as u32 {
            Err(io::Error::from_raw_os_error(linux_errno_raw(libc::ERANGE)))
        } else {
            Ok(ListxattrReply::Names(buf))
        }
    }

    fn removexattr(&self, _ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if matches!(self.cfg.semantics, PermissionSemantics::LinuxSimplified) || !self.cfg.xattr {
            return Err(enosys());
        }

        check_xattr_name(name)?;

        if is_reserved_xattr(name.to_bytes()) {
            return Err(io::Error::from_raw_os_error(linux_errno_raw(libc::EACCES)));
        }

        let path = self.inode_path(inode)?;
        let stream = ads_xattr_path(&path, name);

        fs::remove_file(&stream).map_err(|e| {
            let code = e.raw_os_error().unwrap_or(0) as u32;
            // Windows treats ADS as part of the path, so if the ADS has not been set it
            // returns ERROR_FILE_NOT_FOUND (2) or ERROR_PATH_NOT_FOUND (3).
            // This is normally mapped to ENOENT, but we map it to ENODATA instead to match Linux behavior.
            // If we return ENOENT, the guest will think the file does not exist, which is not what we want.
            if code == 2 || code == 3 {
                io::Error::from_raw_os_error(linux_errno_raw(libc::ENODATA))
            } else {
                win_err_to_linux(e)
            }
        })
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        // EBADF - fd is not a valid file descriptor, or is not opened for writing.
        if is_handle_read_only(handle) {
            return Err(ebadf());
        }

        let file = self
            .reopen_inode(inode, handle, GENERIC_READ | GENERIC_WRITE)
            .map_err(win_err_to_linux)?;

        // EFBIG - offset+size exceeds the maximum file size.
        let target = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::from_raw_os_error(linux_errno_raw(libc::EFBIG)))?;
        let current = file.metadata().map_err(win_err_to_linux)?.len();
        if target > current {
            file.set_len(target).map_err(win_err_to_linux)?;
        }
        Ok(())
    }

    fn lseek(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        // All I/O uses explicit offsets (pread/pwrite), so there is no
        // persistent file-position cursor. SEEK_SET and SEEK_CUR are
        // pure arithmetic; SEEK_END needs the current file length.
        match whence {
            0 => Ok(offset), // SEEK_SET
            1 => Ok(offset), // SEEK_CUR (cursor always at 0)
            2 => {
                // SEEK_END
                let file = self
                    .reopen_inode(inode, handle, FILE_READ_ATTRIBUTES)
                    .map_err(win_err_to_linux)?;
                let len = file.metadata().map_err(win_err_to_linux)?.len();
                Ok((len as i64 + offset as i64) as u64)
            }
            3 => Ok(offset), // SEEK_DATA
            4 => {
                // SEEK_HOLE — return EOF
                let file = self
                    .reopen_inode(inode, handle, FILE_READ_ATTRIBUTES)
                    .map_err(win_err_to_linux)?;
                let len = file.metadata().map_err(win_err_to_linux)?.len();
                Ok(len)
            }
            _ => Err(einval()),
        }
    }

    fn setupmapping(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use std::ptr;
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFileEx, PAGE_READONLY,
            PAGE_READWRITE,
        };

        let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut sys_info) };
        let granularity = sys_info.dwAllocationGranularity as u64;

        if !foffset.is_multiple_of(granularity) {
            error!("foffset {foffset} is not aligned to {granularity}");
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        if (moffset + len) > shm_size {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        let is_write = (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0;
        let page_flags = if is_write {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };
        let map_flags = if is_write {
            FILE_MAP_READ | FILE_MAP_WRITE
        } else {
            FILE_MAP_READ
        };

        let addr = host_shm_base + moffset;
        debug!("setupmapping: ino {inode:?} addr={addr:x} len={len}");

        let file = self
            .reopen_inode(inode, handle, GENERIC_READ)
            .map_err(win_err_to_linux)?;
        let handle_raw = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;

        // 1. Create a file mapping object from the open file handle
        let mapping_handle =
            unsafe { CreateFileMappingW(handle_raw, ptr::null(), page_flags, 0, 0, ptr::null()) };

        if mapping_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        // 2. Map the view exactly into the guest's DAX window address
        let ret = unsafe {
            MapViewOfFileEx(
                mapping_handle,
                map_flags,
                (foffset >> 32) as u32,
                (foffset & 0xFFFFFFFF) as u32,
                len as usize,
                addr as *mut _,
            )
        };

        // The mapping handle can be safely closed after the view is mapped;
        // the mapping remains valid until UnmapViewOfFile is called.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(mapping_handle) };

        if ret.Value.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn removemapping(
        &self,
        _ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        use windows_sys::Win32::System::Memory::UnmapViewOfFile;

        for req in requests {
            let addr = host_shm_base + req.moffset;
            if (req.moffset + req.len) > shm_size {
                return Err(einval());
            }
            debug!("removemapping: addr={addr:x} len={}", req.len);

            // Unmap the file view from the guest's DAX window
            let ret = unsafe {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: addr as *mut _,
                })
            };
            if ret == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::ffi::CString;
    use std::os::windows::fs::FileExt;
    use std::process;

    use super::*;

    const CTX: Context = Context {
        uid: 0,
        gid: 0,
        pid: 0,
    };

    /// A shared directory holding one entry, with a file beside the share that no name
    /// of an entry can reach. Taken down with everything under it when a test ends.
    struct Share {
        base: PathBuf,
        root: PathBuf,
        outside: PathBuf,
    }

    impl Share {
        fn new(tag: &str) -> Share {
            let base = env::temp_dir().join(format!("libkrun-fs-{tag}-{}", process::id()));
            let root = base.join("share");
            let outside = base.join("outside.txt");
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(root.join("sub")).unwrap();
            fs::write(root.join("sub").join("inside.txt"), b"shared").unwrap();
            fs::write(&outside, b"host").unwrap();
            Share {
                base,
                root,
                outside,
            }
        }

        fn served(&self) -> PassthroughFs {
            self.served_as(Config::default().semantics)
        }

        fn served_as(&self, semantics: PermissionSemantics) -> PassthroughFs {
            let cfg = Config {
                root_dir: self.root.to_str().unwrap().to_owned(),
                semantics,
                ..Default::default()
            };
            let fs = PassthroughFs::new(cfg, Arc::new(InodeAllocator::new())).unwrap();
            fs.init(FsOptions::empty()).unwrap();
            fs
        }
    }

    impl Drop for Share {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn name_of(path: &Path) -> CString {
        CString::new(path.to_str().unwrap()).unwrap()
    }

    /// The inode of the one file the shared directory holds.
    fn inside(fs: &PassthroughFs) -> Inode {
        let dir = fs.lookup(CTX, fuse::ROOT_ID, c"sub").unwrap().inode;
        fs.lookup(CTX, dir, c"inside.txt").unwrap().inode
    }

    fn eacces() -> io::Error {
        io::Error::from_raw_os_error(linux_errno_raw(libc::EACCES))
    }

    fn refused(result: io::Result<impl Sized>, expected: io::Error, what: &str) {
        match result {
            Ok(_) => panic!("{what}"),
            Err(e) => assert_eq!(e.raw_os_error(), expected.raw_os_error(), "{what}: {e:?}"),
        }
    }

    #[test]
    fn a_name_that_is_not_one_entry_is_refused() {
        for name in [c"a\\b", c"a/b", c"a:b", c"\\Windows", c"..", c".", c""] {
            assert!(check_name(name).is_err(), "{name:?}");
        }
        assert!(check_name(c"a").is_ok());
    }

    #[test]
    fn a_symlink_target_outside_the_share_is_refused() {
        for (target, depth) in [
            (c"/etc/passwd", 2),
            (c"..", 0),
            (c"../x", 0),
            (c"a/../../x", 0),
            (c"../../x", 1),
            (c"a\\b", 0),
            (c"C:x", 0),
            (c".../../x", 1),
            (c"a/.. /x", 1),
        ] {
            assert!(
                check_symlink_target(target, depth).is_err(),
                "{target:?} at depth {depth}"
            );
        }
        for (target, depth) in [
            (c"x", 0),
            (c"./a//b/", 0),
            (c"a/../x", 0),
            (c"..", 1),
            (c"../../x", 2),
        ] {
            assert!(
                check_symlink_target(target, depth).is_ok(),
                "{target:?} at depth {depth}"
            );
        }
    }

    #[test]
    fn a_lookup_stays_within_the_shared_directory() {
        let share = Share::new("lookup");
        let fs = share.served();

        refused(
            fs.lookup(CTX, fuse::ROOT_ID, c"sub\\inside.txt"),
            einval(),
            "a separator in a name reached an entry of another directory",
        );
        refused(
            fs.lookup(CTX, fuse::ROOT_ID, &name_of(&share.outside)),
            einval(),
            "a name spelling a host path reached a file outside the share",
        );
    }

    #[test]
    fn an_unlink_stays_within_the_directory_it_names() {
        let share = Share::new("unlink");
        let fs = share.served();

        refused(
            fs.unlink(CTX, fuse::ROOT_ID, c"sub\\inside.txt"),
            einval(),
            "a separator in a name removed an entry of another directory",
        );
        assert_eq!(
            fs::read(share.root.join("sub").join("inside.txt")).unwrap(),
            b"shared"
        );
    }

    #[test]
    fn a_create_stays_within_the_shared_directory() {
        let share = Share::new("create");
        let fs = share.served();
        let made = share.base.join("made.txt");

        refused(
            fs.create(
                CTX,
                fuse::ROOT_ID,
                &name_of(&made),
                0o644,
                false,
                LINUX_O_CREAT as u32,
                0,
                Extensions::default(),
            ),
            einval(),
            "a name spelling a host path created a file outside the share",
        );
        assert!(!made.exists());
        assert_eq!(fs::read(&share.outside).unwrap(), b"host");
    }

    #[test]
    fn a_symlink_stays_within_the_shared_directory() {
        let share = Share::new("symlink");
        let fs = share.served();

        for (target, name) in [
            (c"..".to_owned(), c"up"),
            (c"..\\outside.txt".to_owned(), c"beside"),
            (name_of(&share.outside), c"host"),
        ] {
            refused(
                fs.symlink(CTX, &target, fuse::ROOT_ID, name, Extensions::default()),
                einval(),
                "a symlink target reached an entry outside the share",
            );
            let made = share.root.join(name.to_str().unwrap());
            assert!(fs::symlink_metadata(&made).is_err(), "{made:?}");
        }
    }

    #[test]
    fn an_xattr_name_that_is_not_one_stream_is_refused() {
        for name in [
            c":$DATA",
            c"user.x:$DATA",
            c"a\\b",
            c"a/b",
            c"user.x.",
            c"user.x ",
            c"",
        ] {
            assert!(check_xattr_name(name).is_err(), "{name:?}");
        }
        assert!(check_xattr_name(c"user.x").is_ok());
        assert!(check_xattr_name(c"user. x.y").is_ok());
    }

    #[test]
    fn an_xattr_stays_out_of_the_entrys_own_data() {
        let share = Share::new("xattr-data");
        let fs = share.served();
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");

        refused(
            fs.setxattr(CTX, file, c":$DATA", b"written as an xattr", 0),
            einval(),
            "an xattr name reached the entry's own contents",
        );
        assert_eq!(fs::read(&path).unwrap(), b"shared");
        refused(
            fs.getxattr(CTX, file, c":$DATA", 64),
            einval(),
            "an xattr name read the entry's own contents",
        );
        refused(
            fs.removexattr(CTX, file, c":$DATA"),
            einval(),
            "an xattr name removed the entry itself",
        );
        assert_eq!(fs::read(&path).unwrap(), b"shared");
    }

    #[test]
    fn a_reserved_xattr_is_refused_whatever_its_case() {
        let share = Share::new("xattr-case");
        let fs = share.served();
        let file = inside(&fs);

        for name in [
            c"USER.CONTAINERS.OVERRIDE_STAT",
            c"Security.Capability",
            c"user.containers.override_stat",
        ] {
            refused(
                fs.setxattr(CTX, file, name, b"0:0:04755", 0),
                eacces(),
                "a reserved xattr was written by the guest",
            );
        }

        let (attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(attr.st_mode & S_ISUID, 0);

        let path = share.root.join("sub").join("inside.txt");
        fs::write(
            ads_stream_path(&path, ":USER.CONTAINERS.OVERRIDE_STAT"),
            b"0:0:0644",
        )
        .unwrap();
        refused(
            fs.getxattr(CTX, file, c"User.Containers.Override_Stat", 64),
            eacces(),
            "the reserved xattr was read by the guest",
        );
        let listed = match fs.listxattr(CTX, file, 4096).unwrap() {
            ListxattrReply::Names(names) => names,
            ListxattrReply::Count(n) => panic!("asked for the names, got a count of {n}"),
        };
        assert!(listed.is_empty(), "{}", String::from_utf8_lossy(&listed));
    }

    #[test]
    fn a_reserved_xattr_is_refused_whatever_ends_its_name() {
        let share = Share::new("xattr-end");
        let fs = share.served();
        let file = inside(&fs);
        let names = [
            c"user.containers.override_stat.",
            c"user.containers.override_stat ",
            c"security.capability . .",
        ];

        for name in names {
            refused(
                fs.setxattr(CTX, file, name, b"0:0:04755", 0),
                einval(),
                "a reserved xattr was written under a name ending in a dot or a space",
            );
        }
        let (attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(attr.st_mode & S_ISUID, 0);

        let stream = ads_stream_path(
            &share.root.join("sub").join("inside.txt"),
            OVERRIDE_STAT_STREAM,
        );
        fs::write(&stream, b"0:0:0644").unwrap();
        for name in names {
            refused(
                fs.getxattr(CTX, file, name, 64),
                einval(),
                "a reserved xattr was read under a name ending in a dot or a space",
            );
            refused(
                fs.removexattr(CTX, file, name),
                einval(),
                "a reserved xattr was removed under a name ending in a dot or a space",
            );
        }
        assert_eq!(fs::read(&stream).unwrap(), b"0:0:0644");
    }

    fn open_attributes(path: &Path, access: u32) -> HandleGuard {
        let flags = OpenFlags {
            desired_access: access,
            create_disposition: FILE_OPEN,
            create_options: FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        };
        HandleGuard(open_handle(path, &flags).unwrap())
    }

    fn change_time(path: &Path) -> i64 {
        let h = open_attributes(path, FILE_READ_ATTRIBUTES);
        get_file_info_by_handle(h.as_raw()).unwrap().ChangeTime
    }

    fn set_change_time(path: &Path, change_time: i64) {
        let h = open_attributes(path, FILE_WRITE_ATTRIBUTES);
        // Zero leaves a time or the attributes as they are.
        let info = FILE_BASIC_INFO {
            ChangeTime: change_time,
            ..unsafe { mem::zeroed() }
        };
        let ok = unsafe {
            SetFileInformationByHandle(
                h.as_raw(),
                FileBasicInfo,
                &info as *const FILE_BASIC_INFO as *const _,
                mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    }

    /// Write the override_stat stream as a host process would, then put ChangeTime back to
    /// `change_time`, as if the write had landed in the same timestamp tick.
    fn rewrite_override_stat_keeping(path: &Path, value: &[u8], change_time: i64) {
        fs::write(ads_stream_path(path, OVERRIDE_STAT_STREAM), value).unwrap();
        set_change_time(path, change_time);
    }

    #[test]
    fn a_host_edit_of_override_stat_is_seen() {
        let share = Share::new("override-edit");
        let fs = share.served();
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");
        set_change_time(&path, filetime_now() - 3600 * SETTLED_CHANGE_TIME);
        assert_eq!(permissions(&fs, file), 0o644);

        fs::write(ads_stream_path(&path, OVERRIDE_STAT_STREAM), b"0:0:04755").unwrap();
        assert_eq!(permissions(&fs, file), 0o4755);
    }

    #[test]
    fn override_stat_is_read_once_while_change_time_is_settled() {
        let share = Share::new("override-cached");
        let fs = share.served();
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");
        let settled = filetime_now() - 3600 * SETTLED_CHANGE_TIME;
        set_change_time(&path, settled);
        assert_eq!(permissions(&fs, file), 0o644);

        // Only a getattr that skips reading the stream still reports the old mode.
        rewrite_override_stat_keeping(&path, b"0:0:04755", settled);
        assert_eq!(change_time(&path), settled);
        assert_eq!(permissions(&fs, file), 0o644);
    }

    #[test]
    fn override_stat_is_read_again_while_change_time_is_recent() {
        let share = Share::new("override-recent");
        let fs = share.served();
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");
        let recent = filetime_now();
        set_change_time(&path, recent);
        assert_eq!(permissions(&fs, file), 0o644);

        rewrite_override_stat_keeping(&path, b"0:0:04755", recent);
        assert_eq!(permissions(&fs, file), 0o4755);
    }

    #[test]
    fn a_lookup_by_name_reports_what_an_open_handle_does() {
        let share = Share::new("by-name");
        let fs = share.served();
        let path = share.root.join("sub").join("inside.txt");
        fs::write(
            ads_stream_path(&path, OVERRIDE_STAT_STREAM),
            b"1000:1000:0600",
        )
        .unwrap();
        let dir = fs.lookup(CTX, fuse::ROOT_ID, c"sub").unwrap();
        let by_name = fs.lookup(CTX, dir.inode, c"inside.txt").unwrap().attr;

        let (handle, _) = fs.open(CTX, by_name.st_ino, false, 0).unwrap();
        let (by_handle, _) = fs.getattr(CTX, by_name.st_ino, handle).unwrap();
        fs.release(CTX, by_name.st_ino, 0, handle.unwrap(), false, false, None)
            .unwrap();

        let fields = |st: &stat64| {
            (
                st.st_ino,
                st.st_mode,
                st.st_uid,
                st.st_gid,
                st.st_nlink,
                st.st_size,
                st.st_mtime,
                st.st_mtime_nsec,
            )
        };
        assert_eq!(fields(&by_name), fields(&by_handle));
        assert_eq!(by_name.st_mode, libc::S_IFREG as u32 | 0o600);
        assert_eq!(
            fields(&dir.attr),
            fields(&fs.getattr(CTX, dir.inode, None).unwrap().0)
        );
    }

    #[test]
    fn a_lookup_of_a_missing_name_is_enoent() {
        let share = Share::new("by-name-missing");
        let fs = share.served();
        refused(
            fs.lookup(CTX, fuse::ROOT_ID, c"missing"),
            io::Error::from_raw_os_error(linux_errno_raw(libc::ENOENT)),
            "a missing name was found",
        );
    }

    #[test]
    fn a_symlink_lookup_reports_the_link_itself() {
        let share = Share::new("by-name-symlink");
        let fs = share.served();
        fs::write(share.root.join("target.txt"), b"0123456789").unwrap();
        let link = match fs.symlink(
            CTX,
            c"target.txt",
            fuse::ROOT_ID,
            c"link",
            Extensions::default(),
        ) {
            Ok(entry) => entry.inode,
            Err(e) => {
                eprintln!("skipped: this host cannot create symlinks: {e}");
                return;
            }
        };

        let target = fs.lookup(CTX, fuse::ROOT_ID, c"target.txt").unwrap().attr;
        let by_lookup = fs.lookup(CTX, fuse::ROOT_ID, c"link").unwrap().attr;
        let (by_getattr, _) = fs.getattr(CTX, link, None).unwrap();
        for attr in [by_lookup, by_getattr] {
            assert_eq!(attr.st_ino, link);
            assert_ne!(attr.st_ino, target.st_ino);
            assert_eq!(attr.st_mode & libc::S_IFMT as u32, S_IFLNK as u32);
        }
    }

    const USER: Context = Context {
        uid: 1000,
        gid: 1001,
        pid: 0,
    };

    fn stored_lx(path: &Path) -> Option<OverrideStat> {
        lx_metadata(&get_lx_info_by_name(path).unwrap().unwrap())
    }

    fn override_stream(path: &Path) -> PathBuf {
        ads_stream_path(path, OVERRIDE_STAT_STREAM)
    }

    #[test]
    fn new_entries_keep_their_metadata_in_wsl_extended_attributes() {
        let share = Share::new("lx-new");
        let fs = share.served();
        fs.create(
            USER,
            fuse::ROOT_ID,
            c"file",
            0o640,
            false,
            LINUX_O_CREAT as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
        fs.mkdir(USER, fuse::ROOT_ID, c"dir", 0o750, 0, Extensions::default())
            .unwrap();

        let file = share.root.join("file");
        let dir = share.root.join("dir");
        assert_eq!(
            stored_lx(&file),
            Some((Some(1000), Some(1001), Some(S_IFREG as u32 | 0o640)))
        );
        assert_eq!(
            stored_lx(&dir),
            Some((Some(1000), Some(1001), Some(libc::S_IFDIR as u32 | 0o750)))
        );
        assert!(!override_stream(&file).exists());
        assert!(!override_stream(&dir).exists());
    }

    #[test]
    fn wsl_metadata_takes_precedence_over_the_override_stream() {
        let share = Share::new("lx-precedence");
        let fs = share.served();
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");
        fs::write(override_stream(&path), b"1:1:0600").unwrap();
        write_lx_metadata(
            &path,
            (Some(1000), Some(1001), Some(S_IFREG as u32 | 0o644)),
        )
        .unwrap();

        let (attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!((attr.st_uid, attr.st_gid), (1000, 1001));
        assert_eq!(attr.st_mode, S_IFREG as u32 | 0o644);
    }

    #[test]
    fn a_host_edit_of_wsl_metadata_is_seen_through_an_open_handle() {
        let share = Share::new("lx-edit");
        let fs = share.served();
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");
        set_change_time(&path, filetime_now() - 3600 * SETTLED_CHANGE_TIME);
        let (handle, _) = fs.open(CTX, file, false, 0).unwrap();
        let mode = |fs: &PassthroughFs| fs.getattr(CTX, file, handle).unwrap().0.st_mode & 0o7777;
        assert_eq!(mode(&fs), 0o644);

        write_lx_metadata(&path, (None, None, Some(S_IFREG as u32 | 0o600))).unwrap();
        assert_eq!(mode(&fs), 0o600);

        fs.release(CTX, file, 0, handle.unwrap(), false, false, None)
            .unwrap();
    }

    #[test]
    fn a_chmod_of_an_entry_kept_in_the_stream_writes_wsl_extended_attributes() {
        let share = Share::new("lx-from-stream");
        let fs = share.served();
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");
        fs::write(override_stream(&path), b"1000:1001:0600").unwrap();

        let mut attr: stat64 = unsafe { mem::zeroed() };
        attr.st_mode = S_IFREG as u32 | 0o640;
        let (reply, _) = fs
            .setattr(CTX, file, attr, None, SetattrValid::MODE)
            .unwrap();

        assert_eq!((reply.st_uid, reply.st_gid), (1000, 1001));
        assert_eq!(
            stored_lx(&path),
            Some((Some(1000), Some(1001), Some(S_IFREG as u32 | 0o640)))
        );
        let (attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(
            (attr.st_uid, attr.st_gid, attr.st_mode),
            (1000, 1001, S_IFREG as u32 | 0o640)
        );
    }

    #[test]
    fn a_chmod_of_a_directory_in_simplified_semantics_keeps_its_mode() {
        let share = Share::new("simplified-dir-chmod");
        let fs = share.served_as(PermissionSemantics::LinuxSimplified);
        let entry = fs
            .mkdir(CTX, fuse::ROOT_ID, c"dir", 0o755, 0, Extensions::default())
            .unwrap();

        let mut attr: stat64 = unsafe { mem::zeroed() };
        attr.st_mode = libc::S_IFDIR as u32 | 0o700;
        let (reply, _) = fs
            .setattr(CTX, entry.inode, attr, None, SetattrValid::MODE)
            .unwrap();
        assert_eq!(reply.st_mode, libc::S_IFDIR as u32 | 0o700);

        let (attr, _) = fs.getattr(CTX, entry.inode, None).unwrap();
        assert_eq!(attr.st_mode, libc::S_IFDIR as u32 | 0o700);
    }

    #[test]
    fn a_chmod_in_simplified_semantics_keeps_the_permission_bits() {
        let share = Share::new("simplified-chmod");
        let fs = share.served_as(PermissionSemantics::LinuxSimplified);
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");

        let mut attr: stat64 = unsafe { mem::zeroed() };
        attr.st_mode = S_IFREG as u32 | 0o755;
        let (reply, _) = fs
            .setattr(CTX, file, attr, None, SetattrValid::MODE)
            .unwrap();
        assert_eq!(reply.st_mode, S_IFREG as u32 | 0o755);
        assert_eq!(
            stored_lx(&path),
            Some((None, None, Some(S_IFREG as u32 | 0o755)))
        );
        let (mut attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(attr.st_mode, S_IFREG as u32 | 0o755);

        // A chmod that drops them drops the stored ones too.
        attr.st_mode = S_IFREG as u32 | 0o644;
        fs.setattr(CTX, file, attr, None, SetattrValid::MODE)
            .unwrap();
        let (mut attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(attr.st_mode, S_IFREG as u32 | 0o644);

        // Only the owner's write bit gives way to the Read-Only attribute:
        // the group and other ones round-trip as stored.
        attr.st_mode = S_IFREG as u32 | 0o777;
        fs.setattr(CTX, file, attr, None, SetattrValid::MODE)
            .unwrap();
        let (attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(attr.st_mode, S_IFREG as u32 | 0o777);
    }

    #[test]
    fn a_chmod_in_simplified_semantics_maps_write_permission_to_the_read_only_attribute() {
        let share = Share::new("simplified-readonly");
        let fs = share.served_as(PermissionSemantics::LinuxSimplified);
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");

        let mut attr: stat64 = unsafe { mem::zeroed() };
        attr.st_mode = S_IFREG as u32 | 0o555;
        fs.setattr(CTX, file, attr, None, SetattrValid::MODE)
            .unwrap();
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        let (mut attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(attr.st_mode, S_IFREG as u32 | 0o555);

        attr.st_mode = S_IFREG as u32 | 0o755;
        fs.setattr(CTX, file, attr, None, SetattrValid::MODE)
            .unwrap();
        assert!(!fs::metadata(&path).unwrap().permissions().readonly());
        let (attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(attr.st_mode, S_IFREG as u32 | 0o755);
    }

    #[test]
    fn a_mode_the_host_keeps_is_reported_in_simplified_semantics() {
        let share = Share::new("simplified-host-mode");
        let fs = share.served_as(PermissionSemantics::LinuxSimplified);
        let file = inside(&fs);
        let path = share.root.join("sub").join("inside.txt");
        write_lx_metadata(
            &path,
            (Some(1000), Some(1001), Some(S_IFREG as u32 | 0o750)),
        )
        .unwrap();

        let (attr, _) = fs.getattr(CTX, file, None).unwrap();
        assert_eq!(attr.st_mode, S_IFREG as u32 | 0o750);
        // Ownership stays the requester's, not the stored one.
        assert_eq!((attr.st_uid, attr.st_gid), (CTX.uid, CTX.gid));
        let (attr, _) = fs.getattr(USER, file, None).unwrap();
        assert_eq!((attr.st_uid, attr.st_gid), (USER.uid, USER.gid));
    }

    #[test]
    fn a_file_created_in_simplified_semantics_keeps_its_mode() {
        let share = Share::new("simplified-create");
        let fs = share.served_as(PermissionSemantics::LinuxSimplified);
        let (entry, handle, _) = fs
            .create(
                USER,
                fuse::ROOT_ID,
                c"script",
                0o755,
                false,
                LINUX_O_CREAT as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        assert_eq!(entry.attr.st_mode, S_IFREG as u32 | 0o755);
        assert_eq!(entry.attr.st_uid, USER.uid);
        assert_eq!(
            stored_lx(&share.root.join("script")),
            Some((None, None, Some(S_IFREG as u32 | 0o755)))
        );
        let (attr, _) = fs.getattr(USER, entry.inode, None).unwrap();
        assert_eq!(attr.st_mode, S_IFREG as u32 | 0o755);
        fs.release(USER, entry.inode, 0, handle.unwrap(), false, false, None)
            .unwrap();
    }

    #[test]
    fn a_directory_created_in_simplified_semantics_keeps_its_mode() {
        let share = Share::new("simplified-mkdir");
        let fs = share.served_as(PermissionSemantics::LinuxSimplified);
        let entry = fs
            .mkdir(USER, fuse::ROOT_ID, c"dir", 0o700, 0, Extensions::default())
            .unwrap();
        assert_eq!(entry.attr.st_mode, libc::S_IFDIR as u32 | 0o700);
        let (attr, _) = fs.getattr(USER, entry.inode, None).unwrap();
        assert_eq!(attr.st_mode, libc::S_IFDIR as u32 | 0o700);
    }

    #[test]
    fn access_in_simplified_semantics_checks_the_execute_bits() {
        let share = Share::new("simplified-access");
        let fs = share.served_as(PermissionSemantics::LinuxSimplified);
        let file = inside(&fs);

        refused(
            fs.access(CTX, file, 1),
            eacces(),
            "a file no chmod made executable passed an X_OK check",
        );

        let mut attr: stat64 = unsafe { mem::zeroed() };
        attr.st_mode = S_IFREG as u32 | 0o755;
        fs.setattr(CTX, file, attr, None, SetattrValid::MODE)
            .unwrap();
        fs.access(CTX, file, 1).unwrap();
    }

    #[test]
    fn a_symlinks_metadata_stays_on_the_link() {
        let share = Share::new("lx-symlink");
        let fs = share.served();
        fs::write(share.root.join("target.txt"), b"0123456789").unwrap();
        if let Err(e) = fs.symlink(
            USER,
            c"target.txt",
            fuse::ROOT_ID,
            c"link",
            Extensions::default(),
        ) {
            eprintln!("skipped: this host cannot create symlinks: {e}");
            return;
        }

        assert_eq!(
            stored_lx(&share.root.join("link")),
            Some((Some(1000), Some(1001), Some(S_IFLNK as u32 | 0o777)))
        );
        assert_eq!(stored_lx(&share.root.join("target.txt")), None);
    }

    #[test]
    fn a_symlink_to_a_nested_target_is_created() {
        let share = Share::new("symlink-nested");
        let fs = share.served();
        let entry = match fs.symlink(
            USER,
            c"sub/inside.txt",
            fuse::ROOT_ID,
            c"link",
            Extensions::default(),
        ) {
            Ok(entry) => entry,
            Err(e) if !share.root.join("link").exists() => {
                eprintln!("skipped: this host cannot create symlinks: {e}");
                return;
            }
            Err(e) => panic!("the link was made but the symlink failed: {e}"),
        };

        assert_eq!(entry.attr.st_mode & libc::S_IFMT as u32, S_IFLNK as u32);
        assert_eq!(fs.readlink(CTX, entry.inode).unwrap(), b"sub/inside.txt");
    }

    const LINUX_O_RDWR: u32 = 2;

    /// The payload of a guest write.
    struct Payload<'a>(&'a [u8]);

    impl io::Read for Payload<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl ZeroCopyReader for Payload<'_> {
        fn read_to(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
            let n = f.seek_write(&self.0[..count.min(self.0.len())], off)?;
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    /// A setuid file created by the guest, with the handle the create opened.
    fn create_setuid(fs: &PassthroughFs) -> (Inode, Handle) {
        let (entry, handle, _) = fs
            .create(
                CTX,
                fuse::ROOT_ID,
                c"setuid",
                0o4755,
                false,
                LINUX_O_CREAT as u32 | LINUX_O_RDWR,
                0,
                Extensions::default(),
            )
            .unwrap();
        (entry.inode, handle.unwrap())
    }

    fn write_as_unprivileged(fs: &PassthroughFs, inode: Inode, handle: Handle) {
        fs.write(
            CTX,
            inode,
            handle,
            Payload(b"data"),
            4,
            0,
            None,
            false,
            true,
            0,
        )
        .unwrap();
    }

    fn permissions(fs: &PassthroughFs, inode: Inode) -> u32 {
        fs.getattr(CTX, inode, None).unwrap().0.st_mode & 0o7777
    }

    #[test]
    fn a_write_drops_suid_again_after_a_chmod_restores_it() {
        let share = Share::new("kill-priv-chmod");
        let fs = share.served();
        let (file, handle) = create_setuid(&fs);
        assert_eq!(permissions(&fs, file), 0o4755);

        write_as_unprivileged(&fs, file, handle);
        assert_eq!(permissions(&fs, file), 0o755);

        let mut attr: stat64 = unsafe { mem::zeroed() };
        attr.st_mode = 0o4755;
        fs.setattr(CTX, file, attr, None, SetattrValid::MODE)
            .unwrap();
        assert_eq!(permissions(&fs, file), 0o4755);

        write_as_unprivileged(&fs, file, handle);
        assert_eq!(permissions(&fs, file), 0o755);

        fs.release(CTX, file, 0, handle, false, false, None)
            .unwrap();
    }

    #[test]
    fn a_write_after_privileges_were_dropped_does_no_metadata_io() {
        let share = Share::new("kill-priv-once");
        let fs = share.served();
        let (file, handle) = create_setuid(&fs);
        write_as_unprivileged(&fs, file, handle);

        // Privileges only a host process could have restored since: a later write
        // leaving them in place shows it touched no metadata.
        let path = share.root.join("setuid");
        let capability = ads_stream_path(&path, SECURITY_CAPABILITY_STREAM);
        fs::write(&capability, b"cap").unwrap();
        write_lx_metadata(&path, (None, None, Some(S_IFREG as u32 | 0o4755))).unwrap();

        write_as_unprivileged(&fs, file, handle);
        assert!(capability.exists());
        assert_eq!(permissions(&fs, file), 0o4755);

        fs.release(CTX, file, 0, handle, false, false, None)
            .unwrap();
    }
}
