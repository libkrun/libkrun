// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::collections::btree_map;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::ptr::null_mut;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crossbeam_channel::{Sender, unbounded};
use nix::errno::Errno;
use utils::worker_message::WorkerMessage;

use crate::virtio::fs::filesystem::SecContext;

use super::fd_budget::{DescriptorBudget, Reservation};

use super::super::super::linux_errno::{LINUX_ERANGE, linux_error};
use super::super::bindings;
use super::super::filesystem::{
    Context, DirEntry, Entry, ExportTable, Extensions, FileSystem, FsOptions, GetxattrReply,
    ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::super::fuse;
use super::super::inode_alloc::InodeAllocator;
use super::super::multikey::MultikeyBTreeMap;
use super::super::{FuseHandleSnap, FuseInodeSnap, FuseServerState};

const XATTR_KEY: &[u8] = b"user.containers.override_stat\0";
const SECURITY_CAPABILITY: &[u8] = b"security.capability\0";

/// macOS-private xattr namespace prefix. Attributes in this namespace (e.g.
/// `com.apple.provenance`, `com.apple.quarantine`) have no meaning in a Linux
/// guest. Exposing them causes xattr-aware Linux tools like `rsync -X` to
/// attempt `lsetxattr(..., "com.apple.*", ...)` on destination filesystems
/// (tmpfs, overlayfs) that reject the unknown namespace with EOPNOTSUPP,
/// producing spurious errors and non-zero exit codes.
///
/// We strip this prefix from `listxattr` and return `ENODATA` from `getxattr`
/// so that the Linux guest sees a consistent empty set of these attributes.
const MACOS_XATTR_PREFIX: &[u8] = b"com.apple.";

const UID_MAX: u32 = u32::MAX - 1;

/// Where macOS keeps the Rosetta runtime for Linux guests. A share rooted here
/// holds the binary the guest registers as its x86_64 binfmt interpreter.
const ROSETTA_RUNTIME_DIR: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux";

/// What Rosetta expects to read back from the file system holding its binary
/// before it translates anything. Virtualization.framework's Rosetta share
/// answers with this; the reply is the string and its terminating NUL.
const ROSETTA_KEY: &[u8] =
    b"Our hard work\nby these words guarded\nplease don't steal\n\xC2\xA9 Apple Inc\0";

type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
struct InodeAltKey {
    ino: u64,
    dev: i32,
}

struct InodeData {
    inode: Inode,
    ino: u64,
    dev: i32,
    refcount: AtomicU64,
    unlinked_fd: AtomicI64,
    /// The override xattr's values as last read or written for this file,
    /// with the host ctime at that moment. A stat whose ctime matches uses
    /// them without reading the xattr; the host bumps a file's ctime for any
    /// change to its xattrs (and its owner or mode), so a value read under
    /// the same ctime is the current one, whoever last wrote it.
    override_cache: Mutex<Option<CachedOverride>>,
    metadata_lock: Mutex<()>,
}

/// The uid, gid and mode an override xattr holds, each optional.
type Override = (Option<u32>, Option<u32>, Option<u32>);

#[derive(Clone, Copy)]
struct CachedOverride {
    over: Override,
    ctime: (i64, i64),
}

fn ctime_of(st: &bindings::stat64) -> (i64, i64) {
    (st.st_ctime, st.st_ctime_nsec)
}

enum InodeHandle {
    Fd(RawFd),
    Path(CString),
}

struct CachedDirEntry {
    ino: bindings::ino64_t,
    name: Box<[u8]>,
    type_: u8,
}

struct DirStream {
    entries: Vec<CachedDirEntry>,
    ready: bool,
}

/// A descriptor kept for a file the kernel opened without a request (see
/// `PassthroughFs::zero_message_open`): the requests that follow name the
/// inode and handle 0, so the server keeps one open file per inode for them.
struct CachedFd {
    _reservation: Reservation,
    data: Arc<HandleData>,
    /// CREATE can supply a write-only or read-only descriptor. Handle-less
    /// requests must reopen it when the requested access is not available.
    readable: bool,
    writable: bool,
}

/// Descriptors for files opened without a request, by inode, oldest first.
struct InodeFds {
    budget: Arc<DescriptorBudget>,
    map: HashMap<Inode, CachedFd>,
    order: VecDeque<Inode>,
}

/// Files kept open for the kernel's handle-less requests. A forgotten inode
/// drops its entry; past this many, the oldest goes and is reopened on demand.
const INODE_FDS_MAX: usize = 4096;

impl Default for InodeFds {
    fn default() -> Self {
        Self {
            budget: DescriptorBudget::process(),
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl InodeFds {
    fn evict_oldest(&mut self) {
        while let Some(old) = self.order.pop_front() {
            if self.map.remove(&old).is_some() {
                break;
            }
        }
    }
}

impl DirStream {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            ready: false,
        }
    }

    fn get_entry<'a>(&'a self, offset: u64) -> Option<DirEntry<'a>> {
        self.entries.get(offset as usize).map(|e| DirEntry {
            ino: e.ino,
            // offset points to the next entry, not the current one
            offset: offset + 1,
            type_: u32::from(e.type_),
            name: &e.name,
        })
    }

    fn fill_from_fd(&mut self, fd: RawFd) -> io::Result<()> {
        let dev = fstat(fd, true)?.st_dev;
        // fdopendir() takes ownership of the fd, so we need to obtain a new one
        // to be donated.
        let newfd = unsafe { libc::dup(fd) };
        if newfd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }
        let dir = unsafe { libc::fdopendir(newfd) };
        if dir.is_null() {
            let err = io::Error::last_os_error();
            let _ = unsafe { libc::close(newfd) };
            return Err(linux_error(err));
        }

        loop {
            // To detect if error happened in readdir we should clear errno
            // before the call and then verify it after
            Errno::clear();
            let dentry = unsafe { libc::readdir(dir) };
            if dentry.is_null() {
                let errno = Errno::last_raw();
                if errno != 0 {
                    let err = io::Error::from_raw_os_error(errno);
                    let _ = unsafe { libc::closedir(dir) };
                    // Error happened in readdir, but we keep the entries we
                    // already read to handle the partial read.
                    return Err(linux_error(err));
                }
                break;
            }
            // SAFETY: dentry is not null.
            // We trust macOS to return correct number of bytes for the name
            // length. The lifetime of a slice does not escape the unsafe block
            // as we copy the data into box right away.
            let name = unsafe {
                let name_len = usize::from((*dentry).d_namlen);
                let name_ptr = (*dentry).d_name.as_ptr().cast();
                let name = std::slice::from_raw_parts(name_ptr, name_len);

                if name == b"." || name == b".." {
                    continue;
                }
                Box::<[u8]>::from(name)
            };

            // SAFETY: dentry is not null.
            let ino = unsafe { (*dentry).d_ino };
            // SAFETY: dentry is not null. The entry types use the same
            // exact constants (`libc::DT_*`) on macOS, Linux, and FUSE.
            let type_ = guest_dirent_type(dev, ino, unsafe { (*dentry).d_type });

            self.entries.push(CachedDirEntry { ino, name, type_ });
        }

        unsafe { libc::closedir(dir) };
        Ok(())
    }
}

// Special guest nodes are regular backing files with a recorded mode. Returning
// the host DT_REG for a whiteout makes overlayfs enumerate a deleted name even
// though lookup correctly hides it. Read the recorded type for regular backing
// files; directories and symlinks keep their native types without extra I/O.
fn guest_dirent_type(dev: libc::dev_t, ino: u64, host_type: u8) -> u8 {
    if host_type != libc::DT_REG {
        return host_type;
    }
    let path = CString::new(format!("/.vol/{dev}/{ino}")).unwrap();
    let mut buf = [0u8; 32];
    // SAFETY: path and the key are NUL-terminated and buf is writable. NOFOLLOW
    // prevents following a host symlink if the entry changes during the scan.
    let size = unsafe {
        libc::getxattr(
            path.as_ptr(),
            XATTR_KEY.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if size < 0 {
        // Absence means the native type is authoritative. Other errors must
        // not mislabel a possible whiteout: let the guest resolve its type.
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOATTR) {
            host_type
        } else {
            libc::DT_UNKNOWN
        };
    }
    match get_xattr_common(&buf[..size as usize]) {
        Ok((_, _, Some(mode))) if mode & libc::S_IFMT as u32 != 0 => {
            ((mode & libc::S_IFMT as u32) >> 12) as u8
        }
        _ => host_type,
    }
}

struct HandleData {
    inode: Inode,
    file: RwLock<File>,
    dirstream: Mutex<DirStream>,
}

// Runs inside setattr once it holds the handle's fd, so a test can race a
// RELEASE against the fd syscalls deterministically.
#[cfg(test)]
thread_local! {
    #[allow(clippy::type_complexity)]
    static SETATTR_FD_HOOK: std::cell::Cell<Option<Box<dyn FnOnce(&PassthroughFs)>>> =
        const { std::cell::Cell::new(None) };
}

fn ebadf() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EBADF))
}

fn einval() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EINVAL))
}

fn item_to_value(item: &[u8], radix: u32) -> Option<u32> {
    match std::str::from_utf8(item) {
        Ok(val) => match u32::from_str_radix(val, radix) {
            Ok(i) => Some(i),
            Err(e) => {
                debug!("invalid value: {radix} err={e}");
                None
            }
        },
        Err(_) => None,
    }
}

fn get_xattr_common(buf: &[u8]) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut items = buf.split(|c| *c == b':');

    let uid = match items.next() {
        Some(item) => item_to_value(item, 10),
        None => None,
    };
    let gid = match items.next() {
        Some(item) => item_to_value(item, 10),
        None => None,
    };
    let mode = match items.next() {
        Some(item) => item_to_value(item, 8),
        None => None,
    };

    Ok((uid, gid, mode))
}

fn get_xattr_fstat(
    fd: RawFd,
    st: bindings::stat64,
) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut buf: Vec<u8> = vec![0; 32];
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };
    let res = unsafe {
        libc::fgetxattr(
            fd,
            XATTR_KEY.as_ptr() as *const i8,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            options,
        )
    };
    if res < 0 {
        debug!("fget_xattr error: {res}");
        return Ok((None, None, None));
    }

    buf.resize(res as usize, 0);

    get_xattr_common(&buf)
}

fn get_xattr_lstat(
    path: &CString,
    st: bindings::stat64,
) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let mut buf: Vec<u8> = vec![0; 32];
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };
    let res = unsafe {
        libc::getxattr(
            path.as_ptr(),
            XATTR_KEY.as_ptr() as *const i8,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            options,
        )
    };
    if res < 0 {
        debug!("fget_xattr error: {res}");
        return Ok((None, None, None));
    }

    buf.resize(res as usize, 0);

    get_xattr_common(&buf)
}

fn is_valid_owner(owner: Option<(u32, u32)>) -> bool {
    if let Some(owner) = owner
        && owner.0 < UID_MAX
        && owner.1 < UID_MAX
    {
        return true;
    }

    false
}
// We won't need this once expressions like "if let ... &&" are allowed.
#[allow(clippy::unnecessary_unwrap)]
/// Mirror a guest chmod's permission bits onto the host file, as the Linux
/// backend's real chmod does, so a script the guest makes executable also runs
/// on the host. The full mode, special bits included, stays in the override
/// xattr the guest reads. Only regular files and directories carry it: other
/// types are emulated by the xattr. A refusal (a file another host user owns)
/// leaves the host mode as it was.
fn apply_host_permissions(file: &InodeHandle, mode: u32) {
    let Ok(st) = istat(file, true) else {
        return;
    };
    let kind = st.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG && kind != libc::S_IFDIR {
        return;
    }
    let perms = (mode & 0o777) as libc::mode_t;
    // SAFETY: the fd or path is live for the call and the result is checked.
    let res = unsafe {
        match file {
            InodeHandle::Fd(fd) => libc::fchmod(*fd, perms),
            InodeHandle::Path(c_path) => libc::fchmodat(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                perms,
                libc::AT_SYMLINK_NOFOLLOW,
            ),
        }
    };
    if res < 0 {
        debug!(
            "setattr: host chmod {perms:o} refused: {}",
            io::Error::last_os_error()
        );
    }
}

/// Guest root may change ownership or permissions on a read-only inode. macOS
/// nevertheless requires owner-write permission to update its override xattr.
/// Temporarily grant only that bit to the host owner, and restore it even when
/// the xattr update fails. Paths are inode anchors and never follow symlinks.
fn metadata_write(file: &InodeHandle, mut write: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    let error = match write() {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    if error.raw_os_error() != Some(libc::EACCES) {
        return Err(error);
    }
    let st = istat(file, true)?;
    let kind = st.st_mode & libc::S_IFMT;
    if st.st_uid != unsafe { libc::geteuid() }
        || st.st_mode & libc::S_IWUSR != 0
        || (kind != libc::S_IFREG && kind != libc::S_IFDIR)
    {
        return Err(error);
    }
    let mode = st.st_mode & 0o7777;
    let chmod = |mode| {
        // SAFETY: the borrowed fd or inode path remains live for this operation;
        // fchmodat changes the link itself if a path names a symlink.
        let rc = unsafe {
            match file {
                InodeHandle::Fd(fd) => libc::fchmod(*fd, mode),
                InodeHandle::Path(path) => libc::fchmodat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    mode,
                    libc::AT_SYMLINK_NOFOLLOW,
                ),
            }
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    chmod(mode | libc::S_IWUSR)?;
    let result = write();
    chmod(mode)?;
    result
}

fn set_xattr_stat(
    file: &InodeHandle,
    st: Option<bindings::stat64>,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
) -> io::Result<()> {
    let st = match st {
        Some(st) => st,
        None => istat(file, true)?,
    };
    let options = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        libc::XATTR_NOFOLLOW
    } else {
        0
    };

    let buf = if let (Some(owner), Some(mode), true) = (owner, mode, is_valid_owner(owner)) {
        format!("{}:{}:0{:o}", owner.0, owner.1, mode)
    } else {
        let (orig_uid, orig_gid, orig_mode) = match file {
            InodeHandle::Fd(fd) => get_xattr_fstat(*fd, st)?,
            InodeHandle::Path(c_path) => get_xattr_lstat(c_path, st)?,
        };

        let (uid, gid) = match owner {
            Some(o) => {
                let uid = if o.0 < UID_MAX { Some(o.0) } else { orig_uid };
                let gid = if o.1 < UID_MAX { Some(o.1) } else { orig_gid };
                (uid, gid)
            }
            None => (orig_uid, orig_gid),
        };

        let mut buf = String::new();
        if let Some(uid) = uid {
            buf.push_str(&format!("{uid}"));
        } else {
            buf.push('x');
        }
        if let Some(gid) = gid {
            buf.push_str(&format!(":{gid}:"));
        } else {
            buf.push_str(":x:");
        }
        if let Some(mode) = mode {
            buf.push_str(&format!("0{:o}", mode));
        } else if let Some(orig_mode) = orig_mode {
            buf.push_str(&format!("0{:o}", orig_mode));
        } else {
            buf.push('x');
        }
        buf
    };

    let write = || {
        let res = match file {
            InodeHandle::Path(path) => unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    XATTR_KEY.as_ptr() as *const i8,
                    buf.as_ptr() as *mut libc::c_void,
                    buf.len() as libc::size_t,
                    0,
                    libc::XATTR_NOFOLLOW,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fsetxattr(
                    *fd,
                    XATTR_KEY.as_ptr() as *const i8,
                    buf.as_ptr() as *mut libc::c_void,
                    buf.len() as libc::size_t,
                    0,
                    options,
                )
            },
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    metadata_write(file, write).map_err(linux_error)
}

fn stat_common(
    mut st: bindings::stat64,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
    host: bool,
) -> io::Result<bindings::stat64> {
    if !host {
        if let Some(uid) = uid {
            st.st_uid = uid;
        }
        if let Some(gid) = gid {
            st.st_gid = gid;
        }
        if let Some(mode) = mode {
            if mode as u16 & libc::S_IFMT == 0 {
                st.st_mode = (st.st_mode & libc::S_IFMT) | mode as u16;
            } else {
                st.st_mode = mode as u16;
            }
        }
    }

    Ok(st)
}

fn fstat(fd: RawFd, host: bool) -> io::Result<bindings::stat64> {
    let mut st = MaybeUninit::<bindings::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        let st = unsafe { st.assume_init() };
        if !host {
            let (uid, gid, mode) = get_xattr_fstat(fd, st)?;
            stat_common(st, uid, gid, mode, host)
        } else {
            Ok(st)
        }
    } else {
        Err(linux_error(io::Error::last_os_error()))
    }
}

fn lstat(c_path: &CString, host: bool) -> io::Result<bindings::stat64> {
    let mut st = MaybeUninit::<bindings::stat64>::zeroed();

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe { libc::lstat(c_path.as_ptr(), st.as_mut_ptr()) };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        let st = unsafe { st.assume_init() };
        if !host {
            let (uid, gid, mode) = get_xattr_lstat(c_path, st)?;
            stat_common(st, uid, gid, mode, host)
        } else {
            Ok(st)
        }
    } else {
        Err(linux_error(io::Error::last_os_error()))
    }
}

fn istat(ihandle: &InodeHandle, host: bool) -> io::Result<bindings::stat64> {
    match ihandle {
        InodeHandle::Fd(fd) => fstat(*fd, host),
        InodeHandle::Path(c_path) => lstat(c_path, host),
    }
}

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Debug, Default, Clone)]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy and
    /// uses close-to-open consistency as described in the enum documentation.
    #[default]
    Auto,

    /// The client should always cache file data. This means that the FUSE client will not
    /// invalidate any cached data that was returned by the file system the last time the file was
    /// opened. This policy should only be selected when the file system has exclusive access to the
    /// directory.
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

    /// How long the guest may keep a name that does not exist before asking
    /// again. Zero (the default) caches nothing: every stat of a missing path
    /// is a request. A share whose host directory is watched can afford a
    /// second, since the watcher drops the guest's entry when the host
    /// creates the name.
    pub negative_timeout: Duration,

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
    /// The default is `/`.
    pub root_dir: String,

    /// Whether the file system should support Extended Attributes (xattr). Enabling this feature may
    /// have a significant impact on performance, especially on write parallelism. This is the result
    /// of FUSE attempting to remove the special file privileges after each write request.
    ///
    /// The default value for this options is `false`.
    pub xattr: bool,
    /// Keep chmod changes in the override xattr without changing host access,
    /// matching the Linux recorded-ownership server. Guest root must still be
    /// able to traverse mode-000 directories (including overlayfs workdirs).
    /// Ownership is always read from the override xattr on macOS; without this
    /// flag, chmod also mirrors ordinary permission bits onto the host.
    pub override_stat: bool,

    /// The owner a file is served as when it records none of its own: a
    /// mount whose files should belong to a guest user, not to root or to the
    /// host's account. The guest's chown still records an owner per file.
    pub default_owner: Option<(u32, u32)>,

    /// Optional file descriptor for /proc/self/fd. Callers can obtain a file descriptor and pass it
    /// here, so there's no need to open it in PassthroughFs::new(). This is specially useful for
    /// sandboxing.
    ///
    /// The default is `None`.
    pub proc_sfd_rawfd: Option<RawFd>,

    /// ID of this filesystem to uniquely identify exports. Not supported for macos.
    pub export_fsid: u64,
    /// Table of exported FDs to share with other subsystems. Not supported for macos.
    pub export_table: Option<ExportTable>,

    /// Whether the guest may request deletion of the root directory via the
    /// `VIRTIO_IOC_REMOVE_ROOT_DIR_REQ` ioctl. Defaults to `false`.
    pub allow_root_dir_delete: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            negative_timeout: Duration::ZERO,
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            root_dir: String::from("/"),
            xattr: true,
            override_stat: false,
            default_owner: None,
            proc_sfd_rawfd: None,
            export_fsid: 0,
            export_table: None,
            allow_root_dir_delete: false,
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
    inodes: RwLock<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>>,
    inode_alloc: Arc<InodeAllocator>,

    handles: RwLock<BTreeMap<Handle, Arc<HandleData>>>,
    next_handle: AtomicU64,

    map_windows: Mutex<HashMap<u64, u64>>,

    // Whether writeback caching is enabled for this directory. This will only be true when
    // `cfg.writeback` is true and `init` was called with `FsOptions::WRITEBACK_CACHE`.
    writeback: AtomicBool,
    announce_submounts: AtomicBool,
    /// The kernel opens directories without a request (FUSE_NO_OPENDIR_SUPPORT),
    /// so a readdir can arrive for a directory this server never opened.
    zero_message_opendir: AtomicBool,
    /// The kernel opens regular files without a request (FUSE_NO_OPEN_SUPPORT):
    /// read, write, setattr and the rest arrive with handle 0 for them.
    zero_message_open: AtomicBool,
    inode_fds: Mutex<InodeFds>,
    /// Listings in progress for directories opened without a request, by
    /// inode: a directory's entries are read once at offset 0 and served
    /// chunk by chunk, then dropped when the listing reaches its end.
    handleless_dirs: Mutex<HashMap<Inode, DirStream>>,
    /// The share is the host's Rosetta runtime directory, so Rosetta's start-up
    /// ioctls on its own binary are answered here.
    rosetta_runtime: bool,
    cfg: Config,
}

impl PassthroughFs {
    fn safe_relative_path(path: &Path) -> bool {
        !path.as_os_str().is_empty()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
    }

    fn relative_snapshot_path(root: &Path, path: &Path) -> Option<String> {
        let relative = path.strip_prefix(root).ok()?;
        Self::safe_relative_path(relative).then(|| relative.to_string_lossy().into_owned())
    }

    fn host_path_for_inode(data: &InodeData) -> io::Result<PathBuf> {
        let volfs =
            CString::new(format!("/.vol/{}/{}", data.dev, data.ino)).map_err(|_| einval())?;
        let st = lstat(&volfs, false)?;
        let mut flags = libc::O_RDONLY | libc::O_CLOEXEC;
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            flags |= libc::O_SYMLINK;
        }
        // SAFETY: `volfs` is NUL-terminated and the return value is checked.
        let fd = unsafe { libc::open(volfs.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor was opened above and is uniquely owned here.
        let file = unsafe { File::from_raw_fd(fd) };
        let mut buf = vec![0_u8; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH writes at most PATH_MAX bytes into `buf` for a valid fd.
        let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful F_GETPATH always writes a NUL-terminated path.
        let path = unsafe { CStr::from_ptr(buf.as_ptr().cast()) };
        Ok(PathBuf::from(OsStr::from_bytes(path.to_bytes())))
    }

    /// `(dev, ino)` of `relative` beneath the export root `root`, resolved one
    /// component at a time without following a symlink anywhere in the path.
    /// A lexically clean path is not enough: resolving it from the host root
    /// follows symlinks in every intermediate component, and the tree can change
    /// between snapshot and restore, so an intermediate directory replaced by a
    /// symlink would yield an identity outside the export (later opened through
    /// volfs). Intermediates are opened `O_DIRECTORY | O_NOFOLLOW` (a symlink
    /// fails, with `ENOTDIR` on macOS); the final component is `fstatat`ed with
    /// `AT_SYMLINK_NOFOLLOW`, so a trailing symlink is the link itself. The root
    /// itself may be a symlink (as in `setup_root_inode`).
    fn identity_beneath(root: &Path, relative: &Path) -> io::Result<(i32, u64)> {
        let open_dir = |dirfd: RawFd, name: &CStr, flags: libc::c_int| -> io::Result<File> {
            // SAFETY: `name` is NUL-terminated and the return value is checked.
            let fd = unsafe {
                libc::openat(
                    dirfd,
                    name.as_ptr(),
                    flags | libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: we just opened this fd.
            Ok(unsafe { File::from_raw_fd(fd) })
        };
        let root = CString::new(root.as_os_str().as_bytes()).map_err(|_| einval())?;
        let mut dir = open_dir(libc::AT_FDCWD, &root, 0)?;
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(einval());
            };
            let name = CString::new(name.as_bytes()).map_err(|_| einval())?;
            if components.peek().is_some() {
                dir = open_dir(dir.as_raw_fd(), &name, libc::O_NOFOLLOW)?;
                continue;
            }
            let mut st = MaybeUninit::<libc::stat>::zeroed();
            // SAFETY: `dir` is a valid fd, `name` is NUL-terminated, `st` is a
            // valid out-pointer, and the return value is checked.
            let rc = unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    st.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fstatat succeeded and initialized `st`.
            let st = unsafe { st.assume_init() };
            return Ok((st.st_dev, st.st_ino));
        }
        Err(einval())
    }

    fn restore_inode_identity(&self, snap: &FuseInodeSnap) -> Option<(i32, u64)> {
        if let Some(relative) = snap.relative_path.as_deref() {
            let relative = Path::new(relative);
            if !Self::safe_relative_path(relative) {
                warn!("fs restore: rejecting unsafe relative inode path {relative:?}");
                return None;
            }
            return match Self::identity_beneath(Path::new(&self.cfg.root_dir), relative) {
                Ok(identity) => Some(identity),
                Err(error) => {
                    warn!("fs restore: resolve {relative:?} beneath export root failed: {error}");
                    None
                }
            };
        }

        // Same-host compatibility for snapshots created before relative paths.
        let rest = snap.path.strip_prefix("/.vol/").unwrap_or(&snap.path);
        match rest.split_once('/') {
            Some((dev, inode)) => match (dev.parse::<i32>(), inode.parse::<u64>()) {
                (Ok(dev), Ok(inode)) => Some((dev, inode)),
                _ => None,
            },
            None => None,
        }
    }

    pub fn new(cfg: Config, inode_alloc: Arc<InodeAllocator>) -> io::Result<PassthroughFs> {
        let root = CString::new(cfg.root_dir.as_str()).expect("CString::new failed");

        // Safe because this doesn't modify any memory and we check the return value.
        // Note: O_NOFOLLOW is intentionally omitted here — the root dir is explicitly
        // provided by the caller and may be a symlink (e.g. a dev symlink to a cached
        // rootfs).  O_NOFOLLOW on the final path component would return ELOOP, which
        // linux_error maps to Linux errno 40, which macOS strerror then mis-formats as
        // "Message too long" (EMSGSIZE) causing a confusing BadActivate panic.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, root.as_ptr(), libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        unsafe { libc::close(fd) };

        let rosetta_runtime = Path::new(&cfg.root_dir)
            .canonicalize()
            .is_ok_and(|root| root == Path::new(ROSETTA_RUNTIME_DIR));

        Ok(PassthroughFs {
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            inode_alloc,

            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),

            map_windows: Mutex::new(HashMap::new()),

            writeback: AtomicBool::new(false),
            announce_submounts: AtomicBool::new(false),
            zero_message_opendir: AtomicBool::new(false),
            zero_message_open: AtomicBool::new(false),
            inode_fds: Mutex::new(InodeFds::default()),
            handleless_dirs: Mutex::new(HashMap::new()),
            rosetta_runtime,
            cfg,
        })
    }

    /// Establish the root inode (nodeid `ROOT_ID`) in the inode map. Normally
    /// done as part of `init` (the guest's FUSE_INIT), but also called directly
    /// by [`Self::restore`] because a restored, already-booted clone never
    /// re-sends FUSE_INIT. Idempotent: a later call replaces the entry.
    fn setup_root_inode(&self) -> io::Result<()> {
        let root = CString::new(self.cfg.root_dir.as_str()).expect("CString::new failed");

        // Safe because this doesn't modify any memory and we check the return value.
        // Note: O_NOFOLLOW is intentionally omitted — the root dir may be a symlink
        // (e.g. a dev symlink to a cached rootfs). O_NOFOLLOW on the final path
        // component returns ELOOP, which causes the FUSE session init to fail, which
        // causes the guest to be unable to mount its rootfs.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, root.as_ptr(), libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd above.
        let f = unsafe { File::from_raw_fd(fd) };

        let st = fstat(f.as_raw_fd(), true)?;

        let mut inodes = self.inodes.write().unwrap();

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        inodes.insert(
            fuse::ROOT_ID,
            InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
            },
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                ino: st.st_ino,
                dev: st.st_dev,
                refcount: AtomicU64::new(2),
                unlinked_fd: AtomicI64::new(-1),
                override_cache: Mutex::new(None),
                metadata_lock: Mutex::new(()),
            }),
        );
        Ok(())
    }

    /// Capture the FUSE server's logical state for cross-process fork (the macOS
    /// analogue of the Linux `snapshot`). This passthrough addresses every inode
    /// by its host `(dev, ino)` via volfs (`/.vol/{dev}/{ino}`) rather than by a
    /// held fd, so the snapshot records that identity per nodeid; a clone rebuilds
    /// the map and reopens lazily through volfs. The root inode is re-seeded from
    /// `cfg.root_dir` on restore, and the synthetic boot-time init-binary inode is
    /// not needed by an already-booted clone — both are skipped here.
    /// Register the inode `st` describes (from an `lstat` during lookup) and
    /// return its entry, reusing the existing nodeid when the same host inode is
    /// already known. `parent_dev` decides whether a directory is announced as a
    /// submount.
    fn register_lookup(
        &self,
        st: bindings::stat64,
        parent_dev: i32,
        over: Override,
    ) -> io::Result<Entry> {
        let mut attr_flags: u32 = 0;

        if st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && self.announce_submounts.load(Ordering::Relaxed)
            && (st.st_dev != parent_dev)
        {
            attr_flags |= fuse::ATTR_SUBMOUNT;
        }

        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        let data = self.inodes.read().unwrap().get_alt(&altkey).cloned();

        let inode = if let Some(data) = data {
            // Matches with the release store in `forget`.
            data.refcount.fetch_add(1, Ordering::Acquire);
            *data.override_cache.lock().unwrap() = Some(CachedOverride {
                over,
                ctime: ctime_of(&st),
            });
            data.inode
        } else {
            // There is a possible race here where 2 threads end up adding the same file
            // into the inode list.  However, since each of those will get a unique Inode
            // value and unique file descriptors this shouldn't be that much of a problem.
            let inode = self.inode_alloc.next();
            self.inodes.write().unwrap().insert(
                inode,
                InodeAltKey {
                    ino: st.st_ino,
                    dev: st.st_dev,
                },
                Arc::new(InodeData {
                    inode,
                    ino: st.st_ino,
                    dev: st.st_dev,
                    refcount: AtomicU64::new(1),
                    unlinked_fd: AtomicI64::new(-1),
                    metadata_lock: Mutex::new(()),
                    override_cache: Mutex::new(Some(CachedOverride {
                        over,
                        ctime: ctime_of(&st),
                    })),
                }),
            );

            inode
        };

        Ok(Entry {
            inode,
            generation: 0,
            attr: st,
            attr_flags,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    /// Look up a host directory by absolute path, outside this export's root, and
    /// return its entry. This is how a live share's root enters the inode map; it
    /// is reached only through [`super::super::live_fs::LiveFs`], which decides
    /// which host paths may be served.
    pub fn lookup_host_path(&self, path: &Path) -> io::Result<Entry> {
        let root_dev = self
            .inodes
            .read()
            .unwrap()
            .get(&fuse::ROOT_ID)
            .map(|root| root.dev)
            .ok_or_else(ebadf)?;
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| einval())?;
        let st = lstat(&c_path, true)?;
        let over = get_xattr_lstat(&c_path, st)?;
        let st = self.view(st, over)?;
        self.register_lookup(st, root_dev, over)
    }

    /// The host path an inode currently names, if it is still reachable.
    pub fn host_path_of(&self, inode: Inode) -> Option<PathBuf> {
        let data = self.inodes.read().unwrap().get(&inode).cloned()?;
        Self::host_path_for_inode(&data).ok()
    }

    pub fn snapshot(&self) -> FuseServerState {
        let mut inode_snaps = Vec::new();
        {
            let inodes = self.inodes.read().unwrap();
            let root = std::fs::canonicalize(&self.cfg.root_dir).ok();
            for (nodeid, data) in inodes.iter() {
                if *nodeid == fuse::ROOT_ID {
                    continue;
                }
                inode_snaps.push(FuseInodeSnap {
                    nodeid: *nodeid,
                    relative_path: root.as_deref().and_then(|root| {
                        Self::host_path_for_inode(data)
                            .ok()
                            .and_then(|path| Self::relative_snapshot_path(root, &path))
                    }),
                    // Encode the volfs identity this passthrough already uses;
                    // `restore` parses (dev, ino) back out of it.
                    path: format!("/.vol/{}/{}", data.dev, data.ino),
                    refcount: data.refcount.load(Ordering::Relaxed),
                    share: None,
                });
            }
        }
        let mut handle_snaps = Vec::new();
        {
            let handles = self.handles.read().unwrap();
            for (handle, data) in handles.iter() {
                handle_snaps.push(FuseHandleSnap {
                    handle: *handle,
                    nodeid: data.inode,
                    // HandleData does not retain the original open flags; the
                    // restore path reopens with an RDWR→RDONLY ladder, so this is
                    // advisory only.
                    flags: libc::O_RDWR,
                });
            }
        }
        FuseServerState {
            inodes: inode_snaps,
            handles: handle_snaps,
            next_inode: self.inode_alloc.current(),
            next_handle: self.next_handle.load(Ordering::Relaxed),
            writeback: self.writeback.load(Ordering::Relaxed),
            announce_submounts: self.announce_submounts.load(Ordering::Relaxed),
            zero_message_opendir: self.zero_message_opendir.load(Ordering::Relaxed),
            zero_message_open: self.zero_message_open.load(Ordering::Relaxed),
            // DAX fork-replay is Linux-only; macOS clones have no DAX window.
            dax_maps: Vec::new(),
            live_shares: Vec::new(),
        }
    }

    /// Restore FUSE server state (captured by [`Self::snapshot`]) onto this clone's
    /// freshly-built passthrough: re-seed the root inode, rebuild the inode map
    /// from the saved volfs `(dev, ino)` identities, restore the id counters and
    /// flags, then reopen the saved handles (best-effort RDWR→RDONLY since the
    /// original open flags are not retained). Unknown/failed entries are skipped;
    /// the guest re-walks from root on a miss.
    pub fn restore(&self, state: &FuseServerState) -> io::Result<()> {
        self.restore_with_roots(state, &HashMap::new())
    }

    /// [`Self::restore`], also rebuilding the inodes a snapshot reached through a
    /// live share: each resolved beneath that share's host directory in
    /// `share_roots`, the same way the rest are resolved beneath the export root.
    /// An inode of a share missing from `share_roots` is skipped.
    pub fn restore_with_roots(
        &self,
        state: &FuseServerState,
        share_roots: &HashMap<u64, PathBuf>,
    ) -> io::Result<()> {
        // A restored, already-booted clone never re-sends FUSE_INIT, so seed root
        // explicitly (mirrors the Linux restore).
        self.setup_root_inode()?;

        {
            let mut inodes = self.inodes.write().unwrap();
            for snap in &state.inodes {
                let identity = match snap.share {
                    Some(id) => {
                        let Some(root) = share_roots.get(&id) else {
                            continue;
                        };
                        match snap.relative_path.as_deref().map(Path::new) {
                            Some(rel)
                                if rel.as_os_str().is_empty() || Self::safe_relative_path(rel) =>
                            {
                                let identity = if rel.as_os_str().is_empty() {
                                    CString::new(root.as_os_str().as_bytes())
                                        .map_err(|_| einval())
                                        .and_then(|c| lstat(&c, false))
                                        .map(|st| (st.st_dev, st.st_ino))
                                } else {
                                    Self::identity_beneath(root, rel)
                                };
                                match identity {
                                    Ok(identity) => Some(identity),
                                    Err(error) => {
                                        warn!(
                                            "fs restore: resolve {rel:?} beneath live share failed: {error}"
                                        );
                                        None
                                    }
                                }
                            }
                            _ => {
                                warn!(
                                    "fs restore: rejecting live share inode path {:?}",
                                    snap.relative_path
                                );
                                None
                            }
                        }
                    }
                    None => self.restore_inode_identity(snap),
                };
                let Some((dev, ino)) = identity else {
                    continue;
                };
                inodes.insert(
                    snap.nodeid,
                    InodeAltKey { ino, dev },
                    Arc::new(InodeData {
                        inode: snap.nodeid,
                        ino,
                        dev,
                        refcount: AtomicU64::new(snap.refcount),
                        unlinked_fd: AtomicI64::new(-1),
                        override_cache: Mutex::new(None),
                        metadata_lock: Mutex::new(()),
                    }),
                );
            }
        }

        // Counters must be restored before reopening handles so newly-allocated
        // ids don't collide with the restored ones.
        self.inode_alloc.restore(state.next_inode);
        self.next_handle.store(state.next_handle, Ordering::Relaxed);
        self.writeback.store(state.writeback, Ordering::Relaxed);
        self.announce_submounts
            .store(state.announce_submounts, Ordering::Relaxed);
        self.zero_message_opendir
            .store(state.zero_message_opendir, Ordering::Relaxed);
        self.zero_message_open
            .store(state.zero_message_open, Ordering::Relaxed);

        for snap in &state.handles {
            // open_inode reopens via volfs on demand. Try RDWR, then RDONLY
            // (directories and read-only files reject RDWR).
            let file = match self.open_inode(snap.nodeid, libc::O_RDWR) {
                Ok(f) => Some(f),
                Err(_) => self.open_inode(snap.nodeid, libc::O_RDONLY).ok(),
            };
            match file {
                Some(file) => {
                    self.handles.write().unwrap().insert(
                        snap.handle,
                        Arc::new(HandleData {
                            inode: snap.nodeid,
                            file: RwLock::new(file),
                            dirstream: Mutex::new(DirStream::new()),
                        }),
                    );
                }
                None => warn!(
                    "fs restore: reopen handle {} (nodeid {}) failed",
                    snap.handle, snap.nodeid
                ),
            }
        }
        Ok(())
    }

    fn inode_to_handle(&self, inode: Inode, supports_fd: bool) -> io::Result<InodeHandle> {
        debug!("inode_to_handle: inode={inode}");
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let cstr =
            CString::new(format!("/.vol/{}/{}", data.dev, data.ino)).map_err(|_| einval())?;
        debug!("inode_to_handle: path={}", cstr.to_string_lossy());

        if supports_fd {
            let unlinked_fd = data.unlinked_fd.load(Ordering::Acquire);
            if unlinked_fd >= 0 {
                return Ok(InodeHandle::Fd(unlinked_fd as RawFd));
            }
        }

        // This path names the inode itself, which may be a symlink: every xattr
        // call on it passes XATTR_NOFOLLOW, or a link's attributes are read
        // from (and written to) whatever its target resolves to on the host.
        Ok(InodeHandle::Path(cstr))
    }

    fn name_to_path(&self, parent: Inode, name: &CStr) -> io::Result<CString> {
        debug!(
            "name_to_path: parent={} name={}",
            parent,
            name.to_string_lossy()
        );
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        let cstr = CString::new(format!(
            "/.vol/{}/{}/{}",
            data.dev,
            data.ino,
            name.to_string_lossy()
        ))
        .map_err(|_| einval())?;
        debug!("name_to_path: path={}", cstr.to_string_lossy());
        Ok(cstr)
    }

    fn open_inode(&self, inode: Inode, mut flags: i32) -> io::Result<File> {
        // When writeback caching is enabled, the kernel may send read requests even if the
        // userspace program opened the file write-only. So we need to ensure that we have opened
        // the file for reading as well as writing.
        let writeback = self.writeback.load(Ordering::Relaxed);
        if writeback && flags & libc::O_ACCMODE == libc::O_WRONLY {
            flags &= !libc::O_ACCMODE;
            flags |= libc::O_RDWR;
        }

        // When writeback caching is enabled the kernel is responsible for handling `O_APPEND`.
        // However, this breaks atomicity as the file may have changed on disk, invalidating the
        // cached copy of the data in the kernel and the offset that the kernel thinks is the end of
        // the file. Just allow this for now as it is the user's responsibility to enable writeback
        // caching only for directories that are not shared. It also means that we need to clear the
        // `O_APPEND` flag.
        if writeback && flags & libc::O_APPEND != 0 {
            flags &= !libc::O_APPEND;
        }

        let ihandle = self.inode_to_handle(inode, true)?;
        let fd = match ihandle {
            InodeHandle::Path(c_path) => unsafe {
                // The volfs path names one specific inode. If that inode is a
                // symlink, following it opens the link's target — and a guest
                // can point a symlink it created inside the share anywhere on
                // the host, so a traversal here would read or write an arbitrary
                // host file outside the shared tree. Force `O_NOFOLLOW` so the
                // kernel refuses a symlink atomically (`ELOOP`) at open time;
                // it has no effect on a regular file or directory, which is all
                // a well-behaved guest ever opens (a symlink node is reached by
                // `readlink`, never `open`). This matches the Linux backend,
                // whose `O_PATH` anchor makes the same open fail with `ELOOP`.
                // (Unlike Linux, the macOS volfs path is direct rather than a
                // `/proc/self/fd` magic link, so it must not be followed.)
                libc::open(
                    c_path.as_ptr(),
                    (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) & (!libc::O_EXLOCK),
                )
            },
            // Check if we have recently unlinked the inode and kept open a file descriptor to it.
            InodeHandle::Fd(fd) => unsafe { libc::dup(fd) },
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        // Safe because we just opened this fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn do_readdir<F>(
        &self,
        inode: Inode,
        handle: Handle,
        size: u32,
        mut offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned();
        let Some(data) = data else {
            return if self.zero_message_opendir.load(Ordering::Relaxed) {
                self.readdir_without_handle(inode, offset, add_entry)
            } else {
                Err(ebadf())
            };
        };

        let mut ds = data.dirstream.lock().unwrap();

        // We use offset == 0 as an indicator of this being either a fresh directory
        // stream or a stream that has been rewound. If that's the case, make sure
        // the cache will be refreshed.
        if offset == 0 && ds.ready {
            let fd = data.file.write().unwrap().as_raw_fd();
            unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
            ds.entries.clear();
            ds.ready = false;
        }

        if !ds.ready {
            // Fill the cache on first call
            if let Err(e) = ds.fill_from_fd(data.file.write().unwrap().as_raw_fd()) {
                if ds.entries.is_empty() {
                    return Err(e);
                }
                // If we got some valid entries before error happened,
                // treat this partial read as success and just log
                // the error.
                warn!("virtio-fs: error in readdir {}: {:?}", inode, e);
            }
            ds.ready = true;
        }

        while let Some(entry) = ds.get_entry(offset) {
            offset += 1;

            let name = entry.name;
            match add_entry(entry) {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "virtio-fs: error adding entry {}: {:?}",
                        String::from_utf8_lossy(name),
                        e
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    fn do_open(
        &self,
        inode: Inode,
        kill_priv: bool,
        writer_gid: libc::gid_t,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let flags = self.parse_open_flags(flags as i32);

        let file = RwLock::new(self.open_inode(inode, flags)?);

        // If O_TRUNC and kill_priv (OPEN_KILL_SUIDGID), clear security.capability and suid/sgid
        if (flags & libc::O_TRUNC) != 0 && kill_priv {
            let fd = file.read().unwrap().as_raw_fd();
            let ihandle = InodeHandle::Fd(fd);

            remove_security_capability(&ihandle);

            if let Ok(st) = fstat(fd, false) {
                let new_mode =
                    mode_after_unprivileged_write(st.st_mode as u32, writer_gid, st.st_gid);
                if new_mode != st.st_mode as u32
                    && let Err(err) = set_xattr_stat(&ihandle, Some(st), None, Some(new_mode))
                {
                    error!("Couldn't clear suid/sgid for inode {inode}: {err}");
                }
            }
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode,
            file,
            dirstream: Mutex::new(DirStream::new()),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(OpenOptions::DIRECT_IO, flags & libc::O_DIRECTORY == 0),
            CachePolicy::Always => {
                if flags & libc::O_DIRECTORY == 0 {
                    opts |= OpenOptions::KEEP_CACHE;
                } else {
                    opts |= OpenOptions::CACHE_DIR;
                }
            }
            _ => {}
        };

        // As on Linux (virtio/fs: reduce request latency): this server does
        // not negotiate POSIX/FLOCK locks and its flush() only dup(2)+close(2)s
        // the same host descriptor, while durability is FUSE_FSYNC's job, so
        // the close-time FUSE_FLUSH is a redundant guest/host round trip: one
        // of the five requests every small file read costs.
        opts |= OpenOptions::NOFLUSH;

        Ok((Some(handle), opts))
    }

    /// Serve a readdir chunk for a directory the kernel opened without a
    /// request. Offset 0 reads the directory into a stream kept by inode; later
    /// chunks continue from it; the stream goes when the listing reaches its
    /// end or the directory is released. A stream lost in between (the cap
    /// below, or a restore) is read again from the offset asked for, which is
    /// what any reopened listing would see.
    fn readdir_without_handle<F>(
        &self,
        inode: Inode,
        mut offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        /// Listings kept at once. Each holds one directory's names; a walk
        /// finishes a directory's listing before descending, so a handful is
        /// plenty and a forgotten one costs a re-read, not correctness.
        const HANDLELESS_DIR_STREAMS: usize = 64;

        let mut streams = self.handleless_dirs.lock().unwrap();
        if offset == 0 || !streams.contains_key(&inode) {
            let dir = self.open_inode(inode, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let mut ds = DirStream::new();
            if let Err(e) = ds.fill_from_fd(dir.as_raw_fd()) {
                if ds.entries.is_empty() {
                    return Err(e);
                }
                warn!("virtio-fs: error in readdir {}: {:?}", inode, e);
            }
            ds.ready = true;
            if streams.len() >= HANDLELESS_DIR_STREAMS && !streams.contains_key(&inode) {
                streams.clear();
            }
            streams.insert(inode, ds);
        }
        let ds = streams.get(&inode).expect("inserted above");
        while let Some(entry) = ds.get_entry(offset) {
            offset += 1;
            let name = entry.name;
            match add_entry(entry) {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "virtio-fs: error adding entry {}: {:?}",
                        String::from_utf8_lossy(name),
                        e
                    );
                    break;
                }
            }
        }
        if ds.get_entry(offset).is_none() {
            streams.remove(&inode);
        }
        Ok(())
    }

    /// The open file a request names: the handle's, or, for a file the kernel
    /// opened without a request (handle 0 and no such handle), a descriptor
    /// opened for the inode and kept for the requests that follow.
    fn file_for(&self, inode: Inode, handle: Handle, write: bool) -> io::Result<Arc<HandleData>> {
        if let Some(data) = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
        {
            return Ok(data);
        }
        if !self.zero_message_open.load(Ordering::Relaxed) {
            return Err(ebadf());
        }
        self.inode_fd(inode, write)
    }

    /// The kept descriptor for `inode`, opened on first use: read-only for a
    /// read, read-write for a write (a read-only one is replaced then).
    fn inode_fd(&self, inode: Inode, write: bool) -> io::Result<Arc<HandleData>> {
        let cached = self
            .inode_fds
            .lock()
            .unwrap()
            .map
            .get(&inode)
            .filter(|cached| {
                if write {
                    cached.writable
                } else {
                    cached.readable
                }
            })
            .map(|cached| cached.data.clone());
        if let Some(data) = cached {
            if self.fd_still_names(inode, &data) {
                return Ok(data);
            }
            self.inode_fds.lock().unwrap().map.remove(&inode);
        }
        // Open before taking the cache lock: open_inode reads the inode map,
        // which forget holds while it drops a descriptor from this cache. Two
        // requests racing here may both open; the later insert wins and the
        // other descriptor closes with its last user.
        let flags = if write { libc::O_RDWR } else { libc::O_RDONLY };
        let file = self.open_inode(inode, flags)?;
        let data = Arc::new(HandleData {
            inode,
            file: RwLock::new(file),
            dirstream: Mutex::new(DirStream::new()),
        });
        Ok(self.keep_inode_fd(inode, data, true, write, false))
    }

    /// Whether a kept descriptor still names the file the inode stands for.
    /// The host may have unlinked the file and reused its inode number for
    /// another, or the guest may have created a new file under a number a
    /// forgotten one had; a descriptor into the old file must not serve the
    /// new one. One fstat (a few microseconds) against the numbers the inode
    /// was registered with.
    fn fd_still_names(&self, inode: Inode, data: &HandleData) -> bool {
        let Some(expected) = self.inodes.read().unwrap().get(&inode).cloned() else {
            return false;
        };
        let fd = data.file.read().unwrap().as_raw_fd();
        match fstat(fd, true) {
            Ok(st) => st.st_ino == expected.ino && st.st_dev == expected.dev && st.st_nlink > 0,
            Err(_) => false,
        }
    }

    /// Keep `data` as the descriptor for `inode`; a descriptor opened by a
    /// create replaces whatever was kept, since it names the file just made.
    /// Otherwise a usable one that arrived first wins. Returns the one to use.
    /// Past the cap, the oldest kept goes.
    fn keep_inode_fd(
        &self,
        inode: Inode,
        data: Arc<HandleData>,
        readable: bool,
        writable: bool,
        replace: bool,
    ) -> Arc<HandleData> {
        let mut fds = self.inode_fds.lock().unwrap();
        if !replace
            && let Some(cached) = fds.map.get(&inode)
            && (cached.readable || !readable)
            && (cached.writable || !writable)
        {
            return cached.data.clone();
        }
        let reservation = if let Some(previous) = fds.map.remove(&inode) {
            // Upgrading an entry reuses its slot and its position in the
            // eviction queue, even when another share has filled the budget.
            previous._reservation
        } else {
            if fds.map.len() >= INODE_FDS_MAX {
                fds.evict_oldest();
            }
            let reservation = fds.budget.reserve().or_else(|| {
                // Other shares can consume the process budget. Recycle one
                // of this share's entries instead of retaining another fd.
                fds.evict_oldest();
                fds.budget.reserve()
            });
            let Some(reservation) = reservation else {
                // Retention is an optimization; the current request still
                // owns this fd and the next can reopen it on demand.
                return data;
            };
            // Releases and forgets remove from the map only; drop their
            // leftovers from the order before it outgrows the map.
            if fds.order.len() >= 2 * INODE_FDS_MAX {
                let InodeFds { map, order, .. } = &mut *fds;
                order.retain(|kept| map.contains_key(kept));
            }
            fds.order.push_back(inode);
            reservation
        };
        fds.map.insert(
            inode,
            CachedFd {
                _reservation: reservation,
                data: data.clone(),
                readable,
                writable,
            },
        );
        data
    }

    /// The inode's record, if the guest still holds it.
    fn inode_data(&self, inode: Inode) -> Option<Arc<InodeData>> {
        self.inodes.read().unwrap().get(&inode).cloned()
    }

    /// The override xattr's values for a file whose host stat is `st`: the
    /// remembered ones when the ctime still matches, else read and
    /// remembered.
    fn override_for(
        &self,
        ihandle: &InodeHandle,
        st: &bindings::stat64,
        data: Option<&InodeData>,
    ) -> io::Result<Override> {
        let ctime = ctime_of(st);
        if let Some(cached) = data.and_then(|d| *d.override_cache.lock().unwrap())
            && cached.ctime == ctime
        {
            return Ok(cached.over);
        }
        let over = match ihandle {
            InodeHandle::Fd(fd) => get_xattr_fstat(*fd, *st)?,
            InodeHandle::Path(c_path) => get_xattr_lstat(c_path, *st)?,
        };
        if let Some(d) = data {
            *d.override_cache.lock().unwrap() = Some(CachedOverride { over, ctime });
        }
        Ok(over)
    }

    /// stat as the guest sees the file: the host stat with the override
    /// xattr applied, the xattr read from the host unless remembered for
    /// this ctime.
    fn gstat(
        &self,
        ihandle: &InodeHandle,
        data: Option<&InodeData>,
    ) -> io::Result<bindings::stat64> {
        let st = istat(ihandle, true)?;
        let over = self.override_for(ihandle, &st, data)?;
        self.view(st, over)
    }

    /// The host stat as the guest sees it: the recorded owner and mode, else
    /// the share's default owner.
    fn view(&self, st: bindings::stat64, over: Override) -> io::Result<bindings::stat64> {
        let owner = self.cfg.default_owner;
        stat_common(
            st,
            over.0.or(owner.map(|o| o.0)),
            over.1.or(owner.map(|o| o.1)),
            over.2,
            false,
        )
    }

    /// Look a name up. `known` is the override xattr a caller has just
    /// written for the file, which saves reading it back; otherwise it is
    /// read unless remembered for the file's current ctime.
    fn lookup_as(&self, parent: Inode, name: &CStr, known: Option<Override>) -> io::Result<Entry> {
        let parent_data = self.inode_data(parent).ok_or_else(ebadf)?;
        let c_path = self.name_to_path(parent, name)?;
        let st = match lstat(&c_path, true) {
            Ok(st) => st,
            // A name that does not exist: an entry with inode 0 tells the
            // kernel to remember the absence for `negative_timeout` instead
            // of asking again at every stat of the path.
            Err(e)
                if e.raw_os_error() == Some(libc::ENOENT)
                    && self.cfg.negative_timeout > Duration::ZERO =>
            {
                return Ok(Entry {
                    inode: 0,
                    generation: 0,
                    // SAFETY: an all-zero stat is a valid value of the C struct.
                    attr: unsafe { std::mem::zeroed() },
                    attr_flags: 0,
                    attr_timeout: Duration::ZERO,
                    entry_timeout: self.cfg.negative_timeout,
                });
            }
            Err(e) => return Err(e),
        };

        debug!(
            "lookup: inode={} path={}",
            st.st_ino,
            c_path.to_str().unwrap()
        );

        let over = match known {
            Some(over) => over,
            None => {
                let existing = self
                    .inodes
                    .read()
                    .unwrap()
                    .get_alt(&InodeAltKey {
                        ino: st.st_ino,
                        dev: st.st_dev,
                    })
                    .cloned();
                self.override_for(&InodeHandle::Path(c_path.clone()), &st, existing.as_deref())?
            }
        };
        let view = self.view(st, over)?;
        self.register_lookup(view, parent_data.dev, over)
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();

        if let btree_map::Entry::Occupied(e) = handles.entry(handle)
            && e.get().inode == inode
        {
            // We don't need to close the file here because that will happen automatically when
            // the last `Arc` is dropped.
            e.remove();
            return Ok(());
        }

        Err(ebadf())
    }

    fn do_getattr(&self, inode: Inode) -> io::Result<(bindings::stat64, Duration)> {
        let data = self.inode_data(inode);
        let ihandle = self.inode_to_handle(inode, true)?;
        let st = self.gstat(&ihandle, data.as_deref())?;

        Ok((st, self.cfg.attr_timeout))
    }

    fn grab_unlinked_fd(&self, parent_fd: RawFd, name: &CStr) -> io::Result<RawFd> {
        let fd =
            unsafe { libc::openat(parent_fd, name.as_ptr(), libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn store_unlinked_fd(&self, unlinked_fd: RawFd) -> io::Result<bool> {
        let st = fstat(unlinked_fd, true)?;
        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        // Hold the read lock across the swap: dropping it earlier would let a
        // concurrent `forget` remove this inode (closing its then-`-1`
        // `unlinked_fd`) between our lookup and swap, leaking the fd we store.
        let inodes = self.inodes.read().unwrap();
        if let Some(data) = inodes.get_alt(&altkey) {
            // Swap rather than store so that if this inode already had a
            // preserved fd (e.g. another hard link was unlinked/overwritten
            // earlier), we recover and close it instead of leaking it.
            let old_fd = data.unlinked_fd.swap(unlinked_fd as i64, Ordering::AcqRel);
            if old_fd >= 0 {
                unsafe { libc::close(old_fd as RawFd) };
            }
            // The tracked inode now owns `unlinked_fd` (closed in `forget_one`).
            Ok(true)
        } else {
            // No tracked inode for this (dev, ino): the caller keeps ownership
            // of `unlinked_fd` and must close it to avoid a leak.
            Ok(false)
        }
    }

    fn do_unlink(
        &self,
        _ctx: Context,
        parent: Inode,
        name: &CStr,
        flags: libc::c_int,
    ) -> io::Result<()> {
        let ihandle = self.inode_to_handle(parent, true)?;

        let (fd, close_fd) = match ihandle {
            InodeHandle::Path(c_path) => unsafe {
                (
                    libc::open(c_path.as_ptr(), libc::O_NOFOLLOW | libc::O_CLOEXEC),
                    true,
                )
            },
            InodeHandle::Fd(fd) => (fd, false),
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // After unlinking this inode, we can't keep relying on getting a "/.vol/..." path
        // to operate on it. Before unlinking the inode, grab a file descriptor so we can
        // still operate on it. This one will be closed on "forget_one".
        let unlinked_fd = match self.grab_unlinked_fd(fd, name) {
            Ok(fd) => Some(fd),
            Err(err) => {
                warn!(
                    "Couldn't grab a file descriptor for file \"{}\": {err}",
                    name.to_string_lossy()
                );
                None
            }
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::unlinkat(fd, name.as_ptr(), flags) };
        let err = io::Error::last_os_error();

        if close_fd {
            unsafe { libc::close(fd) };
        }

        if res == 0 {
            if let Some(unlinked_fd) = unlinked_fd {
                match self.store_unlinked_fd(unlinked_fd) {
                    // The tracked inode took ownership of the fd.
                    Ok(true) => {}
                    // No tracked inode: we still own the fd and must close it.
                    Ok(false) => unsafe {
                        libc::close(unlinked_fd);
                    },
                    Err(err) => {
                        unsafe { libc::close(unlinked_fd) };
                        warn!("Couldn't store unlinked fd \"{}\": {err}", unlinked_fd);
                    }
                }
            }
            Ok(())
        } else {
            if let Some(unlinked_fd) = unlinked_fd {
                unsafe { libc::close(unlinked_fd) };
            }
            Err(linux_error(err))
        }
    }

    fn parse_open_flags(&self, flags: i32) -> i32 {
        let mut mflags: i32 = flags & 0b11;

        if (flags & bindings::LINUX_O_NONBLOCK) != 0 {
            mflags |= libc::O_NONBLOCK;
        }
        if (flags & bindings::LINUX_O_APPEND) != 0 {
            mflags |= libc::O_APPEND;
        }
        if (flags & bindings::LINUX_O_CREAT) != 0 {
            mflags |= libc::O_CREAT;
        }
        if (flags & bindings::LINUX_O_TRUNC) != 0 {
            mflags |= libc::O_TRUNC;
        }
        if (flags & bindings::LINUX_O_EXCL) != 0 {
            mflags |= libc::O_EXCL;
        }
        if (flags & bindings::LINUX_O_NOFOLLOW) != 0 {
            mflags |= libc::O_NOFOLLOW;
        }
        if (flags & bindings::LINUX_O_CLOEXEC) != 0 {
            mflags |= libc::O_CLOEXEC;
        }

        mflags
    }
}

fn set_secctx(file: &InodeHandle, secctx: SecContext, symlink: bool) -> io::Result<()> {
    let options = if symlink { libc::XATTR_NOFOLLOW } else { 0 };
    let ret = match file {
        InodeHandle::Path(path) => unsafe {
            libc::setxattr(
                path.as_ptr(),
                secctx.name.as_ptr(),
                secctx.secctx.as_ptr() as *const libc::c_void,
                secctx.secctx.len(),
                0,
                options,
            )
        },
        InodeHandle::Fd(fd) => unsafe {
            libc::fsetxattr(
                *fd,
                secctx.name.as_ptr(),
                secctx.secctx.as_ptr() as *const libc::c_void,
                secctx.secctx.len(),
                0,
                options,
            )
        },
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Remove the security.capability extended attribute
fn remove_security_capability(file: &InodeHandle) {
    let remove = || {
        let ret = match file {
            InodeHandle::Path(path) => unsafe {
                libc::removexattr(
                    path.as_ptr(),
                    SECURITY_CAPABILITY.as_ptr().cast(),
                    libc::XATTR_NOFOLLOW,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fremovexattr(*fd, SECURITY_CAPABILITY.as_ptr().cast(), 0)
            },
        };
        if ret == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        // Darwin reports ENOATTR, not Linux's ENODATA. Most files have no
        // capability: this is the normal truncate/write path, not a warning.
        if error.raw_os_error() == Some(libc::ENOATTR) {
            Ok(())
        } else {
            Err(error)
        }
    };
    if let Err(error) = metadata_write(file, remove) {
        warn!("Error removing security.capability from file: {error}");
    }
}

/// Clear suid/sgid bits from mode.
/// sgid is cleared only if group executable bit is set.
fn clear_suid_sgid(mode: u32) -> u32 {
    let mut new_mode = mode;

    // Clear suid bit
    new_mode &= !libc::S_ISUID as u32;

    // Clear sgid bit only if group executable bit is set
    if (mode & libc::S_IXGRP as u32) != 0 {
        new_mode &= !libc::S_ISGID as u32;
    }

    new_mode
}

/// The mode a regular file is left with after an unprivileged write or truncating open (the kernel's
/// `setattr_should_drop_suidgid`): the setuid bit always goes, and the setgid bit goes when the file is
/// group-executable (without it the bit only marks mandatory locking) or when the writer is outside the
/// file's group. A FUSE request carries the caller's primary gid alone, so that is the group it is
/// checked against.
fn mode_after_unprivileged_write(mode: u32, writer_gid: libc::gid_t, file_gid: libc::gid_t) -> u32 {
    let mut new_mode = clear_suid_sgid(mode);
    if writer_gid != file_gid {
        new_mode &= !libc::S_ISGID as u32;
    }
    new_mode
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

            // Synchronizes with the acquire load in `lookup`.
            if data
                .refcount
                .compare_exchange(refcount, new_count, Ordering::Release, Ordering::Relaxed)
                .unwrap()
                == refcount
            {
                if new_count == 0 {
                    // If we have unlinked this inode, we have opened a file descriptor to be
                    // able to operate on it without a path. Close it now.
                    let fd = data.unlinked_fd.load(Ordering::Acquire);
                    if fd >= 0 {
                        unsafe { libc::close(fd as RawFd) };
                    }
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

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        self.setup_root_inode()?;

        let mut opts = FsOptions::empty();
        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }

        if capable.contains(FsOptions::SUBMOUNTS) {
            opts |= FsOptions::SUBMOUNTS;
            self.announce_submounts.store(true, Ordering::Relaxed);
        }

        // readdirplus answers a directory listing with each entry's attributes
        // in the same reply, so a listing followed by a stat of every entry
        // (ls -l, git status, tar, a package manager walking node_modules)
        // costs one request per readdir chunk instead of one LOOKUP per entry.
        // AUTO lets the kernel keep plain readdir for a listing it has not seen
        // entries of stat'ed, so `find -type f`, which needs only d_type, pays
        // nothing extra.
        if capable.contains(FsOptions::DO_READDIRPLUS) {
            opts |= FsOptions::DO_READDIRPLUS;
            if capable.contains(FsOptions::READDIRPLUS_AUTO) {
                opts |= FsOptions::READDIRPLUS_AUTO;
            }
        }

        // Let the kernel skip OPENDIR and RELEASEDIR: a directory walk then
        // costs its readdir chunks and nothing else, two requests fewer per
        // directory. The entries are read when the first chunk is asked for
        // (see `readdir_without_handle`).
        let zero_message_opendir = capable.contains(FsOptions::ZERO_MESSAGE_OPENDIR);
        self.zero_message_opendir
            .store(zero_message_opendir, Ordering::Relaxed);
        if zero_message_opendir {
            opts |= FsOptions::ZERO_MESSAGE_OPENDIR;
        }

        // The same for regular files: no OPEN and no RELEASE per file, and the
        // kernel keeps a file's pages across opens (it applies KEEP_CACHE to
        // files it opened without a request). Reading a tree of small files
        // then costs the READ requests and nothing else. The server opens a
        // descriptor per inode on the first handle-less request and keeps it
        // (see `file_for`). The server withdraws ATOMIC_O_TRUNC when this is
        // on: with no OPEN to carry the truncation, O_TRUNC must come as a
        // SETATTR, which the kernel only sends without that flag.
        let zero_message_open = capable.contains(FsOptions::ZERO_MESSAGE_OPEN);
        self.zero_message_open
            .store(zero_message_open, Ordering::Relaxed);
        if zero_message_open {
            opts |= FsOptions::ZERO_MESSAGE_OPEN;
        }

        Ok(opts)
    }

    fn destroy(&self) {
        self.handles.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
        *self.inode_fds.lock().unwrap() = InodeFds::default();
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        let mut out = MaybeUninit::<bindings::statvfs64>::zeroed();

        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                bindings::statvfs64(c_path.as_ptr(), out.as_mut_ptr())
            },
            InodeHandle::Fd(fd) => unsafe { bindings::fstatvfs64(fd, out.as_mut_ptr()) },
        };
        if res == 0 {
            // Safe because the kernel guarantees that `out` has been initialized.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.lookup_as(parent, name, None)
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let gone = {
            let mut inodes = self.inodes.write().unwrap();
            forget_one(&mut inodes, inode, count);
            inodes.get(&inode).is_none()
        };
        // After the inode lock is released: inode_fd takes the two locks the
        // other way round while it opens a file, and holding both here would
        // deadlock the worker threads.
        if gone {
            self.inode_fds.lock().unwrap().map.remove(&inode);
        }
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let gone: Vec<Inode> = {
            let mut inodes = self.inodes.write().unwrap();
            requests
                .into_iter()
                .filter_map(|(inode, count)| {
                    forget_one(&mut inodes, inode, count);
                    inodes.get(&inode).is_none().then_some(inode)
                })
                .collect()
        };
        if !gone.is_empty() {
            let mut fds = self.inode_fds.lock().unwrap();
            for inode in gone {
                fds.map.remove(&inode);
            }
        }
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if self.zero_message_opendir.load(Ordering::Relaxed) {
            // ENOSYS here is the protocol's way of saying "no OPENDIR needed":
            // the kernel treats it as success and stops sending them. It must
            // be Linux's ENOSYS (38): the host's (78 on macOS) would reach the
            // guest as EREMCHG and fail every directory open.
            Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)))
        } else {
            self.do_open(inode, false, ctx.gid, flags | libc::O_DIRECTORY as u32)
        }
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        match self.do_release(inode, handle) {
            // A directory opened without a request has no handle to release;
            // whatever listing it had in progress goes with it.
            Err(_) if self.zero_message_opendir.load(Ordering::Relaxed) => {
                self.handleless_dirs.lock().unwrap().remove(&inode);
                Ok(())
            }
            other => other,
        }
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
        let c_path = self.name_to_path(parent, name)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::mkdir(c_path.as_ptr(), 0o700) };
        if res == 0 {
            let ihandle = InodeHandle::Path(c_path);
            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, false)?
            };

            let written = (Some(ctx.uid), Some(ctx.gid), Some(mode & !umask));
            set_xattr_stat(&ihandle, None, written.0.zip(written.1), written.2)?;
            self.lookup_as(parent, name, Some(written))
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn rmdir(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(ctx, parent, name, libc::AT_REMOVEDIR)
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, |dir_entry| {
            // The cached name is d_namlen bytes, without a NUL.
            let name = CString::new(dir_entry.name)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let entry = self.lookup(ctx, inode, &name)?;

            add_entry(dir_entry, entry)
        })
    }

    fn open(
        &self,
        ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if self.zero_message_open.load(Ordering::Relaxed) {
            // Linux's ENOSYS, as for opendir: the kernel reads it as "no OPEN
            // needed" and never sends another.
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }
        self.do_open(inode, kill_priv, ctx.gid, flags)
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
        match self.do_release(inode, handle) {
            // A file opened without a request has no handle, but the kernel
            // still sends a release, naming handle 0, when the guest closes a
            // file it created. The guest is done with the file, so the kept
            // descriptor closes now rather than when the cache evicts it: the
            // host sees the close when the guest's happens, which keeps the
            // host's own change notifications for the file together. A later
            // request for the inode opens afresh.
            Err(_) if self.zero_message_open.load(Ordering::Relaxed) => {
                let dropped = self.inode_fds.lock().unwrap().map.remove(&inode);
                drop(dropped);
                Ok(())
            }
            other => other,
        }
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
        let c_path = self.name_to_path(parent, name)?;

        let flags = self.parse_open_flags(flags as i32);
        let hostmode = if (flags & libc::O_DIRECTORY) != 0 {
            0o700
        } else {
            0o600
        };

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                flags | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                hostmode,
            )
        };
        if fd < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }
        let ihandle = InodeHandle::Fd(fd);

        let written = (
            Some(ctx.uid),
            Some(ctx.gid),
            Some(libc::S_IFREG as u32 | (mode & !(umask & 0o777))),
        );
        if let Err(e) = set_xattr_stat(&ihandle, None, written.0.zip(written.1), written.2) {
            unsafe { libc::close(fd) };
            return Err(e);
        }

        // Set security context
        if let Some(secctx) = extensions.secctx {
            set_secctx(&ihandle, secctx, false)?
        };

        // If O_TRUNC and kill_priv (OPEN_KILL_SUIDGID), clear security.capability.
        // We don't need to clear suid/sgid here because we've just updated them
        // unconditionally above.
        if (flags & libc::O_TRUNC) != 0 && kill_priv {
            remove_security_capability(&ihandle);
        }

        // Safe because we just opened this fd.
        let file = RwLock::new(unsafe { File::from_raw_fd(fd) });

        // The xattr was just written: the lookup need not read it back.
        let entry = self.lookup_as(parent, name, Some(written))?;

        let data = HandleData {
            inode: entry.inode,
            file,
            dirstream: Mutex::new(DirStream::new()),
        };
        // While files open without a request, the requests that follow name
        // handle 0 whatever this reply says, and a handle here would hold its
        // descriptor until a release that may never come. Keep the descriptor
        // with the inode instead, where the handle-0 writes that follow find
        // it; the guest's close (release) or the cache's bound ends it.
        let handle = if self.zero_message_open.load(Ordering::Relaxed) {
            let access = flags & libc::O_ACCMODE;
            self.keep_inode_fd(
                entry.inode,
                Arc::new(data),
                access != libc::O_WRONLY,
                access != libc::O_RDONLY,
                true,
            );
            None
        } else {
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.handles.write().unwrap().insert(handle, Arc::new(data));
            Some(handle)
        };

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        };

        // See open(): explicit fsync remains intact; only the redundant close
        // notification is suppressed.
        opts |= OpenOptions::NOFLUSH;

        Ok((entry, handle, opts))
    }

    fn unlink(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(ctx, parent, name, 0)
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
        let data = self.file_for(inode, handle, false)?;

        // This is safe because write_from uses preadv64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        w.write_from(&f, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
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
        let data = self.file_for(inode, handle, true)?;

        // This is safe because read_to uses pwritev64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        let result = r.read_to(&f, size as usize, offset);

        // If write succeeded and kill_priv is set, clear security.capability and suid/sgid
        if result.is_ok() && kill_priv {
            let fd = f.as_raw_fd();
            let ihandle = InodeHandle::Fd(fd);

            remove_security_capability(&ihandle);

            if let Ok(st) = fstat(fd, false) {
                let new_mode = mode_after_unprivileged_write(st.st_mode as u32, ctx.gid, st.st_gid);
                if new_mode != st.st_mode as u32
                    && let Err(err) = set_xattr_stat(&ihandle, Some(st), None, Some(new_mode))
                {
                    error!("Couldn't clear suid/sgid for inode {inode}: {err}");
                }
            }
        }

        result
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        let inode_data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;
        // Keep the temporary host permission adjustment and the final chmod in
        // one metadata operation when requests for this inode run concurrently.
        let _metadata = inode_data.metadata_lock.lock().unwrap();
        // Reuse a handle-less writer for O_TRUNC, so the subsequent WRITE does
        // not reopen the same inode after SETATTR just opened and closed it.
        let truncation = if valid.contains(SetattrValid::SIZE)
            && handle.is_none_or(|h| h == 0)
            && self.zero_message_open.load(Ordering::Relaxed)
        {
            Some(self.file_for(inode, 0, true)?)
        } else {
            None
        };
        // If we have a handle then use it otherwise get a new fd from the inode.
        // `hd` outlives every use of the raw fd: a concurrent release would
        // otherwise close it and a newly opened file could reuse the number.
        let hd;
        let known = handle.and_then(|handle| {
            self.handles
                .read()
                .unwrap()
                .get(&handle)
                .filter(|hd| hd.inode == inode)
                .cloned()
        });
        let ihandle = match (handle, known.or(truncation)) {
            (_, Some(data)) => {
                hd = data;
                let fd = hd.file.write().unwrap().as_raw_fd();
                InodeHandle::Fd(fd)
            }
            // A handle the server never issued: the kernel's handle 0 for a
            // file it opened without a request (an ftruncate on it), served
            // by inode like a setattr with no handle.
            (Some(_), None) if !self.zero_message_open.load(Ordering::Relaxed) => {
                return Err(ebadf());
            }
            _ => self.inode_to_handle(inode, true)?,
        };

        #[cfg(test)]
        if let Some(hook) = SETATTR_FD_HOOK.take() {
            hook(self);
        }

        if valid.contains(SetattrValid::MODE) {
            set_xattr_stat(&ihandle, None, None, Some(attr.st_mode as u32))?;
            // Recorded ownership is virtual: applying a mode-000 guest chmod
            // to the host would deny our unprivileged server access even when
            // guest root is entitled to it. The guest enforces the xattr mode.
            if !self.cfg.override_stat {
                apply_host_permissions(&ihandle, attr.st_mode as u32);
            }
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };

            remove_security_capability(&ihandle);
            let st = self.gstat(&ihandle, Some(&inode_data))?;

            // Clear suid/sgid if UID or GID is being changed
            let new_mode = clear_suid_sgid(st.st_mode as u32);
            let new_mode = if new_mode != st.st_mode as u32 {
                Some(new_mode)
            } else {
                None
            };
            set_xattr_stat(&ihandle, Some(st), Some((uid, gid)), new_mode)?;
        }

        let mut result_attr = None;
        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            match ihandle {
                InodeHandle::Fd(fd) => {
                    let res = unsafe { libc::ftruncate(fd, attr.st_size) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }

                    // Clear security.capability on truncate unconditionally
                    remove_security_capability(&ihandle);
                    let st = self.gstat(&ihandle, Some(&inode_data))?;
                    let new_mode = clear_suid_sgid(st.st_mode as u32);
                    if new_mode != st.st_mode as u32 {
                        set_xattr_stat(&ihandle, Some(st), None, Some(new_mode))?;
                    } else {
                        result_attr = Some(st);
                    }
                }
                InodeHandle::Path(_) => {
                    // There is no `ftruncateat` so we need to get a new fd and truncate it.
                    let f = self.open_inode(inode, libc::O_NONBLOCK | libc::O_RDWR)?;
                    let res = unsafe { libc::ftruncate(f.as_raw_fd(), attr.st_size) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }

                    // Clear security.capability on truncate unconditionally
                    //
                    // Do this here even if it means duplicating the code above to be able to
                    // reuse the FD we just opened, thus reducing the number of syscalls.
                    let ihandle = InodeHandle::Fd(f.as_raw_fd());
                    remove_security_capability(&ihandle);
                    let st = self.gstat(&ihandle, Some(&inode_data))?;
                    let new_mode = clear_suid_sgid(st.st_mode as u32);
                    if new_mode != st.st_mode as u32 {
                        set_xattr_stat(&ihandle, Some(st), None, Some(new_mode))?;
                    } else {
                        result_attr = Some(st);
                    }
                }
            };
        }

        if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
            result_attr = None;
            let mut tvs = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];

            if valid.contains(SetattrValid::ATIME_NOW) {
                tvs[0].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::ATIME) {
                tvs[0].tv_sec = attr.st_atime;
                tvs[0].tv_nsec = attr.st_atime_nsec;
            }

            if valid.contains(SetattrValid::MTIME_NOW) {
                tvs[1].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::MTIME) {
                tvs[1].tv_sec = attr.st_mtime;
                tvs[1].tv_nsec = attr.st_mtime_nsec;
            }

            // Safe because this doesn't modify any memory and we check the return value.
            let res = match ihandle {
                InodeHandle::Fd(fd) => unsafe { libc::futimens(fd, tvs.as_ptr()) },
                InodeHandle::Path(ref c_path) => unsafe {
                    let fd = libc::open(c_path.as_ptr(), libc::O_SYMLINK | libc::O_CLOEXEC);
                    let res = libc::futimens(fd, tvs.as_ptr());
                    libc::close(fd);
                    res
                },
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        // Truncation already obtained the final guest attributes after the
        // host size/capability changes. Reuse that snapshot if no subsequent
        // mode or timestamp update changed it; otherwise refresh through the
        // same handle, keeping its descriptor alive throughout this request.
        let st = match result_attr {
            Some(st) => st,
            None => self.gstat(&ihandle, Some(&inode_data))?,
        };
        Ok((st, self.cfg.attr_timeout))
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let mut mflags: u32 = 0;
        if ((flags as i32) & bindings::LINUX_RENAME_NOREPLACE) != 0 {
            mflags |= libc::RENAME_EXCL;
        }
        if ((flags as i32) & bindings::LINUX_RENAME_EXCHANGE) != 0 {
            mflags |= libc::RENAME_SWAP;
        }

        if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0
            && ((flags as i32) & bindings::LINUX_RENAME_EXCHANGE) != 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }

        let old_cpath = self.name_to_path(olddir, oldname)?;
        let new_cpath = self.name_to_path(newdir, newname)?;

        // macOS addresses inodes by their volfs path ("/.vol/{dev}/{ino}"),
        // which only resolves while the inode still has a directory entry. A
        // rename that REPLACES an existing target drops that target's last
        // link, so any inode the guest still holds open there would afterwards
        // resolve to a dangling volfs path and fail path-based ops
        // (getattr/open/setattr/...) with ENOENT (e.g. apt/dpkg's atomic
        // rewrite of /var/lib/dpkg/status, surfaced as
        // "close (2: No such file or directory)"). `do_unlink` already guards
        // the unlink case by stashing an fd to the doomed inode in
        // `InodeData.unlinked_fd`; mirror that for the overwritten target. Grab
        // it *before* the rename, while its entry still exists. RENAME_SWAP
        // keeps both inodes linked and RENAME_EXCL never overwrites, so skip
        // those; best-effort otherwise (a non-overwriting rename finds nothing).
        let doomed_fd = if (flags as i32)
            & (bindings::LINUX_RENAME_EXCHANGE | bindings::LINUX_RENAME_NOREPLACE)
            == 0
        {
            match self.inode_to_handle(newdir, true) {
                Ok(InodeHandle::Path(newdir_cpath)) => {
                    let newdir_fd = unsafe {
                        libc::open(newdir_cpath.as_ptr(), libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    };
                    if newdir_fd < 0 {
                        None
                    } else {
                        let grabbed = self.grab_unlinked_fd(newdir_fd, newname).ok();
                        unsafe { libc::close(newdir_fd) };
                        grabbed
                    }
                }
                Ok(InodeHandle::Fd(newdir_fd)) => self.grab_unlinked_fd(newdir_fd, newname).ok(),
                Err(_) => None,
            }
        } else {
            None
        };

        let res = unsafe { libc::renamex_np(old_cpath.as_ptr(), new_cpath.as_ptr(), mflags) };
        if res == 0 {
            // If the rename overwrote a tracked inode, hand its preserved fd to
            // the inode store so later ops resolve by fd, not the vanished path.
            // `store_unlinked_fd` takes ownership only when that inode is
            // tracked; close the fd ourselves otherwise so it is never leaked.
            if let Some(fd) = doomed_fd {
                match self.store_unlinked_fd(fd) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => unsafe {
                        libc::close(fd);
                    },
                }
            }

            if ((flags as i32) & bindings::LINUX_RENAME_WHITEOUT) != 0 {
                let fd = unsafe {
                    libc::open(
                        old_cpath.as_ptr(),
                        libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                        0o600,
                    )
                };
                if fd > 0 {
                    if let Err(e) = set_xattr_stat(
                        &InodeHandle::Fd(fd),
                        None,
                        None,
                        Some((libc::S_IFCHR | 0o600) as u32),
                    ) {
                        unsafe { libc::close(fd) };
                        return Err(e);
                    }
                    unsafe { libc::close(fd) };
                }
            }

            let entry = self.lookup(ctx, newdir, newname)?;
            self.forget(ctx, entry.inode, 1);

            Ok(())
        } else {
            if let Some(fd) = doomed_fd {
                // The rename failed; nothing was overwritten. Drop the fd.
                unsafe { libc::close(fd) };
            }
            Err(linux_error(io::Error::last_os_error()))
        }
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
        let c_path = self.name_to_path(parent, name)?;

        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            Err(linux_error(io::Error::last_os_error()))
        } else {
            let ihandle = InodeHandle::Fd(fd);

            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, false)?
            };

            let written = (Some(ctx.uid), Some(ctx.gid), Some(mode & !umask));
            if let Err(e) = set_xattr_stat(&ihandle, None, written.0.zip(written.1), written.2) {
                unsafe { libc::close(fd) };
                return Err(e);
            }

            unsafe { libc::close(fd) };
            self.lookup_as(parent, name, Some(written))
        }
    }

    fn link(
        &self,
        ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let orig_c_path = match self.inode_to_handle(inode, false)? {
            InodeHandle::Path(c_path) => c_path,
            InodeHandle::Fd(_) => return Err(ebadf()),
        };
        let link_c_path = self.name_to_path(newparent, newname)?;

        // `link()` follows a symlink source on macOS, so a guest could hard-link
        // a symlink it made pointing outside the share and reach that host file
        // through the new name. `linkat` without AT_SYMLINK_FOLLOW links the
        // symlink itself, as Linux does.
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                orig_c_path.as_ptr(),
                libc::AT_FDCWD,
                link_c_path.as_ptr(),
                0,
            )
        };
        if res == 0 {
            self.lookup(ctx, newparent, newname)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let c_path = self.name_to_path(parent, name)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::symlink(linkname.as_ptr(), c_path.as_ptr()) };
        if res == 0 {
            let ihandle = InodeHandle::Path(c_path);

            // Set security context
            if let Some(secctx) = extensions.secctx {
                set_secctx(&ihandle, secctx, true)?
            };

            let mode = libc::S_IFLNK | 0o777;
            let written = (Some(ctx.uid), Some(ctx.gid), Some(mode as u32));
            set_xattr_stat(&ihandle, None, written.0.zip(written.1), written.2)?;
            let mut entry = self.lookup_as(parent, name, Some(written))?;
            entry.attr.st_uid = ctx.uid;
            entry.attr.st_gid = ctx.gid;
            entry.attr.st_mode = mode;
            Ok(entry)
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let mut buf = vec![0; libc::PATH_MAX as usize];

        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::readlink(
                    c_path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::freadlink(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) as isize
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        buf.resize(res as usize, 0);
        Ok(buf)
    }

    fn flush(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        // Files opened without a request carry the kernel's default open
        // flags, which lack NOFLUSH, so each close would send a FLUSH this
        // server answers by dup(2)+close(2). Linux's ENOSYS once makes the
        // kernel stop sending them (fuse_flush sets no_flush); fsync stays.
        if self.zero_message_open.load(Ordering::Relaxed) {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }
        let data = self.file_for(inode, handle, false)?;

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = libc::dup(data.file.write().unwrap().as_raw_fd());
            if newfd < 0 {
                return Err(linux_error(io::Error::last_os_error()));
            }

            if libc::close(newfd) < 0 {
                Err(linux_error(io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }

    fn fsync(
        &self,
        _ctx: Context,
        inode: Inode,
        _datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        let data = self.file_for(inode, handle, false)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::fsync(fd) };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        if self.zero_message_opendir.load(Ordering::Relaxed)
            && !self
                .handles
                .read()
                .unwrap()
                .get(&handle)
                .is_some_and(|data| data.inode == inode)
        {
            let dir = self.open_inode(inode, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let res = unsafe { libc::fsync(dir.as_raw_fd()) };
            return if res == 0 {
                Ok(())
            } else {
                Err(linux_error(io::Error::last_os_error()))
            };
        }
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        let data = self.inode_data(inode);
        let st = self.gstat(&self.inode_to_handle(inode, true)?, data.as_deref())?;

        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            // The file exists since we were able to call `stat(2)` on it.
            return Ok(());
        }

        // We use ctx.uid/ctx.gid for these checks, but when idmapped mounts
        // support is enabled on the guest side, it means that "default_permissions"
        // flag is set on virtiofs mount and FUSE_ACCESS request should never be
        // sent to the userspace. Please, refer to the kernel commit
        // ("fs/fuse: warn if fuse_access is called when idmapped mounts are allowed").
        // In case when idmapped mounts are not enabled we are good to rely on ctx.uid/ctx.gid values.

        if (mode & libc::R_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o400 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o040 == 0)
            && st.st_mode & 0o004 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o200 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o020 == 0)
            && st.st_mode & 0o002 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.st_mode & 0o111 == 0)
            && (st.st_uid != ctx.uid || st.st_mode & 0o100 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o010 == 0)
            && st.st_mode & 0o001 == 0
        {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
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
        debug!("setxattr: inode={inode} name={name:?} value={value:?}");

        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        let mut mflags: i32 = 0;
        if (flags as i32) & bindings::LINUX_XATTR_CREATE != 0 {
            mflags |= libc::XATTR_CREATE;
        }
        if (flags as i32) & bindings::LINUX_XATTR_REPLACE != 0 {
            mflags |= libc::XATTR_REPLACE;
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::setxattr(
                    c_path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    0,
                    mflags as libc::c_int | libc::XATTR_NOFOLLOW,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::fsetxattr(
                    fd,
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    0,
                    mflags as libc::c_int,
                )
            },
        };

        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        debug!("getxattr: inode={inode} name={name:?}, size={size}");

        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EACCES)));
        }

        if name.to_bytes().starts_with(MACOS_XATTR_PREFIX) {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENODATA)));
        }

        let mut buf = vec![0; size as usize];

        // Safe because this will only modify the contents of `buf`
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                if size == 0 {
                    libc::getxattr(
                        c_path.as_ptr(),
                        name.as_ptr(),
                        std::ptr::null_mut(),
                        size as libc::size_t,
                        0,
                        libc::XATTR_NOFOLLOW,
                    )
                } else {
                    libc::getxattr(
                        c_path.as_ptr(),
                        name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                        0,
                        libc::XATTR_NOFOLLOW,
                    )
                }
            },
            InodeHandle::Fd(fd) => unsafe {
                if size == 0 {
                    libc::fgetxattr(
                        fd,
                        name.as_ptr(),
                        std::ptr::null_mut(),
                        size as libc::size_t,
                        0,
                        0,
                    )
                } else {
                    libc::fgetxattr(
                        fd,
                        name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                        0,
                        0,
                    )
                }
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, _ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        let mut buf = vec![0; 512_usize];

        // Safe because this will only modify the contents of `buf`.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::listxattr(
                    c_path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    512,
                    libc::XATTR_NOFOLLOW,
                )
            },
            InodeHandle::Fd(fd) => unsafe {
                libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, 512, 0)
            },
        };
        if res < 0 {
            return Err(linux_error(io::Error::last_os_error()));
        }

        buf.truncate(res as usize);

        if size == 0 {
            let mut clean_size = res as usize;

            for attr in buf.split(|c| *c == 0) {
                if attr.starts_with(&XATTR_KEY[..XATTR_KEY.len() - 1]) {
                    clean_size -= XATTR_KEY.len();
                } else if attr.starts_with(MACOS_XATTR_PREFIX) {
                    // attr does not include the null terminator; add 1 for it.
                    clean_size -= attr.len() + 1;
                }
            }

            Ok(ListxattrReply::Count(clean_size as u32))
        } else {
            let mut clean_buf = Vec::new();

            for attr in buf.split(|c| *c == 0) {
                if attr.is_empty()
                    || attr.starts_with(&XATTR_KEY[..XATTR_KEY.len() - 1])
                    || attr.starts_with(MACOS_XATTR_PREFIX)
                {
                    continue;
                }

                clean_buf.extend_from_slice(attr);
                clean_buf.push(0);
            }

            clean_buf.shrink_to_fit();

            if clean_buf.len() > size as usize {
                Err(io::Error::from_raw_os_error(LINUX_ERANGE))
            } else {
                Ok(ListxattrReply::Names(clean_buf))
            }
        }
    }

    fn removexattr(&self, _ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        if name.to_bytes() == XATTR_KEY {
            return Err(linux_error(io::Error::from_raw_os_error(
                bindings::LINUX_EACCES,
            )));
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let res = match self.inode_to_handle(inode, true)? {
            InodeHandle::Path(c_path) => unsafe {
                libc::removexattr(c_path.as_ptr(), name.as_ptr(), libc::XATTR_NOFOLLOW)
            },
            InodeHandle::Fd(fd) => unsafe { libc::fremovexattr(fd, name.as_ptr(), 0) },
        };
        if res == 0 {
            Ok(())
        } else {
            Err(linux_error(io::Error::last_os_error()))
        }
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let data = self.file_for(inode, handle, true)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        const SUPPORTED_FLAGS: i32 = bindings::LINUX_FALLOC_FL_ALLOCATE_RANGE
            | bindings::LINUX_FALLOC_FL_KEEP_SIZE
            | bindings::LINUX_FALLOC_FL_PUNCH_HOLE;

        if mode as i32 & !SUPPORTED_FLAGS != 0 {
            return Err(linux_error(io::Error::from_raw_os_error(libc::EOPNOTSUPP)));
        }

        let keep_size = mode & bindings::LINUX_FALLOC_FL_KEEP_SIZE as u32 != 0;
        let mode = mode & !bindings::LINUX_FALLOC_FL_KEEP_SIZE as u32;

        match mode as i32 {
            bindings::LINUX_FALLOC_FL_ALLOCATE_RANGE => {
                // The closest thing we have on macOS to posix_fallocate is F_PREALLOCATE,
                // but this one doesn't allow us to allocate arbitrary ranges, only allocate
                // blocks to the file's end.
                //
                // The best thing we can do here is extend the file to (offset + length).
                // This doesn't adhere to the same semantics, but should work fine (albeit
                // less performant) for most guest applications.
                let st = fstat(fd, true)?;
                let new_length = (offset + length) as i64;

                if keep_size {
                    // Check the number of allocated blocks instead of the file size.
                    let disk_size = st.st_blocks * 512_i64;
                    if disk_size >= new_length {
                        return Ok(());
                    }
                    let mut fs = libc::fstore_t {
                        fst_flags: libc::F_ALLOCATEALL,
                        fst_posmode: libc::F_PEOFPOSMODE,
                        fst_offset: 0,
                        fst_length: new_length - disk_size,
                        fst_bytesalloc: 0,
                    };

                    let res = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut fs as *mut _) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }
                } else {
                    if st.st_size >= new_length {
                        return Ok(());
                    }
                    let res = unsafe { libc::ftruncate(fd, new_length) };
                    if res < 0 {
                        return Err(linux_error(io::Error::last_os_error()));
                    }
                }
            }
            bindings::LINUX_FALLOC_FL_PUNCH_HOLE => {
                if !keep_size {
                    // Linux forbids the use of PUNCH_HOLE without KEEP_SIZE.
                    return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
                }

                let mut hole = libc::fpunchhole_t {
                    fp_offset: offset as i64,
                    fp_flags: 0,
                    reserved: 0,
                    fp_length: length as i64,
                };

                let res = unsafe { libc::fcntl(fd, libc::F_PUNCHHOLE, &mut hole as *mut _) };
                if res < 0 {
                    return Err(linux_error(io::Error::last_os_error()));
                }
            }
            _ => unreachable!(),
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
        let data = self.file_for(inode, handle, false)?;

        // SEEK_DATA and SEEK_HOLE have slightly different semantics
        // in Linux vs. macOS, which means we can't support them.
        let mwhence = if whence == 3 {
            // SEEK_DATA
            return Ok(offset);
        } else if whence == 4 {
            // SEEK_HOLE
            libc::SEEK_END
        } else {
            whence as i32
        };

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek(fd, offset as bindings::off64_t, mwhence as libc::c_int) };
        if res < 0 {
            Err(linux_error(io::Error::last_os_error()))
        } else {
            Ok(res as u64)
        }
    }

    fn setupmapping(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        if map_sender.is_none() {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        let open_flags = if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };

        let prot_flags = if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        let einval = || linux_error(io::Error::from_raw_os_error(libc::EINVAL));
        let end = moffset.checked_add(len).ok_or_else(einval)?;
        if end > shm_size {
            return Err(einval());
        }

        let guest_addr = guest_shm_base.checked_add(moffset).ok_or_else(einval)?;

        debug!("setupmapping: ino {inode:?} guest_addr={guest_addr:x} len={len}");

        let file = self.open_inode(inode, open_flags)?;
        let fd = file.as_raw_fd();

        let host_addr = unsafe {
            libc::mmap(
                null_mut(),
                len as usize,
                prot_flags,
                libc::MAP_SHARED,
                fd,
                foffset as libc::off_t,
            )
        };
        if host_addr == libc::MAP_FAILED {
            return Err(linux_error(io::Error::last_os_error()));
        }

        drop(file);

        // We've checked that map_sender is something above.
        let sender = map_sender.as_ref().unwrap();
        let (reply_sender, reply_receiver) = unbounded();
        sender
            .send(WorkerMessage::GpuAddMapping(
                reply_sender,
                host_addr as u64,
                guest_addr,
                len,
            ))
            .unwrap();
        if !reply_receiver.recv().unwrap() {
            error!("Error requesting HVF the addition of a DAX window");
            unsafe { libc::munmap(host_addr, len as usize) };
            return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
        }

        self.map_windows
            .lock()
            .unwrap()
            .insert(guest_addr, host_addr as u64);

        Ok(())
    }

    fn removemapping(
        &self,
        _ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        if map_sender.is_none() {
            return Err(linux_error(io::Error::from_raw_os_error(libc::ENOSYS)));
        }

        for req in requests {
            let einval = || linux_error(io::Error::from_raw_os_error(libc::EINVAL));
            let end = req.moffset.checked_add(req.len).ok_or_else(einval)?;
            if end > shm_size {
                return Err(einval());
            }
            let guest_addr = guest_shm_base.checked_add(req.moffset).ok_or_else(einval)?;
            let host_addr = match self.map_windows.lock().unwrap().remove(&guest_addr) {
                Some(a) => a,
                None => return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL))),
            };
            debug!(
                "removemapping: guest_addr={:x} len={:?}",
                guest_addr, req.len
            );

            let sender = map_sender.as_ref().unwrap();
            let (reply_sender, reply_receiver) = unbounded();
            sender
                .send(WorkerMessage::GpuRemoveMapping(
                    reply_sender,
                    guest_addr,
                    req.len,
                ))
                .unwrap();
            if !reply_receiver.recv().unwrap() {
                error!("Error requesting HVF the removal of a DAX window");
                return Err(linux_error(io::Error::from_raw_os_error(libc::EINVAL)));
            }

            let ret = unsafe { libc::munmap(host_addr as *mut libc::c_void, req.len as usize) };
            if ret == -1 {
                error!("Error unmapping DAX window");
                return Err(linux_error(io::Error::last_os_error()));
            }
        }

        Ok(())
    }

    fn ioctl(
        &self,
        _ctx: Context,
        _inode: Self::Inode,
        _handle: Self::Handle,
        _flags: u32,
        cmd: u32,
        arg: u64,
        _in_size: u32,
        _out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        // We can't use nix::request_code_none here since it's system-dependent
        // and we need the value from Linux.
        const VIRTIO_IOC_EXIT_CODE_REQ: u32 = 0x7602;
        const VIRTIO_IOC_REMOVE_ROOT_DIR_REQ: u32 = 0x7603;

        // Rosetta checks, through its own binary, that the share it was
        // started from is the one a Rosetta-enabled VM provides. Answering
        // here lets the guest register Rosetta itself as the binfmt
        // interpreter, so a translated program keeps its pid, its signals and
        // its setuid credentials. Without the answer Rosetta aborts, and the
        // guest has to run it under a ptrace shim that fakes this reply and
        // stays between the program and its parent.
        if self.rosetta_runtime
            && let Some(reply) = rosetta_ioctl_reply(cmd)
        {
            return Ok(reply);
        }

        match cmd {
            VIRTIO_IOC_EXIT_CODE_REQ => {
                exit_code.store(arg as i32, Ordering::SeqCst);
                Ok(Vec::new())
            }
            VIRTIO_IOC_REMOVE_ROOT_DIR_REQ if self.cfg.allow_root_dir_delete => {
                std::fs::remove_dir_all(&self.cfg.root_dir)?;
                Ok(Vec::new())
            }
            // A regular file is never a terminal, so reject the terminal ioctl
            // family with ENOTTY. Without this the catch-all below reports
            // success, and glibc's `isatty()` — which probes with a terminal
            // ioctl and reads success as "is a tty" (TCGETS before glibc 2.42,
            // TCGETS2 since) — treats every virtiofs-mounted file as a terminal,
            // so e.g. `python3 script.py` on a mount drops into interactive mode.
            _ if is_terminal_ioctl(cmd) => Err(io::Error::from_raw_os_error(libc::ENOTTY)),
            // For FS_IOC_GETFLAGS (used by overlayfs copy-up): return zero flags
            // instead of an error. macOS doesn't support Linux file attributes, so
            // report "no flags set" which lets overlayfs proceed normally.
            // Returning EOPNOTSUPP/ENOTSUPP causes overlayfs copy-up to fail.
            _ => Ok(vec![0u8; std::mem::size_of::<u32>()]),
        }
    }
}

/// Whether a Linux ioctl request belongs to the terminal (`'T'`) family —
/// `TCGETS`, `TCGETS2`, `TIOCGWINSZ`, and the rest of the termios/tty ioctls.
///
/// The request is a Linux `_IOC(...)` value forwarded verbatim by the guest
/// virtiofs client; its "type" byte sits at bits 8..=15. A regular file is
/// never a terminal, so the passthrough backend answers these with `ENOTTY`
/// rather than a bogus success — otherwise `isatty()` in the guest reports a
/// mounted file as a tty.
fn is_terminal_ioctl(cmd: u32) -> bool {
    const IOC_TYPE_SHIFT: u32 = 8;
    const IOC_TYPE_MASK: u32 = 0xff;
    (cmd >> IOC_TYPE_SHIFT) & IOC_TYPE_MASK == b'T' as u32
}

/// The reply to one of Rosetta's start-up ioctls, or `None` for any other
/// request.
///
/// Rosetta issues two read ioctls of type `'a'` on its own binary. The request
/// number has changed between macOS releases (0x22, then 0x25, for the first),
/// so they are told apart by the size of the buffer they read into:
///
/// - 69 bytes: the key that proves the share comes from a Rosetta-enabled VM.
/// - 128 bytes: where the translation cache daemon listens. All zeroes means
///   there is none, and Rosetta translates in process.
fn rosetta_ioctl_reply(cmd: u32) -> Option<Vec<u8>> {
    const IOC_READ: u32 = 2;
    const CACHE_REPLY_LEN: usize = 128;

    let dir = cmd >> 30;
    let size = ((cmd >> 16) & 0x3fff) as usize;
    let ty = (cmd >> 8) & 0xff;
    if ty != b'a' as u32 || dir != IOC_READ {
        return None;
    }

    if size == ROSETTA_KEY.len() {
        Some(ROSETTA_KEY.to_vec())
    } else if size == CACHE_REPLY_LEN {
        Some(vec![0u8; CACHE_REPLY_LEN])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    // A restore resolves inode identities beneath the export root without
    // following any symlink: an intermediate component that is (or became) a
    // symlink must be refused, while a trailing symlink is the link itself.
    #[test]
    fn restore_identities_stay_beneath_the_export_root() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "libkrun-identity-beneath-{}-{nonce}",
            std::process::id()
        ));
        let root = base.join("export");
        fs::create_dir_all(root.join("dir")).unwrap();
        fs::write(root.join("dir/file"), b"inside").unwrap();
        fs::create_dir(base.join("elsewhere")).unwrap();
        fs::write(base.join("elsewhere/file"), b"outside").unwrap();
        std::os::unix::fs::symlink(base.join("elsewhere"), root.join("linked")).unwrap();
        let identity = |p: &Path| {
            let m = fs::symlink_metadata(p).unwrap();
            (m.dev() as i32, m.ino())
        };

        assert_eq!(
            PassthroughFs::identity_beneath(&root, Path::new("dir/file")).unwrap(),
            identity(&root.join("dir/file"))
        );
        // macOS refuses the link with ENOTDIR (O_DIRECTORY is checked
        // first), Linux with ELOOP; either way it is not followed.
        assert!(
            matches!(
                PassthroughFs::identity_beneath(&root, Path::new("linked/file"))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ELOOP | libc::ENOTDIR)
            ),
            "an intermediate symlink must not be followed"
        );
        assert_eq!(
            PassthroughFs::identity_beneath(&root, Path::new("linked")).unwrap(),
            identity(&root.join("linked"))
        );
        assert!(PassthroughFs::identity_beneath(&root, Path::new("../export/dir")).is_err());

        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn terminal_ioctls_are_recognized() {
        // The termios/tty family that `isatty()` probes with.
        const TCGETS: u32 = 0x5401; // glibc < 2.42, musl
        const TCGETS2: u32 = 0x802c_542b; // glibc >= 2.42
        const TIOCGWINSZ: u32 = 0x5413;
        assert!(is_terminal_ioctl(TCGETS));
        assert!(is_terminal_ioctl(TCGETS2));
        assert!(is_terminal_ioctl(TIOCGWINSZ));
    }

    #[test]
    fn rosetta_start_up_ioctls_get_their_reply() {
        // The key request under both numbers macOS has used for it.
        for cmd in [0x8045_6122u32, 0x8045_6125] {
            let reply = rosetta_ioctl_reply(cmd).expect("key request");
            assert_eq!(reply.len(), 69);
            assert!(reply.starts_with(b"Our hard work\n"));
            assert_eq!(reply.last(), Some(&0));
        }

        assert_eq!(rosetta_ioctl_reply(0x8080_6123), Some(vec![0u8; 128]));
    }

    #[test]
    fn other_ioctls_get_no_rosetta_reply() {
        const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
        const TCGETS: u32 = 0x5401;

        assert_eq!(rosetta_ioctl_reply(FS_IOC_GETFLAGS), None);
        assert_eq!(rosetta_ioctl_reply(TCGETS), None);
        // Type 'a' but no buffer to read into, a write, or another size.
        assert_eq!(rosetta_ioctl_reply(0x6124), None);
        assert_eq!(rosetta_ioctl_reply(0x4045_6125), None);
        assert_eq!(rosetta_ioctl_reply(0x8008_6125), None);
    }

    #[test]
    fn non_terminal_ioctls_are_not_misclassified() {
        // FS_IOC_GETFLAGS (type 'f') is used by overlayfs copy-up and must
        // still reach the catch-all, not be rejected as a terminal ioctl.
        const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
        const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
        assert!(!is_terminal_ioctl(FS_IOC_GETFLAGS));
        assert!(!is_terminal_ioctl(FS_IOC_SETFLAGS));
    }

    #[test]
    fn init_offers_readdirplus_when_the_kernel_can_take_it() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "libkrun-readdirplus-init-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        let both = FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        assert_eq!(
            FileSystem::init(&filesystem, both).unwrap() & both,
            both,
            "a kernel offering both gets adaptive readdirplus"
        );
        assert_eq!(
            FileSystem::init(&filesystem, FsOptions::DO_READDIRPLUS).unwrap() & both,
            FsOptions::DO_READDIRPLUS,
            "without AUTO the kernel issues readdirplus for every listing"
        );
        assert!(
            !FileSystem::init(&filesystem, FsOptions::empty())
                .unwrap()
                .intersects(both),
            "a kernel that cannot take it is not offered it"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn regular_opens_skip_redundant_close_flushes() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "libkrun-no-close-flush-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("existing"), b"data").unwrap();

        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        let negotiated =
            FileSystem::init(&filesystem, FsOptions::POSIX_LOCKS | FsOptions::FLOCK_LOCKS).unwrap();
        assert!(!negotiated.intersects(FsOptions::POSIX_LOCKS | FsOptions::FLOCK_LOCKS));
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let existing = CString::new("existing").unwrap();
        let entry = FileSystem::lookup(&filesystem, context, fuse::ROOT_ID, &existing).unwrap();
        for access in [libc::O_RDONLY, libc::O_WRONLY, libc::O_RDWR] {
            let (_, open_options) =
                FileSystem::open(&filesystem, context, entry.inode, false, access as u32).unwrap();
            assert!(open_options.contains(OpenOptions::NOFLUSH), "{access:#o}");
        }

        let created = CString::new("created").unwrap();
        let (_, _, create_options) = FileSystem::create(
            &filesystem,
            context,
            fuse::ROOT_ID,
            &created,
            0o644,
            false,
            libc::O_WRONLY as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
        assert!(create_options.contains(OpenOptions::NOFLUSH));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directories_list_without_an_opendir_when_the_kernel_offers_to_skip_it() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "libkrun-zero-opendir-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        for name in ["a", "b", "c"] {
            fs::write(root.join(name), b"x").unwrap();
        }
        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };

        // Without the kernel's offer, opendir hands out a handle as before.
        assert!(
            !FileSystem::init(&filesystem, FsOptions::empty())
                .unwrap()
                .contains(FsOptions::ZERO_MESSAGE_OPENDIR)
        );
        let (handle, _) =
            FileSystem::opendir(&filesystem, context, fuse::ROOT_ID, libc::O_RDONLY as u32)
                .unwrap();
        assert!(handle.is_some());

        // With it, opendir is ENOSYS and readdir works with no handle: a
        // first chunk, a continuation from its offset, then the end.
        assert!(
            FileSystem::init(&filesystem, FsOptions::ZERO_MESSAGE_OPENDIR)
                .unwrap()
                .contains(FsOptions::ZERO_MESSAGE_OPENDIR)
        );
        let err = FileSystem::opendir(&filesystem, context, fuse::ROOT_ID, libc::O_RDONLY as u32)
            .unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(bindings::LINUX_ENOSYS),
            "the guest must see Linux's ENOSYS, not the host's"
        );
        let mut names = Vec::new();
        let mut next = 0;
        FileSystem::readdir(&filesystem, context, fuse::ROOT_ID, 0, 4096, 0, |entry| {
            names.push(String::from_utf8_lossy(entry.name).into_owned());
            next = entry.offset;
            // the kernel's buffer holds one entry: ask for the rest later
            Ok(if names.len() == 1 { 0 } else { 1 })
        })
        .unwrap();
        assert_eq!(names.len(), 1);
        FileSystem::readdir(
            &filesystem,
            context,
            fuse::ROOT_ID,
            0,
            4096,
            next,
            |entry| {
                names.push(String::from_utf8_lossy(entry.name).into_owned());
                next = entry.offset;
                Ok(1)
            },
        )
        .unwrap();
        names.sort();
        assert_eq!(names, ["a", "b", "c"]);
        let mut extra = 0;
        FileSystem::readdir(&filesystem, context, fuse::ROOT_ID, 0, 4096, next, |_| {
            extra += 1;
            Ok(1)
        })
        .unwrap();
        assert_eq!(extra, 0, "the listing has ended");
        assert!(
            filesystem.handleless_dirs.lock().unwrap().is_empty(),
            "a finished listing keeps nothing"
        );
        // releasedir for a handle that never existed is not an error
        FileSystem::releasedir(&filesystem, context, fuse::ROOT_ID, 0, 0).unwrap();
        FileSystem::fsyncdir(&filesystem, context, fuse::ROOT_ID, false, 0).unwrap();

        fs::remove_dir_all(root).unwrap();
    }

    /// Test stand-ins for the transport: a sink the server copies file bytes
    /// into, and a source it copies into the file.
    struct Sink(Vec<u8>);
    impl io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl ZeroCopyWriter for Sink {
        fn write_from(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
            use std::os::unix::fs::FileExt;
            let mut buf = vec![0; count];
            let n = f.read_at(&mut buf, off)?;
            self.0.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }
    struct Source(Vec<u8>);
    impl io::Read for Source {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        }
    }
    impl ZeroCopyReader for Source {
        fn read_to(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
            use std::os::unix::fs::FileExt;
            let n = count.min(self.0.len());
            let written = f.write_at(&self.0[..n], off)?;
            self.0.drain(..written);
            Ok(written)
        }
    }

    #[test]
    fn an_unprivileged_write_drops_setgid_as_a_local_filesystem_does() {
        // The kernel's rule for a local file (setattr_should_drop_suidgid): an
        // unprivileged write always drops setuid, and drops setgid when the file
        // is group-executable or the writer is outside the file's group. The
        // server is handed the write with the kill flag and must apply the same.
        assert_eq!(mode_after_unprivileged_write(0o106_666, 7, 7), 0o102_666);
        assert_eq!(mode_after_unprivileged_write(0o106_666, 7, 8), 0o100_666);
        assert_eq!(mode_after_unprivileged_write(0o102_666, 7, 7), 0o102_666);
        assert_eq!(mode_after_unprivileged_write(0o102_676, 7, 7), 0o100_676);
        assert_eq!(mode_after_unprivileged_write(0o102_676, 7, 8), 0o100_676);
        assert_eq!(mode_after_unprivileged_write(0o100_666, 7, 8), 0o100_666);

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("libkrun-sgid-write-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&filesystem, FsOptions::empty()).unwrap();
        let root_ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        // Two setuid-and-setgid files without a group-exec bit, each written by
        // a user in a group other than the file's and by one in the file's group.
        let mut modes = Vec::new();
        for (name, writer_gid) in [("outside", 1234u32), ("inside", 0u32)] {
            let name = CString::new(name).unwrap();
            let (entry, handle, _) = FileSystem::create(
                &filesystem,
                root_ctx,
                fuse::ROOT_ID,
                &name,
                0o100_666,
                false,
                libc::O_WRONLY as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
            let mut attr: bindings::stat64 = unsafe { std::mem::zeroed() };
            attr.st_mode = 0o106_666;
            FileSystem::setattr(
                &filesystem,
                root_ctx,
                entry.inode,
                attr,
                handle,
                SetattrValid::MODE,
            )
            .unwrap();
            let (st, _) = FileSystem::getattr(&filesystem, root_ctx, entry.inode, None).unwrap();
            assert_eq!(
                st.st_mode as u32 & 0o7777,
                0o6666,
                "{name:?} before the write"
            );
            assert_eq!(st.st_gid, 0, "{name:?} is group 0 as the guest sees it");
            let writer = Context {
                uid: 1234,
                gid: writer_gid,
                pid: 0,
            };
            FileSystem::write(
                &filesystem,
                writer,
                entry.inode,
                handle.unwrap(),
                Source(b"y".to_vec()),
                1,
                0,
                None,
                false,
                true,
                0,
            )
            .unwrap();
            let (st, _) = FileSystem::getattr(&filesystem, root_ctx, entry.inode, None).unwrap();
            modes.push(st.st_mode as u32 & 0o7777);
        }
        assert_eq!(modes, vec![0o666, 0o2666]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn shared_descriptor_budget_recycles_entries_without_closing_active_requests() {
        use std::os::unix::fs::FileExt;
        let root = std::env::temp_dir().join(format!("krun-fd-budget-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a"), b"first").unwrap();
        fs::write(root.join("b"), b"second").unwrap();
        let budget = Arc::new(DescriptorBudget::new(2));
        let make_share = || {
            let fs = PassthroughFs::new(
                Config {
                    root_dir: root.to_string_lossy().into_owned(),
                    ..Default::default()
                },
                Arc::new(InodeAllocator::new()),
            )
            .unwrap();
            FileSystem::init(&fs, FsOptions::ZERO_MESSAGE_OPEN).unwrap();
            fs.inode_fds.lock().unwrap().budget = budget.clone();
            fs
        };
        let first = make_share();
        let second = make_share();
        let third = make_share();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let lookup = |fs: &PassthroughFs, name: &str| {
            FileSystem::lookup(fs, ctx, fuse::ROOT_ID, &CString::new(name).unwrap())
                .unwrap()
                .inode
        };
        let a = lookup(&first, "a");
        let active = first.inode_fd(a, false).unwrap();
        let second_a = lookup(&second, "a");
        second.inode_fd(second_a, false).unwrap();
        assert!(budget.reserve().is_none());
        // A new share still serves reads when other shares retain every slot.
        let third_a = lookup(&third, "a");
        third.inode_fd(third_a, false).unwrap();
        assert!(third.inode_fds.lock().unwrap().map.is_empty());
        // Upgrading a read descriptor must work with the budget already full.
        first.inode_fd(a, true).unwrap();
        assert!(first.inode_fds.lock().unwrap().map[&a].writable);
        let b = lookup(&first, "b");
        first.inode_fd(b, true).unwrap();
        {
            let cache = first.inode_fds.lock().unwrap();
            assert_eq!(cache.map.len(), 1);
            assert!(cache.map.contains_key(&b));
            assert!(!cache.map.contains_key(&a));
        }
        let mut buf = [0; 5];
        active
            .file
            .read()
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        assert_eq!(
            &buf, b"first",
            "eviction must not close an in-flight request's fd"
        );
        FileSystem::forget(&first, ctx, b, 1);
        let returned = budget.reserve().expect("forget releases the retained slot");
        assert!(budget.reserve().is_none());
        drop(returned);
        FileSystem::release(&second, ctx, second_a, 0, 0, false, false, None).unwrap();
        let slots = (budget.reserve().unwrap(), budget.reserve().unwrap());
        assert!(budget.reserve().is_none());
        drop(slots);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn truncate_returns_final_modes_and_timestamps() {
        let root = std::env::temp_dir().join(format!("krun-truncate-reply-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("f"), b"payload").unwrap();
        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&filesystem, FsOptions::ZERO_MESSAGE_OPEN).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let entry =
            FileSystem::lookup(&filesystem, ctx, fuse::ROOT_ID, &CString::new("f").unwrap())
                .unwrap();
        let mut attr = entry.attr;
        attr.st_mode = (libc::S_IFREG | 0o6755) as _;
        FileSystem::setattr(
            &filesystem,
            ctx,
            entry.inode,
            attr,
            None,
            SetattrValid::MODE,
        )
        .unwrap();
        attr.st_size = 3;
        let (truncated, _) = FileSystem::setattr(
            &filesystem,
            ctx,
            entry.inode,
            attr,
            None,
            SetattrValid::SIZE,
        )
        .unwrap();
        assert_eq!(truncated.st_size, 3);
        assert_eq!(truncated.st_mode as u32 & 0o7777, 0o755);
        attr.st_size = 2;
        attr.st_mtime = 123456789;
        attr.st_mtime_nsec = 0;
        let (timed, _) = FileSystem::setattr(
            &filesystem,
            ctx,
            entry.inode,
            attr,
            Some(0),
            SetattrValid::SIZE | SetattrValid::MTIME,
        )
        .unwrap();
        assert_eq!(timed.st_size, 2);
        assert_eq!(timed.st_mtime, 123456789);
        // External metadata edits must still invalidate cached overrides.
        let path = CString::new(root.join("f").to_str().unwrap()).unwrap();
        set_xattr_stat(
            &InodeHandle::Path(path),
            None,
            Some((123, 456)),
            Some(libc::S_IFREG as u32 | 0o640),
        )
        .unwrap();
        attr.st_size = 1;
        let (external, _) = FileSystem::setattr(
            &filesystem,
            ctx,
            entry.inode,
            attr,
            None,
            SetattrValid::SIZE,
        )
        .unwrap();
        assert_eq!(external.st_uid, 123);
        assert_eq!(external.st_gid, 456);
        assert_eq!(external.st_mode as u32 & 0o7777, 0o640);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn files_read_and_write_without_an_open_when_the_kernel_offers_to_skip_it() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("libkrun-zero-open-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("f"), b"hello").unwrap();
        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let name = CString::new("f").unwrap();

        // Without the kernel's offer, open hands out a handle as before.
        assert!(
            !FileSystem::init(&filesystem, FsOptions::empty())
                .unwrap()
                .contains(FsOptions::ZERO_MESSAGE_OPEN)
        );
        let entry = FileSystem::lookup(&filesystem, context, fuse::ROOT_ID, &name).unwrap();
        let (handle, _) = FileSystem::open(
            &filesystem,
            context,
            entry.inode,
            false,
            libc::O_RDONLY as u32,
        )
        .unwrap();
        assert!(handle.is_some());
        FileSystem::release(
            &filesystem,
            context,
            entry.inode,
            0,
            handle.unwrap(),
            false,
            false,
            None,
        )
        .unwrap();

        // With it: open is Linux's ENOSYS, and read, write, ftruncate and
        // release all work with handle 0.
        assert!(
            FileSystem::init(&filesystem, FsOptions::ZERO_MESSAGE_OPEN)
                .unwrap()
                .contains(FsOptions::ZERO_MESSAGE_OPEN)
        );
        let err = FileSystem::open(
            &filesystem,
            context,
            entry.inode,
            false,
            libc::O_RDONLY as u32,
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(bindings::LINUX_ENOSYS));

        let mut out = Sink(Vec::new());
        let n = FileSystem::read(
            &filesystem,
            context,
            entry.inode,
            0,
            &mut out,
            16,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(&out.0[..n], b"hello");

        // O_TRUNC without an OPEN carries no handle. A descriptor cached by
        // the preceding read must be upgraded for truncation and later writes.
        let mut truncate: bindings::stat64 = unsafe { std::mem::zeroed() };
        truncate.st_size = 5;
        FileSystem::setattr(
            &filesystem,
            context,
            entry.inode,
            truncate,
            None,
            SetattrValid::SIZE,
        )
        .unwrap();

        let n = FileSystem::write(
            &filesystem,
            context,
            entry.inode,
            0,
            Source(b"HE".to_vec()),
            2,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(fs::read(root.join("f")).unwrap(), b"HEllo");

        // the kernel's ftruncate on such a file names handle 0 too
        let mut attr: bindings::stat64 = unsafe { std::mem::zeroed() };
        attr.st_size = 1;
        FileSystem::setattr(
            &filesystem,
            context,
            entry.inode,
            attr,
            Some(0),
            SetattrValid::SIZE,
        )
        .unwrap();
        assert_eq!(fs::read(root.join("f")).unwrap(), b"H");

        assert_eq!(
            filesystem.inode_fds.lock().unwrap().map.len(),
            1,
            "one kept descriptor"
        );
        FileSystem::release(&filesystem, context, entry.inode, 0, 0, false, false, None).unwrap();
        assert!(
            filesystem.inode_fds.lock().unwrap().map.is_empty(),
            "a release naming handle 0 closes the kept descriptor"
        );
        let mut again = Sink(Vec::new());
        let n = FileSystem::read(
            &filesystem,
            context,
            entry.inode,
            0,
            &mut again,
            16,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(&again.0[..n], b"H", "and the next request opens afresh");
        assert_eq!(
            FileSystem::flush(&filesystem, context, entry.inode, 0, 0)
                .unwrap_err()
                .raw_os_error(),
            Some(bindings::LINUX_ENOSYS),
            "no FLUSH while files open without a request"
        );

        // a created file hands out no handle either; its descriptor is kept
        // with the inode, where the handle-0 writes find it
        let created = CString::new("made").unwrap();
        let (made, handle, _) = FileSystem::create(
            &filesystem,
            context,
            fuse::ROOT_ID,
            &created,
            0o644,
            false,
            libc::O_WRONLY as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
        assert!(handle.is_none());
        assert!(
            filesystem.handles.read().unwrap().is_empty(),
            "no handle kept"
        );
        assert_eq!(filesystem.inode_fds.lock().unwrap().map.len(), 2);
        let n = FileSystem::write(
            &filesystem,
            context,
            made.inode,
            0,
            Source(b"new".to_vec()),
            3,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
        assert_eq!(n, 3);
        assert_eq!(fs::read(root.join("made")).unwrap(), b"new");
        // A later read arrives without OPEN/RELEASE too. The create used
        // O_WRONLY, so its cached descriptor must not serve this read.
        let mut created_out = Sink(Vec::new());
        let n = FileSystem::read(
            &filesystem,
            context,
            made.inode,
            0,
            &mut created_out,
            16,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(&created_out.0[..n], b"new");
        FileSystem::forget(&filesystem, context, entry.inode, u64::MAX);
        assert!(
            !filesystem
                .inode_fds
                .lock()
                .unwrap()
                .map
                .contains_key(&entry.inode),
            "a forgotten inode drops its descriptor"
        );
        FileSystem::batch_forget(&filesystem, context, vec![(made.inode, u64::MAX)]);
        assert!(
            filesystem.inode_fds.lock().unwrap().map.is_empty(),
            "so does a batch forget"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_missing_name_is_an_error_unless_the_share_keeps_negative_entries() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("libkrun-negative-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let missing = CString::new("nothing-here").unwrap();

        // as before: ENOENT, which the kernel does not cache
        let plain = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&plain, FsOptions::empty()).unwrap();
        let Err(err) = FileSystem::lookup(&plain, context, fuse::ROOT_ID, &missing) else {
            panic!("a missing name looked up without negative entries must fail");
        };
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));

        // with a negative timeout: an entry with inode 0 the kernel keeps that long
        let keeping = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                negative_timeout: Duration::from_secs(1),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&keeping, FsOptions::empty()).unwrap();
        let entry = FileSystem::lookup(&keeping, context, fuse::ROOT_ID, &missing).unwrap();
        assert_eq!(entry.inode, 0);
        assert_eq!(entry.entry_timeout, Duration::from_secs(1));
        assert!(
            keeping
                .inodes
                .read()
                .unwrap()
                .get_alt(&InodeAltKey { ino: 0, dev: 0 })
                .is_none()
        );
        // a name that exists is unaffected
        fs::write(root.join("present"), b"x").unwrap();
        let present = FileSystem::lookup(
            &keeping,
            context,
            fuse::ROOT_ID,
            &CString::new("present").unwrap(),
        )
        .unwrap();
        assert_ne!(present.inode, 0);
        assert_eq!(present.entry_timeout, Duration::from_secs(5));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_entries_preserve_recorded_whiteout_types() {
        for handleless in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "krun-whiteout-types-{}-{handleless}",
                std::process::id()
            ));
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("regular"), b"data").unwrap();
            fs::write(root.join("renamed"), b"data").unwrap();
            let filesystem = PassthroughFs::new(
                Config {
                    root_dir: root.to_string_lossy().into_owned(),
                    override_stat: true,
                    ..Default::default()
                },
                Arc::new(InodeAllocator::new()),
            )
            .unwrap();
            let options = if handleless {
                FsOptions::ZERO_MESSAGE_OPENDIR
            } else {
                FsOptions::empty()
            };
            FileSystem::init(&filesystem, options).unwrap();
            let ctx = Context {
                uid: 0,
                gid: 0,
                pid: 0,
            };
            FileSystem::mknod(
                &filesystem,
                ctx,
                fuse::ROOT_ID,
                &CString::new("whiteout").unwrap(),
                libc::S_IFCHR as u32 | 0o600,
                0,
                0,
                Extensions::default(),
            )
            .unwrap();
            FileSystem::rename(
                &filesystem,
                ctx,
                fuse::ROOT_ID,
                &CString::new("renamed").unwrap(),
                fuse::ROOT_ID,
                &CString::new("destination").unwrap(),
                bindings::LINUX_RENAME_WHITEOUT as u32,
            )
            .unwrap();
            let handle = if handleless {
                0
            } else {
                FileSystem::opendir(&filesystem, ctx, fuse::ROOT_ID, libc::O_RDONLY as u32)
                    .unwrap()
                    .0
                    .unwrap()
            };
            let mut found = Vec::new();
            FileSystem::readdir(&filesystem, ctx, fuse::ROOT_ID, handle, 4096, 0, |entry| {
                found.push((entry.name.to_vec(), entry.type_));
                Ok(1)
            })
            .unwrap();
            found.sort();
            assert_eq!(
                found,
                vec![
                    (b"destination".to_vec(), libc::DT_REG as u32),
                    (b"regular".to_vec(), libc::DT_REG as u32),
                    (b"renamed".to_vec(), libc::DT_CHR as u32),
                    (b"whiteout".to_vec(), libc::DT_CHR as u32),
                ]
            );
            FileSystem::readdirplus(
                &filesystem,
                ctx,
                fuse::ROOT_ID,
                handle,
                4096,
                0,
                |dir, entry| {
                    assert_eq!(
                        dir.type_,
                        (entry.attr.st_mode as u32 & libc::S_IFMT as u32) >> 12
                    );
                    Ok(1)
                },
            )
            .unwrap();
            // Rewinding must observe metadata changed outside this server too.
            let path = CString::new(root.join("whiteout").as_os_str().as_bytes()).unwrap();
            set_xattr_stat(
                &InodeHandle::Path(path),
                None,
                None,
                Some(libc::S_IFREG as u32 | 0o600),
            )
            .unwrap();
            FileSystem::readdir(&filesystem, ctx, fuse::ROOT_ID, handle, 4096, 0, |entry| {
                if entry.name == b"whiteout" {
                    assert_eq!(entry.type_, libc::DT_REG as u32);
                }
                Ok(1)
            })
            .unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn readdirplus_looks_up_each_entry_by_its_full_name() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "libkrun-readdirplus-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("abc"), b"data").unwrap();
        fs::write(root.join("ab"), b"other").unwrap();

        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&filesystem, FsOptions::empty()).unwrap();
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let (handle, _) =
            FileSystem::opendir(&filesystem, context, fuse::ROOT_ID, libc::O_RDONLY as u32)
                .unwrap();
        let mut found = Vec::new();
        FileSystem::readdirplus(
            &filesystem,
            context,
            fuse::ROOT_ID,
            handle.unwrap(),
            4096,
            0,
            |dir_entry, entry| {
                found.push((dir_entry.name.to_vec(), entry.attr.st_ino));
                Ok(1)
            },
        )
        .unwrap();
        found.sort();
        let ino = |name: &str| fs::metadata(root.join(name)).unwrap().ino();
        assert_eq!(
            found,
            vec![(b"ab".to_vec(), ino("ab")), (b"abc".to_vec(), ino("abc"))]
        );

        fs::remove_dir_all(root).unwrap();
    }

    // A RELEASE racing a setattr must not close the handle's fd before the
    // fd syscalls run: a file opened in between would reuse the number and
    // the truncate would land on it instead.
    // A guest chmod reaches the host file's permission bits, as on Linux, so a
    // script the guest makes executable runs on the host; the guest still
    // reads the full mode it set.
    #[test]
    fn a_guest_chmod_sets_the_host_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "libkrun-setattr-mode-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("s.sh"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(root.join("s.sh"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::create_dir(root.join("d")).unwrap();

        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&filesystem, FsOptions::empty()).unwrap();
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        for (name, mode) in [("s.sh", 0o4755u32), ("d", 0o700)] {
            let c = CString::new(name).unwrap();
            let entry = FileSystem::lookup(&filesystem, context, fuse::ROOT_ID, &c).unwrap();
            let mut attr: bindings::stat64 = unsafe { std::mem::zeroed() };
            attr.st_mode = mode as u16;
            let (st, _) = FileSystem::setattr(
                &filesystem,
                context,
                entry.inode,
                attr,
                None,
                SetattrValid::MODE,
            )
            .unwrap();
            assert_eq!(
                u32::from(st.st_mode) & 0o7777,
                mode,
                "{name}: the guest reads its mode"
            );
            let host = fs::metadata(root.join(name)).unwrap().permissions().mode();
            // The permission bits reach the host; setuid stays in the xattr.
            assert_eq!(host & 0o7777, mode & 0o777, "{name}: host mode");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_file_with_no_recorded_owner_is_served_as_the_shares_owner() {
        let root = std::env::temp_dir().join(format!("krun-default-owner-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        // written by the host: it records no owner of its own
        fs::write(root.join("settings.json"), b"{}").unwrap();
        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                default_owner: Some((1000, 1001)),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&filesystem, FsOptions::ZERO_MESSAGE_OPEN).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let name = CString::new("settings.json").unwrap();
        let entry = FileSystem::lookup(&filesystem, ctx, fuse::ROOT_ID, &name).unwrap();
        assert_eq!((entry.attr.st_uid, entry.attr.st_gid), (1000, 1001));
        // The guest's chown of the uid alone records it; the gid stays the share's.
        let mut attr = entry.attr;
        attr.st_uid = 2000;
        let (st, _) =
            FileSystem::setattr(&filesystem, ctx, entry.inode, attr, None, SetattrValid::UID)
                .unwrap();
        assert_eq!((st.st_uid, st.st_gid), (2000, 1001));
        // The host replacing the file drops what was recorded: the share's owner again.
        fs::remove_file(root.join("settings.json")).unwrap();
        fs::write(root.join("settings.json"), b"{\"v\": 2}").unwrap();
        FileSystem::forget(&filesystem, ctx, entry.inode, 1);
        let entry = FileSystem::lookup(&filesystem, ctx, fuse::ROOT_ID, &name).unwrap();
        assert_eq!((entry.attr.st_uid, entry.attr.st_gid), (1000, 1001));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recorded_chmod_keeps_host_access_to_overlay_workdirs() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("krun-recorded-mode-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                override_stat: true,
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&filesystem, FsOptions::ZERO_MESSAGE_OPEN).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let denied = Context {
            uid: 65534,
            gid: 65534,
            pid: 0,
        };
        let work = FileSystem::mkdir(
            &filesystem,
            ctx,
            fuse::ROOT_ID,
            &CString::new("work").unwrap(),
            0o700,
            0,
            Extensions::default(),
        )
        .unwrap();
        let mut attr = work.attr;
        attr.st_mode = 0;
        let (st, _) =
            FileSystem::setattr(&filesystem, ctx, work.inode, attr, None, SetattrValid::MODE)
                .unwrap();
        assert_eq!(st.st_mode as u32 & 0o777, 0);
        assert_eq!(
            fs::metadata(root.join("work"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(FileSystem::access(&filesystem, denied, work.inode, libc::R_OK as u32).is_err());
        // Overlayfs creates and inspects entries inside its mode-000 workdir
        // as guest root. The host server must retain traversal/write access.
        let (child, _, _) = FileSystem::create(
            &filesystem,
            ctx,
            work.inode,
            &CString::new("child").unwrap(),
            0o600,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
        let mut child_attr = child.attr;
        child_attr.st_mode = 0;
        FileSystem::setattr(
            &filesystem,
            ctx,
            child.inode,
            child_attr,
            None,
            SetattrValid::MODE,
        )
        .unwrap();
        FileSystem::write(
            &filesystem,
            ctx,
            child.inode,
            0,
            Source(b"payload".to_vec()),
            7,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
        assert_eq!(fs::read(root.join("work/child")).unwrap(), b"payload");
        let (st, _) = FileSystem::getattr(&filesystem, ctx, child.inode, None).unwrap();
        assert_eq!(st.st_mode as u32 & 0o777, 0);
        assert_eq!(st.st_uid, 0);
        assert!(FileSystem::access(&filesystem, denied, child.inode, libc::R_OK as u32).is_err());
        FileSystem::unlink(
            &filesystem,
            ctx,
            work.inode,
            &CString::new("child").unwrap(),
        )
        .unwrap();
        FileSystem::rmdir(
            &filesystem,
            ctx,
            fuse::ROOT_ID,
            &CString::new("work").unwrap(),
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn readonly_metadata_updates_preserve_host_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("krun-readonly-metadata-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("file"), b"payload").unwrap();
        fs::create_dir(root.join("dir")).unwrap();
        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&filesystem, FsOptions::empty()).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        for (name, readonly) in [("file", 0o444), ("dir", 0o555)] {
            let entry = FileSystem::lookup(
                &filesystem,
                ctx,
                fuse::ROOT_ID,
                &CString::new(name).unwrap(),
            )
            .unwrap();
            let mut attr: bindings::stat64 = unsafe { std::mem::zeroed() };
            attr.st_mode = readonly;
            FileSystem::setattr(
                &filesystem,
                ctx,
                entry.inode,
                attr,
                None,
                SetattrValid::MODE,
            )
            .unwrap();
            attr.st_uid = 1234;
            attr.st_gid = 5678;
            let (st, _) = FileSystem::setattr(
                &filesystem,
                ctx,
                entry.inode,
                attr,
                None,
                SetattrValid::UID | SetattrValid::GID,
            )
            .unwrap();
            assert_eq!((st.st_uid, st.st_gid), (1234, 5678));
            assert_eq!(st.st_mode & 0o777, readonly);
            assert_eq!(
                fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777,
                u32::from(readonly)
            );
            attr.st_mode = 0o755;
            FileSystem::setattr(
                &filesystem,
                ctx,
                entry.inode,
                attr,
                None,
                SetattrValid::MODE,
            )
            .unwrap();
            assert_eq!(
                fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn chown_clears_readonly_capabilities_without_touching_symlink_targets() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root =
            std::env::temp_dir().join(format!("krun-readonly-capability-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("file");
        fs::write(&path, b"data").unwrap();
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        let cap = b"capability";
        assert_eq!(
            unsafe {
                libc::setxattr(
                    c.as_ptr(),
                    SECURITY_CAPABILITY.as_ptr().cast(),
                    cap.as_ptr().cast(),
                    cap.len(),
                    0,
                    0,
                )
            },
            0
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        symlink(&path, root.join("link")).unwrap();
        let link =
            InodeHandle::Path(CString::new(root.join("link").as_os_str().as_bytes()).unwrap());
        remove_security_capability(&link);
        assert_eq!(
            unsafe {
                libc::getxattr(
                    c.as_ptr(),
                    SECURITY_CAPABILITY.as_ptr().cast(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                )
            },
            cap.len() as isize
        );
        remove_security_capability(&InodeHandle::Path(c.clone()));
        assert_eq!(
            unsafe {
                libc::getxattr(
                    c.as_ptr(),
                    SECURITY_CAPABILITY.as_ptr().cast(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                )
            },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOATTR)
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o444
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_metadata_write_restores_mode_and_never_follows_links() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = std::env::temp_dir().join(format!("krun-metadata-error-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        fs::write(&target, b"untouched").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();
        let inode = InodeHandle::Path(CString::new(target.as_os_str().as_bytes()).unwrap());
        let mut calls = 0;
        let err = metadata_write(&inode, || {
            calls += 1;
            Err(io::Error::from_raw_os_error(if calls == 1 {
                libc::EACCES
            } else {
                libc::EIO
            }))
        })
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        assert_eq!(calls, 2);
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o444
        );
        symlink(&target, root.join("link")).unwrap();
        let link =
            InodeHandle::Path(CString::new(root.join("link").as_os_str().as_bytes()).unwrap());
        metadata_write(&link, || Err(io::Error::from_raw_os_error(libc::EACCES))).unwrap_err();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o444
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn setattr_keeps_its_handle_open_across_a_concurrent_release() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "libkrun-setattr-release-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a"), b"aaaa").unwrap();
        fs::write(root.join("b"), b"bbbb").unwrap();

        let filesystem = PassthroughFs::new(
            Config {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            },
            Arc::new(InodeAllocator::new()),
        )
        .unwrap();
        FileSystem::init(&filesystem, FsOptions::empty()).unwrap();
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let a = CString::new("a").unwrap();
        let entry = FileSystem::lookup(&filesystem, context, fuse::ROOT_ID, &a).unwrap();
        let (handle, _) = FileSystem::open(
            &filesystem,
            context,
            entry.inode,
            false,
            libc::O_RDWR as u32,
        )
        .unwrap();
        let handle = handle.unwrap();
        let a_fd = filesystem.handles.read().unwrap()[&handle]
            .file
            .read()
            .unwrap()
            .as_raw_fd();

        let (opened, reopened) = std::sync::mpsc::channel();
        let b_path = root.join("b");
        let inode = entry.inode;
        SETATTR_FD_HOOK.set(Some(Box::new(move |filesystem: &PassthroughFs| {
            FileSystem::release(filesystem, context, inode, 0, handle, false, false, None).unwrap();
            let b = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(b_path)
                .unwrap();
            opened.send(b).unwrap();
        })));

        let mut attr: bindings::stat64 = unsafe { std::mem::zeroed() };
        attr.st_size = 0;
        let result = FileSystem::setattr(
            &filesystem,
            context,
            entry.inode,
            attr,
            Some(handle),
            SetattrValid::SIZE,
        );
        let b = reopened.recv().unwrap();
        eprintln!(
            "released fd {a_fd}, then b opened as fd {}{}",
            b.as_raw_fd(),
            if b.as_raw_fd() == a_fd {
                " (number reused)"
            } else {
                ""
            }
        );
        result.unwrap();
        assert_eq!(
            fs::read(root.join("b")).unwrap(),
            b"bbbb",
            "b was truncated"
        );
        assert_eq!(
            fs::read(root.join("a")).unwrap(),
            b"",
            "a was not truncated"
        );

        drop(b);
        fs::remove_dir_all(root).unwrap();
    }

    // overlayfs keeps a lower file's handle across reboots. A new server must
    // not give an earlier session's nodeid to a file, so such a handle finds
    // nothing; a restored server must keep the snapshotted nodeids, including
    // the small ones of a snapshot taken by an engine that numbered from 2.
    #[test]
    fn nodeids_differ_per_session_and_survive_restore() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "libkrun-nodeid-base-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"data").unwrap();
        fs::write(root.join("other"), b"other").unwrap();
        let server = || {
            let fs = PassthroughFs::new(
                Config {
                    root_dir: root.to_string_lossy().into_owned(),
                    ..Default::default()
                },
                Arc::new(InodeAllocator::new()),
            )
            .unwrap();
            FileSystem::init(&fs, FsOptions::empty()).unwrap();
            fs
        };
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let lookup = |fs: &PassthroughFs, name: &str| {
            let name = CString::new(name).unwrap();
            FileSystem::lookup(fs, context, fuse::ROOT_ID, &name).unwrap()
        };

        let first = server();
        let before = lookup(&first, "file");
        assert_eq!(before.generation, 0);

        let next_boot = server();
        let other = lookup(&next_boot, "other");
        assert_ne!(other.inode, before.inode);
        assert!(FileSystem::getattr(&next_boot, context, before.inode, None).is_err());

        let restored = server();
        restored.restore(&first.snapshot()).unwrap();
        assert_eq!(lookup(&restored, "file").inode, before.inode);
        assert!(FileSystem::getattr(&restored, context, before.inode, None).is_ok());

        let old: FuseServerState = serde_json::from_value(serde_json::json!({
            "inodes": [{
                "nodeid": 2,
                "relative_path": "file",
                "path": root.join("file").to_string_lossy(),
                "refcount": 1
            }],
            "handles": [],
            "next_inode": 3,
            "next_handle": 0,
            "writeback": false,
            "announce_submounts": false
        }))
        .unwrap();
        let from_old = server();
        from_old.restore(&old).unwrap();
        assert_eq!(lookup(&from_old, "file").inode, 2);
        assert_eq!(lookup(&from_old, "other").inode, 3);

        fs::remove_dir_all(root).unwrap();
    }
}
