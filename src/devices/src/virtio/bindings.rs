#![allow(clippy::missing_safety_doc)]
use libc;

pub const LINUX_EACCES: libc::c_int = 13;
pub const LINUX_ENODATA: libc::c_int = 61;
pub const LINUX_ENOSYS: libc::c_int = 38;
pub const LINUX_ENOTEMPTY: libc::c_int = 39;

pub const LINUX_O_APPEND: libc::c_int = 1024;
pub const LINUX_O_CLOEXEC: libc::c_int = 0x80000;
pub const LINUX_O_DIRECT: libc::c_int = 0x4000;
pub const LINUX_O_DIRECTORY: libc::c_int = 0x10000;
pub const LINUX_O_LARGEFILE: libc::c_int = 0;
pub const LINUX_O_NOFOLLOW: libc::c_int = 0x20000;
pub const LINUX_O_CREAT: libc::c_int = 64;
pub const LINUX_O_EXCL: libc::c_int = 128;
pub const LINUX_O_NOCTTY: libc::c_int = 256;
pub const LINUX_O_NONBLOCK: libc::c_int = 2048;
pub const LINUX_O_SYNC: libc::c_int = 1052672;
pub const LINUX_O_TRUNC: libc::c_int = 512;
pub const LINUX_O_RSYNC: libc::c_int = 1052672;
pub const LINUX_O_DSYNC: libc::c_int = 4096;
pub const LINUX_O_ASYNC: libc::c_int = 0x2000;

pub const LINUX_RENAME_NOREPLACE: libc::c_int = 1 << 0;
pub const LINUX_RENAME_EXCHANGE: libc::c_int = 1 << 1;
pub const LINUX_RENAME_WHITEOUT: libc::c_int = 1 << 2;

pub const LINUX_XATTR_CREATE: libc::c_int = 1;
pub const LINUX_XATTR_REPLACE: libc::c_int = 2;

pub const LINUX_FALLOC_FL_ALLOCATE_RANGE: libc::c_int = 0;
pub const LINUX_FALLOC_FL_KEEP_SIZE: libc::c_int = 1;
pub const LINUX_FALLOC_FL_PUNCH_HOLE: libc::c_int = 2;

#[cfg(target_os = "macos")]
pub type stat64 = libc::stat;
#[cfg(target_os = "linux")]
pub use libc::stat64;
#[cfg(target_os = "windows")]
// We create a custom stat64 type for Windows because the Windows C-Runtime still use 16-bit for the inode field.
#[repr(C)]
pub struct stat64 {
    pub st_ino: u64,
    pub st_size: i64,
    pub st_atime: i64,
    pub st_mtime: i64,
    pub st_ctime: i64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u32,
    pub st_dev: u32,
    pub st_atime_nsec: u32,
    pub st_mtime_nsec: u32,
    pub st_ctime_nsec: u32,
    pub st_blksize: i64,
    pub st_blocks: i64,
}

#[cfg(target_os = "macos")]
pub type off64_t = libc::off_t;
#[cfg(target_os = "linux")]
pub use libc::off64_t;

#[cfg(target_os = "macos")]
pub type statvfs64 = libc::statvfs;
#[cfg(target_os = "linux")]
pub use libc::statvfs64;

#[cfg(target_os = "macos")]
pub type ino64_t = libc::ino_t;
#[cfg(target_os = "linux")]
pub use libc::ino64_t;

#[cfg(target_os = "linux")]
pub unsafe fn pread64(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    count: libc::size_t,
    offset: off64_t,
) -> libc::ssize_t {
    unsafe { libc::pread64(fd, buf, count, offset) }
}
#[cfg(target_os = "macos")]
pub unsafe fn pread64(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    count: libc::size_t,
    offset: off64_t,
) -> libc::ssize_t {
    unsafe { libc::pread(fd, buf, count, offset) }
}

#[cfg(target_os = "linux")]
pub unsafe fn preadv64(
    fd: libc::c_int,
    iov: *const libc::iovec,
    iovcnt: libc::c_int,
    offset: off64_t,
) -> libc::ssize_t {
    unsafe { libc::preadv64(fd, iov, iovcnt, offset) }
}
#[cfg(target_os = "macos")]
pub unsafe fn preadv64(
    fd: libc::c_int,
    iov: *const libc::iovec,
    iovcnt: libc::c_int,
    offset: off64_t,
) -> libc::ssize_t {
    unsafe { libc::preadv(fd, iov, iovcnt, offset) }
}

#[cfg(target_os = "linux")]
pub unsafe fn pwrite64(
    fd: libc::c_int,
    buf: *const libc::c_void,
    count: libc::size_t,
    offset: off64_t,
) -> libc::ssize_t {
    unsafe { libc::pwrite64(fd, buf, count, offset) }
}
#[cfg(target_os = "macos")]
pub unsafe fn pwrite64(
    fd: libc::c_int,
    buf: *const libc::c_void,
    count: libc::size_t,
    offset: off64_t,
) -> libc::ssize_t {
    unsafe { libc::pwrite(fd, buf, count, offset) }
}

#[cfg(target_os = "linux")]
pub unsafe fn pwritev64(
    fd: libc::c_int,
    iov: *const libc::iovec,
    iovcnt: libc::c_int,
    offset: off64_t,
) -> libc::ssize_t {
    unsafe { libc::pwritev64(fd, iov, iovcnt, offset) }
}
#[cfg(target_os = "macos")]
pub unsafe fn pwritev64(
    fd: libc::c_int,
    iov: *const libc::iovec,
    iovcnt: libc::c_int,
    offset: off64_t,
) -> libc::ssize_t {
    unsafe { libc::pwritev(fd, iov, iovcnt, offset) }
}

#[cfg(target_os = "linux")]
pub unsafe fn fstatat64(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    buf: *mut stat64,
    flags: libc::c_int,
) -> libc::c_int {
    unsafe { libc::fstatat64(dirfd, pathname, buf, flags) }
}
#[cfg(target_os = "macos")]
pub unsafe fn fstatat64(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    buf: *mut stat64,
    flags: libc::c_int,
) -> libc::c_int {
    unsafe { libc::fstatat(dirfd, pathname, buf, flags) }
}

#[cfg(target_os = "linux")]
pub unsafe fn fallocate64(
    fd: libc::c_int,
    mode: libc::c_int,
    offset: off64_t,
    len: off64_t,
) -> libc::c_int {
    unsafe { libc::fallocate64(fd, mode, offset, len) }
}
#[cfg(target_os = "macos")]
pub unsafe fn fallocate64(
    _fd: libc::c_int,
    _mode: libc::c_int,
    _offset: off64_t,
    _len: off64_t,
) -> libc::c_int {
    -LINUX_ENOSYS
}

#[cfg(target_os = "linux")]
pub unsafe fn ftruncate64(fd: libc::c_int, length: off64_t) -> libc::c_int {
    unsafe { libc::ftruncate64(fd, length) }
}
#[cfg(target_os = "macos")]
pub unsafe fn ftruncate64(fd: libc::c_int, length: off64_t) -> libc::c_int {
    unsafe { libc::ftruncate(fd, length) }
}

#[cfg(target_os = "linux")]
pub unsafe fn lseek64(fd: libc::c_int, offset: off64_t, whence: libc::c_int) -> off64_t {
    unsafe { libc::lseek64(fd, offset, whence) }
}
#[cfg(target_os = "macos")]
pub unsafe fn lseek64(fd: libc::c_int, offset: off64_t, whence: libc::c_int) -> off64_t {
    unsafe { libc::lseek(fd, offset, whence) }
}

#[cfg(target_os = "macos")]
pub unsafe fn statvfs64(path: *const libc::c_char, buf: *mut statvfs64) -> libc::c_int {
    unsafe { libc::statvfs(path, buf) }
}

#[cfg(target_os = "linux")]
pub unsafe fn fstatvfs64(fd: libc::c_int, buf: *mut statvfs64) -> libc::c_int {
    unsafe { libc::fstatvfs64(fd, buf) }
}
#[cfg(target_os = "macos")]
pub unsafe fn fstatvfs64(fd: libc::c_int, buf: *mut statvfs64) -> libc::c_int {
    unsafe { libc::fstatvfs(fd, buf) }
}

#[cfg(target_os = "linux")]
pub unsafe fn mknodat(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    mode: libc::mode_t,
    dev: libc::dev_t,
) -> libc::c_int {
    unsafe { libc::mknodat(dirfd, pathname, mode, dev) }
}
#[cfg(target_os = "macos")]
pub unsafe fn mknodat(
    _dirfd: libc::c_int,
    _pathname: *const libc::c_char,
    _mode: libc::mode_t,
    _dev: u64,
) -> libc::c_int {
    -LINUX_ENOSYS
}
