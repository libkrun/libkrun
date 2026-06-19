use std::io;

use super::super::super::linux_errno::linux_errno_raw;

// Linux/POSIX constants not provided by the Windows libc crate. These are
// guest-facing values used by the virtiofs FUSE protocol and must match
// the Linux ABI regardless of the host platform.
pub const O_ACCMODE: i32 = 0o3;
pub const W_OK: i32 = 2;
pub const SEEK_DATA: i32 = 3;
pub const SEEK_HOLE: i32 = 4;
pub const ST_RDONLY: u64 = 1;

pub fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(linux_errno_raw(libc::EBADF))
}

pub fn einval() -> io::Error {
    io::Error::from_raw_os_error(linux_errno_raw(libc::EINVAL))
}

pub fn enosys() -> io::Error {
    io::Error::from_raw_os_error(linux_errno_raw(libc::ENOSYS))
}

pub fn win_err_to_linux(e: io::Error) -> io::Error {
    println!("win_err_to_linux: {:?}", e.raw_os_error());
    // Try to map highly specific Windows raw error codes first
    let linux_errno = if let Some(code) = e.raw_os_error() {
        match code as u32 {
            1 | 1314 => libc::EPERM, // ERROR_INVALID_FUNCTION / ERROR_PRIVILEGE_NOT_HELD
            6 | 21 => libc::ENXIO,   // ERROR_INVALID_HANDLE / ERROR_NOT_READY
            1117 => libc::EIO,       // ERROR_IO_DEVICE

            2 | 3 | 15 | 267 => libc::ENOENT, // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND / ERROR_INVALID_DRIVE / ERROR_DIRECTORY
            5 => libc::EACCES,                // ERROR_ACCESS_DENIED
            80 | 183 => libc::EEXIST,         // ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
            111 | 206 => libc::ENAMETOOLONG,  // ERROR_BUFFER_OVERFLOW / ERROR_FILENAME_EXCED_RANGE
            17 => libc::EXDEV,                // ERROR_NOT_SAME_DEVICE (Cross-device link)
            223 => libc::EFBIG,               // ERROR_FILE_TOO_LARGE
            145 => libc::ENOTEMPTY,           // ERROR_DIR_NOT_EMPTY context

            39 | 112 => libc::ENOSPC, // ERROR_HANDLE_DISK_FULL / ERROR_DISK_FULL
            25 | 132 => libc::ESPIPE, // ERROR_SEEK / ERROR_SEEK_ON_DEVICE (Illegal seek)

            29 | 30 => libc::EIO, // ERROR_WRITE_FAULT / ERROR_READ_FAULT

            31 => libc::ENXIO, // ERROR_GEN_FAILURE

            8 | 14 => libc::ENOMEM, // ERROR_NOT_ENOUGH_MEMORY / ERROR_OUTOFMEMORY
            487 => libc::EFAULT,    // ERROR_INVALID_ADDRESS (Bad pointer)

            12 | 13 | 24 | 87 | 123 | 160 => libc::EINVAL,
            // ERROR_INVALID_ACCESS / ERROR_INVALID_DATA / ERROR_BAD_LENGTH / ERROR_INVALID_PARAMETER / ERROR_INVALID_NAME / ERROR_BAD_ARGUMENTS
            4 => libc::EMFILE,        // ERROR_TOO_MANY_OPEN_FILES
            32 | 170 => libc::EBUSY,  // ERROR_SHARING_VIOLATION / ERROR_BUSY
            109 | 232 => libc::EPIPE, // ERROR_BROKEN_PIPE / ERROR_NO_DATA
            120 => libc::ENOSYS,      // ERROR_CALL_NOT_IMPLEMENTED

            _ => map_kind_to_linux(e.kind()),
        }
    } else {
        map_kind_to_linux(e.kind())
    };

    io::Error::from_raw_os_error(linux_errno_raw(linux_errno))
}

/// Helper function to cleanly map Rust's platform-agnostic ErrorKind to Linux errnos
fn map_kind_to_linux(kind: io::ErrorKind) -> i32 {
    match kind {
        io::ErrorKind::NotFound => libc::ENOENT,
        io::ErrorKind::PermissionDenied => libc::EACCES,
        io::ErrorKind::AlreadyExists => libc::EEXIST,
        io::ErrorKind::InvalidInput => libc::EINVAL,
        io::ErrorKind::DirectoryNotEmpty => libc::ENOTEMPTY,
        io::ErrorKind::OutOfMemory => libc::ENOMEM,
        io::ErrorKind::WriteZero => libc::ENOSPC,
        io::ErrorKind::Unsupported => libc::ENOSYS,
        io::ErrorKind::InvalidData => libc::EILSEQ,
        io::ErrorKind::Interrupted => libc::EINTR,
        // Default fallback
        _ => libc::EIO,
    }
}
