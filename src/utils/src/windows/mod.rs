use std::os::windows::io::{AsRawSocket, OwnedSocket};

use windows_sys::Win32::Foundation::HANDLE;

pub(crate) mod bindings;
pub mod epoll;
pub mod eventfd;

/// Cross-platform alias used by the rest of the codebase.  On Windows this
/// is just [`HANDLE`] — the two names are interchangeable.
pub type RawFd = HANDLE;

/// Windows equivalent of [`std::os::unix::io::AsRawFd`].
pub trait AsRawFd {
    fn as_raw_fd(&self) -> RawFd;
}

impl AsRawFd for OwnedSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw_socket() as RawFd
    }
}

/// A thin wrapper around a raw `HANDLE` that implements [`Send`].
///
/// Raw pointers do not implement `Send`, but Windows kernel handles are safe
/// to use from any thread.  This wrapper lets closures capture a handle value
/// without needing an `unsafe impl Send` on the closure itself.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct SendHandle(HANDLE);

// SAFETY: Windows kernel object handles are process-wide and thread-safe.
unsafe impl Send for SendHandle {}

impl SendHandle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn as_raw_handle(self) -> HANDLE {
        self.0
    }
}
