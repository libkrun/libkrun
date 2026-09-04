//! Windows FFI bindings used by the epoll and eventfd implementations.
//!
//! Documented Win32 APIs come from the [`windows_sys`] crate.  The
//! undocumented NT native APIs (`NtCreateWaitCompletionPacket`, etc.) are
//! declared manually since they are not included in any official bindings
//! crate.

use std::io;

use windows_sys::Win32::Foundation::HANDLE;

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub type NTSTATUS = i32;

#[link(name = "ntdll")]
unsafe extern "system" {
    pub unsafe fn NtCreateWaitCompletionPacket(
        WaitCompletionPacketHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *const std::ffi::c_void,
    ) -> NTSTATUS;

    pub unsafe fn NtAssociateWaitCompletionPacket(
        WaitCompletionPacketHandle: HANDLE,
        IoCompletionHandle: HANDLE,
        TargetObjectHandle: HANDLE,
        KeyContext: *mut std::ffi::c_void,
        ApcContext: *mut std::ffi::c_void,
        IoStatus: NTSTATUS,
        IoStatusInformation: usize,
        AlreadySignaled: *mut u8,
    ) -> NTSTATUS;

    pub unsafe fn NtCancelWaitCompletionPacket(
        WaitCompletionPacketHandle: HANDLE,
        RemoveSignaledPacket: u8,
    ) -> NTSTATUS;

    pub unsafe fn RtlNtStatusToDosError(Status: NTSTATUS) -> u32;
}

/// Equivalent of the `NT_SUCCESS` macro: returns `true` when `status` is in
/// the success (0x0000_0000–0x3FFF_FFFF) or informational
/// (0x4000_0000–0x7FFF_FFFF) range.
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
#[inline]
pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Convert a failing `NTSTATUS` to an [`io::Error`] via the corresponding
/// Win32 error code.
/// A mapping of NTSTATUS values to Win32 error codes can be found at
/// https://www.osr.com/blog/2020/04/23/ntstatus-to-win32-error-code-mappings/
pub fn nt_status_err(status: NTSTATUS) -> io::Error {
    let win_err = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(win_err as i32)
}
