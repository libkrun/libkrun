// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Small cross-platform host-socket helpers for the vsock/TSI proxies.
//!
//! The proxies use `socket2::Socket` directly for most operations; these helpers
//! cover the few spots where the raw API is awkward or platform-divergent:
//!  * `recv_into` adapts `socket2`'s `MaybeUninit` recv to a `&mut [u8]` buffer,
//!  * `connect_in_progress` classifies the nonblocking-connect "in progress"
//!    error, which is `EINPROGRESS` on Unix but `WSAEWOULDBLOCK` on Windows,
//!  * `domain_of` picks the `socket2` domain for an address.
//!
//! See WINDOWS_NETWORKING_PORT.md.

use std::io;
use std::mem::MaybeUninit;

use socket2::Socket;

/// Listen backlog clamp, matching the platform's `SOMAXCONN`.
#[cfg(unix)]
pub const SOMAXCONN: i32 = libc::SOMAXCONN;
#[cfg(windows)]
pub const SOMAXCONN: i32 = 0x7fff_ffff;

/// Receive into an initialized byte slice, returning the number of bytes read.
///
/// `socket2::Socket::recv` takes `&mut [MaybeUninit<u8>]`; viewing an already
/// initialized `&mut [u8]` as uninitialized memory is sound (we never read the
/// "uninit" view, only write through it), and the returned count bounds what the
/// caller reads back.
///
/// On Unix the recv is forced non-blocking with `MSG_DONTWAIT`. The host-IPC
/// `UnixProxy` keeps its connected socket in *blocking* mode (so partial-write
/// `send`s drain fully), but its recv is driven by edge-readiness from the
/// muxer's epoll loop and must never block that single thread on a spurious or
/// already-drained `IN` wakeup — which a blocking `recv()` would do, hanging the
/// whole muxer. This restores the pre-socket2 `nix` behavior, which always
/// passed `MSG_DONTWAIT` regardless of the socket's blocking mode. Windows has
/// no `MSG_DONTWAIT`; there the socket's own non-blocking state governs recv,
/// matching the established (verified) Windows path.
pub fn recv_into(sock: &Socket, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `[u8]` and `[MaybeUninit<u8>]` have identical layout; we only hand
    // the slice to the kernel to write into and use the returned length.
    let uninit = unsafe {
        std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, buf.len())
    };
    #[cfg(unix)]
    {
        sock.recv_with_flags(uninit, libc::MSG_DONTWAIT)
    }
    #[cfg(windows)]
    {
        sock.recv(uninit)
    }
}

/// True if a nonblocking `connect` error means "connection in progress" rather
/// than a hard failure (`EINPROGRESS` on Unix, `WSAEWOULDBLOCK` on Windows).
pub fn connect_in_progress(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::EINPROGRESS)
    }
    #[cfg(windows)]
    {
        // WSAEWOULDBLOCK
        e.raw_os_error() == Some(10035) || e.kind() == io::ErrorKind::WouldBlock
    }
}

/// Translate a host socket error into the **Linux** errno the guest expects.
/// Identity on Linux; via the existing BSD→Linux table on macOS; via a Winsock
/// (`WSAE*`) → Linux mapping on Windows.
pub fn to_linux_errno(e: &io::Error) -> i32 {
    let raw = e.raw_os_error().unwrap_or(libc::EIO);
    #[cfg(target_os = "linux")]
    {
        raw
    }
    #[cfg(target_os = "macos")]
    {
        super::super::linux_errno::linux_errno_raw(raw)
    }
    #[cfg(target_os = "windows")]
    {
        wsa_to_linux_errno(raw)
    }
}

/// Map the common Winsock error codes to their Linux errno equivalents so the
/// guest kernel sees the errors it expects. Unknown codes fall back to EIO.
#[cfg(target_os = "windows")]
fn wsa_to_linux_errno(wsa: i32) -> i32 {
    // Linux errno values (stable on the guest ABI).
    const E_ACCES: i32 = 13;
    const E_INVAL: i32 = 22;
    const E_AGAIN: i32 = 11;
    const E_INPROGRESS: i32 = 115;
    const E_ADDRINUSE: i32 = 98;
    const E_ADDRNOTAVAIL: i32 = 99;
    const E_NETUNREACH: i32 = 101;
    const E_CONNABORTED: i32 = 103;
    const E_CONNRESET: i32 = 104;
    const E_NOTCONN: i32 = 107;
    const E_TIMEDOUT: i32 = 110;
    const E_CONNREFUSED: i32 = 111;
    const E_HOSTUNREACH: i32 = 113;
    const E_IO: i32 = 5;
    match wsa {
        10013 => E_ACCES,               // WSAEACCES
        10022 => E_INVAL,               // WSAEINVAL
        10035 => E_AGAIN,               // WSAEWOULDBLOCK
        10036 => E_INPROGRESS,          // WSAEINPROGRESS
        10037 => E_AGAIN,               // WSAEALREADY
        10048 => E_ADDRINUSE,           // WSAEADDRINUSE
        10049 => E_ADDRNOTAVAIL,        // WSAEADDRNOTAVAIL
        10050 | 10051 => E_NETUNREACH,  // WSAENETDOWN / WSAENETUNREACH
        10053 => E_CONNABORTED,         // WSAECONNABORTED
        10054 => E_CONNRESET,           // WSAECONNRESET
        10057 => E_NOTCONN,             // WSAENOTCONN
        10060 => E_TIMEDOUT,            // WSAETIMEDOUT
        10061 => E_CONNREFUSED,         // WSAECONNREFUSED
        10064 | 10065 => E_HOSTUNREACH, // WSAEHOSTDOWN / WSAEHOSTUNREACH
        _ => E_IO,
    }
}
