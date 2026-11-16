// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-platform AF_UNIX helpers for the virtio-net userspace-proxy backends.
//!
//! Windows 10 1809+ has native AF_UNIX, which `socket2` exposes via
//! `Domain::UNIX` / `SockAddr::unix`. The backends use nonblocking sockets and
//! these helpers so the same code path serves Unix and Windows; the `tap`
//! backend stays Linux-only (it needs a TUN/TAP driver). See
//! WINDOWS_NETWORKING_PORT.md.

use std::io;
use std::mem::MaybeUninit;
use std::path::Path;

use socket2::{Domain, SockAddr, Socket, Type};

/// Raw handle the net worker registers with the epoll layer. Unix file
/// descriptor; on Windows the Winsock SOCKET cast to the epoll shim's HANDLE.
#[cfg(unix)]
pub type NetRawHandle = std::os::fd::RawFd;
#[cfg(windows)]
pub type NetRawHandle = utils::windows::RawFd;

/// [`NetRawHandle`] for a socket, cross-platform.
#[cfg(unix)]
pub fn raw_handle(sock: &Socket) -> NetRawHandle {
    use std::os::fd::AsRawFd;
    sock.as_raw_fd()
}
#[cfg(windows)]
pub fn raw_handle(sock: &Socket) -> NetRawHandle {
    use std::os::windows::io::AsRawSocket;
    sock.as_raw_socket() as NetRawHandle
}

/// Nonblocking receive into an initialized byte slice. Returns `WouldBlock` when
/// no data is available (the backends treat that as "nothing read").
pub fn recv(sock: &Socket, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `[u8]` and `[MaybeUninit<u8>]` share layout; the kernel only writes
    // into the slice and the returned length bounds what the caller reads.
    let uninit = unsafe {
        std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, buf.len())
    };
    sock.recv(uninit)
}

/// Send, suppressing SIGPIPE on Linux (other platforms have no SIGPIPE).
pub fn send(sock: &Socket, buf: &[u8]) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        sock.send_with_flags(buf, libc::MSG_NOSIGNAL)
    }
    #[cfg(not(target_os = "linux"))]
    {
        sock.send(buf)
    }
}

/// Create a nonblocking AF_UNIX stream socket connected to the proxy at `path`.
pub fn connect_unix_stream(path: &Path) -> io::Result<Socket> {
    let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    let address = utils::SocketPath::new(path)?;
    sock.connect(&SockAddr::unix(address.path())?)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Create a nonblocking AF_UNIX datagram socket bound to `local` and connected
/// to the proxy at `peer`. Unix-only: Windows AF_UNIX is stream-only.
#[cfg(unix)]
pub fn connect_unix_dgram(local: &Path, peer: &Path) -> io::Result<(Socket, utils::SocketPath)> {
    let sock = Socket::new(Domain::UNIX, Type::DGRAM, None)?;
    let _ = std::fs::remove_file(local);
    let local_address = utils::SocketPath::new(local)?;
    let peer_address = utils::SocketPath::new(peer)?;
    sock.bind(&SockAddr::unix(local_address.path())?)?;
    sock.connect(&SockAddr::unix(peer_address.path())?)?;
    sock.set_nonblocking(true)?;
    Ok((sock, local_address))
}
