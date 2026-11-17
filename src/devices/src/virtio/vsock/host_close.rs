// SPDX-License-Identifier: Apache-2.0

//! Close policy and nonblocking completion queries for the host TCP transport.
use super::proxy::raw_handle;
use socket2::Socket;
use std::io;

pub const ABORT: u32 = 1;
pub const WAIT: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseRequest {
    pub peer_port: u32,
    pub local_port: u32,
    /// Total payload accepted by the guest transport, modulo 2^32. Control
    /// packets may overtake data; FIN must not overtake this watermark.
    pub tx_count: u32,
    pub flags: u32,
}

impl CloseRequest {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 16 {
            return None;
        }
        let flags = u32::from_le_bytes(data[12..16].try_into().ok()?);
        if flags != 0 && flags != ABORT && flags != WAIT {
            return None;
        }
        Some(Self {
            peer_port: u32::from_le_bytes(data[..4].try_into().ok()?),
            local_port: u32::from_le_bytes(data[4..8].try_into().ok()?),
            tx_count: u32::from_le_bytes(data[8..12].try_into().ok()?),
            flags,
        })
    }
}

/// Query only after SHUT_WR has queued FIN. An empty user-space queue does
/// not prove delivery: the native TCP stack may still be retransmitting.
/// CLOSED also completes a close after the peer has reset the transport.
pub fn complete(socket: &Socket) -> io::Result<bool> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        #[cfg(target_os = "linux")]
        let (mut info, option) = (
            unsafe { std::mem::zeroed::<libc::tcp_info>() },
            libc::TCP_INFO,
        );
        #[cfg(target_os = "macos")]
        let (mut info, option) = (
            unsafe { std::mem::zeroed::<libc::tcp_connection_info>() },
            libc::TCP_CONNECTION_INFO,
        );
        let mut length = size_of_val(&info) as libc::socklen_t;
        // SAFETY: socket owns its fd; info and length are writable and sized
        // for the platform's TCP information option. Both structs are POD.
        let result = unsafe {
            libc::getsockopt(
                raw_handle(socket),
                libc::IPPROTO_TCP,
                option,
                std::ptr::from_mut(&mut info).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if length < 1 {
            return Err(io::Error::other("TCP information omitted state"));
        }
        #[cfg(target_os = "linux")]
        // Linux TCP_FIN_WAIT2, TCP_TIME_WAIT, TCP_CLOSE.
        return Ok(matches!(info.tcpi_state, 5..=7));
        #[cfg(target_os = "macos")]
        // XNU bsd/netinet/tcp_fsm.h: TCPS_CLOSED, FIN_WAIT_2, TIME_WAIT.
        return Ok(matches!(info.tcpi_state, 0 | 9 | 10));
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock as ws;
        let mut info = ws::TCP_INFO_v0::default();
        let version = 0u32;
        let mut length = 0;
        // SAFETY: synchronous query on an owned socket, with live version,
        // output, and byte-count buffers; no overlapped callback is supplied.
        let result = unsafe {
            ws::WSAIoctl(
                raw_handle(socket) as _,
                ws::SIO_TCP_INFO,
                std::ptr::from_ref(&version).cast(),
                size_of::<u32>() as _,
                std::ptr::from_mut(&mut info).cast(),
                size_of_val(&info) as _,
                &mut length,
                std::ptr::null_mut(),
                None,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(unsafe {
                ws::WSAGetLastError()
            }));
        }
        if length < size_of::<ws::TCPSTATE>() as u32 {
            return Err(io::Error::other("TCP information omitted state"));
        }
        return Ok(matches!(
            info.State,
            ws::TCPSTATE_CLOSED | ws::TCPSTATE_FIN_WAIT_2 | ws::TCPSTATE_TIME_WAIT
        ));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = socket;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host TCP completion query",
        ))
    }
}
