use std::collections::HashMap;
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};

use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, FIONBIO, INVALID_SOCKET, IPPROTO_IPV6, IPV6_V6ONLY, SD_RECEIVE, SD_SEND, SOCK_STREAM,
    SOCKADDR, SOCKET, SOCKET_ERROR, WSAEINTR, WSAESHUTDOWN, WSAEWOULDBLOCK, WSAGetLastError,
    accept, bind, closesocket, connect, getpeername, getsockname, ioctlsocket, listen, recv, send,
    setsockopt, shutdown, socket,
};

use crate::virtio::vsock::windows::sockaddr_storage::{
    SockaddrStorage, storage_to_winsock, winsock_to_storage,
};

use super::super::super::linux_errno::wsa_errno_to_linux;
use super::super::defs;
use super::super::defs::uapi;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiAcceptReq, TsiConnectReq, TsiGetnameRsp, TsiListenReq, VsockPacket};
use super::super::proxy::{
    AddressFamily, AsRawFd, NewProxyType, OwnedFd, Proxy, ProxyError, ProxyStatus, ProxyUpdate,
    RecvPkt, address_family_from_linux,
};
use super::super::tsi_wire::EIO;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

fn create_stream_socket(win_family: i32) -> Result<SOCKET, i32> {
    let sock = unsafe { socket(win_family, SOCK_STREAM, 0) };
    if sock == INVALID_SOCKET {
        return Err(unsafe { WSAGetLastError() });
    }
    let mut mode: u32 = 1;
    if unsafe { ioctlsocket(sock, FIONBIO, &mut mode) } == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        unsafe {
            closesocket(sock);
        }
        return Err(e);
    }
    // Linux guests expect dual-stack IPv6 sockets (bindv6only=0), but Winsock
    // defaults to v6-only.
    if win_family == AF_INET6 as i32
        && unsafe {
            setsockopt(
                sock,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (&0u32 as *const u32).cast(),
                size_of::<u32>() as i32,
            )
        } == SOCKET_ERROR
    {
        let e = unsafe { WSAGetLastError() };
        unsafe {
            closesocket(sock);
        }
        return Err(e);
    }
    Ok(sock)
}

pub(crate) fn create_socket(
    _id: u64,
    linux_family: u16,
) -> Result<(OwnedFd, AddressFamily), ProxyError> {
    let af = address_family_from_linux(linux_family).ok_or(ProxyError::InvalidFamily)?;
    let win_family = af as i32;
    let sock = create_stream_socket(win_family)
        .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e)))?;

    Ok((
        unsafe { OwnedSocket::from_raw_socket(sock as RawSocket) },
        af,
    ))
}

fn sock(proxy: &super::TsiStreamProxy) -> SOCKET {
    proxy.fd.as_raw_socket() as SOCKET
}

pub(crate) fn try_write(fd: &OwnedSocket, buf: &[u8]) -> io::Result<usize> {
    let sock = fd.as_raw_socket() as SOCKET;
    let mut written = 0;
    // A short successful send alone does not arrange another FD_WRITE wakeup.
    while written < buf.len() {
        let remaining = &buf[written..];
        let res = unsafe { send(sock, remaining.as_ptr() as _, remaining.len() as i32, 0) };
        if res == SOCKET_ERROR {
            let error = unsafe { WSAGetLastError() };
            if written > 0 && error == WSAEWOULDBLOCK {
                break;
            }
            return Err(io::Error::from_raw_os_error(error));
        }
        if res == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        written += res as usize;
    }
    Ok(written)
}

pub(crate) fn is_retryable_write_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(WSAEWOULDBLOCK)
}

pub(super) fn shutdown_write(fd: &OwnedSocket) {
    let res = unsafe { shutdown(fd.as_raw_socket() as SOCKET, SD_SEND) };
    if res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        debug!("error sending shutdown(SD_SEND) to socket: {e}");
    }
}

pub(super) fn shutdown_read(fd: &OwnedSocket) {
    let res = unsafe { shutdown(fd.as_raw_socket() as SOCKET, SD_RECEIVE) };
    if res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        debug!("error sending shutdown(SD_RECEIVE) to socket: {e}");
    }
}

pub(crate) fn recv_to_pkt(
    proxy: &super::TsiStreamProxy,
    pkt: &mut VsockPacket,
) -> io::Result<RecvPkt> {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);

        if max_len == 0 {
            return Ok(RecvPkt::WaitForCredit);
        }

        let res = unsafe { recv(sock(proxy), buf.as_mut_ptr() as _, max_len as i32, 0) };

        if res > 0 {
            Ok(RecvPkt::Read(res as usize))
        } else if res == 0 {
            Ok(RecvPkt::Close)
        } else {
            let err = unsafe { WSAGetLastError() };
            if err == WSAEWOULDBLOCK || err == WSAEINTR {
                Ok(RecvPkt::Error)
            } else if err == WSAESHUTDOWN
                && proxy.peer_shutdown & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0
            {
                Ok(RecvPkt::Close)
            } else {
                Err(io::Error::from_raw_os_error(err))
            }
        }
    } else {
        Ok(RecvPkt::BadBuffer)
    }
}

fn listen_error(family: u16, strict: bool, error: i32) -> i32 {
    use super::super::defs::{LINUX_AF_INET, LINUX_AF_INET6};
    use super::super::tsi_wire::{EACCES, EPERM};
    use windows_sys::Win32::Networking::WinSock::WSAEACCES;

    // Best-effort publication can leave a guest-local listener when the
    // host denies publication. EPERM is the existing TSI fallback result.
    if error == WSAEACCES && matches!(family, LINUX_AF_INET | LINUX_AF_INET6) {
        if strict { -EACCES } else { -EPERM }
    } else {
        -wsa_errno_to_linux(error)
    }
}

#[cfg(test)]
mod publication_tests {
    use super::{listen_error, wsa_errno_to_linux};
    use crate::virtio::vsock::defs::{LINUX_AF_INET, LINUX_AF_INET6, LINUX_AF_UNIX};
    use crate::virtio::vsock::tsi_wire::{EACCES, EADDRINUSE, EPERM};
    use windows_sys::Win32::Networking::WinSock::{WSAEACCES, WSAEADDRINUSE};

    #[test]
    fn access_denied_is_a_fallback_result_only_for_best_effort_inet() {
        for family in [LINUX_AF_INET, LINUX_AF_INET6] {
            assert_eq!(listen_error(family, false, WSAEACCES), -EPERM);
            assert_eq!(listen_error(family, true, WSAEACCES), -EACCES);
            assert_eq!(listen_error(family, false, WSAEADDRINUSE), -EADDRINUSE);
        }
        assert_eq!(
            listen_error(LINUX_AF_UNIX, false, WSAEACCES),
            -wsa_errno_to_linux(WSAEACCES)
        );
    }
}

fn try_listen(
    proxy: &mut super::TsiStreamProxy,
    req: &TsiListenReq,
    host_port_map: &Option<HashMap<u16, u16>>,
) -> i32 {
    if proxy.status == ProxyStatus::Listening || proxy.status == ProxyStatus::WaitingOnAccept {
        return 0;
    }

    let effective_addr: SockaddrStorage = if let Some(port_map) = host_port_map {
        if let Some(v4) = req.addr.to_std_v4() {
            if let Some(&mapped_port) = port_map.get(&v4.port()) {
                SocketAddrV4::new(*v4.ip(), mapped_port).into()
            } else {
                req.addr.clone()
            }
        } else if let Some(v6) = req.addr.to_std_v6() {
            // Port overrides apply to IPv6 listeners too; without this a
            // guest dual-stack listener publishes its IPv6 socket on the
            // unmapped host port.
            if let Some(&mapped_port) = port_map.get(&v6.port()) {
                SocketAddrV6::new(*v6.ip(), mapped_port, v6.flowinfo(), v6.scope_id()).into()
            } else {
                req.addr.clone()
            }
        } else {
            req.addr.clone()
        }
    } else {
        req.addr.clone()
    };

    let unixsock_path = if effective_addr.family() == defs::LINUX_AF_UNIX {
        effective_addr.unix_path().map(std::path::PathBuf::from)
    } else {
        None
    };

    if let Some(path) = &unixsock_path
        && let Err(e) = std::fs::remove_file(path)
    {
        debug!("error removing previous socket path: {e}");
    }

    let (sa_bytes, sa_len) = match storage_to_winsock(&effective_addr) {
        Some(v) => v,
        None => {
            return -22; // LINUX_EINVAL
        }
    };

    let bind_res = unsafe { bind(sock(proxy), sa_bytes.as_ptr() as *const SOCKADDR, sa_len) };
    if bind_res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        warn!(
            "bind failed: id={} addr={:?} err={e}",
            proxy.id, effective_addr
        );
        return listen_error(req.addr.family(), req.strict, e);
    }

    proxy.unixsock_path = unixsock_path;

    // Fixed: Constrain the network queue size utilizing the configuration parameters sent by the guest
    let clamped_backlog = req.backlog.clamp(0, 0x7fff_ffff);
    let listen_res = unsafe { listen(sock(proxy), clamped_backlog) };
    if listen_res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        warn!("listen failed: id={} err={e}", proxy.id);
        return listen_error(req.addr.family(), req.strict, e);
    }

    0
}

pub(crate) fn do_connect(
    proxy: &mut super::TsiStreamProxy,
    _pkt: &VsockPacket,
    req: TsiConnectReq,
    epoll: &Epoll,
) -> ProxyUpdate {
    let (sa_bytes, sa_len) = match storage_to_winsock(&req.addr) {
        Some(v) => v,
        None => {
            proxy.push_connect_rsp(-22); // EINVAL
            return ProxyUpdate::default();
        }
    };

    // Register first so a fast completion cannot race the FD_CONNECT watch.
    let event = EpollEvent::new(EventSet::CONNECT | EventSet::EDGE_TRIGGERED, proxy.id);
    if let Err(error) = epoll.ctl_socket(ControlOperation::Add, sock(proxy), &event) {
        warn!(
            "could not watch connect completion: id={} err={error}",
            proxy.id
        );
        proxy.push_connect_rsp(-EIO);
        return ProxyUpdate::default();
    }

    let res = unsafe { connect(sock(proxy), sa_bytes.as_ptr() as *const SOCKADDR, sa_len) };

    let result = if res == 0 {
        proxy.status = ProxyStatus::AwaitingRequest;
        0
    } else {
        let e = unsafe { WSAGetLastError() };
        if e == WSAEWOULDBLOCK {
            proxy.status = ProxyStatus::Connecting;
            return ProxyUpdate::default();
        }
        debug!("connect error: id={} err={e}", proxy.id);
        -wsa_errno_to_linux(e)
    };

    proxy.push_connect_rsp(result);
    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty())),
        ..Default::default()
    }
}

pub(super) fn finish_connect(proxy: &mut super::TsiStreamProxy, error: i32) -> ProxyUpdate {
    debug!("FD_CONNECT completed: id={} err={error}", proxy.id);
    let result = if error == 0 {
        proxy.status = ProxyStatus::AwaitingRequest;
        0
    } else {
        proxy.status = ProxyStatus::Closed;
        -wsa_errno_to_linux(error)
    };
    proxy.push_connect_rsp(result);
    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty())),
        signal_queue: true,
        ..Default::default()
    }
}

pub(crate) fn do_getname(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket, peer: bool) {
    let mut sa_buf = [0u8; 128];
    let mut sa_len: i32 = 128;

    let res = unsafe {
        if peer {
            getpeername(sock(proxy), sa_buf.as_mut_ptr().cast(), &mut sa_len)
        } else {
            getsockname(sock(proxy), sa_buf.as_mut_ptr().cast(), &mut sa_len)
        }
    };

    let (result, addr_len, addr) = if res == 0 {
        match winsock_to_storage(&sa_buf, sa_len) {
            Some(storage) => {
                let len = storage.len();
                (0i32, len, storage)
            }
            None => (
                -22i32,
                0,
                SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
            ),
        }
    } else {
        let e = unsafe { WSAGetLastError() };
        (
            -wsa_errno_to_linux(e),
            0,
            SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
        )
    };

    let data = TsiGetnameRsp {
        result,
        addr_len,
        addr,
    };
    let rx = MuxerRx::GetnameResponse {
        request_id: pkt.control_request_id(),
        operation: pkt.control_operation(),
        peer_port: pkt.src_port(),
        data,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn do_listen(
    proxy: &mut super::TsiStreamProxy,
    pkt: &VsockPacket,
    req: TsiListenReq,
    host_port_map: &Option<HashMap<u16, u16>>,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let result = try_listen(proxy, &req, host_port_map);

    let rx = MuxerRx::ListenResponse {
        request_id: pkt.control_request_id(),
        operation: pkt.control_operation(),
        peer_port: pkt.src_port(),
        result,
        flags: req.response_flags(),
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    if result == 0 {
        proxy.peer_port = req.vm_port;
        proxy.status = ProxyStatus::Listening;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
    }

    update
}

pub(crate) fn do_accept(proxy: &mut super::TsiStreamProxy, req: TsiAcceptReq) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if proxy.pending_accepts > 0 {
        proxy.pending_accepts -= 1;
        proxy.push_accept_rsp(0);
        update.signal_queue = true;
    } else {
        proxy.status = ProxyStatus::WaitingOnAccept;
    }

    update
}

pub(crate) fn process_event(proxy: &mut super::TsiStreamProxy, evset: EventSet) -> ProxyUpdate {
    if !matches!(
        proxy.status,
        ProxyStatus::Listening | ProxyStatus::WaitingOnAccept
    ) {
        return ProxyUpdate::default();
    }
    if evset.contains(EventSet::HANG_UP) {
        return proxy.reset_after_error();
    }
    if !evset.contains(EventSet::IN) {
        return ProxyUpdate::default();
    }

    let socket = unsafe { accept(sock(proxy), std::ptr::null_mut(), std::ptr::null_mut()) };
    if socket == INVALID_SOCKET {
        let e = unsafe { WSAGetLastError() };
        if e != WSAEWOULDBLOCK {
            warn!("accept error: id={} err={e}", proxy.id);
        }
        return ProxyUpdate::default();
    }
    let fd = unsafe { OwnedSocket::from_raw_socket(socket as RawSocket) };
    let mut mode = 1;
    if unsafe { ioctlsocket(socket, FIONBIO, &mut mode) } == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        warn!("error setting up accepted socket: id={}, err={e}", proxy.id);
        return ProxyUpdate::default();
    }

    ProxyUpdate {
        new_proxy: Some((proxy.peer_port, fd, proxy.family, NewProxyType::Tcp)),
        ..Default::default()
    }
}
