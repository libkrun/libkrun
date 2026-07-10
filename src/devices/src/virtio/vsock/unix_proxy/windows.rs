use std::num::Wrapping;
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};
use std::path::PathBuf;
use windows_sys::Win32::Networking::WinSock::{
    AF_UNIX, FIONBIO, INVALID_SOCKET, SD_BOTH, SD_RECEIVE, SD_SEND, SOCK_STREAM, SOCKADDR,
    SOCKADDR_UN, SOCKET, SOCKET_ERROR, WSAECONNREFUSED, WSAEWOULDBLOCK, WSAGetLastError, accept,
    bind, connect, ioctlsocket, listen, recv, send, shutdown, socket,
};

use super::super::super::linux_errno::wsa_errno_to_linux;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiConnectReq, VsockPacket};
use super::super::proxy::{
    NewProxyType, OwnedFd, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RawFd, RecvPkt,
};
use utils::epoll::EventSet;

pub(crate) fn create_socket(_id: u64) -> Result<OwnedFd, ProxyError> {
    let sock = unsafe { socket(AF_UNIX as i32, SOCK_STREAM, 0) };
    if sock == INVALID_SOCKET {
        return Err(ProxyError::CreatingSocket(
            std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }),
        ));
    }
    let owned_sock = unsafe { OwnedSocket::from_raw_socket(sock as RawSocket) };

    let mut mode: u32 = 1;
    if unsafe { ioctlsocket(sock, FIONBIO, &mut mode) } == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        warn!("error switching to non-blocking: err={e}");
    }
    Ok(owned_sock)
}

fn unix_sockaddr(path: &str) -> (SOCKADDR_UN, i32) {
    let mut sa: SOCKADDR_UN = unsafe { std::mem::zeroed() };
    sa.sun_family = AF_UNIX;
    let pb = path.as_bytes();
    // Reserve the very last byte for the null terminator '\0'
    let max_len = sa.sun_path.len() - 1;

    if pb.len() > max_len {
        warn!("AF_UNIX path too long, truncating: {}", path);
    }

    for (slot, &byte) in sa.sun_path.iter_mut().take(max_len).zip(pb) {
        *slot = byte as i8;
    }
    (sa, std::mem::size_of::<SOCKADDR_UN>() as i32)
}

pub(crate) fn switch_to_connected(proxy: &mut super::UnixProxy) {
    proxy.status = ProxyStatus::Connected;
    // Windows lacks `MSG_DONTWAIT`, so the socket must remain non-blocking
    // to prevent freezing the event loop thread during `recv_pkt` iterations.
}

fn push_connect_rsp(proxy: &super::UnixProxy, result: i32) {
    let rx = MuxerRx::ConnResponse {
        local_port: 1025,
        peer_port: proxy.control_port,
        result,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn recv_to_pkt(proxy: &super::UnixProxy, pkt: &mut VsockPacket) -> RecvPkt {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);
        if max_len == 0 {
            return RecvPkt::WaitForCredit;
        }

        let res = unsafe {
            recv(
                proxy.fd.as_raw_socket() as SOCKET,
                buf.as_mut_ptr() as _,
                max_len as i32,
                0,
            )
        };

        if res > 0 {
            RecvPkt::Read(res as usize)
        } else if res == 0 {
            RecvPkt::Close
        } else {
            let e = unsafe { WSAGetLastError() };
            if e == WSAEWOULDBLOCK {
                // Map WSAEWOULDBLOCK to an expected exit for the mod.rs loop without tearing down the proxy.
                RecvPkt::Error
            } else {
                warn!("unix proxy recv error: id={}, err={}", proxy.id, e);
                RecvPkt::Error
            }
        }
    } else {
        RecvPkt::Error
    }
}

pub(crate) fn do_connect(
    proxy: &mut super::UnixProxy,
    _pkt: &VsockPacket,
    _req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let path_str = match proxy.path.to_str() {
        Some(s) => s,
        None => {
            warn!("unix proxy: invalid path");
            return update;
        }
    };

    let (sa, sa_len) = unix_sockaddr(&path_str);
    let res = unsafe {
        connect(
            proxy.fd.as_raw_socket() as SOCKET,
            &sa as *const _ as *const SOCKADDR,
            sa_len,
        )
    };

    if res == 0 {
        switch_to_connected(proxy);
        update.polling = Some((proxy.id, proxy.fd.as_raw_socket() as RawFd, EventSet::IN));
        push_connect_rsp(proxy, 0);
    } else {
        let e = unsafe { WSAGetLastError() };
        if e == WSAEWOULDBLOCK {
            proxy.status = ProxyStatus::Connecting;
            // Watch both IN and OUT events on Windows for async connection tracking
            update.polling = Some((
                proxy.id,
                proxy.fd.as_raw_socket() as RawFd,
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED,
            ));
        } else {
            warn!("unix proxy connect error: id={} err={e}", proxy.id);
            push_connect_rsp(proxy, -wsa_errno_to_linux(e));
        }
    }

    update
}

pub(crate) fn confirm_connect(
    proxy: &mut super::UnixProxy,
    pkt: &VsockPacket,
) -> Option<ProxyUpdate> {
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
    proxy.local_port = pkt.dst_port();
    proxy.peer_port = pkt.src_port();

    let rx = MuxerRx::OpResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    Some(ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_socket() as RawFd, EventSet::IN)),
        ..Default::default()
    })
}

pub(crate) fn sendmsg(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let ret = if let Some(buf) = pkt.buf() {
        let res = unsafe {
            send(
                proxy.fd.as_raw_socket() as SOCKET,
                buf.as_ptr() as _,
                buf.len() as i32,
                0,
            )
        };
        if res >= 0 {
            proxy.tx_cnt += Wrapping(res as u32);
            res
        } else {
            let e = unsafe { WSAGetLastError() };
            -wsa_errno_to_linux(e)
        }
    } else {
        -22 // LINUX_EINVAL
    };

    if ret > 0 && (proxy.tx_cnt - proxy.last_tx_cnt_sent).0 >= proxy.peer_buf_alloc / 2 {
        proxy.last_tx_cnt_sent = proxy.tx_cnt;
        let rx = MuxerRx::CreditUpdate {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            fwd_cnt: proxy.tx_cnt.0,
        };
        push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
        update.signal_queue = true;
    }

    update
}

pub(crate) fn update_peer_credit(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
    let mut update = ProxyUpdate::default();

    // If we were deadlocked waiting for credit, and credit is now restored:
    if proxy.status == ProxyStatus::WaitingCreditUpdate && proxy.peer_avail_credit() > 0 {
        proxy.status = ProxyStatus::Connected;

        // Proactively pull data to bypass the missed Windows edge-trigger
        let (signal_queue, wait_credit) = proxy.recv_pkt();
        update.signal_queue = signal_queue;

        if wait_credit {
            // We immediately ran out of credit again. Suspend again and ask for more.
            proxy.status = ProxyStatus::WaitingCreditUpdate;
            let rx = MuxerRx::CreditRequest {
                local_port: proxy.local_port,
                peer_port: proxy.peer_port,
                fwd_cnt: proxy.tx_cnt.0,
            };
            update.push_credit_req = Some(rx);
            update.polling = Some((
                proxy.id,
                proxy.fd.as_raw_socket() as RawFd,
                EventSet::empty(),
            ));
        } else {
            // Successfully drained, safe to listen for the next edge
            update.polling = Some((proxy.id, proxy.fd.as_raw_socket() as RawFd, EventSet::IN));
        }
    } else {
        // Normal update (wasn't suspended)
        proxy.status = ProxyStatus::Connected;
        update.polling = Some((proxy.id, proxy.fd.as_raw_socket() as RawFd, EventSet::IN));
    }

    update
}

pub(crate) fn push_op_request(proxy: &super::UnixProxy) {
    let rx = MuxerRx::OpRequest {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn process_op_response(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_socket() as RawFd, EventSet::IN)),
        ..Default::default()
    }
}

pub(crate) fn do_shutdown(proxy: &mut super::UnixProxy, pkt: &VsockPacket) {
    let recv_off = pkt.flags() & super::uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
    let send_off = pkt.flags() & super::uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;

    let how = if recv_off && send_off {
        SD_BOTH
    } else if recv_off {
        SD_RECEIVE
    } else {
        SD_SEND
    };

    let _ret = unsafe { shutdown(proxy.fd.as_raw_socket() as SOCKET, how) };
}

pub(crate) fn release(proxy: &mut super::UnixProxy) -> ProxyUpdate {
    let remove_proxy = if proxy.status == ProxyStatus::Listening {
        ProxyRemoval::Immediate
    } else {
        ProxyRemoval::Deferred
    };
    ProxyUpdate {
        remove_proxy,
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::UnixProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        if proxy.status == ProxyStatus::Connecting {
            push_connect_rsp(proxy, -wsa_errno_to_linux(WSAECONNREFUSED));
        } else {
            proxy.push_reset();
        }
        proxy.status = ProxyStatus::Closed;
        update.polling = Some((
            proxy.id,
            proxy.fd.as_raw_socket() as RawFd,
            EventSet::empty(),
        ));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
        return update;
    }

    if evset.contains(EventSet::IN) {
        if proxy.status == ProxyStatus::Connected {
            let (signal_queue, wait_credit) = proxy.recv_pkt();
            update.signal_queue = signal_queue;

            if wait_credit && proxy.status != ProxyStatus::WaitingCreditUpdate {
                proxy.status = ProxyStatus::WaitingCreditUpdate;
                let rx = MuxerRx::CreditRequest {
                    local_port: proxy.local_port,
                    peer_port: proxy.peer_port,
                    fwd_cnt: proxy.tx_cnt.0,
                };
                update.push_credit_req = Some(rx);
            }

            if proxy.status == ProxyStatus::Closed {
                proxy.push_reset();
                update.signal_queue = true;
                update.polling = Some((
                    proxy.id,
                    proxy.fd.as_raw_socket() as RawFd,
                    EventSet::empty(),
                ));
                return update;
            } else if proxy.status == ProxyStatus::WaitingCreditUpdate {
                update.polling = Some((
                    proxy.id,
                    proxy.fd.as_raw_socket() as RawFd,
                    EventSet::empty(),
                ));
            }
        } else if proxy.status == ProxyStatus::Listening
            || proxy.status == ProxyStatus::WaitingOnAccept
        {
            let new_sock = unsafe {
                accept(
                    proxy.fd.as_raw_socket() as SOCKET,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if new_sock != INVALID_SOCKET {
                let mut mode: u32 = 1;
                unsafe {
                    ioctlsocket(new_sock, FIONBIO, &mut mode);
                }
                let new_fd = unsafe { OwnedSocket::from_raw_socket(new_sock as RawSocket) };
                update.new_proxy = Some((proxy.peer_port, new_fd, AF_UNIX, NewProxyType::Unix));
            } else {
                let e = unsafe { WSAGetLastError() };
                warn!("unix accept error: id={} err={e}", proxy.id);
            }
            update.signal_queue = true;
            return update;
        }
    }

    if evset.contains(EventSet::OUT) {
        if proxy.status == ProxyStatus::Connecting {
            switch_to_connected(proxy);
            push_connect_rsp(proxy, 0);
            update.signal_queue = true;
            update.polling = Some((proxy.id, proxy.fd.as_raw_socket() as RawFd, EventSet::IN));
        }
    }

    update
}

pub(crate) fn as_raw_fd(proxy: &super::UnixProxy) -> RawFd {
    proxy.fd.as_raw_socket() as RawFd
}

pub(crate) fn new_acceptor_proxy(
    id: u64,
    path: &PathBuf,
    peer_port: u32,
) -> Result<super::UnixAcceptorProxy, ProxyError> {
    let sock = unsafe { socket(AF_UNIX as i32, SOCK_STREAM, 0) };
    if sock == INVALID_SOCKET {
        return Err(ProxyError::CreatingSocket(
            std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }),
        ));
    }

    let owned_sock = unsafe { OwnedSocket::from_raw_socket(sock as RawSocket) };
    let raw_sock = owned_sock.as_raw_socket() as SOCKET;

    let path_str = match path.to_str() {
        Some(s) => s,
        None => {
            warn!("unix acceptor proxy: invalid path");
            return Err(ProxyError::CreatingSocket(
                std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }),
            ));
        }
    };

    let (sa, sa_len) = unix_sockaddr(&path_str);

    if unsafe { bind(raw_sock, &sa as *const _ as *const SOCKADDR, sa_len) } == SOCKET_ERROR {
        return Err(ProxyError::CreatingSocket(
            std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }),
        ));
    }

    if unsafe { listen(raw_sock, 5) } == SOCKET_ERROR {
        return Err(ProxyError::CreatingSocket(
            std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }),
        ));
    }

    Ok(super::UnixAcceptorProxy {
        id,
        fd: owned_sock,
        peer_port,
    })
}

pub(crate) fn process_acceptor_event(
    proxy: &mut super::UnixAcceptorProxy,
    evset: EventSet,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();
    if evset.contains(EventSet::HANG_UP) {
        update.polling = Some((
            proxy.id,
            proxy.fd.as_raw_socket() as RawFd,
            EventSet::empty(),
        ));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
        return update;
    }
    if evset.contains(EventSet::IN) {
        let new_sock = unsafe {
            accept(
                proxy.fd.as_raw_socket() as SOCKET,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if new_sock != INVALID_SOCKET {
            let mut mode: u32 = 1;
            if unsafe { ioctlsocket(new_sock, FIONBIO, &mut mode) } == SOCKET_ERROR {
                let e = unsafe { WSAGetLastError() };
                warn!("acceptor error switching to non-blocking: err={e}");
            }
            let new_sock = unsafe { OwnedSocket::from_raw_socket(new_sock as RawSocket) };
            update.new_proxy = Some((proxy.peer_port, new_sock, AF_UNIX, NewProxyType::Unix));
        }
        update.signal_queue = true;
    }
    update
}

pub(crate) fn as_raw_acceptor_fd(proxy: &super::UnixAcceptorProxy) -> RawFd {
    proxy.fd.as_raw_socket() as RawFd
}
