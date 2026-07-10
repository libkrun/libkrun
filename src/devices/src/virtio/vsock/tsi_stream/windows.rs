use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::Wrapping;
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};

use utils::windows::RawFd;
use windows_sys::Win32::Networking::WinSock::{
    FIONBIO, INVALID_SOCKET, SD_BOTH, SD_RECEIVE, SD_SEND, SOCK_STREAM, SOCKADDR, SOCKET,
    SOCKET_ERROR, WSAEWOULDBLOCK, WSAGetLastError, accept, bind, closesocket, connect, getpeername,
    ioctlsocket, listen, recv, send, shutdown, socket,
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
    AddressFamily, AsRawFd, NewProxyType, OwnedFd, Proxy, ProxyError, ProxyRemoval, ProxyStatus,
    ProxyUpdate, RecvPkt, address_family_from_linux,
};
use utils::epoll::EventSet;

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

pub(crate) fn recv_to_pkt(proxy: &super::TsiStreamProxy, pkt: &mut VsockPacket) -> RecvPkt {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);

        if max_len == 0 {
            return RecvPkt::WaitForCredit;
        }

        let res = unsafe { recv(sock(proxy), buf.as_mut_ptr() as _, max_len as i32, 0) };

        if res > 0 {
            RecvPkt::Read(res as usize)
        } else if res == 0 {
            RecvPkt::Close
        } else {
            let err = unsafe { WSAGetLastError() };
            if err == WSAEWOULDBLOCK {
                RecvPkt::Error
            } else {
                debug!("recv_to_pkt error: {err}");
                RecvPkt::Error
            }
        }
    } else {
        RecvPkt::Error
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

    if let Some(path) = &unixsock_path {
        if let Err(e) = std::fs::remove_file(path) {
            debug!("error removing previous socket path: {e}");
        }
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
        warn!("bind failed: id={} err={e}", proxy.id);
        return -wsa_errno_to_linux(e);
    }

    proxy.unixsock_path = unixsock_path;

    // Fixed: Constrain the network queue size utilizing the configuration parameters sent by the guest
    let clamped_backlog = req.backlog.clamp(0, 0x7fff_ffff);
    let listen_res = unsafe { listen(sock(proxy), clamped_backlog as i32) };
    if listen_res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        warn!("listen failed: id={} err={e}", proxy.id);
        return -wsa_errno_to_linux(e);
    }

    0
}

pub(crate) fn do_connect(
    proxy: &mut super::TsiStreamProxy,
    _pkt: &VsockPacket,
    req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let (sa_bytes, sa_len) = match storage_to_winsock(&req.addr) {
        Some(v) => v,
        None => {
            proxy.push_connect_rsp(-22); // EINVAL
            return update;
        }
    };

    let res = unsafe { connect(sock(proxy), sa_bytes.as_ptr() as *const SOCKADDR, sa_len) };

    let result = if res == 0 {
        proxy.status = ProxyStatus::Connected;
        0
    } else {
        let e = unsafe { WSAGetLastError() };
        if e == WSAEWOULDBLOCK {
            proxy.status = ProxyStatus::Connecting;
            0
        } else {
            debug!("connect error: id={} err={e}", proxy.id);
            -wsa_errno_to_linux(e)
        }
    };

    if proxy.status == ProxyStatus::Connecting {
        update.polling = Some((
            proxy.id,
            proxy.fd.as_raw_fd(),
            EventSet::OUT | EventSet::EDGE_TRIGGERED,
        ));
    } else if proxy.status == ProxyStatus::Connected {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        proxy.push_connect_rsp(result);
    } else {
        proxy.push_connect_rsp(result);
    }

    update
}

pub(crate) fn do_getpeername(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket) {
    let mut sa_buf = [0u8; 128];
    let mut sa_len: i32 = 128;

    let res = unsafe {
        getpeername(
            sock(proxy),
            sa_buf.as_mut_ptr() as *mut SOCKADDR,
            &mut sa_len,
        )
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
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        data,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn sendmsg(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let ret = if let Some(buf) = pkt.buf() {
        let res = unsafe { send(sock(proxy), buf.as_ptr() as _, buf.len() as i32, 0) };

        if res >= 0 {
            proxy.tx_cnt += Wrapping(res as u32);
            res
        } else {
            let e = unsafe { WSAGetLastError() };
            if e != WSAEWOULDBLOCK {
                debug!("send error: id={} err={e}", proxy.id);
            }
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

pub(crate) fn update_peer_credit(
    proxy: &mut super::TsiStreamProxy,
    pkt: &VsockPacket,
) -> ProxyUpdate {
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

pub(crate) fn do_listen(
    proxy: &mut super::TsiStreamProxy,
    pkt: &VsockPacket,
    req: TsiListenReq,
    host_port_map: &Option<HashMap<u16, u16>>,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let result = try_listen(proxy, &req, host_port_map);

    let rx = MuxerRx::ListenResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        result,
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

    const O_NONBLOCK: u32 = 2048;
    if proxy.pending_accepts > 0 {
        proxy.pending_accepts -= 1;
        proxy.push_accept_rsp(0);
        update.signal_queue = true;
    } else if (req.flags & O_NONBLOCK) != 0 {
        proxy.push_accept_rsp(-11); // LINUX_EAGAIN
        update.signal_queue = true;
    } else {
        proxy.status = ProxyStatus::WaitingOnAccept;
    }

    update
}

pub(crate) fn process_op_response(
    proxy: &mut super::TsiStreamProxy,
    pkt: &VsockPacket,
) -> ProxyUpdate {
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        push_accept: Some((proxy.id, proxy.parent_id)),
        ..Default::default()
    }
}

pub(crate) fn do_shutdown(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket) {
    let recv_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
    let send_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;

    let how = if recv_off && send_off {
        SD_BOTH
    } else if recv_off {
        SD_RECEIVE
    } else {
        SD_SEND
    };

    unsafe {
        shutdown(sock(proxy), how);
    }
}

pub(crate) fn process_event(proxy: &mut super::TsiStreamProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        if proxy.status == ProxyStatus::Connecting {
            proxy.push_connect_rsp(-111); // ECONNREFUSED
        } else {
            proxy.push_reset();
        }
        proxy.status = ProxyStatus::Closed;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = if proxy.status == ProxyStatus::Listening {
            ProxyRemoval::Immediate
        } else {
            ProxyRemoval::Deferred
        };
        return update;
    }

    if evset.contains(EventSet::IN) {
        if proxy.status == ProxyStatus::Connected {
            let (signal_queue, wait_credit) = proxy.recv_pkt();
            update.signal_queue = signal_queue || wait_credit;

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
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
                return update;
            } else if proxy.status == ProxyStatus::WaitingCreditUpdate {
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
            }
        } else if proxy.status == ProxyStatus::Listening
            || proxy.status == ProxyStatus::WaitingOnAccept
        {
            let new_sock =
                unsafe { accept(sock(proxy), std::ptr::null_mut(), std::ptr::null_mut()) };
            if new_sock != INVALID_SOCKET {
                let mut mode: u32 = 1;
                unsafe {
                    ioctlsocket(new_sock, FIONBIO, &mut mode);
                }
                let new_fd = unsafe { OwnedSocket::from_raw_socket(new_sock as RawSocket) };
                update.new_proxy = Some((proxy.peer_port, new_fd, proxy.family, NewProxyType::Tcp));
            } else {
                let e = unsafe { WSAGetLastError() };
                warn!("accept error: id={} err={e}", proxy.id);
            }
            update.signal_queue = true;
            return update;
        }
    }

    if evset.contains(EventSet::OUT) {
        if proxy.status == ProxyStatus::Connecting {
            proxy.status = ProxyStatus::Connected;
            proxy.push_connect_rsp(0);
            update.signal_queue = true;
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        }
    }

    update
}
