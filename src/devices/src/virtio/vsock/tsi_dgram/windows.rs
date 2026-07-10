use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::Wrapping;
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, FIONBIO, INVALID_SOCKET, SOCK_DGRAM, SOCKADDR, SOCKET, SOCKET_ERROR,
    WSAEWOULDBLOCK, WSAGetLastError, bind, closesocket, connect, getpeername, ioctlsocket, recv,
    send, sendto, socket,
};

use super::super::super::Queue as VirtQueue;
use super::super::super::linux_errno::wsa_errno_to_linux;
use super::super::defs;
use super::super::defs::uapi;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::muxer_rxq::MuxerRxQ;
use super::super::packet::{TsiConnectReq, TsiGetnameRsp, TsiSendtoAddr, VsockPacket};
use super::super::proxy::{
    AsRawFd, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt, address_family_from_linux,
};
use super::super::windows::sockaddr_storage::{
    SockaddrStorage, storage_to_winsock, winsock_to_storage,
};
use utils::epoll::EventSet;
use vm_memory::GuestMemoryMmap;

pub type SendtoAddr = SockaddrStorage;

fn create_dgram_socket(win_family: i32) -> Result<SOCKET, i32> {
    let sock = unsafe { socket(win_family, SOCK_DGRAM, 0) };
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

fn sock(proxy: &super::TsiDgramProxy) -> SOCKET {
    proxy.fd.as_raw_socket() as SOCKET
}

pub(crate) fn create(
    id: u64,
    cid: u64,
    family: u16,
    peer_port: u32,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
) -> Result<super::TsiDgramProxy, ProxyError> {
    let af = address_family_from_linux(family).ok_or(ProxyError::InvalidFamily)?;
    let win_family = af as i32;
    let sock = create_dgram_socket(win_family)
        .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e)))?;

    Ok(super::TsiDgramProxy {
        id,
        cid,
        local_port: defs::TSI_PROXY_PORT,
        peer_port,
        fd: unsafe { OwnedSocket::from_raw_socket(sock as RawSocket) },
        status: ProxyStatus::Idle,
        sendto_addr: None,
        listening: false,
        family: af,
        mem,
        queue,
        rxq,
        rx_cnt: Wrapping(0),
        tx_cnt: Wrapping(0),
        peer_buf_alloc: 0,
        peer_fwd_cnt: Wrapping(0),
    })
}

pub(crate) fn init_pkt(proxy: &super::TsiDgramProxy, pkt: &mut VsockPacket) {
    pkt.set_op(uapi::VSOCK_OP_RW)
        .set_src_cid(uapi::VSOCK_HOST_CID)
        .set_dst_cid(proxy.cid)
        .set_src_port(proxy.local_port)
        .set_dst_port(proxy.peer_port)
        .set_type(uapi::VSOCK_TYPE_DGRAM)
        .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
        .set_fwd_cnt(proxy.tx_cnt.0);
}

pub(crate) fn recv_to_pkt(proxy: &super::TsiDgramProxy, pkt: &mut VsockPacket) -> RecvPkt {
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
                RecvPkt::WaitForCredit
            } else {
                RecvPkt::Error
            }
        }
    } else {
        RecvPkt::Error
    }
}

pub(crate) fn do_connect(
    proxy: &mut super::TsiDgramProxy,
    pkt: &VsockPacket,
    req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let (sa_bytes, sa_len) = match storage_to_winsock(&req.addr) {
        Some(v) => v,
        None => return update,
    };

    let res = unsafe { connect(sock(proxy), sa_bytes.as_ptr() as *const SOCKADDR, sa_len) };

    let err_code = if res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        if e != WSAEWOULDBLOCK {
            debug!("dgram connect error: id={} err={e}", proxy.id);
        }
        -wsa_errno_to_linux(e as i32)
    } else {
        proxy.status = ProxyStatus::Connected;
        0
    };

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    // Push the connection response packet back to the guest virtual queue
    let rx = MuxerRx::ConnResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        result: err_code,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    if err_code == 0 && !proxy.listening {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
    }

    update
}

pub(crate) fn do_getpeername(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) {
    let mut sa_buf = [0u8; 128]; // Size matching SOCKADDR_STORAGE
    let mut sa_len = sa_buf.len() as i32;

    let res = unsafe {
        getpeername(
            sock(proxy),
            sa_buf.as_mut_ptr() as *mut SOCKADDR,
            &mut sa_len,
        )
    };

    let (result, addr) = if res == 0 && sa_len >= 0 && sa_len <= 128 {
        // Adjust the method slice match based on your tsi_stream implementation format
        match winsock_to_storage(&sa_buf, sa_len) {
            Some(storage) => (0, storage),
            None => (-1, SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into()),
        }
    } else {
        let e = unsafe { WSAGetLastError() };
        (
            -wsa_errno_to_linux(e as i32),
            SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
        )
    };

    let data = TsiGetnameRsp {
        result,
        addr_len: addr.len(),
        addr,
    };
    let rx = MuxerRx::GetnameResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        data,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn sendmsg(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) -> ProxyUpdate {
    if let Some(buf) = pkt.buf() {
        let res = unsafe { send(sock(proxy), buf.as_ptr() as _, buf.len() as i32, 0) };
        if res >= 0 {
            proxy.tx_cnt += Wrapping(res as u32);
        }
    }
    ProxyUpdate::default()
}

pub(crate) fn do_sendto_addr(proxy: &mut super::TsiDgramProxy, req: TsiSendtoAddr) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();
    proxy.sendto_addr = Some(req.addr);

    // Explicitly bind the socket and add it to polling interest to capture incoming traffic
    if !proxy.listening {
        let addr: Option<SockaddrStorage> = match proxy.family {
            AF_INET => Some(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into()),
            AF_INET6 => {
                Some(std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0).into())
            }
            _ => None,
        };

        if let Some(storage_addr) = addr {
            if let Some((sa_bytes, sa_len)) = storage_to_winsock(&storage_addr) {
                let res =
                    unsafe { bind(sock(proxy), sa_bytes.as_ptr() as *const SOCKADDR, sa_len) };
                if res != SOCKET_ERROR {
                    proxy.listening = true;
                    update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
                } else {
                    let e = unsafe { WSAGetLastError() };
                    debug!("dgram bind error: id={} err={e}", proxy.id);
                }
            }
        } else {
            debug!(
                "sendto_addr: unsupported address family: {:?}",
                proxy.family
            );
        }
    }

    update
}

pub(crate) fn sendto_data(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) {
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    if let Some(addr) = &proxy.sendto_addr {
        if let Some(buf) = pkt.buf() {
            if let Some((sa_bytes, sa_len)) = storage_to_winsock(addr) {
                let res = unsafe {
                    sendto(
                        sock(proxy),
                        buf.as_ptr() as _,
                        buf.len() as i32,
                        0,
                        sa_bytes.as_ptr() as *const SOCKADDR,
                        sa_len,
                    )
                };
                if res >= 0 {
                    proxy.tx_cnt += Wrapping(res as u32);
                } else {
                    let e = unsafe { WSAGetLastError() };
                    debug!("error in sendto: {e}");
                }
            }
        }
    }
    // sendto_addr is retained to preserve multi-packet stream integration mirrored from unix.rs
}

pub(crate) fn do_listen(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) -> ProxyUpdate {
    let result = -1i32; // DGRAM doesn't listen
    let rx = MuxerRx::ListenResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        result,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
    ProxyUpdate::default()
}

pub(crate) fn update_peer_credit(
    proxy: &mut super::TsiDgramProxy,
    pkt: &VsockPacket,
) -> ProxyUpdate {
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    }
}

pub(crate) fn release(_proxy: &mut super::TsiDgramProxy) -> ProxyUpdate {
    ProxyUpdate {
        remove_proxy: ProxyRemoval::Immediate,
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::TsiDgramProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        update.remove_proxy = if proxy.status == ProxyStatus::Listening {
            ProxyRemoval::Immediate
        } else {
            ProxyRemoval::Deferred
        };
        return update;
    }

    if evset.contains(EventSet::IN) {
        let (signal_queue, wait_credit) = proxy.recv_pkt();
        update.signal_queue = signal_queue || wait_credit;

        // Correctly handle credit depletion state transitions and alert the guest
        if wait_credit && proxy.status != ProxyStatus::WaitingCreditUpdate {
            proxy.status = ProxyStatus::WaitingCreditUpdate;
            let rx = MuxerRx::CreditRequest {
                local_port: proxy.local_port,
                peer_port: proxy.peer_port,
                fwd_cnt: proxy.tx_cnt.0,
            };
            update.push_credit_req = Some(rx);
        }

        // Suppress incoming event loop reads until credit constraints clear to block a 100% CPU spin-loop
        if proxy.status == ProxyStatus::WaitingCreditUpdate {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        }
    }

    update
}
