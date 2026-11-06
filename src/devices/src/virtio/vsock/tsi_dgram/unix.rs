use std::collections::HashMap;
use std::io::{Error as IoError, IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::num::Wrapping;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
#[cfg(target_os = "linux")]
use nix::sys::socket::UnixAddr;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockProtocol, SockType,
    SockaddrIn, SockaddrLike, SockaddrStorage, bind, connect, getpeername, getsockname, recv,
    recvmsg, send, sendmsg as send_message, sendto, setsockopt, socket, sockopt,
};

#[cfg(target_os = "macos")]
use super::super::super::linux_errno::linux_errno_raw;
use super::super::defs;
use super::super::defs::uapi;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{
    TsiConnectReq, TsiGetnameRsp, TsiProxyCreate, TsiSendtoAddr, VsockPacket,
};
use super::super::proxy::{ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt};
use super::super::tsi_wire::{DGRAM_HEADER_LEN, DGRAM_MAX_SIZE, DatagramInfo, encode_header};
use utils::epoll::EventSet;
use vm_memory::GuestMemoryMmap;

pub type SendtoAddr = SockaddrStorage;

pub(crate) fn create(
    id: u64,
    cid: u64,
    req: TsiProxyCreate,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<super::super::super::Queue>>,
    rxq: Arc<Mutex<super::super::muxer_rxq::MuxerRxQ>>,
) -> Result<super::TsiDgramProxy, ProxyError> {
    let family = match req.family {
        defs::LINUX_AF_INET => AddressFamily::Inet,
        defs::LINUX_AF_INET6 => AddressFamily::Inet6,
        #[cfg(target_os = "linux")]
        defs::LINUX_AF_UNIX => AddressFamily::Unix,
        _ => return Err(ProxyError::InvalidFamily),
    };

    let protocol = match req.protocol {
        1 => Some(SockProtocol::Icmp),
        58 => Some(SockProtocol::IcmpV6),
        _ => None,
    };
    let fd = socket(family, SockType::Datagram, SockFlag::empty(), protocol)
        .map_err(|e| ProxyError::CreatingSocket(IoError::from_raw_os_error(e as i32)))?;

    let metadata = match family {
        AddressFamily::Inet => setsockopt(&fd, sockopt::Ipv4PacketInfo, &true),
        AddressFamily::Inet6 => setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true),
        _ => Ok(()),
    };
    metadata
        .map_err(|error| ProxyError::CreatingSocket(IoError::from_raw_os_error(error as i32)))?;

    #[cfg(target_os = "linux")]
    match family {
        AddressFamily::Inet => setsockopt(&fd, sockopt::Ipv4RecvTtl, &true),
        AddressFamily::Inet6 => setsockopt(&fd, sockopt::Ipv6RecvHopLimit, &true),
        _ => Ok(()),
    }
    .map_err(|error| ProxyError::CreatingSocket(IoError::from_raw_os_error(error as i32)))?;

    // macOS forces us to do this here instead of just using SockFlag::SOCK_NONBLOCK above.
    match fcntl(&fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!("error switching to non-blocking: id={id}, err={e}");
                }
            }
            None => error!("invalid fd flags id={id}"),
        },
        Err(e) => error!("couldn't obtain fd flags id={id}, err={e}"),
    };

    #[cfg(target_os = "macos")]
    {
        // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
        let option_value: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &option_value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&option_value) as libc::socklen_t,
            )
        };
    }

    Ok(super::TsiDgramProxy {
        id,
        cid,
        local_port: 0,
        peer_port: req.peer_port,
        fd,
        status: ProxyStatus::Idle,
        pending_error: std::sync::atomic::AtomicI32::new(0),
        sendto_addr: None,
        listening: false,
        family,
        protocol: req.protocol,
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
    debug!(
        "init_pkt: id={}, src_port={}, dst_port={}",
        proxy.id, proxy.local_port, proxy.peer_port
    );
    pkt.set_op(uapi::VSOCK_OP_RW)
        .set_src_cid(if proxy.family == AddressFamily::Unix {
            proxy.cid
        } else {
            uapi::VSOCK_HOST_CID
        })
        .set_dst_cid(if proxy.family == AddressFamily::Unix {
            uapi::VSOCK_HOST_CID
        } else {
            proxy.cid
        })
        .set_dst_port(proxy.peer_port)
        .set_src_port(if proxy.family == AddressFamily::Unix {
            0
        } else {
            defs::TSI_DATAGRAM
        })
        .set_type(uapi::VSOCK_TYPE_DGRAM)
        .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
        .set_fwd_cnt(proxy.tx_cnt.0);
}

fn record_socket_error(proxy: &super::TsiDgramProxy, error: nix::errno::Errno) {
    #[cfg(target_os = "linux")]
    let code = error as i32;
    #[cfg(target_os = "macos")]
    let code = linux_errno_raw(error as i32);
    proxy.record_error(code);
}

pub(crate) fn recv_to_pkt(proxy: &super::TsiDgramProxy, pkt: &mut VsockPacket) -> RecvPkt {
    if proxy.family == AddressFamily::Unix {
        return recv_legacy(proxy, pkt);
    }
    let Some(buf) = pkt.buf_mut() else {
        return RecvPkt::Error;
    };
    if buf.len() < DGRAM_HEADER_LEN {
        return RecvPkt::Error;
    }
    let capacity = buf.len().min(DGRAM_MAX_SIZE) - DGRAM_HEADER_LEN;
    let (count, truncated, address, info) = {
        let mut iov = [IoSliceMut::new(
            &mut buf[DGRAM_HEADER_LEN..DGRAM_HEADER_LEN + capacity],
        )];
        let mut control = nix::cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
        match recvmsg::<SockaddrStorage>(
            proxy.fd.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::MSG_TRUNC,
        ) {
            Ok(msg) => {
                let Ok(messages) = msg.cmsgs() else {
                    return RecvPkt::Error;
                };
                let mut info = None;
                #[allow(unused_mut)]
                let mut hop_limit = None;
                for message in messages {
                    match message {
                        ControlMessageOwned::Ipv4PacketInfo(native) => {
                            let mut address = [0; 16];
                            address[..4].copy_from_slice(&native.ipi_addr.s_addr.to_ne_bytes());
                            info = Some(DatagramInfo {
                                address,
                                ifindex: native.ipi_ifindex as u32,
                                hop_limit: None,
                            });
                        }
                        ControlMessageOwned::Ipv6PacketInfo(native) => {
                            info = Some(DatagramInfo {
                                address: native.ipi6_addr.s6_addr,
                                ifindex: native.ipi6_ifindex,
                                hop_limit: None,
                            });
                        }
                        #[cfg(target_os = "linux")]
                        ControlMessageOwned::Ipv4Ttl(value)
                        | ControlMessageOwned::Ipv6HopLimit(value) => {
                            hop_limit = u8::try_from(value).ok();
                        }
                        _ => (),
                    }
                }
                if let Some(info) = info.as_mut() {
                    info.hop_limit = hop_limit;
                }
                (
                    msg.bytes,
                    msg.flags.contains(MsgFlags::MSG_TRUNC),
                    msg.address,
                    info,
                )
            }
            Err(error) => {
                if !matches!(error, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) {
                    record_socket_error(proxy, error);
                }
                return RecvPkt::Error;
            }
        }
    };
    let Some(address) = address else {
        return RecvPkt::Error;
    };
    let mut addr = [0u8; 28];
    let addr_len = if let Some(inet) = address.as_sockaddr_in() {
        addr[..2].copy_from_slice(&defs::LINUX_AF_INET.to_le_bytes());
        addr[2..4].copy_from_slice(&inet.port().to_be_bytes());
        addr[4..8].copy_from_slice(&inet.ip().octets());
        16
    } else if let Some(inet) = address.as_sockaddr_in6() {
        addr[..2].copy_from_slice(&defs::LINUX_AF_INET6.to_le_bytes());
        addr[2..4].copy_from_slice(&inet.port().to_be_bytes());
        addr[4..8].copy_from_slice(&inet.flowinfo().to_ne_bytes());
        addr[8..24].copy_from_slice(&inet.ip().octets());
        addr[24..28].copy_from_slice(&inet.scope_id().to_le_bytes());
        28
    } else {
        return RecvPkt::Error;
    };
    encode_header(buf, &addr[..addr_len], count, truncated, info);
    RecvPkt::Read(DGRAM_HEADER_LEN + count.min(capacity))
}

fn recv_legacy(proxy: &super::TsiDgramProxy, pkt: &mut VsockPacket) -> RecvPkt {
    if let Some(buf) = pkt.buf_mut() {
        // Disable UDP credit accounting until is fixed in the kernel
        //let peer_credit = self.peer_avail_credit();
        //let max_len = std::cmp::min(buf.len(), peer_credit);
        let max_len = buf.len();

        /*
        debug!(
            "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
            self.peer_avail_credit(),
            buf.len(),
            max_len,
        );

        if max_len == 0 {
            return RecvPkt::WaitForCredit;
        }
        */

        match recv(proxy.fd.as_raw_fd(), &mut buf[..max_len], MsgFlags::empty()) {
            Ok(cnt) => {
                debug!("recv cnt={cnt}");
                if cnt > 0 {
                    RecvPkt::Read(cnt)
                } else {
                    RecvPkt::Close
                }
            }
            Err(e) => {
                debug!("recv_pkt: recv error: {e:?}");
                RecvPkt::Error
            }
        }
    } else {
        debug!("recv_pkt: pkt without buf");
        RecvPkt::Error
    }
}

pub(crate) fn bind_datagram(
    proxy: &mut super::TsiDgramProxy,
    req: TsiSendtoAddr,
    host_port_map: &Option<HashMap<u16, u16>>,
) -> Result<ProxyUpdate, i32> {
    let addr: SockaddrStorage = if let Some(inet) = req.addr.as_sockaddr_in() {
        if proxy.family != AddressFamily::Inet {
            return Err(-super::super::tsi_wire::EAFNOSUPPORT);
        }
        let port = host_port_map
            .as_ref()
            .filter(|_| matches!(proxy.protocol, 0 | 17))
            .and_then(|map| map.get(&inet.port()))
            .copied()
            .unwrap_or(inet.port());
        SocketAddrV4::new(inet.ip(), port).into()
    } else if let Some(inet) = req.addr.as_sockaddr_in6() {
        if proxy.family != AddressFamily::Inet6 {
            return Err(-super::super::tsi_wire::EAFNOSUPPORT);
        }
        let port = host_port_map
            .as_ref()
            .filter(|_| matches!(proxy.protocol, 0 | 17))
            .and_then(|map| map.get(&inet.port()))
            .copied()
            .unwrap_or(inet.port());
        SocketAddrV6::new(inet.ip(), port, inet.flowinfo(), inet.scope_id()).into()
    } else {
        return Err(-super::super::tsi_wire::EOPNOTSUPP);
    };
    bind(proxy.fd.as_raw_fd(), &addr).map_err(|error| {
        #[cfg(target_os = "macos")]
        {
            -linux_errno_raw(error as i32)
        }
        #[cfg(target_os = "linux")]
        {
            -(error as i32)
        }
    })?;
    proxy.listening = true;
    Ok(ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    })
}

pub(crate) fn do_connect(
    proxy: &mut super::TsiDgramProxy,
    pkt: &VsockPacket,
    req: TsiConnectReq,
) -> ProxyUpdate {
    debug!("connect: addr={}", req.addr);
    let res = match connect(proxy.fd.as_raw_fd(), &req.addr) {
        Ok(()) => {
            debug!("connect: Connected");
            proxy.status = ProxyStatus::Connected;
            0
        }
        Err(e) => {
            debug!("Error connecting: {e}");
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(e as i32);
            #[cfg(target_os = "linux")]
            let errno = -(e as i32);
            errno
        }
    };

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    // This response goes to the connection.
    let rx = MuxerRx::ConnResponse {
        request_id: pkt.control_request_id(),
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        result: res,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    let mut update = ProxyUpdate::default();
    if res == 0 && !proxy.listening {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
    }
    update
}

pub(crate) fn do_disconnect(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) -> ProxyUpdate {
    // UNIX datagrams retain their separate legacy protocol.
    let result = if proxy.family == AddressFamily::Unix {
        -super::super::tsi_wire::EOPNOTSUPP
    } else {
        #[allow(unused_mut)] // Darwin sockaddr includes its length in byte zero.
        let mut addr = [0u8; 28];
        let len = if proxy.family == AddressFamily::Inet {
            16
        } else {
            28
        };
        #[cfg(target_os = "macos")]
        {
            addr[0] = len as u8;
        }
        let result = unsafe { libc::connect(proxy.fd.as_raw_fd(), addr.as_ptr().cast(), len) };
        if result == 0 {
            0
        } else {
            let error = nix::errno::Errno::last();
            #[cfg(target_os = "macos")]
            {
                // Darwin may report EAFNOSUPPORT after dissolving the peer.
                if error == nix::errno::Errno::EAFNOSUPPORT
                    && matches!(
                        getpeername::<SockaddrStorage>(proxy.fd.as_raw_fd()),
                        Err(nix::errno::Errno::ENOTCONN)
                    )
                {
                    0
                } else {
                    -linux_errno_raw(error as i32)
                }
            }
            #[cfg(target_os = "linux")]
            {
                -(error as i32)
            }
        }
    };
    if result == 0 {
        proxy.status = ProxyStatus::Idle;
    }
    let rx = MuxerRx::ConnResponse {
        request_id: pkt.control_request_id(),
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        result,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
    ProxyUpdate::default()
}

pub(crate) fn do_getname(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket, peer: bool) {
    debug!("process_getpeername");

    let (result, addr): (i32, SockaddrStorage) = match if peer {
        getpeername(proxy.fd.as_raw_fd())
    } else {
        getsockname(proxy.fd.as_raw_fd())
    } {
        Ok(name) => (0, name),
        Err(e) => {
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(e as i32);
            #[cfg(target_os = "linux")]
            let errno = -(e as i32);
            (
                errno,
                SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
            )
        }
    };

    let addr_len = if let Some(inet) = addr.as_sockaddr_in() {
        inet.len()
    } else if let Some(inet6) = addr.as_sockaddr_in6() {
        inet6.len()
    } else if let Some(unix) = addr.as_unix_addr() {
        unix.len()
    } else {
        0
    };
    let data = TsiGetnameRsp {
        result,
        addr_len,
        addr,
    };

    // This response goes to the connection.
    let rx = MuxerRx::GetnameResponse {
        request_id: pkt.control_request_id(),
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        data,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn sendmsg(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) -> ProxyUpdate {
    if proxy.family != AddressFamily::Unix {
        let Some((addr, info, data)) = pkt.read_datagram() else {
            return ProxyUpdate::default();
        };
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::empty();
        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_NOSIGNAL;
        if addr.family() != Some(proxy.family) {
            proxy.record_error(libc::EAFNOSUPPORT);
            return ProxyUpdate::default();
        }
        let result = if let Some(info) = info {
            let iov = [IoSlice::new(data)];
            if proxy.family == AddressFamily::Inet {
                let control = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(info.address[..4].try_into().unwrap()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                send_message(
                    proxy.fd.as_raw_fd(),
                    &iov,
                    &[ControlMessage::Ipv4PacketInfo(&control)],
                    flags,
                    Some(&addr),
                )
            } else {
                let control = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: info.address,
                    },
                    ipi6_ifindex: 0,
                };
                send_message(
                    proxy.fd.as_raw_fd(),
                    &iov,
                    &[ControlMessage::Ipv6PacketInfo(&control)],
                    flags,
                    Some(&addr),
                )
            }
        } else {
            sendto(proxy.fd.as_raw_fd(), data, &addr, flags)
        };
        return match result {
            Ok(_) => {
                proxy.tx_cnt += Wrapping(pkt.len());
                proxy.listening = true;
                ProxyUpdate {
                    polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
                    ..Default::default()
                }
            }
            Err(e) => {
                record_socket_error(proxy, e);
                debug!("datagram send failed: id={} error={e}", proxy.id);
                ProxyUpdate::default()
            }
        };
    }
    debug!("sendmsg");

    let ret = if let Some(buf) = pkt.buf() {
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::empty();
        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_NOSIGNAL;

        match send(proxy.fd.as_raw_fd(), buf, flags) {
            Ok(sent) => {
                proxy.tx_cnt += Wrapping(sent as u32);
                sent as i32
            }
            Err(err) => {
                record_socket_error(proxy, err);
                -(err as i32)
            }
        }
    } else {
        -libc::EINVAL
    };

    debug!("sendmsg ret={ret}");

    ProxyUpdate::default()
}

pub(crate) fn do_sendto_addr(proxy: &mut super::TsiDgramProxy, req: TsiSendtoAddr) -> ProxyUpdate {
    debug!("sendto_addr: addr={}", req.addr);

    let mut update = ProxyUpdate::default();

    proxy.sendto_addr = Some(req.addr);
    if !proxy.listening {
        let bind_result = match proxy.family {
            AddressFamily::Inet => bind(proxy.fd.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, 0)),
            AddressFamily::Inet6 => {
                let addr6: SockaddrStorage =
                    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into();
                bind(proxy.fd.as_raw_fd(), &addr6)
            }
            #[cfg(target_os = "linux")]
            AddressFamily::Unix => {
                let addr = UnixAddr::new_unnamed();
                bind(proxy.fd.as_raw_fd(), &addr)
            }
            _ => {
                warn!(
                    "sendto_addr: unsupported address family: {:?}",
                    proxy.family
                );
                return update;
            }
        };

        match bind_result {
            Ok(_) => {
                proxy.listening = true;
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
            }
            Err(e) => debug!("couldn't bind socket: {e}"),
        }
    }

    update
}

pub(crate) fn sendto_data(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) {
    debug!("sendto_data");

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    if let Some(addr) = proxy.sendto_addr {
        if let Some(buf) = pkt.buf() {
            #[cfg(target_os = "macos")]
            let flags = MsgFlags::empty();
            #[cfg(target_os = "linux")]
            let flags = MsgFlags::MSG_NOSIGNAL;

            match sendto(proxy.fd.as_raw_fd(), buf, &addr, flags) {
                Ok(sent) => {
                    proxy.tx_cnt += Wrapping(sent as u32);
                }
                Err(err) => {
                    record_socket_error(proxy, err);
                    debug!("error in sendto: {err}");
                }
            }
        } else {
            debug!("sendto_data pkt without buffer");
        }
    } else {
        debug!("sendto_data without sendto_addr");
    }
}

pub(crate) fn do_listen(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) -> ProxyUpdate {
    let rx = MuxerRx::ListenResponse {
        request_id: pkt.control_request_id(),
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        result: -95, // Linux EOPNOTSUPP
        flags: 0,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
    ProxyUpdate::default()
}

pub(crate) fn update_peer_credit(
    proxy: &mut super::TsiDgramProxy,
    pkt: &VsockPacket,
) -> ProxyUpdate {
    debug!(
        "update_credit: buf_alloc={} rx_cnt={} fwd_cnt={}",
        pkt.buf_alloc(),
        proxy.rx_cnt,
        pkt.fwd_cnt()
    );
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    }
}

pub(crate) fn release(_proxy: &mut super::TsiDgramProxy) -> ProxyUpdate {
    debug!("release");
    ProxyUpdate {
        remove_proxy: ProxyRemoval::Immediate,
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::TsiDgramProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    #[cfg(target_os = "linux")]
    if evset.contains(EventSet::ERROR) {
        // Reading SO_ERROR clears error readiness; keep it for the guest.
        if let Ok(error) = super::super::tsi_sockopt::socket_option(
            proxy.fd.as_raw_fd(),
            proxy.family,
            defs::SOCK_DGRAM,
            1,
            4,
            None,
        ) {
            proxy.record_error(error);
        }
    }

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

        if wait_credit && proxy.status != ProxyStatus::WaitingCreditUpdate {
            proxy.status = ProxyStatus::WaitingCreditUpdate;
            let rx = MuxerRx::CreditRequest {
                local_port: proxy.local_port,
                peer_port: proxy.peer_port,
                fwd_cnt: proxy.tx_cnt.0,
            };
            update.push_credit_req = Some(rx);
        }

        if proxy.status == ProxyStatus::WaitingCreditUpdate {
            debug!("process_event: WaitingCreditUpdate");
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        }
    }

    if evset.contains(EventSet::OUT) {
        error!("EventSet::OUT unexpected");
    }

    update
}
