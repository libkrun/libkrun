use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::num::Wrapping;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
#[cfg(target_os = "linux")]
use nix::sys::socket::UnixAddr;
use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn, SockaddrLike, SockaddrStorage, bind,
    connect, getpeername, recv, send, sendto, socket,
};

#[cfg(target_os = "macos")]
use super::super::super::linux_errno::linux_errno_raw;
use super::super::defs;
use super::super::defs::uapi;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiConnectReq, TsiGetnameRsp, TsiSendtoAddr, VsockPacket};
use super::super::proxy::{ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt};
use utils::epoll::EventSet;
use vm_memory::GuestMemoryMmap;

pub type SendtoAddr = SockaddrStorage;

pub(crate) fn create(
    id: u64,
    cid: u64,
    family: u16,
    peer_port: u32,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<super::super::super::Queue>>,
    rxq: Arc<Mutex<super::super::muxer_rxq::MuxerRxQ>>,
) -> Result<super::TsiDgramProxy, ProxyError> {
    let family = match family {
        defs::LINUX_AF_INET => AddressFamily::Inet,
        defs::LINUX_AF_INET6 => AddressFamily::Inet6,
        #[cfg(target_os = "linux")]
        defs::LINUX_AF_UNIX => AddressFamily::Unix,
        _ => return Err(ProxyError::InvalidFamily),
    };

    let fd = socket(family, SockType::Datagram, SockFlag::empty(), None)
        .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;

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
        peer_port,
        fd,
        status: ProxyStatus::Idle,
        sendto_addr: None,
        listening: false,
        family,
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
        .set_src_cid(proxy.cid)
        .set_dst_cid(uapi::VSOCK_HOST_CID)
        .set_dst_port(proxy.peer_port)
        .set_src_port(0)
        .set_type(uapi::VSOCK_TYPE_DGRAM)
        .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
        .set_fwd_cnt(proxy.tx_cnt.0);
}

pub(crate) fn recv_to_pkt(proxy: &super::TsiDgramProxy, pkt: &mut VsockPacket) -> RecvPkt {
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

pub(crate) fn do_getpeername(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) {
    debug!("process_getpeername");

    let (result, addr): (i32, SockaddrStorage) = match getpeername(proxy.fd.as_raw_fd()) {
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

    let data = TsiGetnameRsp {
        result,
        addr_len: addr.len(),
        addr,
    };

    // This response goes to the connection.
    let rx = MuxerRx::GetnameResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        data,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn sendmsg(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) -> ProxyUpdate {
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
            Err(err) => -(err as i32),
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
                Err(err) => debug!("error in sendto: {err}"),
            }
        } else {
            debug!("sendto_data pkt without buffer");
        }
    } else {
        debug!("sendto_data without sendto_addr");
    }
}

pub(crate) fn do_listen(_proxy: &mut super::TsiDgramProxy, _pkt: &VsockPacket) -> ProxyUpdate {
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

pub(crate) fn release(proxy: &mut super::TsiDgramProxy) -> ProxyUpdate {
    debug!("release");
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
