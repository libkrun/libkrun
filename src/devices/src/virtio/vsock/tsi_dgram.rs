use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::Wrapping;
use std::sync::{Arc, Mutex};

use socket2::{Domain, Socket, Type};

use super::super::Queue as VirtQueue;
use super::defs;
use super::defs::uapi;
use super::dns_filter::{DNS_PORT, DnsRequest, sockaddr_port};
use super::muxer::{MuxerRx, push_packet};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{
    TsiAcceptReq, TsiConnectReq, TsiGetnameRsp, TsiListenReq, TsiSendtoAddr, VsockPacket,
};
use super::proxy::{
    Family, Proxy, ProxyError, ProxyRawHandle, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt,
    raw_handle,
};
use super::snapshot_gate::SnapshotGate;
use super::sys;
use super::vsock_addr::VsockAddr;
use crossbeam_channel::Sender;
use utils::epoll::EventSet;

use vm_memory::GuestMemoryMmap;

pub struct TsiDgramProxy {
    pub id: u64,
    cid: u64,
    local_port: u32,
    peer_port: u32,
    sock: Socket,
    pub status: ProxyStatus,
    sendto_addr: Option<VsockAddr>,
    listening: bool,
    family: Family,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    snapshot_gate: Arc<SnapshotGate>,
    rx_cnt: Wrapping<u32>,
    tx_cnt: Wrapping<u32>,
    peer_buf_alloc: u32,
    peer_fwd_cnt: Wrapping<u32>,
    /// Sender to the DNS worker; `Some` only when DNS filtering is active.
    dns_sender: Option<Sender<DnsRequest>>,
    /// Set when this socket was `connect()`ed to a resolver (port 53) and is
    /// being intercepted — sends on it are routed to the DNS worker.
    connected_dns: bool,
}

impl TsiDgramProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        cid: u64,
        family: u16,
        peer_port: u32,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        dns_sender: Option<Sender<DnsRequest>>,
        snapshot_gate: Arc<SnapshotGate>,
    ) -> Result<Self, ProxyError> {
        let (family, domain) = match family {
            defs::LINUX_AF_INET => (Family::Inet, Domain::IPV4),
            defs::LINUX_AF_INET6 => (Family::Inet6, Domain::IPV6),
            #[cfg(target_os = "linux")]
            defs::LINUX_AF_UNIX => (Family::Unix, Domain::UNIX),
            _ => return Err(ProxyError::InvalidFamily),
        };

        let sock = Socket::new(domain, Type::DGRAM, None).map_err(ProxyError::CreatingSocket)?;
        if let Err(e) = sock.set_nonblocking(true) {
            warn!("error switching to non-blocking: id={id}, err={e}");
        }
        // Match Linux's dual-stack default for IPv6 wildcard binds (no-op on IPv4).
        if family == Family::Inet6 {
            let _ = sock.set_only_v6(false);
        }

        Ok(TsiDgramProxy {
            id,
            cid,
            local_port: 0,
            peer_port,
            sock,
            status: ProxyStatus::Idle,
            sendto_addr: None,
            listening: false,
            family,
            mem,
            queue,
            rxq,
            snapshot_gate,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            dns_sender,
            connected_dns: false,
        })
    }

    /// Hand a guest DNS query to the worker thread instead of sending it out the
    /// host socket. `tx_cnt` is advanced by the query length so the response's
    /// `fwd_cnt` stays monotonic — identical to the normal send paths — without
    /// the worker ever touching per-proxy state.
    fn send_dns_query(&mut self, buf: &[u8]) {
        self.tx_cnt += Wrapping(buf.len() as u32);
        if let Some(sender) = &self.dns_sender {
            let _ = sender.send(DnsRequest {
                query: buf.to_vec(),
                peer_port: self.peer_port,
                fwd_cnt: self.tx_cnt.0,
                cid: self.cid,
            });
        }
    }

    fn init_pkt(&self, pkt: &mut VsockPacket) {
        debug!(
            "init_pkt: id={}, src_port={}, dst_port={}",
            self.id, self.local_port, self.peer_port
        );
        pkt.set_op(uapi::VSOCK_OP_RW)
            .set_src_cid(self.cid)
            .set_dst_cid(uapi::VSOCK_HOST_CID)
            .set_dst_port(self.peer_port)
            .set_src_port(0)
            .set_type(uapi::VSOCK_TYPE_DGRAM)
            .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
            .set_fwd_cnt(self.tx_cnt.0);
    }

    fn recv_to_pkt(&self, pkt: &mut VsockPacket) -> RecvPkt {
        if let Some(buf) = pkt.buf_mut() {
            let max_len = buf.len();
            match sys::recv_into(&self.sock, &mut buf[..max_len]) {
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

    fn recv_pkt(&mut self) -> (bool, bool) {
        let mut have_used = false;
        let mut wait_credit = false;
        let _snapshot_activity = self.snapshot_gate.enter();
        let mut queue = self.queue.lock().unwrap();

        while let Some(head) = queue.pop(&self.mem) {
            let len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => match self.recv_to_pkt(&mut pkt) {
                    RecvPkt::WaitForCredit => {
                        wait_credit = true;
                        0
                    }
                    RecvPkt::Read(cnt) => {
                        self.rx_cnt += Wrapping(cnt as u32);
                        self.init_pkt(&mut pkt);
                        pkt.set_len(cnt as u32);
                        pkt.hdr().len() + cnt
                    }
                    RecvPkt::Close => {
                        self.status = ProxyStatus::Closed;
                        0
                    }
                    RecvPkt::Error => 0,
                },
                Err(e) => {
                    debug!("recv_pkt: RX queue error: {e:?}");
                    0
                }
            };

            if len == 0 {
                queue.undo_pop();
                break;
            } else {
                have_used = true;
                debug!("recv_pkt: pushing packet with {len} bytes");
                if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            }
        }

        debug!("recv_pkt: have_used={have_used}");
        (have_used, wait_credit)
    }

    /// Bind the datagram socket to an unspecified local address so it can
    /// receive replies. Returns the bind result.
    fn bind_unspecified(&self) -> std::io::Result<()> {
        match self.family {
            Family::Inet => self
                .sock
                .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()),
            Family::Inet6 => self.sock.bind(
                &std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0).into(),
            ),
            #[cfg(unix)]
            Family::Unix => {
                // Autobind an unnamed AF_UNIX datagram socket (zero-length path).
                let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
                sun.sun_family = libc::AF_UNIX as _;
                let len = std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t;
                let rc = unsafe {
                    libc::bind(
                        raw_handle(&self.sock),
                        &sun as *const _ as *const libc::sockaddr,
                        len,
                    )
                };
                if rc == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }
        }
    }
}

impl Proxy for TsiDgramProxy {
    fn poll_handle(&self) -> ProxyRawHandle {
        raw_handle(&self.sock)
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    fn is_dgram(&self) -> bool {
        true
    }

    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate {
        debug!("connect: addr={}", req.addr);

        // A connected DNS socket is intercepted: we never open a host socket to
        // the (guest-chosen) resolver. Sends are routed to the DNS worker, which
        // queries only the host-trusted resolvers.
        let intercept = self.dns_sender.is_some() && sockaddr_port(&req.addr) == Some(DNS_PORT);
        let (res, poll_host_socket) = if intercept {
            debug!("connect: intercepting DNS socket (no host connect)");
            self.connected_dns = true;
            self.status = ProxyStatus::Connected;
            (0, false)
        } else {
            self.connected_dns = false;
            let addr: std::io::Result<socket2::SockAddr> = match req.addr.inet() {
                Some(inet) => Ok(inet.into()),
                #[cfg(target_os = "linux")]
                None => match req.addr.unix_path() {
                    Some(p) => socket2::SockAddr::unix(p),
                    None => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                },
                #[cfg(not(target_os = "linux"))]
                None => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            };
            match addr.and_then(|a| self.sock.connect(&a)) {
                Ok(()) => {
                    debug!("connect: Connected");
                    self.status = ProxyStatus::Connected;
                    (0, true)
                }
                Err(e) => {
                    debug!("Error connecting: {e}");
                    (-sys::to_linux_errno(&e), false)
                }
            }
        };

        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        // This response goes to the connection.
        let rx = MuxerRx::ConnResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            result: res,
        };
        push_packet(
            self.cid,
            rx,
            &self.rxq,
            &self.queue,
            &self.mem,
            &self.snapshot_gate,
        );

        let mut update = ProxyUpdate::default();
        if poll_host_socket && !self.listening {
            update.polling = Some((self.id, raw_handle(&self.sock), EventSet::IN));
        }
        update
    }

    fn getpeername(&mut self, pkt: &VsockPacket) {
        debug!("process_getpeername");

        let (result, addr): (i32, VsockAddr) = match self.sock.peer_addr() {
            Ok(sa) => match sa.as_socket() {
                Some(socket_addr) => (0, VsockAddr::Inet(socket_addr)),
                None => (
                    -libc::EINVAL,
                    VsockAddr::Inet(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()),
                ),
            },
            Err(e) => (
                -sys::to_linux_errno(&e),
                VsockAddr::Inet(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()),
            ),
        };

        let data = TsiGetnameRsp {
            result,
            addr_len: addr.linux_len(),
            addr,
        };

        // This response goes to the connection.
        let rx = MuxerRx::GetnameResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            data,
        };
        push_packet(
            self.cid,
            rx,
            &self.rxq,
            &self.queue,
            &self.mem,
            &self.snapshot_gate,
        );
    }

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        debug!("sendmsg");

        // Connected DNS socket: route the query to the worker; the worker pushes
        // the response and signals the guest asynchronously.
        if self.connected_dns {
            if let Some(buf) = pkt.buf() {
                self.send_dns_query(buf);
            }
            return ProxyUpdate::default();
        }

        let ret = if let Some(buf) = pkt.buf() {
            #[cfg(target_os = "linux")]
            let send_res = self.sock.send_with_flags(buf, libc::MSG_NOSIGNAL);
            #[cfg(not(target_os = "linux"))]
            let send_res = self.sock.send(buf);

            match send_res {
                Ok(sent) => {
                    self.tx_cnt += Wrapping(sent as u32);
                    sent as i32
                }
                Err(err) => -sys::to_linux_errno(&err),
            }
        } else {
            -libc::EINVAL
        };

        debug!("sendmsg ret={ret}");

        ProxyUpdate::default()
    }

    fn sendto_addr(&mut self, req: TsiSendtoAddr) -> ProxyUpdate {
        debug!("sendto_addr: addr={}", req.addr);

        let mut update = ProxyUpdate::default();

        self.sendto_addr = Some(req.addr);
        if !self.listening {
            match self.bind_unspecified() {
                Ok(_) => {
                    self.listening = true;
                    update.polling = Some((self.id, raw_handle(&self.sock), EventSet::IN));
                }
                Err(e) => debug!("couldn't bind socket: {e}"),
            }
        }

        update
    }

    fn sendto_data(&mut self, pkt: &VsockPacket) {
        debug!("sendto_data");

        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        if let Some(addr) = self.sendto_addr.clone() {
            if let Some(buf) = pkt.buf() {
                // Unconnected DNS query (sendto a resolver:53): route to the
                // worker instead of the host socket.
                if self.dns_sender.is_some() && sockaddr_port(&addr) == Some(DNS_PORT) {
                    self.send_dns_query(buf);
                    return;
                }

                let dst: Option<socket2::SockAddr> = match addr.inet() {
                    Some(inet) => Some(inet.into()),
                    #[cfg(target_os = "linux")]
                    None => addr
                        .unix_path()
                        .and_then(|p| socket2::SockAddr::unix(p).ok()),
                    #[cfg(not(target_os = "linux"))]
                    None => None,
                };

                match dst {
                    Some(d) => match self.sock.send_to(buf, &d) {
                        Ok(sent) => {
                            self.tx_cnt += Wrapping(sent as u32);
                        }
                        Err(err) => debug!("error in sendto: {err}"),
                    },
                    None => debug!("sendto_data: unsupported destination address"),
                }
            } else {
                debug!("sendto_data pkt without buffer");
            }
        } else {
            debug!("sendto_data without sendto_addr");
        }
    }

    fn listen(
        &mut self,
        _pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        debug!(
            "update_credit: buf_alloc={} rx_cnt={} fwd_cnt={}",
            pkt.buf_alloc(),
            self.rx_cnt,
            pkt.fwd_cnt()
        );
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        ProxyUpdate {
            polling: Some((self.id, raw_handle(&self.sock), EventSet::IN)),
            ..Default::default()
        }
    }

    fn process_op_response(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn release(&mut self) -> ProxyUpdate {
        debug!("release");
        let remove_proxy = if self.status == ProxyStatus::Listening {
            ProxyRemoval::Immediate
        } else {
            ProxyRemoval::Deferred
        };
        ProxyUpdate {
            remove_proxy,
            ..Default::default()
        }
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        if evset.contains(EventSet::HANG_UP) {
            update.remove_proxy = if self.status == ProxyStatus::Listening {
                ProxyRemoval::Immediate
            } else {
                ProxyRemoval::Deferred
            };
            return update;
        }

        if evset.contains(EventSet::IN) {
            let (signal_queue, wait_credit) = self.recv_pkt();
            update.signal_queue = signal_queue || wait_credit;

            if wait_credit && self.status != ProxyStatus::WaitingCreditUpdate {
                self.status = ProxyStatus::WaitingCreditUpdate;
                let rx = MuxerRx::CreditRequest {
                    local_port: self.local_port,
                    peer_port: self.peer_port,
                    fwd_cnt: self.tx_cnt.0,
                };
                update.push_credit_req = Some(rx);
            }

            if self.status == ProxyStatus::WaitingCreditUpdate {
                debug!("process_event: WaitingCreditUpdate");
                update.polling = Some((self.id(), raw_handle(&self.sock), EventSet::empty()));
            }
        }

        if evset.contains(EventSet::OUT) {
            error!("EventSet::OUT unexpected");
        }

        update
    }
}
