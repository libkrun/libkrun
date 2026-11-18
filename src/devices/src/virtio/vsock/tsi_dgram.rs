use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::Wrapping;
use std::sync::{Arc, Mutex};

use socket2::{Domain, Socket, Type};

use super::super::Queue as VirtQueue;
use super::super::linux_errno::LINUX_EAFNOSUPPORT;
use super::defs;
use super::defs::uapi;
use super::dns_filter::{DNS_PORT, DnsRequest, HostDnsReply, sockaddr_port};
use super::host_bind::{BindRequest, bind_inet};
use super::host_datagram::{FRAME_HEADER, HostDatagramRx};
use super::host_send::PendingHostSend;
use super::host_sockopt::SocketBuffers;
#[cfg(target_os = "macos")]
use super::macos_datagram::MacDatagram;
use super::muxer::{MuxerRx, push_packet};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{
    TsiAcceptReq, TsiConnectReq, TsiGetnameRsp, TsiListenReq, TsiSendtoAddr, VsockPacket,
};
use super::proxy::{
    Family, Proxy, ProxyError, ProxyRawHandle, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt,
    raw_handle,
};
use super::snapshot_gate::{SnapshotActivity, SnapshotGate};
use super::sys;
use super::vsock_addr::VsockAddr;
use crossbeam_channel::Sender;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use vm_memory::GuestMemoryMmap;

pub struct TsiDgramProxy {
    pub id: u64,
    cid: u64,
    local_port: u32,
    peer_port: u32,
    sock: Arc<Socket>,
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
    host_rx: Option<HostDatagramRx>,
    #[cfg(target_os = "macos")]
    macos_datagram: Option<MacDatagram>,
    #[cfg(target_os = "macos")]
    macos_reuse: [bool; 2],
    #[cfg(target_os = "macos")]
    macos_router: Option<Arc<super::macos_udp_router::DatagramRouter>>,
    dns_identity: Option<Arc<()>>,
    host_peer: Option<SocketAddr>,
    host_send: Option<PendingHostSend>,
    host_error: Option<i32>,
    pending_rx: Arc<Mutex<HashSet<u64>>>,
    epoll: Epoll,
    buffers: SocketBuffers,
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
        pending_rx: Arc<Mutex<HashSet<u64>>>,
        epoll: Epoll,
        #[cfg(target_os = "macos")] macos_router: Option<
            Arc<super::macos_udp_router::DatagramRouter>,
        >,
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
            sock: Arc::new(sock),
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
            host_rx: None,
            #[cfg(target_os = "macos")]
            macos_datagram: None,
            #[cfg(target_os = "macos")]
            macos_reuse: [false; 2],
            #[cfg(target_os = "macos")]
            macos_router,
            dns_identity: None,
            host_peer: None,
            host_send: None,
            host_error: None,
            pending_rx,
            epoll,
            buffers: SocketBuffers::default(),
        })
    }

    /// Hand a guest DNS query to the worker thread instead of sending it out the
    /// host socket. `tx_cnt` is advanced by the query length so the response's
    /// `fwd_cnt` stays monotonic — identical to the normal send paths — without
    /// consulting host resolver configuration on the muxer thread.
    fn send_dns_query(&mut self, buf: &[u8], source: Option<VsockAddr>) {
        self.tx_cnt += Wrapping(buf.len() as u32);
        if let Some(sender) = &self.dns_sender {
            let _ = sender.send(DnsRequest {
                query: buf.to_vec(),
                host_reply: source
                    .filter(|_| self.host_rx.is_some())
                    .map(|source| HostDnsReply {
                        identity: self.dns_identity.as_ref().unwrap().clone(),
                        source,
                    }),
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
            .set_src_cid(if self.host_rx.is_some() {
                uapi::VSOCK_HOST_CID
            } else {
                self.cid
            })
            .set_dst_cid(if self.host_rx.is_some() {
                self.cid
            } else {
                uapi::VSOCK_HOST_CID
            })
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

    fn recv_host_datagrams(&mut self) -> ProxyUpdate {
        let gate = self.snapshot_gate.clone();
        let activity = gate.enter();
        self.drain_host_datagrams(&activity)
    }

    fn drain_host_datagrams(&mut self, _activity: &SnapshotActivity<'_>) -> ProxyUpdate {
        let mut have_used = false;
        let mut exhausted = true;
        let mut queue = self.queue.lock().unwrap();
        while let Some(head) = queue.pop(&self.mem) {
            let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) else {
                let _ = queue.add_used(&self.mem, head.index, 0);
                have_used = true;
                continue;
            };
            if let Some(errno) = self.host_error.take() {
                // ABI 3 uses a header-only datagram reset to report an async
                // socket error without consuming or corrupting queued data.
                self.init_pkt(&mut pkt);
                pkt.set_op(uapi::VSOCK_OP_RST)
                    .set_src_port(defs::TSI_PROXY_PORT)
                    .set_flags(errno as u32)
                    .set_len(0);
                if let Err(error) = queue.add_used(&self.mem, head.index, pkt.hdr().len() as u32) {
                    error!("failed to publish host UDP error: {error:?}");
                }
                have_used = true;
                continue;
            }
            let Some(buf) = pkt.buf_mut().filter(|buf| buf.len() > FRAME_HEADER) else {
                // Consume a malformed descriptor without consuming a UDP
                // datagram or permanently wedging the shared receive queue.
                let _ = queue.add_used(&self.mem, head.index, 0);
                have_used = true;
                continue;
            };
            #[cfg(target_os = "macos")]
            let result = if let Some(datagram) = &mut self.macos_datagram {
                self.host_rx
                    .as_mut()
                    .unwrap()
                    .receive_frame_with(buf, |bytes| {
                        datagram
                            .receive(&self.sock, bytes)
                            .map(|(n, addr)| (n, addr.into()))
                    })
            } else {
                self.host_rx
                    .as_mut()
                    .unwrap()
                    .receive_frame(&self.sock, buf)
            };
            #[cfg(not(target_os = "macos"))]
            let result = self
                .host_rx
                .as_mut()
                .unwrap()
                .receive_frame(&self.sock, buf);
            match result {
                Ok(len) => {
                    self.rx_cnt += Wrapping(len as u32);
                    self.init_pkt(&mut pkt);
                    pkt.set_len(len as u32);
                    if let Err(e) =
                        queue.add_used(&self.mem, head.index, (pkt.hdr().len() + len) as u32)
                    {
                        error!("failed to publish host UDP frame: {e:?}");
                    }
                    have_used = true;
                }
                Err(e) => {
                    queue.undo_pop();
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        self.host_error = Some(sys::to_linux_errno(&e));
                        continue;
                    }
                    exhausted = false;
                    break;
                }
            }
        }
        // Set the retry marker while the virtqueue is still locked. A guest
        // refill must observe it, even if it races this last empty pop.
        let mut pending = self.pending_rx.lock().unwrap();
        if exhausted {
            pending.insert(self.id);
        } else {
            pending.remove(&self.id);
        }
        drop(pending);
        drop(queue);
        // Serialize poll changes under the proxy lock. Applying a deferred
        // remove after a concurrent refill rearmed IN would lose the wakeup.
        let fd = raw_handle(&self.sock);
        let _ = self
            .epoll
            .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
        if !exhausted {
            let _ = self.epoll.ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(EventSet::IN, self.id),
            );
        }
        ProxyUpdate {
            signal_queue: have_used,
            ..Default::default()
        }
    }

    fn connect_socket(&mut self, address: &socket2::SockAddr) -> std::io::Result<()> {
        #[cfg(target_os = "macos")]
        if let Some(datagram) = &mut self.macos_datagram {
            return datagram.connect(&self.sock, address.as_socket().unwrap());
        }
        self.sock.connect(address)
    }

    fn socket_name(&self, local: bool) -> std::io::Result<socket2::SockAddr> {
        #[cfg(target_os = "macos")]
        if let Some(datagram) = &self.macos_datagram {
            return if local {
                datagram.local_addr(&self.sock)
            } else {
                datagram.peer_addr()
            }
            .map(Into::into);
        }
        if local {
            self.sock.local_addr()
        } else {
            self.sock.peer_addr()
        }
    }

    fn send_host_packet(
        &mut self,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> std::io::Result<usize> {
        #[cfg(target_os = "macos")]
        if let Some(datagram) = &mut self.macos_datagram {
            return datagram.send_to(&self.sock, bytes, destination);
        }
        if self.host_peer == Some(destination) {
            self.sock.send(bytes)
        } else {
            self.sock.send_to(bytes, &destination.into())
        }
    }

    fn disconnect_socket(&mut self) -> Result<(), i32> {
        if self.host_rx.is_none() {
            return Err(-95);
        }
        #[cfg(target_os = "linux")]
        {
            // The Linux kernel retains explicitly selected ports/addresses,
            // releases automatic ports, and permits repeated disconnects.
            let address: libc::sockaddr = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::connect(
                    raw_handle(&self.sock),
                    &address,
                    std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(-sys::to_linux_errno(&std::io::Error::last_os_error()));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let datagram = self.macos_datagram.as_mut().unwrap();
            let replacement = datagram
                .replacement_for_disconnect(&self.sock)
                .map_err(|err| -sys::to_linux_errno(&err))?;
            datagram
                .save_received(&self.sock)
                .map_err(|err| -sys::to_linux_errno(&err))?;
            if let Some(replacement) = replacement {
                if !self.pending_rx.lock().unwrap().contains(&self.id) {
                    self.epoll
                        .ctl(
                            ControlOperation::Add,
                            raw_handle(&replacement),
                            &EpollEvent::new(EventSet::IN, self.id),
                        )
                        .map_err(|err| -sys::to_linux_errno(&err))?;
                }
                let _ = self.epoll.ctl(
                    ControlOperation::Delete,
                    raw_handle(&self.sock),
                    &EpollEvent::default(),
                );
                self.sock = Arc::new(replacement);
            }
            datagram.disconnected();
        }
        #[cfg(windows)]
        {
            Err(-95)
        }
        #[cfg(not(windows))]
        {
            self.host_peer = None;
            self.connected_dns = false;
            self.sendto_addr = None;
            self.status = ProxyStatus::Idle;
            Ok(())
        }
    }

    fn deliver_saved_datagrams(&mut self) -> ProxyUpdate {
        #[cfg(target_os = "macos")]
        if self
            .macos_datagram
            .as_ref()
            .is_some_and(MacDatagram::has_saved)
        {
            return self.recv_host_datagrams();
        }
        ProxyUpdate::default()
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
    fn set_host_option(&mut self, req: &super::host_sockopt::OptionRequest) -> Result<(), i32> {
        if let Some(result) = self.buffers.apply(req, &self.sock, true) {
            result?;
            #[cfg(target_os = "macos")]
            if let Some(datagram) = &self.macos_datagram
                && let Some(capacity) = self.buffers.receive
            {
                datagram.set_receive_capacity(capacity);
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            req.apply_datagram(&self.sock, &mut self.macos_reuse)?;
            if let Some(datagram) = &self.macos_datagram {
                datagram.set_reuse_port(self.macos_reuse[1]);
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            req.apply(&self.sock)
        }
    }

    fn bind_host(&mut self, req: &BindRequest) -> Result<VsockAddr, i32> {
        if self.listening || self.status != ProxyStatus::Idle {
            return Err(-libc::EINVAL);
        }
        // macOS's default UDP send buffer is only 9 KiB. A Linux host-mode
        // socket must be able to carry a full UDP datagram in either direction.
        if self.buffers.send.is_none() {
            self.sock
                .set_send_buffer_size(128 * 1024)
                .map_err(|e| -sys::to_linux_errno(&e))?;
        }
        if self.buffers.receive.is_none() {
            self.sock
                .set_recv_buffer_size(128 * 1024)
                .map_err(|e| -sys::to_linux_errno(&e))?;
        }
        #[cfg(target_os = "macos")]
        let mut datagram = MacDatagram::new(
            &self.sock,
            req.addr.inet().ok_or(-97)?,
            self.family == Family::Inet,
            self.id,
            self.macos_router.clone().ok_or(-95)?,
        )
        .map_err(|err| -sys::to_linux_errno(&err))?;
        let addr = bind_inet(&self.sock, self.family, req)?;
        #[cfg(target_os = "macos")]
        {
            self.macos_reuse = req.datagram_reuse();
            if let Some(capacity) = self.buffers.receive {
                datagram.set_receive_capacity(capacity);
            }
            datagram.bound(
                &self.sock,
                addr,
                self.macos_reuse[1],
                req.datagram_v6_only(),
            );
            self.macos_datagram = Some(datagram);
        }
        // sendto must keep this source port instead of trying to autobind again.
        self.listening = true;
        self.host_rx = Some(HostDatagramRx::default());
        self.dns_identity = Some(Arc::new(()));
        Ok(addr.into())
    }

    fn prepare_host_send(&mut self, send: PendingHostSend) -> Result<(), i32> {
        if self.host_rx.is_none() {
            return Err(-95);
        }
        self.sendto_addr = None;
        self.host_send = Some(send);
        Ok(())
    }

    fn receive_dns(
        &mut self,
        reply: HostDnsReply,
        data: Vec<u8>,
        activity: &SnapshotActivity<'_>,
    ) -> bool {
        if !self
            .dns_identity
            .as_ref()
            .is_some_and(|identity| Arc::ptr_eq(identity, &reply.identity))
            || self
                .host_peer
                .is_some_and(|peer| reply.source.inet() != Some(peer))
        {
            return false;
        }
        let Some(rx) = self.host_rx.as_mut() else {
            return false;
        };
        if !rx.enqueue(reply.source, data) {
            return false;
        }
        self.drain_host_datagrams(activity).signal_queue
    }

    #[cfg(target_os = "macos")]
    fn receive_host_error(
        &mut self,
        error: &super::macos_icmp::DatagramError,
    ) -> Option<ProxyUpdate> {
        if self.connected_dns
            || !self
                .macos_datagram
                .as_ref()
                .is_some_and(|socket| socket.matches_error(error.source, error.destination))
        {
            return None;
        }
        self.host_error = Some(error.errno);
        Some(self.recv_host_datagrams())
    }

    fn clear_sendto_addr(&mut self) {
        self.sendto_addr = None;
    }

    fn disconnect_host_datagram(&mut self) -> (Result<(), i32>, ProxyUpdate) {
        let result = self.disconnect_socket();
        // Captured replies need delivery even when queue pressure prevented
        // the peer change. They no longer have native socket readiness.
        (result, self.deliver_saved_datagrams())
    }

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

        // A connected DNS socket is intercepted: its sends are routed to the
        // DNS worker, which queries only the host forwarder or the
        // host-trusted resolvers, never the guest-chosen one. The host socket
        // is still connected (a datagram connect sends nothing, it only looks
        // up the route), so a resolver the host cannot reach fails the connect
        // exactly as it would without interception, and the guest's resolver
        // and address selection see the same errors.
        let intercept = self.dns_sender.is_some() && sockaddr_port(&req.addr) == Some(DNS_PORT);
        let addr: std::io::Result<socket2::SockAddr> = match req.addr.inet() {
            _ if !req.addr.suits_family(self.family) => {
                warn!(
                    "connect: id={} refused address {} for its family",
                    self.id, req.addr
                );
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
            Some(inet) => Ok(inet.into()),
            #[cfg(target_os = "linux")]
            None => match req.addr.unix_path() {
                Some(p) => socket2::SockAddr::unix(p),
                None => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            },
            #[cfg(not(target_os = "linux"))]
            None => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
        };
        let connected =
            if self.family == Family::Inet && req.addr.inet().is_some_and(|a| a.is_ipv6()) {
                // Linux rejects this before changing the socket. Darwin can
                // disconnect an existing UDP peer before returning the error.
                // This is already a guest errno, not a native Winsock/BSD error.
                Err(LINUX_EAFNOSUPPORT)
            } else {
                addr.and_then(|a| self.connect_socket(&a))
                    .map_err(|err| sys::to_linux_errno(&err))
            };
        let (res, poll_host_socket) = match connected {
            Ok(()) => {
                // A failed reconnect leaves the previous peer and its DNS
                // interception active; commit the new policy with the socket.
                self.connected_dns = intercept;
                self.status = ProxyStatus::Connected;
                if self.host_rx.is_some() {
                    self.host_peer = req.addr.inet();
                    #[cfg(target_os = "macos")]
                    if let Some(datagram) = &self.macos_datagram {
                        self.host_peer = datagram.peer_addr().ok();
                    }
                }
                if intercept {
                    debug!("connect: intercepting DNS socket");
                    (0, false)
                } else {
                    debug!("connect: Connected");
                    (0, true)
                }
            }
            Err(errno) => {
                debug!("Error connecting: Linux errno {errno}");
                (-errno, false)
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

        let mut update = self.deliver_saved_datagrams();
        if poll_host_socket && !self.listening {
            update.polling = Some((self.id, raw_handle(&self.sock), EventSet::IN));
        }
        update
    }

    fn getpeername(&mut self, pkt: &VsockPacket) {
        debug!("process_getpeername");

        let local = pkt.read_getname_req().is_some_and(|req| req.peer == 0);
        let name = self.socket_name(local);
        let (result, addr): (i32, VsockAddr) = match name {
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
            if let Some(buf) = pkt
                .data()
                .or_else(|| (self.host_rx.is_some() && pkt.len() == 0).then_some(&[]))
            {
                self.send_dns_query(buf, self.host_peer.map(Into::into));
            }
            return ProxyUpdate::default();
        }

        let ret = if let Some(buf) = pkt
            .data()
            .or_else(|| (self.host_rx.is_some() && pkt.len() == 0).then_some(&[]))
        {
            #[cfg(target_os = "linux")]
            let send_res = self.sock.send_with_flags(buf, libc::MSG_NOSIGNAL);
            #[cfg(not(target_os = "linux"))]
            let send_res = if self.host_rx.is_some() && self.host_peer.is_some() {
                self.send_host_packet(buf, self.host_peer.unwrap())
            } else {
                self.sock.send(buf)
            };

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

        if !req.addr.suits_family(self.family) {
            warn!(
                "sendto: id={} refused address {} for its family",
                self.id, req.addr
            );
            self.sendto_addr = None;
            return update;
        }
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
        if let Some(send) = self.host_send.take() {
            let result = send
                .destination
                .and_then(|addr| {
                    let destination = addr
                        .inet()
                        .filter(|_| addr.suits_family(self.family))
                        .ok_or(-22)?;
                    let buf = pkt
                        .data()
                        .or_else(|| (pkt.len() == 0).then_some(&[]))
                        .ok_or(-22)?;
                    if self.dns_sender.is_some() && destination.port() == DNS_PORT {
                        self.send_dns_query(buf, Some(addr));
                        return Ok(buf.len() as i32);
                    }
                    let sent = self
                        .send_host_packet(buf, destination)
                        .map_err(|err| -sys::to_linux_errno(&err))?;
                    self.tx_cnt += Wrapping(sent as u32);
                    Ok(sent as i32)
                })
                .unwrap_or_else(|err| err);
            push_packet(
                self.cid,
                MuxerRx::HostSendResponse {
                    peer_port: send.control_port,
                    sequence: send.sequence,
                    result,
                },
                &self.rxq,
                &self.queue,
                &self.mem,
                &self.snapshot_gate,
            );
            return;
        }

        if let Some(addr) = self.sendto_addr.clone() {
            if let Some(buf) = pkt
                .data()
                .or_else(|| (self.host_rx.is_some() && pkt.len() == 0).then_some(&[]))
            {
                // Unconnected DNS query (sendto a resolver:53): route to the
                // worker instead of the host socket.
                if self.dns_sender.is_some() && sockaddr_port(&addr) == Some(DNS_PORT) {
                    self.send_dns_query(buf, Some(addr.clone()));
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
                    Some(d) => match if self.host_rx.is_some() && d.as_socket().is_some() {
                        self.send_host_packet(buf, d.as_socket().unwrap())
                    } else {
                        self.sock.send_to(buf, &d)
                    } {
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

    fn accept(&mut self, _control_port: u32, _req: TsiAcceptReq) -> ProxyUpdate {
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
        // The guest closed its datagram socket; nothing of it is left to
        // deliver, so its host socket goes now rather than after a grace period.
        let remove_proxy = ProxyRemoval::Immediate;
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

        let readable = evset.contains(EventSet::IN);
        #[cfg(target_os = "linux")]
        let readable = readable || evset.contains(EventSet::ERROR);
        if self.host_rx.is_some() && readable {
            // EPOLLERR is level-triggered even when only IN was requested.
            // Consume SO_ERROR once, retain it through RX backpressure, and
            // deliver it to the guest instead of spinning on the same error.
            if let Ok(Some(error)) = self.sock.take_error() {
                self.host_error = Some(sys::to_linux_errno(&error));
            }
            return self.recv_host_datagrams();
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

impl Drop for TsiDgramProxy {
    fn drop(&mut self) {
        self.pending_rx.lock().unwrap().remove(&self.id);
    }
}
