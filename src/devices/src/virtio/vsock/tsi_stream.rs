use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::Wrapping;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use socket2::{Domain, Socket, Type};

use super::super::Queue as VirtQueue;
use super::super::linux_errno::{LINUX_EADDRINUSE, LINUX_EAGAIN, LINUX_ECONNREFUSED};
use super::defs;
use super::defs::uapi;
use super::host_bind::{BindRequest, bind_inet};
use super::muxer::{MuxerRx, push_packet};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{
    TsiAcceptReq, TsiConnectReq, TsiGetnameRsp, TsiListenReq, TsiSendtoAddr, VsockPacket,
};
use super::proxy::{
    Family, ListenerDesc, NewProxyType, Proxy, ProxyError, ProxyRawHandle, ProxyRemoval,
    ProxyStatus, ProxyUpdate, RecvPkt, StreamIntercept, connected_event_set, raw_handle,
};
use super::snapshot_gate::SnapshotGate;
use super::sys;
use super::vsock_addr::VsockAddr;
use utils::epoll::EventSet;

use vm_memory::GuestMemoryMmap;

#[cfg(test)]
#[path = "tsi_stream_tests.rs"]
mod tests;

pub struct TsiStreamProxy {
    id: u64,
    cid: u64,
    parent_id: u64,
    family: Family,
    local_port: u32,
    peer_port: u32,
    control_port: u32,
    sock: Socket,
    pub status: ProxyStatus,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    snapshot_gate: Arc<SnapshotGate>,
    rx_cnt: Wrapping<u32>,
    tx_cnt: Wrapping<u32>,
    last_tx_cnt_sent: Wrapping<u32>,
    peer_buf_alloc: u32,
    peer_fwd_cnt: Wrapping<u32>,
    push_cnt: Wrapping<u32>,
    pending_accepts: u64,
    #[cfg(target_os = "linux")]
    unixsock_path: Option<PathBuf>,
    /// Guest listen port, set once this proxy becomes a listener (via
    /// `try_listen`/`relisten`). Captured into a [`ListenerDesc`] so a fork clone
    /// can re-establish the host-side listener. 0 = not a listener.
    listen_guest_port: u16,
    host_bound: Option<SocketAddr>,
    /// A cross-family interceptor uses a separate transport socket. Retain
    /// the guest's explicitly bound socket so its address remains reserved.
    intercept_reservation: Option<Socket>,
    /// Listen backlog requested by the guest, for the same reason.
    listen_backlog: i32,
    /// Set once the remote peer half-closed its send side (our recv hit EOF) and
    /// we forwarded a partial SHUTDOWN to the guest. Guards against re-sending
    /// the shutdown and marks that remote→guest is done while guest→remote still
    /// flows.
    local_read_shutdown: bool,
    /// Guest->host bytes accepted from the guest but not yet written to the host
    /// socket, because the host socket's send buffer was full (a slow or stalled
    /// remote peer — the #1093 blackhole shape). Drained on EPOLLOUT. Bounded by
    /// the guest's own vsock send window (`CONN_TX_BUF_SIZE`), since `tx_cnt`
    /// (which drives the credit we hand back) only advances for bytes actually
    /// flushed: once the backlog reaches the window the guest's own TCP stack
    /// blocks, so the host never buffers unboundedly and the muxer thread never
    /// blocks.
    tx_buf: VecDeque<u8>,
    /// True while we have paused reading the host socket (guest RX credit
    /// exhausted, or the remote half-closed). Kept separate from the epoll
    /// interest so TX-flush (OUT) and RX-read (IN) interest compose correctly
    /// via `conn_evset`.
    rx_paused: bool,
    /// Host-only bytes that must reach the socket before any guest payload:
    /// the [`StreamIntercept`] preamble. Not guest data, so flushing it never
    /// advances `tx_cnt` or the guest's credit.
    preamble: VecDeque<u8>,
    /// Destination the guest asked for when this flow was redirected to an
    /// interceptor; `getpeername` answers with it so the guest never sees the
    /// loopback endpoint.
    intercept_peer: Option<SocketAddr>,
    /// A redirected flow stays `Connecting` until the interceptor answers the
    /// preamble with its own connect result, so the guest sees the real
    /// destination's outcome (and can fall back, e.g. IPv6 to IPv4) rather
    /// than a loopback connect that always succeeds.
    awaiting_verdict: bool,
}

impl TsiStreamProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        cid: u64,
        family: u16,
        local_port: u32,
        peer_port: u32,
        control_port: u32,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        snapshot_gate: Arc<SnapshotGate>,
        host_network: bool,
    ) -> Result<Self, ProxyError> {
        let (family, domain) = match family {
            defs::LINUX_AF_INET => (Family::Inet, Domain::IPV4),
            defs::LINUX_AF_INET6 => (Family::Inet6, Domain::IPV6),
            #[cfg(target_os = "linux")]
            defs::LINUX_AF_UNIX => (Family::Unix, Domain::UNIX),
            _ => return Err(ProxyError::InvalidFamily),
        };
        let sock = Socket::new(domain, Type::STREAM, None).map_err(ProxyError::CreatingSocket)?;
        if let Err(e) = sock.set_nonblocking(true) {
            warn!("error switching to non-blocking: id={id}, err={e}");
        }

        // SO_REUSEADDR mirrors the previous behavior (Unix used REUSEADDR, INET
        // used REUSEPORT; Windows has no REUSEPORT, so REUSEADDR is the portable
        // choice for re-binding a listener).
        let _ = sock.set_reuse_address(true);

        // Match Linux's default dual-stack behavior so an IPv6 wildcard listener
        // (e.g. a guest binding `[::]`) also accepts IPv4. Linux defaults
        // IPV6_V6ONLY off; Windows defaults it on. No-op for IPv4.
        if family == Family::Inet6 {
            let _ = sock.set_only_v6(false);
        }

        // Legacy forwarding uses transport keepalive. Host-network sockets start
        // with Linux SO_KEEPALIVE disabled and follow the guest application.
        #[cfg(target_os = "linux")]
        let is_unix = family == Family::Unix;
        #[cfg(not(target_os = "linux"))]
        let is_unix = false;
        if !host_network && !is_unix {
            let ka = socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(60))
                .with_interval(std::time::Duration::from_secs(15));
            let _ = sock.set_tcp_keepalive(&ka);
        }

        Ok(TsiStreamProxy {
            id,
            cid,
            parent_id: 0,
            family,
            local_port,
            peer_port,
            control_port,
            sock,
            status: ProxyStatus::Idle,
            mem,
            queue,
            rxq,
            snapshot_gate,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            push_cnt: Wrapping(0),
            tx_buf: VecDeque::new(),
            preamble: VecDeque::new(),
            intercept_peer: None,
            awaiting_verdict: false,
            rx_paused: false,
            pending_accepts: 0,
            #[cfg(target_os = "linux")]
            unixsock_path: None,
            listen_guest_port: 0,
            host_bound: None,
            intercept_reservation: None,
            listen_backlog: 0,
            local_read_shutdown: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_reverse(
        id: u64,
        cid: u64,
        parent_id: u64,
        family: Family,
        local_port: u32,
        peer_port: u32,
        sock: Socket,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        snapshot_gate: Arc<SnapshotGate>,
    ) -> Self {
        debug!("new_reverse: id={id} local_port={local_port} peer_port={peer_port}");
        TsiStreamProxy {
            id,
            cid,
            parent_id,
            family,
            local_port,
            peer_port,
            control_port: 0,
            sock,
            status: ProxyStatus::ReverseInit,
            mem,
            queue,
            rxq,
            snapshot_gate,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            push_cnt: Wrapping(0),
            tx_buf: VecDeque::new(),
            preamble: VecDeque::new(),
            intercept_peer: None,
            awaiting_verdict: false,
            rx_paused: false,
            pending_accepts: 0,
            #[cfg(target_os = "linux")]
            unixsock_path: None,
            listen_guest_port: 0,
            host_bound: None,
            intercept_reservation: None,
            listen_backlog: 0,
            local_read_shutdown: false,
        }
    }

    fn init_data_pkt(&self, pkt: &mut VsockPacket) {
        debug!(
            "init_data_pkt: id={}, local_port={}, peer_port={}",
            self.id, self.local_port, self.peer_port
        );
        pkt.set_op(uapi::VSOCK_OP_RW)
            .set_src_cid(uapi::VSOCK_HOST_CID)
            .set_dst_cid(self.cid)
            .set_src_port(self.local_port)
            .set_dst_port(self.peer_port)
            .set_type(uapi::VSOCK_TYPE_STREAM)
            .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
            .set_fwd_cnt(self.tx_cnt.0);
    }

    fn try_listen(&mut self, req: &TsiListenReq, host_port_map: &Option<HashMap<u16, u16>>) -> i32 {
        if self.status == ProxyStatus::Listening || self.status == ProxyStatus::WaitingOnAccept {
            return 0;
        }
        if !req.addr.suits_family(self.family) {
            warn!(
                "listen: id={} refused address {} for its family",
                self.id, req.addr
            );
            return -libc::EINVAL;
        }

        // Resolve the bind address, applying the host port map for INET listeners.
        let mapped: Option<SocketAddr> = match req.addr.inet() {
            Some(inet) => {
                if let Some(port_map) = host_port_map {
                    match port_map.get(&inet.port()) {
                        Some(host_port) => Some(match inet {
                            SocketAddr::V4(a) => {
                                SocketAddr::V4(SocketAddrV4::new(*a.ip(), *host_port))
                            }
                            SocketAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(
                                *a.ip(),
                                *host_port,
                                a.flowinfo(),
                                a.scope_id(),
                            )),
                        }),
                        None => return -libc::EPERM,
                    }
                } else {
                    Some(inet)
                }
            }
            None => None, // AF_UNIX (Linux) handled below
        };

        // Remember the guest listen port (the host_port_map key) so this listener
        // can be re-established on a fork clone (see ListenerDesc).
        let guest_listen_port = req.addr.inet().map(|s| s.port()).unwrap_or(0);

        let bind_res: std::io::Result<()> = match mapped {
            Some(addr) if self.host_bound == Some(addr) => Ok(()),
            Some(_) if self.host_bound.is_some() => {
                return -libc::EINVAL;
            }
            Some(addr) => self.sock.bind(&addr.into()),
            #[cfg(target_os = "linux")]
            None => self.bind_unix(req),
            #[cfg(not(target_os = "linux"))]
            None => return -libc::EINVAL,
        };

        match bind_res {
            Ok(_) => {
                debug!("tcp bind: id={}", self.id);
                let clamped_backlog = req.backlog.clamp(0, sys::SOMAXCONN);
                match self.sock.listen(clamped_backlog) {
                    Ok(_) => {
                        debug!("proxy: id={}", self.id);
                        self.listen_guest_port = guest_listen_port;
                        self.listen_backlog = clamped_backlog;
                        0
                    }
                    Err(e) => {
                        warn!("proxy listen: id={} err={}", self.id, e);
                        -sys::to_linux_errno(&e)
                    }
                }
            }
            Err(e) => {
                warn!("tcp bind: id={} err={}", self.id, e);
                -sys::to_linux_errno(&e)
            }
        }
    }

    /// Bind an AF_UNIX listener (Linux only). Removes a stale socket node first
    /// so we can take ownership, refusing anything else at the guest-chosen path,
    /// and records the path for unlink-on-drop.
    #[cfg(target_os = "linux")]
    fn bind_unix(&mut self, req: &TsiListenReq) -> std::io::Result<()> {
        let path = req.addr.unix_path();
        if let Some(p) = &path {
            super::vsock_addr::remove_stale_unix_socket(p)?;
        }
        let addr = match &path {
            Some(p) => socket2::SockAddr::unix(p)?,
            None => {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
        };
        self.sock.bind(&addr)?;
        // Track for unlink on Drop if it is a real on-disk socket path.
        if let Some(p) = path
            && super::vsock_addr::is_unix_socket_node(&p)
        {
            self.unixsock_path = Some(p);
        }
        Ok(())
    }

    fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    fn recv_to_pkt(&self, pkt: &mut VsockPacket) -> RecvPkt {
        if let Some(buf) = pkt.buf_mut() {
            let peer_credit = self.peer_avail_credit();
            let max_len = std::cmp::min(buf.len(), peer_credit);

            debug!(
                "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
                self.peer_avail_credit(),
                buf.len(),
                max_len,
            );

            if max_len == 0 {
                return RecvPkt::WaitForCredit;
            }

            match sys::recv_into(&self.sock, &mut buf[..max_len]) {
                Ok(cnt) => {
                    debug!("recv cnt={cnt}");
                    if cnt > 0 {
                        debug!("recv rx_cnt={}", self.rx_cnt);
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
                        self.init_data_pkt(&mut pkt);
                        pkt.set_len(cnt as u32);
                        pkt.hdr().len() + cnt
                    }
                    RecvPkt::Close => {
                        self.status = ProxyStatus::PeerClosed;
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
                self.push_cnt += Wrapping(len as u32);
                debug!(
                    "recv_pkt: pushing packet with {} bytes, push_cnt={}",
                    len, self.push_cnt
                );
                if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            }
        }

        debug!("recv_pkt: have_used={have_used}");
        (have_used, wait_credit)
    }

    fn push_connect_rsp(&self, result: i32) {
        debug!(
            "push_connect_rsp: id: {}, control_port: {}, result: {}",
            self.id, self.control_port, result
        );

        // This response goes to the control port (DGRAM).
        let rx = MuxerRx::ConnResponse {
            local_port: 1025,
            peer_port: self.control_port,
            result,
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

    fn push_reset(&self) {
        debug!(
            "push_reset: id: {}, peer_port: {}, local_port: {}",
            self.id, self.peer_port, self.local_port
        );

        // This response goes to the connection.
        let rx = MuxerRx::Reset {
            local_port: self.local_port,
            peer_port: self.peer_port,
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

    /// Forward a partial SHUTDOWN toward the guest. Used when the remote peer
    /// half-closes (our recv hits EOF) so the guest sees an orderly end-of-data
    /// on its receive half while the proxy keeps forwarding guest→remote — a full
    /// RST here would drop any output the guest is still sending after a remote
    /// server closes only its write side.
    fn push_shutdown(&self, flags: u32) {
        debug!(
            "push_shutdown: id: {}, peer_port: {}, local_port: {}, flags: {}",
            self.id, self.peer_port, self.local_port, flags
        );

        let rx = MuxerRx::Shutdown {
            local_port: self.local_port,
            peer_port: self.peer_port,
            flags,
            fwd_cnt: self.tx_cnt.0,
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

    fn switch_to_connected(&mut self) {
        self.status = ProxyStatus::Connected;
        // Deliberately keep the host socket NON-BLOCKING. Guest->host sends are
        // drained non-blockingly (see `flush_tx`) and buffered on `WouldBlock`,
        // so a stalled remote peer can never block the single vsock muxer thread
        // and deadlock the whole VM. See smol-machines/smolvm#1093.
        //
        // A redirected flow announces its destination before the guest can send
        // a byte; anything the socket will not take yet drains on OUT.
        if !self.preamble.is_empty() {
            let _ = self.flush_tx();
        }
    }

    /// Drive a redirected flow's handshake with the interceptor: send the
    /// preamble, then read the one-byte verdict (`0`, or the Linux errno of the
    /// interceptor's connect to the real destination) and report it to the
    /// guest as the outcome of its connect.
    fn advance_verdict(&mut self, update: &mut ProxyUpdate) {
        if !self.preamble.is_empty() {
            if self.flush_tx().is_err() {
                return self.fail_connect(update, LINUX_ECONNREFUSED);
            }
            if !self.preamble.is_empty() {
                update.polling = Some((
                    self.id,
                    raw_handle(&self.sock),
                    EventSet::OUT | EventSet::EDGE_TRIGGERED,
                ));
                return;
            }
        }
        let mut verdict = [0u8; 1];
        match sys::recv_into(&self.sock, &mut verdict) {
            Ok(1) if verdict[0] == 0 => {
                debug!("connect: interceptor reached the destination");
                self.awaiting_verdict = false;
                self.switch_to_connected();
                self.push_connect_rsp(0);
                update.signal_queue = true;
                // As for a direct connect: no socket events until OP_REQUEST.
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
            }
            Ok(1) => {
                debug!(
                    "connect: interceptor could not reach the destination: errno {}",
                    verdict[0]
                );
                self.fail_connect(update, verdict[0] as i32);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::IN));
            }
            Ok(_) | Err(_) => self.fail_connect(update, LINUX_ECONNREFUSED),
        }
    }

    fn guest_local_addr(&self) -> std::io::Result<socket2::SockAddr> {
        let local = self.sock.local_addr()?;
        if self.intercept_peer.is_none() {
            return Ok(local);
        }
        let Some(local) = local.as_socket() else {
            return Ok(local);
        };
        // Interceptors are loopback endpoints. Translate their transport's
        // local address into the original guest family, just as getpeername
        // exposes the original destination rather than the interceptor.
        let mut local: SocketAddr = match (self.family, local) {
            (Family::Inet6, SocketAddr::V4(addr)) => {
                let ip = if addr.ip().is_unspecified() {
                    Ipv6Addr::UNSPECIFIED
                } else {
                    addr.ip().to_ipv6_mapped()
                };
                SocketAddrV6::new(ip, addr.port(), 0, 0).into()
            }
            (Family::Inet, SocketAddr::V6(addr)) => {
                let ip = if addr.ip().is_loopback() {
                    Ipv4Addr::LOCALHOST
                } else if addr.ip().is_unspecified() {
                    Ipv4Addr::UNSPECIFIED
                } else {
                    addr.ip()
                        .to_ipv4_mapped()
                        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT))?
                };
                SocketAddrV4::new(ip, addr.port()).into()
            }
            (_, addr) => addr,
        };
        if let Some(bound) = self.host_bound {
            local.set_port(bound.port());
            if !bound.ip().is_unspecified() {
                local = bound;
            }
        }
        Ok(local.into())
    }

    fn fail_connect(&mut self, update: &mut ProxyUpdate, errno: i32) {
        self.awaiting_verdict = false;
        self.push_connect_rsp(-errno);
        self.status = ProxyStatus::Closed;
        update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
    }

    /// Dial `addr` on the host socket, reporting the outcome to the guest.
    fn dial(&mut self, addr: std::io::Result<socket2::SockAddr>) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();
        let result = match addr {
            Ok(addr) => match self.sock.connect(&addr) {
                Ok(()) if self.awaiting_verdict => {
                    debug!("connect: Connected to interceptor, awaiting its verdict");
                    self.status = ProxyStatus::Connecting;
                    0
                }
                Ok(()) => {
                    debug!("connect: Connected");
                    self.switch_to_connected();
                    0
                }
                Err(e) if sys::connect_in_progress(&e) => {
                    debug!("connect: Connecting");
                    self.status = ProxyStatus::Connecting;
                    0
                }
                Err(e) => {
                    debug!("TcpProxy: Error connecting: {e}");
                    -sys::to_linux_errno(&e)
                }
            },
            Err(e) => -sys::to_linux_errno(&e),
        };

        if self.status == ProxyStatus::Connecting {
            update.polling = Some((
                self.id,
                raw_handle(&self.sock),
                EventSet::OUT | EventSet::EDGE_TRIGGERED,
            ));
        } else {
            if self.status == ProxyStatus::Connected {
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::IN));
            }
            self.push_connect_rsp(result);
        }
        update
    }

    /// Re-establish this freshly-constructed proxy as a host-side inbound
    /// listener for a fork clone, using the clone's own `host_port_map` (see
    /// [`ListenerDesc`]). Mirrors `try_listen`'s bind+listen but is driven by the
    /// snapshot rather than a guest `TSI_LISTEN`. Returns 0 on success, a
    /// negative errno otherwise.
    pub fn relisten(
        &mut self,
        guest_port: u16,
        backlog: i32,
        host_port_map: &Option<HashMap<u16, u16>>,
    ) -> i32 {
        let host_port = match host_port_map.as_ref().and_then(|m| m.get(&guest_port)) {
            Some(p) => *p,
            None => return -libc::EPERM,
        };
        let addr: SocketAddr = match self.family {
            Family::Inet => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, host_port).into(),
            Family::Inet6 => SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, host_port, 0, 0).into(),
            #[cfg(unix)]
            Family::Unix => return -libc::EINVAL,
        };
        if let Err(e) = self.sock.bind(&addr.into()) {
            warn!("relisten bind id={} err={e}", self.id);
            return -LINUX_EADDRINUSE;
        }
        let clamped = backlog.clamp(0, sys::SOMAXCONN);
        if let Err(e) = self.sock.listen(clamped) {
            warn!("relisten listen id={} err={e}", self.id);
            return -libc::EINVAL;
        }
        self.status = ProxyStatus::Listening;
        self.listen_guest_port = guest_port;
        self.listen_backlog = clamped;
        debug!(
            "relisten: id={} guest_port={} host_port={}",
            self.id, guest_port, host_port
        );
        0
    }
    /// Host-socket epoll interest for a connected data stream: read (IN) unless
    /// RX is paused for credit/half-close, plus write (OUT) whenever there are
    /// buffered guest->host bytes still to flush. Keeping the two composable is
    /// what lets a stalled send keep OUT armed without losing the RX side.
    fn conn_evset(&self) -> EventSet {
        connected_event_set(
            self.rx_paused,
            !self.tx_buf.is_empty() || !self.preamble.is_empty(),
        )
    }

    fn repoll(&self) -> Option<(u64, ProxyRawHandle, EventSet)> {
        Some((self.id, raw_handle(&self.sock), self.conn_evset()))
    }

    /// Non-blocking drain of `tx_buf` to the host socket. Advances `tx_cnt` for
    /// bytes actually written. Returns Ok(true) if any bytes reached the host,
    /// Ok(false) if none could be sent right now (WouldBlock or empty), Err(())
    /// if the host socket failed and the connection must be reset.
    fn flush_tx(&mut self) -> Result<bool, ()> {
        let mut advanced = false;
        // The interceptor preamble goes first and is not guest data: it never
        // advances `tx_cnt`. Until it is fully out, guest bytes must wait.
        while !self.preamble.is_empty() {
            let front = self.preamble.as_slices().0;
            match self.sock.send(front) {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    self.preamble.drain(..n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!(
                        "flush_tx: interceptor preamble send failed id={}: {e}",
                        self.id
                    );
                    return Err(());
                }
            }
        }
        while !self.tx_buf.is_empty() {
            let front = self.tx_buf.as_slices().0;
            match self.sock.send(front) {
                Ok(0) => break,
                Ok(n) => {
                    self.tx_cnt += Wrapping(n as u32);
                    self.tx_buf.drain(..n);
                    advanced = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!("flush_tx: host send failed id={}: {e}", self.id);
                    return Err(());
                }
            }
        }
        Ok(advanced)
    }

    /// Emit a vsock credit update to the guest if `tx_cnt` has advanced by at
    /// least half the guest's advertised buffer since the last one. Returns
    /// whether a packet was pushed (caller should signal the queue).
    fn maybe_send_credit_update(&mut self) -> bool {
        if self.peer_buf_alloc != 0
            && (self.tx_cnt - self.last_tx_cnt_sent).0 >= self.peer_buf_alloc / 2
        {
            self.last_tx_cnt_sent = self.tx_cnt;
            let rx = MuxerRx::CreditUpdate {
                local_port: self.local_port,
                peer_port: self.peer_port,
                fwd_cnt: self.tx_cnt.0,
            };
            push_packet(
                self.cid,
                rx,
                &self.rxq,
                &self.queue,
                &self.mem,
                &self.snapshot_gate,
            );
            true
        } else {
            false
        }
    }
}

impl Proxy for TsiStreamProxy {
    fn set_host_option(&mut self, req: &super::host_sockopt::OptionRequest) -> Result<(), i32> {
        req.apply(&self.sock)
    }

    fn bind_host(&mut self, req: &BindRequest) -> Result<VsockAddr, i32> {
        if self.host_bound.is_some() || self.status != ProxyStatus::Idle {
            return Err(-libc::EINVAL);
        }
        let addr = bind_inet(&self.sock, self.family, req)?;
        self.host_bound = Some(addr);
        Ok(addr.into())
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

    fn listener_desc(&self) -> Option<ListenerDesc> {
        if (self.status == ProxyStatus::Listening || self.status == ProxyStatus::WaitingOnAccept)
            && self.listen_guest_port != 0
        {
            let family = match self.family {
                Family::Inet => defs::LINUX_AF_INET,
                Family::Inet6 => defs::LINUX_AF_INET6,
                #[cfg(unix)]
                Family::Unix => return None,
            };
            Some(ListenerDesc {
                family,
                peer_port: self.peer_port,
                control_port: self.control_port,
                guest_port: self.listen_guest_port,
                backlog: self.listen_backlog,
            })
        } else {
            None
        }
    }

    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate {
        // The guest may use a dedicated reply socket for asynchronous dials.
        self.control_port = pkt.src_port();
        if !req.addr.suits_family(self.family) {
            warn!(
                "connect: id={} refused address {} for its family",
                self.id, req.addr
            );
            return self.dial(Err(std::io::Error::from_raw_os_error(libc::EINVAL)));
        }
        let connect_addr: std::io::Result<socket2::SockAddr> = match req.addr.inet() {
            Some(inet) => Ok(inet.into()),
            #[cfg(target_os = "linux")]
            None => match req.addr.unix_path() {
                Some(p) => socket2::SockAddr::unix(p),
                None => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            },
            #[cfg(not(target_os = "linux"))]
            None => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
        };
        self.dial(connect_addr)
    }

    fn confirm_connect(&mut self, pkt: &VsockPacket) -> Option<ProxyUpdate> {
        debug!(
            "confirm_connect: local_port={} peer_port={}, src_port={}, dst_port={}",
            pkt.dst_port(),
            pkt.src_port(),
            self.local_port,
            self.peer_port,
        );

        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        self.local_port = pkt.dst_port();
        self.peer_port = pkt.src_port();

        // This response goes to the connection.
        let rx = MuxerRx::OpResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
        };
        push_packet(
            self.cid,
            rx,
            &self.rxq,
            &self.queue,
            &self.mem,
            &self.snapshot_gate,
        );

        // Now that the vsock transport is fully established, start listening
        // for events in the TCP socket again.
        self.rx_paused = false;
        Some(ProxyUpdate {
            polling: self.repoll(),
            ..Default::default()
        })
    }

    fn connect_intercepted(
        &mut self,
        pkt: &VsockPacket,
        req: TsiConnectReq,
        intercept: &StreamIntercept,
    ) -> ProxyUpdate {
        self.control_port = pkt.src_port();
        let Some(destination) = req.addr.inet() else {
            return self.dial(Err(std::io::Error::from_raw_os_error(libc::EINVAL)));
        };
        // The guest's socket family need not match the interceptor's. Replace
        // the transport before registering it for polling, but retain any
        // explicit reservation independently of that transport's endpoint.
        let wanted = if intercept.endpoint.is_ipv4() {
            (Family::Inet, Domain::IPV4)
        } else {
            (Family::Inet6, Domain::IPV6)
        };
        if self.family != wanted.0 {
            match Socket::new(wanted.1, Type::STREAM, None) {
                Ok(sock) => {
                    if let Err(error) = sock
                        .set_nonblocking(true)
                        .and_then(|()| super::host_sockopt::copy_tcp_options(&self.sock, &sock))
                    {
                        return self.dial(Err(error));
                    }
                    let original = std::mem::replace(&mut self.sock, sock);
                    if self.host_bound.is_some() {
                        self.intercept_reservation = Some(original);
                    }
                }
                Err(e) => return self.dial(Err(e)),
            }
        }
        self.intercept_peer = Some(destination);
        self.preamble = intercept.preamble(destination).into();
        self.awaiting_verdict = true;
        debug!(
            "connect: redirecting {} to interceptor {}",
            destination, intercept.endpoint
        );
        self.dial(Ok(intercept.endpoint.into()))
    }

    fn getpeername(&mut self, pkt: &VsockPacket) {
        debug!("getpeername: id={}", self.id);

        let local = pkt.read_getname_req().is_some_and(|req| req.peer == 0);
        let peer = if local {
            self.guest_local_addr()
        } else {
            match self.intercept_peer {
                Some(destination) => Ok(socket2::SockAddr::from(destination)),
                None => self.sock.peer_addr(),
            }
        };
        let (result, addr_len, addr): (i32, u32, VsockAddr) = match peer {
            Ok(sa) => match sa.as_socket() {
                Some(socket_addr) => {
                    let va = VsockAddr::Inet(socket_addr);
                    let len = va.linux_len();
                    (0, len, va)
                }
                None => (
                    -libc::EINVAL,
                    0,
                    VsockAddr::Inet(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()),
                ),
            },
            Err(e) => (
                -sys::to_linux_errno(&e),
                0,
                VsockAddr::Inet(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()),
            ),
        };

        let data = TsiGetnameRsp {
            result,
            addr_len,
            addr,
        };

        debug!("getpeername: reply={data:?}");

        // This response goes to the control port (DGRAM).
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

        // If the proxy is already closed (e.g. remote server closed the connection
        // while the guest was idle), send RST immediately so the guest gets a clean
        // error instead of writing into the void and timing out.
        if self.status == ProxyStatus::Closed || self.status == ProxyStatus::PeerClosed {
            debug!(
                "sendmsg: proxy closed/peer-closed, sending RST: id={}",
                self.id
            );
            self.push_reset();
            return ProxyUpdate {
                signal_queue: true,
                ..Default::default()
            };
        }

        let mut update = ProxyUpdate::default();

        // Accept the whole buffer from the guest (a vsock data packet is
        // all-or-nothing — there is no way to tell the guest we took only part),
        // then drain as much as the host socket will take right now.
        // A guest honouring the window we advertise (buf_alloc = CONN_TX_BUF_SIZE,
        // fwd_cnt = flushed bytes) never has more than that unflushed.
        let accepted = match pkt.data() {
            Some(buf) if self.tx_buf.len() + buf.len() > defs::CONN_TX_BUF_SIZE => {
                warn!(
                    "sendmsg: guest overran its tx window, resetting id={}",
                    self.id
                );
                Err(())
            }
            Some(buf) => {
                self.tx_buf.extend(buf.iter().copied());
                Ok(())
            }
            None => Ok(()),
        };

        match accepted.and_then(|()| self.flush_tx()) {
            Ok(advanced) => {
                if advanced && self.maybe_send_credit_update() {
                    update.signal_queue = true;
                }
                update.polling = self.repoll();
            }
            Err(()) => {
                self.push_reset();
                self.status = ProxyStatus::Closed;
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
                update.signal_queue = true;
                update.remove_proxy = ProxyRemoval::Deferred;
            }
        }

        update
    }

    fn sendto_addr(&mut self, _req: TsiSendtoAddr) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn listen(
        &mut self,
        pkt: &VsockPacket,
        req: TsiListenReq,
        host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        debug!(
            "listen: id={} vm_port={} backlog={}",
            self.id, req.vm_port, req.backlog
        );
        let mut update = ProxyUpdate::default();

        let result = self.try_listen(&req, host_port_map);

        // This packet goes to the control port (DGRAM).
        let rx = MuxerRx::ListenResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            result,
        };
        push_packet(
            self.cid,
            rx,
            &self.rxq,
            &self.queue,
            &self.mem,
            &self.snapshot_gate,
        );

        if result == 0 {
            self.peer_port = req.vm_port;
            self.status = ProxyStatus::Listening;
            update.polling = Some((self.id, raw_handle(&self.sock), EventSet::IN));
        }

        update
    }

    fn accept(&mut self, req: TsiAcceptReq) -> ProxyUpdate {
        debug!("accept: id={} flags={}", req.peer_port, req.flags);

        let mut update = ProxyUpdate::default();

        if self.pending_accepts > 0 {
            self.pending_accepts -= 1;
            self.push_accept_rsp(0);
            update.signal_queue = true;
        } else if (req.flags & defs::LINUX_O_NONBLOCK) != 0 {
            self.push_accept_rsp(-LINUX_EAGAIN);
            update.signal_queue = true;
        } else {
            self.status = ProxyStatus::WaitingOnAccept;
        }

        update
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

        self.status = ProxyStatus::Connected;

        self.rx_paused = false;
        ProxyUpdate {
            polling: self.repoll(),
            ..Default::default()
        }
    }

    fn push_op_request(&self) {
        debug!(
            "push_op_request: id={}, local_port={} peer_port={}",
            self.id, self.local_port, self.peer_port
        );

        // This packet goes to the connection.
        let rx = MuxerRx::OpRequest {
            local_port: self.local_port,
            peer_port: self.peer_port,
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

    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        debug!(
            "process_op_response: id={} src_port={} dst_port={}",
            self.id,
            pkt.src_port(),
            pkt.dst_port()
        );

        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        self.switch_to_connected();

        self.rx_paused = false;
        ProxyUpdate {
            polling: self.repoll(),
            push_accept: Some((self.id, self.parent_id)),
            ..Default::default()
        }
    }

    fn enqueue_accept(&mut self) {
        debug!("enqueue_accept: control_port: {}", self.control_port);

        if self.status == ProxyStatus::WaitingOnAccept {
            self.status = ProxyStatus::Listening;
            self.push_accept_rsp(0);
        } else {
            self.pending_accepts += 1;
        }
    }

    fn push_accept_rsp(&self, result: i32) {
        debug!(
            "push_accept_rsp: control_port: {}, result: {}",
            self.control_port, result
        );

        // This packet goes to the control port (DGRAM).
        let rx = MuxerRx::AcceptResponse {
            local_port: 1030,
            peer_port: self.control_port,
            result,
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

    fn shutdown(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        // Linux semantics for shutting down a LISTENING socket: any blocked
        // accept() fails with EINVAL. Without waking it, the guest acceptor —
        // and every syscall serialized behind the in-kernel socket lock it
        // holds (including this shutdown's caller) — hangs forever.
        if self.status == ProxyStatus::WaitingOnAccept {
            self.status = ProxyStatus::Listening;
            self.push_accept_rsp(-libc::EINVAL);
            return ProxyUpdate {
                signal_queue: true,
                ..Default::default()
            };
        }
        if self.status == ProxyStatus::Listening {
            // Host-side TcpListener has no shutdown; nothing else to do.
            return ProxyUpdate::default();
        }

        let recv_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
        let send_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;

        let how = if recv_off && send_off {
            std::net::Shutdown::Both
        } else if recv_off {
            std::net::Shutdown::Read
        } else {
            std::net::Shutdown::Write
        };

        if let Err(e) = self.sock.shutdown(how) {
            warn!("error sending shutdown to socket: {e}");
        }
        ProxyUpdate::default()
    }

    fn release(&mut self) -> ProxyUpdate {
        debug!(
            "release: id={}, tx_cnt={}, last_tx_cnt={}",
            self.id, self.tx_cnt, self.last_tx_cnt_sent
        );
        // The guest closed its socket. With no guest bytes still waiting for
        // the host socket, close it now: holding it through the reaper's grace
        // period kept one host descriptor per closed connection for 5 s, so a
        // guest opening and closing a few thousand connections a second held
        // tens of thousands of descriptors and hit the process's limit. Bytes
        // still buffered keep the deferral so they get their chance to drain.
        let remove_proxy = if self.status == ProxyStatus::Listening
            || (self.tx_buf.is_empty() && self.preamble.is_empty())
        {
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

        if self.awaiting_verdict && self.status == ProxyStatus::Connecting {
            self.advance_verdict(&mut update);
            return update;
        }

        let connect_events = EventSet::OUT | EventSet::HANG_UP;
        #[cfg(target_os = "linux")]
        let connect_events = connect_events | EventSet::ERROR;
        if self.status == ProxyStatus::Connecting && evset.intersects(connect_events) {
            // Writability means that the nonblocking dial finished, not that
            // it succeeded. An error can arrive without HANG_UP (or without
            // OUT on Linux); consume SO_ERROR before acknowledging the dial.
            match self.sock.take_error() {
                Ok(Some(error)) | Err(error) => {
                    self.fail_connect(&mut update, sys::to_linux_errno(&error));
                }
                Ok(None) if evset.contains(EventSet::OUT) && !evset.contains(EventSet::HANG_UP) => {
                    self.switch_to_connected();
                    self.push_connect_rsp(0);
                    update.signal_queue = true;
                    // Wait for OP_REQUEST to establish the guest transport
                    // before polling this socket for data.
                    update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
                }
                Ok(None) => self.fail_connect(&mut update, LINUX_ECONNREFUSED),
            }
            return update;
        }

        if evset.contains(EventSet::HANG_UP) {
            debug!("process_event: HANG_UP");
            if self.status == ProxyStatus::Connected {
                // Drain any remaining data before signaling closure.
                let (signal_queue, _) = self.recv_pkt();
                update.signal_queue = signal_queue;
                // Send RST to force-close the vsock connection (see git history
                // for why RST and not SHUTDOWN).
                self.push_reset();
                self.status = ProxyStatus::Closed;
                update.signal_queue = true;
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
                update.remove_proxy = ProxyRemoval::Deferred;
                return update;
            } else {
                self.push_reset();
                self.status = ProxyStatus::Closed;
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
                update.signal_queue = true;
                update.remove_proxy = if self.status == ProxyStatus::Listening {
                    ProxyRemoval::Immediate
                } else {
                    ProxyRemoval::Deferred
                };
                return update;
            }
        }

        if evset.contains(EventSet::IN) {
            debug!("process_event: IN");
            if self.status == ProxyStatus::Connected {
                let (signal_queue, wait_credit) = self.recv_pkt();
                update.signal_queue = signal_queue;

                if wait_credit && self.status != ProxyStatus::WaitingCreditUpdate {
                    self.status = ProxyStatus::WaitingCreditUpdate;
                    let rx = MuxerRx::CreditRequest {
                        local_port: self.local_port,
                        peer_port: self.peer_port,
                        fwd_cnt: self.tx_cnt.0,
                    };
                    update.push_credit_req = Some(rx);
                }

                if self.status == ProxyStatus::PeerClosed {
                    // The remote peer half-closed its send side (our recv hit
                    // EOF). Forward a partial SHUTDOWN so the guest sees an
                    // orderly end-of-data on its receive half, but keep the proxy
                    // alive so guest→remote output still flows — a full RST here
                    // silently drops output the guest is still sending after a
                    // remote server that closes only its write side. Stop polling
                    // the fd (the EOF is level-triggered and would spin); the
                    // proxy is reaped when the guest closes its half.
                    debug!(
                        "process_event: peer half-closed, forwarding shutdown: id={}",
                        self.id
                    );
                    if !self.local_read_shutdown {
                        self.push_shutdown(uapi::VSOCK_FLAGS_SHUTDOWN_SEND);
                        self.local_read_shutdown = true;
                    }
                    self.status = ProxyStatus::Connected;
                    update.signal_queue = true;
                    self.rx_paused = true;
                    update.polling = self.repoll();
                    return update;
                } else if self.status == ProxyStatus::WaitingCreditUpdate {
                    debug!("process_event: WaitingCreditUpdate");
                    self.rx_paused = true;
                    update.polling = self.repoll();
                }
            } else if self.status == ProxyStatus::Listening
                || self.status == ProxyStatus::WaitingOnAccept
            {
                match self.sock.accept() {
                    Ok((new_sock, _addr)) => {
                        // Use the original vsock ephemeral port (encoded in the
                        // high 32 bits of self.id) rather than self.peer_port,
                        // which listen() overwrites with the VM TCP port.
                        let vsock_peer_port = (self.id >> 32) as u32;
                        update.new_proxy =
                            Some((vsock_peer_port, new_sock, self.family, NewProxyType::Tcp));
                    }
                    Err(e) => warn!("error accepting connection: id={}, err={}", self.id, e),
                };
                update.signal_queue = true;
                return update;
            } else {
                debug!("EventSet::IN while not connected: {:?}", self.status);
            }
        }

        if evset.contains(EventSet::OUT) {
            debug!("process_event: OUT");
            if self.status == ProxyStatus::Connected {
                // The host socket drained: flush buffered guest->host bytes and,
                // if enough progressed, re-open the guest's credit window. This
                // is what makes the non-blocking send in `sendmsg` complete
                // without ever blocking the muxer thread (#1093).
                match self.flush_tx() {
                    Ok(advanced) => {
                        if advanced && self.maybe_send_credit_update() {
                            update.signal_queue = true;
                        }
                        update.polling = self.repoll();
                    }
                    Err(()) => {
                        self.push_reset();
                        self.status = ProxyStatus::Closed;
                        update.polling =
                            Some((self.id(), raw_handle(&self.sock), EventSet::empty()));
                        update.signal_queue = true;
                        update.remove_proxy = ProxyRemoval::Deferred;
                    }
                }
            } else {
                debug!("EventSet::OUT while not connecting/connected");
            }
        }

        update
    }
}

#[cfg(target_os = "linux")]
impl Drop for TsiStreamProxy {
    fn drop(&mut self) {
        // The guest can replace what is at the path while we listen; remove it
        // only if it is still a socket node.
        if let Some(path) = &self.unixsock_path
            && super::vsock_addr::is_unix_socket_node(path)
        {
            _ = fs::remove_file(path);
        }
    }
}
