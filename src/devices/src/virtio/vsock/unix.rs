use super::{
    defs::{self, uapi},
    proxy::{ProxyRemoval, RecvPkt},
};

use std::collections::{HashMap, VecDeque};
use std::net::Shutdown;
use std::num::Wrapping;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use socket2::{Domain, SockAddr, Socket, Type};

use super::super::Queue as VirtQueue;
use super::muxer::{MuxerRx, push_packet};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket};
use super::proxy::{
    Family, NewProxyType, Proxy, ProxyError, ProxyRawHandle, ProxyStatus, ProxyUpdate, raw_handle,
};
use super::sys;
use utils::epoll::EventSet;

use vm_memory::GuestMemoryMmap;

pub struct UnixProxy {
    id: u64,
    cid: u64,
    sock: Socket,
    pub status: ProxyStatus,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    path: PathBuf,
    peer_port: u32,
    local_port: u32,
    control_port: u32,
    peer_fwd_cnt: Wrapping<u32>,
    peer_buf_alloc: u32,
    tx_cnt: Wrapping<u32>,
    last_tx_cnt_sent: Wrapping<u32>,
    push_cnt: Wrapping<u32>,
    rx_cnt: Wrapping<u32>,
    /// Number of OP_REQUEST retries after guest RST during ReverseInit.
    connect_retries: u32,
    /// Set once the host peer half-closed its send side (our recv hit EOF) and
    /// we forwarded a partial SHUTDOWN to the guest. Guards against re-sending
    /// the shutdown and marks that host→guest is done while guest→host still
    /// flows.
    local_read_shutdown: bool,
    /// Guest->host bytes buffered because the host socket was full (a stalled
    /// remote peer — #1093). Drained on EPOLLOUT; bounded by the guest's own
    /// vsock window since `tx_cnt` advances only for flushed bytes.
    tx_buf: VecDeque<u8>,
    /// True while reading the host socket is paused for credit/half-close; kept
    /// separate from epoll interest so TX-flush (OUT) and RX-read (IN) compose.
    rx_paused: bool,
}

/// Safety cap on OP_REQUEST retries. Each retry is naturally paced by
/// the vsock virtio round-trip (~100-500μs), so 10000 retries ≈ 1-5s.
const MAX_CONNECT_RETRIES: u32 = 10000;

/// Create a nonblocking AF_UNIX stream socket for the host-IPC proxy.
fn proxy_sock_create(id: u64) -> Result<Socket, ProxyError> {
    let sock = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(ProxyError::CreatingSocket)?;

    if let Err(e) = sock.set_nonblocking(true) {
        warn!("error switching to non-blocking: id={id}, err={e}");
    }

    Ok(sock)
}

impl UnixProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        cid: u64,
        local_port: u32,
        control_port: u32,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        path: PathBuf,
    ) -> Result<Self, ProxyError> {
        let sock = proxy_sock_create(id)?;

        Ok(UnixProxy {
            id,
            cid,
            local_port,
            peer_port: 0,
            control_port,
            sock,
            status: ProxyStatus::Idle,
            mem,
            queue,
            rxq,
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            path,
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            push_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            connect_retries: 0,
            local_read_shutdown: false,
            tx_buf: VecDeque::new(),
            rx_paused: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_reverse(
        id: u64,
        cid: u64,
        local_port: u32,
        peer_port: u32,
        sock: Socket,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Self {
        debug!("new_reverse: id={id} local_port={local_port} peer_port={peer_port}");
        UnixProxy {
            id,
            cid,
            local_port,
            peer_port,
            control_port: 0,
            sock,
            status: ProxyStatus::ReverseInit,
            mem,
            queue,
            rxq,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            push_cnt: Wrapping(0),
            path: Default::default(),
            connect_retries: 0,
            local_read_shutdown: false,
            tx_buf: VecDeque::new(),
            rx_paused: false,
        }
    }

    fn switch_to_connected(&mut self) {
        self.status = ProxyStatus::Connected;
        // Keep the host socket NON-BLOCKING; guest->host sends drain via
        // `flush_tx` and buffer on WouldBlock so a stalled peer can never block
        // the vsock muxer thread. See smol-machines/smolvm#1093.
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
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    fn push_reset(&self) {
        debug!(
            "push_reset: id: {}, peer_port: {}, local_port: {}",
            self.id, self.peer_port, self.local_port
        );

        let rx = MuxerRx::Reset {
            local_port: self.local_port,
            peer_port: self.peer_port,
        };

        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    /// Forward a partial SHUTDOWN toward the guest. Used when the host peer
    /// half-closes (our recv hits EOF) so the guest sees an orderly end-of-data
    /// on its receive half while the proxy keeps forwarding guest→host — a full
    /// RST here would drop any output the guest is still sending (e.g. a
    /// hijacked Docker attach that half-closes with no stdin).
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

        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
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
                max_len
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

    fn conn_evset(&self) -> EventSet {
        let mut e = EventSet::empty();
        if !self.rx_paused {
            e |= EventSet::IN;
        }
        if !self.tx_buf.is_empty() {
            e |= EventSet::OUT;
        }
        // Edge-triggered: a partially-writable host socket would otherwise
        // re-fire OUT every cycle and spin the muxer (#1093). Both `flush_tx`
        // and `recv_pkt` drain to WouldBlock, as edge-triggering requires.
        if !e.is_empty() {
            e |= EventSet::EDGE_TRIGGERED;
        }
        e
    }

    fn repoll(&self) -> Option<(u64, ProxyRawHandle, EventSet)> {
        Some((self.id, raw_handle(&self.sock), self.conn_evset()))
    }

    fn flush_tx(&mut self) -> Result<bool, ()> {
        let mut advanced = false;
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
            push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
            true
        } else {
            false
        }
    }
}

impl Proxy for UnixProxy {
    fn poll_handle(&self) -> ProxyRawHandle {
        raw_handle(&self.sock)
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    fn connect(&mut self, _pkt: &VsockPacket, _req: TsiConnectReq) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        let result = match SockAddr::unix(&self.path) {
            Ok(addr) => match self.sock.connect(&addr) {
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
                    debug!("Error connecting: {e}");
                    -sys::to_linux_errno(&e)
                }
            },
            Err(e) => {
                debug!("Error building unix address: {e}");
                -sys::to_linux_errno(&e)
            }
        };

        if self.status == ProxyStatus::Connecting {
            update.polling = Some((
                self.id,
                raw_handle(&self.sock),
                EventSet::IN | EventSet::OUT,
            ));
        } else {
            if self.status == ProxyStatus::Connected {
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::IN));
            }
            self.push_connect_rsp(result);
        }

        update
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
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);

        None
    }

    fn getpeername(&mut self, _pkt: &VsockPacket) {
        todo!();
    }

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        // Accept the whole buffer (vsock is all-or-nothing), then drain what the
        // host socket will take now. `tx_cnt` advances only for flushed bytes, so
        // a stalled host peer backpressures the guest via its own vsock window and
        // never blocks the muxer thread. See smol-machines/smolvm#1093.
        if let Some(buf) = pkt.buf() {
            self.tx_buf.extend(buf.iter().copied());
        }

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
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
                update.signal_queue = true;
                update.remove_proxy = ProxyRemoval::Deferred;
            }
        }

        update
    }

    fn sendto_addr(&mut self, _req: TsiSendtoAddr) -> ProxyUpdate {
        todo!();
    }

    fn listen(
        &mut self,
        _pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        todo!();
    }

    fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
        todo!();
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
        info!(
            "[VSOCK_TIMING] push_op_request: id={:#x} local_port={} peer_port={} (expecting RESPONSE with src_port={} dst_port={})",
            self.id, self.local_port, self.peer_port, self.peer_port, self.local_port
        );

        // This packet goes to the connection.
        let rx = MuxerRx::OpRequest {
            local_port: self.local_port,
            peer_port: self.peer_port,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
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
            ..Default::default()
        }
    }

    fn enqueue_accept(&mut self) {
        todo!();
    }

    fn shutdown(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        let recv_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
        let send_off = pkt.flags() & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;

        let how = if recv_off && send_off {
            Shutdown::Both
        } else if recv_off {
            Shutdown::Read
        } else {
            Shutdown::Write
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

        // If we're in ReverseInit (sent OP_REQUEST, got RST because guest
        // listener isn't ready yet), immediately re-send OP_REQUEST.
        // The vsock virtio round-trip (~100-500μs) naturally throttles retries.
        if self.status == ProxyStatus::ReverseInit && self.connect_retries < MAX_CONNECT_RETRIES {
            self.connect_retries += 1;
            if self.connect_retries.is_multiple_of(100) {
                debug!(
                    "connect retry #{} for id={:#x}",
                    self.connect_retries, self.id
                );
            }
            self.push_op_request();
            return ProxyUpdate::default();
        }

        if self.connect_retries >= MAX_CONNECT_RETRIES {
            warn!(
                "giving up after {} connect retries for id={:#x}",
                self.connect_retries, self.id
            );
        }

        ProxyUpdate {
            remove_proxy: ProxyRemoval::Deferred,
            ..Default::default()
        }
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        if evset.contains(EventSet::HANG_UP) {
            debug!("process_event: HANG_UP");

            if self.status == ProxyStatus::Connecting {
                self.push_connect_rsp(-libc::ECONNREFUSED);
                self.status = ProxyStatus::Closed;
                update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
                update.signal_queue = true;
                update.remove_proxy = ProxyRemoval::Deferred;
                return update;
            } else if self.status == ProxyStatus::Connected {
                // Drain any remaining data before signaling closure.
                let (signal_queue, _) = self.recv_pkt();
                update.signal_queue = signal_queue;
                // Send RST to force-close — see tsi_stream.rs HANG_UP handler.
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
                update.remove_proxy = ProxyRemoval::Deferred;
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
                    // The host peer half-closed its send side (our recv hit EOF).
                    // Forward a partial SHUTDOWN so the guest sees an orderly
                    // end-of-data on its receive half, but keep the proxy alive so
                    // guest→host output still flows — a full RST here silently
                    // drops output the guest is still sending (e.g. a hijacked
                    // Docker attach that half-closes with no stdin while the
                    // daemon streams back). Stop polling the fd (the EOF is
                    // level-triggered and would spin); the proxy is reaped when
                    // the guest closes its half (OP_RST → release()).
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
            } else {
                debug!("EventSet::IN while not connected: {:?}", self.status);
            }
        }

        if evset.contains(EventSet::OUT) {
            debug!("process_event: OUT");
            if self.status == ProxyStatus::Connecting {
                self.switch_to_connected();
                self.push_connect_rsp(0);
                update.signal_queue = true;
                update.polling = Some((self.id(), raw_handle(&self.sock), EventSet::IN));
            } else if self.status == ProxyStatus::Connected {
                // Host socket drained: flush buffered guest->host bytes and
                // re-open the guest's credit window without blocking (#1093).
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
                error!("EventSet::OUT while not connecting/connected");
            }
        }

        update
    }
}

pub struct UnixAcceptorProxy {
    id: u64,
    sock: Socket,
    peer_port: u32,
}

impl UnixAcceptorProxy {
    pub fn new(id: u64, path: &PathBuf, peer_port: u32) -> Result<Self, ProxyError> {
        let start = std::time::Instant::now();
        info!(
            "[VSOCK_TIMING] UnixAcceptorProxy::new() id={:#x} path={:?} peer_port={}",
            id, path, peer_port
        );

        let sock =
            Socket::new(Domain::UNIX, Type::STREAM, None).map_err(ProxyError::CreatingSocket)?;
        info!(
            "[VSOCK_TIMING] UnixAcceptorProxy socket created in {:?}",
            start.elapsed()
        );

        let addr = SockAddr::unix(path).map_err(ProxyError::CreatingSocket)?;
        sock.bind(&addr).map_err(ProxyError::CreatingSocket)?;
        info!(
            "[VSOCK_TIMING] UnixAcceptorProxy bound to {:?} in {:?}",
            path,
            start.elapsed()
        );

        sock.listen(5).map_err(ProxyError::CreatingSocket)?;
        info!(
            "[VSOCK_TIMING] UnixAcceptorProxy listening, total setup {:?}",
            start.elapsed()
        );

        Ok(UnixAcceptorProxy {
            id,
            sock,
            peer_port,
        })
    }
}

impl Proxy for UnixAcceptorProxy {
    fn poll_handle(&self) -> ProxyRawHandle {
        raw_handle(&self.sock)
    }

    fn id(&self) -> u64 {
        self.id
    }
    fn is_listener(&self) -> bool {
        true
    }
    fn status(&self) -> ProxyStatus {
        ProxyStatus::WaitingOnAccept
    }
    fn connect(&mut self, _: &VsockPacket, _: TsiConnectReq) -> ProxyUpdate {
        unreachable!()
    }
    fn getpeername(&mut self, _: &VsockPacket) {
        unreachable!()
    }
    fn sendmsg(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn sendto_addr(&mut self, _: TsiSendtoAddr) -> ProxyUpdate {
        unreachable!()
    }
    fn listen(
        &mut self,
        _: &VsockPacket,
        _: TsiListenReq,
        _: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        unreachable!()
    }
    fn accept(&mut self, _: TsiAcceptReq) -> ProxyUpdate {
        unreachable!()
    }
    fn update_peer_credit(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn process_op_response(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn release(&mut self) -> ProxyUpdate {
        unreachable!()
    }
    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        if evset.contains(EventSet::HANG_UP) {
            debug!("process_event: HANG_UP");
            update.polling = Some((self.id, raw_handle(&self.sock), EventSet::empty()));
            update.signal_queue = true;
            update.remove_proxy = ProxyRemoval::Deferred;
            return update;
        }
        if evset.contains(EventSet::IN) {
            info!(
                "[VSOCK_TIMING] UnixAcceptorProxy id={:#x} received IN event, accepting connection",
                self.id
            );
            let accept_start = std::time::Instant::now();

            match self.sock.accept() {
                Ok((new_sock, _addr)) => {
                    info!(
                        "[VSOCK_TIMING] UnixAcceptorProxy id={:#x} accepted connection in {:?}",
                        self.id,
                        accept_start.elapsed()
                    );
                    update.new_proxy = Some((
                        self.peer_port,
                        new_sock,
                        ACCEPTOR_FAMILY,
                        NewProxyType::Unix,
                    ));
                }
                Err(e) => warn!("error accepting connection: id={}, err={}", self.id, e),
            };
            update.signal_queue = true;
        }
        update
    }
}

/// `Family` value attached to a host-IPC accepted connection. The muxer only
/// uses the family for the `Tcp` proxy variant; the `Unix` variant ignores it,
/// so on Windows (which has no `Family::Unix`) any value works. We use the
/// AF_UNIX family on Unix hosts and a harmless placeholder on Windows.
#[cfg(unix)]
const ACCEPTOR_FAMILY: Family = Family::Unix;
#[cfg(windows)]
const ACCEPTOR_FAMILY: Family = Family::Inet;
