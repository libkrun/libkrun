use std::collections::{HashMap, VecDeque};
use std::io;
use std::num::Wrapping;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::super::Queue as VirtQueue;
use super::defs;
use super::defs::uapi;
use super::muxer::{MuxerRx, push_packet};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, VsockPacket};

use super::proxy::{
    AddressFamily, AsRawFd, OwnedFd, Proxy, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate,
    RawFd, RecvPkt,
};
#[cfg(windows)]
use super::tsi_sockopt::GuestOnlyOptions;

use utils::epoll::EventSet;
#[cfg(windows)]
use utils::epoll::{Epoll, EpollEvent};
use vm_memory::GuestMemoryMmap;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

struct SendQueue {
    buf: VecDeque<u8>,
    limit: usize,
}

enum EnqueueError {
    Capacity,
    Alloc,
}

impl SendQueue {
    fn new(limit: usize) -> Self {
        SendQueue {
            buf: VecDeque::new(),
            limit,
        }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn remaining(&self) -> usize {
        self.limit - self.buf.len()
    }

    fn push(&mut self, data: &[u8]) -> Result<(), EnqueueError> {
        if data.len() > self.remaining() {
            return Err(EnqueueError::Capacity);
        }
        let required = self.buf.len() + data.len();
        if required > self.buf.capacity() {
            let capacity = required.max(self.buf.capacity() * 2).min(self.limit);
            self.buf
                .try_reserve_exact(capacity - self.buf.len())
                .map_err(|_| EnqueueError::Alloc)?;
        }
        self.buf.extend(data);
        Ok(())
    }

    fn front(&self, max: usize) -> &[u8] {
        let (front, _) = self.buf.as_slices();
        &front[..front.len().min(max)]
    }

    fn consume(&mut self, count: usize) {
        self.buf.drain(..count);
    }

    fn clear(&mut self) {
        self.buf = VecDeque::new();
    }
}

#[cfg(unix)]
const TX_DRAIN_BATCH: usize = 1024 * 1024;
// Winsock only wakes a stalled writer again after a send reports WSAEWOULDBLOCK.
#[cfg(windows)]
const TX_DRAIN_BATCH: usize = defs::CONN_TX_BUF_SIZE;

pub struct TsiStreamProxy {
    pub(crate) id: u64,
    pub(crate) cid: u64,
    pub(crate) parent_id: u64,
    pub(crate) family: AddressFamily,
    pub(crate) local_port: u32,
    pub(crate) peer_port: u32,
    pub(crate) control_port: u32,
    pub(crate) connect_request_id: u64,
    pub(crate) accept_request_id: u64,
    pub(crate) fd: OwnedFd,
    pub status: ProxyStatus,
    pub(crate) mem: GuestMemoryMmap,
    pub(crate) queue: Arc<Mutex<VirtQueue>>,
    pub(crate) rxq: Arc<Mutex<MuxerRxQ>>,
    pub(crate) rx_cnt: Wrapping<u32>,
    pub(crate) tx_cnt: Wrapping<u32>,
    pub(crate) peer_buf_alloc: u32,
    pub(crate) peer_fwd_cnt: Wrapping<u32>,
    pub(crate) peer_shutdown: u32,
    pub(crate) host_read_closed: bool,
    pub(crate) push_cnt: Wrapping<u32>,
    pub(crate) pending_accepts: u64,
    send_queue: SendQueue,
    #[cfg(target_os = "linux")]
    unixsock_path: Option<unix::PinnedUnixPath>,
    #[cfg(not(target_os = "linux"))]
    unixsock_path: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    pub(crate) protected_unix_paths: Vec<PathBuf>,
    #[cfg(windows)]
    guest_options: GuestOnlyOptions,
}

const SHUTDOWN_MASK: u32 = uapi::VSOCK_FLAGS_SHUTDOWN_RCV | uapi::VSOCK_FLAGS_SHUTDOWN_SEND;

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
    ) -> Result<Self, ProxyError> {
        let (fd, family) = sys::create_socket(id, family)?;

        Ok(TsiStreamProxy {
            id,
            cid,
            parent_id: 0,
            family,
            local_port,
            peer_port,
            control_port,
            connect_request_id: 0,
            accept_request_id: 0,
            fd,
            status: ProxyStatus::Idle,
            mem,
            queue,
            rxq,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            peer_shutdown: 0,
            host_read_closed: false,
            push_cnt: Wrapping(0),
            pending_accepts: 0,
            send_queue: SendQueue::new(defs::CONN_TX_BUF_SIZE),
            unixsock_path: None,
            #[cfg(target_os = "linux")]
            protected_unix_paths: Vec::new(),
            #[cfg(windows)]
            guest_options: GuestOnlyOptions::default(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_reverse(
        id: u64,
        cid: u64,
        parent_id: u64,
        family: AddressFamily,
        local_port: u32,
        peer_port: u32,
        fd: OwnedFd,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
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
            connect_request_id: 0,
            accept_request_id: 0,
            fd,
            status: ProxyStatus::ReverseInit,
            mem,
            queue,
            rxq,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            peer_shutdown: 0,
            host_read_closed: false,
            push_cnt: Wrapping(0),
            pending_accepts: 0,
            send_queue: SendQueue::new(defs::CONN_TX_BUF_SIZE),
            unixsock_path: None,
            #[cfg(target_os = "linux")]
            protected_unix_paths: Vec::new(),
            #[cfg(windows)]
            guest_options: GuestOnlyOptions::default(),
        }
    }

    pub(crate) fn init_data_pkt(&self, pkt: &mut VsockPacket) {
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

    pub(crate) fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    fn is_established(&self) -> bool {
        matches!(
            self.status,
            ProxyStatus::Connected | ProxyStatus::WaitingCreditUpdate
        )
    }

    fn event_interest(&self) -> EventSet {
        let mut interest = EventSet::empty();
        if self.status == ProxyStatus::Connected
            && !self.host_read_closed
            && self.peer_shutdown & uapi::VSOCK_FLAGS_SHUTDOWN_RCV == 0
        {
            interest |= EventSet::IN | EventSet::READ_HANG_UP;
        }
        if !self.send_queue.is_empty() {
            interest |= EventSet::OUT;
            #[cfg(windows)]
            {
                interest |= EventSet::HANG_UP;
            }
        }
        interest
    }

    fn polling_change(&self, previous: EventSet) -> Option<(u64, RawFd, EventSet)> {
        let interest = self.event_interest();
        (interest != previous).then(|| (self.id, self.fd.as_raw_fd(), interest))
    }

    fn send_data(&mut self, data: &[u8]) -> ProxyUpdate {
        if data.is_empty()
            || !self.is_established()
            || self.peer_shutdown & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0
        {
            return ProxyUpdate::default();
        }

        if data.len() > self.send_queue.remaining() {
            return self.abort_send(EnqueueError::Capacity);
        }

        let previous = self.event_interest();
        let mut written = 0;
        if self.send_queue.is_empty() {
            written = match self.write_host(data) {
                Ok(count) => count,
                Err(err) => return self.fail_write(err),
            };
            self.tx_cnt += Wrapping(written as u32);
        }
        if written < data.len()
            && let Err(error) = self.send_queue.push(&data[written..])
        {
            return self.abort_send(error);
        }
        if written > 0 {
            self.stage_credit(false);
        }

        ProxyUpdate {
            polling: self.polling_change(previous),
            ..Default::default()
        }
    }

    fn abort_send(&mut self, error: EnqueueError) -> ProxyUpdate {
        match error {
            EnqueueError::Capacity => warn!("send queue capacity exceeded: id={}", self.id),
            EnqueueError::Alloc => error!("could not allocate send queue storage: id={}", self.id),
        }
        self.reset_after_error()
    }

    fn write_host(&self, data: &[u8]) -> io::Result<usize> {
        match sys::try_write(&self.fd, data) {
            Ok(0) => Err(io::ErrorKind::WriteZero.into()),
            Err(err) if sys::is_retryable_write_error(&err) => Ok(0),
            result => result,
        }
    }

    fn fail_write(&mut self, err: io::Error) -> ProxyUpdate {
        warn!("error writing to host socket: id={}, err={err}", self.id);
        self.reset_after_error()
    }

    fn stop_stream(&mut self) {
        self.send_queue.clear();
        self.rxq.lock().unwrap().clear_stream_credit(self.id);
        self.status = ProxyStatus::Closed;
        sys::shutdown_write(&self.fd);
        sys::shutdown_read(&self.fd);
    }

    fn reset_after_error(&mut self) -> ProxyUpdate {
        self.stop_stream();
        self.push_reset();
        ProxyUpdate {
            signal_queue: true,
            polling: Some((self.id, self.fd.as_raw_fd(), EventSet::empty())),
            ..Default::default()
        }
    }

    fn process_writable(&mut self) -> io::Result<bool> {
        let mut written = 0;
        while written < TX_DRAIN_BATCH && !self.send_queue.is_empty() {
            let chunk = self.send_queue.front(TX_DRAIN_BATCH - written);
            let count = self.write_host(chunk)?;
            if count == 0 {
                break;
            }
            self.send_queue.consume(count);
            self.tx_cnt += Wrapping(count as u32);
            written += count;
        }
        if written > 0 {
            self.stage_credit(false);
        }

        if self.send_queue.is_empty() && self.peer_shutdown & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0 {
            sys::shutdown_write(&self.fd);
            return Ok(self.finish_peer_shutdown());
        }
        Ok(false)
    }

    fn stage_credit(&self, request: bool) {
        self.rxq
            .lock()
            .unwrap()
            .stage_stream_credit(self.id, self.tx_cnt.0, request);
    }

    fn finish_peer_shutdown(&mut self) -> bool {
        if self.peer_shutdown != SHUTDOWN_MASK || !self.send_queue.is_empty() {
            return false;
        }
        self.rxq.lock().unwrap().clear_stream_credit(self.id);
        self.status = ProxyStatus::Closed;
        self.push_reset();
        true
    }

    fn read_host(&mut self, previous: EventSet) -> ProxyUpdate {
        let (signal_queue, wait_credit) = self.recv_pkt();
        if self.status == ProxyStatus::Closed {
            return self.reset_after_error();
        }
        if wait_credit {
            self.status = ProxyStatus::WaitingCreditUpdate;
            self.stage_credit(true);
        }
        ProxyUpdate {
            signal_queue,
            polling: self.polling_change(previous),
            ..Default::default()
        }
    }

    fn process_connected_event(&mut self, events: EventSet) -> ProxyUpdate {
        let previous = self.event_interest();
        let mut update = ProxyUpdate::default();
        let hangup = EventSet::HANG_UP;
        #[cfg(target_os = "linux")]
        let hangup = hangup | EventSet::ERROR;
        // HUP can arrive with unread bytes. recv() determines when the host
        // has half-closed, leaving pending writes independent of read EOF.
        if previous.contains(EventSet::IN)
            && events.intersects(EventSet::IN | EventSet::READ_HANG_UP | hangup)
        {
            update = self.read_host(previous);
        }
        if !self.send_queue.is_empty() && events.intersects(EventSet::OUT | hangup) {
            match self.process_writable() {
                Ok(signal_queue) => update.signal_queue |= signal_queue,
                Err(err) => return self.fail_write(err),
            }
        }
        update.polling = self.polling_change(previous);
        update
    }

    pub(crate) fn recv_pkt(&mut self) -> (bool, bool) {
        let mut have_used = false;
        let mut wait_credit = false;
        let mut queue = self.queue.lock().unwrap();

        while !self.host_read_closed {
            let Some(head) = queue.pop(&self.mem) else {
                break;
            };
            let len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => match sys::recv_to_pkt(self, &mut pkt) {
                    Ok(RecvPkt::WaitForCredit) => {
                        wait_credit = true;
                        0
                    }
                    Ok(RecvPkt::Read(cnt)) => {
                        self.rx_cnt += Wrapping(cnt as u32);
                        self.init_data_pkt(&mut pkt);
                        pkt.set_len(cnt as u32);
                        pkt.finish_rx().unwrap_or(0) as usize
                    }
                    Ok(RecvPkt::Close) => {
                        self.host_read_closed = true;
                        self.init_data_pkt(&mut pkt);
                        pkt.set_op(uapi::VSOCK_OP_SHUTDOWN)
                            .set_flags(uapi::VSOCK_FLAGS_SHUTDOWN_SEND)
                            .set_len(0);
                        pkt.finish_rx().unwrap_or(0) as usize
                    }
                    Ok(RecvPkt::Error) => 0,
                    Err(e) => {
                        debug!("recv_pkt: socket error: {e}");
                        self.status = ProxyStatus::Closed;
                        0
                    }
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
                self.push_cnt += Wrapping(len as u32);
                debug!(
                    "recv_pkt: pushing packet with {} bytes, push_cnt={}",
                    len, self.push_cnt
                );
                match queue.add_used(&self.mem, head.index, len as u32) {
                    Ok(()) => have_used = true,
                    Err(e) => error!("failed to add used elements to the queue: {e:?}"),
                }
            }
        }

        debug!("recv_pkt: have_used={have_used}");
        if have_used {
            self.rxq
                .lock()
                .unwrap()
                .stream_credit_piggybacked(self.id, self.tx_cnt.0);
        }
        (have_used, wait_credit)
    }

    pub(crate) fn push_connect_rsp(&self, result: i32) {
        debug!(
            "push_connect_rsp: id: {}, control_port: {}, result: {}",
            self.id, self.control_port, result
        );

        // This response goes to the control port (DGRAM).
        let rx = MuxerRx::ConnResponse {
            request_id: self.connect_request_id,
            operation: super::defs::TSI_OP_CONNECT,
            peer_port: self.control_port,
            result,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    pub(crate) fn push_reset(&self) {
        debug!(
            "push_reset: id: {}, peer_port: {}, local_port: {}",
            self.id, self.peer_port, self.local_port
        );

        // This response goes to the connection.
        let rx = MuxerRx::Reset {
            local_port: self.local_port,
            peer_port: self.peer_port,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }
}

impl Proxy for TsiStreamProxy {
    fn tsi_socket(&self) -> Option<(u16, AddressFamily)> {
        Some((super::defs::SOCK_STREAM, self.family))
    }
    fn id(&self) -> u64 {
        self.id
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    fn connect(
        &mut self,
        pkt: &VsockPacket,
        req: TsiConnectReq,
        #[cfg(windows)] epoll: &Epoll,
    ) -> ProxyUpdate {
        if self.status == ProxyStatus::Connecting {
            let rx = MuxerRx::ConnResponse {
                request_id: req.request_id,
                operation: pkt.control_operation(),
                peer_port: pkt.src_port(),
                result: -114, // Linux EALREADY
            };
            push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
            return ProxyUpdate::default();
        }
        self.control_port = pkt.src_port();
        self.connect_request_id = req.request_id;
        sys::do_connect(
            self,
            pkt,
            req,
            #[cfg(windows)]
            epoll,
        )
    }

    fn confirm_connect(&mut self, pkt: &VsockPacket) -> Option<ProxyUpdate> {
        if self.status != ProxyStatus::AwaitingRequest {
            return None;
        }

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
        self.status = ProxyStatus::Connected;

        // This response goes to the connection.
        let rx = MuxerRx::OpResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);

        // Now that the vsock transport is fully established, start listening
        // for events in the TCP socket again.
        Some(ProxyUpdate {
            polling: Some((self.id, self.fd.as_raw_fd(), self.event_interest())),
            ..Default::default()
        })
    }

    fn socket_option(&self, level: u32, name: u32, value: Option<i32>) -> Result<i32, i32> {
        #[cfg(windows)]
        if let Some(result) = self.guest_options.apply(self.family, level, name, value) {
            return Ok(result);
        }
        super::tsi_sockopt::socket_option(
            self.as_raw_fd(),
            self.family,
            super::defs::SOCK_STREAM,
            level,
            name,
            value,
        )
    }

    fn getname(&mut self, pkt: &VsockPacket, peer: bool) {
        sys::do_getname(self, pkt, peer)
    }

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        match pkt.buf() {
            Some(buf) => self.send_data(buf),
            None => ProxyUpdate::default(),
        }
    }

    fn listen(
        &mut self,
        pkt: &VsockPacket,
        req: TsiListenReq,
        host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        sys::do_listen(self, pkt, req, host_port_map)
    }

    fn accept(&mut self, req: TsiAcceptReq) -> ProxyUpdate {
        if self.status == ProxyStatus::WaitingOnAccept {
            let rx = MuxerRx::AcceptResponse {
                request_id: req.request_id,
                operation: super::defs::TSI_OP_ACCEPT,
                peer_port: self.control_port,
                result: -16, // Linux EBUSY
            };
            push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
            return ProxyUpdate::default();
        }
        self.accept_request_id = req.request_id;
        sys::do_accept(self, req)
    }

    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        sys::update_peer_credit(self, pkt)
    }

    fn push_op_request(&self) -> bool {
        debug!(
            "push_op_request: id={}, local_port={} peer_port={}",
            self.id, self.local_port, self.peer_port
        );

        // This packet goes to the connection.
        let rx = MuxerRx::OpRequest {
            local_port: self.local_port,
            peer_port: self.peer_port,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem)
    }

    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        if self.status != ProxyStatus::ReverseInit {
            return ProxyUpdate::default();
        }
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
        self.status = ProxyStatus::Connected;

        ProxyUpdate {
            polling: Some((self.id, self.fd.as_raw_fd(), self.event_interest())),
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
            request_id: self.accept_request_id,
            operation: super::defs::TSI_OP_ACCEPT,
            peer_port: self.control_port,
            result,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    fn shutdown(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        let shutdown = pkt.flags() & SHUTDOWN_MASK & !self.peer_shutdown;
        if shutdown == 0 || !self.is_established() {
            return ProxyUpdate::default();
        }

        let previous = self.event_interest();
        self.peer_shutdown |= shutdown;
        // SHUT_BOTH can fail on macOS after the peer has sent its FIN.
        if shutdown & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0 {
            sys::shutdown_read(&self.fd);
        }
        if shutdown & uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0 && self.send_queue.is_empty() {
            sys::shutdown_write(&self.fd);
        }

        ProxyUpdate {
            signal_queue: self.finish_peer_shutdown(),
            polling: self.polling_change(previous),
            ..Default::default()
        }
    }

    fn release(&mut self) -> ProxyUpdate {
        debug!("release: id={}, tx_cnt={}", self.id, self.tx_cnt);
        let remove_proxy = if matches!(
            self.status,
            ProxyStatus::Listening | ProxyStatus::WaitingOnAccept
        ) {
            ProxyRemoval::Immediate
        } else {
            ProxyRemoval::Deferred
        };

        // TSI RELEASE may arrive before the stream SHUTDOWN from guest close.
        // Keep forwarding its queued bytes until shutdown or deferred removal.
        self.host_read_closed = true;
        ProxyUpdate {
            remove_proxy,
            polling: Some((self.id, self.fd.as_raw_fd(), self.event_interest())),
            ..Default::default()
        }
    }

    fn reset(&mut self) -> ProxyUpdate {
        let update = self.release();
        self.stop_stream();
        ProxyUpdate {
            polling: Some((self.id, self.fd.as_raw_fd(), EventSet::empty())),
            ..update
        }
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        if self.is_established() {
            self.process_connected_event(evset)
        } else {
            sys::process_event(self, evset)
        }
    }

    #[cfg(windows)]
    fn process_windows_event(&mut self, event: &EpollEvent) -> ProxyUpdate {
        if self.status == ProxyStatus::Connecting
            && let Some(error) = event.connect_error()
        {
            return sys::finish_connect(self, error);
        }
        self.process_event(event.event_set())
    }
}

impl AsRawFd for TsiStreamProxy {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for TsiStreamProxy {
    fn drop(&mut self) {
        self.rxq.lock().unwrap().clear_stream_credit(self.id);
        #[cfg(not(target_os = "linux"))]
        if let Some(path) = &self.unixsock_path {
            _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    use nix::sys::socket::{setsockopt, sockopt};
    use vm_memory::{Bytes, GuestAddress};

    use super::*;
    use crate::virtio::queue::{Descriptor, DescriptorChain, VIRTQ_DESC_F_WRITE};
    use crate::virtio::vsock::packet::VSOCK_PKT_HDR_SIZE;

    fn stream_pair() -> (TsiStreamProxy, UnixStream) {
        let (sender, reader) = UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        setsockopt(&sender, sockopt::SndBuf, &4096).unwrap();
        let mut proxy = TsiStreamProxy::new_reverse(
            1024 << 32 | 620,
            3,
            1,
            AddressFamily::Unix,
            620,
            1024,
            sender.into(),
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap(),
            Arc::new(Mutex::new(VirtQueue::new(8))),
            Arc::new(Mutex::new(MuxerRxQ::new())),
        );
        proxy.status = ProxyStatus::Connected;
        (proxy, reader)
    }

    #[test]
    fn short_write_and_would_block_preserve_data_through_release_and_shutdown() {
        let (mut proxy, mut reader) = stream_pair();
        let mut expected = vec![0x17; 128 * 1024];
        proxy.send_data(&expected);
        let written = proxy.tx_cnt.0 as usize;
        assert!(written > 0 && written < expected.len());
        proxy.process_event(EventSet::OUT);
        assert_eq!(proxy.tx_cnt.0 as usize, written);

        proxy.send_data(b"last frame");
        expected.extend_from_slice(b"last frame");
        assert_eq!(proxy.release().polling.unwrap().2, EventSet::OUT);
        let table = GuestAddress(0x1000);
        let mem = proxy.mem.clone();
        mem.write_obj(
            Descriptor {
                addr: 0x2000,
                len: VSOCK_PKT_HDR_SIZE as u32 + 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            table,
        )
        .unwrap();
        let head = DescriptorChain::checked_new(&mem, table, 8, 0).unwrap();
        let mut pkt = VsockPacket::from_rx_virtq_head(&head).unwrap();
        pkt.set_flags(uapi::VSOCK_FLAGS_SHUTDOWN_SEND);
        proxy.shutdown(&pkt);
        proxy.send_data(b"after shutdown");

        let mut received = Vec::new();
        for _ in 0..100 {
            match reader.read_to_end(&mut received) {
                Ok(_) => break,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    proxy.process_event(EventSet::OUT);
                }
                Err(err) => panic!("reading host socket: {err}"),
            }
        }
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
        assert!(proxy.event_interest().is_empty());
        assert_eq!(received, expected);
        assert!(matches!(
            proxy.rxq.lock().unwrap().pop(),
            Some(MuxerRx::CreditUpdate { fwd_cnt, .. }) if fwd_cnt as usize == expected.len()
        ));
    }

    #[test]
    fn reset_discards_queued_bytes_and_credit() {
        let (mut proxy, mut reader) = stream_pair();
        proxy.send_data(&[0x17; 128 * 1024]);
        assert!(!proxy.send_queue.is_empty());
        let written = proxy.tx_cnt.0 as usize;
        assert_eq!(proxy.reset().polling.unwrap().2, EventSet::empty());
        proxy.process_event(EventSet::OUT);

        let mut received = Vec::new();
        reader.read_to_end(&mut received).unwrap();
        assert_eq!(received.len(), written);
        assert!(proxy.send_queue.is_empty());
        assert!(proxy.rxq.lock().unwrap().is_empty());
    }
}
