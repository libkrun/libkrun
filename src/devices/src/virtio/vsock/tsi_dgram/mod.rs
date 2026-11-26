use std::collections::HashMap;
use std::num::Wrapping;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::LPFN_WSARECVMSG;

use super::super::Queue as VirtQueue;
use super::defs::uapi;
use super::muxer_rxq::MuxerRxQ;
use super::packet::{
    TsiAcceptReq, TsiBindReq, TsiConnectReq, TsiDatagram, TsiProxyCreate, VsockPacket,
};

use super::proxy::{
    AddressFamily, AsRawFd, OwnedFd, Proxy, ProxyError, ProxyStatus, ProxyUpdate, RawFd, RecvPkt,
};
#[cfg(windows)]
use super::tsi_sockopt::GuestOnlyOptions;

#[cfg(windows)]
use utils::epoll::Epoll;
use utils::epoll::EventSet;
use vm_memory::GuestMemoryMmap;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;

#[cfg(target_os = "macos")]
mod icmp_macos;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

pub struct TsiDgramProxy {
    pub(crate) id: u64,
    pub(crate) cid: u64,
    pub(crate) local_port: u32,
    pub(crate) peer_port: u32,
    pub(crate) fd: OwnedFd,
    #[cfg(windows)]
    pub(crate) recv_msg: LPFN_WSARECVMSG,
    // Credit and polling transitions do not change the host UDP peer.
    #[cfg(windows)]
    host_connected: bool,
    pub status: ProxyStatus,
    pub(crate) pending_error: AtomicI32,
    pub(crate) listening: bool,
    pub(crate) family: AddressFamily,
    pub(crate) protocol: u32,
    /// The guest RX queue ran dry while the host socket may still be
    /// readable; IN polling stays off until the guest posts new buffers.
    pub(crate) rx_starved: bool,
    /// Receive scratch holding the TSI frame of the datagram in flight,
    /// sized `DGRAM_MAX_SIZE` on first use.
    pub(crate) dgram_scratch: Vec<u8>,
    /// A datagram caught mid-fragmentation when guest RX buffers ran out.
    /// Its undelivered tail resumes when buffers return; if other traffic
    /// reaches the guest first, its START marker makes the guest drop the
    /// stale fragments and the datagram is lost.
    pub(crate) pending_dgram: Option<PendingDgram>,
    #[cfg(target_os = "macos")]
    icmp: Option<icmp_macos::IcmpSocket>,
    pub(crate) mem: GuestMemoryMmap,
    pub(crate) queue: Arc<Mutex<VirtQueue>>,
    pub(crate) rxq: Arc<Mutex<MuxerRxQ>>,
    pub(crate) rx_cnt: Wrapping<u32>,
    pub(crate) tx_cnt: Wrapping<u32>,
    pub(crate) peer_buf_alloc: u32,
    pub(crate) peer_fwd_cnt: Wrapping<u32>,
    #[cfg(windows)]
    pub(crate) guest_options: GuestOnlyOptions,
}

/// A datagram in `dgram_scratch` that has only been partially delivered to
/// the guest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct PendingDgram {
    /// Total frame length (TSI header plus payload).
    pub(crate) len: usize,
    /// Frame bytes already written to the guest.
    pub(crate) offset: usize,
}

impl TsiDgramProxy {
    pub(crate) fn record_error(&self, error: i32) {
        Self::record_error_on(&self.pending_error, error);
    }

    pub(crate) fn record_error_on(pending_error: &AtomicI32, error: i32) {
        if error > 0 && !matches!(error, 4 | 11) {
            let _ = pending_error.compare_exchange(0, error, Ordering::Relaxed, Ordering::Relaxed);
        }
    }

    pub fn new(
        id: u64,
        cid: u64,
        req: TsiProxyCreate,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Result<Self, ProxyError> {
        sys::create(id, cid, req, mem, queue, rxq)
    }

    pub(crate) fn recv_pkt(&mut self) -> (bool, bool) {
        let mut have_used = false;
        let mut wait_credit = false;
        let mut parked = false;
        let mut pending = self.pending_dgram.take();
        // Bound the guard to a local clone so the receive step can borrow the
        // proxy mutably inside the loop.
        let queue = self.queue.clone();
        let mut queue = queue.lock().unwrap();

        loop {
            if pending.is_none() {
                match sys::recv_datagram(self) {
                    RecvPkt::Read(len) => pending = Some(PendingDgram { len, offset: 0 }),
                    RecvPkt::Close => {
                        self.status = ProxyStatus::Closed;
                        parked = true;
                        break;
                    }
                    // Nothing readable on the host socket.
                    RecvPkt::Error | RecvPkt::WaitForCredit | RecvPkt::BadBuffer => {
                        parked = true;
                        break;
                    }
                }
            }

            let Some(head) = queue.pop(&self.mem) else {
                // Out of guest buffers, possibly mid-datagram.
                break;
            };
            // A head that cannot hold a packet is returned to the guest empty
            // instead of being parked at the queue head, where a readable host
            // socket would trip the event loop forever.
            let mut bad_buffer = false;
            match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    if write_dgram_fragment(&*self, &mut pending, &mut pkt) {
                        self.rx_cnt += Wrapping(pkt.len());
                        let len = pkt.finish_rx().unwrap_or(0) as usize;
                        have_used = true;
                        if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                            error!("failed to add used elements to the queue: {e:?}");
                        }
                    } else {
                        bad_buffer = true;
                    }
                }
                Err(e) => {
                    debug!("recv_pkt: RX queue error: {e:?}");
                    bad_buffer = true;
                }
            }

            if bad_buffer {
                wait_credit = true;
                have_used = true;
                if let Err(e) = queue.add_used(&self.mem, head.index, 0) {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            }
        }

        self.pending_dgram = pending;
        debug!("recv_pkt: have_used={have_used}");
        // A pass that ended over a drained host socket means polling can
        // stay armed. Running out of buffers instead leaves the
        // level-triggered IN interest armed over a possibly readable
        // socket, which would spin the event loop until the guest refills.
        self.rx_starved = !parked;
        (have_used, wait_credit)
    }
}

/// Write one fragment of the pending datagram into `pkt`. Returns `false`
/// when the buffer cannot hold any fragment byte and must be returned to
/// the guest empty.
fn write_dgram_fragment(
    proxy: &TsiDgramProxy,
    pending: &mut Option<PendingDgram>,
    pkt: &mut VsockPacket,
) -> bool {
    let Some(state) = *pending else {
        return false;
    };
    let Some(buf) = pkt.buf_mut() else {
        return false;
    };
    let frame = &proxy.dgram_scratch[..state.len];
    let count = buf.len().min(frame.len() - state.offset);
    if count == 0 {
        return false;
    }
    buf[..count].copy_from_slice(&frame[state.offset..state.offset + count]);

    let start = state.offset == 0;
    let end = state.offset + count == frame.len();
    let mut flags = 0;
    if start {
        flags |= uapi::VSOCK_DGRAM_START;
    }
    if end {
        flags |= uapi::VSOCK_DGRAM_EOM;
    }
    sys::init_pkt(proxy, pkt);
    pkt.set_flags(flags).set_len(count as u32);

    if end {
        *pending = None;
    } else {
        *pending = Some(PendingDgram {
            len: state.len,
            offset: state.offset + count,
        });
    }
    true
}

impl Proxy for TsiDgramProxy {
    fn tsi_socket(&self) -> Option<(u16, AddressFamily)> {
        Some((super::defs::SOCK_DGRAM, self.family))
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
        #[cfg(windows)] _epoll: &Epoll,
    ) -> ProxyUpdate {
        sys::do_connect(self, pkt, req)
    }

    fn disconnect(&mut self, pkt: &VsockPacket) -> Option<ProxyUpdate> {
        Some(sys::do_disconnect(self, pkt))
    }

    fn bind_datagram(
        &mut self,
        req: TsiBindReq,
        host_port_map: &Option<HashMap<u16, u16>>,
    ) -> Option<Result<ProxyUpdate, i32>> {
        Some(sys::bind_datagram(self, req, host_port_map))
    }

    fn socket_option(&self, level: u32, name: u32, value: Option<i32>) -> Result<i32, i32> {
        if level == 1 && name == 4 && value.is_none() {
            let error = self.pending_error.swap(0, Ordering::Relaxed);
            if error != 0 {
                return Ok(error);
            }
        }
        #[cfg(windows)]
        if let Some(result) = self.guest_options.apply(self.family, level, name, value) {
            return Ok(result);
        }
        super::tsi_sockopt::socket_option(
            self.as_raw_fd(),
            self.family,
            super::defs::SOCK_DGRAM,
            level,
            name,
            value,
        )
    }

    fn getname(&mut self, pkt: &VsockPacket, peer: bool) {
        sys::do_getname(self, pkt, peer)
    }

    fn send_datagram(&mut self, datagram: TsiDatagram<'_>) -> ProxyUpdate {
        sys::send_datagram(self, datagram)
    }

    fn record_datagram_error(&self, errno: i32) {
        self.record_error(errno);
    }

    fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        sys::update_peer_credit(self, pkt)
    }

    fn process_op_response(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn release(&mut self) -> ProxyUpdate {
        sys::release(self)
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        sys::process_event(self, evset)
    }

    fn resume_rx(&mut self) -> Option<(u64, RawFd, EventSet)> {
        if !self.rx_starved || matches!(self.status, ProxyStatus::Closed) {
            return None;
        }
        self.rx_starved = false;
        // Datagram sockets do not take part in the vsock credit protocol, so
        // a credit wait can only come from a malformed buffer; the guest
        // dropping its credit request is recovered here.
        if self.status == ProxyStatus::WaitingCreditUpdate {
            self.status = ProxyStatus::Connected;
        }
        Some((self.id, self.fd.as_raw_fd(), EventSet::IN))
    }
}

impl AsRawFd for TsiDgramProxy {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
