use std::collections::HashMap;
use std::num::Wrapping;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::LPFN_WSARECVMSG;

use super::super::Queue as VirtQueue;
use super::muxer_rxq::MuxerRxQ;
use super::packet::{
    TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiProxyCreate, TsiSendtoAddr, VsockPacket,
};

use super::proxy::{
    AddressFamily, AsRawFd, OwnedFd, Proxy, ProxyError, ProxyStatus, ProxyUpdate, RawFd, RecvPkt,
};

use utils::epoll::EventSet;
use vm_memory::GuestMemoryMmap;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;

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
    pub status: ProxyStatus,
    pub(crate) pending_error: AtomicI32,
    pub(crate) sendto_addr: Option<sys::SendtoAddr>,
    pub(crate) listening: bool,
    pub(crate) family: AddressFamily,
    pub(crate) protocol: u32,
    pub(crate) mem: GuestMemoryMmap,
    pub(crate) queue: Arc<Mutex<VirtQueue>>,
    pub(crate) rxq: Arc<Mutex<MuxerRxQ>>,
    pub(crate) rx_cnt: Wrapping<u32>,
    pub(crate) tx_cnt: Wrapping<u32>,
    pub(crate) peer_buf_alloc: u32,
    pub(crate) peer_fwd_cnt: Wrapping<u32>,
}

impl TsiDgramProxy {
    pub(crate) fn record_error(&self, error: i32) {
        if error > 0 && !matches!(error, 4 | 11) {
            let _ =
                self.pending_error
                    .compare_exchange(0, error, Ordering::Relaxed, Ordering::Relaxed);
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
        let mut queue = self.queue.lock().unwrap();

        while let Some(head) = queue.pop(&self.mem) {
            let len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => match sys::recv_to_pkt(self, &mut pkt) {
                    RecvPkt::WaitForCredit => {
                        wait_credit = true;
                        0
                    }
                    RecvPkt::Read(cnt) => {
                        self.rx_cnt += Wrapping(cnt as u32);
                        sys::init_pkt(self, &mut pkt);
                        pkt.set_len(cnt as u32);
                        pkt.finish_rx().unwrap_or(0) as usize
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
}

impl Proxy for TsiDgramProxy {
    fn is_tsi(&self) -> bool {
        true
    }
    fn id(&self) -> u64 {
        self.id
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate {
        sys::do_connect(self, pkt, req)
    }

    fn disconnect(&mut self, pkt: &VsockPacket) -> Option<ProxyUpdate> {
        Some(sys::do_disconnect(self, pkt))
    }

    fn bind_datagram(
        &mut self,
        req: TsiSendtoAddr,
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

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        sys::sendmsg(self, pkt)
    }

    fn sendto_addr(&mut self, req: TsiSendtoAddr) -> ProxyUpdate {
        sys::do_sendto_addr(self, req)
    }

    fn sendto_data(&mut self, pkt: &VsockPacket) {
        sys::sendto_data(self, pkt)
    }

    fn listen(
        &mut self,
        pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        sys::do_listen(self, pkt)
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
}

impl AsRawFd for TsiDgramProxy {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
