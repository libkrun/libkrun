use std::collections::HashMap;
use std::num::Wrapping;
use std::sync::{Arc, Mutex};

use super::super::Queue as VirtQueue;
use super::muxer_rxq::MuxerRxQ;
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket};
#[cfg(unix)]
use nix::sys::socket::AddressFamily;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

use super::proxy::{Proxy, ProxyError, ProxyStatus, ProxyUpdate, RecvPkt};

use utils::epoll::EventSet;
use vm_memory::GuestMemoryMmap;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;

pub struct TsiDgramProxy {
    pub(crate) id: u64,
    pub(crate) cid: u64,
    pub(crate) local_port: u32,
    pub(crate) peer_port: u32,
    pub(crate) fd: OwnedFd,
    pub status: ProxyStatus,
    pub(crate) sendto_addr: Option<sys::SendtoAddr>,
    pub(crate) listening: bool,
    pub(crate) family: AddressFamily,
    pub(crate) mem: GuestMemoryMmap,
    pub(crate) queue: Arc<Mutex<VirtQueue>>,
    pub(crate) rxq: Arc<Mutex<MuxerRxQ>>,
    pub(crate) rx_cnt: Wrapping<u32>,
    pub(crate) tx_cnt: Wrapping<u32>,
    pub(crate) peer_buf_alloc: u32,
    pub(crate) peer_fwd_cnt: Wrapping<u32>,
}

impl TsiDgramProxy {
    pub fn new(
        id: u64,
        cid: u64,
        family: u16,
        peer_port: u32,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Result<Self, ProxyError> {
        sys::create(id, cid, family, peer_port, mem, queue, rxq)
    }

    /* pub(crate) fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    } */

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
}

impl Proxy for TsiDgramProxy {
    fn id(&self) -> u64 {
        self.id
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate {
        sys::do_connect(self, pkt, req)
    }

    fn getpeername(&mut self, pkt: &VsockPacket) {
        sys::do_getpeername(self, pkt)
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
