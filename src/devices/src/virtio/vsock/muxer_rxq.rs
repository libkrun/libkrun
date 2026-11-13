// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

/// `MuxerRxQ` implements a helper object that `VsockMuxer` can use for queuing RX (host -> guest)
/// packets (or rather instructions on how to build said packets).
///
/// Under ideal operation, every connection, that has pending RX data, will be present in the muxer
/// RX queue. However, since the RX queue is smaller than the connection pool, it may, under some
/// conditions, become full, meaning that it can no longer account for all the connections that can
/// yield RX data.  When that happens, we say that it is no longer "synchronized" (i.e. with the
/// connection pool).  A desynchronized RX queue still holds valid data, and the muxer will
/// continue to pop packets from it. However, when a desynchronized queue is drained, additional
/// data may still be available, so the muxer will have to perform a more costly walk of the entire
/// connection pool to find it.  This walk is performed here, as part of building an RX queue from
/// the connection pool. When an out-of-sync is drained, the muxer will discard it, and attempt to
/// rebuild a synced one.
use std::collections::{HashMap, VecDeque};

use super::defs;
use super::defs::uapi;
use super::muxer::MuxerRx;
use super::packet::{TsiAcceptRsp, TsiConnectRsp, TsiListenRsp, VsockPacket};

/// The muxer RX queue.
pub struct MuxerRxQ {
    /// The RX queue data.
    q: VecDeque<MuxerRx>,
    /// The RX queue sync status.
    synced: bool,
    /// The newest `fwd_cnt` given to the guest per connection, by any path.
    delivered: HashMap<(u32, u32), u32>,
}

impl MuxerRxQ {
    const SIZE: usize = defs::MUXER_RXQ_SIZE;

    /// Trivial RX queue constructor.
    pub fn new() -> Self {
        Self {
            q: VecDeque::with_capacity(Self::SIZE),
            synced: true,
            delivered: HashMap::new(),
        }
    }

    /// Push a new RX item to the queue.
    ///
    /// A push will fail when:
    /// - trying to push a connection key onto an out-of-sync, or full queue; or
    /// - trying to push an RST onto a queue already full of RSTs.
    ///
    /// RSTs take precedence over connections, because connections can always be queried for
    /// pending RX data later. Aside from this queue, there is no other storage for RSTs, so
    /// failing to push one means that we have to drop the packet.
    ///
    /// Returns:
    /// - `true` if the new item has been successfully queued; or
    /// - `false` if there was no room left in the queue.
    pub fn push(&mut self, mut rx: MuxerRx) -> bool {
        if self.coalesce_credit(&mut rx) {
            return true;
        }

        // Pushing to a non-full, synchronized queue will always succeed.
        if self.is_synced() && !self.is_full() {
            self.q.push_back(rx);
            return true;
        }

        false
    }

    /// Put back an item that was just popped but could not be delivered, keeping its place.
    pub fn push_front(&mut self, rx: MuxerRx) {
        self.q.push_front(rx);
    }

    /// The guest keeps only the last `fwd_cnt` it receives for a connection, so a queued
    /// credit-carrying packet must never deliver an older one than a later packet carries:
    /// that shrinks the guest's view of our buffer, and with nothing left to correct it the
    /// connection stalls. Bring every such packet for the connection up to the newest
    /// `fwd_cnt`, and fold a credit update into one already queued.
    ///
    /// Only packets queued since the connection's last reset or handshake packet count: before
    /// that boundary the ports may belong to an earlier connection, whose `fwd_cnt` means
    /// nothing to this one.
    ///
    /// Returns `true` if `rx` was folded into a queued credit update.
    fn coalesce_credit(&mut self, rx: &mut MuxerRx) -> bool {
        let Some((port, peer, new)) = credit_of(rx) else {
            return false;
        };
        let start = self
            .q
            .iter()
            .rposition(|queued| ports_of(queued) == (port, peer) && credit_of(queued).is_none())
            .map_or(0, |boundary| boundary + 1);
        let newest = self
            .q
            .range(start..)
            .filter_map(credit_of)
            .filter(|&(l, p, _)| (l, p) == (port, peer))
            .map(|(_, _, f)| f)
            .fold(new, |a, b| if is_after(b, a) { b } else { a });

        set_fwd_cnt(rx, newest);
        let mut folded = false;
        for queued in self.q.range_mut(start..) {
            if credit_of(queued).is_some_and(|(l, p, _)| (l, p) == (port, peer)) {
                set_fwd_cnt(queued, newest);
                folded |= matches!(
                    (&*queued, &*rx),
                    (MuxerRx::CreditUpdate { .. }, MuxerRx::CreditUpdate { .. })
                );
            }
        }
        folded
    }

    /// Record the `fwd_cnt` of a data packet just given to the guest. Data is stamped with the
    /// current count when it is written, so it is the newest the guest has.
    pub fn note_data(&mut self, local_port: u32, peer_port: u32, fwd_cnt: u32) {
        self.delivered.insert((local_port, peer_port), fwd_cnt);
    }

    /// Build the guest packet for `rx`, which is being given to the guest now.
    ///
    /// A credit update or request carries the `fwd_cnt` from when it was made. Data for the
    /// connection does not wait here, so while it waited the guest may already have been sent a
    /// newer count; delivering the older one would shrink the guest's view of our buffer just as
    /// reordering would. Raise it to the newest count the guest has been sent.
    pub fn deliver(&mut self, cid: u64, mut rx: MuxerRx, pkt: &mut VsockPacket) {
        self.stamp(&mut rx);
        rx_to_pkt(cid, rx, pkt);
    }

    fn stamp(&mut self, rx: &mut MuxerRx) {
        let ports = ports_of(rx);
        if let Some((_, _, fwd_cnt)) = credit_of(rx) {
            let newest = match self.delivered.get(&ports) {
                Some(&sent) if is_after(sent, fwd_cnt) => sent,
                _ => fwd_cnt,
            };
            set_fwd_cnt(rx, newest);
            self.delivered.insert(ports, newest);
        } else if starts_or_ends_connection(rx) {
            self.delivered.remove(&ports);
        }
    }

    /// Pop an RX item from the front of the queue.
    pub fn pop(&mut self) -> Option<MuxerRx> {
        self.q.pop_front()
    }

    /// Check if the RX queue is synchronized with the connection pool.
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Get the total number of items in the queue.
    pub fn len(&self) -> usize {
        self.q.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.len() == Self::SIZE
    }
}

fn credit_of(rx: &MuxerRx) -> Option<(u32, u32, u32)> {
    match *rx {
        MuxerRx::CreditUpdate {
            local_port,
            peer_port,
            fwd_cnt,
        }
        | MuxerRx::CreditRequest {
            local_port,
            peer_port,
            fwd_cnt,
        } => Some((local_port, peer_port, fwd_cnt)),
        _ => None,
    }
}

fn ports_of(rx: &MuxerRx) -> (u32, u32) {
    match *rx {
        MuxerRx::Reset {
            local_port,
            peer_port,
        }
        | MuxerRx::GetnameResponse {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::ConnResponse {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::OpRequest {
            local_port,
            peer_port,
        }
        | MuxerRx::OpResponse {
            local_port,
            peer_port,
        }
        | MuxerRx::CreditRequest {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::CreditUpdate {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::ListenResponse {
            local_port,
            peer_port,
            ..
        }
        | MuxerRx::AcceptResponse {
            local_port,
            peer_port,
            ..
        } => (local_port, peer_port),
    }
}

/// After these the ports may name a different connection, whose `fwd_cnt` starts afresh.
fn starts_or_ends_connection(rx: &MuxerRx) -> bool {
    matches!(
        rx,
        MuxerRx::Reset { .. }
            | MuxerRx::ConnResponse { .. }
            | MuxerRx::OpRequest { .. }
            | MuxerRx::OpResponse { .. }
            | MuxerRx::AcceptResponse { .. }
    )
}

fn set_fwd_cnt(rx: &mut MuxerRx, value: u32) {
    if let MuxerRx::CreditUpdate { fwd_cnt, .. } | MuxerRx::CreditRequest { fwd_cnt, .. } = rx {
        *fwd_cnt = value;
    }
}

/// Whether wrapping counter `a` is ahead of `b`.
fn is_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn rx_to_pkt(cid: u64, rx: MuxerRx, pkt: &mut VsockPacket) {
    match rx {
        MuxerRx::Reset {
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_len(0)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);
        }
        MuxerRx::ConnResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_connect_rsp(TsiConnectRsp { result });
            pkt.set_len(pkt.buf().unwrap().len() as u32);
        }
        MuxerRx::OpRequest {
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_REQUEST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32);

            pkt.set_len(0);
        }
        MuxerRx::OpResponse {
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RESPONSE)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32);

            pkt.set_len(0);
        }
        MuxerRx::GetnameResponse {
            local_port,
            peer_port,
            data,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_getname_rsp(data);
            pkt.set_len(pkt.buf().unwrap().len() as u32);
        }
        MuxerRx::CreditRequest {
            local_port,
            peer_port,
            fwd_cnt,
        } => {
            pkt.set_op(uapi::VSOCK_OP_CREDIT_REQUEST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
                .set_fwd_cnt(fwd_cnt);
        }
        MuxerRx::CreditUpdate {
            local_port,
            peer_port,
            fwd_cnt,
        } => {
            pkt.set_op(uapi::VSOCK_OP_CREDIT_UPDATE)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
                .set_fwd_cnt(fwd_cnt);
        }
        MuxerRx::ListenResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_listen_rsp(TsiListenRsp { result });
            pkt.set_len(pkt.buf().unwrap().len() as u32);
        }
        MuxerRx::AcceptResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_accept_rsp(TsiAcceptRsp { result });
            pkt.set_len(pkt.buf().unwrap().len() as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;

    fn update(fwd_cnt: u32) -> MuxerRx {
        MuxerRx::CreditUpdate {
            local_port: 5600,
            peer_port: 1234,
            fwd_cnt,
        }
    }

    fn request(fwd_cnt: u32) -> MuxerRx {
        MuxerRx::CreditRequest {
            local_port: 5600,
            peer_port: 1234,
            fwd_cnt,
        }
    }

    fn drain(q: &mut MuxerRxQ) -> Vec<Option<(u32, u32, u32)>> {
        iter::from_fn(|| q.pop()).map(|rx| credit_of(&rx)).collect()
    }

    #[test]
    fn credit_update_folds_into_queued_one() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(update(100)));
        assert!(q.push(update(200)));
        assert_eq!(drain(&mut q), vec![Some((5600, 1234, 200))]);
    }

    #[test]
    fn older_credit_never_overtakes_newer() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(update(200)));
        assert!(q.push(request(100)));
        assert_eq!(
            drain(&mut q),
            vec![Some((5600, 1234, 200)), Some((5600, 1234, 200))]
        );
    }

    #[test]
    fn credit_request_is_brought_up_to_date() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(request(100)));
        assert!(q.push(update(300)));
        assert_eq!(
            drain(&mut q),
            vec![Some((5600, 1234, 300)), Some((5600, 1234, 300))]
        );
    }

    #[test]
    fn other_connections_are_left_alone() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(update(100)));
        assert!(q.push(MuxerRx::CreditUpdate {
            local_port: 5601,
            peer_port: 1234,
            fwd_cnt: 900,
        }));
        assert_eq!(
            drain(&mut q),
            vec![Some((5600, 1234, 100)), Some((5601, 1234, 900))]
        );
    }

    #[test]
    fn newest_wins_across_counter_wrap() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(update(u32::MAX - 10)));
        assert!(q.push(update(5)));
        assert_eq!(drain(&mut q), vec![Some((5600, 1234, 5))]);
    }

    #[test]
    fn push_front_keeps_the_order() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(update(100)));
        assert!(q.push(MuxerRx::Reset {
            local_port: 5600,
            peer_port: 1234,
        }));
        let first = q.pop().unwrap();
        q.push_front(first);
        assert_eq!(drain(&mut q), vec![Some((5600, 1234, 100)), None]);
    }

    #[test]
    fn never_coalesces_across_a_reset() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(update(300_000_000)));
        assert!(q.push(MuxerRx::Reset {
            local_port: 5600,
            peer_port: 1234,
        }));
        assert!(q.push(update(5)));
        assert_eq!(
            drain(&mut q),
            vec![Some((5600, 1234, 300_000_000)), None, Some((5600, 1234, 5))]
        );
    }

    #[test]
    fn coalesces_only_within_the_current_connection() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(update(300_000_000)));
        assert!(q.push(MuxerRx::OpResponse {
            local_port: 5600,
            peer_port: 1234,
        }));
        assert!(q.push(request(10)));
        assert!(q.push(update(20)));
        assert_eq!(
            drain(&mut q),
            vec![
                Some((5600, 1234, 300_000_000)),
                None,
                Some((5600, 1234, 20)),
                Some((5600, 1234, 20)),
            ]
        );
    }

    fn stamped(q: &mut MuxerRxQ, mut rx: MuxerRx) -> Option<(u32, u32, u32)> {
        q.stamp(&mut rx);
        credit_of(&rx)
    }

    #[test]
    fn queued_update_is_raised_to_data_sent_meanwhile() {
        let mut q = MuxerRxQ::new();
        assert!(q.push(update(100)));
        q.note_data(5600, 1234, 300);
        let rx = q.pop().unwrap();
        assert_eq!(stamped(&mut q, rx), Some((5600, 1234, 300)));
    }

    #[test]
    fn queued_request_is_raised_to_an_update_sent_before_it() {
        let mut q = MuxerRxQ::new();
        assert_eq!(stamped(&mut q, update(300)), Some((5600, 1234, 300)));
        assert_eq!(stamped(&mut q, request(100)), Some((5600, 1234, 300)));
    }

    #[test]
    fn newer_credit_is_delivered_as_it_is() {
        let mut q = MuxerRxQ::new();
        q.note_data(5600, 1234, 100);
        assert_eq!(stamped(&mut q, update(300)), Some((5600, 1234, 300)));
    }

    #[test]
    fn raising_works_across_counter_wrap() {
        let mut q = MuxerRxQ::new();
        q.note_data(5600, 1234, 5);
        assert_eq!(
            stamped(&mut q, update(u32::MAX - 10)),
            Some((5600, 1234, 5))
        );
    }

    #[test]
    fn a_new_connection_on_the_same_ports_starts_afresh() {
        let mut q = MuxerRxQ::new();
        q.note_data(5600, 1234, 500);
        stamped(
            &mut q,
            MuxerRx::Reset {
                local_port: 5600,
                peer_port: 1234,
            },
        );
        assert_eq!(stamped(&mut q, update(100)), Some((5600, 1234, 100)));
    }

    #[test]
    fn data_on_another_connection_is_not_counted() {
        let mut q = MuxerRxQ::new();
        q.note_data(5601, 1234, 500);
        assert_eq!(stamped(&mut q, update(100)), Some((5600, 1234, 100)));
    }
}
