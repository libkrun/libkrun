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
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use super::defs;
use super::defs::uapi;
use super::muxer::MuxerRx;
use super::packet::{TsiAcceptRsp, TsiConnectRsp, TsiListenRsp, VsockPacket};

#[derive(Default)]
struct StreamCredit {
    fwd_cnt: u32,
    request_peer_credit: bool,
}

/// The muxer RX queue.
pub struct MuxerRxQ {
    /// The RX queue data.
    q: VecDeque<MuxerRx>,
    /// The RX queue sync status.
    synced: bool,
    stream_credit: BTreeMap<u64, StreamCredit>,
    /// Bytes the stream send queues may still claim from the device-wide
    /// budget. Shared by every proxy through its `rxq` reference. Starts
    /// unbounded; a configured muxer replaces it with the caller's budget.
    pub(super) send_budget: Arc<AtomicUsize>,
    #[cfg(feature = "tsi-fault-injection")]
    pub(super) faults: super::tsi_control_faults::Injector,
}

impl MuxerRxQ {
    const SIZE: usize = defs::MUXER_RXQ_SIZE;

    /// Trivial RX queue constructor.
    pub fn new() -> Self {
        Self {
            q: VecDeque::with_capacity(Self::SIZE),
            synced: true,
            stream_credit: BTreeMap::new(),
            send_budget: Arc::new(AtomicUsize::new(usize::MAX)),
            #[cfg(feature = "tsi-fault-injection")]
            faults: super::tsi_control_faults::Injector::default(),
        }
    }

    // Keep the latest counter even if the guest has supplied no RX buffers.
    pub fn stage_stream_credit(&mut self, id: u64, fwd_cnt: u32, request: bool) {
        let pending = self.stream_credit.entry(id).or_default();
        pending.fwd_cnt = fwd_cnt;
        pending.request_peer_credit |= request;
    }

    pub fn stream_credit_piggybacked(&mut self, id: u64, fwd_cnt: u32) {
        if let Some(pending) = self.stream_credit.get_mut(&id) {
            if pending.request_peer_credit {
                pending.fwd_cnt = fwd_cnt;
            } else {
                self.stream_credit.remove(&id);
            }
        }
    }

    pub fn clear_stream_credit(&mut self, id: u64) {
        self.stream_credit.remove(&id);
    }

    /// Push a new RX item to the queue.
    ///
    /// A push fails when the queue is full or out of sync, and the item is
    /// then lost: aside from this queue there is no other storage for it.
    /// Callers for which a lost item is unrecoverable, such as a connection
    /// announcement the guest cannot otherwise learn about, must check the
    /// return value.
    ///
    /// Returns:
    /// - `true` if the new item has been successfully queued; or
    /// - `false` if there was no room left in the queue.
    pub fn push(&mut self, rx: MuxerRx) -> bool {
        // Pushing to a non-full, synchronized queue will always succeed.
        if self.is_synced() && !self.is_full() {
            self.q.push_back(rx);
            return true;
        }

        false
    }

    /// Pop an RX item from the front of the queue.
    pub fn pop(&mut self) -> Option<MuxerRx> {
        self.q.pop_front().or_else(|| {
            let (id, credit) = self.stream_credit.pop_first()?;
            let local_port = id as u32;
            let peer_port = (id >> 32) as u32;
            let fwd_cnt = credit.fwd_cnt;
            Some(if credit.request_peer_credit {
                MuxerRx::CreditRequest {
                    local_port,
                    peer_port,
                    fwd_cnt,
                }
            } else {
                MuxerRx::CreditUpdate {
                    local_port,
                    peer_port,
                    fwd_cnt,
                }
            })
        })
    }

    /// Check if the RX queue is synchronized with the connection pool.
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.q.is_empty() && self.stream_credit.is_empty()
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.q.len() == Self::SIZE
    }
}

pub fn rx_to_pkt(cid: u64, rx: MuxerRx, pkt: &mut VsockPacket) {
    match rx {
        #[cfg(feature = "tsi-fault-injection")]
        MuxerRx::FaultPacket {
            response,
            fault,
            peer_port,
        } => {
            super::tsi_control_faults::packet(cid, *response, fault, peer_port, pkt);
        }
        #[cfg(feature = "tsi-fault-injection")]
        MuxerRx::FaultAck { peer_port, words } => {
            super::tsi_control_faults::ack(cid, peer_port, words, pkt);
        }
        MuxerRx::SockoptResponse {
            request_id,
            operation,
            peer_port,
            result,
            value,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(defs::TSI_CONTROL_PORT)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM)
                .set_flags(uapi::VSOCK_DGRAM_START | uapi::VSOCK_DGRAM_EOM);
            pkt.write_sockopt_rsp(result, value, operation, request_id);
        }
        MuxerRx::FeatureResponse {
            request_id,
            operation,
            peer_port,
            result,
            services,
            features,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(defs::TSI_CONTROL_PORT)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM)
                .set_flags(uapi::VSOCK_DGRAM_START | uapi::VSOCK_DGRAM_EOM);
            pkt.write_features_rsp(result, services, features, operation, request_id);
        }
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
            request_id,
            operation,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(defs::TSI_CONTROL_PORT)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM)
                .set_flags(uapi::VSOCK_DGRAM_START | uapi::VSOCK_DGRAM_EOM);

            pkt.write_connect_rsp(TsiConnectRsp { result }, operation, request_id);
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
            request_id,
            operation,
            peer_port,
            data,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(defs::TSI_CONTROL_PORT)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM)
                .set_flags(uapi::VSOCK_DGRAM_START | uapi::VSOCK_DGRAM_EOM);

            pkt.write_getname_rsp(data, operation, request_id);
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
            request_id,
            operation,
            peer_port,
            result,
            flags,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(defs::TSI_CONTROL_PORT)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM)
                .set_flags(uapi::VSOCK_DGRAM_START | uapi::VSOCK_DGRAM_EOM);

            pkt.write_listen_rsp(TsiListenRsp { result, flags }, operation, request_id);
        }
        MuxerRx::AcceptResponse {
            request_id,
            operation,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(defs::TSI_CONTROL_PORT)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM)
                .set_flags(uapi::VSOCK_DGRAM_START | uapi::VSOCK_DGRAM_EOM);

            pkt.write_accept_rsp(TsiAcceptRsp { result }, operation, request_id);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_stream_credit_until_an_rx_buffer_is_available() {
        let mut rxq = MuxerRxQ::new();
        let id = 1024 << 32 | 620;
        rxq.stage_stream_credit(id, u32::MAX, false);
        rxq.stage_stream_credit(id, 10, false);
        assert!(!rxq.is_empty());
        assert!(matches!(
            rxq.pop(),
            Some(MuxerRx::CreditUpdate {
                local_port: 620,
                peer_port: 1024,
                fwd_cnt: 10,
            })
        ));
        assert!(rxq.is_empty());

        rxq.stage_stream_credit(id, 20, false);
        rxq.stream_credit_piggybacked(id, 20);
        assert!(rxq.is_empty());

        rxq.stage_stream_credit(id, 30, true);
        rxq.stage_stream_credit(id, 40, false);
        rxq.stream_credit_piggybacked(id, 50);
        assert!(matches!(
            rxq.pop(),
            Some(MuxerRx::CreditRequest { fwd_cnt: 50, .. })
        ));
        assert!(rxq.is_empty());
    }
}
