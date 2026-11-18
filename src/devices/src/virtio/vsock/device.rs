// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use utils::byte_order;
use utils::eventfd::EventFd;
use vm_memory::{Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, Queue as VirtQueue, QueueConfig,
    VirtioDevice,
};
use super::TsiFlags;
use super::muxer::VsockMuxer;
use super::packet::VsockPacket;
use super::proxy::ListenerDesc;
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;
use crate::virtio::queue::QueueState;

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

/// `virtio_vsock_event.id` telling the driver that every connection it holds is
/// gone (virtio spec 5.10.6.7). The guest resets its connected sockets and
/// keeps its listeners.
const VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: u32 = 0;
/// Longest RX stays held waiting for the guest to handle a transport reset.
const TRANSPORT_RESET_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_F_IN_ORDER as u64)
    | (1 << uapi::VIRTIO_VSOCK_F_DGRAM);

pub struct Vsock {
    cid: u64,
    pub(crate) muxer: VsockMuxer,
    pub(crate) queue_rx: Option<Arc<Mutex<VirtQueue>>>,
    pub(crate) queue_tx: Option<Arc<Mutex<VirtQueue>>>,
    /// The event queue. The device only uses it to announce a transport reset
    /// after a restore.
    pub(crate) queue_ev: Option<Arc<Mutex<VirtQueue>>>,
    // Queue events are stored separately for event handling.
    pub(crate) queue_events: Vec<Arc<EventFd>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    /// Inbound listeners staged by `restore_state`, re-established once the muxer
    /// worker is live in `finish_restore_activation` (fork-clone path).
    pending_restore_listeners: Vec<ListenerDesc>,
    /// Set by `restore_state` when the snapshot carries the event queue, so
    /// `finish_restore_activation` can tell the guest its connections are gone.
    pending_transport_reset: bool,
    /// A transport reset was posted; RX is held until the guest refills the
    /// event queue, which its driver does right after handling the event.
    pub(crate) awaiting_transport_reset_ack: bool,
    /// Listener metadata captured after host handlers and RX producers stop.
    quiesced_listeners: Option<Vec<ListenerDesc>>,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM CID.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
        egress_cidrs: Option<Vec<(IpAddr, u8)>>,
        egress_hosts: Option<Vec<String>>,
        egress_resolvers: Option<Vec<IpAddr>>,
        dns_forwarder: Option<std::net::SocketAddr>,
        stream_intercept: Option<super::proxy::StreamIntercept>,
    ) -> super::Result<Vsock> {
        Ok(Vsock {
            cid,
            muxer: VsockMuxer::new(
                cid,
                host_port_map,
                unix_ipc_port_map,
                tsi_flags,
                egress_cidrs,
                egress_hosts,
                egress_resolvers,
                dns_forwarder,
                stream_intercept,
            ),
            queue_rx: None,
            queue_tx: None,
            queue_ev: None,
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
            pending_restore_listeners: Vec::new(),
            pending_transport_reset: false,
            awaiting_transport_reset_ack: false,
            quiesced_listeners: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_stream_rx(&mut self) -> bool {
        debug!("process_stream_rx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;
        if self.muxer.rx_held_for_transport_reset() {
            return have_used;
        }

        debug!("process_rx before while");
        let queue_rx = self
            .queue_rx
            .as_ref()
            .expect("queue_rx should exist when activated");
        let mut queue_rx = queue_rx.lock().unwrap();
        while let Some(head) = queue_rx.pop(mem) {
            debug!("process_rx inside while");
            let used_len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    if self.muxer.recv_pkt(&mut pkt).is_ok() {
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we can't
                        // fill in this buffer, we'll need to undo the last iterator step.
                        queue_rx.undo_pop();
                        break;
                    }
                }
                Err(e) => {
                    warn!("RX queue error: {e:?}");
                    0
                }
            };

            debug!("process_rx: something to queue");
            have_used = true;
            if let Err(e) = queue_rx.add_used(mem, head.index, used_len) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        drop(queue_rx);
        have_used |= self.muxer.resume_datagram_rx();
        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and process
    /// them. Return `true` if descriptors have been added to the used ring, and `false` otherwise.
    pub fn process_stream_tx(&mut self) -> bool {
        debug!("process_stream_tx()");
        // A TX reply can enter the held RX gate. Blocking here would prevent
        // this same event loop from handling the guest's reset acknowledgement.
        // Keep descriptors queued; the acknowledgement explicitly drains them.
        if self.muxer.rx_held_for_transport_reset() {
            return false;
        }
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        let queue_tx = self
            .queue_tx
            .as_ref()
            .expect("queue_tx should exist when activated");
        let mut queue_tx = queue_tx.lock().unwrap();
        while let Some(head) = queue_tx.pop(mem) {
            let pkt = match VsockPacket::from_tx_virtq_head(&head) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("error reading TX packet: {e:?}");
                    have_used = true;
                    if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                        error!("failed to add used elements to the queue: {e:?}");
                    }
                    continue;
                }
            };

            if pkt.type_() == uapi::VSOCK_TYPE_DGRAM {
                debug!("process_stream_tx() is DGRAM");
                if self.muxer.send_dgram_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            } else {
                debug!("process_stream_tx() is STREAM");
                if self.muxer.send_stream_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            }

            have_used = true;
            if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }
}

/// Serializable runtime state of the [`Vsock`] device, for VM checkpoint/fork.
///
/// Captures device-level negotiated state (acked features, activation), the
/// guest `cid`, and the rx/tx [`QueueState`].
///
/// **Connections are intentionally NOT captured.** vsock/TSI connections live
/// in the muxer's `proxy_map` as host-backed sockets (live `RawFd`s); they
/// cannot be serialized to disk nor cloned across a fork (a clone could not
/// share the parent's fds). The model is therefore **reset-and-reconnect**: on
/// restore the muxer starts with an empty `proxy_map` and the guest
/// re-establishes connections. This is sound for the target use case — a
/// "browser ready, no active task" checkpoint has no in-flight task
/// connections to preserve, and the persistent agent channel simply reconnects.
///
/// **Fork note:** `cid` is the VM's vsock identity. A plain restore keeps it; a
/// *fork* must construct the clone with a FRESH `cid` (rejuvenation) so the two
/// VMs are distinguishable on the host — `restore_state` deliberately does not
/// overwrite the device's `cid`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VsockState {
    pub cid: u64,
    pub acked_features: u64,
    pub activated: bool,
    pub queue_rx: Option<QueueState>,
    pub queue_tx: Option<QueueState>,
    /// The event queue, needed to announce a transport reset to the restored
    /// guest. `#[serde(default)]` keeps older snapshots (without it) loadable;
    /// those restore without the announcement.
    #[serde(default)]
    pub queue_ev: Option<QueueState>,
    /// Negotiated protocol of the booted guest, absent for legacy networking.
    #[serde(default)]
    pub host_network_abi: Option<u32>,
    /// Live TSI inbound-port-forward listeners at snapshot time, re-established
    /// on a fork clone against its own host port map (see [`ListenerDesc`]).
    /// `#[serde(default)]` keeps older snapshots (without this field) loadable.
    #[serde(default)]
    pub listeners: Vec<ListenerDesc>,
}

impl VsockState {
    pub fn validate_host_network(&self, host_network: bool) -> Result<(), String> {
        let expected = host_network.then_some(super::HOST_NETWORK_ABI_VERSION);
        if self.host_network_abi != expected {
            return Err(format!(
                "checkpoint host-network ABI {:?} does not match requested {:?}",
                self.host_network_abi, expected
            ));
        }
        Ok(())
    }
}

impl Vsock {
    /// Capture this vsock device's runtime state for VM checkpoint/fork.
    pub fn save_state(&self) -> VsockState {
        let q = |slot: &Option<Arc<Mutex<VirtQueue>>>| {
            slot.as_ref().map(|m| m.lock().unwrap().save_state())
        };
        VsockState {
            cid: self.cid,
            acked_features: self.acked_features,
            activated: matches!(self.device_state, DeviceState::Activated(..)),
            queue_rx: q(&self.queue_rx),
            queue_tx: q(&self.queue_tx),
            queue_ev: q(&self.queue_ev),
            host_network_abi: self
                .muxer
                .host_network_enabled()
                .then_some(super::HOST_NETWORK_ABI_VERSION),
            listeners: self
                .quiesced_listeners
                .clone()
                .unwrap_or_else(|| self.muxer.snapshot_listeners()),
        }
    }

    /// Restore a fresh device or rewind an activated, quiesced one. Host-backed
    /// connections are reset; saved TSI listeners are recreated before resume.
    pub fn restore_state(&mut self, state: &VsockState) -> Result<(), String> {
        state.validate_host_network(self.muxer.host_network_enabled())?;
        self.acked_features = state.acked_features;
        // `cid` left as constructed (fresh on fork, matching on restore).
        if let (Some(m), Some(qs)) = (self.queue_rx.as_ref(), state.queue_rx.as_ref()) {
            m.lock().unwrap().restore_state(qs)?;
        }
        if let (Some(m), Some(qs)) = (self.queue_tx.as_ref(), state.queue_tx.as_ref()) {
            m.lock().unwrap().restore_state(qs)?;
        }
        // Tear down host-backed streams and TSI listeners; host IPC acceptors
        // remain so the agent can reconnect. TSI listeners are rebuilt below
        // from the saved set, including ports closed since the checkpoint.
        // This is the in-process-rewind counterpart to the "reset-and-reconnect"
        // model — for a fresh-device restore the proxy_map is already empty, so
        // this is a no-op there.
        self.muxer.reset_connections();
        if let (Some(m), Some(qs)) = (self.queue_ev.as_ref(), state.queue_ev.as_ref()) {
            m.lock().unwrap().restore_state(qs)?;
        }
        // Stash inbound listeners; they are re-established in
        // `finish_restore_activation`, after the muxer worker/epoll is live.
        self.pending_restore_listeners = state.listeners.clone();
        // The restored guest still has every connection that was open when
        // the snapshot was taken, but their
        // host ends are gone. Without being told, it keeps them established
        // forever, and whatever serves them (e.g. an agent with a bounded number
        // of connection handlers) waits on them indefinitely. Nothing may reach
        // the guest until it has handled the reset (see
        // `hold_rx_for_transport_reset`).
        if state.queue_ev.is_some() {
            self.pending_transport_reset = true;
            self.muxer.hold_rx_for_transport_reset();
        }
        // In-process rewind has live queues/workers and never runs fresh-VM
        // activation. Recreate listeners and announce the reset now, while
        // host event handlers and vCPUs are still stopped.
        if self.is_activated() {
            self.finish_restore_activation()?;
        }
        Ok(())
    }

    /// Tell the guest driver that all of its connections are gone.
    ///
    /// Posts a `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET` into the next buffer the
    /// driver made available on the event queue. Returns whether one was posted.
    fn send_transport_reset(&mut self) -> bool {
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            return false;
        };
        let Some(queue_ev) = self.queue_ev.as_ref() else {
            return false;
        };
        let mut queue_ev = queue_ev.lock().unwrap();
        let Some(head) = queue_ev.pop(mem) else {
            warn!("vsock: no event buffer available to announce a transport reset");
            return false;
        };
        let event_len = std::mem::size_of::<u32>() as u32;
        let used_len = if head.is_write_only() && head.len >= event_len {
            match mem.write_obj(VIRTIO_VSOCK_EVENT_TRANSPORT_RESET.to_le(), head.addr) {
                Ok(()) => event_len,
                Err(e) => {
                    error!("vsock: failed to write transport reset event: {e:?}");
                    0
                }
            }
        } else {
            error!("vsock: event buffer is not a writable virtio_vsock_event");
            0
        };
        if let Err(e) = queue_ev.add_used(mem, head.index, used_len) {
            error!("vsock: failed to return event buffer: {e:?}");
            return false;
        }
        used_len == event_len
    }
}

impl VirtioDevice for Vsock {
    fn quiesce_for_snapshot(&mut self) {
        self.muxer.quiesce_for_snapshot();
        self.quiesced_listeners = Some(self.muxer.snapshot_listeners());
    }

    fn rearm_after_snapshot(&mut self) {
        self.muxer.rearm_after_snapshot();
        self.quiesced_listeners = None;
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    /// Fork-clone restore: the muxer worker + epoll are live now, so rebuild the
    /// inbound-port-forward listeners staged by `restore_state` against this
    /// clone's own host port map. A no-op for a normal boot (none staged).
    fn finish_restore_activation(&mut self) -> Result<(), String> {
        if !self.pending_restore_listeners.is_empty() {
            let listeners = std::mem::take(&mut self.pending_restore_listeners);
            self.muxer.restore_listeners(listeners)?;
        }
        if std::mem::take(&mut self.pending_transport_reset) {
            if self.send_transport_reset() {
                self.awaiting_transport_reset_ack = true;
                self.muxer.arm_transport_reset_timeout(
                    TRANSPORT_RESET_ACK_TIMEOUT,
                    self.queue_events[TXQ_INDEX].clone(),
                );
                self.device_state.signal_used_queue();
            } else {
                self.muxer.release_rx_after_transport_reset();
            }
        }
        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn device_name(&self) -> &str {
        "vsock"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let activate_start = std::time::Instant::now();
        debug!("[VSOCK_TIMING] device.activate() called, cid={}", self.cid);

        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        // Store queue events for event handling.
        self.queue_events = queues.iter().map(|dq| dq.event.clone()).collect();

        // Extract queues from DeviceQueues and wrap in Arc<Mutex<>>.
        let mut queues_vec: Vec<VirtQueue> = queues.into_iter().map(|dq| dq.queue).collect();
        let ev_queue = queues_vec.pop().unwrap();
        let tx_queue = queues_vec.pop().unwrap();
        let rx_queue = queues_vec.pop().unwrap();

        self.queue_ev = Some(Arc::new(Mutex::new(ev_queue)));
        self.queue_tx = Some(Arc::new(Mutex::new(tx_queue)));
        self.queue_rx = Some(Arc::new(Mutex::new(rx_queue)));
        self.muxer.activate(
            mem.clone(),
            self.queue_rx.clone().unwrap(),
            interrupt.clone(),
        );

        self.device_state = DeviceState::Activated(mem, interrupt);

        debug!(
            "[VSOCK_TIMING] device.activate() completed in {:?}",
            activate_start.elapsed()
        );
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_requires_matching_recorded_host_network_protocol() {
        for abi in [
            None,
            Some(7),
            Some(super::super::HOST_NETWORK_ABI_VERSION),
            Some(9),
        ] {
            let state = VsockState {
                host_network_abi: abi,
                ..Default::default()
            };
            assert_eq!(
                state.validate_host_network(true).is_ok(),
                abi == Some(super::super::HOST_NETWORK_ABI_VERSION)
            );
            assert_eq!(state.validate_host_network(false).is_ok(), abi.is_none());
        }
    }

    #[test]
    fn save_state_uses_listener_metadata_captured_before_quiesce() {
        let mut vsock = Vsock::new(
            3,
            None,
            None,
            TsiFlags::empty(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let listener = ListenerDesc {
            family: defs::LINUX_AF_INET,
            peer_port: 41,
            control_port: 42,
            guest_port: 8080,
            backlog: 128,
            socket: None,
            accept_pending: false,
        };
        vsock.quiesced_listeners = Some(vec![listener.clone()]);

        assert_eq!(vsock.save_state().listeners, vec![listener]);
    }
}
