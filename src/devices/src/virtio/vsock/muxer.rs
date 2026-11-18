use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use super::super::Queue as VirtQueue;
use super::TsiFlags;
use super::VsockError;
use super::defs;
use super::defs::uapi;
use super::dns_filter::{
    DnsRequest, DnsWorker, EgressPolicy, FloorMode, floor_mode, is_addr_floored,
    is_addr_host_loopback, sockaddr_port,
};
use super::host_bind::{BindRequest, BindResponse};
use super::host_send::{HostSendRequest, PendingHostSend};
use super::muxer_rxq::{MuxerRxQ, rx_to_pkt};
use super::muxer_thread::MuxerThread;
use super::packet::TsiConnectReq;
use super::packet::{TsiGetnameRsp, VsockPacket};
use super::polling::update_live_polling;
use super::proxy::ProxyRawHandle;
#[cfg(test)]
use super::proxy::ProxyRemoval;
use super::proxy::{ListenerDesc, Proxy, ProxyError, ProxyStatus, ProxyUpdate, StreamIntercept};
use super::reaper::{ReapRequest, ReaperThread, apply_removal};
use super::snapshot_gate::SnapshotGate;
use super::sys;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use super::timesync::TimesyncThread;
use super::tsi_dgram::TsiDgramProxy;
use super::tsi_stream::TsiStreamProxy;
use super::unix::UnixProxy;
use super::vsock_addr::VsockAddr;
use crossbeam_channel::{Sender, unbounded};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use crate::virtio::InterruptTransport;

#[cfg(test)]
#[path = "host_bind_tests.rs"]
mod host_bind_tests;

pub type ProxyHandle = Arc<Mutex<Box<dyn Proxy>>>;
pub type ProxyTable = RwLock<HashMap<u64, ProxyHandle>>;
pub type ProxyMap = Arc<ProxyTable>;

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
    HostSendResponse {
        peer_port: u32,
        sequence: u64,
        result: i32,
    },
    BindResponse {
        local_port: u32,
        peer_port: u32,
        data: BindResponse,
    },
    Reset {
        local_port: u32,
        peer_port: u32,
    },
    Shutdown {
        local_port: u32,
        peer_port: u32,
        flags: u32,
        fwd_cnt: u32,
    },
    GetnameResponse {
        local_port: u32,
        peer_port: u32,
        data: TsiGetnameRsp,
    },
    ConnResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    OpRequest {
        local_port: u32,
        peer_port: u32,
    },
    OpResponse {
        local_port: u32,
        peer_port: u32,
    },
    CreditRequest {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    CreditUpdate {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    ListenResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    AcceptResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    /// A DNS response datagram synthesized by the DNS worker, delivered to the
    /// guest as an unconnected/connected UDP datagram.
    DgramDataDnsResponse {
        peer_port: u32,
        data: Vec<u8>,
        fwd_cnt: u32,
    },
}

pub fn push_packet(
    cid: u64,
    rx: MuxerRx,
    rxq_mutex: &Arc<Mutex<MuxerRxQ>>,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &GuestMemoryMmap,
    snapshot_gate: &SnapshotGate,
) {
    let _snapshot_activity = snapshot_gate.enter();
    let mut queue = queue_mutex.lock().unwrap();
    if let Some(head) = queue.pop(mem) {
        if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
            rx_to_pkt(cid, rx, &mut pkt);
            if let Err(e) = queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len()) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
    } else {
        error!("couldn't push pkt to queue, adding it to rxq");
        drop(queue);
        rxq_mutex.lock().unwrap().push(rx);
    }
}

pub struct VsockMuxer {
    cid: u64,
    host_port_map: Option<HashMap<u16, u16>>,
    queue: Option<Arc<Mutex<VirtQueue>>>,
    mem: Option<GuestMemoryMmap>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    epoll: Epoll,
    interrupt: Option<InterruptTransport>,
    proxy_map: ProxyMap,
    pending_datagram_rx: Arc<Mutex<HashSet<u64>>>,
    reaper_sender: Option<Sender<ReapRequest>>,
    unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    tsi_flags: TsiFlags,
    /// Optional egress policy (CIDRs + DNS allow-hosts + learned IPs).
    /// None = no allow-list (allow all EXCEPT the platform hard-floor below).
    egress_policy: Option<Arc<RwLock<EgressPolicy>>>,
    /// Platform hard-floor scope, resolved once from the deployment context. This
    /// is applied to EVERY connect/sendto, including the no-policy default case,
    /// so a guest can never reach cloud-metadata even with no allow-list set.
    floor: FloorMode,
    /// Sender to the DNS worker thread; Some only when DNS filtering is active.
    dns_sender: Option<Sender<DnsRequest>>,
    /// Host DNS forwarder that answers every guest UDP DNS query, if set.
    dns_forwarder: Option<std::net::SocketAddr>,
    snapshot_gate: Arc<SnapshotGate>,
    /// Stop host event handlers before pausing their nested guest-RX writes.
    host_event_gate: Arc<SnapshotGate>,
    /// Redirect guest stream connects to one destination port through a host
    /// interceptor (see `krun_set_stream_intercept`). Applied after the egress
    /// policy admitted the real destination.
    stream_intercept: Option<StreamIntercept>,
    /// Guest sockets whose host socket could not be created, with the errno,
    /// so the guest's connect fails with the reason (say, the host process
    /// is out of file descriptors) instead of a refusal from nowhere.
    failed_creates: Mutex<FailedCreates>,
    #[cfg(target_os = "macos")]
    host_icmp: Option<Result<Arc<super::macos_icmp::MacIcmp>, i32>>,
    #[cfg(target_os = "macos")]
    host_udp_router: Option<Result<Arc<super::macos_udp_router::DatagramRouter>, i32>>,
}

/// Bound on [`FailedCreates`]: guest sockets that fail to get a host socket
/// and are never connected must not grow it without limit.
const MAX_FAILED_CREATES: usize = 4096;
/// The shortest gap between two "host refused a socket" warnings.
const CREATE_WARNING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Default)]
struct FailedCreates {
    errnos: HashMap<u64, i32>,
    total: u64,
    reported: u64,
    last_warning: Option<std::time::Instant>,
}

impl FailedCreates {
    /// Remember why the host socket for guest socket `id` failed, and say so
    /// in the log at most once per interval.
    fn record(&mut self, id: u64, err: &ProxyError, open: usize) {
        let errno = match err {
            ProxyError::CreatingSocket(e) => sys::to_linux_errno(e),
            _ => return,
        };
        if self.errnos.len() >= MAX_FAILED_CREATES {
            self.errnos.clear();
        }
        self.errnos.insert(id, errno);
        self.total = self.total.saturating_add(1);
        let now = std::time::Instant::now();
        if self
            .last_warning
            .is_some_and(|at| now.duration_since(at) < CREATE_WARNING_INTERVAL)
        {
            return;
        }
        warn!(
            "the host could not open a socket for a guest connection ({err}) with {open} open; \
             raise this process's open-file limit; {} failed since the last report",
            self.total - self.reported
        );
        self.reported = self.total;
        self.last_warning = Some(now);
    }
}

impl VsockMuxer {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
        egress_cidrs: Option<Vec<(IpAddr, u8)>>,
        egress_hosts: Option<Vec<String>>,
        egress_resolvers: Option<Vec<IpAddr>>,
        dns_forwarder: Option<std::net::SocketAddr>,
        stream_intercept: Option<StreamIntercept>,
    ) -> Self {
        if let Some(ref intercept) = stream_intercept {
            info!(
                "stream intercept configured: guest port {} -> {}",
                intercept.port, intercept.endpoint
            );
        }
        if let Some(ref cidrs) = egress_cidrs {
            info!("egress policy configured with {} CIDR rule(s)", cidrs.len());
        }
        if let Some(ref hosts) = egress_hosts {
            info!("DNS filter configured with {} host rule(s)", hosts.len());
        }
        let egress_policy = EgressPolicy::new(egress_cidrs, egress_hosts, egress_resolvers)
            .map(|policy| Arc::new(RwLock::new(policy)));
        let epoll = Epoll::new().unwrap();
        #[cfg(target_os = "macos")]
        let host_icmp = tsi_flags.contains(TsiFlags::HOST_BIND).then(|| {
            super::macos_icmp::MacIcmp::new(&epoll)
                .map(Arc::new)
                .map_err(|error| -sys::to_linux_errno(&error))
        });
        #[cfg(target_os = "macos")]
        let host_udp_router = tsi_flags.contains(TsiFlags::HOST_BIND).then(|| {
            super::macos_udp_router::DatagramRouter::new(&epoll)
                .map(Arc::new)
                .map_err(|error| -sys::to_linux_errno(&error))
        });
        VsockMuxer {
            #[cfg(target_os = "macos")]
            host_udp_router,
            #[cfg(target_os = "macos")]
            host_icmp,
            cid,
            host_port_map,
            queue: None,
            mem: None,
            rxq: Arc::new(Mutex::new(MuxerRxQ::new())),
            epoll,
            interrupt: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
            pending_datagram_rx: Arc::new(Mutex::new(HashSet::new())),
            reaper_sender: None,
            unix_ipc_port_map,
            tsi_flags,
            egress_policy,
            floor: floor_mode()
                .with_host_network(tsi_flags.contains(TsiFlags::HIJACK_INET | TsiFlags::HOST_BIND)),
            dns_sender: None,
            dns_forwarder,
            snapshot_gate: Arc::new(SnapshotGate::default()),
            host_event_gate: Arc::new(SnapshotGate::default()),
            stream_intercept,
            failed_creates: Mutex::new(FailedCreates::default()),
        }
    }

    /// Check if the given socket address is allowed for egress. The platform
    /// hard-floor is enforced FIRST and unconditionally — even with no allow-list
    /// — so a guest can never reach cloud-metadata (and, under fleet mode, the
    /// host/control internal subnets). Past the floor: true if no allow-list is
    /// set (allow all), the IP matches a CIDR, or the IP was learned from an
    /// allowed DNS answer. Fail-closed on a poisoned policy lock.
    fn is_ip_allowed(&self, addr: &VsockAddr) -> bool {
        if is_addr_floored(addr, self.floor) {
            // Only host loopback, floored by the local default, may be
            // deliberately re-opened by an EXPLICIT static allow-list entry
            // (`--allow-cidr`, `--outbound-localhost-only`) — e.g. a dev reaching
            // a server on the host's own 127.0.0.1. Cloud-metadata (link-local)
            // and, under `Strict` (multi-tenant/fleet), the internal ranges stay
            // absolute: no allow-list can re-expose the credential/control door.
            // A learned DNS IP never qualifies (see `is_addr_explicitly_allowed`),
            // so this is not a rebinding hole.
            if self.floor != FloorMode::Strict && is_addr_host_loopback(addr) {
                return self.egress_policy.as_ref().is_some_and(|policy| {
                    policy
                        .read()
                        .map(|policy| policy.is_addr_explicitly_allowed(addr))
                        .unwrap_or(false)
                });
            }
            return false;
        }
        let Some(policy) = &self.egress_policy else {
            return true;
        };
        policy
            .read()
            .map(|policy| policy.is_addr_allowed(addr))
            .unwrap_or(false)
    }

    /// Whether this destination is a DNS query to intercept: DNS filtering is
    /// active (a worker exists) and the destination port is 53.
    fn is_dns_dest(&self, addr: &VsockAddr) -> bool {
        self.dns_sender.is_some() && sockaddr_port(addr) == Some(super::dns_filter::DNS_PORT)
    }

    pub(crate) fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
    ) {
        let activate_start = std::time::Instant::now();
        debug!("[VSOCK_TIMING] muxer.activate() called, cid={}", self.cid);

        self.queue = Some(queue.clone());
        self.mem = Some(mem.clone());
        self.interrupt = Some(interrupt.clone());

        // The guest wall-clock is synced from the host over a vsock DGRAM here on
        // hypervisors without a paravirt clock the guest can read directly:
        // macOS/HVF and Windows/WHP. (On Linux/KVM the guest uses kvmclock, so
        // this is unnecessary.) Without it the WHP guest boots at ~1999 and all
        // TLS cert validation fails ("certificate not yet valid").
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            debug!("[VSOCK_TIMING] starting TimesyncThread");
            let timesync = TimesyncThread::new(
                self.cid,
                mem.clone(),
                queue.clone(),
                interrupt.clone(),
                self.snapshot_gate.clone(),
            );
            timesync.run();
            debug!("[VSOCK_TIMING] TimesyncThread started");
        }

        // Spawn the DNS worker (off-muxer blocking resolution) when DNS
        // filtering is active or a host forwarder takes the guest's DNS. The
        // dgram proxy treats `dns_sender.is_some()` as "intercept port 53".
        let dns_active = self
            .egress_policy
            .as_ref()
            .is_some_and(|policy| policy.read().map(|p| p.dns_active()).unwrap_or(false));
        if dns_active || self.dns_forwarder.is_some() {
            let (dns_sender, dns_receiver) = unbounded::<DnsRequest>();
            let worker = DnsWorker::new(
                dns_receiver,
                Arc::downgrade(&self.proxy_map),
                self.egress_policy.clone(),
                self.dns_forwarder,
                mem.clone(),
                queue.clone(),
                self.rxq.clone(),
                interrupt.clone(),
                self.snapshot_gate.clone(),
            );
            worker.run();
            self.dns_sender = Some(dns_sender);
            debug!("[VSOCK_TIMING] DnsWorker spawned");
        }

        let (sender, receiver) = unbounded();

        debug!(
            "[VSOCK_TIMING] creating MuxerThread with {} unix_ipc_ports",
            self.unix_ipc_port_map
                .as_ref()
                .map(|m| m.len())
                .unwrap_or(0)
        );
        let thread = MuxerThread::new(
            self.cid,
            self.epoll.clone(),
            self.rxq.clone(),
            self.proxy_map.clone(),
            mem,
            queue,
            interrupt.clone(),
            sender.clone(),
            self.unix_ipc_port_map.clone().unwrap_or_default(),
            self.snapshot_gate.clone(),
            self.host_event_gate.clone(),
            #[cfg(target_os = "macos")]
            self.host_icmp
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .cloned(),
            #[cfg(target_os = "macos")]
            self.host_udp_router
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .cloned(),
        );
        thread.run();
        debug!("[VSOCK_TIMING] MuxerThread spawned");

        self.reaper_sender = Some(sender);
        let reaper = ReaperThread::new(receiver, self.proxy_map.clone());
        reaper.run();
        debug!("[VSOCK_TIMING] ReaperThread spawned");

        debug!(
            "[VSOCK_TIMING] muxer.activate() completed in {:?}",
            activate_start.elapsed()
        );
    }

    pub(crate) fn quiesce_for_snapshot(&self) {
        // A handler can hold a proxy/table lock while entering the RX gate.
        // Drain whole handlers first so restore can safely inspect or replace
        // proxies after RX has stopped. These gates must not be nested in the
        // opposite order, or pause would wait on its own blocked producer.
        self.host_event_gate.pause();
        self.snapshot_gate.pause();
        // A producer normally signals just after releasing the RX queue. If
        // snapshot quiescing lands in that small gap, make the already-written
        // used entries visible before the interrupt-controller state is saved.
        // Virtio permits spurious notifications, so this is also safe when the
        // queue had no pending update.
        if let Some(interrupt) = &self.interrupt {
            interrupt.signal_used_queue();
        }
    }

    pub(crate) fn rearm_after_snapshot(&self) {
        self.snapshot_gate.resume();
        self.host_event_gate.resume();
    }

    /// Deliver nothing to the guest until it has handled a transport reset.
    ///
    /// The guest handles the reset event asynchronously and resets every
    /// connected socket it has at that moment, without telling the peer. A
    /// host connection delivered before that would be reset too, and its host
    /// end would wait forever. The fallback is armed after activation, once
    /// the device's TX event is available to wake held requests.
    pub(crate) fn hold_rx_for_transport_reset(&self) {
        self.snapshot_gate.hold_for_transport_reset();
    }

    pub(crate) fn arm_transport_reset_timeout(&self, fallback: Duration, tx_event: Arc<EventFd>) {
        let gate = self.snapshot_gate.clone();
        let Some(generation) = gate.transport_reset_generation() else {
            return;
        };
        std::thread::Builder::new()
            .name("vsock-reset-hold".into())
            .spawn(move || {
                std::thread::sleep(fallback);
                if gate.expire_transport_reset(generation) {
                    warn!("vsock: guest did not acknowledge the transport reset; releasing RX");
                    // A TX event may have been consumed while RX was held.
                    // Wake the device loop to drain it even without a guest ACK.
                    if let Err(error) = tx_event.write(1) {
                        error!("vsock: failed to wake TX after reset timeout: {error}");
                    }
                }
            })
            .map(drop)
            .unwrap_or_else(|e| error!("vsock: failed to start reset hold timer: {e}"));
    }

    pub(crate) fn release_rx_after_transport_reset(&self) {
        self.snapshot_gate.release_transport_reset();
    }

    pub(crate) fn rx_held_for_transport_reset(&self) -> bool {
        self.snapshot_gate.is_held_for_transport_reset()
    }

    /// Resume only host datagrams that exhausted the RX descriptors. Called
    /// after dropping the virtqueue lock: proxies acquire it while delivering.
    pub(crate) fn resume_datagram_rx(&self) -> bool {
        if !self.tsi_flags.contains(TsiFlags::HOST_BIND) {
            return false;
        }
        let ids: Vec<_> = self
            .pending_datagram_rx
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect();
        let mut used = false;
        for id in ids {
            let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
                (
                    proxy.clone(),
                    proxy.lock().unwrap().process_event(EventSet::IN),
                )
            });
            if let Some(update) = update {
                used |= update.1.signal_queue;
                self.process_proxy_update(id, update);
            }
        }
        used
    }

    pub(crate) fn has_pending_rx(&self) -> bool {
        !self.rxq.lock().unwrap().is_empty()
    }

    pub(crate) fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        debug!("recv_stream_pkt");
        if self.rxq.lock().unwrap().is_empty() {
            return Err(VsockError::NoData);
        }

        if let Some(rx) = self.rxq.lock().unwrap().pop() {
            rx_to_pkt(self.cid, rx, pkt);
        }

        Ok(())
    }

    fn push_packet(&self, rx: MuxerRx) {
        let mem = match self.mem.as_ref() {
            Some(m) => m,
            None => {
                error!("proxy creation without mem");
                return;
            }
        };
        let queue_mutex = match self.queue.as_ref() {
            Some(q) => q,
            None => {
                error!("stream proxy creation without stream queue");
                return;
            }
        };

        let _snapshot_activity = self.snapshot_gate.enter();
        let mut queue = queue_mutex.lock().unwrap();
        if let Some(head) = queue.pop(mem) {
            if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
                rx_to_pkt(self.cid, rx, &mut pkt);
                if let Err(e) = queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len())
                {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            }
        } else {
            error!("couldn't push pkt to queue, adding it to rxq");
            drop(queue);
            self.rxq.lock().unwrap().push(rx);
        }
    }

    /// Reset all live host-backed connections for a VM restore/rewind.
    ///
    /// Drops every active connection proxy — agent unix-IPC connections *and*
    /// TSI network-egress sockets — which closes their host fds (also removing
    /// them from the shared epoll, since closing an fd evicts it) and clears the
    /// pending RX queue. Host IPC acceptors are preserved (e.g. the agent
    /// channel); TSI listeners are dropped and rebuilt from the checkpoint.
    /// The guest receives a transport reset so its old streams reconnect too.
    ///
    /// Safe to call concurrently with the `MuxerThread`: the proxy_map/rxq are
    /// the same `RwLock`/`Mutex`-guarded structures it uses, and it tolerates a
    /// proxy disappearing between epoll wakeup and lookup.
    pub(crate) fn reset_connections(&self) {
        let removed = {
            let mut map = self.proxy_map.write().unwrap();
            let before = map.len();
            map.retain(|_id, proxy| proxy.lock().unwrap().is_listener());
            before - map.len()
        };
        self.rxq.lock().unwrap().clear();
        self.pending_datagram_rx.lock().unwrap().clear();
        self.failed_creates.lock().unwrap().errnos.clear();
        info!("vsock muxer reset on restore: dropped {removed} connection proxy(ies)");
    }

    /// Capture every live TSI inbound-port-forward listener for VM checkpoint/fork
    /// (see [`ListenerDesc`]). The muxer's `proxy_map` is otherwise not part of the
    /// device snapshot, so without this a fork clone loses all inbound forwards.
    pub(crate) fn host_network_enabled(&self) -> bool {
        self.tsi_flags.contains(TsiFlags::HOST_BIND)
    }

    pub(crate) fn snapshot_listeners(&self) -> Vec<ListenerDesc> {
        self.proxy_map
            .read()
            .unwrap()
            .values()
            .filter_map(|p| p.lock().unwrap().listener_desc())
            .collect()
    }

    /// Re-establish inbound-port-forward listeners on a freshly-restored clone,
    /// binding each to the *clone's* own `host_port_map`. The guest's listening
    /// sockets are already restored in RAM (CoW) but never re-issue `TSI_LISTEN`,
    /// so the host side must be rebuilt here. Must run after [`Self::activate`]
    /// (needs `mem`/`queue`). Preserves each listener's `peer_port`/`control_port`
    /// so host-accepted connections route to the guest's existing socket.
    pub(crate) fn restore_listeners(&self, descs: Vec<ListenerDesc>) -> Result<(), String> {
        let mem = self
            .mem
            .as_ref()
            .ok_or("restore listeners before memory activation")?;
        let queue = self
            .queue
            .as_ref()
            .ok_or("restore listeners before queue activation")?;
        // Prepare every socket before installing any. A conflict must return
        // an error and leave no partially restored listeners in the muxer.
        let mut prepared = Vec::with_capacity(descs.len());
        for d in descs {
            let id = ((d.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            if self.proxy_map.read().unwrap().contains_key(&id)
                || prepared.iter().any(|(other, _)| *other == id)
            {
                return Err(format!("duplicate restored listener {id:#x}"));
            }
            let mut proxy = TsiStreamProxy::new(
                id,
                self.cid,
                d.family,
                defs::TSI_PROXY_PORT,
                d.peer_port,
                d.control_port,
                mem.clone(),
                queue.clone(),
                self.rxq.clone(),
                self.snapshot_gate.clone(),
                self.tsi_flags.contains(TsiFlags::HOST_BIND),
            )
            .map_err(|e| format!("recreate listener {}: {e}", d.guest_port))?;
            proxy.relisten(&d, &self.host_port_map)?;
            prepared.push((id, proxy));
        }
        for (id, proxy) in prepared {
            let fd = proxy.poll_handle();
            self.proxy_map
                .write()
                .unwrap()
                .insert(id, Arc::new(Mutex::new(Box::new(proxy))));
            self.update_polling(id, fd, EventSet::IN);
        }
        Ok(())
    }

    pub fn update_polling(&self, id: u64, fd: ProxyRawHandle, evset: EventSet) {
        debug!("update_polling id={id} fd={fd:?} evset={evset:?}");
        let _ = self
            .epoll
            .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
        if !evset.is_empty() {
            let _ = self
                .epoll
                .ctl(ControlOperation::Add, fd, &EpollEvent::new(evset, id));
        }
    }

    fn process_proxy_update(&self, id: u64, (source, update): (ProxyHandle, ProxyUpdate)) {
        if let Some(polling) = update.polling {
            update_live_polling(
                &self.proxy_map,
                &self.epoll,
                polling.0,
                polling.1,
                polling.2,
            );
        }

        apply_removal(
            &self.proxy_map,
            self.reaper_sender.as_ref(),
            id,
            &source,
            update.remove_proxy,
        );

        if update.signal_queue
            && let Some(interrupt) = &self.interrupt
        {
            interrupt.signal_used_queue();
        }
    }

    fn process_proxy_create(&self, pkt: &VsockPacket) {
        debug!("proxy create request");
        if let Some(req) = pkt.read_proxy_create() {
            debug!(
                "proxy create request: peer_port={}, type={}",
                req.peer_port, req._type
            );
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    error!("proxy creation without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    error!("stream proxy creation without stream queue");
                    return;
                }
            };
            match req._type {
                defs::SOCK_STREAM => {
                    debug!("proxy create stream");
                    let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
                    if req.family == defs::LINUX_AF_UNIX
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_UNIX)
                    {
                        warn!("rejecting stream unix proxy because HIJACK_UNIX is disabled");
                        return;
                    }
                    if (req.family == defs::LINUX_AF_INET || req.family == defs::LINUX_AF_INET6)
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_INET)
                    {
                        warn!("rejecting stream inet proxy because HIJACK_INET is disabled");
                        return;
                    }
                    match TsiStreamProxy::new(
                        id,
                        self.cid,
                        req.family,
                        defs::TSI_PROXY_PORT,
                        req.peer_port,
                        pkt.src_port(),
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                        self.snapshot_gate.clone(),
                        self.tsi_flags.contains(TsiFlags::HOST_BIND),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Arc::new(Mutex::new(Box::new(proxy))));
                        }
                        Err(e) => {
                            let open = self.proxy_map.read().unwrap().len();
                            self.failed_creates.lock().unwrap().record(id, &e, open);
                        }
                    }
                }
                defs::SOCK_DGRAM => {
                    debug!("proxy create dgram");
                    let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
                    if req.family == defs::LINUX_AF_UNIX
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_UNIX)
                    {
                        warn!("rejecting dgram unix proxy because HIJACK_UNIX is disabled");
                        return;
                    }
                    if (req.family == defs::LINUX_AF_INET || req.family == defs::LINUX_AF_INET6)
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_INET)
                    {
                        warn!("rejecting dgram inet proxy because HIJACK_INET is disabled");
                        return;
                    }
                    match TsiDgramProxy::new(
                        id,
                        self.cid,
                        req.family,
                        req.peer_port,
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                        self.dns_sender.clone(),
                        self.snapshot_gate.clone(),
                        self.pending_datagram_rx.clone(),
                        self.epoll.clone(),
                        #[cfg(target_os = "macos")]
                        self.host_udp_router
                            .as_ref()
                            .and_then(|result| result.as_ref().ok())
                            .cloned(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Arc::new(Mutex::new(Box::new(proxy))));
                        }
                        Err(e) => {
                            let open = self.proxy_map.read().unwrap().len();
                            self.failed_creates.lock().unwrap().record(id, &e, open);
                        }
                    }
                }
                _ => debug!("unknown type on connection request"),
            };
        }
    }

    fn process_connect(&self, pkt: &VsockPacket) {
        debug!("proxy connect request");
        if let Some(peer_port) = pkt.read_disconnect_req() {
            let id = ((peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            let (result, update) = if self.tsi_flags.contains(TsiFlags::HOST_BIND) {
                match self.proxy_map.read().unwrap().get(&id) {
                    Some(proxy) => {
                        let (result, update) = proxy.lock().unwrap().disconnect_host_datagram();
                        (result, Some((proxy.clone(), update)))
                    }
                    None => (Err(-107), None), // Linux ENOTCONN.
                }
            } else {
                (Err(-95), None)
            };
            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
            self.push_packet(MuxerRx::ConnResponse {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
                result: result.err().unwrap_or(0),
            });
            return;
        }
        if let Some(req) = pkt.read_connect_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("proxy connect request: id={id}");
            let update = match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    let source = proxy.clone();
                    let mut proxy = proxy.lock().unwrap();
                    // A DGRAM connect to a resolver (port 53) is allowed so
                    // it can be intercepted; any other destination must pass
                    // the egress policy (CIDR or learned IP).
                    let dns = proxy.is_dgram() && self.is_dns_dest(&req.addr);
                    if !dns && !self.is_ip_allowed(&req.addr) {
                        warn!("egress policy denied connect to {}", req.addr);
                        self.push_packet(MuxerRx::ConnResponse {
                            local_port: pkt.dst_port(),
                            peer_port: pkt.src_port(),
                            result: -libc::EACCES,
                        });
                        return;
                    }
                    let redirected = self.stream_intercept.as_ref().filter(|intercept| {
                        !proxy.is_dgram()
                            && req.addr.inet().is_some_and(|a| a.port() == intercept.port)
                    });
                    let update = match redirected {
                        Some(intercept) => proxy.connect_intercepted(pkt, req, intercept),
                        None => proxy.connect(pkt, req),
                    };
                    (source, update)
                }
                None => {
                    // No proxy: its host socket could not be created (say why),
                    // or the guest never asked for one.
                    let errno = self
                        .failed_creates
                        .lock()
                        .unwrap()
                        .errnos
                        .remove(&id)
                        .unwrap_or(super::super::linux_errno::LINUX_ECONNREFUSED);
                    self.push_packet(MuxerRx::ConnResponse {
                        local_port: pkt.dst_port(),
                        peer_port: pkt.src_port(),
                        result: -errno,
                    });
                    return;
                }
            };
            // Applied with no proxy_map guard held: a removal takes the write lock.
            self.process_proxy_update(id, update);
        } else {
            self.push_packet(MuxerRx::ConnResponse {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
                result: -22,
            });
        }
    }

    fn process_getname(&self, pkt: &VsockPacket) {
        debug!("new getname request");
        if let Some(req) = pkt.read_getname_req() {
            let id = ((req.peer_port as u64) << 32) | (req.local_port as u64);
            debug!(
                "new getname request: id={}, peer_port={}, local_port={}",
                id, req.peer_port, req.local_port
            );

            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => proxy.lock().unwrap().getpeername(pkt),
                None => self.push_packet(MuxerRx::GetnameResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    data: TsiGetnameRsp {
                        result: -libc::EINVAL,
                        addr_len: 0,
                        addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
                    },
                }),
            }
        }
    }

    fn process_sendto_addr(&self, pkt: &VsockPacket) {
        debug!("new DGRAM sendto addr: src={}", pkt.src_port());
        if let Some(req) = pkt.read_sendto_addr() {
            // A DGRAM sendto a resolver (port 53) is allowed so it can be
            // intercepted; any other destination must pass the egress policy.
            if !self.is_dns_dest(&req.addr) && !self.is_ip_allowed(&req.addr) {
                warn!("egress policy denied sendto {}", req.addr);
                // Never let the following payload reuse a prior destination.
                let id = ((req.peer_port as u64) << 32) | defs::TSI_PROXY_PORT as u64;
                if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                    proxy.lock().unwrap().clear_sendto_addr();
                }
                return;
            }

            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("new DGRAM sendto addr: id={id}");
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| (proxy.clone(), proxy.lock().unwrap().sendto_addr(req)));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_host_sendto_addr(&self, pkt: &VsockPacket) {
        let Some(mut req) = pkt.data().and_then(HostSendRequest::parse) else {
            self.push_packet(MuxerRx::HostSendResponse {
                peer_port: pkt.src_port(),
                sequence: 0,
                result: -22,
            });
            return;
        };
        if !self
            .tsi_flags
            .contains(TsiFlags::HIJACK_INET | TsiFlags::HOST_BIND)
            || self.host_port_map.is_some()
        {
            req.destination = Err(-1);
        } else if req
            .destination
            .as_ref()
            .is_ok_and(|addr| !self.is_ip_allowed(addr))
        {
            req.destination = Err(-13);
        }
        let id = ((req.peer_port as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        let result = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .ok_or(-9)
            .and_then(|proxy| {
                proxy.lock().unwrap().prepare_host_send(PendingHostSend {
                    control_port: pkt.src_port(),
                    sequence: req.sequence,
                    destination: req.destination,
                })
            });
        if let Err(result) = result {
            self.push_packet(MuxerRx::HostSendResponse {
                peer_port: pkt.src_port(),
                sequence: req.sequence,
                result,
            });
        }
    }

    fn process_sendto_data(&self, pkt: &VsockPacket) {
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
        debug!("DGRAM sendto data: id={} src={}", id, pkt.src_port());
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().sendto_data(pkt);
        }
    }

    fn process_host_setsockopt(&self, pkt: &VsockPacket) {
        let allowed = self
            .tsi_flags
            .contains(TsiFlags::HIJACK_INET | TsiFlags::HOST_BIND)
            && self.host_port_map.is_none();
        let result = if !allowed {
            Err(-1)
        } else if let Some(req) = pkt
            .data()
            .and_then(super::host_sockopt::OptionRequest::parse)
        {
            let id = ((req.peer_port as u64) << 32) | req.local_port as u64;
            let proxies = self.proxy_map.read().unwrap();
            match proxies.get(&id) {
                Some(proxy) => proxy.lock().unwrap().set_host_option(&req),
                None => Err(-9),
            }
        } else {
            Err(-22)
        };
        self.push_packet(MuxerRx::BindResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            data: BindResponse::status(result),
        });
    }

    fn process_host_stream_close(&self, pkt: &VsockPacket) {
        let request = pkt.data().and_then(super::host_close::CloseRequest::parse);
        let allowed = self
            .tsi_flags
            .contains(TsiFlags::HIJACK_INET | TsiFlags::HOST_BIND)
            && self.host_port_map.is_none();
        let (result, update) = if !allowed {
            (-1, None)
        } else if let Some(req) = request {
            let id = ((req.peer_port as u64) << 32) | req.local_port as u64;
            let map = self.proxy_map.read().unwrap();
            match map.get(&id) {
                Some(proxy) => {
                    let (result, update) = proxy.lock().unwrap().close_host_stream(&req);
                    (result, Some((id, (proxy.clone(), update))))
                }
                // The peer may have reset and the closed-proxy grace period
                // expired while the guest was in a long linger wait.
                None => (0, None),
            }
        } else {
            (-22, None)
        };
        if let Some((id, update)) = update {
            self.process_proxy_update(id, update);
        }
        // Normal and abortive closes do not wait on the control socket. Only
        // positive linger needs a response, so avoid queueing unused replies.
        if request.is_some_and(|req| req.flags != super::host_close::WAIT) {
            return;
        }
        self.push_packet(MuxerRx::BindResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            data: BindResponse::status(if result == 0 { Ok(()) } else { Err(result) }),
        });
    }

    fn process_listener_shutdown(&self, pkt: &VsockPacket) {
        let data = pkt.data().filter(|data| data.len() == 8);
        let (result, update) = if let Some(data) = data {
            let peer = u32::from_le_bytes(data[..4].try_into().unwrap());
            let mode = u32::from_le_bytes(data[4..].try_into().unwrap());
            let id = ((peer as u64) << 32) | defs::TSI_PROXY_PORT as u64;
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    let (result, update) = proxy.lock().unwrap().shutdown_listener(mode);
                    (result, Some((id, (proxy.clone(), update))))
                }
                None => (-9, None),
            }
        } else {
            (-22, None)
        };
        if let Some((id, update)) = update {
            self.process_proxy_update(id, update);
        }
        self.push_packet(MuxerRx::BindResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            data: BindResponse::status(if result == 0 { Ok(()) } else { Err(result) }),
        });
    }

    fn process_bind_request(&self, pkt: &VsockPacket) {
        // This is a new capability, not a way around the legacy publishing
        // allow-list. Even an empty map deliberately forbids direct host binds.
        let allowed = self
            .tsi_flags
            .contains(TsiFlags::HIJACK_INET | TsiFlags::HOST_BIND)
            && self.host_port_map.is_none();
        let mut update = None;
        let result = if !allowed {
            Err(-libc::EPERM)
        } else if let Some(req) = pkt.data().and_then(BindRequest::parse) {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            let map = self.proxy_map.read().unwrap();
            match map.get(&id) {
                Some(proxy) => {
                    let source = proxy.clone();
                    let mut proxy = proxy.lock().unwrap();
                    #[cfg(target_os = "macos")]
                    let result = if proxy.is_dgram() {
                        match (&self.host_icmp, &self.host_udp_router) {
                            (Some(Ok(_)), Some(Ok(_))) => proxy.bind_host(&req),
                            (Some(Err(error)), _) | (_, Some(Err(error))) => Err(*error),
                            _ => Err(-95),
                        }
                    } else {
                        proxy.bind_host(&req)
                    };
                    #[cfg(not(target_os = "macos"))]
                    let result = proxy.bind_host(&req);
                    if result.is_ok() && proxy.is_dgram() {
                        update = Some((
                            id,
                            (
                                source,
                                ProxyUpdate {
                                    polling: Some((id, proxy.poll_handle(), EventSet::IN)),
                                    ..Default::default()
                                },
                            ),
                        ));
                    }
                    result
                }
                None => Err(-libc::EBADF),
            }
        } else {
            Err(-libc::EINVAL)
        };
        // Register UDP reads with no proxy-map lock held. The host socket is
        // already bound when success is sent; conflicts cannot be hidden by
        // later best-effort publication.
        if let Some((id, update)) = update {
            self.process_proxy_update(id, update);
        }
        self.push_packet(MuxerRx::BindResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            data: BindResponse::from(result),
        });
    }

    fn process_listen_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM listen request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_listen_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM listen request: id={id}");
            let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
                (
                    proxy.clone(),
                    proxy.lock().unwrap().listen(pkt, req, &self.host_port_map),
                )
            });
            match update {
                Some(update) => self.process_proxy_update(id, update),
                None => self.push_packet(MuxerRx::ListenResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EPERM,
                }),
            }
        }
    }

    fn process_accept_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM accept request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_accept_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM accept request: id={id}");
            let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
                (
                    proxy.clone(),
                    proxy.lock().unwrap().accept(pkt.src_port(), req),
                )
            });
            match update {
                Some(update) => self.process_proxy_update(id, update),
                None => self.push_packet(MuxerRx::AcceptResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EINVAL,
                }),
            }
        }
    }

    fn process_proxy_release(&self, pkt: &VsockPacket) {
        debug!("DGRAM release request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_release_req() {
            let id = ((req.peer_port as u64) << 32) | (req.local_port as u64);
            debug!(
                "DGRAM release request: id={} local_port={} peer_port={}",
                id, req.local_port, req.peer_port
            );
            let update = if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                Some((proxy.clone(), proxy.lock().unwrap().release()))
            } else {
                debug!(
                    "release without proxy: id={}, proxies={}",
                    id,
                    self.proxy_map.read().unwrap().len()
                );
                None
            };

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
        debug!(
            "DGRAM release request: proxies={}",
            self.proxy_map.read().unwrap().len()
        );
    }

    fn process_dgram_rw(&self, pkt: &VsockPacket) {
        debug!("DGRAM OP_RW");
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);

        let update = if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!("DGRAM allowing OP_RW for {}", pkt.src_port());
            Some((proxy_lock.clone(), proxy_lock.lock().unwrap().sendmsg(pkt)))
        } else {
            debug!("DGRAM ignoring OP_RW for {}", pkt.src_port());
            None
        };
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    pub(crate) fn send_dgram_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "send_dgram_pkt: src_port={} dst_port={}",
            pkt.src_port(),
            pkt.dst_port()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!("dropping guest packet for unknown CID: {:?}", pkt.hdr());
            return Ok(());
        }

        match pkt.dst_port() {
            defs::TSI_PROXY_CREATE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_create(pkt)
            }
            defs::TSI_CONNECT if self.tsi_flags.tsi_enabled() => self.process_connect(pkt),
            defs::TSI_GETNAME if self.tsi_flags.tsi_enabled() => self.process_getname(pkt),
            defs::TSI_SENDTO_ADDR if self.tsi_flags.tsi_enabled() => self.process_sendto_addr(pkt),
            defs::TSI_SENDTO_DATA if self.tsi_flags.tsi_enabled() => self.process_sendto_data(pkt),
            defs::TSI_BIND => self.process_bind_request(pkt),
            defs::TSI_HOST_SETSOCKOPT => self.process_host_setsockopt(pkt),
            defs::TSI_HOST_STREAM_CLOSE => self.process_host_stream_close(pkt),
            defs::TSI_LISTENER_SHUTDOWN if self.tsi_flags.tsi_enabled() => {
                self.process_listener_shutdown(pkt)
            }
            defs::TSI_HOST_SENDTO_ADDR => self.process_host_sendto_addr(pkt),
            defs::TSI_LISTEN if self.tsi_flags.tsi_enabled() => self.process_listen_request(pkt),
            defs::TSI_ACCEPT if self.tsi_flags.tsi_enabled() => self.process_accept_request(pkt),
            defs::TSI_PROXY_RELEASE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_release(pkt)
            }
            _ => {
                if pkt.op() == uapi::VSOCK_OP_RW {
                    self.process_dgram_rw(pkt);
                } else {
                    error!("unexpected dgram pkt: {}", pkt.op());
                }
            }
        }

        Ok(())
    }

    fn process_op_request(&mut self, pkt: &VsockPacket) {
        debug!("OP_REQUEST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        debug!(
            "[VSOCK_TIMING] process_op_request: id={:#x} src_port={} dst_port={}",
            id,
            pkt.src_port(),
            pkt.dst_port()
        );
        let mut proxy_map = self.proxy_map.write().unwrap();

        if let Some(proxy) = proxy_map.get(&id) {
            let update = proxy
                .lock()
                .unwrap()
                .confirm_connect(pkt)
                .map(|update| (proxy.clone(), update));
            // The write guard must be gone before a removal re-takes it.
            drop(proxy_map);
            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        } else {
            // AF_UNIX host-IPC connect target. AF_UNIX is available on both Unix
            // and Windows (via socket2), so this path is cross-platform.
            if let Some(ipc_map) = &mut self.unix_ipc_port_map
                && let Some((path, listen)) = ipc_map.get(&pkt.dst_port())
            {
                let mem = self.mem.as_ref().unwrap();
                let queue = self.queue.as_ref().unwrap();
                if *listen {
                    warn!("Attempting to connect a socket that is listening, sending rst");
                    let rx = MuxerRx::Reset {
                        local_port: pkt.dst_port(),
                        peer_port: pkt.src_port(),
                    };
                    push_packet(self.cid, rx, &self.rxq, queue, mem, &self.snapshot_gate);
                    return;
                }
                let rxq = self.rxq.clone();

                let mut unix = match UnixProxy::new(
                    id,
                    self.cid,
                    pkt.dst_port(),
                    pkt.src_port(),
                    mem.clone(),
                    queue.clone(),
                    rxq,
                    path.to_path_buf(),
                    self.snapshot_gate.clone(),
                ) {
                    Ok(unix) => unix,
                    // e.g. EMFILE: the guest can open connections faster than they close.
                    Err(e) => {
                        warn!("host-IPC proxy for {path:?} failed, sending rst: {e:?}");
                        let rx = MuxerRx::Reset {
                            local_port: pkt.dst_port(),
                            peer_port: pkt.src_port(),
                        };
                        push_packet(self.cid, rx, &self.rxq, queue, mem, &self.snapshot_gate);
                        return;
                    }
                };
                let tsi = TsiConnectReq {
                    peer_port: 0,
                    addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
                };
                let update = unix.connect(pkt, tsi);
                if unix.status() == ProxyStatus::Idle {
                    // connect() hit a hard, immediate failure (e.g. EAGAIN when
                    // the target's accept backlog is momentarily full) rather
                    // than succeeding or going Connecting. Tell the guest's
                    // real connect() it failed instead of unconditionally
                    // confirming a connection that never happened -- otherwise
                    // the guest believes it's connected, writes into a proxy
                    // whose backing socket was never connected, and hangs
                    // forever waiting for a response that can't arrive.
                    warn!(
                        "host-IPC connect to {:?} failed, sending rst: id={:#x}",
                        path, id
                    );
                    let rx = MuxerRx::Reset {
                        local_port: pkt.dst_port(),
                        peer_port: pkt.src_port(),
                    };
                    push_packet(self.cid, rx, &self.rxq, queue, mem, &self.snapshot_gate);
                    return;
                }
                unix.confirm_connect(pkt);
                let source: ProxyHandle = Arc::new(Mutex::new(Box::new(unix)));
                proxy_map.insert(id, source.clone());
                drop(proxy_map);
                self.process_proxy_update(id, (source, update));
            }
        }
    }

    fn process_op_response(&self, pkt: &VsockPacket) {
        debug!("OP_RESPONSE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        debug!(
            "[VSOCK_TIMING] process_op_response: id={:#x} src_port={} dst_port={}",
            id,
            pkt.src_port(),
            pkt.dst_port()
        );
        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
            (
                proxy.clone(),
                proxy.lock().unwrap().process_op_response(pkt),
            )
        });

        if update.is_none() {
            debug!(
                "[VSOCK_TIMING] process_op_response: NO PROXY FOUND for id={:#x}",
                id
            );
        }

        update
            .as_ref()
            .and_then(|(_, u)| u.push_accept)
            .and_then(|(_id, parent_id)| {
                self.proxy_map
                    .read()
                    .unwrap()
                    .get(&parent_id)
                    .map(|proxy| proxy.lock().unwrap().enqueue_accept())
            });

        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_shutdown(&self, pkt: &VsockPacket) {
        debug!("OP_SHUTDOWN");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| (proxy.clone(), proxy.lock().unwrap().shutdown(pkt)));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_credit_request(&self, pkt: &VsockPacket) {
        let id = ((pkt.src_port() as u64) << 32) | pkt.dst_port() as u64;
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| (proxy.clone(), proxy.lock().unwrap().request_credit()));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_credit_update(&self, pkt: &VsockPacket) {
        debug!("OP_CREDIT_UPDATE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| (proxy.clone(), proxy.lock().unwrap().update_peer_credit(pkt)));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }

        // Drain any data already buffered on the host socket now that the
        // guest has credit again. Waiting for the poller is not enough on
        // Windows: `WSAEventSelect`'s `FD_READ` only re-signals after a
        // `recv` call, and a proxy that hit WaitForCredit returned without
        // recv'ing — so buffered bytes would never produce another readiness
        // event, the stream would stall, and the remote peer's idle timeout
        // would reset the connection (a guest download dying "unexpected
        // EOF"). On Unix the extra recv attempt just reports WouldBlock when
        // nothing is buffered.
        let drain = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
            (
                proxy.clone(),
                proxy.lock().unwrap().process_event(EventSet::IN),
            )
        });
        if let Some(update) = drain {
            self.process_proxy_update(id, update);
        }
    }

    fn process_stream_rw(&self, pkt: &VsockPacket) {
        debug!("OP_RW");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy_lock| {
            debug!(
                "allowing OP_RW: src={} dst={}",
                pkt.src_port(),
                pkt.dst_port()
            );
            (proxy_lock.clone(), proxy_lock.lock().unwrap().sendmsg(pkt))
        });
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        } else {
            debug!("invalid OP_RW for {}, sending reset", pkt.src_port());
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    warn!("OP_RW without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    warn!("OP_RW without queue");
                    return;
                }
            };

            // This response goes to the connection.
            let rx = MuxerRx::Reset {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
            };
            push_packet(self.cid, rx, &self.rxq, queue, mem, &self.snapshot_gate);
        }
    }

    fn process_stream_rst(&self, pkt: &VsockPacket) {
        debug!("OP_RST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        debug!(
            "[VSOCK_TIMING] process_stream_rst: GUEST SENT RST! id={:#x} src_port={} dst_port={}",
            id,
            pkt.src_port(),
            pkt.dst_port()
        );
        let update = if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!(
                "[VSOCK_TIMING] OP_RST: releasing proxy id={:#x} src={} dst={}",
                id,
                pkt.src_port(),
                pkt.dst_port()
            );
            Some((proxy_lock.clone(), proxy_lock.lock().unwrap().release()))
        } else {
            debug!("[VSOCK_TIMING] OP_RST: no proxy found for id={:#x}", id);
            None
        };
        // A guest-sent RST on a Listening TSI proxy asks for Immediate removal,
        // which takes the proxy_map write lock: apply it with no guard held.
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    pub(crate) fn send_stream_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static STREAM_PKT_COUNT: AtomicU64 = AtomicU64::new(0);
        let count = STREAM_PKT_COUNT.fetch_add(1, Ordering::Relaxed);

        // Log first 20 packets for debugging
        if count < 20 {
            let op_name = match pkt.op() {
                uapi::VSOCK_OP_REQUEST => "REQUEST",
                uapi::VSOCK_OP_RESPONSE => "RESPONSE",
                uapi::VSOCK_OP_SHUTDOWN => "SHUTDOWN",
                uapi::VSOCK_OP_CREDIT_UPDATE => "CREDIT_UPDATE",
                uapi::VSOCK_OP_CREDIT_REQUEST => "CREDIT_REQUEST",
                uapi::VSOCK_OP_RW => "RW",
                uapi::VSOCK_OP_RST => "RST",
                _ => "UNKNOWN",
            };
            debug!(
                "[VSOCK_TIMING] send_stream_pkt #{}: op={} src_port={} dst_port={}",
                count,
                op_name,
                pkt.src_port(),
                pkt.dst_port()
            );
        }

        debug!(
            "send_pkt: src_port={} dst_port={}, op={}",
            pkt.src_port(),
            pkt.dst_port(),
            pkt.op()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!("dropping guest packet for unknown CID: {:?}", pkt.hdr());
            return Ok(());
        }

        match pkt.op() {
            uapi::VSOCK_OP_REQUEST => self.process_op_request(pkt),
            uapi::VSOCK_OP_RESPONSE => self.process_op_response(pkt),
            uapi::VSOCK_OP_SHUTDOWN => self.process_op_shutdown(pkt),
            uapi::VSOCK_OP_CREDIT_UPDATE => self.process_op_credit_update(pkt),
            uapi::VSOCK_OP_CREDIT_REQUEST => self.process_op_credit_request(pkt),
            uapi::VSOCK_OP_RW => self.process_stream_rw(pkt),
            uapi::VSOCK_OP_RST => self.process_stream_rst(pkt),
            _ => warn!("stream: unhandled op={}", pkt.op()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    /// Helper: create a VsockAddr from an IPv4 address.
    fn sockaddr_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> VsockAddr {
        VsockAddr::Inet(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port).into())
    }

    /// Helper: create a VsockAddr from an IPv6 address.
    fn sockaddr_v6(addr: Ipv6Addr, port: u16) -> VsockAddr {
        VsockAddr::Inet(SocketAddrV6::new(addr, port, 0, 0).into())
    }

    /// Test wrapper: extract the IP from an address and delegate to the shared
    /// CIDR matcher (which lives in `dns_filter` and takes an `IpAddr`).
    fn ip_matches_cidrs(addr: &VsockAddr, cidrs: &[(IpAddr, u8)]) -> bool {
        let Some(ip) = addr.inet().map(|a| a.ip()) else {
            return true;
        };
        super::super::dns_filter::ip_matches_cidrs(ip, cidrs)
    }

    #[test]
    fn test_empty_cidrs_denies_all() {
        let cidrs: Vec<(IpAddr, u8)> = vec![];
        let addr = sockaddr_v4(10, 0, 0, 1, 80);
        assert!(!ip_matches_cidrs(&addr, &cidrs));
    }

    #[test]
    fn test_exact_ipv4_match() {
        let cidrs = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32)];
        assert!(ip_matches_cidrs(&sockaddr_v4(10, 0, 0, 1, 80), &cidrs));
        assert!(!ip_matches_cidrs(&sockaddr_v4(10, 0, 0, 2, 80), &cidrs));
    }

    #[test]
    fn test_ipv4_cidr_8() {
        let cidrs = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)];
        assert!(ip_matches_cidrs(&sockaddr_v4(10, 0, 0, 1, 80), &cidrs));
        assert!(ip_matches_cidrs(
            &sockaddr_v4(10, 255, 255, 255, 80),
            &cidrs
        ));
        assert!(!ip_matches_cidrs(&sockaddr_v4(11, 0, 0, 1, 80), &cidrs));
        assert!(!ip_matches_cidrs(&sockaddr_v4(192, 168, 1, 1, 80), &cidrs));
    }

    #[test]
    fn test_ipv4_cidr_16() {
        let cidrs = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16)];
        assert!(ip_matches_cidrs(&sockaddr_v4(192, 168, 0, 1, 80), &cidrs));
        assert!(ip_matches_cidrs(
            &sockaddr_v4(192, 168, 255, 255, 80),
            &cidrs
        ));
        assert!(!ip_matches_cidrs(&sockaddr_v4(192, 169, 0, 1, 80), &cidrs));
    }

    #[test]
    fn test_ipv4_cidr_0_matches_all() {
        let cidrs = vec![(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)];
        assert!(ip_matches_cidrs(&sockaddr_v4(1, 2, 3, 4, 80), &cidrs));
        assert!(ip_matches_cidrs(
            &sockaddr_v4(255, 255, 255, 255, 80),
            &cidrs
        ));
    }

    #[test]
    fn test_multiple_cidrs() {
        let cidrs = vec![
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 32),
        ];
        assert!(ip_matches_cidrs(&sockaddr_v4(10, 0, 0, 5, 80), &cidrs));
        assert!(ip_matches_cidrs(&sockaddr_v4(1, 1, 1, 1, 53), &cidrs));
        assert!(!ip_matches_cidrs(&sockaddr_v4(8, 8, 8, 8, 53), &cidrs));
    }

    #[test]
    fn test_ipv6_exact_match() {
        let cidrs = vec![(IpAddr::V6(Ipv6Addr::LOCALHOST), 128)];
        assert!(ip_matches_cidrs(
            &sockaddr_v6(Ipv6Addr::LOCALHOST, 80),
            &cidrs
        ));
        assert!(!ip_matches_cidrs(
            &sockaddr_v6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2), 80),
            &cidrs
        ));
    }

    #[test]
    fn test_ipv6_cidr_64() {
        let cidrs = vec![(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            32,
        )];
        assert!(ip_matches_cidrs(
            &sockaddr_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 80),
            &cidrs
        ));
        assert!(ip_matches_cidrs(
            &sockaddr_v6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 0), 80),
            &cidrs
        ));
        assert!(!ip_matches_cidrs(
            &sockaddr_v6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0), 80),
            &cidrs
        ));
    }

    #[test]
    fn test_ipv6_cidr_0_matches_all() {
        let cidrs = vec![(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)];
        assert!(ip_matches_cidrs(
            &sockaddr_v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 80),
            &cidrs
        ));
    }

    #[test]
    fn test_v4_addr_v6_cidr_no_match() {
        // IPv4 address should not match IPv6 CIDR
        let cidrs = vec![(IpAddr::V6(Ipv6Addr::LOCALHOST), 128)];
        assert!(!ip_matches_cidrs(&sockaddr_v4(127, 0, 0, 1, 80), &cidrs));
    }

    #[test]
    fn test_v6_addr_v4_cidr_no_match() {
        // IPv6 address should not match IPv4 CIDR
        let cidrs = vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)];
        assert!(!ip_matches_cidrs(
            &sockaddr_v6(Ipv6Addr::LOCALHOST, 80),
            &cidrs
        ));
    }

    #[test]
    fn test_non_canonical_cidr() {
        // 10.0.0.1/8 — host bits set in CIDR network, should still match 10.x.x.x
        let cidrs = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8)];
        assert!(ip_matches_cidrs(&sockaddr_v4(10, 99, 99, 99, 80), &cidrs));
        assert!(!ip_matches_cidrs(&sockaddr_v4(11, 0, 0, 0, 80), &cidrs));
    }

    /// A proxy that asks to be removed immediately from every path that returns
    /// an update, the way a Listening TSI stream proxy answers a guest RST.
    struct RemovedOnUpdate;

    impl Proxy for RemovedOnUpdate {
        fn poll_handle(&self) -> ProxyRawHandle {
            -1
        }
        fn id(&self) -> u64 {
            0
        }
        fn status(&self) -> ProxyStatus {
            ProxyStatus::Listening
        }
        fn connect(&mut self, _: &VsockPacket, _: TsiConnectReq) -> ProxyUpdate {
            removal()
        }
        fn confirm_connect(&mut self, _: &VsockPacket) -> Option<ProxyUpdate> {
            Some(removal())
        }
        fn getpeername(&mut self, _: &VsockPacket) {}
        fn sendmsg(&mut self, _: &VsockPacket) -> ProxyUpdate {
            removal()
        }
        fn sendto_addr(&mut self, _: super::super::packet::TsiSendtoAddr) -> ProxyUpdate {
            removal()
        }
        fn listen(
            &mut self,
            _: &VsockPacket,
            _: super::super::packet::TsiListenReq,
            _: &Option<HashMap<u16, u16>>,
        ) -> ProxyUpdate {
            removal()
        }
        fn accept(&mut self, _: u32, _: super::super::packet::TsiAcceptReq) -> ProxyUpdate {
            removal()
        }
        fn update_peer_credit(&mut self, _: &VsockPacket) -> ProxyUpdate {
            removal()
        }
        fn process_op_response(&mut self, _: &VsockPacket) -> ProxyUpdate {
            removal()
        }
        fn release(&mut self) -> ProxyUpdate {
            removal()
        }
        fn process_event(&mut self, _: EventSet) -> ProxyUpdate {
            removal()
        }
    }

    fn removal() -> ProxyUpdate {
        ProxyUpdate {
            remove_proxy: ProxyRemoval::Immediate,
            ..Default::default()
        }
    }

    /// Every muxer path that applies a proxy's update must do so with no
    /// proxy_map guard held, or an Immediate removal re-takes the lock on the
    /// muxer thread and wedges the whole vsock device.
    #[cfg(unix)]
    #[test]
    fn an_immediate_removal_from_any_path_does_not_deadlock() {
        use super::super::packet::VSOCK_PKT_HDR_SIZE;
        use crate::virtio::queue::tests::VirtQueue as TestQueue;
        use vm_memory::{Bytes, GuestAddress};

        const GUEST: u32 = 7000;
        const TSI: u64 = defs::TSI_PROXY_PORT as u64;
        let sockaddr: Vec<u8> = [
            &2u16.to_le_bytes()[..],
            &80u16.to_be_bytes(),
            &[1, 1, 1, 1],
            &[0; 8],
        ]
        .concat();

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
            let mut muxer = VsockMuxer::new(
                3,
                None,
                None,
                TsiFlags::default(),
                None,
                None,
                None,
                None,
                None,
            );
            muxer.mem = Some(mem.clone());
            muxer.queue = Some(Arc::new(Mutex::new(rx.create_queue())));

            let packet = |op: u16, src: u32, dst: u32, data: &[u8]| {
                let tx = TestQueue::new(GuestAddress(0x1000), &mem, 8);
                let hdr = GuestAddress(0x10000);
                mem.write_slice(&[0; VSOCK_PKT_HDR_SIZE], hdr).unwrap();
                mem.write_obj(data.len() as u32, GuestAddress(0x10000 + 24))
                    .unwrap();
                mem.write_slice(data, GuestAddress(0x10000 + VSOCK_PKT_HDR_SIZE as u64))
                    .unwrap();
                tx.dtable[0].set(0x10000, (VSOCK_PKT_HDR_SIZE + data.len()) as u32, 0, 0);
                tx.avail.ring[0].set(0);
                tx.avail.idx.set(1);
                let mut pkt =
                    VsockPacket::from_tx_virtq_head(&tx.create_queue().pop(&mem).unwrap()).unwrap();
                pkt.set_op(op).set_src_port(src).set_dst_port(dst);
                pkt
            };
            let insert = |muxer: &VsockMuxer, id: u64| {
                muxer
                    .proxy_map
                    .write()
                    .unwrap()
                    .insert(id, Arc::new(Mutex::new(Box::new(RemovedOnUpdate))));
            };
            let tsi_req = |extra: &[u8]| [&GUEST.to_le_bytes()[..], extra].concat();
            let stream_id = ((GUEST as u64) << 32) | 620;
            let dgram_id = ((GUEST as u64) << 32) | TSI;

            insert(&muxer, stream_id);
            muxer.process_stream_rst(&packet(uapi::VSOCK_OP_RST, GUEST, 620, &[]));
            insert(&muxer, stream_id);
            muxer.process_stream_rw(&packet(uapi::VSOCK_OP_RW, GUEST, 620, &[]));
            insert(&muxer, stream_id);
            muxer.process_op_request(&packet(uapi::VSOCK_OP_REQUEST, GUEST, 620, &[]));
            insert(&muxer, dgram_id);
            muxer.process_dgram_rw(&packet(uapi::VSOCK_OP_RW, GUEST, 9999, &[]));
            insert(&muxer, dgram_id);
            muxer.process_accept_request(&packet(
                uapi::VSOCK_OP_RW,
                GUEST,
                defs::TSI_ACCEPT,
                &tsi_req(&0u32.to_le_bytes()),
            ));
            insert(&muxer, dgram_id);
            let listen = [
                &0u32.to_le_bytes()[..],
                &1u32.to_le_bytes(),
                &16u32.to_le_bytes(),
                &sockaddr,
            ]
            .concat();
            muxer.process_listen_request(&packet(
                uapi::VSOCK_OP_RW,
                GUEST,
                defs::TSI_LISTEN,
                &tsi_req(&listen),
            ));
            insert(&muxer, dgram_id);
            let connect = [&16u32.to_le_bytes()[..], &sockaddr].concat();
            muxer.process_connect(&packet(
                uapi::VSOCK_OP_RW,
                GUEST,
                defs::TSI_CONNECT,
                &tsi_req(&connect),
            ));

            done_tx.send(muxer.proxy_map.read().unwrap().len()).unwrap();
        });

        let left = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the muxer deadlocked applying an Immediate removal");
        assert_eq!(left, 0, "every Immediate removal should have taken effect");
    }

    /// Runs itself in a child process, since it uses up every file descriptor.
    #[cfg(unix)]
    #[test]
    fn a_host_ipc_connect_without_a_free_fd_is_reset() {
        use super::super::packet::VSOCK_PKT_HDR_SIZE;
        use crate::virtio::queue::tests::VirtQueue as TestQueue;
        use std::os::fd::AsRawFd;
        use vm_memory::GuestAddress;

        const NAME: &str =
            "virtio::vsock::muxer::tests::a_host_ipc_connect_without_a_free_fd_is_reset";
        if std::env::var_os("LIBKRUN_TEST_CHILD").is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env("LIBKRUN_TEST_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (tx, rx) = (
            TestQueue::new(GuestAddress(0x1000), &mem, 8),
            TestQueue::new(GuestAddress(0x4000), &mem, 8),
        );
        let ipc = HashMap::from([(1024, (PathBuf::from("/nonexistent"), false))]);
        let mut muxer = VsockMuxer::new(
            3,
            None,
            Some(ipc),
            TsiFlags::default(),
            None,
            None,
            None,
            None,
            None,
        );
        muxer.mem = Some(mem.clone());
        muxer.queue = Some(Arc::new(Mutex::new(rx.create_queue())));
        tx.dtable[0].set(0x10000, VSOCK_PKT_HDR_SIZE as u32, 0, 0);
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        let mut pkt =
            VsockPacket::from_tx_virtq_head(&tx.create_queue().pop(&mem).unwrap()).unwrap();
        pkt.set_op(uapi::VSOCK_OP_REQUEST)
            .set_src_port(5)
            .set_dst_port(1024);

        let null = std::fs::File::open("/dev/null").unwrap();
        let limit = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 256,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        while unsafe { libc::dup(null.as_raw_fd()) } >= 0 {}
        muxer.process_op_request(&pkt);

        assert!(matches!(
            muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::Reset {
                local_port: 1024,
                peer_port: 5
            })
        ));
    }

    /// A guest socket whose host socket cannot be created (the VMM is out of
    /// file descriptors) fails its connect with EMFILE, not a bare refusal.
    /// Runs itself in a child process, since it uses up every file descriptor.
    #[cfg(unix)]
    #[test]
    fn a_connect_without_a_free_fd_reports_emfile() {
        use super::super::packet::VSOCK_PKT_HDR_SIZE;
        use crate::virtio::queue::tests::VirtQueue as TestQueue;
        use std::os::fd::AsRawFd;
        use vm_memory::{Bytes, GuestAddress};

        const NAME: &str =
            "virtio::vsock::muxer::tests::a_connect_without_a_free_fd_reports_emfile";
        if std::env::var_os("LIBKRUN_TEST_CHILD").is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env("LIBKRUN_TEST_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }

        const GUEST: u32 = 7001;
        const LINUX_EMFILE: i32 = 24;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
        let mut muxer = VsockMuxer::new(
            3,
            None,
            None,
            TsiFlags::HIJACK_INET,
            None,
            None,
            None,
            None,
            None,
        );
        muxer.mem = Some(mem.clone());
        muxer.queue = Some(Arc::new(Mutex::new(rx.create_queue())));
        let packet = |dst: u32, data: &[u8]| {
            let tx = TestQueue::new(GuestAddress(0x1000), &mem, 8);
            let hdr = GuestAddress(0x10000);
            mem.write_slice(&[0; VSOCK_PKT_HDR_SIZE], hdr).unwrap();
            mem.write_obj(data.len() as u32, GuestAddress(0x10000 + 24))
                .unwrap();
            mem.write_slice(data, GuestAddress(0x10000 + VSOCK_PKT_HDR_SIZE as u64))
                .unwrap();
            tx.dtable[0].set(0x10000, (VSOCK_PKT_HDR_SIZE + data.len()) as u32, 0, 0);
            tx.avail.ring[0].set(0);
            tx.avail.idx.set(1);
            let mut pkt =
                VsockPacket::from_tx_virtq_head(&tx.create_queue().pop(&mem).unwrap()).unwrap();
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_port(GUEST + 1)
                .set_dst_port(dst);
            pkt
        };
        let create = [
            &GUEST.to_le_bytes()[..],
            &(defs::LINUX_AF_INET).to_le_bytes(),
            &(defs::SOCK_STREAM).to_le_bytes(),
        ]
        .concat();
        let sockaddr: Vec<u8> = [
            &2u16.to_le_bytes()[..],
            &80u16.to_be_bytes(),
            &[127, 0, 0, 1],
            &[0; 8],
        ]
        .concat();
        let connect = [&GUEST.to_le_bytes()[..], &16u32.to_le_bytes(), &sockaddr].concat();

        let null = std::fs::File::open("/dev/null").unwrap();
        let limit = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 256,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        while unsafe { libc::dup(null.as_raw_fd()) } >= 0 {}
        muxer.process_proxy_create(&packet(defs::TSI_PROXY_CREATE, &create));
        muxer.process_connect(&packet(defs::TSI_CONNECT, &connect));

        match muxer.rxq.lock().unwrap().pop() {
            Some(MuxerRx::ConnResponse { result, .. }) => assert_eq!(result, -LINUX_EMFILE),
            _ => panic!("expected a connect response"),
        }
    }
}
