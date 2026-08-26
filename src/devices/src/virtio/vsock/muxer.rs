use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use super::super::Queue as VirtQueue;
use super::TsiFlags;
use super::VsockError;
use super::defs;
use super::defs::uapi;
use super::dns_filter::{
    DnsRequest, DnsWorker, EgressPolicy, FloorMode, floor_mode, is_addr_floored,
    is_addr_host_loopback, sockaddr_port,
};
use super::muxer_rxq::{MuxerRxQ, rx_to_pkt};
use super::muxer_thread::MuxerThread;
use super::packet::TsiConnectReq;
use super::packet::{TsiGetnameRsp, VsockPacket};
use super::proxy::ProxyRawHandle;
use super::proxy::{ListenerDesc, Proxy, ProxyRemoval, ProxyStatus, ProxyUpdate};
use super::reaper::ReaperThread;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use super::timesync::TimesyncThread;
use super::tsi_dgram::TsiDgramProxy;
use super::tsi_stream::TsiStreamProxy;
use super::unix::UnixProxy;
use super::vsock_addr::VsockAddr;
use crossbeam_channel::{Sender, unbounded};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::GuestMemoryMmap;

use crate::virtio::InterruptTransport;

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
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
) {
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
    reaper_sender: Option<Sender<u64>>,
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
}

impl VsockMuxer {
    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
        egress_cidrs: Option<Vec<(IpAddr, u8)>>,
        egress_hosts: Option<Vec<String>>,
        egress_resolvers: Option<Vec<IpAddr>>,
    ) -> Self {
        if let Some(ref cidrs) = egress_cidrs {
            info!("egress policy configured with {} CIDR rule(s)", cidrs.len());
        }
        if let Some(ref hosts) = egress_hosts {
            info!("DNS filter configured with {} host rule(s)", hosts.len());
        }
        let egress_policy = EgressPolicy::new(egress_cidrs, egress_hosts, egress_resolvers)
            .map(|policy| Arc::new(RwLock::new(policy)));
        VsockMuxer {
            cid,
            host_port_map,
            queue: None,
            mem: None,
            rxq: Arc::new(Mutex::new(MuxerRxQ::new())),
            epoll: Epoll::new().unwrap(),
            interrupt: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
            reaper_sender: None,
            unix_ipc_port_map,
            tsi_flags,
            egress_policy,
            floor: floor_mode(),
            dns_sender: None,
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
        info!("[VSOCK_TIMING] muxer.activate() called, cid={}", self.cid);

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
            info!("[VSOCK_TIMING] starting TimesyncThread");
            let timesync =
                TimesyncThread::new(self.cid, mem.clone(), queue.clone(), interrupt.clone());
            timesync.run();
            info!("[VSOCK_TIMING] TimesyncThread started");
        }

        // Spawn the DNS worker (off-muxer blocking resolution) when DNS
        // filtering is active. The dgram proxy treats `dns_sender.is_some()` as
        // the "DNS filtering active" signal.
        if let Some(policy) = &self.egress_policy {
            let dns_active = policy.read().map(|p| p.dns_active()).unwrap_or(false);
            if dns_active {
                let (dns_sender, dns_receiver) = unbounded::<DnsRequest>();
                let worker = DnsWorker::new(
                    dns_receiver,
                    policy.clone(),
                    mem.clone(),
                    queue.clone(),
                    self.rxq.clone(),
                    interrupt.clone(),
                );
                worker.run();
                self.dns_sender = Some(dns_sender);
                info!("[VSOCK_TIMING] DnsWorker spawned");
            }
        }

        let (sender, receiver) = unbounded();

        info!(
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
        );
        thread.run();
        info!("[VSOCK_TIMING] MuxerThread spawned");

        self.reaper_sender = Some(sender);
        let reaper = ReaperThread::new(receiver, self.proxy_map.clone());
        reaper.run();
        info!("[VSOCK_TIMING] ReaperThread spawned");

        info!(
            "[VSOCK_TIMING] muxer.activate() completed in {:?}",
            activate_start.elapsed()
        );
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
    /// pending RX queue. **Listener/acceptor proxies are preserved** so the
    /// muxer keeps accepting new connections on the configured unix-IPC ports
    /// (e.g. the agent channel). The guest, rewound to the checkpoint, has no
    /// live connections either, so both sides start clean and the host
    /// reconnects on its next request.
    ///
    /// Safe to call concurrently with the `MuxerThread`: the proxy_map/rxq are
    /// the same `RwLock`/`Mutex`-guarded structures it uses, and it tolerates a
    /// proxy disappearing between epoll wakeup and lookup.
    pub(crate) fn reset_connections(&self) {
        let removed = {
            let mut map = self.proxy_map.write().unwrap();
            let before = map.len();
            map.retain(|_id, proxy| proxy.get_mut().unwrap().is_listener());
            before - map.len()
        };
        self.rxq.lock().unwrap().clear();
        info!("vsock muxer reset on restore: dropped {removed} connection proxy(ies)");
    }

    /// Capture every live TSI inbound-port-forward listener for VM checkpoint/fork
    /// (see [`ListenerDesc`]). The muxer's `proxy_map` is otherwise not part of the
    /// device snapshot, so without this a fork clone loses all inbound forwards.
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
    pub(crate) fn restore_listeners(&self, descs: Vec<ListenerDesc>) {
        let mem = match self.mem.as_ref() {
            Some(m) => m.clone(),
            None => {
                warn!(
                    "restore_listeners before activation; skipping {} listener(s)",
                    descs.len()
                );
                return;
            }
        };
        let queue = match self.queue.as_ref() {
            Some(q) => q.clone(),
            None => return,
        };
        for d in descs {
            let id = ((d.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            match TsiStreamProxy::new(
                id,
                self.cid,
                d.family,
                defs::TSI_PROXY_PORT,
                d.peer_port,
                d.control_port,
                mem.clone(),
                queue.clone(),
                self.rxq.clone(),
            ) {
                Ok(mut proxy) => {
                    let rc = proxy.relisten(d.guest_port, d.backlog, &self.host_port_map);
                    if rc == 0 {
                        let fd = proxy.poll_handle();
                        self.proxy_map
                            .write()
                            .unwrap()
                            .insert(id, Mutex::new(Box::new(proxy)));
                        self.update_polling(id, fd, EventSet::IN);
                        info!(
                            "restored TSI inbound listener: guest_port={} (id={:#x})",
                            d.guest_port, id
                        );
                    } else {
                        warn!(
                            "failed to restore TSI listener guest_port={}: errno {}",
                            d.guest_port, -rc
                        );
                    }
                }
                Err(e) => warn!("failed to recreate TSI listener proxy: {e}"),
            }
        }
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

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                info!("immediately removing proxy: {id}");
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                info!("deferring proxy removal: {id}");
                if let Some(reaper_sender) = &self.reaper_sender
                    && reaper_sender.send(id).is_err()
                {
                    self.proxy_map.write().unwrap().remove(&id);
                }
            }
        }

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
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating tcp proxy: {e}"),
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
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating udp proxy: {e}"),
                    }
                }
                _ => debug!("unknown type on connection request"),
            };
        }
    }

    fn process_connect(&self, pkt: &VsockPacket) {
        debug!("proxy connect request");
        if let Some(req) = pkt.read_connect_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("proxy connect request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    let update = {
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
                        proxy.connect(pkt, req)
                    };
                    self.process_proxy_update(id, update);
                }
                None => self.push_packet(MuxerRx::ConnResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::ECONNREFUSED,
                }),
            }
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
                return;
            }

            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("new DGRAM sendto addr: id={id}");
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().sendto_addr(req));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_sendto_data(&self, pkt: &VsockPacket) {
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
        debug!("DGRAM sendto data: id={} src={}", id, pkt.src_port());
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().sendto_data(pkt);
        }
    }

    fn process_listen_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM listen request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_listen_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM listen request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => self.process_proxy_update(
                    id,
                    proxy.lock().unwrap().listen(pkt, req, &self.host_port_map),
                ),
                None => self.push_packet(MuxerRx::ListenResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EPERM,
                }),
            };
        }
    }

    fn process_accept_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM accept request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_accept_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM accept request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => self.process_proxy_update(id, proxy.lock().unwrap().accept(req)),
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
                Some(proxy.lock().unwrap().release())
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

        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!("DGRAM allowing OP_RW for {}", pkt.src_port());
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.sendmsg(pkt);
            self.process_proxy_update(id, update);
        } else {
            debug!("DGRAM ignoring OP_RW for {}", pkt.src_port());
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
        info!(
            "[VSOCK_TIMING] process_op_request: id={:#x} src_port={} dst_port={}",
            id,
            pkt.src_port(),
            pkt.dst_port()
        );
        let mut proxy_map = self.proxy_map.write().unwrap();

        if let Some(proxy) = proxy_map.get(&id) {
            if let Some(update) = proxy.lock().unwrap().confirm_connect(pkt) {
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
                    push_packet(self.cid, rx, &self.rxq, queue, mem);
                    return;
                }
                let rxq = self.rxq.clone();

                let mut unix = UnixProxy::new(
                    id,
                    self.cid,
                    pkt.dst_port(),
                    pkt.src_port(),
                    mem.clone(),
                    queue.clone(),
                    rxq,
                    path.to_path_buf(),
                )
                .unwrap();
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
                    push_packet(self.cid, rx, &self.rxq, queue, mem);
                    return;
                }
                unix.confirm_connect(pkt);
                proxy_map.insert(id, Mutex::new(Box::new(unix)));
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_op_response(&self, pkt: &VsockPacket) {
        debug!("OP_RESPONSE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        info!(
            "[VSOCK_TIMING] process_op_response: id={:#x} src_port={} dst_port={}",
            id,
            pkt.src_port(),
            pkt.dst_port()
        );
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().process_op_response(pkt));

        if update.is_none() {
            info!(
                "[VSOCK_TIMING] process_op_response: NO PROXY FOUND for id={:#x}",
                id
            );
        }

        update
            .as_ref()
            .and_then(|u| u.push_accept)
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
            .map(|proxy| proxy.lock().unwrap().shutdown(pkt));
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
            .map(|proxy| proxy.lock().unwrap().update_peer_credit(pkt));
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
        let drain = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().process_event(EventSet::IN));
        if let Some(update) = drain {
            self.process_proxy_update(id, update);
        }
    }

    fn process_stream_rw(&self, pkt: &VsockPacket) {
        debug!("OP_RW");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!(
                "allowing OP_RW: src={} dst={}",
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.sendmsg(pkt);
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
            push_packet(self.cid, rx, &self.rxq, queue, mem);
        }
    }

    fn process_stream_rst(&self, pkt: &VsockPacket) {
        debug!("OP_RST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        info!(
            "[VSOCK_TIMING] process_stream_rst: GUEST SENT RST! id={:#x} src_port={} dst_port={}",
            id,
            pkt.src_port(),
            pkt.dst_port()
        );
        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            info!(
                "[VSOCK_TIMING] OP_RST: releasing proxy id={:#x} src={} dst={}",
                id,
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.release();
            self.process_proxy_update(id, update);
        } else {
            info!("[VSOCK_TIMING] OP_RST: no proxy found for id={:#x}", id);
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
                uapi::VSOCK_OP_RW => "RW",
                uapi::VSOCK_OP_RST => "RST",
                _ => "UNKNOWN",
            };
            info!(
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
}
