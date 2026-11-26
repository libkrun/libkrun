use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::OsStr;
use std::fs;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, RwLock};
#[cfg(windows)]
use utils::windows::RawFd;

use super::super::Queue as VirtQueue;
use super::TsiFlags;
use super::VsockError;
use super::defs;
use super::defs::uapi;
use super::muxer_rxq::{MuxerRxQ, rx_to_pkt};
use super::muxer_thread::MuxerThread;
use super::packet::{TsiGetnameRsp, VsockPacket, address_family};
use super::proxy::{Proxy, ProxyRemoval, ProxyStatus, ProxyUpdate};
use super::reaper::ReaperThread;
#[cfg(target_os = "macos")]
use super::timesync::TimesyncThread;
use super::tsi_dgram::TsiDgramProxy;
use super::tsi_stream::TsiStreamProxy;
use super::tsi_wire;
use super::unix_proxy::UnixProxy;
#[cfg(windows)]
use super::windows::sockaddr_storage::SockaddrStorage;
use crossbeam_channel::{Sender, unbounded};
#[cfg(unix)]
use nix::sys::socket::SockaddrStorage;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use crate::virtio::InterruptTransport;
use std::net::{Ipv4Addr, SocketAddrV4};

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;

/// A muxer RX queue item.
#[derive(Debug)]
#[cfg_attr(feature = "tsi-fault-injection", derive(Clone))]
pub enum MuxerRx {
    #[cfg(feature = "tsi-fault-injection")]
    FaultPacket {
        response: Box<MuxerRx>,
        fault: super::tsi_control_faults::Fault,
        peer_port: Option<u32>,
    },
    #[cfg(feature = "tsi-fault-injection")]
    FaultAck {
        peer_port: u32,
        words: [u32; 5],
    },
    Reset {
        local_port: u32,
        peer_port: u32,
    },
    SockoptResponse {
        request_id: u64,
        operation: u32,
        peer_port: u32,
        result: i32,
        value: i32,
    },
    FeatureResponse {
        request_id: u64,
        operation: u32,
        peer_port: u32,
        result: i32,
        services: u64,
        features: u64,
    },
    GetnameResponse {
        request_id: u64,
        operation: u32,
        peer_port: u32,
        data: TsiGetnameRsp,
    },
    ConnResponse {
        request_id: u64,
        operation: u32,
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
        request_id: u64,
        operation: u32,
        peer_port: u32,
        result: i32,
        flags: u32,
    },
    AcceptResponse {
        request_id: u64,
        operation: u32,
        peer_port: u32,
        result: i32,
    },
}

/// Deliver a packet to the guest, borrowing a free RX buffer when available
/// and queueing it in the rxq otherwise. Returns whether the packet was
/// delivered or queued; a full rxq means the packet is lost.
pub fn push_packet(
    cid: u64,
    rx: MuxerRx,
    rxq_mutex: &Arc<Mutex<MuxerRxQ>>,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &GuestMemoryMmap,
) -> bool {
    #[cfg(feature = "tsi-fault-injection")]
    let packets = rxq_mutex.lock().unwrap().faults.filter(rx);
    #[cfg(not(feature = "tsi-fault-injection"))]
    let packets = [rx];
    let mut delivered = !packets.is_empty();
    for rx in packets {
        let mut queue = queue_mutex.lock().unwrap();
        if let Some(head) = queue.pop(mem) {
            match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    rx_to_pkt(cid, rx, &mut pkt);
                    if let Err(e) = queue.add_used(mem, head.index, pkt.finish_rx().unwrap_or(0)) {
                        error!("failed to add used elements to the queue: {e:?}");
                    }
                }
                Err(_) => {
                    // Return the unusable buffer empty and keep the reply for
                    // the next usable buffer.
                    if let Err(e) = queue.add_used(mem, head.index, 0) {
                        error!("failed to add used elements to the queue: {e:?}");
                    }
                    drop(queue);
                    delivered &= queue_or_warn(rxq_mutex, rx);
                }
            }
        } else {
            drop(queue);
            delivered &= queue_or_warn(rxq_mutex, rx);
        }
    }
    delivered
}

fn queue_or_warn(rxq_mutex: &Arc<Mutex<MuxerRxQ>>, rx: MuxerRx) -> bool {
    if rxq_mutex.lock().unwrap().push(rx) {
        true
    } else {
        warn!("guest RX queue full, dropping a pending reply");
        false
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
    rx_available_evt: EventFd,
    /// Optional cap on live proxies, guarding the VMM's file descriptors.
    proxy_limit: Option<usize>,
}

impl VsockMuxer {
    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        mut unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
        proxy_limit: Option<usize>,
        send_queue_budget: Option<usize>,
    ) -> super::Result<Self> {
        if let Some(map) = &mut unix_ipc_port_map {
            let needs_cwd = map
                .values()
                .any(|(path, listen)| *listen && path.is_relative());
            if needs_cwd {
                let cwd = std::env::current_dir().map_err(VsockError::CurrentDir)?;
                for (path, listen) in map.values_mut() {
                    if *listen && path.is_relative() {
                        *path = cwd.join(&*path);
                    }
                }
            }
        }
        let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));
        if let Some(budget) = send_queue_budget {
            rxq.lock().unwrap().send_budget = Arc::new(AtomicUsize::new(budget));
        }
        Ok(VsockMuxer {
            cid,
            host_port_map,
            queue: None,
            mem: None,
            rxq,
            epoll: Epoll::new().unwrap(),
            interrupt: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
            reaper_sender: None,
            unix_ipc_port_map,
            tsi_flags,
            rx_available_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(VsockError::EventFd)?,
            proxy_limit,
        })
    }

    pub(crate) fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
    ) {
        self.queue = Some(queue.clone());
        self.mem = Some(mem.clone());
        self.interrupt = Some(interrupt.clone());

        #[cfg(target_os = "macos")]
        {
            let timesync =
                TimesyncThread::new(self.cid, mem.clone(), queue.clone(), interrupt.clone());
            timesync.run();
        }

        let (sender, receiver) = unbounded();

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
            self.rx_available_evt.try_clone().unwrap(),
        );
        thread.run();

        self.reaper_sender = Some(sender);
        let reaper = ReaperThread::new(receiver, self.proxy_map.clone());
        reaper.run();
    }

    pub(crate) fn has_pending_rx(&self) -> bool {
        !self.rxq.lock().unwrap().is_empty()
    }

    /// Wake the muxer thread so it resumes proxies that stopped polling
    /// after the guest ran out of RX buffers.
    pub(crate) fn notify_rx_available(&self) {
        if let Err(e) = self.rx_available_evt.write(1) {
            error!("failed to notify rx buffers available: {e:?}");
        }
    }

    pub(crate) fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        debug!("recv_stream_pkt");
        let rx = self.rxq.lock().unwrap().pop().ok_or(VsockError::NoData)?;
        rx_to_pkt(self.cid, rx, pkt);
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

        push_packet(self.cid, rx, &self.rxq, queue_mutex, mem);
    }

    pub fn update_polling(&self, id: u64, fd: RawFd, evset: EventSet) {
        debug!("update_polling id={id} fd={fd:?} evset={evset:?}");
        #[cfg(unix)]
        {
            let _ = self
                .epoll
                .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
            if !evset.is_empty() {
                let _ = self
                    .epoll
                    .ctl(ControlOperation::Add, fd, &EpollEvent::new(evset, id));
            }
        }
        #[cfg(windows)]
        {
            let sock = fd as windows_sys::Win32::Networking::WinSock::SOCKET;
            let _ = self
                .epoll
                .ctl_socket(ControlOperation::Delete, sock, &EpollEvent::default());
            if !evset.is_empty() {
                let _ =
                    self.epoll
                        .ctl_socket(ControlOperation::Add, sock, &EpollEvent::new(evset, id));
            }
        }
    }

    /// Apply a proxy's polling mask while its lock is still held, so the
    /// event thread cannot install a stale interest for the same fd in
    /// between.
    fn apply_polling_under_lock(&self, update: &mut ProxyUpdate) {
        if let Some((id, fd, events)) = update.polling.take() {
            self.update_polling(id, fd, events);
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

    fn control_error(&self, pkt: &VsockPacket, result: i32) {
        let operation = pkt.control_operation();
        if pkt.control_request_id() == 0
            || pkt.control_is_oneway()
            || operation == defs::TSI_OP_RELEASE
        {
            return;
        }
        if operation == defs::TSI_OP_GETOPT {
            self.push_packet(MuxerRx::SockoptResponse {
                request_id: pkt.control_request_id(),
                operation,
                peer_port: pkt.src_port(),
                result,
                value: 0,
            });
        } else if operation == defs::TSI_OP_LISTEN {
            self.push_packet(MuxerRx::ListenResponse {
                request_id: pkt.control_request_id(),
                operation,
                peer_port: pkt.src_port(),
                result,
                flags: 0,
            });
        } else if operation == defs::TSI_OP_GETNAME {
            self.push_packet(MuxerRx::GetnameResponse {
                request_id: pkt.control_request_id(),
                operation,
                peer_port: pkt.src_port(),
                data: TsiGetnameRsp {
                    result,
                    ..Default::default()
                },
            });
        } else if matches!(operation, defs::TSI_OP_CAPABILITIES | defs::TSI_OP_ACTIVATE) {
            self.push_packet(MuxerRx::FeatureResponse {
                request_id: pkt.control_request_id(),
                operation,
                peer_port: pkt.src_port(),
                result,
                services: 0,
                features: 0,
            });
        } else {
            self.push_packet(MuxerRx::ConnResponse {
                request_id: pkt.control_request_id(),
                operation,
                peer_port: pkt.src_port(),
                result,
            });
        }
    }

    fn process_proxy_create(&self, pkt: &VsockPacket) {
        let result = self.create_proxy(pkt).err().unwrap_or(0);
        self.push_packet(MuxerRx::ConnResponse {
            request_id: pkt.control_request_id(),
            operation: defs::TSI_OP_CREATE,
            peer_port: pkt.src_port(),
            result,
        });
    }

    fn create_proxy(&self, pkt: &VsockPacket) -> Result<(), i32> {
        let req = pkt.read_proxy_create().ok_or(-tsi_wire::EPROTO)?;
        tsi_wire::check_protocol(req.family, req._type, req.protocol)?;
        let flag = match req.family {
            defs::LINUX_AF_UNIX => TsiFlags::HIJACK_UNIX,
            defs::LINUX_AF_INET | defs::LINUX_AF_INET6 => TsiFlags::HIJACK_INET,
            _ => return Err(-tsi_wire::EAFNOSUPPORT),
        };
        if !self.tsi_flags.contains(flag) {
            return Err(-tsi_wire::EPERM);
        }
        // Every proxy holds a host file descriptor; refuse before creating
        // one so a guest cannot exhaust the VMM's descriptors.
        if let Some(limit) = self.proxy_limit
            && self.proxy_map.read().unwrap().len() >= limit
        {
            return Err(-libc::EMFILE);
        }
        let mem = self.mem.as_ref().ok_or(-tsi_wire::EIO)?;
        let queue = self.queue.as_ref().ok_or(-tsi_wire::EIO)?;
        let id = ((req.peer_port as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        if self.is_host_listener_id(id) {
            return Err(-tsi_wire::EADDRINUSE);
        }
        let proxy: Box<dyn Proxy> = match req._type {
            defs::SOCK_STREAM => {
                let proxy = TsiStreamProxy::new(
                    id,
                    self.cid,
                    req.family,
                    defs::TSI_PROXY_PORT,
                    req.peer_port,
                    pkt.src_port(),
                    mem.clone(),
                    queue.clone(),
                    self.rxq.clone(),
                )
                .map_err(|e| -e.linux_errno())?;
                #[cfg(target_os = "linux")]
                let proxy = {
                    let mut proxy = proxy;
                    proxy.protected_unix_paths = self
                        .unix_ipc_port_map
                        .as_ref()
                        .into_iter()
                        .flat_map(|map| map.values())
                        .filter(|(_, listen)| *listen)
                        .map(|(path, _)| path.clone())
                        .collect();
                    proxy
                };
                Box::new(proxy)
            }
            defs::SOCK_DGRAM => Box::new(
                TsiDgramProxy::new(
                    id,
                    self.cid,
                    req,
                    mem.clone(),
                    queue.clone(),
                    self.rxq.clone(),
                )
                .map_err(|e| -e.linux_errno())?,
            ),
            _ => return Err(-tsi_wire::ESOCKTNOSUPPORT),
        };
        let mut proxies = self.proxy_map.write().unwrap();
        if proxies.contains_key(&id) {
            return Err(-tsi_wire::EADDRINUSE);
        }
        proxies.insert(id, Mutex::new(proxy));
        Ok(())
    }

    fn is_host_listener_id(&self, id: u64) -> bool {
        id as u32 == defs::TSI_PROXY_PORT
            && self
                .unix_ipc_port_map
                .as_ref()
                .and_then(|map| map.get(&((id >> 32) as u32)))
                .is_some_and(|(_, listen)| *listen)
    }

    /// Unix sockets the VMM listens on for the host, such as the init control
    /// endpoint, must stay out of reach of the guest: with AF_UNIX hijacking a
    /// guest connect to that path would look like a host connection.
    fn is_protected_unix_path(&self, addr: &SockaddrStorage) -> bool {
        let Some(map) = &self.unix_ipc_port_map else {
            return false;
        };
        let Some(path) = tsi_unix_path(addr) else {
            return false;
        };
        map.values()
            .filter(|(_, listen)| *listen)
            .any(|(protected, _)| same_file(protected, &path))
    }

    fn process_connect(&self, pkt: &VsockPacket) {
        debug!("proxy connect request");
        if let Some(req) = pkt.read_connect_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("proxy connect request: id={id}");
            if self.is_host_listener_id(id) || self.is_protected_unix_path(&req.addr) {
                warn!("rejecting guest connection to a host-side listening unix socket");
                self.control_error(pkt, -libc::EACCES);
                return;
            }
            let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
                let mut proxy = proxy.lock().unwrap();
                let (_, family) = proxy.tsi_socket().ok_or(-tsi_wire::EINVAL)?;
                if address_family(&req.addr) != Some(family) {
                    return Err(-tsi_wire::EAFNOSUPPORT);
                }
                let mut update = proxy.connect(
                    pkt,
                    req,
                    #[cfg(windows)]
                    &self.epoll,
                );
                self.apply_polling_under_lock(&mut update);
                Ok(update)
            });
            match update.unwrap_or(Err(-tsi_wire::ECONNREFUSED)) {
                Ok(update) => self.process_proxy_update(id, update),
                Err(result) => self.control_error(pkt, result),
            }
        } else {
            self.control_error(pkt, -tsi_wire::EPROTO);
        }
    }

    fn process_disconnect(&self, pkt: &VsockPacket) {
        let Ok(body) = pkt.control_payload() else {
            return;
        };
        // decode_control's body-length table guarantees this; keep both in
        // sync when the wire format changes.
        debug_assert_eq!(body.len(), 4);
        let port = u32::from_le_bytes(body.try_into().unwrap());
        let id = ((port as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        let update = {
            let proxies = self.proxy_map.read().unwrap();
            let Some(proxy) = proxies.get(&id) else {
                self.control_error(pkt, -tsi_wire::EINVAL);
                return;
            };
            proxy.lock().unwrap().disconnect(pkt)
        };
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        } else {
            self.control_error(pkt, -tsi_wire::EOPNOTSUPP);
        }
    }

    fn process_bind(&self, pkt: &VsockPacket) {
        let Some(req) = pkt.read_bind_req() else {
            self.control_error(pkt, -tsi_wire::EPROTO);
            return;
        };
        let id = ((req.peer_port as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        let result = {
            let proxies = self.proxy_map.read().unwrap();
            let Some(proxy) = proxies.get(&id) else {
                self.control_error(pkt, -tsi_wire::EINVAL);
                return;
            };
            let mut proxy = proxy.lock().unwrap();
            let Some((defs::SOCK_DGRAM, family)) = proxy.tsi_socket() else {
                self.control_error(pkt, -tsi_wire::EOPNOTSUPP);
                return;
            };
            if address_family(&req.addr) != Some(family) {
                self.control_error(pkt, -tsi_wire::EAFNOSUPPORT);
                return;
            }
            proxy.bind_datagram(req, &self.host_port_map)
        };
        let error = match result {
            Some(Ok(update)) => {
                self.process_proxy_update(id, update);
                0
            }
            Some(Err(error)) => error,
            None => -tsi_wire::EOPNOTSUPP,
        };
        self.control_error(pkt, error);
    }

    fn process_socket_option(&self, pkt: &VsockPacket, set: bool) {
        let Ok(body) = pkt.control_payload() else {
            return;
        };
        // decode_control's body-length table guarantees this; keep both in
        // sync when the wire format changes.
        debug_assert_eq!(body.len(), if set { 20 } else { 16 });
        let port = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let peer = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let level = u32::from_le_bytes(body[8..12].try_into().unwrap());
        let name = u32::from_le_bytes(body[12..16].try_into().unwrap());
        let value = if set {
            Some(i32::from_le_bytes(body[16..20].try_into().unwrap()))
        } else {
            None
        };
        let id = ((port as u64) << 32) | peer as u64;
        let result =
            self.proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map_or(Err(-tsi_wire::EINVAL), |proxy| {
                    let proxy = proxy.lock().unwrap();
                    if proxy.is_tsi() {
                        proxy.socket_option(level, name, value)
                    } else {
                        Err(-tsi_wire::EINVAL)
                    }
                });
        if set {
            self.push_packet(MuxerRx::ConnResponse {
                request_id: pkt.control_request_id(),
                operation: pkt.control_operation(),
                peer_port: pkt.src_port(),
                result: result.err().unwrap_or(0),
            });
        } else {
            self.push_packet(MuxerRx::SockoptResponse {
                request_id: pkt.control_request_id(),
                operation: pkt.control_operation(),
                peer_port: pkt.src_port(),
                result: result.as_ref().err().copied().unwrap_or(0),
                value: result.unwrap_or(0),
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

            match self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .filter(|_| !self.is_host_listener_id(id))
            {
                Some(proxy) => {
                    let mut proxy = proxy.lock().unwrap();
                    if proxy.is_tsi() {
                        proxy.getname(pkt, req.peer != 0);
                    } else {
                        self.control_error(pkt, -tsi_wire::EINVAL);
                    }
                }
                None => self.push_packet(MuxerRx::GetnameResponse {
                    request_id: pkt.control_request_id(),
                    operation: pkt.control_operation(),
                    peer_port: pkt.src_port(),
                    data: TsiGetnameRsp {
                        result: -libc::EINVAL,
                        addr_len: 0,
                        addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
                    },
                }),
            }
        } else {
            self.control_error(pkt, -tsi_wire::EPROTO);
        }
    }

    fn process_listen_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM listen request: src={}", pkt.src_port());
        let Some(mut req) = pkt.read_listen_req() else {
            self.control_error(pkt, -tsi_wire::EPROTO);
            return;
        };
        req.strict = self
            .tsi_flags
            .contains(TsiFlags::FAIL_ON_TCP_PUBLICATION_ERROR);
        let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
        if self.is_host_listener_id(id) || self.is_protected_unix_path(&req.addr) {
            warn!("rejecting guest listen on a host-side listening unix socket");
            self.push_packet(MuxerRx::ListenResponse {
                request_id: pkt.control_request_id(),
                operation: pkt.control_operation(),
                peer_port: pkt.src_port(),
                result: -libc::EACCES,
                flags: req.response_flags(),
            });
            return;
        }
        debug!("DGRAM listen request: id={id}");
        let response_flags = req.response_flags();
        // Applying the update re-locks the proxy map when removing, so the
        // guard must not outlive this lookup.
        let (update, result) = {
            let proxies = self.proxy_map.read().unwrap();
            match proxies.get(&id) {
                Some(proxy) => {
                    let mut proxy = proxy.lock().unwrap();
                    match proxy.tsi_socket() {
                        Some((defs::SOCK_STREAM, family))
                            if address_family(&req.addr) == Some(family) =>
                        {
                            let mut update = proxy.listen(pkt, req, &self.host_port_map);
                            self.apply_polling_under_lock(&mut update);
                            (Some(update), 0)
                        }
                        Some((defs::SOCK_STREAM, _)) => (None, -tsi_wire::EAFNOSUPPORT),
                        _ => (None, -tsi_wire::EOPNOTSUPP),
                    }
                }
                None => (None, -libc::EPERM),
            }
        };
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        } else {
            self.push_packet(MuxerRx::ListenResponse {
                request_id: pkt.control_request_id(),
                operation: pkt.control_operation(),
                peer_port: pkt.src_port(),
                result,
                flags: response_flags,
            });
        }
    }

    fn process_accept_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM accept request: src={}", pkt.src_port());
        let Some(req) = pkt.read_accept_req() else {
            self.control_error(pkt, -tsi_wire::EPROTO);
            return;
        };
        let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
        debug!("DGRAM accept request: id={id}");
        // Applying the update re-locks the proxy map when removing, so the
        // guard must not outlive this lookup.
        let update = {
            let proxies = self.proxy_map.read().unwrap();
            match proxies.get(&id).filter(|_| !self.is_host_listener_id(id)) {
                Some(proxy) => {
                    let mut proxy = proxy.lock().unwrap();
                    if !matches!(proxy.tsi_socket(), Some((defs::SOCK_STREAM, _)))
                        || !matches!(
                            proxy.status(),
                            ProxyStatus::Listening | ProxyStatus::WaitingOnAccept
                        )
                    {
                        self.control_error(pkt, -tsi_wire::EOPNOTSUPP);
                        None
                    } else {
                        let mut update = proxy.accept(req);
                        self.apply_polling_under_lock(&mut update);
                        Some(update)
                    }
                }
                None => {
                    self.push_packet(MuxerRx::AcceptResponse {
                        request_id: pkt.control_request_id(),
                        operation: pkt.control_operation(),
                        peer_port: pkt.src_port(),
                        result: -libc::EINVAL,
                    });
                    None
                }
            }
        };
        if let Some(update) = update {
            self.process_proxy_update(id, update);
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
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .filter(|_| !self.is_host_listener_id(id))
                .and_then(|proxy| {
                    let mut proxy = proxy.lock().unwrap();
                    proxy.is_tsi().then(|| {
                        let mut update = proxy.release();
                        self.apply_polling_under_lock(&mut update);
                        update
                    })
                });

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
        if pkt.flags() != uapi::VSOCK_DGRAM_START | uapi::VSOCK_DGRAM_EOM {
            // Every datagram the device forwards to the host socket is
            // delivered whole, so a guest packet without both boundaries is
            // a fragment it cannot reassemble.
            debug!(
                "dropping datagram without START/EOM boundaries: src={}",
                pkt.src_port()
            );
            return;
        }
        let Some(datagram) = pkt.read_datagram() else {
            return;
        };
        let id = ((pkt.src_port() as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        let update = {
            let proxies = self.proxy_map.read().unwrap();
            let Some(proxy) = proxies.get(&id).filter(|_| !self.is_host_listener_id(id)) else {
                return;
            };
            let mut proxy = proxy.lock().unwrap();
            let Some((defs::SOCK_DGRAM, family)) = proxy.tsi_socket() else {
                return;
            };
            if address_family(&datagram.address) != Some(family) {
                proxy.record_datagram_error(tsi_wire::EAFNOSUPPORT);
                return;
            }
            if self.is_protected_unix_path(&datagram.address) {
                proxy.record_datagram_error(tsi_wire::EACCES);
                return;
            }
            proxy.send_datagram(datagram)
        };
        self.process_proxy_update(id, update);
    }

    fn process_capabilities(&self, pkt: &VsockPacket) {
        let mut services = 0;
        if self.tsi_flags.contains(TsiFlags::HIJACK_INET) {
            services |= tsi_wire::SERVICE_INET;
            if cfg!(any(target_os = "linux", target_os = "macos")) {
                services |= tsi_wire::SERVICE_ICMP;
            }
        }
        if self.tsi_flags.contains(TsiFlags::HIJACK_UNIX) {
            services |= tsi_wire::SERVICE_UNIX;
        }
        self.push_packet(MuxerRx::FeatureResponse {
            request_id: pkt.control_request_id(),
            operation: defs::TSI_OP_CAPABILITIES,
            peer_port: pkt.src_port(),
            result: 0,
            services,
            features: tsi_wire::SUPPORTED_EXTENSIONS,
        });
    }

    fn process_activation(&self, pkt: &VsockPacket) {
        let Ok(body) = pkt.control_payload() else {
            return;
        };
        // decode_control's body-length table guarantees this; keep both in
        // sync when the wire format changes.
        debug_assert_eq!(body.len(), 16);
        let port = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let reserved = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let requested = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let id = ((port as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        let result = if reserved != 0 {
            Err(-tsi_wire::EINVAL)
        } else if requested & !tsi_wire::SUPPORTED_EXTENSIONS != 0 {
            Err(-tsi_wire::EOPNOTSUPP)
        } else {
            self.proxy_map
                .read()
                .unwrap()
                .get(&id)
                .filter(|_| !self.is_host_listener_id(id))
                .map_or(Err(-tsi_wire::EINVAL), |proxy| {
                    let mut proxy = proxy.lock().unwrap();
                    if proxy.is_tsi() {
                        proxy.activate(requested)
                    } else {
                        Err(-tsi_wire::EINVAL)
                    }
                })
        };
        self.push_packet(MuxerRx::FeatureResponse {
            request_id: pkt.control_request_id(),
            operation: defs::TSI_OP_ACTIVATE,
            peer_port: pkt.src_port(),
            result: result.as_ref().err().copied().unwrap_or(0),
            services: 0,
            features: result.unwrap_or(0),
        });
    }

    pub(crate) fn send_dgram_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "send_dgram_pkt: src_port={} dst_port={}",
            pkt.src_port(),
            pkt.dst_port()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID || pkt.op() != uapi::VSOCK_OP_RW {
            return Ok(());
        }

        #[cfg(feature = "tsi-fault-injection")]
        if pkt.dst_port() == super::tsi_control_faults::PORT {
            let proxies = self.proxy_map.read().unwrap().len() as u32;
            let (words, released) = self
                .rxq
                .lock()
                .unwrap()
                .faults
                .request(pkt.buf().unwrap_or_default(), proxies);
            if let Some(reply) = released {
                self.push_packet(reply);
            }
            self.push_packet(MuxerRx::FaultAck {
                peer_port: pkt.src_port(),
                words,
            });
            return Ok(());
        }

        if pkt.dst_port() == defs::TSI_CONTROL_PORT && self.tsi_flags.tsi_enabled() {
            let request = match pkt.control_request() {
                Ok(request) => request,
                Err(result) => {
                    self.control_error(pkt, result);
                    return Ok(());
                }
            };
            match request.operation {
                defs::TSI_OP_CREATE => self.process_proxy_create(pkt),
                defs::TSI_OP_CONNECT => self.process_connect(pkt),
                defs::TSI_OP_GETNAME => self.process_getname(pkt),
                defs::TSI_OP_SETOPT => self.process_socket_option(pkt, true),
                defs::TSI_OP_GETOPT => self.process_socket_option(pkt, false),
                defs::TSI_OP_BIND => self.process_bind(pkt),
                defs::TSI_OP_DISCONNECT => self.process_disconnect(pkt),
                defs::TSI_OP_LISTEN => self.process_listen_request(pkt),
                defs::TSI_OP_ACCEPT => self.process_accept_request(pkt),
                defs::TSI_OP_RELEASE => self.process_proxy_release(pkt),
                defs::TSI_OP_CAPABILITIES => self.process_capabilities(pkt),
                defs::TSI_OP_ACTIVATE => self.process_activation(pkt),
                _ if request.flags == 0 => self.control_error(pkt, -tsi_wire::EOPNOTSUPP),
                _ => (),
            }
            return Ok(());
        }

        if pkt.dst_port() == defs::TSI_DATAGRAM && self.tsi_flags.tsi_enabled() {
            self.process_dgram_rw(pkt);
        }

        Ok(())
    }

    fn process_op_request(&mut self, pkt: &VsockPacket) {
        debug!("OP_REQUEST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);

        // Applying the update re-locks the proxy map when removing, so the
        // guard must not outlive this block.
        let update = {
            let mut proxy_map = self.proxy_map.write().unwrap();

            if let Some(proxy) = proxy_map.get(&id) {
                let mut proxy = proxy.lock().unwrap();
                let mut update = proxy.confirm_connect(pkt);
                if let Some(update) = &mut update {
                    self.apply_polling_under_lock(update);
                }
                update
            } else if let Some(ipc_map) = &mut self.unix_ipc_port_map
                && let Some((path, listen)) = ipc_map.get(&pkt.dst_port())
            {
                if let Some(limit) = self.proxy_limit
                    && proxy_map.len() >= limit
                {
                    warn!("refusing guest connection: proxy limit reached");
                    self.push_packet(MuxerRx::Reset {
                        local_port: pkt.dst_port(),
                        peer_port: pkt.src_port(),
                    });
                    return;
                }
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

                let mut unix = match UnixProxy::new(
                    id,
                    self.cid,
                    pkt.dst_port(),
                    mem.clone(),
                    queue.clone(),
                    rxq,
                    path.to_path_buf(),
                ) {
                    Ok(unix) => unix,
                    Err(e) => {
                        error!(
                            "error creating unix proxy for port {}, sending rst: {e}",
                            pkt.dst_port()
                        );
                        self.push_packet(MuxerRx::Reset {
                            local_port: pkt.dst_port(),
                            peer_port: pkt.src_port(),
                        });
                        return;
                    }
                };
                let mut update = unix.connect_mapped(pkt);
                if !matches!(
                    unix.status(),
                    ProxyStatus::Connected | ProxyStatus::Connecting
                ) {
                    error!(
                        "error connecting unix proxy for port {} to {}, sending rst",
                        pkt.dst_port(),
                        path.display()
                    );
                    self.push_packet(MuxerRx::Reset {
                        local_port: pkt.dst_port(),
                        peer_port: pkt.src_port(),
                    });
                    return;
                }
                proxy_map.insert(id, Mutex::new(Box::new(unix)));
                self.apply_polling_under_lock(&mut update);
                Some(update)
            } else {
                debug!(
                    "no unix socket mapped for port {}, sending rst",
                    pkt.dst_port()
                );
                self.push_packet(MuxerRx::Reset {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                });
                None
            }
        };
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_response(&self, pkt: &VsockPacket) {
        debug!("OP_RESPONSE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
            let mut proxy = proxy.lock().unwrap();
            let mut update = proxy.process_op_response(pkt);
            self.apply_polling_under_lock(&mut update);
            update
        });
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
        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
            let mut proxy = proxy.lock().unwrap();
            let mut update = proxy.shutdown(pkt);
            self.apply_polling_under_lock(&mut update);
            update
        });
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_credit_update(&self, pkt: &VsockPacket) {
        debug!("OP_CREDIT_UPDATE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
            let mut proxy = proxy.lock().unwrap();
            let mut update = proxy.update_peer_credit(pkt);
            // Apply the polling change under the proxy lock so a later event on
            // the same connection cannot rearm it after we stopped polling.
            self.apply_polling_under_lock(&mut update);
            update
        });
        if let Some(update) = update {
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
            let mut proxy = proxy_lock.lock().unwrap();
            let mut update = proxy.sendmsg(pkt);
            // Apply the polling mask under the proxy lock so the event
            // thread cannot rearm a stale interest in between.
            self.apply_polling_under_lock(&mut update);
            update
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
            push_packet(self.cid, rx, &self.rxq, queue, mem);
        }
    }

    fn process_stream_rst(&self, pkt: &VsockPacket) {
        debug!("OP_RST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!(
                "allowing OP_RST: id={} src={} dst={}",
                id,
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = proxy_lock.lock().unwrap();
            let mut update = proxy.reset();
            self.apply_polling_under_lock(&mut update);
            drop(proxy);
            Some(update)
        } else {
            debug!("invalid OP_RST for {}", pkt.src_port());
            None
        };

        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    pub(crate) fn send_stream_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
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

        let id = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let is_datagram = pkt.dst_port() == defs::TSI_PROXY_PORT
            && self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .is_some_and(|proxy| {
                    matches!(
                        proxy.lock().unwrap().tsi_socket(),
                        Some((defs::SOCK_DGRAM, _))
                    )
                });
        if self.is_host_listener_id(id) || is_datagram {
            if matches!(pkt.op(), uapi::VSOCK_OP_REQUEST | uapi::VSOCK_OP_RW) {
                self.push_packet(MuxerRx::Reset {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                });
            }
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

#[cfg(unix)]
pub(super) fn tsi_unix_path(addr: &SockaddrStorage) -> Option<PathBuf> {
    let path = addr.as_unix_addr()?.path()?;
    let bytes = path.as_os_str().as_bytes();
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    (end != 0).then(|| PathBuf::from(OsStr::from_bytes(&bytes[..end])))
}

#[cfg(windows)]
fn tsi_unix_path(addr: &SockaddrStorage) -> Option<PathBuf> {
    addr.unix_path()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    #[cfg(unix)]
    {
        match (fs::metadata(a), fs::metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(windows)]
    {
        match (fs::canonicalize(a), fs::canonicalize(b)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod protected_path_tests {
    use super::*;
    use crate::virtio::descriptor_utils::{DescriptorType, create_descriptor_chain};
    use crate::virtio::vsock::packet::{
        TsiAcceptReq, TsiConnectReq, TsiListenReq, VSOCK_PKT_HDR_SIZE,
    };
    use crate::virtio::vsock::proxy::AddressFamily;
    use crate::virtio::vsock::unix_proxy::UnixAcceptorProxy;
    use nix::sys::socket::SockaddrLike;
    use std::mem;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use vm_memory::{Bytes, GuestAddress};

    fn guest_packet(
        mem: &GuestMemoryMmap,
        type_: u16,
        op: u16,
        src_port: u32,
        dst_port: u32,
        data: &[u8],
    ) -> VsockPacket {
        let chain = create_descriptor_chain(
            mem,
            GuestAddress(0),
            GuestAddress(0x1000),
            vec![
                (DescriptorType::Readable, VSOCK_PKT_HDR_SIZE as u32),
                (DescriptorType::Readable, data.len() as u32),
            ],
            0,
        )
        .unwrap();
        let mut header = [0u8; VSOCK_PKT_HDR_SIZE];
        header[8..16].copy_from_slice(&uapi::VSOCK_HOST_CID.to_le_bytes());
        header[16..20].copy_from_slice(&src_port.to_le_bytes());
        header[20..24].copy_from_slice(&dst_port.to_le_bytes());
        header[24..28].copy_from_slice(&(data.len() as u32).to_le_bytes());
        header[28..30].copy_from_slice(&type_.to_le_bytes());
        header[30..32].copy_from_slice(&op.to_le_bytes());
        mem.write_slice(&header, GuestAddress(0x1000)).unwrap();
        mem.write_slice(data, GuestAddress(0x1000 + VSOCK_PKT_HDR_SIZE as u64))
            .unwrap();
        VsockPacket::from_tx_virtq_head(&chain).unwrap()
    }

    fn guest_control_packet(mem: &GuestMemoryMmap, operation: u32, body: &[u8]) -> VsockPacket {
        let mut data = vec![0; tsi_wire::CONTROL_HEADER_LEN + body.len()];
        data[..4].copy_from_slice(&tsi_wire::VERSION.to_le_bytes());
        data[4..8].copy_from_slice(&operation.to_le_bytes());
        data[8..16].copy_from_slice(&1u64.to_le_bytes());
        data[16..20].copy_from_slice(&(body.len() as u32).to_le_bytes());
        data[tsi_wire::CONTROL_HEADER_LEN..].copy_from_slice(body);
        guest_packet(
            mem,
            uapi::VSOCK_TYPE_DGRAM,
            uapi::VSOCK_OP_RW,
            4000,
            defs::TSI_CONTROL_PORT,
            &data,
        )
    }

    #[test]
    fn control_dispatch_uses_one_guest_memory_snapshot() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let mut body = [0u8; 12];
        body[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        body[4..6].copy_from_slice(&2u16.to_le_bytes());
        body[6..8].copy_from_slice(&2u16.to_le_bytes());
        body[8..12].copy_from_slice(&17u32.to_le_bytes());
        let pkt = guest_control_packet(&mem, defs::TSI_OP_CREATE, &body);
        mem.write_slice(&defs::TSI_OP_BIND.to_le_bytes(), GuestAddress(0x1000 + 20))
            .unwrap();
        mem.write_slice(
            &defs::TSI_OP_BIND.to_le_bytes(),
            GuestAddress(0x1000 + VSOCK_PKT_HDR_SIZE as u64 + 4),
        )
        .unwrap();
        mem.write_slice(
            &[0xff; 12],
            GuestAddress(0x1000 + VSOCK_PKT_HDR_SIZE as u64 + 24),
        )
        .unwrap();
        assert_eq!(pkt.dst_port(), defs::TSI_CONTROL_PORT);
        assert_eq!(
            pkt.control_request().unwrap().operation,
            defs::TSI_OP_CREATE
        );
        assert_eq!(pkt.read_proxy_create().unwrap().protocol, 17);
    }

    #[test]
    fn capability_reply_tracks_enabled_services() {
        for (flags, expected) in [
            (
                TsiFlags::HIJACK_INET,
                tsi_wire::SERVICE_INET | tsi_wire::SERVICE_ICMP,
            ),
            (
                TsiFlags::HIJACK_INET | TsiFlags::HIJACK_UNIX,
                tsi_wire::SERVICE_INET | tsi_wire::SERVICE_UNIX | tsi_wire::SERVICE_ICMP,
            ),
        ] {
            let mut muxer = VsockMuxer::new(3, None, None, flags, None, None).unwrap();
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap();
            muxer.mem = Some(mem.clone());
            muxer.queue = Some(Arc::new(Mutex::new(VirtQueue::new(256))));
            let packet = guest_control_packet(&mem, defs::TSI_OP_CAPABILITIES, &[]);
            muxer.send_dgram_pkt(&packet).unwrap();
            assert!(matches!(
                muxer.rxq.lock().unwrap().pop(),
                Some(MuxerRx::FeatureResponse {
                    operation: defs::TSI_OP_CAPABILITIES,
                    services,
                    features: 0,
                    ..
                }) if services == expected
            ));
        }
    }

    #[test]
    fn unknown_oneway_control_has_no_reply() {
        let mut muxer = VsockMuxer::new(3, None, None, TsiFlags::HIJACK_INET, None, None).unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap();
        muxer.mem = Some(mem.clone());
        muxer.queue = Some(Arc::new(Mutex::new(VirtQueue::new(256))));
        let mut data = vec![0; tsi_wire::CONTROL_HEADER_LEN];
        tsi_wire::encode_control_reply(&mut data, 0xf000_0000, 1, 0);
        data[20..24].copy_from_slice(&tsi_wire::CONTROL_ONEWAY.to_le_bytes());
        let packet = guest_packet(
            &mem,
            uapi::VSOCK_TYPE_DGRAM,
            uapi::VSOCK_OP_RW,
            4000,
            defs::TSI_CONTROL_PORT,
            &data,
        );
        muxer.send_dgram_pkt(&packet).unwrap();
        assert!(muxer.rxq.lock().unwrap().is_empty());
    }

    fn create_packet(mem: &GuestMemoryMmap, peer_port: u32) -> VsockPacket {
        let mut body = [0u8; 12];
        body[0..4].copy_from_slice(&peer_port.to_le_bytes());
        body[4..6].copy_from_slice(&defs::LINUX_AF_INET.to_le_bytes());
        body[6..8].copy_from_slice(&defs::SOCK_DGRAM.to_le_bytes());
        guest_control_packet(mem, defs::TSI_OP_CREATE, &body)
    }

    fn create_result(muxer: &mut VsockMuxer) -> Option<i32> {
        match muxer.rxq.lock().unwrap().pop() {
            Some(MuxerRx::ConnResponse { result, .. }) => Some(result),
            other => panic!("unexpected reply: {other:?}"),
        }
    }

    #[test]
    fn create_reply_reports_emfile_when_proxy_limit_is_reached() {
        let mut muxer = VsockMuxer::new(3, None, None, TsiFlags::HIJACK_INET, None, None).unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap();
        muxer.mem = Some(mem.clone());
        muxer.queue = Some(Arc::new(Mutex::new(VirtQueue::new(256))));
        muxer.proxy_limit = Some(1);

        muxer.send_dgram_pkt(&create_packet(&mem, 0x1000)).unwrap();
        assert_eq!(create_result(&mut muxer), Some(0));
        assert_eq!(muxer.proxy_map.read().unwrap().len(), 1);

        muxer.send_dgram_pkt(&create_packet(&mem, 0x1001)).unwrap();
        assert_eq!(create_result(&mut muxer), Some(-libc::EMFILE));
        assert_eq!(muxer.proxy_map.read().unwrap().len(), 1);
    }

    #[test]
    fn guest_connection_gets_reset_when_proxy_limit_is_reached() {
        let mut muxer = VsockMuxer::new(
            3,
            None,
            Some(HashMap::from([(
                4000u32,
                (PathBuf::from("/unmapped"), false),
            )])),
            TsiFlags::empty(),
            Some(0),
            None,
        )
        .unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap();
        muxer.mem = Some(mem.clone());
        muxer.queue = Some(Arc::new(Mutex::new(VirtQueue::new(256))));
        muxer.proxy_limit = Some(0);

        let packet = guest_packet(
            &mem,
            uapi::VSOCK_TYPE_STREAM,
            uapi::VSOCK_OP_REQUEST,
            5000,
            4000,
            b"x",
        );
        muxer.process_op_request(&packet);
        assert!(matches!(
            muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::Reset {
                local_port: 4000,
                peer_port: 5000
            })
        ));
        assert!(muxer.proxy_map.read().unwrap().is_empty());
    }

    #[test]
    fn mapped_unix_stream_completes_with_vsock_response_only() {
        let path = std::env::temp_dir().join(format!(
            "krun-mapped-stream-{}-{}.sock",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let port = 4000;
        let mut muxer = VsockMuxer::new(
            3,
            None,
            Some(HashMap::from([(port, (path.clone(), false))])),
            TsiFlags::empty(),
            None,
            None,
        )
        .unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap();
        muxer.mem = Some(mem.clone());
        muxer.queue = Some(Arc::new(Mutex::new(VirtQueue::new(256))));
        let packet = guest_packet(
            &mem,
            uapi::VSOCK_TYPE_STREAM,
            uapi::VSOCK_OP_REQUEST,
            5000,
            port,
            b"x",
        );
        muxer.process_op_request(&packet);
        assert!(matches!(
            muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::OpResponse {
                local_port: 4000,
                peer_port: 5000
            })
        ));
        assert!(muxer.rxq.lock().unwrap().is_empty());
        drop(listener);
        fs::remove_file(path).unwrap();
    }

    fn guest_unix_addr(path: &[u8]) -> SockaddrStorage {
        let mut raw: libc::sockaddr_un = unsafe { mem::zeroed() };
        raw.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (dst, src) in raw.sun_path.iter_mut().zip(path) {
            *dst = *src as libc::c_char;
        }
        unsafe {
            SockaddrStorage::from_raw(
                &raw as *const libc::sockaddr_un as *const libc::sockaddr,
                Some(mem::size_of::<libc::sockaddr_un>() as libc::socklen_t),
            )
        }
        .unwrap()
    }

    #[test]
    fn guest_path_strips_padding_nuls() {
        assert_eq!(
            tsi_unix_path(&guest_unix_addr(b"/run/krun-init.sock")),
            Some(PathBuf::from("/run/krun-init.sock"))
        );
    }

    #[test]
    fn guest_path_stops_at_first_nul() {
        let path = PathBuf::from("/run/krun-init.sock");
        let muxer = VsockMuxer::new(
            3,
            None,
            Some(HashMap::from([(1234, (path.clone(), true))])),
            TsiFlags::HIJACK_UNIX,
            None,
            None,
        )
        .unwrap();
        let addr = guest_unix_addr(b"/run/krun-init.sock\0suffix");
        assert_eq!(tsi_unix_path(&addr), Some(path));
        assert!(muxer.is_protected_unix_path(&addr));
    }

    #[test]
    fn guest_packets_cannot_dispatch_to_or_replace_host_listener() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "krun-protected-listener-{}-{nonce}.sock",
            std::process::id()
        ));
        let port = 0x4b52554e;
        let id = ((port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
        let mut muxer = VsockMuxer::new(
            3,
            None,
            Some(HashMap::from([(port, (path.clone(), true))])),
            TsiFlags::HIJACK_UNIX,
            None,
            None,
        )
        .unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap();
        muxer.mem = Some(mem.clone());
        muxer.queue = Some(Arc::new(Mutex::new(VirtQueue::new(256))));
        let listener = UnixAcceptorProxy::new(id, &path, port).unwrap();
        muxer
            .proxy_map
            .write()
            .unwrap()
            .insert(id, Mutex::new(Box::new(listener)));

        let mut connect = [0u8; 136];
        connect[..4].copy_from_slice(&port.to_le_bytes());
        connect[4..8].copy_from_slice(&16u32.to_le_bytes());
        connect[8..10].copy_from_slice(&(libc::AF_INET as u16).to_le_bytes());
        let packet = guest_control_packet(&mem, defs::TSI_OP_CONNECT, &connect);
        muxer.send_dgram_pkt(&packet).unwrap();
        assert!(matches!(
            muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { request_id: 1, result, .. }) if result == -libc::EACCES
        ));

        let mut create = [0u8; 12];
        create[..4].copy_from_slice(&port.to_le_bytes());
        create[4..6].copy_from_slice(&(libc::AF_UNIX as u16).to_le_bytes());
        create[6..8].copy_from_slice(&defs::SOCK_STREAM.to_le_bytes());
        let packet = guest_control_packet(&mem, defs::TSI_OP_CREATE, &create);
        muxer.send_dgram_pkt(&packet).unwrap();
        assert!(matches!(
            muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { request_id: 1, result, .. }) if result == -tsi_wire::EADDRINUSE
        ));

        let packet = guest_packet(
            &mem,
            uapi::VSOCK_TYPE_STREAM,
            uapi::VSOCK_OP_RW,
            port,
            defs::TSI_PROXY_PORT,
            b"x",
        );
        muxer.send_stream_pkt(&packet).unwrap();
        assert!(matches!(
            muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::Reset { .. })
        ));
        assert_eq!(
            muxer.proxy_map.read().unwrap()[&id]
                .lock()
                .unwrap()
                .status(),
            ProxyStatus::WaitingOnAccept
        );
        assert!(UnixStream::connect(&path).is_ok());
    }

    #[test]
    fn same_file_matches_identical_and_aliased_paths() {
        let dir = std::env::temp_dir();
        let a = dir.join(format!("krun-same-file-test-{}", std::process::id()));
        fs::write(&a, b"").unwrap();
        let b = dir.join(".").join(a.file_name().unwrap());
        let hardlink = dir.join(format!("krun-same-file-link-{}", std::process::id()));
        fs::hard_link(&a, &hardlink).unwrap();
        assert!(same_file(&a, &b));
        assert!(same_file(&a, &hardlink));
        assert!(!same_file(&a, &dir.join("other")));
        fs::remove_file(&hardlink).unwrap();
        fs::remove_file(&a).unwrap();
    }

    #[test]
    fn relative_listening_path_remains_protected_after_chdir() {
        const CHILD: &str = "KRUN_VSOCK_RELATIVE_PATH_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "virtio::vsock::muxer::protected_path_tests::relative_listening_path_remains_protected_after_chdir",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let path = PathBuf::from("krun-relative-protected.sock");
        let absolute = std::env::current_dir().unwrap().join(&path);
        let muxer = VsockMuxer::new(
            3,
            None,
            Some(HashMap::from([(1234, (path, true))])),
            TsiFlags::HIJACK_UNIX,
            None,
            None,
        )
        .unwrap();
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        assert_eq!(muxer.unix_ipc_port_map.as_ref().unwrap()[&1234].0, absolute);
        assert!(muxer.is_protected_unix_path(&guest_unix_addr(absolute.as_os_str().as_bytes())));
    }
    struct RemovingProxy {
        id: u64,
    }

    impl Proxy for RemovingProxy {
        fn id(&self) -> u64 {
            self.id
        }
        fn status(&self) -> ProxyStatus {
            ProxyStatus::Listening
        }
        fn tsi_socket(&self) -> Option<(u16, AddressFamily)> {
            Some((defs::SOCK_STREAM, AddressFamily::Inet))
        }
        fn listen(
            &mut self,
            _pkt: &VsockPacket,
            _req: TsiListenReq,
            _host_port_map: &Option<HashMap<u16, u16>>,
        ) -> ProxyUpdate {
            ProxyUpdate {
                remove_proxy: ProxyRemoval::Immediate,
                signal_queue: true,
                ..Default::default()
            }
        }
        fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
            ProxyUpdate {
                remove_proxy: ProxyRemoval::Immediate,
                ..Default::default()
            }
        }
        fn confirm_connect(&mut self, _pkt: &VsockPacket) -> Option<ProxyUpdate> {
            Some(ProxyUpdate {
                remove_proxy: ProxyRemoval::Immediate,
                ..Default::default()
            })
        }
        fn connect(
            &mut self,
            _pkt: &VsockPacket,
            _req: TsiConnectReq,
            #[cfg(windows)] _epoll: &Epoll,
        ) -> ProxyUpdate {
            ProxyUpdate::default()
        }
        fn update_peer_credit(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
            ProxyUpdate::default()
        }
        fn process_op_response(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
            ProxyUpdate::default()
        }
        fn release(&mut self) -> ProxyUpdate {
            ProxyUpdate::default()
        }
        fn process_event(&mut self, _evset: EventSet) -> ProxyUpdate {
            ProxyUpdate::default()
        }
        fn getname(&mut self, _pkt: &VsockPacket, _peer: bool) {}
    }

    impl AsRawFd for RemovingProxy {
        fn as_raw_fd(&self) -> RawFd {
            -1
        }
    }

    #[test]
    fn request_handlers_apply_removals_without_relocking_the_map() {
        // If a handler re-locked the proxy map while applying a removal,
        // the dispatches below would deadlock instead of finishing.
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut muxer =
                VsockMuxer::new(3, None, None, TsiFlags::HIJACK_INET, None, None).unwrap();
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap();
            muxer.mem = Some(mem.clone());
            muxer.queue = Some(Arc::new(Mutex::new(VirtQueue::new(256))));
            let id = (0x1000u64 << 32) | defs::TSI_PROXY_PORT as u64;
            let insert = |muxer: &VsockMuxer| {
                muxer.proxy_map.write().unwrap().insert(
                    id,
                    Mutex::new(Box::new(RemovingProxy { id }) as Box<dyn Proxy>),
                );
            };

            let mut body = [0u8; 144];
            body[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
            body[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
            body[8..12].copy_from_slice(&16u32.to_le_bytes());
            body[12..16].copy_from_slice(&16u32.to_le_bytes());
            body[16..18].copy_from_slice(&defs::LINUX_AF_INET.to_le_bytes());
            body[18..20].copy_from_slice(&80u16.to_be_bytes());
            body[20..24].copy_from_slice(&[127, 0, 0, 1]);
            let listen = guest_control_packet(&mem, defs::TSI_OP_LISTEN, &body);
            insert(&muxer);
            muxer.send_dgram_pkt(&listen).unwrap();
            let listen_removed = muxer.proxy_map.read().unwrap().get(&id).is_none();

            let mut body = [0u8; 8];
            body[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
            let accept = guest_control_packet(&mem, defs::TSI_OP_ACCEPT, &body);
            insert(&muxer);
            muxer.send_dgram_pkt(&accept).unwrap();
            let accept_removed = muxer.proxy_map.read().unwrap().get(&id).is_none();

            let request = guest_packet(
                &mem,
                uapi::VSOCK_TYPE_STREAM,
                uapi::VSOCK_OP_REQUEST,
                0x1000,
                defs::TSI_PROXY_PORT,
                b"x",
            );
            insert(&muxer);
            muxer.process_op_request(&request);
            let confirm_removed = muxer.proxy_map.read().unwrap().get(&id).is_none();

            tx.send(listen_removed && accept_removed && confirm_removed)
                .unwrap();
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(10))
                .expect("request handler deadlocked on the proxy map lock")
        );
    }
}
