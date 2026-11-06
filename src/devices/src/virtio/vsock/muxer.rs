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
use vm_memory::GuestMemoryMmap;

use crate::virtio::InterruptTransport;
use std::net::{Ipv4Addr, SocketAddrV4};

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
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
            if let Err(e) = queue.add_used(mem, head.index, pkt.finish_rx().unwrap_or(0)) {
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
}

impl VsockMuxer {
    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        mut unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
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
        Ok(VsockMuxer {
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
        );
        thread.run();

        self.reaper_sender = Some(sender);
        let reaper = ReaperThread::new(receiver, self.proxy_map.clone());
        reaper.run();
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
                if let Err(e) = queue.add_used(mem, head.index, pkt.finish_rx().unwrap_or(0)) {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            }
        } else {
            error!("couldn't push pkt to queue, adding it to rxq");
            drop(queue);
            self.rxq.lock().unwrap().push(rx);
        }
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
                Ok(proxy.connect(pkt, req))
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
        if let Some(mut req) = pkt.read_listen_req() {
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
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    let mut proxy = proxy.lock().unwrap();
                    let result = match proxy.tsi_socket() {
                        Some((defs::SOCK_STREAM, family))
                            if address_family(&req.addr) == Some(family) =>
                        {
                            self.process_proxy_update(
                                id,
                                proxy.listen(pkt, req, &self.host_port_map),
                            );
                            return;
                        }
                        Some((defs::SOCK_STREAM, _)) => -tsi_wire::EAFNOSUPPORT,
                        _ => -tsi_wire::EOPNOTSUPP,
                    };
                    self.push_packet(MuxerRx::ListenResponse {
                        request_id: pkt.control_request_id(),
                        operation: pkt.control_operation(),
                        peer_port: pkt.src_port(),
                        result,
                        flags: req.response_flags(),
                    });
                }
                None => self.push_packet(MuxerRx::ListenResponse {
                    request_id: pkt.control_request_id(),
                    operation: pkt.control_operation(),
                    peer_port: pkt.src_port(),
                    result: -libc::EPERM,
                    flags: req.response_flags(),
                }),
            };
        } else {
            self.control_error(pkt, -tsi_wire::EPROTO);
        }
    }

    fn process_accept_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM accept request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_accept_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM accept request: id={id}");
            match self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .filter(|_| !self.is_host_listener_id(id))
            {
                Some(proxy) => {
                    let mut proxy = proxy.lock().unwrap();
                    if !matches!(proxy.tsi_socket(), Some((defs::SOCK_STREAM, _)))
                        || !matches!(
                            proxy.status(),
                            ProxyStatus::Listening | ProxyStatus::WaitingOnAccept
                        )
                    {
                        self.control_error(pkt, -tsi_wire::EOPNOTSUPP);
                    } else {
                        self.process_proxy_update(id, proxy.accept(req));
                    }
                }
                None => self.push_packet(MuxerRx::AcceptResponse {
                    request_id: pkt.control_request_id(),
                    operation: pkt.control_operation(),
                    peer_port: pkt.src_port(),
                    result: -libc::EINVAL,
                }),
            }
        } else {
            self.control_error(pkt, -tsi_wire::EPROTO);
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
                    proxy.is_tsi().then(|| proxy.release())
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
        let body = pkt.control_payload().unwrap();
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
        let mut proxy_map = self.proxy_map.write().unwrap();

        if let Some(proxy) = proxy_map.get(&id) {
            if let Some(update) = proxy.lock().unwrap().confirm_connect(pkt) {
                self.process_proxy_update(id, update);
            }
        } else if let Some(ipc_map) = &mut self.unix_ipc_port_map
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
            let update = unix.connect_mapped(pkt);
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
            self.process_proxy_update(id, update);
        } else {
            debug!(
                "no unix socket mapped for port {}, sending rst",
                pkt.dst_port()
            );
            self.push_packet(MuxerRx::Reset {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
            });
        }
    }

    fn process_op_response(&self, pkt: &VsockPacket) {
        debug!("OP_RESPONSE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().process_op_response(pkt));
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
        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy| {
            let mut proxy = proxy.lock().unwrap();
            let mut update = proxy.update_peer_credit(pkt);
            // Apply the polling change under the proxy lock so a later event on
            // the same connection cannot rearm it after we stopped polling.
            if let Some((id, fd, events)) = update.polling.take() {
                self.update_polling(id, fd, events);
            }
            update
        });
        if let Some(update) = update {
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
        let update = if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!(
                "allowing OP_RST: id={} src={} dst={}",
                id,
                pkt.src_port(),
                pkt.dst_port()
            );
            Some(proxy_lock.lock().unwrap().release())
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
    use crate::virtio::vsock::packet::VSOCK_PKT_HDR_SIZE;
    use crate::virtio::vsock::unix_proxy::UnixAcceptorProxy;
    use nix::sys::socket::SockaddrLike;
    use std::mem;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{SystemTime, UNIX_EPOCH};
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
            let mut muxer = VsockMuxer::new(3, None, None, flags).unwrap();
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
        let mut muxer = VsockMuxer::new(3, None, None, TsiFlags::HIJACK_INET).unwrap();
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
        )
        .unwrap();
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        assert_eq!(muxer.unix_ipc_port_map.as_ref().unwrap()[&1234].0, absolute);
        assert!(muxer.is_protected_unix_path(&guest_unix_addr(absolute.as_os_str().as_bytes())));
    }
}
