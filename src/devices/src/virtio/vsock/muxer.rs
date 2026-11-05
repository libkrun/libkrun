use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::path::PathBuf;
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
use super::packet::{TsiConnectReq, TsiGetnameRsp, VsockPacket};
use super::proxy::{Proxy, ProxyRemoval, ProxyStatus, ProxyUpdate};
use super::reaper::ReaperThread;
#[cfg(target_os = "macos")]
use super::timesync::TimesyncThread;
use super::tsi_dgram::TsiDgramProxy;
use super::tsi_stream::TsiStreamProxy;
use super::tsi_wire;
use super::unix_proxy::UnixProxy;
use crossbeam_channel::{Sender, unbounded};
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
        local_port: u32,
        peer_port: u32,
        result: i32,
        value: i32,
    },
    GetnameResponse {
        request_id: u64,
        local_port: u32,
        peer_port: u32,
        data: TsiGetnameRsp,
    },
    ConnResponse {
        request_id: u64,
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
        request_id: u64,
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    AcceptResponse {
        request_id: u64,
        local_port: u32,
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
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
    ) -> Self {
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
        }
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
        if pkt.control_request_id() == 0 || matches!(pkt.dst_port(), 1027 | 1031) {
            return;
        }
        if pkt.dst_port() == defs::TSI_GETOPT {
            self.push_packet(MuxerRx::SockoptResponse {
                request_id: pkt.control_request_id(),
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
                result,
                value: 0,
            });
        } else if pkt.dst_port() == 1026 {
            self.push_packet(MuxerRx::GetnameResponse {
                request_id: pkt.control_request_id(),
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
                data: TsiGetnameRsp {
                    result,
                    ..Default::default()
                },
            });
        } else {
            self.push_packet(MuxerRx::ConnResponse {
                request_id: pkt.control_request_id(),
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
                result,
            });
        }
    }

    fn process_proxy_create(&self, pkt: &VsockPacket) {
        let result = self.create_proxy(pkt).err().unwrap_or(0);
        self.push_packet(MuxerRx::ConnResponse {
            request_id: pkt.control_request_id(),
            local_port: pkt.dst_port(),
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
        let proxy: Box<dyn Proxy> = match req._type {
            defs::SOCK_STREAM => Box::new(
                TsiStreamProxy::new(
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
                .map_err(|e| -e.linux_errno())?,
            ),
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

    fn process_connect(&self, pkt: &VsockPacket) {
        debug!("proxy connect request");
        if let Some(req) = pkt.read_connect_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("proxy connect request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    let mut proxy = proxy.lock().unwrap();
                    if proxy.is_tsi() {
                        self.process_proxy_update(id, proxy.connect(pkt, req));
                    } else {
                        self.control_error(pkt, -tsi_wire::EINVAL);
                    }
                }
                None => self.push_packet(MuxerRx::ConnResponse {
                    request_id: pkt.control_request_id(),
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -tsi_wire::ECONNREFUSED,
                }),
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
        let Some(req) = pkt.read_sendto_addr() else {
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
            if !proxy.is_tsi() {
                self.control_error(pkt, -tsi_wire::EINVAL);
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
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
                result: result.err().unwrap_or(0),
            });
        } else {
            self.push_packet(MuxerRx::SockoptResponse {
                request_id: pkt.control_request_id(),
                local_port: pkt.dst_port(),
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

            match self.proxy_map.read().unwrap().get(&id) {
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
                    local_port: pkt.dst_port(),
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

    fn process_sendto_addr(&self, pkt: &VsockPacket) {
        debug!("new DGRAM sendto addr: src={}", pkt.src_port());
        if let Some(req) = pkt.read_sendto_addr() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("new DGRAM sendto addr: id={id}");
            let update = self.proxy_map.read().unwrap().get(&id).and_then(|proxy| {
                let mut proxy = proxy.lock().unwrap();
                proxy.is_tsi().then(|| proxy.sendto_addr(req))
            });

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
                Some(proxy) => {
                    let mut proxy = proxy.lock().unwrap();
                    if proxy.is_tsi() {
                        self.process_proxy_update(id, proxy.listen(pkt, req, &self.host_port_map));
                    } else {
                        self.control_error(pkt, -tsi_wire::EINVAL);
                    }
                }
                None => self.push_packet(MuxerRx::ListenResponse {
                    request_id: pkt.control_request_id(),
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EPERM,
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
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    let mut proxy = proxy.lock().unwrap();
                    if !proxy.is_tsi()
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
                    local_port: pkt.dst_port(),
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
            let update = if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                let mut proxy = proxy.lock().unwrap();
                proxy.is_tsi().then(|| proxy.release())
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

        if self.tsi_flags.tsi_enabled()
            && matches!(pkt.dst_port(), 1024..=1027 | 1029..=1031 | 1033..=1036)
            && let Err(result) = pkt.control_payload()
        {
            self.control_error(pkt, result);
            return Ok(());
        }

        match pkt.dst_port() {
            defs::TSI_PROXY_CREATE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_create(pkt)
            }
            defs::TSI_CONNECT if self.tsi_flags.tsi_enabled() => self.process_connect(pkt),
            defs::TSI_GETNAME if self.tsi_flags.tsi_enabled() => self.process_getname(pkt),
            defs::TSI_SETOPT if self.tsi_flags.tsi_enabled() => {
                self.process_socket_option(pkt, true)
            }
            defs::TSI_GETOPT if self.tsi_flags.tsi_enabled() => {
                self.process_socket_option(pkt, false)
            }
            defs::TSI_BIND if self.tsi_flags.tsi_enabled() => self.process_bind(pkt),
            defs::TSI_DISCONNECT if self.tsi_flags.tsi_enabled() => self.process_disconnect(pkt),
            defs::TSI_SENDTO_ADDR if self.tsi_flags.tsi_enabled() => self.process_sendto_addr(pkt),
            defs::TSI_SENDTO_DATA if self.tsi_flags.tsi_enabled() => self.process_sendto_data(pkt),
            defs::TSI_DATAGRAM if self.tsi_flags.tsi_enabled() => self.process_dgram_rw(pkt),
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
                pkt.src_port(),
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
            let tsi = TsiConnectReq {
                request_id: 0,
                peer_port: 0,
                addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
            };
            let update = unix.connect(pkt, tsi);
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
            unix.confirm_connect(pkt);
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
