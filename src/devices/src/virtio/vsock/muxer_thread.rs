use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use super::super::Queue as VirtQueue;
use super::muxer::{MuxerRx, ProxyMap, push_packet};
use super::muxer_rxq::MuxerRxQ;
use super::proxy::{NewProxyType, Proxy, ProxyRawHandle, ProxyRemoval, ProxyUpdate};
use super::snapshot_gate::SnapshotGate;
use super::tsi_stream::TsiStreamProxy;

use crate::virtio::InterruptTransport;
use crate::virtio::vsock::defs;
use crate::virtio::vsock::unix::{UnixAcceptorProxy, UnixProxy};
use crossbeam_channel::Sender;
use rand::{Rng, rng, rngs::ThreadRng};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::GuestMemoryMmap;

pub struct MuxerThread {
    cid: u64,
    pub epoll: Epoll,
    rxq: Arc<Mutex<MuxerRxQ>>,
    proxy_map: ProxyMap,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
    reaper_sender: Sender<u64>,
    /// AF_UNIX host-IPC listeners; consumed by `create_lisening_ipc_sockets`.
    unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
    snapshot_gate: Arc<SnapshotGate>,
}

impl MuxerThread {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cid: u64,
        epoll: Epoll,
        rxq: Arc<Mutex<MuxerRxQ>>,
        proxy_map: ProxyMap,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        reaper_sender: Sender<u64>,
        unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
        snapshot_gate: Arc<SnapshotGate>,
    ) -> Self {
        MuxerThread {
            cid,
            epoll,
            rxq,
            proxy_map,
            mem,
            queue,
            interrupt,
            reaper_sender,
            unix_ipc_port_map,
            snapshot_gate,
        }
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("vsock muxer".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn send_credit_request(&self, credit_rx: MuxerRx) {
        debug!("send_credit_request");
        push_packet(
            self.cid,
            credit_rx,
            &self.rxq,
            &self.queue,
            &self.mem,
            &self.snapshot_gate,
        );
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

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate, thread_rng: &mut ThreadRng) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        if let Some(credit_rx) = update.push_credit_req {
            debug!("send_credit_request");
            self.send_credit_request(credit_rx);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                warn!("immediately removing proxy: {id}");
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                warn!("deferring proxy removal: {id}");
                if self.reaper_sender.send(id).is_err() {
                    self.proxy_map.write().unwrap().remove(&id);
                }
            }
        }

        let mut should_signal = update.signal_queue;

        if let Some((peer_port, accept_fd, family, proxy_type)) = update.new_proxy {
            let local_port: u32 = thread_rng.random_range(1024..u32::MAX);
            let new_id: u64 = ((peer_port as u64) << 32) | (local_port as u64);
            info!(
                "[VSOCK_TIMING] creating new proxy: new_id={:#x} (peer_port={}, local_port={}) from acceptor id={:#x}",
                new_id, peer_port, local_port, id
            );
            let new_proxy: Box<dyn Proxy> = match proxy_type {
                NewProxyType::Tcp => Box::new(TsiStreamProxy::new_reverse(
                    new_id,
                    self.cid,
                    id,
                    family,
                    local_port,
                    peer_port,
                    accept_fd,
                    self.mem.clone(),
                    self.queue.clone(),
                    self.rxq.clone(),
                    self.snapshot_gate.clone(),
                )),
                NewProxyType::Unix => Box::new(UnixProxy::new_reverse(
                    new_id,
                    self.cid,
                    local_port,
                    peer_port,
                    accept_fd,
                    self.mem.clone(),
                    self.queue.clone(),
                    self.rxq.clone(),
                    self.snapshot_gate.clone(),
                )),
            };
            self.proxy_map
                .write()
                .unwrap()
                .insert(new_id, Mutex::new(new_proxy));
            info!("[VSOCK_TIMING] new proxy inserted into proxy_map, calling push_op_request");
            if let Some(proxy) = self.proxy_map.read().unwrap().get(&new_id) {
                proxy.lock().unwrap().push_op_request();
            };
            should_signal = true;
        }

        if should_signal {
            debug!("signal IRQ");
            self.interrupt.signal_used_queue();
        }
    }

    /// Set up AF_UNIX host-IPC listeners from `unix_ipc_port_map`. Cross-platform
    /// (AF_UNIX is available on Unix and Windows via socket2).
    fn create_lisening_ipc_sockets(&self) {
        let start = std::time::Instant::now();
        info!(
            "[VSOCK_TIMING] create_lisening_ipc_sockets() called, {} ports to create",
            self.unix_ipc_port_map.len()
        );

        for (port, (path, do_listen)) in &self.unix_ipc_port_map {
            if !do_listen {
                info!("[VSOCK_TIMING] skipping port {} (do_listen=false)", port);
                continue;
            }
            let proxy_start = std::time::Instant::now();
            let id = ((*port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            info!(
                "[VSOCK_TIMING] creating UnixAcceptorProxy for port {} at {:?}",
                port, path
            );

            let proxy = match UnixAcceptorProxy::new(id, path, *port) {
                Ok(proxy) => {
                    info!(
                        "[VSOCK_TIMING] UnixAcceptorProxy created for port {} in {:?}",
                        port,
                        proxy_start.elapsed()
                    );
                    proxy
                }
                Err(e) => {
                    warn!("Failed to create listening proxy at {path:?}: {e:?}");
                    continue;
                }
            };
            self.proxy_map
                .write()
                .unwrap()
                .insert(id, Mutex::new(Box::new(proxy)));
            if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                self.update_polling(id, proxy.lock().unwrap().poll_handle(), EventSet::IN);
            };
            info!("[VSOCK_TIMING] port {} registered with epoll", port);
        }

        info!(
            "[VSOCK_TIMING] create_lisening_ipc_sockets() completed in {:?}",
            start.elapsed()
        );
    }

    fn work(mut self) {
        let work_start = std::time::Instant::now();
        info!("[VSOCK_TIMING] MuxerThread work() started");

        let mut thread_rng = rng();
        self.create_lisening_ipc_sockets();

        info!(
            "[VSOCK_TIMING] MuxerThread entering epoll loop after {:?}",
            work_start.elapsed()
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        let mut first_event = true;
        let mut event_count: u64 = 0;
        loop {
            match self
                .epoll
                .wait(epoll_events.len(), -1, epoll_events.as_mut_slice())
            {
                Ok(ev_cnt) => {
                    if first_event && ev_cnt > 0 {
                        info!(
                            "[VSOCK_TIMING] MuxerThread received first epoll event(s) after {:?} since work() start",
                            work_start.elapsed()
                        );
                        first_event = false;
                    }
                    event_count += ev_cnt as u64;

                    for ev in &epoll_events[0..ev_cnt] {
                        debug!("Event: ev.data={} ev.fd={:?}", ev.data(), ev.fd());
                        let evset = EventSet::from_bits(ev.events).unwrap();
                        let id = ev.data();

                        // Log connection-related events
                        if event_count <= 10 {
                            info!(
                                "[VSOCK_TIMING] processing event #{}: id={:#x} evset={:?}",
                                event_count, id, evset
                            );
                        }

                        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy_lock| {
                            let mut proxy = proxy_lock.lock().unwrap();
                            proxy.process_event(evset)
                        });

                        if let Some(update) = update {
                            self.process_proxy_update(id, update, &mut thread_rng);
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }
}
