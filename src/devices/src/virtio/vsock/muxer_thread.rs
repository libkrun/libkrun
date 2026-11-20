use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
#[cfg(windows)]
use utils::windows::{AsRawFd, RawFd};

use super::super::Queue as VirtQueue;
use super::muxer::{MuxerRx, ProxyMap, push_packet};
use super::muxer_rxq::{MuxerRxQ, rx_to_pkt};
use super::packet::VsockPacket;
use super::proxy::{NewProxyType, Proxy, ProxyRemoval, ProxyUpdate};
use super::tsi_stream::TsiStreamProxy;

use crate::virtio::InterruptTransport;
use crate::virtio::vsock::defs;
use crate::virtio::vsock::unix_proxy::{UnixAcceptorProxy, UnixProxy};
use crossbeam_channel::Sender;
use rand::{RngExt, rng, rngs::ThreadRng};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

/// Reserved epoll data marking the guest-RX-available notification rather
/// than a proxy id. No proxy can use it: the low word holds a local port
/// below `u32::MAX` and guest socket ports never reach `u32::MAX`.
const RX_AVAILABLE_ID: u64 = u64::MAX;

pub struct MuxerThread {
    cid: u64,
    pub epoll: Epoll,
    rxq: Arc<Mutex<MuxerRxQ>>,
    proxy_map: ProxyMap,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
    reaper_sender: Sender<u64>,
    unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
    rx_available_evt: EventFd,
    starved: Mutex<HashSet<u64>>,
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
        rx_available_evt: EventFd,
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
            rx_available_evt,
            starved: Mutex::new(HashSet::new()),
        }
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("vsock muxer".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn drain_rxq(&self) -> bool {
        let mut queue = self.queue.lock().unwrap();
        let mut rxq = self.rxq.lock().unwrap();
        let mut drained = false;

        while !rxq.is_empty() {
            let Some(head) = queue.pop(&self.mem) else {
                break;
            };
            let used_len = if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
                rx_to_pkt(self.cid, rxq.pop().unwrap(), &mut pkt);
                pkt.finish_rx().unwrap_or(0)
            } else {
                0
            };
            match queue.add_used(&self.mem, head.index, used_len) {
                Ok(()) => drained = true,
                Err(e) => error!("failed to add used elements to the queue: {e:?}"),
            }
        }

        drained
    }

    fn send_credit_request(&self, credit_rx: MuxerRx) {
        debug!("send_credit_request");
        push_packet(self.cid, credit_rx, &self.rxq, &self.queue, &self.mem);
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

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate, thread_rng: &mut ThreadRng) {
        if let Some(credit_rx) = update.push_credit_req {
            debug!("send_credit_request");
            self.send_credit_request(credit_rx);
        }

        if update.rx_starved {
            self.starved.lock().unwrap().insert(id);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                warn!("immediately removing proxy: {id}");
                self.proxy_map.write().unwrap().remove(&id);
                self.starved.lock().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                warn!("deferring proxy removal: {id}");
                if self.reaper_sender.send(id).is_err() {
                    self.proxy_map.write().unwrap().remove(&id);
                    self.starved.lock().unwrap().remove(&id);
                }
            }
        }

        let mut should_signal = update.signal_queue;

        if let Some((peer_port, accept_fd, family, proxy_type)) = update.new_proxy {
            let local_port: u32 = thread_rng.random_range(1024..u32::MAX);
            let new_id: u64 = ((peer_port as u64) << 32) | (local_port as u64);
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
                )),
            };
            self.proxy_map
                .write()
                .unwrap()
                .insert(new_id, Mutex::new(new_proxy));
            let announced = self
                .proxy_map
                .read()
                .unwrap()
                .get(&new_id)
                .is_some_and(|proxy| proxy.lock().unwrap().push_op_request());
            if !announced {
                // Without the request the guest can never learn of the
                // connection, so nothing would release the proxy or its
                // descriptor; close the accepted socket instead of holding
                // it until teardown.
                self.proxy_map.write().unwrap().remove(&new_id);
                warn!("dropping accepted connection {new_id}: guest RX queue is full");
            } else {
                should_signal = true;
            }
        }

        if should_signal {
            debug!("signal IRQ");
            self.interrupt.signal_used_queue();
        }
    }

    fn create_listening_ipc_sockets(&self) {
        for (port, (path, do_listen)) in &self.unix_ipc_port_map {
            if !do_listen {
                continue;
            }
            let id = ((*port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            let proxy = match UnixAcceptorProxy::new(id, path, *port) {
                Ok(proxy) => proxy,
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
                self.update_polling(id, proxy.lock().unwrap().as_raw_fd(), EventSet::IN);
            };
        }
    }

    fn resume_starved_proxies(&self) {
        let starved: Vec<u64> = self.starved.lock().unwrap().drain().collect();
        let proxies = self.proxy_map.read().unwrap();
        for id in starved {
            let Some(proxy) = proxies.get(&id) else {
                // A proxy removed through the reaper can leave its id behind;
                // the entry dies here.
                continue;
            };
            let mut proxy = proxy.lock().unwrap();
            if let Some((id, fd, events)) = proxy.resume_rx() {
                self.update_polling(id, fd, events);
            }
        }
    }

    fn work(mut self) {
        let mut thread_rng = rng();
        self.create_listening_ipc_sockets();
        if let Err(e) = self.epoll.ctl(
            ControlOperation::Add,
            self.rx_available_evt.as_raw_fd(),
            &EpollEvent::new(EventSet::IN, RX_AVAILABLE_ID),
        ) {
            error!("failed to register the rx-available event: {e:?}");
        }
        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            if self.drain_rxq() {
                self.interrupt.signal_used_queue();
            }

            match self
                .epoll
                .wait(epoll_events.len(), -1, epoll_events.as_mut_slice())
            {
                Ok(ev_cnt) => {
                    for ev in &epoll_events[0..ev_cnt] {
                        debug!("Event: ev.data={} ev.fd={:?}", ev.data(), ev.fd());
                        let id = ev.data();

                        if id == RX_AVAILABLE_ID {
                            let _ = self.rx_available_evt.read();
                            self.resume_starved_proxies();
                            continue;
                        }

                        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy_lock| {
                            let mut proxy = proxy_lock.lock().unwrap();
                            #[cfg(unix)]
                            let mut update =
                                proxy.process_event(EventSet::from_bits(ev.events).unwrap());
                            #[cfg(windows)]
                            let mut update = proxy.process_windows_event(ev);
                            // Credit updates must not rearm polling before this
                            // event's decision to stop polling has been applied.
                            if let Some((id, fd, events)) = update.polling.take() {
                                self.update_polling(id, fd, events);
                            }
                            update
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
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    mod reverse_proxy_announcement {
        use std::io::Read;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        use crossbeam_channel::unbounded;
        use nix::sys::socket::AddressFamily;
        use vm_memory::GuestAddress;

        use super::super::*;
        use crate::Error;
        use crate::virtio::device::{InterruptHandler, InterruptType};

        struct NoopInterrupt;

        impl InterruptHandler for NoopInterrupt {
            fn try_signal(&self, _interrupt: InterruptType) -> Result<(), Error> {
                Ok(())
            }
        }

        fn muxer_thread(rxq: Arc<Mutex<MuxerRxQ>>, proxies: ProxyMap) -> MuxerThread {
            let (reaper_sender, _) = unbounded();
            MuxerThread::new(
                3,
                Epoll::new().unwrap(),
                rxq,
                proxies,
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap(),
                Arc::new(Mutex::new(VirtQueue::new(256))),
                InterruptTransport::from_handler(Arc::new(NoopInterrupt)),
                reaper_sender,
                HashMap::new(),
                EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            )
        }

        fn accept_update(fd: OwnedFd) -> ProxyUpdate {
            ProxyUpdate {
                new_proxy: Some((5000, fd, AddressFamily::Unix, NewProxyType::Unix)),
                ..Default::default()
            }
        }

        #[test]
        fn undeliverable_op_request_tears_down_the_reverse_proxy() {
            // No guest RX buffers and a full rxq leave no way to deliver or
            // queue the announcement.
            let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));
            for _ in 0..defs::MUXER_RXQ_SIZE {
                assert!(rxq.lock().unwrap().push(MuxerRx::Reset {
                    local_port: 1,
                    peer_port: 2
                }));
            }
            let proxies: ProxyMap = Arc::new(std::sync::RwLock::new(HashMap::new()));
            let (accepted, mut peer) = UnixStream::pair().unwrap();
            muxer_thread(rxq.clone(), proxies.clone()).process_proxy_update(
                1,
                accept_update(accepted.into()),
                &mut rng(),
            );

            assert!(proxies.read().unwrap().is_empty());
            // Dropping the proxy closed the accepted socket.
            peer.set_nonblocking(true).unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);

            // With room to queue, the connection is announced and kept.
            let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));
            let proxies: ProxyMap = Arc::new(std::sync::RwLock::new(HashMap::new()));
            let (accepted, mut peer) = UnixStream::pair().unwrap();
            muxer_thread(rxq.clone(), proxies.clone()).process_proxy_update(
                1,
                accept_update(accepted.into()),
                &mut rng(),
            );

            assert_eq!(proxies.read().unwrap().len(), 1);
            assert!(matches!(
                rxq.lock().unwrap().pop(),
                Some(MuxerRx::OpRequest { .. })
            ));
            peer.set_nonblocking(true).unwrap();
            assert_eq!(
                peer.read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
}
