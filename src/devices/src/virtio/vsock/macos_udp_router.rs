// SPDX-License-Identifier: Apache-2.0

//! Route shared host UDP ports using Linux socket selection, not Darwin's
//! wildcard insertion order. Queues are bounded and wake the existing muxer.
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::mem::MaybeUninit;

use socket2::Socket;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::{EFD_NONBLOCK, EventFd};

use super::macos_datagram::{canonical_ip, canonical_peer, is_broadcast, receive_with_destination};

pub const ROUTER_EVENT: u64 = u64::MAX - 2;
const DEFAULT_RECEIVE_CAPACITY: usize = 256 * 1024;
// Charge queue metadata even for empty datagrams; this also bounds their count.
const PACKET_OVERHEAD: usize = 512;
// Bound work per peer transition independently of the configured queue size.
const CAPTURE_BATCH: usize = 512;
type Packet = (SocketAddr, Box<[u8]>);
type PortEndpoints = HashMap<u64, Weak<Mutex<Endpoint>>>;

pub struct Endpoint {
    pub id: u64,
    pub bound: SocketAddr,
    pub peer: Option<SocketAddr>,
    pub selected: Option<SocketAddr>,
    pub only_v6: bool,
    pub reuse_port: bool,
    pub order: u64,
    pub socket: Weak<Socket>,
    packets: VecDeque<Packet>,
    bytes: usize,
    receive_capacity: usize,
}

impl Endpoint {
    pub fn new(id: u64, bound: SocketAddr, only_v6: bool) -> Self {
        Self {
            id,
            bound,
            peer: None,
            selected: None,
            only_v6,
            reuse_port: false,
            order: 0,
            socket: Weak::new(),
            packets: VecDeque::new(),
            bytes: 0,
            receive_capacity: DEFAULT_RECEIVE_CAPACITY,
        }
    }

    pub fn pop(&mut self) -> Option<Packet> {
        let packet = self.packets.pop_front()?;
        self.bytes -= packet.1.len() + PACKET_OVERHEAD;
        self.trim_reservation();
        Some(packet)
    }

    pub fn has_packets(&self) -> bool {
        !self.packets.is_empty()
    }

    fn admits(&self, length: usize) -> bool {
        length <= super::host_datagram::MAX_DATAGRAM
            && (self.packets.is_empty()
                || length + PACKET_OVERHEAD <= self.receive_capacity.saturating_sub(self.bytes))
    }

    fn trim_reservation(&mut self) {
        // Preserve accepted packets on shrink, then release excess deque
        // storage once draining brings the queue under the new budget.
        if self.bytes <= self.receive_capacity
            && self.packets.capacity() > 2 * (self.receive_capacity / PACKET_OVERHEAD).max(1)
        {
            self.packets.shrink_to_fit();
        }
    }

    fn score(&self, sender: SocketAddr, destination: IpAddr) -> Option<u8> {
        let destination = canonical_ip(destination);
        let bound = canonical_ip(self.bound.ip());
        if self.only_v6 && destination.is_ipv4() {
            return None;
        }
        if !bound.is_unspecified() && bound != destination {
            return None;
        }
        if self
            .peer
            .is_some_and(|peer| canonical_peer(peer) != canonical_peer(sender))
        {
            return None;
        }
        if self
            .selected
            .is_some_and(|selected| canonical_ip(selected.ip()) != destination)
        {
            return None;
        }
        Some(
            u8::from(self.bound.is_ipv4() && destination.is_ipv4())
                + 4 * u8::from(!bound.is_unspecified() || self.selected.is_some())
                + 4 * u8::from(self.peer.is_some()),
        )
    }
}

pub struct DatagramRouter {
    ports: Mutex<HashMap<u16, PortEndpoints>>,
    ready: Mutex<HashSet<u64>>,
    wake: EventFd,
    sequence: AtomicU64,
    read_gate: Mutex<()>,
}

impl DatagramRouter {
    pub fn new(epoll: &Epoll) -> io::Result<Self> {
        let wake = EventFd::new(EFD_NONBLOCK)?;
        epoll.ctl(
            ControlOperation::Add,
            wake.as_raw_fd(),
            &EpollEvent::new(EventSet::IN, ROUTER_EVENT),
        )?;
        Ok(Self {
            ports: Mutex::new(HashMap::new()),
            ready: Mutex::new(HashSet::new()),
            wake,
            sequence: AtomicU64::new(1),
            read_gate: Mutex::new(()),
        })
    }

    pub fn set_receive_capacity(&self, endpoint: &Arc<Mutex<Endpoint>>, capacity: usize) {
        // Serialize with capture's peek/check/consume sequence so a concurrent
        // shrink cannot discard a datagram during a peer transition.
        let _gate = self.read_gate.lock().unwrap();
        let mut entry = endpoint.lock().unwrap();
        entry.receive_capacity = capacity;
        entry.trim_reservation();
    }

    pub fn next_order(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    pub fn register(&self, endpoint: &Arc<Mutex<Endpoint>>) {
        let entry = endpoint.lock().unwrap();
        self.ports
            .lock()
            .unwrap()
            .entry(entry.bound.port())
            .or_default()
            .insert(entry.id, Arc::downgrade(endpoint));
    }

    pub fn unregister(&self, id: u64, port: u16) {
        let mut ports = self.ports.lock().unwrap();
        if let Some(entries) = ports.get_mut(&port) {
            entries.remove(&id);
            if entries.is_empty() {
                ports.remove(&port);
            }
        }
        self.ready.lock().unwrap().remove(&id);
    }

    pub fn take_ready(&self) -> Vec<u64> {
        let _ = self.wake.read();
        self.ready.lock().unwrap().drain().collect()
    }

    fn candidates(&self, port: u16) -> Vec<Arc<Mutex<Endpoint>>> {
        self.ports
            .lock()
            .unwrap()
            .get(&port)
            .map(|entries| entries.values().filter_map(Weak::upgrade).collect())
            .unwrap_or_default()
    }

    fn recipient(
        &self,
        source: u64,
        port: u16,
        sender: SocketAddr,
        destination: Option<IpAddr>,
    ) -> Option<Arc<Mutex<Endpoint>>> {
        let entries = self.candidates(port);
        // Darwin already fans out broadcast and multicast. Preserve each
        // native recipient rather than multiplying those copies again.
        let native_recipient = destination.is_none_or(|ip| {
            ip.is_multicast()
                || matches!(canonical_ip(ip), IpAddr::V4(ip) if is_broadcast(ip).unwrap_or(false))
        });
        let mut candidates = Vec::new();
        for endpoint in entries {
            let entry = endpoint.lock().unwrap();
            if entry.bound.port() != port {
                continue;
            }
            if native_recipient {
                if entry.id == source
                    && destination.is_none_or(|ip| entry.score(sender, ip).is_some())
                {
                    return Some(endpoint.clone());
                }
            } else if let Some(score) = entry.score(sender, destination.unwrap()) {
                candidates.push((score, entry.order, entry.reuse_port, endpoint.clone()));
            }
        }
        let best = candidates.iter().map(|candidate| candidate.0).max()?;
        candidates.retain(|candidate| candidate.0 == best);
        candidates.sort_unstable_by_key(|candidate| candidate.1);
        let chosen = if candidates.len() > 1 && candidates.iter().all(|candidate| candidate.2) {
            let mut hash = DefaultHasher::new();
            canonical_peer(sender).hash(&mut hash);
            canonical_ip(destination.unwrap()).hash(&mut hash);
            port.hash(&mut hash);
            hash.finish() as usize % candidates.len()
        } else {
            candidates.len() - 1
        };
        Some(candidates[chosen].3.clone())
    }

    fn wake_recipient(&self, id: u64) {
        let mut ready = self.ready.lock().unwrap();
        let notify = ready.is_empty();
        ready.insert(id);
        if notify {
            let _ = self.wake.write(1);
        }
    }

    fn enqueue(
        &self,
        recipient: &Arc<Mutex<Endpoint>>,
        sender: SocketAddr,
        payload: &[u8],
    ) -> bool {
        let mut entry = recipient.lock().unwrap();
        if !entry.admits(payload.len()) {
            return false;
        }
        entry.packets.push_back((sender, payload.into()));
        entry.bytes += payload.len() + PACKET_OVERHEAD;
        let id = entry.id;
        drop(entry);
        self.wake_recipient(id);
        true
    }

    /// True means consume locally; false means forwarded or dropped at capacity.
    pub fn route(
        &self,
        source: u64,
        port: u16,
        sender: SocketAddr,
        destination: Option<IpAddr>,
        payload: &[u8],
    ) -> bool {
        // Most ports have one owner: no packet allocation or routing scan.
        if self
            .ports
            .lock()
            .unwrap()
            .get(&port)
            .is_some_and(|entries| entries.len() == 1 && entries.contains_key(&source))
        {
            return true;
        }
        let Some(recipient) = self.recipient(source, port, sender, destination) else {
            return false;
        };
        if recipient.lock().unwrap().id == source {
            return true;
        }
        self.enqueue(&recipient, sender, payload);
        false
    }

    pub fn receive(
        &self,
        source: u64,
        port: u16,
        socket: &Socket,
        bytes: &mut [MaybeUninit<u8>],
    ) -> io::Result<Option<(usize, SocketAddr, Option<IpAddr>)>> {
        let _gate = self.read_gate.lock().unwrap();
        let (length, sender, destination) = receive_with_destination(socket, bytes, 0)?;
        // SAFETY: recvmsg initialized precisely this returned prefix.
        let payload = unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), length) };
        Ok(self
            .route(source, port, sender, destination, payload)
            .then_some((length, sender, destination)))
    }

    /// Assign already-arrived packets before a peer policy changes, including
    /// packets Darwin put on another FD sharing this port. A full queue leaves
    /// the native packet and the old peer policy intact for a bounded retry.
    pub fn capture_port(&self, port: u16) -> io::Result<()> {
        let _gate = self.read_gate.lock().unwrap();
        let sockets: Vec<_> = self
            .candidates(port)
            .into_iter()
            .filter_map(|endpoint| {
                let entry = endpoint.lock().unwrap();
                entry.socket.upgrade().map(|socket| (entry.id, socket))
            })
            .collect();
        let mut remaining = CAPTURE_BATCH;
        let mut bytes = vec![MaybeUninit::new(0); super::host_datagram::MAX_DATAGRAM];
        for (source, socket) in sockets {
            loop {
                let (length, sender, destination) =
                    match receive_with_destination(&socket, &mut bytes, libc::MSG_PEEK) {
                        Ok(packet) => packet,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    };
                if remaining == 0 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let recipient = self.recipient(source, port, sender, destination);
                if let Some(endpoint) = &recipient {
                    let entry = endpoint.lock().unwrap();
                    if !entry.admits(length) {
                        return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
                    }
                }
                let (length, sender, _) = receive_with_destination(&socket, &mut bytes, 0)?;
                remaining -= 1;
                if let Some(endpoint) = recipient {
                    // SAFETY: the consuming recvmsg initialized this prefix.
                    let payload =
                        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), length) };
                    self.enqueue(&endpoint, sender, payload);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(router: &DatagramRouter, id: u64, address: &str) -> Arc<Mutex<Endpoint>> {
        let mut entry = Endpoint::new(id, address.parse().unwrap(), false);
        entry.order = router.next_order();
        let endpoint = Arc::new(Mutex::new(entry));
        router.register(&endpoint);
        endpoint
    }

    #[test]
    fn latest_wildcard_receives_until_close_and_specific_peers_take_priority() {
        let epoll = Epoll::new().unwrap();
        let router = DatagramRouter::new(&epoll).unwrap();
        let first = endpoint(&router, 1, "0.0.0.0:5000");
        let second = endpoint(&router, 2, "0.0.0.0:5000");
        let sender: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let destination = Some("127.0.0.1".parse().unwrap());
        assert!(!router.route(1, 5000, sender, destination, b"latest"));
        assert_eq!(router.take_ready(), [2]);
        assert_eq!(second.lock().unwrap().pop().unwrap().1.as_ref(), b"latest");
        assert!(!first.lock().unwrap().has_packets());
        {
            let mut entry = first.lock().unwrap();
            entry.peer = Some(sender);
            entry.selected = Some("127.0.0.1:5000".parse().unwrap());
        }
        assert!(!router.route(2, 5000, sender, destination, b"connected"));
        assert_eq!(
            first.lock().unwrap().pop().unwrap().1.as_ref(),
            b"connected"
        );
        let alternate: SocketAddr = "127.0.0.1:4001".parse().unwrap();
        assert!(!router.route(1, 5000, alternate, destination, b"other-peer"));
        assert_eq!(
            second.lock().unwrap().pop().unwrap().1.as_ref(),
            b"other-peer"
        );
        router.unregister(2, 5000);
        first.lock().unwrap().peer = None;
        assert!(router.route(1, 5000, alternate, destination, b"after-close"));
    }

    #[test]
    fn redirected_queues_bound_empty_and_full_datagrams_and_coalesce_wakeups() {
        for size in [0, 65_507] {
            let mut epoll = Epoll::new().unwrap();
            let router = DatagramRouter::new(&epoll).unwrap();
            let _first = endpoint(&router, 1, "[::]:5000");
            let second = endpoint(&router, 2, "[::]:5000");
            let payload = vec![71; size];
            for _ in 0..1024 {
                assert!(!router.route(
                    1,
                    5000,
                    "[::1]:4000".parse().unwrap(),
                    Some("::1".parse().unwrap()),
                    &payload
                ));
            }
            let mut events = [EpollEvent::default(); 1];
            assert_eq!(epoll.wait(1, 100, &mut events).unwrap(), 1);
            assert_eq!(router.take_ready(), [2]);
            assert_eq!(epoll.wait(1, 0, &mut events).unwrap(), 0);
            let mut entry = second.lock().unwrap();
            assert_eq!(entry.packets.len(), if size == 0 { 512 } else { 3 });
            assert!(entry.bytes <= DEFAULT_RECEIVE_CAPACITY);
            while let Some((sender, data)) = entry.pop() {
                assert_eq!(sender, "[::1]:4000".parse().unwrap());
                assert_eq!(data.as_ref(), payload);
            }
            assert_eq!(entry.bytes, 0);
        }
    }

    #[test]
    fn receive_budgets_cover_empty_packets_growth_shrink_and_oversized_first_packet() {
        for size in [0, 1024] {
            let router = DatagramRouter::new(&Epoll::new().unwrap()).unwrap();
            let recipient = endpoint(&router, 1, "[::]:5000");
            let sender = "[::1]:4000".parse().unwrap();
            let payload = vec![73; size];
            router.set_receive_capacity(&recipient, 8192);
            let small = 8192 / (size + PACKET_OVERHEAD);
            for _ in 0..small {
                assert!(router.enqueue(&recipient, sender, &payload));
            }
            assert!(!router.enqueue(&recipient, sender, &payload));
            router.set_receive_capacity(&recipient, 2 * 1024 * 1024);
            for _ in small..1024 {
                assert!(router.enqueue(&recipient, sender, &payload));
            }
            router.set_receive_capacity(&recipient, 1024);
            assert!(!router.enqueue(&recipient, sender, &payload));
            let mut entry = recipient.lock().unwrap();
            for _ in 0..1024 {
                let (source, received) = entry.pop().unwrap();
                assert_eq!(source, sender);
                assert_eq!(received.as_ref(), payload);
            }
            assert_eq!(entry.bytes, 0);
            assert!(
                entry.packets.capacity() <= 4,
                "shrink must release spare metadata storage"
            );
            drop(entry);
            // Linux permits one datagram bigger than the receive budget when
            // the queue is empty. It still blocks all further arrivals.
            let large = vec![89; 65507];
            assert!(router.enqueue(&recipient, sender, &large));
            assert!(!router.enqueue(&recipient, sender, &[]));
            assert_eq!(recipient.lock().unwrap().pop().unwrap().1.as_ref(), large);
            assert!(router.enqueue(&recipient, sender, &[]));
        }
    }

    #[test]
    fn reuseport_keeps_each_flow_stable_while_distributing_distinct_flows() {
        let router = DatagramRouter::new(&Epoll::new().unwrap()).unwrap();
        let first = endpoint(&router, 1, "0.0.0.0:5000");
        let second = endpoint(&router, 2, "0.0.0.0:5000");
        first.lock().unwrap().reuse_port = true;
        second.lock().unwrap().reuse_port = true;
        let mut selected = HashSet::new();
        for port in 4000..4100 {
            let sender = SocketAddr::from(([127, 0, 0, 1], port));
            let mut choices = Vec::new();
            for _ in 0..3 {
                let direct =
                    router.route(1, 5000, sender, Some("127.0.0.1".parse().unwrap()), b"flow");
                choices.push(direct);
                if !direct {
                    assert_eq!(second.lock().unwrap().pop().unwrap().0, sender);
                }
            }
            assert!(choices.iter().all(|choice| *choice == choices[0]));
            selected.insert(choices[0]);
        }
        assert_eq!(selected.len(), 2);
    }
}
