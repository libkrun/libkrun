use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use super::muxer::{ProxyHandle, ProxyMap};
use super::proxy::{Proxy, ProxyRemoval};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};

// Allow the guest to consume the reset before removing a closed proxy.
const TIMEOUT: Duration = Duration::from_secs(5);

type WeakProxy = Weak<Mutex<Box<dyn Proxy>>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReapKind {
    Closed,
    Drain,
}

pub struct ReapRequest {
    id: u64,
    proxy: WeakProxy,
    kind: ReapKind,
    deadline: Instant,
}

/// Retain the operation's original owner, not a fresh lookup by reusable ports.
/// This also prevents a late immediate removal from deleting a replacement.
pub(super) fn apply_removal(
    proxies: &ProxyMap,
    sender: Option<&Sender<ReapRequest>>,
    id: u64,
    source: &ProxyHandle,
    removal: ProxyRemoval,
) {
    let kind = match removal {
        ProxyRemoval::Keep => return,
        ProxyRemoval::Immediate => None,
        ProxyRemoval::Deferred => Some(ReapKind::Closed),
        ProxyRemoval::Drain => Some(ReapKind::Drain),
    };
    if let Some(kind) = kind {
        let deadline = match kind {
            ReapKind::Closed => Some(Instant::now() + TIMEOUT),
            ReapKind::Drain => source.lock().unwrap().drain_deadline(),
        };
        if let (Some(sender), Some(deadline)) = (sender, deadline)
            && sender
                .send(ReapRequest {
                    id,
                    proxy: Arc::downgrade(source),
                    kind,
                    deadline,
                })
                .is_ok()
        {
            return;
        }
    }
    let mut proxies = proxies.write().unwrap();
    if proxies
        .get(&id)
        .is_some_and(|live| Arc::ptr_eq(live, source))
    {
        proxies.remove(&id);
    }
}

pub struct ReaperThread {
    receiver: Receiver<ReapRequest>,
    proxy_map: ProxyMap,
    released_map: HashMap<u64, ReapRequest>,
}

impl ReaperThread {
    pub fn new(receiver: Receiver<ReapRequest>, proxy_map: ProxyMap) -> Self {
        Self {
            receiver,
            proxy_map,
            released_map: HashMap::new(),
        }
    }

    fn register(&mut self, request: ReapRequest) {
        let proxies = self.proxy_map.read().unwrap();
        let Some(live) = proxies.get(&request.id) else {
            return;
        };
        if !request.proxy.ptr_eq(&Arc::downgrade(live)) {
            return;
        }
        if let Some(pending) = self.released_map.get_mut(&request.id)
            && pending.proxy.ptr_eq(&request.proxy)
        {
            // Duplicate releases never restart a timer. A terminal failure can
            // shorten a drain to the closed-proxy grace period, not extend it.
            pending.deadline = pending.deadline.min(request.deadline);
            if request.kind == ReapKind::Closed {
                pending.kind = ReapKind::Closed;
            }
        } else {
            self.released_map.insert(request.id, request);
        }
    }

    fn check_expiration(&mut self, now: Instant) -> Duration {
        let mut next = Duration::MAX;
        self.released_map.retain(|id, pending| {
            // Drains usually finish promptly. Do not accumulate dead timer
            // entries for two minutes under a stream of short connections.
            if pending.proxy.strong_count() == 0 {
                return false;
            }
            if pending.deadline <= now {
                let mut proxies = self.proxy_map.write().unwrap();
                let Some(live) = proxies.get(id) else {
                    return false;
                };
                if !pending.proxy.ptr_eq(&Arc::downgrade(live)) {
                    return false;
                }
                if pending.kind == ReapKind::Drain
                    && let Some(deadline) = live.lock().unwrap().drain_deadline()
                    && deadline > now
                {
                    // Progress is recorded under the proxy lock by actual
                    // writes. No channel traffic or periodic polling required.
                    pending.deadline = deadline;
                } else {
                    // A stalled stream's Drop uses an abortive close: never
                    // report clean EOF for accepted output we could not deliver.
                    proxies.remove(id);
                    return false;
                }
            }
            next = next.min(pending.deadline.saturating_duration_since(now));
            true
        });
        next
    }

    fn work(&mut self) {
        loop {
            let timeout = self.check_expiration(Instant::now());
            match self.receiver.recv_timeout(timeout) {
                Ok(request) => self.register(request),
                Err(RecvTimeoutError::Timeout) => {}
                // Release sockets and stop on VMM teardown, without spinning.
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    pub fn run(mut self) {
        thread::Builder::new()
            .name("vsock reaper".into())
            .spawn(move || self.work())
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    #[test]
    fn dropping_the_muxer_releases_the_reaper_and_its_proxy_map() {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::new()));
        let weak = Arc::downgrade(&map);
        let (finished, done) = crossbeam_channel::bounded(1);
        let worker = thread::spawn(move || {
            let mut reaper = ReaperThread::new(receiver, map);
            reaper.work();
            drop(reaper);
            finished.send(()).unwrap();
        });
        drop(sender);
        done.recv_timeout(Duration::from_secs(2))
            .expect("reaper retained a destroyed muxer");
        worker.join().unwrap();
        assert!(weak.upgrade().is_none());
    }

    use super::super::packet::{
        TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket,
    };
    use super::super::proxy::{ProxyRawHandle, ProxyStatus, ProxyUpdate};
    use utils::epoll::EventSet;

    struct TimedProxy(Arc<Mutex<Option<Instant>>>);
    impl Proxy for TimedProxy {
        fn drain_deadline(&self) -> Option<Instant> {
            *self.0.lock().unwrap()
        }
        fn poll_handle(&self) -> ProxyRawHandle {
            unreachable!()
        }
        fn id(&self) -> u64 {
            1
        }
        fn status(&self) -> ProxyStatus {
            ProxyStatus::Connected
        }
        fn connect(&mut self, _: &VsockPacket, _: TsiConnectReq) -> ProxyUpdate {
            unreachable!()
        }
        fn getpeername(&mut self, _: &VsockPacket) {
            unreachable!()
        }
        fn sendmsg(&mut self, _: &VsockPacket) -> ProxyUpdate {
            unreachable!()
        }
        fn sendto_addr(&mut self, _: TsiSendtoAddr) -> ProxyUpdate {
            unreachable!()
        }
        fn listen(
            &mut self,
            _: &VsockPacket,
            _: TsiListenReq,
            _: &Option<HashMap<u16, u16>>,
        ) -> ProxyUpdate {
            unreachable!()
        }
        fn accept(&mut self, _: u32, _: TsiAcceptReq) -> ProxyUpdate {
            unreachable!()
        }
        fn update_peer_credit(&mut self, _: &VsockPacket) -> ProxyUpdate {
            unreachable!()
        }
        fn process_op_response(&mut self, _: &VsockPacket) -> ProxyUpdate {
            unreachable!()
        }
        fn release(&mut self) -> ProxyUpdate {
            unreachable!()
        }
        fn process_event(&mut self, _: EventSet) -> ProxyUpdate {
            unreachable!()
        }
    }

    fn proxy(deadline: Option<Instant>) -> (ProxyHandle, Arc<Mutex<Option<Instant>>>) {
        let clock = Arc::new(Mutex::new(deadline));
        (
            Arc::new(Mutex::new(Box::new(TimedProxy(clock.clone())))),
            clock,
        )
    }

    fn request(source: &ProxyHandle, deadline: Instant, kind: ReapKind) -> ReapRequest {
        ReapRequest {
            id: 1,
            proxy: Arc::downgrade(source),
            deadline,
            kind,
        }
    }

    #[test]
    fn idle_stream_expires_at_boundary_and_scheduling_does_not_retain_it() {
        let (_sender, receiver) = crossbeam_channel::unbounded();
        let now = Instant::now();
        let deadline = now + Duration::from_secs(120);
        let (source, _) = proxy(Some(deadline));
        let weak = Arc::downgrade(&source);
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::from([(1, source.clone())])));
        let mut reaper = ReaperThread::new(receiver, map.clone());
        reaper.register(request(&source, deadline, ReapKind::Drain));
        drop(source);
        assert_eq!(reaper.check_expiration(now), Duration::from_secs(120));
        assert_eq!(
            reaper.check_expiration(deadline - Duration::from_nanos(1)),
            Duration::from_nanos(1)
        );
        assert_eq!(map.read().unwrap().len(), 1);
        assert_eq!(reaper.check_expiration(deadline), Duration::MAX);
        assert!(map.read().unwrap().is_empty());
        assert!(
            weak.upgrade().is_none(),
            "scheduled request retained socket ownership"
        );
    }

    #[test]
    fn completed_drain_does_not_keep_a_timer_or_socket_alive() {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let now = Instant::now();
        let (source, _) = proxy(Some(now + Duration::from_secs(120)));
        let weak = Arc::downgrade(&source);
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::from([(1, source.clone())])));
        let mut reaper = ReaperThread::new(receiver, map.clone());
        apply_removal(&map, Some(&sender), 1, &source, ProxyRemoval::Drain);
        reaper.register(reaper.receiver.try_recv().unwrap());
        apply_removal(&map, Some(&sender), 1, &source, ProxyRemoval::Immediate);
        drop(source);
        assert!(weak.upgrade().is_none());
        assert_eq!(reaper.check_expiration(now), Duration::MAX);
        assert!(reaper.released_map.is_empty());
    }

    #[test]
    fn progress_extends_drain_but_duplicate_release_does_not() {
        let (_sender, receiver) = crossbeam_channel::unbounded();
        let deadline = Instant::now() + Duration::from_secs(120);
        let (source, clock) = proxy(Some(deadline));
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::from([(1, source.clone())])));
        let mut reaper = ReaperThread::new(receiver, map.clone());
        reaper.register(request(&source, deadline, ReapKind::Drain));
        let later = deadline + Duration::from_secs(100);
        *clock.lock().unwrap() = Some(later);
        reaper.register(request(&source, later, ReapKind::Drain));
        assert_eq!(reaper.released_map[&1].deadline, deadline);
        assert_eq!(reaper.check_expiration(deadline), Duration::from_secs(100));
        assert_eq!(reaper.check_expiration(later), Duration::MAX);
        assert!(map.read().unwrap().is_empty());
    }

    #[test]
    fn stale_timer_and_late_release_cannot_reap_reused_ports() {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let now = Instant::now();
        let (old, _) = proxy(None);
        let (new, _) = proxy(None);
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::from([(1, old.clone())])));
        let mut reaper = ReaperThread::new(receiver, map.clone());
        reaper.register(request(&old, now, ReapKind::Closed));
        map.write().unwrap().insert(1, new.clone());
        assert_eq!(reaper.check_expiration(now), Duration::MAX);
        assert!(Arc::ptr_eq(&map.read().unwrap()[&1], &new));
        // A release generated by the old operation must retain the old identity
        // even when it is first scheduled after replacement, not just at expiry.
        apply_removal(&map, Some(&sender), 1, &old, ProxyRemoval::Deferred);
        reaper.register(reaper.receiver.try_recv().unwrap());
        assert!(reaper.released_map.is_empty());
        for removal in [
            ProxyRemoval::Immediate,
            ProxyRemoval::Deferred,
            ProxyRemoval::Drain,
        ] {
            apply_removal(&map, None, 1, &old, removal);
            assert!(Arc::ptr_eq(&map.read().unwrap()[&1], &new));
        }
        reaper.register(request(&new, now + TIMEOUT, ReapKind::Closed));
        reaper.register(request(&old, now, ReapKind::Closed));
        assert_eq!(reaper.check_expiration(now), TIMEOUT);
        assert_eq!(reaper.check_expiration(now + TIMEOUT), Duration::MAX);
        assert!(map.read().unwrap().is_empty());
    }

    #[test]
    fn failure_shortens_drain_and_duplicate_close_does_not_extend_grace() {
        let (_sender, receiver) = crossbeam_channel::unbounded();
        let now = Instant::now();
        let (source, _) = proxy(Some(now + Duration::from_secs(120)));
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::from([(1, source.clone())])));
        let mut reaper = ReaperThread::new(receiver, map.clone());
        reaper.register(request(
            &source,
            now + Duration::from_secs(120),
            ReapKind::Drain,
        ));
        reaper.register(request(&source, now + TIMEOUT, ReapKind::Closed));
        reaper.register(request(&source, now + TIMEOUT * 2, ReapKind::Closed));
        reaper.register(request(
            &source,
            now + Duration::from_secs(120),
            ReapKind::Drain,
        ));
        assert_eq!(reaper.check_expiration(now), TIMEOUT);
        assert_eq!(reaper.check_expiration(now + TIMEOUT), Duration::MAX);
        assert!(map.read().unwrap().is_empty());
    }
}
