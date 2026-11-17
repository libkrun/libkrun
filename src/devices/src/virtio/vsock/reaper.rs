use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use super::proxy::Proxy;
use crossbeam_channel::{Receiver, RecvTimeoutError};

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;
// Grace period before removing a closed proxy from the map.
// Must be long enough for the guest kernel to process the RST and
// close its end of the connection; too short causes silent drops on
// idle keep-alive connections.
const TIMEOUT: Duration = Duration::from_secs(5);

pub struct ReaperThread {
    receiver: Receiver<u64>,
    proxy_map: ProxyMap,
    released_map: HashMap<u64, Instant>,
}

impl ReaperThread {
    pub fn new(receiver: Receiver<u64>, proxy_map: ProxyMap) -> Self {
        Self {
            receiver,
            proxy_map,
            released_map: HashMap::new(),
        }
    }

    fn check_expiration(&mut self) -> Duration {
        let mut highest_elapsed = Duration::ZERO;
        let mut expired: Vec<u64> = Vec::new();
        let now = Instant::now();

        for (id, exptime) in self.released_map.iter() {
            let elapsed = now.duration_since(*exptime);
            if elapsed >= TIMEOUT {
                expired.push(*id);
            } else if elapsed > highest_elapsed {
                highest_elapsed = elapsed;
            }
        }

        if !expired.is_empty() {
            let mut pmap = self.proxy_map.write().unwrap();
            for id in expired {
                debug!("removing proxy: {id}");
                pmap.remove(&id);
                self.released_map.remove(&id);
            }
            debug!("remainig proxies: {}", pmap.len());
        }

        // Wake when the oldest pending proxy expires. Testing the elapsed time
        // instead of whether any are pending left a batch released within one
        // clock tick (elapsed zero) waiting with no timeout at all: its host
        // sockets stayed open until some later release woke the thread.
        if self.released_map.is_empty() {
            Duration::MAX
        } else {
            TIMEOUT
                .saturating_sub(highest_elapsed)
                .max(Duration::from_millis(1))
        }
    }

    fn work(&mut self) {
        loop {
            let timeout = self.check_expiration();
            match self.receiver.recv_timeout(timeout) {
                Ok(id) => {
                    self.released_map.insert(id, Instant::now());
                }
                Err(RecvTimeoutError::Timeout) => {}
                // Once the muxer is gone there is no future release to wait
                // for. Retaining its map here leaked sockets and spun on the
                // permanently disconnected channel during VMM teardown.
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

    #[test]
    fn proxies_released_in_the_same_instant_still_expire() {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let proxy_map: ProxyMap = Arc::new(RwLock::new(HashMap::new()));
        let mut reaper = ReaperThread::new(receiver, proxy_map);
        let now = Instant::now();
        reaper.released_map.insert(1, now);
        reaper.released_map.insert(2, now);
        drop(sender);
        let timeout = reaper.check_expiration();
        assert!(
            timeout <= TIMEOUT,
            "pending proxies must bound the wait, got {timeout:?}"
        );
    }
}
