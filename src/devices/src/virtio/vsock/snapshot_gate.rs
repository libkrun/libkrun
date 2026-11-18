use std::sync::{Condvar, Mutex, MutexGuard};

#[derive(Default)]
struct GateState {
    paused: bool,
    /// RX is held until a restored guest has handled a transport reset.
    transport_reset: bool,
    reset_generation: u64,
    active: usize,
}

/// Stops detached vsock RX producers while snapshot state and guest memory are
/// captured. Entering the gate is intentionally cheap outside snapshotting.
#[derive(Default)]
pub(crate) struct SnapshotGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl SnapshotGate {
    pub(super) fn enter(&self) -> SnapshotActivity<'_> {
        let mut state = self.state.lock().unwrap();
        while state.paused || state.transport_reset {
            state = self.changed.wait(state).unwrap();
        }
        state.active += 1;
        SnapshotActivity { gate: self }
    }

    /// A producer holding a proxy lock must never wait for snapshot release:
    /// reset may need that same lock while the gate is closed.
    pub(super) fn try_enter(&self) -> Option<SnapshotActivity<'_>> {
        let mut state = self.state.lock().unwrap();
        if state.paused || state.transport_reset {
            return None;
        }
        state.active += 1;
        Some(SnapshotActivity { gate: self })
    }

    pub(super) fn pause(&self) {
        let mut state = self.state.lock().unwrap();
        state.paused = true;
        while state.active != 0 {
            state = self.changed.wait(state).unwrap();
        }
    }

    pub(super) fn resume(&self) {
        let mut state = self.state.lock().unwrap();
        state.paused = false;
        self.changed.notify_all();
    }

    /// Hold RX producers until [`release_transport_reset`](Self::release_transport_reset).
    ///
    /// Unlike [`pause`](Self::pause) this does not wait for active producers:
    /// it is set before the restored guest runs, when none can be mid-packet.
    pub(super) fn hold_for_transport_reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.reset_generation = state.reset_generation.wrapping_add(1);
        state.transport_reset = true;
    }

    pub(super) fn release_transport_reset(&self) {
        let mut state = self.state.lock().unwrap();
        if state.transport_reset {
            state.transport_reset = false;
            self.changed.notify_all();
        }
    }

    pub(super) fn transport_reset_generation(&self) -> Option<u64> {
        let state = self.state.lock().unwrap();
        state.transport_reset.then_some(state.reset_generation)
    }

    /// A timer from a previous restore must not release a later restore's gate.
    pub(super) fn expire_transport_reset(&self, generation: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        if !state.transport_reset || state.reset_generation != generation {
            return false;
        }
        state.transport_reset = false;
        self.changed.notify_all();
        true
    }

    pub(super) fn is_held_for_transport_reset(&self) -> bool {
        self.state.lock().unwrap().transport_reset
    }

    fn finish(&self, mut state: MutexGuard<'_, GateState>) {
        state.active -= 1;
        if state.active == 0 {
            self.changed.notify_all();
        }
    }
}

pub struct SnapshotActivity<'a> {
    gate: &'a SnapshotGate,
}

impl Drop for SnapshotActivity<'_> {
    fn drop(&mut self) {
        self.gate.finish(self.gate.state.lock().unwrap());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::SnapshotGate;

    #[test]
    fn an_old_reset_timeout_cannot_release_a_later_restore() {
        let gate = SnapshotGate::default();
        gate.hold_for_transport_reset();
        let old = gate.transport_reset_generation().unwrap();
        gate.release_transport_reset();
        gate.hold_for_transport_reset();
        let current = gate.transport_reset_generation().unwrap();
        assert!(!gate.expire_transport_reset(old));
        assert!(gate.is_held_for_transport_reset());
        assert!(gate.expire_transport_reset(current));
        assert!(!gate.expire_transport_reset(current));
        assert!(!gate.is_held_for_transport_reset());
    }

    #[test]
    fn a_producer_holding_other_locks_never_waits_at_a_closed_gate() {
        let gate = SnapshotGate::default();
        gate.pause();
        assert!(gate.try_enter().is_none());
        gate.resume();
        drop(gate.try_enter().unwrap());
        gate.hold_for_transport_reset();
        assert!(gate.try_enter().is_none());
        gate.release_transport_reset();
        drop(gate.try_enter().unwrap());
        gate.pause(); // all successful entries were released
        gate.resume();
    }

    #[test]
    fn transport_reset_hold_blocks_writers_until_released() {
        let gate = Arc::new(SnapshotGate::default());
        gate.hold_for_transport_reset();
        let entered = Arc::new(AtomicBool::new(false));
        let writer = {
            let gate = gate.clone();
            let entered = entered.clone();
            thread::spawn(move || {
                let _activity = gate.enter();
                entered.store(true, Ordering::SeqCst);
            })
        };
        thread::sleep(Duration::from_millis(50));
        assert!(!entered.load(Ordering::SeqCst));
        assert!(gate.is_held_for_transport_reset());

        gate.release_transport_reset();
        writer.join().unwrap();
        assert!(entered.load(Ordering::SeqCst));
        assert!(!gate.is_held_for_transport_reset());
    }

    #[test]
    fn pause_waits_for_an_active_writer() {
        let gate = Arc::new(SnapshotGate::default());
        let activity = gate.enter();
        let (paused_tx, paused_rx) = mpsc::channel();
        let pause_gate = gate.clone();

        let pause_thread = thread::spawn(move || {
            pause_gate.pause();
            paused_tx.send(()).unwrap();
        });

        assert!(paused_rx.recv_timeout(Duration::from_millis(20)).is_err());
        drop(activity);
        paused_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        gate.resume();
        pause_thread.join().unwrap();
    }

    #[test]
    fn pause_blocks_new_writers_until_resume() {
        let gate = Arc::new(SnapshotGate::default());
        gate.pause();
        let (entered_tx, entered_rx) = mpsc::channel();
        let enter_gate = gate.clone();

        let enter_thread = thread::spawn(move || {
            let _activity = enter_gate.enter();
            entered_tx.send(()).unwrap();
        });

        assert!(entered_rx.recv_timeout(Duration::from_millis(20)).is_err());
        gate.resume();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        enter_thread.join().unwrap();
    }

    #[test]
    fn repeated_pauses_drain_concurrent_writers() {
        const WRITERS: usize = 4;
        let gate = Arc::new(SnapshotGate::default());
        let ready = Arc::new(Barrier::new(WRITERS + 1));
        let running = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::new();

        for _ in 0..WRITERS {
            let worker_gate = gate.clone();
            let worker_ready = ready.clone();
            let worker_running = running.clone();
            let worker_stop = stop.clone();
            workers.push(thread::spawn(move || {
                worker_ready.wait();
                while !worker_stop.load(Ordering::Acquire) {
                    let _activity = worker_gate.enter();
                    worker_running.fetch_add(1, Ordering::SeqCst);
                    thread::yield_now();
                    worker_running.fetch_sub(1, Ordering::SeqCst);
                }
            }));
        }

        ready.wait();
        for _ in 0..100 {
            gate.pause();
            assert_eq!(running.load(Ordering::SeqCst), 0);
            gate.resume();
        }

        stop.store(true, Ordering::Release);
        gate.resume();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}
