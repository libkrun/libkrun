use std::sync::{Condvar, Mutex, MutexGuard};

#[derive(Default)]
struct GateState {
    paused: bool,
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
        while state.paused {
            state = self.changed.wait(state).unwrap();
        }
        state.active += 1;
        SnapshotActivity { gate: self }
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

    fn finish(&self, mut state: MutexGuard<'_, GateState>) {
        state.active -= 1;
        if state.active == 0 {
            self.changed.notify_all();
        }
    }
}

pub(super) struct SnapshotActivity<'a> {
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
