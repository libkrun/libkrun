#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::thread;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::{Duration, Instant};
#[cfg(windows)]
use utils::windows::AsRawFd;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{FsError, FuseServerState, Queue};
use super::augment_fs::AugmentFs;
use super::defs::HPQ_INDEX;
use super::descriptor_utils::{Reader, Writer};
use super::inode_alloc::InodeAllocator;
use super::null_fs::NullFs;
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;
use super::virtual_entry::VirtualDirEntry;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

// Serial filesystem operations often submit the next request immediately after
// the guest receives our completion interrupt. Keep the request worker runnable
// for one short scheduling window so it can service that burst without another
// eventfd sleep/wake cycle. Yielding lets the guest vCPU produce the request and
// avoids consuming a host core while the worker waits.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const REQUEST_QUEUE_QUIET_POLL: Duration = Duration::from_micros(50);
#[cfg(any(target_os = "linux", target_os = "macos"))]
const REQUEST_QUEUE_MAX_POLL: Duration = Duration::from_millis(1);
#[cfg(target_os = "linux")]
const REQUEST_QUEUE_CONTENTION_YIELD: Duration = Duration::from_micros(250);
#[cfg(target_os = "linux")]
const REQUEST_QUEUE_CONTENTION_COOLDOWN: Duration = Duration::from_millis(100);

pub(super) enum FsServer {
    ReadWrite(Server<AugmentFs<PassthroughFs>>),
    ReadOnly(Server<AugmentFs<PassthroughFsRo>>),
    Null(Server<AugmentFs<NullFs>>),
}

pub(super) struct WorkerQueue {
    pub(super) index: usize,
    pub(super) queue: Queue,
    pub(super) event: Arc<EventFd>,
}

impl FsServer {
    fn handle_message(
        &self,
        r: Reader,
        w: Writer,
        shm_region: &Option<VirtioShmRegion>,
        exit_code: &Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> super::Result<usize> {
        match self {
            FsServer::ReadWrite(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::ReadOnly(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::Null(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
        }
    }
}

pub(super) struct FsWorker {
    queues: Vec<WorkerQueue>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    shm_region: Option<VirtioShmRegion>,
    server: Arc<FsServer>,
    stop_fd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "linux")]
    request_poll_after: Instant,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl FsWorker {
    pub(super) fn new_server(
        _shm_region: Option<VirtioShmRegion>,
        passthrough_cfg: Option<passthrough::Config>,
        read_only: bool,
        virtual_entries: Vec<VirtualDirEntry>,
        restore_fuse: Option<FuseServerState>,
    ) -> Result<Arc<FsServer>, io::Error> {
        let inode_alloc = Arc::new(InodeAllocator::new());
        let server = match passthrough_cfg {
            Some(cfg) if read_only => {
                let inner = PassthroughFsRo::new(cfg, inode_alloc.clone())?;
                if let Some(state) = restore_fuse.as_ref() {
                    inner.inner().restore(state)?;
                    #[cfg(target_os = "linux")]
                    if let Some(shm) = _shm_region.as_ref() {
                        inner
                            .inner()
                            .replay_dax_maps(shm.host_addr, shm.size as u64);
                    }
                }
                FsServer::ReadOnly(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            Some(cfg) => {
                let inner = PassthroughFs::new(cfg, inode_alloc.clone())?;
                if let Some(state) = restore_fuse.as_ref() {
                    inner.restore(state)?;
                    #[cfg(target_os = "linux")]
                    if let Some(shm) = _shm_region.as_ref() {
                        inner.replay_dax_maps(shm.host_addr, shm.size as u64);
                    }
                }
                FsServer::ReadWrite(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            None => FsServer::Null(Server::new(AugmentFs::new(
                NullFs,
                &inode_alloc,
                virtual_entries,
            ))),
        };
        Ok(Arc::new(server))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        queues: Vec<WorkerQueue>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        shm_region: Option<VirtioShmRegion>,
        server: Arc<FsServer>,
        stop_fd: EventFd,
        exit_code: Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: Option<Sender<WorkerMessage>>,
    ) -> Self {
        Self {
            queues,
            interrupt,
            mem,
            shm_region,
            server,
            stop_fd,
            exit_code,
            #[cfg(target_os = "linux")]
            request_poll_after: Instant::now(),
            #[cfg(target_os = "macos")]
            map_sender,
        }
    }

    pub(super) fn run(self) -> thread::JoinHandle<FsWorker> {
        thread::Builder::new()
            .name("fs worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    /// Snapshot the worker's virtqueue indices (for checkpoint/fork). Call only
    /// while the worker is stopped (reclaimed), so there is no concurrent access.
    pub(super) fn save_queue_states(&self) -> Vec<(usize, crate::virtio::queue::QueueState)> {
        self.queues
            .iter()
            .map(|queue| (queue.index, queue.queue.save_state()))
            .collect()
    }

    /// Snapshot the FUSE passthrough server's logical state (inode/handle maps as
    /// host paths) for checkpoint/fork. Call only while the worker is stopped.
    pub(super) fn save_fuse_state(&self) -> Option<FuseServerState> {
        match &*self.server {
            FsServer::ReadWrite(s) => Some(s.fs().inner().snapshot()),
            FsServer::ReadOnly(s) => Some(s.fs().inner().inner().snapshot()),
            FsServer::Null(_) => None,
        }
    }

    fn work(mut self) -> FsWorker {
        let stop_ev_fd = self.stop_fd.as_raw_fd();

        let mut epoll = Epoll::new().unwrap();

        for queue in &self.queues {
            let queue_ev_fd = queue.event.as_raw_fd();
            let _ = epoll.ctl(
                ControlOperation::Add,
                queue_ev_fd,
                &EpollEvent::new(EventSet::IN, queue_ev_fd as u64),
            );
        }
        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN
                                if self
                                    .queues
                                    .iter()
                                    .any(|queue| queue.event.as_raw_fd() == source) =>
                            {
                                let queue_position = self
                                    .queues
                                    .iter()
                                    .position(|queue| queue.event.as_raw_fd() == source)
                                    .unwrap();
                                self.handle_event(queue_position);
                                #[cfg(any(target_os = "linux", target_os = "macos"))]
                                if self.queues[queue_position].index != HPQ_INDEX {
                                    self.poll_request_burst(queue_position);
                                }
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return self;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn handle_event(&mut self, queue_position: usize) {
        let queue = &mut self.queues[queue_position];
        debug!("Fs: queue event: {}", queue.index);
        // A drained eventfd reports WouldBlock on a spurious level-triggered
        // wakeup (common with the Windows epoll shim) — expected, not an error.
        if let Err(e) = queue.event.read()
            && e.kind() != io::ErrorKind::WouldBlock
        {
            error!("Failed to get queue event: {e:?}");
        }

        loop {
            queue.queue.disable_notification(&self.mem).unwrap();

            Self::process_queue(
                &mut queue.queue,
                &self.server,
                &self.mem,
                &self.shm_region,
                &self.interrupt,
                &self.exit_code,
                #[cfg(target_os = "macos")]
                &self.map_sender,
            );

            if !queue.queue.enable_notification(&self.mem).unwrap() {
                break;
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn poll_request_burst(&mut self, queue_position: usize) {
        let start = Instant::now();
        let hard_deadline = start + REQUEST_QUEUE_MAX_POLL;
        let mut quiet_deadline = start + REQUEST_QUEUE_QUIET_POLL;

        loop {
            if self.process_queue_at(queue_position) {
                quiet_deadline = Instant::now() + REQUEST_QUEUE_QUIET_POLL;
            } else if Instant::now() >= quiet_deadline {
                break;
            } else {
                thread::yield_now();
            }
            if Instant::now() >= hard_deadline {
                break;
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn poll_request_burst(&mut self, queue_position: usize) {
        let start = Instant::now();
        if start < self.request_poll_after {
            return;
        }
        let hard_deadline = start + REQUEST_QUEUE_MAX_POLL;
        let mut quiet_deadline = start + REQUEST_QUEUE_QUIET_POLL;

        // Suppress guest kicks while we watch the queue directly. Besides
        // avoiding a stale eventfd wake for every request that we process here,
        // the enable_notification() check below closes the race between the
        // final empty queue observation and returning to epoll.
        if let Err(e) = self.queues[queue_position]
            .queue
            .disable_notification(&self.mem)
        {
            error!("failed to suppress filesystem queue notifications: {e:?}");
            return;
        }

        loop {
            if self.process_queue_at(queue_position) {
                quiet_deadline = Instant::now() + REQUEST_QUEUE_QUIET_POLL;
            } else if Instant::now() >= quiet_deadline {
                break;
            } else {
                let before_yield = Instant::now();
                thread::yield_now();
                let after_yield = Instant::now();
                if after_yield.duration_since(before_yield) >= REQUEST_QUEUE_CONTENTION_YIELD {
                    if self.process_queue_at(queue_position) {
                        // The guest vCPU used that scheduling window to produce
                        // the next request, so the poll was productive rather
                        // than host contention.
                        quiet_deadline = after_yield + REQUEST_QUEUE_QUIET_POLL;
                    } else {
                        // The CPU ran something unrelated and our queue is still
                        // empty. Stop competing for it and sample again after a
                        // short cooldown.
                        self.request_poll_after = after_yield + REQUEST_QUEUE_CONTENTION_COOLDOWN;
                        break;
                    }
                }
            }
            if Instant::now() >= hard_deadline {
                break;
            }
        }

        match self.queues[queue_position]
            .queue
            .enable_notification(&self.mem)
        {
            Ok(true) => {
                // Work arrived while notifications were suppressed. Queue a
                // host-side wake instead of processing indefinitely so the
                // stop/checkpoint event remains bounded by MAX_POLL.
                if let Err(e) = self.queues[queue_position].event.write(1) {
                    error!("failed to reawaken filesystem request queue: {e:?}");
                    self.handle_event(queue_position);
                }
            }
            Ok(false) => {}
            Err(e) => error!("failed to re-enable filesystem queue notifications: {e:?}"),
        }
    }

    fn process_queue_at(&mut self, queue_position: usize) -> bool {
        let queue = &mut self.queues[queue_position].queue;
        Self::process_queue(
            queue,
            &self.server,
            &self.mem,
            &self.shm_region,
            &self.interrupt,
            &self.exit_code,
            #[cfg(target_os = "macos")]
            &self.map_sender,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn process_queue(
        queue: &mut Queue,
        server: &FsServer,
        mem: &GuestMemoryMmap,
        shm_region: &Option<VirtioShmRegion>,
        interrupt: &InterruptTransport,
        exit_code: &Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> bool {
        let mut signal_needed = false;
        let mut processed = false;
        while let Some(head) = queue.pop(mem) {
            processed = true;
            let reader = Reader::new(mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            let len = match server.handle_message(
                reader,
                writer,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ) {
                Ok(len) => len,
                Err(e) => {
                    error!("error handling message: {e:?}");
                    0
                }
            };

            if let Err(e) = queue.add_used(mem, head.index, len as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if queue.needs_notification(mem).unwrap() {
                signal_needed = true;
            }
        }
        // Signal once after draining all descriptors rather than per-descriptor,
        // avoiding redundant IRQ signals when multiple FUSE requests complete in
        // a single epoll wake-up.
        if signal_needed {
            interrupt.signal_used_queue();
        }
        processed
    }
}
