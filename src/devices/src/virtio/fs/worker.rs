#[cfg(any(target_os = "macos", target_os = "windows"))]
use crossbeam_channel::Sender;
#[cfg(any(target_os = "macos", target_os = "windows"))]
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::defs::HPQ_INDEX;
use super::descriptor_utils::{Reader, Writer};
use super::inode_alloc::InodeAllocator;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::live_fs::LiveFs;
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Live(Server<AugmentFs<LiveFs<PassthroughFs>>>),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    LiveRo(Server<AugmentFs<LiveFs<PassthroughFsRo>>>),
}

pub(super) struct WorkerQueue {
    pub(super) index: usize,
    pub(super) queue: Queue,
    pub(super) event: Arc<EventFd>,
}

impl FsServer {
    #[cfg(target_os = "windows")]
    fn has_active_dax_mappings(&self) -> bool {
        match self {
            FsServer::ReadWrite(server) => server.fs().inner().has_active_dax_mappings(),
            FsServer::ReadOnly(server) => server.fs().inner().inner().has_active_dax_mappings(),
            FsServer::Null(_) => false,
        }
    }

    /// Re-establish this server's DAX window mappings.
    ///
    /// The window lives inside guest RAM, so anything that replaces those host
    /// mappings — a clone's fresh pages, or the source's own `MAP_FIXED` rebase
    /// when it takes a fork generation — leaves the guest's DAX page-table
    /// entries pointing at zero pages while the guest kernel still believes the
    /// file is mapped: reads return zeros instead of file bytes.
    #[cfg(target_os = "linux")]
    pub(super) fn replay_dax_maps(&self, host_shm_base: u64, shm_size: u64) {
        match self {
            FsServer::ReadWrite(server) => {
                server.fs().inner().replay_dax_maps(host_shm_base, shm_size)
            }
            FsServer::ReadOnly(server) => server
                .fs()
                .inner()
                .inner()
                .replay_dax_maps(host_shm_base, shm_size),
            // No passthrough host files, so no window mappings to replay.
            FsServer::Null(_) => {}
            // Live devices have no DAX window.
            FsServer::Live(_) | FsServer::LiveRo(_) => {}
        }
    }

    fn handle_message(
        &self,
        r: Reader,
        w: Writer,
        shm_region: &Option<VirtioShmRegion>,
        exit_code: &Arc<AtomicI32>,
        #[cfg(any(target_os = "macos", target_os = "windows"))] map_sender: &Option<
            Sender<WorkerMessage>,
        >,
    ) -> super::Result<usize> {
        match self {
            FsServer::ReadWrite(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                map_sender,
            ),
            FsServer::ReadOnly(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                map_sender,
            ),
            FsServer::Null(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                map_sender,
            ),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            FsServer::Live(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            FsServer::LiveRo(s) => s.handle_message(
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
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl FsWorker {
    #[cfg(target_os = "windows")]
    pub(super) fn has_active_dax_mappings(&self) -> bool {
        self.server.has_active_dax_mappings()
    }

    pub(super) fn new_server(
        _shm_region: Option<VirtioShmRegion>,
        passthrough_cfg: Option<passthrough::Config>,
        read_only: bool,
        live_tag: Option<&str>,
        virtual_entries: Vec<VirtualDirEntry>,
        restore_fuse: Option<FuseServerState>,
    ) -> Result<Arc<FsServer>, io::Error> {
        let inode_alloc = Arc::new(InodeAllocator::new());
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let (Some(tag), Some(cfg)) = (live_tag, passthrough_cfg.clone()) {
            let server = if read_only {
                let fs = LiveFs::new(PassthroughFsRo::new(cfg, inode_alloc.clone())?, tag);
                if let Some(state) = restore_fuse.as_ref() {
                    fs.restore(state)?;
                }
                FsServer::LiveRo(Server::new(AugmentFs::new(
                    fs,
                    &inode_alloc,
                    virtual_entries,
                )))
            } else {
                let fs = LiveFs::new(PassthroughFs::new(cfg, inode_alloc.clone())?, tag);
                if let Some(state) = restore_fuse.as_ref() {
                    fs.restore(state)?;
                }
                FsServer::Live(Server::new(AugmentFs::new(
                    fs,
                    &inode_alloc,
                    virtual_entries,
                )))
            };
            return Ok(Arc::new(server));
        }
        #[cfg(target_os = "windows")]
        if live_tag.is_some() {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        }
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
            None => {
                // Only virtual entries, and nothing restores a counter here:
                // number them the same way every session so a restored guest's
                // cached nodeids still name them.
                let inode_alloc = InodeAllocator::sequential();
                FsServer::Null(Server::new(AugmentFs::new(
                    NullFs,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
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
        #[cfg(any(target_os = "macos", target_os = "windows"))] map_sender: Option<
            Sender<WorkerMessage>,
        >,
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
            #[cfg(any(target_os = "macos", target_os = "windows"))]
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

    /// Validate all replacement queues before changing any stopped worker.
    pub(super) fn prepare_rewind(
        &self,
        states: &[Option<crate::virtio::queue::QueueState>],
    ) -> Result<Vec<Queue>, String> {
        self.queues
            .iter()
            .map(|current| {
                let state = states
                    .get(current.index)
                    .and_then(Option::as_ref)
                    .ok_or_else(|| {
                        format!("missing filesystem queue {} in checkpoint", current.index)
                    })?;
                let mut queue = Queue::new(current.queue.get_max_size());
                queue.restore_state(state)?;
                if queue.ready && !queue.is_valid(&self.mem) {
                    return Err(format!(
                        "invalid filesystem queue {} in checkpoint",
                        current.index
                    ));
                }
                Ok(queue)
            })
            .collect()
    }

    pub(super) fn apply_rewind(&mut self, queues: Vec<Queue>, server: Arc<FsServer>) {
        for (current, restored) in self.queues.iter_mut().zip(queues) {
            current.queue = restored;
            // The old eventfd is not checkpointed. Ensure restored pending work
            // is examined when this worker is rearmed, even without a guest kick.
            if let Err(error) = current.event.write(1) {
                error!("failed to wake restored filesystem queue: {error}");
            }
        }
        self.server = server;
        #[cfg(target_os = "linux")]
        {
            self.request_poll_after = Instant::now();
        }
    }

    /// Snapshot the FUSE passthrough server's logical state (inode/handle maps as
    /// host paths) for checkpoint/fork. Call only while the worker is stopped.
    pub(super) fn save_fuse_state(&self) -> Option<FuseServerState> {
        match &*self.server {
            FsServer::ReadWrite(s) => Some(s.fs().inner().snapshot()),
            FsServer::ReadOnly(s) => Some(s.fs().inner().inner().snapshot()),
            FsServer::Null(_) => None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            FsServer::Live(s) => Some(s.fs().inner().snapshot()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            FsServer::LiveRo(s) => Some(s.fs().inner().snapshot()),
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
                #[cfg(any(target_os = "macos", target_os = "windows"))]
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn process_queue_at(&mut self, queue_position: usize) -> bool {
        let queue = &mut self.queues[queue_position].queue;
        Self::process_queue(
            queue,
            &self.server,
            &self.mem,
            &self.shm_region,
            &self.interrupt,
            &self.exit_code,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
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
        #[cfg(any(target_os = "macos", target_os = "windows"))] map_sender: &Option<
            Sender<WorkerMessage>,
        >,
    ) -> bool {
        let mut signal_needed = false;
        let mut processed = false;
        while let Some(head) = queue.pop(mem) {
            processed = true;
            let len = match (
                Reader::new(mem, head.clone()).map_err(FsError::QueueReader),
                Writer::new(mem, head.clone()).map_err(FsError::QueueWriter),
            ) {
                (Ok(reader), Ok(writer)) => match server.handle_message(
                    reader,
                    writer,
                    shm_region,
                    exit_code,
                    #[cfg(any(target_os = "macos", target_os = "windows"))]
                    map_sender,
                ) {
                    Ok(len) => len,
                    Err(e) => {
                        error!("error handling message: {e:?}");
                        0
                    }
                },
                (reader, writer) => {
                    error!(
                        "invalid descriptor chain: {:?} {:?}",
                        reader.err(),
                        writer.err()
                    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use vm_memory::GuestAddress;

    #[test]
    fn a_request_outside_guest_memory_is_completed_not_fatal() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
        ring.dtable[0].set(0x10_0000, 64, 0, 0);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        let mut queue = ring.create_queue();
        let server = FsWorker::new_server(None, None, false, None, Vec::new(), None).unwrap();

        FsWorker::process_queue(
            &mut queue,
            &server,
            &mem,
            &None,
            &InterruptTransport::new(DummyIrqChip::new().into(), "fs test".into()).unwrap(),
            &Arc::new(AtomicI32::new(0)),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            &None,
        );
        assert_eq!(ring.used.idx.get(), 1);
    }
}
