#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::cmp;
use std::io::Write;
use std::mem::offset_of;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use utils::eventfd::{EFD_NONBLOCK, EventFd};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use virtio_bindings::{virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, FsError, Queue, QueueConfig,
    VirtioDevice, VirtioShmRegion,
};
use super::ExportTable;
use super::augment_fs::AugmentFs;
use super::descriptor_utils::{Reader, Writer};
use super::inode_alloc::InodeAllocator;
use super::null_fs::NullFs;
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;
use super::virtual_entry::VirtualDirEntry;
use super::worker::{FsServer, FsWorker};
use super::{defs, defs::uapi};
use crate::BusWriteAction;
use crate::virtio::InterruptTransport;
use crate::virtio::passthrough::PermissionSemantics;

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
    num_sync_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; 36],
            num_request_queues: 0,
            num_sync_queues: 0,
        }
    }
}

unsafe impl ByteValued for VirtioFsConfig {}

struct FsSyncRuntime {
    active: AtomicBool,
    mem: GuestMemoryMmap,
    server: Arc<FsServer>,
    allow_idmap: bool,
    shm_region: Option<VirtioShmRegion>,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl FsSyncRuntime {
    fn process_queue(&self, queue: &mut Queue) {
        while let Some(head) = queue.pop(&self.mem) {
            let reader = Reader::new(&self.mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(&self.mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            let len = match self.server.handle_message(
                reader,
                writer,
                self.allow_idmap,
                &self.shm_region,
                &self.exit_code,
                #[cfg(target_os = "macos")]
                &self.map_sender,
            ) {
                Ok(len) => len,
                Err(e) => {
                    error!("error handling message: {e:?}");
                    0
                }
            };

            if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
    }
}

struct FsSyncQueue {
    // Dispatch must not wait for an executing queue while holding the transport lock.
    ready: bool,
    queue: Mutex<Queue>,
    runtime: Arc<FsSyncRuntime>,
}

impl BusWriteAction for FsSyncQueue {
    fn execute(&self) {
        let mut queue = self.queue.lock().unwrap();
        // A notification may have been selected before reset but not yet executed.
        if !self.runtime.active.load(Ordering::Acquire) {
            return;
        }

        loop {
            queue.disable_notification(&self.runtime.mem).unwrap();
            self.runtime.process_queue(&mut queue);
            if !queue.enable_notification(&self.runtime.mem).unwrap() {
                break;
            }
        }
    }
}

pub struct Fs {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    config: VirtioFsConfig,
    queue_configs: Vec<QueueConfig>,
    allow_idmap: bool,
    shm_region: Option<VirtioShmRegion>,
    passthrough_cfg: Option<passthrough::Config>,
    read_only: bool,
    virtual_entries: Vec<VirtualDirEntry<'static>>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
    sync_queues: Vec<Arc<FsSyncQueue>>,
    sync_runtime: Option<Arc<FsSyncRuntime>>,
}

impl Fs {
    pub fn new(
        fs_id: String,
        semantics: PermissionSemantics,
        shared_dir: Option<String>,
        exit_code: Arc<AtomicI32>,
        read_only: bool,
        virtual_entries: Vec<VirtualDirEntry<'static>>,
        num_sync_queues: u32,
    ) -> super::Result<Fs> {
        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);
        if num_sync_queues != 0 {
            avail_features |= 1u64 << uapi::VIRTIO_FS_F_SYNC;
        }

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1u32.to_le();
        config.num_sync_queues = num_sync_queues.to_le();

        let mut queue_configs = vec![QueueConfig::new(defs::QUEUE_SIZE); defs::REQ_INDEX + 1];
        queue_configs.resize(
            queue_configs.len() + num_sync_queues as usize,
            QueueConfig::new_sync(defs::QUEUE_SIZE),
        );

        let attr_timeout = if matches!(semantics, PermissionSemantics::LinuxSimplified) {
            // As uid/gid are context-dependent, attributes can't be cached.
            Duration::from_secs(0)
        } else {
            // The value defined as default in virtio-fs.
            Duration::from_secs(5)
        };

        let fs_cfg = shared_dir.map(|root_dir| passthrough::Config {
            root_dir,
            semantics,
            attr_timeout,
            ..Default::default()
        });

        let allow_idmap = matches!(semantics, PermissionSemantics::LinuxComplete);

        Ok(Fs {
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config,
            queue_configs,
            allow_idmap,
            shm_region: None,
            passthrough_cfg: fs_cfg,
            read_only,
            virtual_entries,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(FsError::EventFd)?,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender: None,
            sync_queues: Vec::new(),
            sync_runtime: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::FS_DEV_ID
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        self.shm_region = Some(shm_region);
    }

    pub fn set_export_table(&mut self, export_table: ExportTable) -> u64 {
        static FS_UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

        let Some(cfg) = self.passthrough_cfg.as_mut() else {
            // NullFs-backed devices have no passthrough config and don't
            // participate in cross-domain fd export. Consume (and waste) an
            // fsid so numbering stays dense, but don't store the table.
            return FS_UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
        };
        cfg.export_fsid = FS_UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
        cfg.export_table = Some(export_table);

        cfg.export_fsid
    }

    pub fn add_virtual_entry(&mut self, entry: VirtualDirEntry<'static>) {
        self.virtual_entries.push(entry);
    }

    #[cfg(target_os = "macos")]
    pub fn set_map_sender(&mut self, map_sender: Sender<WorkerMessage>) {
        self.map_sender = Some(map_sender);
    }

    fn first_sync_queue(&self) -> usize {
        defs::REQ_INDEX + u32::from_le(self.config.num_request_queues) as usize
    }

    fn sync_enabled(&self) -> bool {
        self.acked_features & (1u64 << uapi::VIRTIO_FS_F_SYNC) != 0
    }
}

impl VirtioDevice for Fs {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_FS
    }

    fn device_name(&self) -> &str {
        "fs"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_configs
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let mut config_slice = self.config.as_slice();
        if !self.sync_enabled() {
            config_slice = &config_slice[..offset_of!(VirtioFsConfig, num_sync_queues)];
        }
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "fs: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_fs: worker thread already exists");
        }

        let mut queues = queues;
        let sync_queues = queues.split_off(self.first_sync_queue());

        // Extract queues and eventfds from DeviceQueues.
        let mut worker_queues = Vec::with_capacity(queues.len());
        let mut queue_evts = Vec::with_capacity(queues.len());
        for dq in queues {
            worker_queues.push(dq.queue);
            queue_evts.push(dq.event);
        }

        let inode_alloc = Arc::new(InodeAllocator::new());
        let virtual_entries = self.virtual_entries.clone();
        let server = match &self.passthrough_cfg {
            Some(cfg) if self.read_only => {
                let inner =
                    PassthroughFsRo::new(cfg.clone(), inode_alloc.clone()).map_err(|e| {
                        error!("virtio_fs: failed to create passthrough fs: {e}");
                        ActivateError::BadActivate
                    })?;
                FsServer::ReadOnly(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            Some(cfg) => {
                let inner = PassthroughFs::new(cfg.clone(), inode_alloc.clone()).map_err(|e| {
                    error!("virtio_fs: failed to create passthrough fs: {e}");
                    ActivateError::BadActivate
                })?;
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
        let server = Arc::new(server);
        if self.sync_enabled() {
            let runtime = Arc::new(FsSyncRuntime {
                active: AtomicBool::new(true),
                mem: mem.clone(),
                server: server.clone(),
                allow_idmap: self.allow_idmap,
                shm_region: self.shm_region.clone(),
                exit_code: self.exit_code.clone(),
                #[cfg(target_os = "macos")]
                map_sender: self.map_sender.clone(),
            });
            self.sync_queues = sync_queues
                .into_iter()
                .map(|dq| {
                    Arc::new(FsSyncQueue {
                        ready: dq.queue.ready,
                        queue: Mutex::new(dq.queue),
                        runtime: runtime.clone(),
                    })
                })
                .collect();
            self.sync_runtime = Some(runtime);
        }

        let worker = FsWorker::new(
            worker_queues,
            queue_evts,
            interrupt.clone(),
            mem.clone(),
            self.allow_idmap,
            self.shm_region.clone(),
            server,
            self.worker_stopfd.try_clone().unwrap(),
            self.exit_code.clone(),
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
        );
        self.worker_thread = Some(worker.run());

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        self.shm_region.as_ref()
    }

    fn reset(&mut self) -> bool {
        if let Some(runtime) = &self.sync_runtime {
            runtime.active.store(false, Ordering::Release);
        }
        // Stop admission on every queue before waiting for in-flight handlers.
        for queue in &self.sync_queues {
            drop(queue.queue.lock().unwrap());
        }
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.sync_queues.clear();
        self.sync_runtime = None;
        self.acked_features = 0;
        self.device_state = DeviceState::Inactive;
        true
    }

    fn sync_queue(&self, queue_idx: u32) -> Option<Arc<dyn BusWriteAction>> {
        if !self.sync_enabled() || !self.is_activated() {
            return None;
        }
        let index = (queue_idx as usize).checked_sub(self.first_sync_queue())?;
        let queue = self.sync_queues.get(index)?;
        if !queue.ready {
            return None;
        }
        Some(queue.clone())
    }
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
