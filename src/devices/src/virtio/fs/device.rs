#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::cmp;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::thread::JoinHandle;

use utils::eventfd::{EFD_NONBLOCK, EventFd};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use virtio_bindings::{virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, FsError, QueueConfig, VirtioDevice,
    VirtioShmRegion,
};
use super::ExportTable;
use super::passthrough;
use super::virtual_entry::VirtualDirEntry;
use super::worker::FsWorker;
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; 36],
            num_request_queues: 0,
        }
    }
}

unsafe impl ByteValued for VirtioFsConfig {}

pub struct Fs {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    config: VirtioFsConfig,
    shm_region: Option<VirtioShmRegion>,
    passthrough_cfg: Option<passthrough::Config>,
    read_only: bool,
    virtual_entries: Vec<VirtualDirEntry>,
    worker_thread: Option<JoinHandle<FsWorker>>,
    worker_stopfd: EventFd,
    /// A worker reclaimed by [`Self::quiesce_for_snapshot`] (stopped, drained):
    /// holds the virtqueues so their indices can be captured for a checkpoint
    /// and re-armed afterwards.
    quiesced_worker: Option<FsWorker>,
    /// FUSE server state restored from a checkpoint, consumed by the next
    /// `activate` to rebuild the worker's passthrough inode/handle maps.
    pending_fuse: Option<FuseServerState>,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

/// Serializable runtime state of an [`Fs`] device for VM checkpoint/fork.
/// The virtqueue indices and negotiated features are serialized, as is the
/// host-side FUSE server's logical state ([`FuseServerState`]) — the latter is
/// rebuilt in the clone process by re-opening the recorded host paths, since
/// the open file descriptors themselves are process-local.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FsState {
    pub acked_features: u64,
    /// Per-queue runtime state, indexed like the device's queue config. `None`
    /// means the queue was owned by the worker at snapshot time (a faithful
    /// snapshot first quiesces the worker so it releases its queues).
    pub queues: Vec<Option<crate::virtio::queue::QueueState>>,
    /// Logical FUSE passthrough server state (inode + handle maps as host paths,
    /// counters, negotiated options). `None` if the device was never activated.
    pub fuse: Option<FuseServerState>,
}

/// Logical snapshot of a passthrough FUSE server, captured by host path so it
/// can be rebuilt in a different process. Platform-neutral (no OS handles) so it
/// serializes cleanly; the rebuild logic lives in the per-OS passthrough impl.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuseServerState {
    pub inodes: Vec<FuseInodeSnap>,
    pub handles: Vec<FuseHandleSnap>,
    pub next_inode: u64,
    pub next_handle: u64,
    pub writeback: bool,
    pub announce_submounts: bool,
    /// Active DAX window mappings, replayed into a clone's window after the
    /// inode map is rebuilt. Defaults to empty for snapshots taken before this
    /// field existed.
    #[serde(default)]
    pub dax_maps: Vec<FuseDaxMapSnap>,
}

/// One FUSE inode: the guest's nodeid mapped to its source-host identity and,
/// for portable snapshots, to a path relative to the export root.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuseInodeSnap {
    pub nodeid: u64,
    /// Path relative to this virtio-fs export's root. New snapshots populate
    /// this so a portable checkpoint can rebuild the inode beneath a different
    /// host rootfs location. `path` remains for same-host legacy snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
    pub path: String,
    pub refcount: u64,
}

/// One open FUSE handle: the guest's fh, its owning nodeid, and the open flags
/// it was created with (so it can be re-opened against the rebuilt inode).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuseHandleSnap {
    pub handle: u64,
    pub nodeid: u64,
    pub flags: i32,
}

/// One active DAX window mapping (a SETUPMAPPING the guest has not removed):
/// recorded so a fork clone can replay the host-side `mmap(MAP_SHARED|MAP_FIXED)`
/// into its window. The window itself is an anonymous guest-memory region that a
/// cross-process clone rebuilds as fresh zero pages, while the restored guest
/// kernel still holds DAX page-table entries into it — without replay the guest
/// reads zeros where file pages were.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuseDaxMapSnap {
    /// Byte offset of the mapping inside the DAX window.
    pub moffset: u64,
    /// FUSE nodeid of the mapped file (resolved via the restored inode map).
    pub nodeid: u64,
    /// Byte offset of the mapping inside the file.
    pub foffset: u64,
    /// Mapping length in bytes.
    pub len: u64,
    /// FUSE SETUPMAPPING flags (read/write) the guest requested.
    pub flags: u64,
}

impl Fs {
    pub fn new(
        fs_id: String,
        shared_dir: Option<String>,
        exit_code: Arc<AtomicI32>,
        read_only: bool,
        virtual_entries: Vec<VirtualDirEntry>,
    ) -> super::Result<Fs> {
        let avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1;

        let fs_cfg = shared_dir.map(|root_dir| passthrough::Config {
            root_dir,
            ..Default::default()
        });

        Ok(Fs {
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config,
            shm_region: None,
            passthrough_cfg: fs_cfg,
            read_only,
            virtual_entries,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(FsError::EventFd)?,
            quiesced_worker: None,
            pending_fuse: None,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender: None,
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

    #[cfg(target_os = "macos")]
    pub fn set_map_sender(&mut self, map_sender: Sender<WorkerMessage>) {
        self.map_sender = Some(map_sender);
    }

    /// Capture this device's runtime state for VM checkpoint/fork. The worker
    /// must be quiesced ([`Self::quiesce_for_snapshot`]) first so the virtqueue
    /// indices can be read; otherwise the queues are owned by the worker.
    pub fn save_state(&self) -> FsState {
        FsState {
            acked_features: self.acked_features,
            queues: self
                .quiesced_worker
                .as_ref()
                .map(|w| w.save_queue_states().into_iter().map(Some).collect())
                .unwrap_or_default(),
            fuse: self
                .quiesced_worker
                .as_ref()
                .and_then(|w| w.save_fuse_state()),
        }
    }

    /// Restore runtime state onto a freshly-constructed, not-yet-activated Fs.
    /// Only negotiated features are applied here; the virtqueue indices are
    /// re-applied when the device is re-activated (cross-process fork uses
    /// `restore_and_activate`, which rebuilds the queues from the saved indices
    /// and starts a fresh worker). The host-side FUSE server is recreated fresh.
    pub fn restore_state(&mut self, state: &FsState) -> std::result::Result<(), String> {
        self.acked_features = state.acked_features;
        self.pending_fuse = state.fuse.clone();
        Ok(())
    }

    /// Stop and drain the worker, reclaiming its virtqueues so the indices can
    /// be captured at a clean checkpoint boundary. Pairs with
    /// [`Self::rearm_worker`].
    fn quiesce_worker(&mut self) {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            match worker.join() {
                Ok(w) => self.quiesced_worker = Some(w),
                Err(e) => error!("virtio_fs: error reclaiming worker: {e:?}"),
            }
        }
    }

    /// Re-arm a worker reclaimed by [`Self::quiesce_worker`], resuming FUSE
    /// service from the (possibly restored) virtqueue indices.
    fn rearm_worker(&mut self) {
        if let Some(worker) = self.quiesced_worker.take() {
            self.worker_thread = Some(worker.run());
        }
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
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
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

        // Extract queues and eventfds from DeviceQueues.
        let mut worker_queues = Vec::with_capacity(queues.len());
        let mut queue_evts = Vec::with_capacity(queues.len());
        for dq in queues {
            worker_queues.push(dq.queue);
            queue_evts.push(dq.event);
        }

        let virtual_entries = self.virtual_entries.clone();
        let worker = FsWorker::new(
            worker_queues,
            queue_evts,
            interrupt.clone(),
            mem.clone(),
            self.shm_region.clone(),
            self.passthrough_cfg.clone(),
            self.read_only,
            virtual_entries,
            self.worker_stopfd.try_clone().unwrap(),
            self.exit_code.clone(),
            self.pending_fuse.take(),
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
        )
        .map_err(|e| {
            error!("virtio_fs: failed to create worker: {}", e);
            ActivateError::BadActivate
        })?;
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
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.quiesced_worker = None;
        self.device_state = DeviceState::Inactive;
        true
    }

    fn quiesce_for_snapshot(&mut self) {
        self.quiesce_worker();
    }

    fn rearm_after_snapshot(&mut self) {
        self.rearm_worker();
    }
}
