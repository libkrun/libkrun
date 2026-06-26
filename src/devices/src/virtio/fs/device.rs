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
use crate::virtio::passthrough::PermissionSemantics;

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
    allow_idmap: bool,
    shm_region: Option<VirtioShmRegion>,
    passthrough_cfg: Option<passthrough::Config>,
    read_only: bool,
    virtual_entries: Vec<VirtualDirEntry>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl Fs {
    pub fn new(
        fs_id: String,
        semantics: PermissionSemantics,
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
            semantics,
            ..Default::default()
        });

        let allow_idmap = matches!(semantics, PermissionSemantics::LinuxComplete);

        Ok(Fs {
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config,
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
            self.allow_idmap,
            self.shm_region.clone(),
            self.passthrough_cfg.clone(),
            self.read_only,
            virtual_entries,
            self.worker_stopfd.try_clone().unwrap(),
            self.exit_code.clone(),
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
        self.device_state = DeviceState::Inactive;
        true
    }
}
