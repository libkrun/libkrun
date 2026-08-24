use std::io::Write;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, Queue as VirtQueue, QueueConfig,
    VirtioDevice, VirtioShmRegion, fs::ExportTable, queue::QueueState,
};
use super::defs;
use super::defs::uapi;
use super::defs::uapi::virtio_gpu_config;
use super::worker::Worker;
use crate::virtio::InterruptTransport;
use crate::virtio::display::DisplayInfo;
use krun_display::DisplayBackend;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = (1u64 << uapi::VIRTIO_F_VERSION_1)
    | (1u64 << uapi::VIRTIO_GPU_F_VIRGL)
    | (1u64 << uapi::VIRTIO_GPU_F_EDID)
    | (1u64 << uapi::VIRTIO_GPU_F_RESOURCE_UUID)
    | (1u64 << uapi::VIRTIO_GPU_F_RESOURCE_BLOB)
    | (1u64 << uapi::VIRTIO_GPU_F_CONTEXT_INIT);

const QUEUE_SIZE: u16 = 256;
static QUEUE_CONFIG: [QueueConfig; defs::NUM_QUEUES] =
    [QueueConfig::new(QUEUE_SIZE); defs::NUM_QUEUES];

/// Snapshot of the GPU device's transport-level state for checkpoint/fork.
///
/// Deliberately excludes rutabaga/virgl GPU state (contexts, resources, the
/// render-server connection) — that is live host GPU state which is not
/// serializable (rutabaga only snapshots 2D). A fork clone re-activates the GPU
/// device fresh, spawning its own render-server and rutabaga; this snapshot
/// carries only what the transport needs to re-attach the guest's queues:
/// negotiated features + per-queue ring state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GpuState {
    pub acked_features: u64,
    /// Control queue then cursor queue (index order), each `None` if never set up.
    pub queues: Vec<Option<QueueState>>,
}

pub struct Gpu {
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) device_state: DeviceState,
    shm_region: Option<VirtioShmRegion>,
    virgl_flags: u32,
    #[cfg(target_os = "macos")]
    map_sender: Sender<WorkerMessage>,
    export_table: Option<ExportTable>,
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackend<'static>,
    /// Control queue, shared with the worker (an `Arc` clone). Read at snapshot
    /// time to capture ring state; the golden is paused so the worker is idle.
    control_queue: Option<Arc<Mutex<VirtQueue>>>,
    /// Cursor queue, shared with the worker like the control queue: the worker
    /// drains and acks cursor commands, so ring state must be read live at
    /// snapshot time.
    cursor_queue: Option<Arc<Mutex<VirtQueue>>>,
}

impl Gpu {
    pub fn new(
        virgl_flags: u32,
        displays: Box<[DisplayInfo]>,
        display_backend: DisplayBackend<'static>,
        #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
    ) -> super::Result<Gpu> {
        Ok(Gpu {
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            shm_region: None,
            virgl_flags,
            #[cfg(target_os = "macos")]
            map_sender,
            export_table: None,
            displays,
            display_backend,
            control_queue: None,
            cursor_queue: None,
        })
    }

    /// Capture the device's transport state for checkpoint/fork. GPU state is
    /// intentionally NOT captured (see [`GpuState`]) — the clone re-activates
    /// fresh.
    pub fn save_state(&self) -> GpuState {
        let control = self
            .control_queue
            .as_ref()
            .map(|q| q.lock().expect("gpu control queue poisoned").save_state());
        let cursor = self
            .cursor_queue
            .as_ref()
            .map(|q| q.lock().expect("gpu cursor queue poisoned").save_state());
        GpuState {
            acked_features: self.acked_features,
            queues: vec![control, cursor],
        }
    }

    /// Restore transport state onto a freshly-built device before re-activation.
    /// Only the negotiated features are applied here; the queues are rebuilt from
    /// the saved ring state by the transport's `restore_and_activate`.
    pub fn restore_state(&mut self, state: &GpuState) -> Result<(), String> {
        self.acked_features = state.acked_features;
        Ok(())
    }

    pub fn id(&self) -> &str {
        defs::GPU_DEV_ID
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        debug!("virtio_gpu: set_shm_region");
        self.shm_region = Some(shm_region);
    }

    pub fn set_export_table(&mut self, export_table: ExportTable) {
        self.export_table = Some(export_table);
    }

    /*
    pub fn process_ctl(&mut self) -> bool {
        debug!("gpu: process_ctl()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        //while let Some(head) = self.queues[CTL_INDEX].pop(mem) {
        if let Some(head) = self.queues[CTL_INDEX].pop(mem) {
            let index = head.index;
            let mut written = 0;
            for desc in head.into_iter() {
                error!("gpu: process_ctl() unimplemented");
                self.queues[CTL_INDEX].go_to_previous_position();
                break;
            }

            have_used = true;
            self.queues[CTL_INDEX].add_used(mem, index, written);
        }

        have_used
    }

    pub fn process_cur(&mut self) -> bool {
        debug!("gpu: process_cur()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        while let Some(head) = self.queues[CTL_INDEX].pop(mem) {
            let index = head.index;
            let mut written = 0;
            for desc in head.into_iter() {
                error!("gpu: process_cur() unimplemented");
                self.queues[CTL_INDEX].go_to_previous_position();
                break;
            }

            have_used = true;
            self.queues[CTL_INDEX].add_used(mem, index, written);
        }

        have_used
    }
    */
}

impl VirtioDevice for Gpu {
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
        uapi::VIRTIO_ID_GPU
    }

    fn device_name(&self) -> &str {
        "gpu"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config = virtio_gpu_config {
            events_read: 0,
            events_clear: 0,
            num_scanouts: self.displays.len() as u32,
            num_capsets: 5,
        };

        let config_slice = config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..std::cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "gpu: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        let [control_q, cursor_q]: [_; defs::NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!(
                "Cannot perform activate. Expected {} queue(s)",
                defs::NUM_QUEUES
            );
            ActivateError::BadActivate
        })?;

        let shm_region = match self.shm_region.as_ref() {
            Some(s) => s.clone(),
            None => panic!("virtio_gpu: missing SHM region"),
        };

        // Share both queues with the worker via `Arc` so their ring state can
        // be read at snapshot time (for fork).
        let DeviceQueue {
            queue: control_queue,
            event: control_event,
        } = control_q;
        let control_queue = Arc::new(Mutex::new(control_queue));
        self.control_queue = Some(control_queue.clone());
        let DeviceQueue {
            queue: cursor_queue,
            event: cursor_event,
        } = cursor_q;
        let cursor_queue = Arc::new(Mutex::new(cursor_queue));
        self.cursor_queue = Some(cursor_queue.clone());
        let worker = Worker::new(
            control_queue,
            control_event,
            cursor_queue,
            cursor_event,
            mem.clone(),
            interrupt.clone(),
            shm_region,
            self.virgl_flags,
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
            self.export_table.take(),
            self.displays.clone(),
            self.display_backend,
        );
        worker.run();

        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        debug!("virtio_gpu: GET_shm_region");
        self.shm_region.as_ref()
    }
}
