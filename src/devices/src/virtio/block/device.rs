// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use imago::{
    DynStorage, FormatCreateBuilder, FormatDriverBuilder, PermissiveImplicitOpenGate, Storage,
    StorageCreateOptions, StorageOpenOptions, SyncFormatAccess, file::File as ImagoFile,
    qcow2::Qcow2, raw::Raw, vmdk::Vmdk,
};
use log::{error, warn};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::{
    virtio_blk::*, virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryMmap};

#[cfg(target_os = "windows")]
use std::mem::MaybeUninit;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

use super::worker::BlockWorker;
use super::{
    super::{ActivateResult, DeviceQueue, DeviceState, QueueConfig, TYPE_BLOCK, VirtioDevice},
    Error, NUM_QUEUES, QUEUE_CONFIG, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::virtio::{
    ActivateError, InterruptTransport,
    block::{ImageType, SyncMode},
    queue::QueueState,
};

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl CacheType {
    /// Picks the appropriate cache type based on disk image or device path.
    /// Special files like `/dev/rdisk*` on macOS do not support flush/sync.
    pub fn auto(_path: &str) -> CacheType {
        #[cfg(target_os = "macos")]
        if _path.starts_with("/dev/rdisk") {
            return CacheType::Unsafe;
        }
        CacheType::Writeback
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    cache_type: CacheType,
    pub(crate) file: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    nsectors: u64,
    image_id: Vec<u8>,
}

impl DiskProperties {
    pub fn new(
        disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
    ) -> io::Result<Self> {
        let disk_size = disk_image.lock().unwrap().size();

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if !disk_size.is_multiple_of(SECTOR_SIZE) {
            warn!(
                "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
            );
        }

        Ok(Self {
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: disk_image_id,
            file: disk_image,
        })
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        // This is how kvmtool does it.
        #[cfg(unix)]
        let device_id = {
            let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
            format!(
                "{}{}{}",
                blk_metadata.st_dev(),
                blk_metadata.st_rdev(),
                blk_metadata.st_ino()
            )
        };
        #[cfg(target_os = "windows")]
        let device_id = {
            let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
            let ret =
                unsafe { GetFileInformationByHandle(disk_file.as_raw_handle(), info.as_mut_ptr()) };
            if ret != 0 {
                let info = unsafe { info.assume_init() };
                format!(
                    "{}{}{}",
                    info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
                )
            } else {
                return Err(Error::GetFileMetadata(io::Error::last_os_error()));
            }
        };
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
            }
        }
        default_id
    }

    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }
}

impl Drop for DiskProperties {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Writeback => {
                // flush() first to force any cached data out.
                if self.file.lock().unwrap().flush().is_err() {
                    error!("Failed to flush block data on drop.");
                }
                // Sync data out to physical media on host.
                if self.file.lock().unwrap().sync().is_err() {
                    error!("Failed to sync block data on drop.")
                }
            }
            CacheType::Unsafe => {
                // This is a noop.
            }
        };
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkTopology {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry: VirtioBlkGeometry,
    blk_size: u32,
    topology: VirtioBlkTopology,
    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBlkConfig {}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    disk: Option<DiskProperties>,
    cache_type: CacheType,
    disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    disk_image_id: Vec<u8>,
    direct_io: bool,
    sync_mode: SyncMode,
    worker_thread: Option<JoinHandle<BlockWorker>>,
    worker_stopfd: EventFd,
    /// A worker reclaimed by [`Self::quiesce_for_snapshot`] (stopped, drained):
    /// holds the virtqueue + disk so its state can be snapshotted/restored and
    /// the worker re-armed. `None` during normal running.
    quiesced_worker: Option<BlockWorker>,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config: VirtioBlkConfig,

    // Transport related fields.
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
}

/// A replacement backing image opened and validated before a live block pivot.
///
/// This is intentionally opaque outside the block implementation. Preparing
/// every device first lets the VMM fail without changing any running device.
pub struct PreparedDiskPivot {
    disk: DiskProperties,
    disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
}

/// The previous backing retained until a live block pivot is committed.
pub struct DiskPivotRollback {
    disk: DiskProperties,
    disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
}

/// Open `path` as the given image format, returning the format accessor together
/// with the backing file's discard alignment. Shared by [`Block::new`] and
/// [`create_overlay`] so both agree on raw/qcow2/vmdk open semantics (including
/// recursive backing-chain resolution for qcow2).
fn open_disk_format(
    path: &str,
    format: ImageType,
    writable: bool,
    direct_io: bool,
    relaxed_sync: bool,
) -> io::Result<(SyncFormatAccess<Box<dyn DynStorage>>, usize)> {
    let file_opts = StorageOpenOptions::new()
        .write(writable)
        .filename(path)
        .direct(direct_io);
    #[cfg(target_os = "macos")]
    let file_opts = file_opts.relaxed_sync(relaxed_sync);
    #[cfg(not(target_os = "macos"))]
    let _ = relaxed_sync;
    let file = ImagoFile::open_sync(file_opts)?;
    let discard_alignment = file.discard_align();

    let disk_image = match format {
        ImageType::Qcow2 => {
            let mut qcow2 =
                Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::open_image_sync(
                    Box::new(file),
                    writable,
                )?;
            qcow2.open_implicit_dependencies_sync()?;
            SyncFormatAccess::new(qcow2)?
        }
        ImageType::Raw => {
            let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(Box::new(file), writable)?;
            SyncFormatAccess::new(raw)?
        }
        ImageType::Vmdk => {
            let vmdk =
                Vmdk::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::builder(Box::new(file))
                    .open_sync(PermissiveImplicitOpenGate::default())?;
            SyncFormatAccess::new(vmdk)?
        }
    };
    Ok((disk_image, discard_alignment))
}

/// Create a qcow2 overlay at `overlay_path` backed by `base_path` (format
/// `base_format`). The overlay starts near-empty and grows only with writes;
/// reads fall through to the read-only backing image — copy-on-write block
/// cloning for fork clones, independent of the host filesystem.
///
/// `base_path` is written verbatim into the qcow2 header, so it MUST be
/// absolute: imago resolves a relative backing path against the overlay's own
/// directory, which differs from the base's.
pub fn create_overlay(
    overlay_path: &str,
    base_path: &str,
    base_format: ImageType,
) -> io::Result<()> {
    // The overlay's virtual size must equal the base's.
    let (base, _discard) = open_disk_format(base_path, base_format, false, false, false)?;
    let virtual_size = base.size();
    drop(base);

    let backing_format = match base_format {
        ImageType::Raw => "raw",
        ImageType::Qcow2 => "qcow2",
        ImageType::Vmdk => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmdk backing images are not supported for overlays",
            ));
        }
    };

    // imago's create path is async-only (it has a sync wrapper for open, not
    // create); drive it on a current-thread runtime, as imago's own sync
    // wrappers do internally.
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let storage =
            ImagoFile::create_open(StorageCreateOptions::new().filename(overlay_path)).await?;
        Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<Box<dyn DynStorage>>>>::create_builder(
            Box::new(storage),
        )
        .size(virtual_size)
        .backing(base_path.to_string(), backing_format.to_string())
        .create()
        .await
    })
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        disk_image_format: ImageType,
        is_disk_read_only: bool,
        direct_io: bool,
        sync_mode: SyncMode,
    ) -> io::Result<Block> {
        let disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))?;

        let disk_image_id = DiskProperties::build_disk_image_id(&disk_image);

        let relaxed_sync = {
            #[cfg(target_os = "macos")]
            {
                sync_mode == SyncMode::Relaxed
            }
            #[cfg(not(target_os = "macos"))]
            {
                false
            }
        };
        let (disk_image, discard_alignment) = open_disk_format(
            &disk_image_path,
            disk_image_format,
            !is_disk_read_only,
            direct_io,
            relaxed_sync,
        )?;

        let disk_image = Arc::new(Mutex::new(disk_image));

        let disk_properties =
            DiskProperties::new(disk_image.clone(), disk_image_id.clone(), cache_type)?;

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1u64 << VIRTIO_BLK_F_DISCARD)
            | (1u64 << VIRTIO_BLK_F_WRITE_ZEROES)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if sync_mode != SyncMode::None {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let config = VirtioBlkConfig {
            capacity: disk_properties.nsectors(),
            size_max: 0,
            // QUEUE_SIZE - 2
            seg_max: 254,
            max_discard_sectors: u32::MAX,
            max_discard_seg: 1,
            discard_sector_alignment: discard_alignment as u32 / 512,
            max_write_zeroes_sectors: u32::MAX,
            max_write_zeroes_seg: 1,
            write_zeroes_may_unmap: 1,
            ..Default::default()
        };

        Ok(Block {
            id,
            partuuid,
            config,
            disk: Some(disk_properties),
            cache_type,
            disk_image,
            disk_image_id,
            direct_io,
            sync_mode,
            avail_features,
            acked_features: 0u64,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK)?,
            quiesced_worker: None,
        })
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0
    }

    /// Open and validate a writable replacement image for a running device.
    ///
    /// The device must already be quiesced. No device state changes until
    /// [`Self::apply_live_disk_pivot`] is called.
    pub fn prepare_live_disk_pivot(
        &self,
        path: &str,
        format: ImageType,
    ) -> io::Result<PreparedDiskPivot> {
        if self.is_read_only() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("block '{}' is read-only", self.id),
            ));
        }
        if !self.device_state.is_activated()
            || self.worker_thread.is_some()
            || self.quiesced_worker.is_none()
        {
            return Err(io::Error::other(format!(
                "block '{}' must be activated and quiesced before a live pivot",
                self.id
            )));
        }

        let relaxed_sync = self.sync_mode == SyncMode::Relaxed;
        let (disk_image, _discard_alignment) =
            open_disk_format(path, format, true, self.direct_io, relaxed_sync)?;
        let disk_image = Arc::new(Mutex::new(disk_image));
        let disk = DiskProperties::new(
            Arc::clone(&disk_image),
            self.disk_image_id.clone(),
            self.cache_type,
        )?;
        let expected_sectors = self.config.capacity;
        if disk.nsectors() != expected_sectors {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "block '{}' replacement has {} sectors, expected {}",
                    self.id,
                    disk.nsectors(),
                    expected_sectors
                ),
            ));
        }
        Ok(PreparedDiskPivot { disk, disk_image })
    }

    /// Atomically replace this quiesced device's backing image.
    pub fn apply_live_disk_pivot(
        &mut self,
        prepared: PreparedDiskPivot,
    ) -> io::Result<DiskPivotRollback> {
        if self.worker_thread.is_some() {
            return Err(io::Error::other(format!(
                "block '{}' worker is still running",
                self.id
            )));
        }
        let worker = self.quiesced_worker.as_mut().ok_or_else(|| {
            io::Error::other(format!("block '{}' has no quiesced worker", self.id))
        })?;
        let old_disk = worker.replace_disk(prepared.disk);
        let old_disk_image = std::mem::replace(&mut self.disk_image, prepared.disk_image);
        Ok(DiskPivotRollback {
            disk: old_disk,
            disk_image: old_disk_image,
        })
    }

    /// Restore a backing retained by [`Self::apply_live_disk_pivot`].
    pub fn rollback_live_disk_pivot(&mut self, rollback: DiskPivotRollback) -> io::Result<()> {
        if self.worker_thread.is_some() {
            return Err(io::Error::other(format!(
                "block '{}' worker is running during pivot rollback",
                self.id
            )));
        }
        let worker = self.quiesced_worker.as_mut().ok_or_else(|| {
            io::Error::other(format!("block '{}' has no quiesced worker", self.id))
        })?;
        let _discarded_new_disk = worker.replace_disk(rollback.disk);
        self.disk_image = rollback.disk_image;
        Ok(())
    }
}

/// Serializable runtime state of the [`Block`] device, for VM checkpoint/fork.
///
/// Captures device-level negotiated state (acked features, activation) and the
/// disk id. The backing disk image is re-provided from the VM config on
/// restore, not serialized.
///
/// QUEUE STATE + IN-FLIGHT DRAIN: block does not hold its virtqueues in the
/// device struct — they are moved into `worker_thread` at `activate()`. So a
/// faithful snapshot must DRAIN the worker first (signal `worker_stopfd`, join
/// the thread so in-flight I/O completes) and have the worker surface its
/// `QueueState` before exiting. The stop path (stopfd + join) already exists
/// for deactivation; extending it to return queue state is the shared
/// worker-quiesce step (block/net/console). Not captured here.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockState {
    pub acked_features: u64,
    pub activated: bool,
    pub disk_image_id: Vec<u8>,
    /// Virtqueue indices, captured after the worker is drained
    /// ([`Block::quiesce_for_snapshot`]). `None` if the device was not
    /// activated / not quiesced at snapshot time.
    pub queue: Option<QueueState>,
}

impl Block {
    /// Capture device-level + virtqueue runtime state for VM checkpoint/fork.
    /// The caller must have run [`Self::quiesce_for_snapshot`] first so the
    /// worker is stopped and its queue reclaimed — otherwise `queue` is `None`.
    pub fn save_state(&self) -> BlockState {
        BlockState {
            acked_features: self.acked_features,
            activated: matches!(self.device_state, DeviceState::Activated(..)),
            disk_image_id: self.disk_image_id.clone(),
            queue: self.quiesced_worker.as_ref().map(|w| w.save_queue_state()),
        }
    }

    /// Restore device-level + virtqueue state. The worker must be quiesced
    /// (reclaimed) first; the restored indices are applied to it and take effect
    /// when [`Self::rearm_after_snapshot`] re-arms the worker.
    pub fn restore_state(&mut self, state: &BlockState) -> std::result::Result<(), String> {
        self.acked_features = state.acked_features;
        if let (Some(worker), Some(qs)) = (self.quiesced_worker.as_mut(), state.queue.as_ref()) {
            worker.restore_queue_state(qs)?;
        }
        Ok(())
    }

    /// Stop and drain the worker, reclaiming its virtqueue so the indices can be
    /// snapshotted at a clean boundary (no in-flight I/O). Idempotent; no-op if
    /// not running. The device stays `Activated`; re-arm with
    /// [`Self::rearm_after_snapshot`].
    fn quiesce_worker(&mut self) {
        if let Some(handle) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            match handle.join() {
                Ok(worker) => self.quiesced_worker = Some(worker),
                Err(e) => error!("block: error draining worker thread: {e:?}"),
            }
        }
    }

    /// Re-arm a worker reclaimed by [`Self::quiesce_worker`], resuming I/O from
    /// the (possibly restored) virtqueue indices. No-op if not quiesced.
    fn rearm_worker(&mut self) {
        if let Some(worker) = self.quiesced_worker.take() {
            self.worker_thread = Some(worker.run());
        }
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn device_name(&self) -> &str {
        "block"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
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

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("Guest attempted to write config");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_blk: worker thread already exists");
        }

        let [blk_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        let disk = match self.disk.take() {
            Some(d) => d,
            None => DiskProperties::new(
                Arc::clone(&self.disk_image),
                self.disk_image_id.clone(),
                self.cache_type,
            )
            .map_err(|_| ActivateError::BadActivate)?,
        };

        let worker = BlockWorker::new(
            blk_q,
            interrupt.clone(),
            mem.clone(),
            disk,
            self.worker_stopfd.try_clone().unwrap(),
        );
        self.worker_thread = Some(worker.run());

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        // Drop any worker reclaimed for a snapshot too.
        self.quiesced_worker = None;
        self.device_state = DeviceState::Inactive;
        true
    }

    /// Quiesce for checkpoint/fork: drain + reclaim the worker's virtqueue so
    /// `save_state` can capture the indices at a clean boundary.
    fn quiesce_for_snapshot(&mut self) {
        self.quiesce_worker();
        // Force buffered writes durable so a fork clone's copy-on-write overlay
        // sees a consistent backing image. `DiskProperties::Drop` already does
        // this, but snapshot quiescence may retain the device or rotate it onto
        // a new writable layer without dropping it, so it must happen here too.
        if self.cache_type == CacheType::Writeback {
            let img = self.disk_image.lock().unwrap();
            if img.flush().is_err() {
                error!("block: failed to flush before snapshot");
            }
            if img.sync().is_err() {
                error!("block: failed to sync before snapshot");
            }
        }
    }

    /// Re-arm the worker after a checkpoint/restore (resumes I/O).
    fn rearm_after_snapshot(&mut self) {
        self.rearm_worker();
    }
}

#[cfg(test)]
mod overlay_tests {
    use super::*;
    use utils::tempfile::TempFile;

    #[test]
    fn create_overlay_over_raw_base() {
        // A 4 MiB raw base image.
        let base = TempFile::new().unwrap();
        let base_path = base.as_path().to_str().unwrap().to_string();
        let size = 4 * 1024 * 1024u64;
        base.as_file().set_len(size).unwrap();

        let overlay_path = format!("{base_path}.overlay.qcow2");
        create_overlay(&overlay_path, &base_path, ImageType::Raw).unwrap();

        // Reopening the overlay must resolve the backing chain and report the
        // base's virtual size.
        let (overlay, _discard) =
            open_disk_format(&overlay_path, ImageType::Qcow2, false, false, false).unwrap();
        assert_eq!(overlay.size(), size);
        drop(overlay);

        // The overlay file is just qcow2 metadata — far smaller than the base.
        let overlay_len = std::fs::metadata(&overlay_path).unwrap().len();
        assert!(
            overlay_len < size,
            "overlay {overlay_len} should be far smaller than base {size}"
        );

        std::fs::remove_file(&overlay_path).ok();
    }
}
