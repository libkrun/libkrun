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
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use imago::{
    DynStorage, FormatCreateBuilder, FormatDriverBuilder, PermissiveImplicitOpenGate, Storage,
    StorageCreateOptions, StorageOpenOptions, SyncFormatAccess,
    file::File as ImagoFile,
    format::drivers::FormatDriverInstance,
    io_buffers::{IoVector, IoVectorMut},
    qcow2::Qcow2,
    raw::Raw,
    vmdk::Vmdk,
};
use log::{error, info, warn};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::{
    virtio_blk::*,
    virtio_config::VIRTIO_F_VERSION_1,
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
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

use super::worker::{AsyncIo, BlockWorker, PreparedAsyncIo, take_prepared_async_io};
use super::{
    super::{
        ActivateResult, DeviceQueue, DeviceState, QueueConfig, TYPE_BLOCK, VirtioDevice,
        VmmExitObserver,
    },
    Error, NUM_QUEUES, QUEUE_CONFIG, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::virtio::{
    ActivateError, InterruptTransport,
    block::{BlockIoEngine, ImageType, SyncMode},
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
    pub(crate) file: Arc<DiskBackend>,
    nsectors: u64,
    image_id: Vec<u8>,
    /// Windows, raw images only: independent handles to the image so queued
    /// reads and writes run concurrently. A synchronous Windows handle
    /// serializes its own I/O, and the format accessor sits behind one mutex,
    /// so without these the guest's queue drains one request at a time.
    #[cfg(target_os = "windows")]
    pub(crate) parallel: Option<Arc<Vec<File>>>,
}

/// Format-aware disk accessor selected when the device is created.
///
/// Both variants retain libkrun's original format wrapper for inline requests.
/// Raw images can additionally use a restricted io_uring for queued reads.
/// Reads share the accessor, so the worker's read lanes run them at once;
/// writes and every other request hold it alone, so a format's metadata still
/// has one writer.
pub(crate) enum DiskBackend {
    Sync(RwLock<SyncFormatAccess<Box<dyn DynStorage>>>),
    AsyncRaw {
        access: RwLock<SyncFormatAccess<Box<dyn DynStorage>>>,
        prepared_async: Box<Mutex<Option<AsyncIo>>>,
    },
}

impl DiskBackend {
    pub(crate) fn supports_async_io(&self) -> bool {
        matches!(self, Self::AsyncRaw { .. })
    }

    pub(crate) fn take_async_io(&self) -> Option<AsyncIo> {
        match self {
            Self::AsyncRaw { prepared_async, .. } => prepared_async.lock().unwrap().take(),
            Self::Sync(_) => None,
        }
    }

    pub(crate) fn return_async_io(&self, async_io: AsyncIo) {
        if let Self::AsyncRaw { prepared_async, .. } = self {
            *prepared_async.lock().unwrap() = Some(async_io);
        }
    }

    pub(crate) fn size(&self) -> u64 {
        match self {
            Self::Sync(access) => access.read().unwrap().size(),
            Self::AsyncRaw { access, .. } => access.read().unwrap().size(),
        }
    }

    pub(crate) fn readv(&self, buf: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        match self {
            Self::Sync(access) => access.read().unwrap().readv(buf, offset),
            Self::AsyncRaw { access, .. } => access.read().unwrap().readv(buf, offset),
        }
    }

    pub(crate) fn writev(&self, buf: IoVector<'_>, offset: u64) -> io::Result<()> {
        match self {
            Self::Sync(access) => access.write().unwrap().writev(buf, offset),
            Self::AsyncRaw { access, .. } => access.write().unwrap().writev(buf, offset),
        }
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        match self {
            Self::Sync(access) => access.write().unwrap().flush(),
            Self::AsyncRaw { access, .. } => access.write().unwrap().flush(),
        }
    }

    pub(crate) fn sync(&self) -> io::Result<()> {
        match self {
            Self::Sync(access) => access.write().unwrap().sync(),
            Self::AsyncRaw { access, .. } => access.write().unwrap().sync(),
        }
    }

    // Exclusive although every call takes `&self`: a resize rewrites the
    // image's metadata and must not overlap a read lane.
    #[allow(clippy::readonly_write_lock)]
    fn grow(&self, bytes: u64) -> io::Result<()> {
        let access = match self {
            Self::Sync(access) | Self::AsyncRaw { access, .. } => access,
        };
        let access = access.write().unwrap();
        access.resize_grow(bytes, imago::format::PreallocateMode::Zero)?;
        access.flush()?;
        access.sync()
    }

    pub(crate) fn write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        match self {
            Self::Sync(access) => access.write().unwrap().write_zeroes(offset, length),
            Self::AsyncRaw { access, .. } => access.write().unwrap().write_zeroes(offset, length),
        }
    }

    pub(crate) fn discard_to_zero(&self, offset: u64, length: u64) -> io::Result<()> {
        match self {
            Self::Sync(access) => access.write().unwrap().discard_to_zero(offset, length),
            Self::AsyncRaw { access, .. } => {
                access.write().unwrap().discard_to_zero(offset, length)
            }
        }
    }

    pub(crate) fn discard_to_any(&self, offset: u64, length: u64) -> io::Result<()> {
        match self {
            Self::Sync(access) => access.write().unwrap().discard_to_any(offset, length),
            Self::AsyncRaw { access, .. } => access.write().unwrap().discard_to_any(offset, length),
        }
    }
}

fn disk_backend<D>(
    driver: D,
    io_engine: BlockIoEngine,
    prepared_async: Option<AsyncIo>,
) -> io::Result<Arc<DiskBackend>>
where
    D: FormatDriverInstance<Storage = Box<dyn DynStorage>> + 'static,
{
    let backend = match io_engine {
        BlockIoEngine::Sync => DiskBackend::Sync(RwLock::new(SyncFormatAccess::new(driver)?)),
        BlockIoEngine::Async => match prepared_async {
            Some(prepared_async) => DiskBackend::AsyncRaw {
                access: RwLock::new(SyncFormatAccess::new(driver)?),
                prepared_async: Box::new(Mutex::new(Some(prepared_async))),
            },
            None => DiskBackend::Sync(RwLock::new(SyncFormatAccess::new(driver)?)),
        },
    };
    Ok(Arc::new(backend))
}

impl DiskProperties {
    pub fn new(
        disk_image: Arc<DiskBackend>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
    ) -> io::Result<Self> {
        let disk_size = disk_image.size();

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
            #[cfg(target_os = "windows")]
            parallel: None,
        })
    }

    /// Open the parallel I/O handles for a raw, buffered Windows image. Any
    /// failure just leaves the serialized path in place.
    #[cfg(target_os = "windows")]
    fn with_parallel_handles(mut self, path: &str, writable: bool) -> Self {
        const HANDLES: usize = 16;
        let handles: io::Result<Vec<File>> = (0..HANDLES)
            .map(|_| OpenOptions::new().read(true).write(writable).open(path))
            .collect();
        match handles {
            Ok(h) => self.parallel = Some(Arc::new(h)),
            Err(e) => warn!("parallel block handles unavailable for {path}: {e}"),
        }
        self
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

    pub(crate) fn backend(&self) -> Arc<DiskBackend> {
        self.file.clone()
    }
}

impl Drop for DiskProperties {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Writeback => {
                // flush() first to force any cached data out.
                if self.file.flush().is_err() {
                    error!("Failed to flush block data on drop.");
                }
                // Sync data out to physical media on host.
                if self.file.sync().is_err() {
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
    disk_image: Arc<DiskBackend>,
    disk_image_id: Vec<u8>,
    direct_io: bool,
    sync_mode: SyncMode,
    io_engine: BlockIoEngine,
    worker_thread: Option<JoinHandle<BlockWorker>>,
    worker_stopfd: EventFd,
    /// A worker reclaimed by [`Self::quiesce_for_snapshot`] (stopped, drained):
    /// holds the virtqueue + disk so its state can be snapshotted/restored and
    /// the worker re-armed. `None` during normal running.
    quiesced_worker: Option<BlockWorker>,
    snapshot_error: Option<String>,

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
    disk_image: Arc<DiskBackend>,
}

/// The previous backing retained until a live block pivot is committed.
pub struct DiskPivotRollback {
    disk: DiskProperties,
    disk_image: Arc<DiskBackend>,
}

/// Open `path` as the given image format, returning the format accessor together
/// with the backing file's discard alignment. Shared by [`Block::new`] and
/// [`create_overlay`] so both agree on raw/qcow2/vmdk open semantics (including
/// recursive backing-chain resolution for qcow2).
pub(crate) fn open_disk_format(
    path: &str,
    format: ImageType,
    writable: bool,
    direct_io: bool,
    relaxed_sync: bool,
    io_engine: BlockIoEngine,
    prepared_async: Option<PreparedAsyncIo>,
) -> io::Result<(Arc<DiskBackend>, usize)> {
    let file_opts = StorageOpenOptions::new()
        .write(writable)
        .filename(path)
        .direct(direct_io);
    let file_opts = file_opts.relaxed_sync(relaxed_sync);
    let file = ImagoFile::open_sync(file_opts)?;
    let discard_alignment = file.discard_align();

    let backend = match format {
        ImageType::Qcow2 => {
            let mut qcow2 =
                Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::open_image_sync(
                    Box::new(file),
                    writable,
                )?;
            qcow2.open_implicit_dependencies_sync()?;
            disk_backend(qcow2, io_engine, None)?
        }
        ImageType::Raw => {
            let prepared_async = if io_engine == BlockIoEngine::Async {
                let prepared = prepared_async.ok_or_else(|| {
                    io::Error::other("async raw block ring was not prepared before seccomp")
                })?;
                Some(take_prepared_async_io(prepared).ok_or_else(|| {
                    io::Error::other("async raw block ring token is invalid or already consumed")
                })?)
            } else {
                None
            };
            let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(Box::new(file), writable)?;
            disk_backend(raw, io_engine, prepared_async)?
        }
        ImageType::Vmdk => {
            let vmdk =
                Vmdk::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::builder(Box::new(file))
                    .open_sync(PermissiveImplicitOpenGate::default())?;
            disk_backend(vmdk, io_engine, None)?
        }
    };
    Ok((backend, discard_alignment))
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
    let (base, _discard) = open_disk_format(
        base_path,
        base_format,
        false,
        false,
        false,
        BlockIoEngine::Sync,
        None,
    )?;
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
        io_engine: BlockIoEngine,
        prepared_async: Option<PreparedAsyncIo>,
    ) -> io::Result<Block> {
        #[cfg(not(target_os = "linux"))]
        if io_engine == BlockIoEngine::Async {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the async block engine is currently available on Linux only",
            ));
        }
        if io_engine == BlockIoEngine::Async && direct_io {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the async block engine currently supports buffered disks only",
            ));
        }
        let disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))?;

        let disk_image_id = DiskProperties::build_disk_image_id(&disk_image);

        let relaxed_sync = sync_mode == SyncMode::Relaxed;
        let (disk_image, discard_alignment) = open_disk_format(
            &disk_image_path,
            disk_image_format,
            !is_disk_read_only,
            direct_io,
            relaxed_sync,
            io_engine,
            prepared_async,
        )?;

        let disk_properties =
            DiskProperties::new(disk_image.clone(), disk_image_id.clone(), cache_type)?;
        #[cfg(target_os = "windows")]
        let disk_properties = if disk_image_format == ImageType::Raw
            && !direct_io
            && std::env::var_os("SMOLVM_BLK_SERIAL").is_none()
        {
            disk_properties.with_parallel_handles(&disk_image_path, !is_disk_read_only)
        } else {
            disk_properties
        };

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1u64 << VIRTIO_BLK_F_DISCARD)
            | (1u64 << VIRTIO_BLK_F_WRITE_ZEROES)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX)
            // One ring slot per request however many pages it spans, so the
            // guest can keep many large requests in flight.
            | (1u64 << VIRTIO_RING_F_INDIRECT_DESC)
            // Report a 4 MiB optimal I/O size; Linux sizes read-ahead from it.
            | (1u64 << VIRTIO_BLK_F_TOPOLOGY);

        if cfg!(target_os = "windows") {
            avail_features |= 1u64 << VIRTIO_BLK_F_SIZE_MAX;
        }

        if sync_mode != SyncMode::None {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let config = VirtioBlkConfig {
            capacity: disk_properties.nsectors(),
            // Windows serves requests on several host lanes, so cap each
            // request near 1 MiB (254 segments of at most 4 KiB): the guest's
            // 8 MiB read-ahead window then keeps every lane busy instead of
            // two 4 MiB requests. Other hosts take requests as large as the
            // guest builds them.
            size_max: if cfg!(target_os = "windows") { 4096 } else { 0 },
            // QUEUE_SIZE - 2
            seg_max: 254,
            max_discard_sectors: u32::MAX,
            max_discard_seg: 1,
            discard_sector_alignment: discard_alignment as u32 / 512,
            max_write_zeroes_sectors: u32::MAX,
            max_write_zeroes_seg: 1,
            write_zeroes_may_unmap: 1,
            topology: VirtioBlkTopology {
                min_io_size: 8,    // 4 KiB in 512-byte sectors
                opt_io_size: 8192, // 4 MiB in 512-byte sectors
                ..Default::default()
            },
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
            io_engine,
            avail_features,
            acked_features: 0u64,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK)?,
            quiesced_worker: None,
            snapshot_error: None,
        })
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Grow an exclusively owned writable disk and notify the guest driver.
    /// The caller must serialize this with snapshots and backing-layer pivots,
    /// and must never use it on an immutable ancestor of another machine.
    /// Filesystem growth inside the guest is a separate, subsequent operation.
    pub fn grow(&mut self, bytes: u64) -> io::Result<()> {
        let current = self.config.capacity * SECTOR_SIZE;
        if bytes < current || !bytes.is_multiple_of(SECTOR_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "disk growth must be sector-aligned and cannot shrink",
            ));
        }
        if self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cannot grow a read-only disk",
            ));
        }
        if self.quiesced_worker.is_some() || self.snapshot_error.is_some() {
            return Err(io::Error::other(
                "cannot grow a disk during snapshot preparation or recovery",
            ));
        }
        // Even an equal-size retry must complete the durability barrier: a
        // previous request may have grown the image but failed to sync it.
        self.disk_image.grow(bytes)?;
        let sectors = bytes >> SECTOR_SHIFT;
        self.config.capacity = sectors;
        if let Some(disk) = self.disk.as_mut() {
            disk.nsectors = sectors;
        }
        if let DeviceState::Activated(_, ref interrupt) = self.device_state {
            interrupt.signal_config_change();
        }
        Ok(())
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
        // Async rings are prepared before the launcher installs seccomp and
        // are fixed to one backing file. A live fork pivot introduces a path
        // that did not exist at launch, so safely fall back to the synchronous
        // backend for the continued source. Its persisted engine remains async,
        // and the next process start prepares a new ring for the new backing.
        let pivot_io_engine = match self.io_engine {
            BlockIoEngine::Async => {
                warn!(
                    "block '{}': live disk pivot uses synchronous I/O until the next VM start",
                    self.id
                );
                BlockIoEngine::Sync
            }
            engine => engine,
        };
        let (disk_image, _discard_alignment) = open_disk_format(
            path,
            format,
            true,
            self.direct_io,
            relaxed_sync,
            pivot_io_engine,
            None,
        )?;
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
                Err(e) => {
                    error!("block: error draining worker thread: {e:?}");
                    self.snapshot_error = Some("block worker failed before checkpoint".into());
                }
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
            self.io_engine,
        )
        .map_err(|_| ActivateError::BadActivate)?;
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
        self.snapshot_error = None;
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
            if let Err(error) = self.disk_image.flush() {
                self.snapshot_error.get_or_insert_with(|| {
                    format!("block flush failed before checkpoint: {error}")
                });
            }
            if let Err(error) = self.disk_image.sync() {
                self.snapshot_error
                    .get_or_insert_with(|| format!("block sync failed before checkpoint: {error}"));
            }
        }
    }

    fn snapshot_error(&self) -> Option<&str> {
        self.snapshot_error.as_deref()
    }

    /// Re-arm the worker after a checkpoint/restore (resumes I/O).
    fn rearm_after_snapshot(&mut self) {
        self.rearm_worker();
    }
}

/// The VMM ends with `_exit`, which skips `DiskProperties::drop`. The image
/// driver keeps the cluster mappings of recent writes in a write-back cache
/// and writes them out only on a guest flush, so a guest that never asks for
/// one (a disk marked "write through" in the guest never does) would lose
/// them with the process: its newest blocks would read back unmapped on the
/// next boot. Drain the worker and write the image out before exiting. The
/// driver's metadata cache exists whatever the cache type, so only a
/// read-only disk, which never dirties it, is skipped.
impl VmmExitObserver for Block {
    fn on_vmm_exit(&mut self) {
        self.quiesce_worker();
        if self.is_read_only() {
            return;
        }
        // The flush comes first and is what keeps the image consistent: it
        // hands the cached metadata to the host page cache, which outlives
        // the process, and takes milliseconds. The sync after it only makes
        // that durable against a host crash and can take seconds, so a host
        // that escalates to SIGKILL may cut it short. Each step is logged on
        // both ends, so a cut-short exit shows as a start without a finish.
        info!("block '{}': flushing image metadata before exit", self.id);
        let started = std::time::Instant::now();
        if let Err(error) = self.disk_image.flush() {
            error!("block '{}': flush on exit failed: {error}", self.id);
        }
        let flushed = started.elapsed();
        info!(
            "block '{}': image metadata flushed in {} ms; syncing",
            self.id,
            flushed.as_millis()
        );
        if let Err(error) = self.disk_image.sync() {
            error!("block '{}': sync on exit failed: {error}", self.id);
        }
        info!(
            "block '{}': image synced in {} ms",
            self.id,
            (started.elapsed() - flushed).as_millis()
        );
    }
}

#[cfg(test)]
mod overlay_tests {
    use super::*;
    use imago::storage::drivers::CommonStorageHelper;
    use std::fmt;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use utils::tempfile::TempFile;

    #[test]
    fn rejected_disk_growth_keeps_the_previous_capacity() {
        let storage: Box<dyn DynStorage> = Box::new(FailingStorage {
            control: Arc::new(FailureControl::default()),
            helper: CommonStorageHelper::default(),
        });
        let raw = Raw::open_image_sync(storage, true).unwrap();
        let access = SyncFormatAccess::new(raw).unwrap();
        let original = access.size();
        assert!(
            access
                .resize_grow(original * 2, imago::format::PreallocateMode::Zero)
                .is_err()
        );
        assert_eq!(
            access.size(),
            original,
            "failed growth must not publish capacity"
        );
        // A repeated request must still report the failure, not a false no-op success.
        assert!(
            access
                .resize_grow(original * 2, imago::format::PreallocateMode::Zero)
                .is_err()
        );
    }

    /// A write that allocated a qcow2 cluster survives a VMM exit that runs
    /// no drop: the exit observer writes the cluster mapping out, whatever
    /// the cache type, and a fresh open of the image finds the data.
    #[test]
    fn exit_writes_out_cluster_mappings_that_drop_never_would() {
        let base = TempFile::new().unwrap();
        base.as_file().set_len(4 * 1024 * 1024).unwrap();
        let path = base.as_path().to_str().unwrap();
        let overlay = format!("{path}.exit.qcow2");
        create_overlay(&overlay, path, ImageType::Raw).unwrap();
        let open = |cache_type| {
            Block::new(
                "exit".into(),
                None,
                cache_type,
                overlay.clone(),
                ImageType::Qcow2,
                false,
                false,
                SyncMode::Full,
                BlockIoEngine::Sync,
                None,
            )
            .unwrap()
        };

        let mut block = open(CacheType::Unsafe);
        let marker = [0xa5; 4096];
        // Past the first cluster, so the write allocates one and updates the
        // L2 table the driver keeps cached.
        block
            .disk_image
            .writev(IoVector::from(&marker[..]), 3 * 1024 * 1024)
            .unwrap();
        block.on_vmm_exit();
        // `_exit` runs no destructor: neither must the test.
        std::mem::forget(block);

        let reopened = open(CacheType::Writeback);
        let mut data = [0; 4096];
        reopened
            .disk_image
            .readv(IoVectorMut::from(&mut data[..]), 3 * 1024 * 1024)
            .unwrap();
        assert_eq!(
            data, marker,
            "the cluster mapping was lost with the process"
        );
        drop(reopened);
        std::fs::remove_file(overlay).unwrap();
    }

    #[test]
    fn disk_growth_preserves_data_and_publishes_zeroed_capacity() {
        for image_type in [ImageType::Raw, ImageType::Qcow2] {
            let base = TempFile::new().unwrap();
            base.as_file().set_len(1024 * 1024).unwrap();
            let path = base.as_path().to_str().unwrap();
            let overlay = format!("{path}.grow.qcow2");
            let disk_path = if image_type == ImageType::Qcow2 {
                create_overlay(&overlay, path, ImageType::Raw).unwrap();
                overlay.as_str()
            } else {
                path
            };
            let mut block = Block::new(
                "grow".into(),
                None,
                CacheType::Writeback,
                disk_path.into(),
                image_type,
                false,
                false,
                SyncMode::Full,
                BlockIoEngine::Sync,
                None,
            )
            .unwrap();
            let marker = [0x5a; 512];
            block
                .disk_image
                .writev(IoVector::from(&marker[..]), 0)
                .unwrap();
            block.grow(2 * 1024 * 1024).unwrap();
            let capacity = block.config.capacity;
            assert_eq!(capacity * SECTOR_SIZE, 2 * 1024 * 1024);
            let mut data = [0; 512];
            block
                .disk_image
                .readv(IoVectorMut::from(&mut data[..]), 0)
                .unwrap();
            assert_eq!(data, marker);
            block
                .disk_image
                .readv(IoVectorMut::from(&mut data[..]), 1024 * 1024)
                .unwrap();
            assert_eq!(data, [0; 512]);
            assert!(block.grow(512).is_err());
            assert!(block.grow(2 * 1024 * 1024 + 1).is_err());
            block.grow(2 * 1024 * 1024).unwrap();
            drop(block);
            if image_type == ImageType::Qcow2 {
                std::fs::remove_file(overlay).unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn growing_overlay_does_not_expose_backing_data_or_change_siblings() {
        use std::os::unix::fs::FileExt;

        let base = TempFile::new().unwrap();
        base.as_file().set_len(2 * 1024 * 1024).unwrap();
        base.as_file()
            .write_all_at(&[0xab; 512], 1024 * 1024)
            .unwrap();
        let base_path = base.as_path().to_str().unwrap();
        let overlay = format!("{base_path}.small.qcow2");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let storage = ImagoFile::create_open(
                StorageCreateOptions::new().filename(&overlay),
            ).await.unwrap();
            Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<Box<dyn DynStorage>>>>::create_builder(
                Box::new(storage),
            )
            .size(1024 * 1024)
            .backing(base_path.to_string(), "raw".to_string())
            .create().await.unwrap();
        });
        let mut block = Block::new(
            "private-overlay".into(),
            None,
            CacheType::Writeback,
            overlay.clone(),
            ImageType::Qcow2,
            false,
            false,
            SyncMode::Full,
            BlockIoEngine::Sync,
            None,
        )
        .unwrap();
        block.grow(2 * 1024 * 1024).unwrap();
        let mut data = [0xff; 512];
        block
            .disk_image
            .readv(IoVectorMut::from(&mut data[..]), 1024 * 1024)
            .unwrap();
        assert_eq!(
            data, [0; 512],
            "new capacity must not reveal the longer backing"
        );
        block
            .disk_image
            .writev(IoVector::from(&[0xcd; 512][..]), 1024 * 1024)
            .unwrap();
        block.disk_image.flush().unwrap();
        base.as_file()
            .read_exact_at(&mut data, 1024 * 1024)
            .unwrap();
        assert_eq!(
            data, [0xab; 512],
            "other readers of the base must remain unchanged"
        );
        drop(block);
        let (reopened, _) = open_disk_format(
            &overlay,
            ImageType::Qcow2,
            false,
            false,
            false,
            BlockIoEngine::Sync,
            None,
        )
        .unwrap();
        assert_eq!(reopened.size(), 2 * 1024 * 1024);
        reopened
            .readv(IoVectorMut::from(&mut data[..]), 1024 * 1024)
            .unwrap();
        assert_eq!(data, [0xcd; 512]);
        drop(reopened);
        std::fs::remove_file(overlay).unwrap();
    }

    #[derive(Debug, Default)]
    struct FailureControl {
        operations: AtomicU8,
        flushes: AtomicUsize,
        syncs: AtomicUsize,
    }

    #[derive(Debug)]
    struct FailingStorage {
        control: Arc<FailureControl>,
        helper: CommonStorageHelper,
    }

    impl fmt::Display for FailingStorage {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("checkpoint failure test storage")
        }
    }

    impl Storage for FailingStorage {
        fn size(&self) -> io::Result<u64> {
            Ok(1024 * 1024)
        }

        async unsafe fn pure_readv(&self, _: IoVectorMut<'_>, _: u64) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }

        async unsafe fn pure_writev(&self, _: IoVector<'_>, _: u64) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }

        async fn flush(&self) -> io::Result<()> {
            self.control.flushes.fetch_add(1, Ordering::SeqCst);
            if self.control.operations.load(Ordering::SeqCst) & 1 != 0 {
                Err(io::Error::other("injected storage flush failure"))
            } else {
                Ok(())
            }
        }

        async fn sync(&self) -> io::Result<()> {
            self.control.syncs.fetch_add(1, Ordering::SeqCst);
            if self.control.operations.load(Ordering::SeqCst) & 2 != 0 {
                Err(io::Error::other("injected storage sync failure"))
            } else {
                Ok(())
            }
        }

        async unsafe fn invalidate_cache(&self) -> io::Result<()> {
            Ok(())
        }

        fn get_storage_helper(&self) -> &CommonStorageHelper {
            &self.helper
        }
    }

    #[test]
    fn checkpoint_rejects_storage_flush_and_sync_failures() {
        for operations in [1, 2, 3] {
            let base = TempFile::new().unwrap();
            base.as_file().set_len(1024 * 1024).unwrap();
            let mut block = Block::new(
                "failure-test".into(),
                None,
                CacheType::Writeback,
                base.as_path().to_str().unwrap().into(),
                ImageType::Raw,
                false,
                false,
                SyncMode::Full,
                BlockIoEngine::Sync,
                None,
            )
            .unwrap();
            let control = Arc::new(FailureControl::default());
            let storage: Box<dyn DynStorage> = Box::new(FailingStorage {
                control: control.clone(),
                helper: CommonStorageHelper::default(),
            });
            let raw = Raw::open_image_sync(storage, true).unwrap();
            block.disk_image = Arc::new(DiskBackend::Sync(RwLock::new(
                SyncFormatAccess::new(raw).unwrap(),
            )));
            control.operations.store(operations, Ordering::SeqCst);
            block.quiesce_for_snapshot();
            let error = block
                .snapshot_error()
                .expect("failed durability must reject checkpoint");
            assert!(error.contains(if operations & 1 != 0 { "flush" } else { "sync" }));
            assert_eq!(control.flushes.load(Ordering::SeqCst), 1);
            assert_eq!(control.syncs.load(Ordering::SeqCst), 1);
            // A later successful barrier cannot recover buffers lost by a
            // failed operation; require explicit device recovery/reset.
            control.operations.store(0, Ordering::SeqCst);
            block.quiesce_for_snapshot();
            assert!(block.snapshot_error().is_some());
            block.reset();
            block.quiesce_for_snapshot();
            assert!(block.snapshot_error().is_none());
        }
    }

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
        let (overlay, _discard) = open_disk_format(
            &overlay_path,
            ImageType::Qcow2,
            false,
            false,
            false,
            BlockIoEngine::Sync,
            None,
        )
        .unwrap();
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

    /// Bytes the host file system holds for `path`, not its apparent length.
    #[cfg(unix)]
    fn allocated_bytes(path: &str) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().blocks() * 512
    }

    #[cfg(unix)]
    #[test]
    fn a_qcow2_discard_gives_the_freed_clusters_back_to_the_host() {
        let base = TempFile::new().unwrap();
        let size = 16 * 1024 * 1024u64;
        base.as_file().set_len(size).unwrap();
        let base_path = base.as_path().to_str().unwrap();
        let overlay = format!("{base_path}.punch.qcow2");
        create_overlay(&overlay, base_path, ImageType::Raw).unwrap();
        let (disk, _) = open_disk_format(
            &overlay,
            ImageType::Qcow2,
            true,
            false,
            false,
            BlockIoEngine::Sync,
            None,
        )
        .unwrap();
        let data = vec![0x5a_u8; 8 * 1024 * 1024];
        disk.writev(IoVector::from(&data[..]), 0).unwrap();
        disk.flush().unwrap();
        let written = allocated_bytes(&overlay);
        assert!(
            written >= 8 * 1024 * 1024,
            "the write is allocated: {written}"
        );

        // What a guest's fstrim sends for a deleted file.
        disk.discard_to_any(0, 8 * 1024 * 1024).unwrap();
        disk.flush().unwrap();
        let trimmed = allocated_bytes(&overlay);
        assert!(
            trimmed < 1024 * 1024,
            "the discarded clusters stay in the file: {written} -> {trimmed} bytes"
        );
        let mut read = vec![1_u8; 4096];
        disk.readv(IoVectorMut::from(&mut read[..]), 4 * 1024 * 1024)
            .unwrap();
        assert_eq!(read, vec![0; 4096], "a discarded range reads as zeros");

        // The freed clusters are reused, and hold only what is written to them.
        let again = vec![0x33_u8; 64 * 1024];
        disk.writev(IoVector::from(&again[..]), 1024 * 1024)
            .unwrap();
        let mut read = vec![0_u8; 128 * 1024];
        disk.readv(IoVectorMut::from(&mut read[..]), 1024 * 1024)
            .unwrap();
        assert_eq!(&read[..64 * 1024], &again[..]);
        assert_eq!(&read[64 * 1024..], &vec![0; 64 * 1024][..]);
        drop(disk);
        std::fs::remove_file(overlay).unwrap();
    }

    fn tail_discard_keeps_raw_capacity(zero: bool) {
        use std::io::{Read, Seek, SeekFrom, Write};

        let base = TempFile::new().unwrap();
        let base_path = base.as_path().to_str().unwrap();
        let size = 4 * 1024 * 1024;
        base.as_file().set_len(size).unwrap();
        let mut file = base.as_file();
        file.write_all(b"keep").unwrap();
        file.seek(SeekFrom::Start(size - 4)).unwrap();
        file.write_all(b"tail").unwrap();
        let (disk, _) = open_disk_format(
            base_path,
            ImageType::Raw,
            true,
            false,
            false,
            BlockIoEngine::Sync,
            None,
        )
        .unwrap();
        if zero {
            disk.discard_to_zero(size / 2, size / 2).unwrap();
        } else {
            disk.discard_to_any(size / 2, size / 2).unwrap();
        }
        assert_eq!(disk.size(), size);
        assert_eq!(
            base.as_file().metadata().unwrap().len(),
            size,
            "discard must not change the capacity seen by the next branch"
        );
        let mut bytes = [0; 4];
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"keep");
        file.seek(SeekFrom::Start(size - 4)).unwrap();
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [0; 4]);
        drop(disk);
        let overlay_path = format!("{base_path}.tail.qcow2");
        create_overlay(&overlay_path, base_path, ImageType::Raw).unwrap();
        let (overlay, _) = open_disk_format(
            &overlay_path,
            ImageType::Qcow2,
            false,
            false,
            false,
            BlockIoEngine::Sync,
            None,
        )
        .unwrap();
        assert_eq!(overlay.size(), size);
        drop(overlay);
        std::fs::remove_file(overlay_path).unwrap();
    }

    #[test]
    fn raw_tail_discard_keeps_capacity_for_branching() {
        tail_discard_keeps_raw_capacity(false);
    }

    #[test]
    fn raw_tail_zeroing_keeps_capacity_for_branching() {
        tail_discard_keeps_raw_capacity(true);
    }
}
