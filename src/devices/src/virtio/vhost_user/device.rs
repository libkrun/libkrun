// Copyright 2026, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic vhost-user device wrapper.
//!
//! This module provides a wrapper around the vhost crate's Frontend,
//! adapting it to work with libkrun's VirtioDevice trait.

use std::io::{self, ErrorKind, IoSlice, Read, Result as IoResult, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use krun_display::{
    DisplayBackend, DisplayBackendBasicFramebuffer, DisplayBackendInstance, ResourceFormat,
};
use log::{debug, error, warn};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use vhost::vhost_user::gpu_message::{
    GpuBackendReq, VhostUserGpuHeaderFlag, VhostUserGpuScanout, VhostUserGpuUpdate,
    VirtioGpuDisplayOne, VirtioGpuRect, VirtioGpuRespDisplayInfo, VirtioGpuRespGetEdid,
};
use vhost::vhost_user::message::{
    FrontendReq, VhostUserConfigFlags, VhostUserMMap, VhostUserMMapFlags,
};
use vhost::vhost_user::{
    Frontend, FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandlerMut,
    VhostUserProtocolFeatures,
};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, ByteValued, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd as VhostEventFd;

use crate::display::DisplayInfo;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    VirtioDevice, VirtioShmRegion,
};

/// VHOST_USER_F_PROTOCOL_FEATURES (bit 30) is a backend-only feature
/// that enables vhost-user protocol extensions. It's not a virtio feature.
const VHOST_USER_F_PROTOCOL_FEATURES: u64 = 1 << 30;

pub const VIRTIO_ID_GPU: u32 = 16;
pub const VIRTIO_ID_MEDIA: u32 = 48;

struct BorrowedFd(RawFd);
impl AsRawFd for BorrowedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Helper function to send GPU_SET_SOCKET message to vhost-user backend.
/// Following QEMU's vhost_user_gpu_set_socket() pattern - sends message without waiting for ACK.
///
/// TODO: This should be part of vhost crate's Frontend trait:
///   frontend.set_gpu_socket(gpu_fd) -> Result<()>
fn send_gpu_set_socket(
    frontend_fd: std::os::unix::io::RawFd,
    gpu_fd: std::os::unix::io::RawFd,
) -> IoResult<()> {
    const VHOST_USER_VERSION: u32 = 0x1;

    let header: [u32; 3] = [
        FrontendReq::GPU_SET_SOCKET as u32,
        VHOST_USER_VERSION,
        0, // size = 0 (no payload, just the FD)
    ];

    // SAFETY: header is a local [u32; 3] array, valid for its entire lifetime here.
    let header_bytes = unsafe {
        std::slice::from_raw_parts(header.as_ptr() as *const u8, std::mem::size_of_val(&header))
    };

    let iov = [IoSlice::new(header_bytes)];
    let fds = [gpu_fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    sendmsg::<()>(frontend_fd, &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(|e| io::Error::other(format!("sendmsg failed: {}", e)))?;

    Ok(())
}

/// Handles backend-to-frontend requests on the BACKEND_REQ channel,
/// in particular shmem_map/shmem_unmap for devices that use shared memory regions.
struct BackendReqInner {
    shm_region: Option<VirtioShmRegion>,
    device_name: String,
}

impl VhostUserFrontendReqHandlerMut for BackendReqInner {
    fn handle_config_change(&mut self) -> io::Result<u64> {
        debug!("{}: backend config change notification", self.device_name);
        Ok(0)
    }

    fn shmem_map(&mut self, req: &VhostUserMMap, fd: &dyn AsRawFd) -> io::Result<u64> {
        let shm = self
            .shm_region
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTSUP))?;

        let shm_offset = req.shm_offset;
        let len = req.len;
        let fd_offset = req.fd_offset;
        let flags = req.flags;

        let end = shm_offset
            .checked_add(len)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        if end > shm.size as u64 {
            error!(
                "{}: shmem_map out of bounds: offset={:#x} len={:#x} region_size={:#x}",
                self.device_name, shm_offset, len, shm.size
            );
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        let addr = shm.host_addr + shm_offset;
        let prot = if VhostUserMMapFlags::from_bits(flags)
            .unwrap_or_default()
            .contains(VhostUserMMapFlags::WRITABLE)
        {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        // SAFETY: addr is within the pre-allocated shm_region (bounds checked above).
        let result = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.as_raw_fd(),
                fd_offset as libc::off_t,
            )
        };

        if result == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            error!("{}: shmem_map mmap failed: {}", self.device_name, err);
            return Err(err);
        }

        debug!(
            "{}: shmem_map: offset={:#x} len={:#x} fd_offset={:#x}",
            self.device_name, shm_offset, len, fd_offset
        );
        Ok(0)
    }

    fn shmem_unmap(&mut self, req: &VhostUserMMap) -> io::Result<u64> {
        let shm = self
            .shm_region
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTSUP))?;

        let shm_offset = req.shm_offset;
        let len = req.len;

        let end = shm_offset
            .checked_add(len)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        if end > shm.size as u64 {
            error!(
                "{}: shmem_unmap out of bounds: offset={:#x} len={:#x} region_size={:#x}",
                self.device_name, shm_offset, len, shm.size
            );
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        let addr = shm.host_addr + shm_offset;

        // SAFETY: addr is within the pre-allocated shm_region (bounds checked above).
        let result = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };

        if result == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            error!("{}: shmem_unmap mmap failed: {}", self.device_name, err);
            return Err(err);
        }

        debug!(
            "{}: shmem_unmap: offset={:#x} len={:#x}",
            self.device_name, shm_offset, len
        );
        Ok(0)
    }
}

/// Generic vhost-user device wrapper.
///
/// This wraps a vhost-user backend connection and implements the VirtioDevice
/// trait, allowing it to be used like any other virtio device in libkrun.
pub struct VhostUserDevice {
    /// Vhost-user frontend connection
    frontend: Arc<Mutex<Frontend>>,

    /// Device type (e.g., VIRTIO_ID_RNG = 4)
    device_type: u32,

    /// Device name for logging
    device_name: String,

    /// Queue configurations
    queue_configs: Vec<QueueConfig>,

    /// Available features from the backend
    avail_features: u64,

    /// Whether the backend supports protocol features
    has_protocol_features: bool,

    /// Protocol features successfully negotiated with the backend
    negotiated_protocol_features: VhostUserProtocolFeatures,

    /// Acknowledged features
    acked_features: u64,

    /// Device state
    device_state: DeviceState,

    /// Activation event (registered with EventManager)
    activate_evt: EventFd,

    /// Vring call event (backend->VMM interrupt notification)
    vring_call_event: Option<EventFd>,

    /// GPU socket for receiving GPU protocol messages (GPU devices only)
    gpu_socket: Option<UnixStream>,

    /// User-configured display resolution for GPU devices (display size, not guest scanout).
    gpu_display_info: Option<DisplayInfo>,

    /// Shared memory region for devices that need it (e.g., media, GPU)
    shm_region: Option<VirtioShmRegion>,

    /// Handler for backend-to-frontend requests (BACKEND_REQ protocol feature)
    backend_req_handler: Option<FrontendReqHandler<Mutex<BackendReqInner>>>,
    display_backend: Option<DisplayBackend<'static>>,

    display_instance: Option<EpollThreadLocal<DisplayBackendInstance>>,
}

struct EpollThreadLocal<T>(T);

// SAFETY: VhostUserDevice is registered with a single EventManager and its
// Subscriber::process() is always called from the same epoll thread. The
// DisplayBackendInstance inside is created and used exclusively in that
// callback, so it never actually crosses a thread boundary.
unsafe impl<T> Send for EpollThreadLocal<T> {}

impl<T> std::ops::Deref for EpollThreadLocal<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for EpollThreadLocal<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl VhostUserDevice {
    /// Create a new vhost-user device by connecting to a socket.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the vhost-user Unix domain socket
    /// * `device_type` - Virtio device type ID
    /// * `device_name` - Human-readable device name for logging
    /// * `num_queues` - Number of queues (0 = query backend via MQ protocol)
    /// * `queue_sizes` - Size for each queue (empty = use default 256)
    ///
    /// # Returns
    ///
    /// A new VhostUserDevice or an error if connection fails.
    pub fn new(
        socket_path: impl AsRef<std::path::Path>,
        device_type: u32,
        device_name: String,
        num_queues: u16,
        queue_sizes: &[u16],
        gpu_display: Option<DisplayInfo>,
        display_backend: Option<DisplayBackend<'static>>,
    ) -> IoResult<Self> {
        debug!(
            "Connecting to vhost-user backend at {}",
            socket_path.as_ref().display()
        );

        // Connect to the vhost-user backend
        let stream = UnixStream::connect(socket_path)?;
        // NOTE: `num_queues` could be 0 here, but this is actually fine
        // because if `VhostUserProtocolFeatures::MQ` is supported the negotiated
        // value will be used automatically by Frontend
        let mut frontend = Frontend::from_stream(stream, num_queues as u64);

        // Get available features from backend
        let avail_features = frontend.get_features().map_err(io::Error::other)?;

        debug!("{}: backend features: 0x{:x}", device_name, avail_features);

        // Strip the vhost specific bit to leave only standard virtio features
        let has_protocol_features = avail_features & VHOST_USER_F_PROTOCOL_FEATURES != 0;
        let avail_features = avail_features & !VHOST_USER_F_PROTOCOL_FEATURES;

        let mut negotiated_protocol_features = VhostUserProtocolFeatures::empty();

        if has_protocol_features {
            let protocol_features = frontend.get_protocol_features().map_err(io::Error::other)?;

            if protocol_features.contains(VhostUserProtocolFeatures::CONFIG) {
                negotiated_protocol_features |= VhostUserProtocolFeatures::CONFIG;
            }
            if protocol_features.contains(VhostUserProtocolFeatures::MQ) {
                negotiated_protocol_features |= VhostUserProtocolFeatures::MQ;
            }
            if protocol_features.contains(VhostUserProtocolFeatures::BACKEND_REQ) {
                negotiated_protocol_features |= VhostUserProtocolFeatures::BACKEND_REQ;
            }
            if protocol_features.contains(VhostUserProtocolFeatures::SHMEM) {
                negotiated_protocol_features |= VhostUserProtocolFeatures::SHMEM;
            }

            frontend
                .set_protocol_features(negotiated_protocol_features)
                .map_err(io::Error::other)?;
        }

        // Determine actual queue count - may require protocol feature negotiation
        let actual_num_queues = if num_queues == 0 {
            if has_protocol_features {
                let backend_queue_num = frontend.get_queue_num().map_err(io::Error::other)?;

                debug!(
                    "{}: backend reports {} queues available",
                    device_name, backend_queue_num
                );

                backend_queue_num as usize
            } else {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "Backend doesn't support protocol features, must specify queue count",
                ));
            }
        } else {
            num_queues as usize
        };

        let default_size = queue_sizes.last().copied().unwrap_or(256);
        let queue_configs: Vec<_> = (0..actual_num_queues)
            .map(|i| {
                let size = queue_sizes.get(i).copied().unwrap_or(default_size);
                QueueConfig::new(size)
            })
            .collect();

        let gpu_display_info = if device_type == VIRTIO_ID_GPU {
            Some(gpu_display.unwrap_or_else(|| DisplayInfo::new(1024, 768)))
        } else {
            None
        };

        Ok(Self {
            frontend: Arc::new(Mutex::new(frontend)),
            device_type,
            device_name,
            queue_configs,
            avail_features,
            has_protocol_features,
            negotiated_protocol_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(EFD_NONBLOCK)?,
            vring_call_event: None,
            gpu_socket: None,
            gpu_display_info,
            shm_region: None,
            backend_req_handler: None,
            display_backend: if device_type == VIRTIO_ID_GPU {
                display_backend
            } else {
                None
            },
            display_instance: None,
        })
    }

    pub fn set_shm_region(&mut self, region: VirtioShmRegion) {
        self.shm_region = Some(region);
    }

    /// Activate the vhost-user device by setting up memory and vrings.
    fn activate_vhost_user(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[DeviceQueue],
    ) -> IoResult<()> {
        let mut frontend = self.frontend.lock().unwrap();

        debug!("{}: activating vhost-user device", self.device_name);

        // Combine guest-acked features with backend-only features (QEMU approach)
        let backend_feature_bits = if self.has_protocol_features {
            self.acked_features | VHOST_USER_F_PROTOCOL_FEATURES
        } else {
            self.acked_features
        };

        frontend.set_owner().map_err(io::Error::other)?;

        // Set up the GPU socket before vhost activation - the backend uses it to send
        // GPU protocol messages (GET_DISPLAY_INFO, GET_EDID, SCANOUT, etc.)
        if self.device_type == VIRTIO_ID_GPU {
            let (our_end, backend_end) = UnixStream::pair().map_err(|e| {
                error!(
                    "{}: failed to create GPU socketpair: {}",
                    self.device_name, e
                );
                io::Error::other(e)
            })?;

            // GPU_SET_SOCKET is a one-way message - no ACK expected from backend
            send_gpu_set_socket(frontend.as_raw_fd(), backend_end.as_raw_fd()).map_err(|e| {
                error!("{}: failed to send GPU_SET_SOCKET: {}", self.device_name, e);
                e
            })?;
            drop(backend_end);
            self.gpu_socket = Some(our_end);

            debug!("{}: GPU socket configured", self.device_name);
        }

        // Set up backend request channel for shmem_map/shmem_unmap
        if self
            .negotiated_protocol_features
            .contains(VhostUserProtocolFeatures::BACKEND_REQ)
        {
            let inner = BackendReqInner {
                shm_region: self.shm_region.clone(),
                device_name: self.device_name.clone(),
            };
            let handler = FrontendReqHandler::new(Arc::new(Mutex::new(inner)))
                .map_err(|e| io::Error::other(format!("FrontendReqHandler::new: {e}")))?;

            let tx_fd = BorrowedFd(handler.get_tx_raw_fd());
            frontend
                .set_backend_request_fd(&tx_fd)
                .map_err(|e| io::Error::other(format!("set_backend_request_fd: {e}")))?;

            debug!("{}: backend request channel established", self.device_name);
            self.backend_req_handler = Some(handler);
        }

        // Can't use from_guest_region(): vhost 0.17 expects vm-memory 0.18 types.
        let regions: Vec<VhostUserMemoryRegionInfo> = mem
            .iter()
            .filter_map(|region| {
                let file_offset = region.file_offset()?;
                Some(VhostUserMemoryRegionInfo {
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len(),
                    userspace_addr: region.as_ptr() as u64,
                    mmap_offset: file_offset.start(),
                    mmap_handle: file_offset.file().as_raw_fd(),
                })
            })
            .collect();

        debug!(
            "{}: sharing {} file-backed regions with backend",
            self.device_name,
            regions.len()
        );

        frontend.set_mem_table(&regions).map_err(|e| {
            error!("{}: set_mem_table failed: {:?}", self.device_name, e);
            io::Error::other(e)
        })?;

        // If protocol features not negotiated, this triggers automatic ring enabling
        frontend
            .set_features(backend_feature_bits)
            .map_err(io::Error::other)?;

        let vring_call_event = EventFd::new(EFD_NONBLOCK)?;

        for (queue_index, device_queue) in queues.iter().enumerate() {
            let queue = &device_queue.queue;

            frontend
                .set_vring_num(queue_index, queue.actual_size())
                .map_err(io::Error::other)?;

            // Set vring base
            frontend
                .set_vring_base(queue_index, 0)
                .map_err(io::Error::other)?;

            // Vring addresses in queue are GPAs, but vhost-user protocol expects VMM VAs
            let desc_table_gpa = queue.desc_table.0;
            let avail_ring_gpa = queue.avail_ring.0;
            let used_ring_gpa = queue.used_ring.0;

            let desc_table_vmm =
                mem.get_host_address(Address::new(desc_table_gpa))
                    .map_err(|_| {
                        io::Error::new(
                            ErrorKind::InvalidInput,
                            format!("GPA 0x{:x} not found in any memory region", desc_table_gpa),
                        )
                    })? as u64;
            let avail_ring_vmm =
                mem.get_host_address(Address::new(avail_ring_gpa))
                    .map_err(|_| {
                        io::Error::new(
                            ErrorKind::InvalidInput,
                            format!("GPA 0x{:x} not found in any memory region", avail_ring_gpa),
                        )
                    })? as u64;
            let used_ring_vmm = mem
                .get_host_address(Address::new(used_ring_gpa))
                .map_err(|_| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("GPA 0x{:x} not found in any memory region", used_ring_gpa),
                    )
                })? as u64;

            let vring_config = VringConfigData {
                flags: 0,
                queue_max_size: queue.get_max_size(),
                queue_size: queue.actual_size(),
                desc_table_addr: desc_table_vmm,
                used_ring_addr: used_ring_vmm,
                avail_ring_addr: avail_ring_vmm,
                log_addr: None,
            };

            frontend
                .set_vring_addr(queue_index, &vring_config)
                .map_err(|e| {
                    error!("{}: set_vring_addr failed: {:?}", self.device_name, e);
                    io::Error::other(e)
                })?;

            // Create vhost-compatible EventFd from the raw fd
            // (bridges krun_utils::EventFd with vmm_sys_util::EventFd type mismatch)
            let kick_fd = unsafe { VhostEventFd::from_raw_fd(device_queue.event.as_raw_fd()) };
            frontend
                .set_vring_kick(queue_index, &kick_fd)
                .map_err(|e| {
                    error!("{}: set_vring_kick failed: {:?}", self.device_name, e);
                    io::Error::other(e)
                })?;
            std::mem::forget(kick_fd); // Don't close the fd twice

            let call_fd = unsafe { VhostEventFd::from_raw_fd(vring_call_event.as_raw_fd()) };
            frontend
                .set_vring_call(queue_index, &call_fd)
                .map_err(|e| {
                    error!("{}: set_vring_call failed: {:?}", self.device_name, e);
                    io::Error::other(e)
                })?;
            std::mem::forget(call_fd); // Don't close the fd twice

            // Per QEMU vhost.c: when VHOST_USER_F_PROTOCOL_FEATURES is not negotiated,
            // the rings start directly in the enabled state, and set_vring_enable will fail.
            if self.has_protocol_features {
                frontend
                    .set_vring_enable(queue_index, true)
                    .map_err(io::Error::other)?;
            } else {
                debug!(
                    "{}: vring {} already enabled (protocol features not negotiated)",
                    self.device_name, queue_index
                );
            }
        }

        self.vring_call_event = Some(vring_call_event);

        debug!(
            "{}: vhost-user device activated successfully",
            self.device_name
        );

        Ok(())
    }
}

impl VirtioDevice for VhostUserDevice {
    fn device_type(&self) -> u32 {
        self.device_type
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_configs
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Fetch config from backend on every read (same as QEMU/crosvm)
        // No caching to avoid invalidation issues
        if self.has_protocol_features
            && let Ok(mut frontend) = self.frontend.lock()
        {
            match frontend.get_config(
                offset as u32,
                data.len() as u32,
                VhostUserConfigFlags::empty(),
                data,
            ) {
                Ok((_, returned_buf)) => {
                    if data.len() <= returned_buf.len() {
                        data.copy_from_slice(&returned_buf[..data.len()]);
                        debug!(
                            "{}: read {} bytes from config at offset {}",
                            self.device_name,
                            data.len(),
                            offset
                        );
                        return;
                    }
                }
                Err(e) => {
                    debug!(
                        "{}: failed to read config from backend: {:?}",
                        self.device_name, e
                    );
                }
            }
        }

        debug!(
            "{}: config read at offset {} returning zeros (backend not available)",
            self.device_name, offset
        );
        data.fill(0);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if !self.has_protocol_features {
            debug!(
                "{}: config write at offset {} skipped (no protocol features)",
                self.device_name, offset
            );
            return;
        }

        if let Ok(mut frontend) = self.frontend.lock() {
            match frontend.set_config(offset as u32, VhostUserConfigFlags::empty(), data) {
                Ok(_) => {
                    debug!(
                        "{}: wrote {} bytes to config at offset {}",
                        self.device_name,
                        data.len(),
                        offset
                    );
                }
                Err(e) => {
                    warn!(
                        "{}: failed to write config at offset {}: {:?}",
                        self.device_name, offset, e
                    );
                }
            }
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if let Err(e) = self.activate_vhost_user(&mem, &queues) {
            error!(
                "{}: failed to activate vhost-user device: {}",
                self.device_name, e
            );
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem, interrupt);

        if let Err(e) = self.activate_evt.write(1) {
            error!(
                "{}: failed to write activate event: {}",
                self.device_name, e
            );
            return Err(ActivateError::BadActivate);
        }

        Ok(())
    }

    fn is_activated(&self) -> bool {
        matches!(self.device_state, DeviceState::Activated(_, _))
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        self.shm_region.as_ref()
    }

    fn reset(&mut self) -> bool {
        debug!("{}: resetting vhost-user device", self.device_name);

        // Disable all vrings
        if let Ok(mut frontend) = self.frontend.lock() {
            for queue_index in 0..self.queue_configs.len() {
                if let Err(e) = frontend.set_vring_enable(queue_index, false) {
                    debug!(
                        "{}: failed to disable vring {} during reset: {}",
                        self.device_name, queue_index, e
                    );
                }
            }
        }

        self.vring_call_event = None;
        self.gpu_socket = None;
        self.backend_req_handler = None;
        self.device_state = DeviceState::Inactive;
        true
    }
}

impl VhostUserDevice {
    fn handle_gpu_socket_event(&mut self, event: &EpollEvent) {
        debug!("{}: GPU socket event received", self.device_name);
        let event_set = event.event_set();

        if event_set.contains(EventSet::HANG_UP) || event_set.contains(EventSet::ERROR) {
            warn!(
                "{}: GPU backend disconnected, closing socket",
                self.device_name
            );
            self.gpu_socket = None;
            return;
        }

        if !event_set.contains(EventSet::IN) {
            warn!(
                "{}: GPU socket unexpected event {event_set:?}",
                self.device_name
            );
            return;
        }

        if let Some(ref mut gpu_socket) = self.gpu_socket {
            // TODO: vhost crate should provide GpuSocket::read_message() API
            // VhostUserGpuMsgHeader exists internally but isn't exposed
            let mut header = [0u32; 3];
            // SAFETY: header is a local [u32; 3] array, valid for the duration of this block.
            let header_bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    header.as_mut_ptr() as *mut u8,
                    std::mem::size_of_val(&header),
                )
            };

            if let Err(e) = gpu_socket.read_exact(header_bytes) {
                error!(
                    "{}: failed to read GPU message header: {}",
                    self.device_name, e
                );
                self.gpu_socket = None;
                return;
            }

            let request = header[0];
            let flags = header[1];
            let size = header[2];

            let mut payload = vec![0u8; size as usize];
            if size > 0
                && let Err(e) = gpu_socket.read_exact(&mut payload)
            {
                error!(
                    "{}: failed to read GPU message payload: {}",
                    self.device_name, e
                );
                self.gpu_socket = None;
                return;
            }

            self.handle_gpu_message(request, flags, &payload);
        }
    }

    fn handle_gpu_message(&mut self, request: u32, _flags: u32, payload: &[u8]) {
        debug!(
            "{}: GPU message: request={}, payload_len={}",
            self.device_name,
            request,
            payload.len()
        );
        match GpuBackendReq::try_from(request) {
            Ok(GpuBackendReq::GET_DISPLAY_INFO) => self.send_gpu_display_info(request),
            Ok(GpuBackendReq::GET_EDID) => self.send_gpu_edid(request, payload),
            Ok(GpuBackendReq::SCANOUT) => self.handle_gpu_scanout(payload),
            Ok(GpuBackendReq::UPDATE) => self.handle_gpu_update(payload),
            _ => {
                warn!("{}: unhandled GPU message: {}", self.device_name, request);
            }
        }
    }

    /// Helper to send GPU protocol responses
    /// TODO: This should be part of vhost crate's GPU message handling
    fn send_gpu_response<T>(&mut self, request: u32, response: &T) -> IoResult<()> {
        if self.gpu_socket.is_none() {
            return Ok(());
        }

        let msg_header = [
            request,
            VhostUserGpuHeaderFlag::REPLY.bits(),
            std::mem::size_of::<T>() as u32,
        ];
        // SAFETY: msg_header is a local [u32; 3] array, valid for the duration of this block.
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                msg_header.as_ptr() as *const u8,
                std::mem::size_of_val(&msg_header),
            )
        };
        // SAFETY: response is a reference to a POD type T, valid and aligned for size_of::<T>() bytes.
        let response_bytes = unsafe {
            std::slice::from_raw_parts(response as *const T as *const u8, std::mem::size_of::<T>())
        };

        let result = self
            .gpu_socket
            .as_mut()
            .unwrap()
            .write_all(header_bytes)
            .and_then(|_| self.gpu_socket.as_mut().unwrap().write_all(response_bytes));

        if result.is_err() {
            self.gpu_socket = None;
        }
        result
    }

    fn send_gpu_display_info(&mut self, request: u32) {
        const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

        let mut display_info = VirtioGpuRespDisplayInfo::default();
        display_info.hdr.type_ = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;

        display_info.pmodes[0] = VirtioGpuDisplayOne {
            r: VirtioGpuRect {
                x: 0,
                y: 0,
                width: self.gpu_display_info.as_ref().map_or(0, |d| d.width),
                height: self.gpu_display_info.as_ref().map_or(0, |d| d.height),
            },
            enabled: 1,
            flags: 0,
        };

        if let Err(e) = self.send_gpu_response(request, &display_info) {
            error!("{}: failed to send DISPLAY_INFO: {}", self.device_name, e);
        }
    }

    fn get_display_instance(&mut self) -> Option<&mut DisplayBackendInstance> {
        if self.display_instance.is_none()
            && let Some(backend) = self.display_backend.take()
        {
            match backend.create_instance() {
                Ok(instance) => self.display_instance = Some(EpollThreadLocal(instance)),
                Err(e) => {
                    error!(
                        "{}: failed to create display instance: {e}",
                        self.device_name
                    );
                    return None;
                }
            }
        }
        self.display_instance.as_deref_mut()
    }

    fn handle_gpu_scanout(&mut self, payload: &[u8]) {
        let header_size = std::mem::size_of::<VhostUserGpuScanout>();
        if payload.len() < header_size {
            error!("{}: SCANOUT payload too short", self.device_name);
            return;
        }
        let mut scanout = VhostUserGpuScanout::default();
        scanout
            .as_mut_slice()
            .copy_from_slice(&payload[..header_size]);

        let scanout_id = scanout.scanout_id;

        // Validate scanout ID - frontend only advertises scanout 0
        if scanout_id != 0 {
            error!(
                "{}: invalid scanout_id {} (only 0 is supported)",
                self.device_name, scanout_id
            );
            return;
        }

        if scanout.width == 0 || scanout.height == 0 {
            debug!("{}: disabling scanout {scanout_id}", self.device_name);
            if let Some(display) = self.get_display_instance()
                && let Err(e) = display.disable_scanout(scanout_id)
            {
                error!("{}: disable_scanout failed: {e}", self.device_name);
            }
            return;
        }

        debug!(
            "{}: configuring scanout {scanout_id} ({}x{})",
            self.device_name, scanout.width, scanout.height
        );

        let display_info = self.gpu_display_info.as_ref();
        let display_width = display_info.map_or(scanout.width, |d| d.width);
        let display_height = display_info.map_or(scanout.height, |d| d.height);

        if let Some(display) = self.get_display_instance()
            && let Err(e) = display.configure_scanout(
                scanout_id,
                display_width,
                display_height,
                scanout.width,
                scanout.height,
                ResourceFormat::XRGB,
            )
        {
            error!("{}: configure_scanout failed: {e}", self.device_name);
        }
    }

    fn handle_gpu_update(&mut self, payload: &[u8]) {
        let header_size = std::mem::size_of::<VhostUserGpuUpdate>();
        if payload.len() < header_size {
            error!("{}: UPDATE payload too short", self.device_name);
            return;
        }
        let mut update = VhostUserGpuUpdate::default();
        update
            .as_mut_slice()
            .copy_from_slice(&payload[..header_size]);

        let pixel_data = &payload[header_size..];
        let scanout_id = update.scanout_id;
        let bytes_per_pixel = ResourceFormat::BYTES_PER_PIXEL;
        let update_x = update.x as usize;
        let update_y = update.y as usize;
        let update_width = update.width as usize;
        let update_height = update.height as usize;

        if scanout_id != 0 {
            error!(
                "{}: invalid scanout_id {} (only 0 is supported)",
                self.device_name, scanout_id
            );
            return;
        }

        let expected_len = update_width * update_height * bytes_per_pixel;
        if pixel_data.len() < expected_len {
            error!("{}: UPDATE pixel data too short", self.device_name);
            return;
        }

        let scanout_width = self
            .gpu_display_info
            .as_ref()
            .map_or(update_width, |d| d.width as usize);
        let scanout_height = self
            .gpu_display_info
            .as_ref()
            .map_or(update_height, |d| d.height as usize);

        if update_x + update_width > scanout_width || update_y + update_height > scanout_height {
            error!(
                "{}: UPDATE rectangle out of bounds: ({},{}) {}x{} exceeds scanout {}x{}",
                self.device_name,
                update_x,
                update_y,
                update_width,
                update_height,
                scanout_width,
                scanout_height
            );
            return;
        }

        let Some(display) = self.get_display_instance() else {
            return;
        };

        let (frame_id, buffer) = match display.alloc_frame(scanout_id) {
            Ok(frame) => frame,
            Err(e) => {
                error!("{}: alloc_frame failed: {e}", self.device_name);
                return;
            }
        };

        // UPDATE carries a rectangular region (x, y, width, height). For partial updates,
        // pixel_data contains only the update rectangle, packed row-by-row. Copy each row
        // into the correct position in the full-frame buffer.
        for row in 0..update_height {
            let dst_offset = ((update_y + row) * scanout_width + update_x) * bytes_per_pixel;
            let src_offset = row * update_width * bytes_per_pixel;
            let row_bytes = update_width * bytes_per_pixel;

            buffer[dst_offset..dst_offset + row_bytes]
                .copy_from_slice(&pixel_data[src_offset..src_offset + row_bytes]);
        }

        if let Err(e) = display.present_frame(scanout_id, frame_id, None) {
            error!("{}: present_frame failed: {e}", self.device_name);
        }
    }

    fn send_gpu_edid(&mut self, request: u32, _payload: &[u8]) {
        const VIRTIO_GPU_RESP_OK_EDID: u32 = 0x1104;

        // EDID reflects the display (monitor) capabilities, not the current guest scanout.
        // The same EDID is returned for all scanout IDs the backend queries.
        let Some(ref display_info) = self.gpu_display_info else {
            return;
        };
        let edid_bytes = display_info.edid_bytes();

        let mut edid_resp = VirtioGpuRespGetEdid::default();
        edid_resp.hdr.type_ = VIRTIO_GPU_RESP_OK_EDID;
        edid_resp.size = edid_bytes.len() as u32;

        let copy_len = edid_bytes.len().min(edid_resp.edid.len());
        edid_resp.edid[..copy_len].copy_from_slice(&edid_bytes[..copy_len]);

        if let Err(e) = self.send_gpu_response(request, &edid_resp) {
            error!("{}: failed to send EDID: {}", self.device_name, e);
        }
    }

    fn handle_vring_call_event(&mut self, event: &EpollEvent) {
        debug!("{}: vring call event received", self.device_name);

        let event_set = event.event_set();
        if !event_set.contains(EventSet::IN) {
            warn!(
                "{}: vring call unexpected event {event_set:?}",
                self.device_name
            );
            return;
        }

        if let Some(ref vring_call_event) = self.vring_call_event {
            if let Err(e) = vring_call_event.read() {
                error!(
                    "{}: failed to read vring_call_event: {}",
                    self.device_name, e
                );
                return;
            }
        } else {
            error!("{}: vring_call_event is None", self.device_name);
            return;
        }

        if let DeviceState::Activated(_, ref interrupt) = self.device_state {
            debug!(
                "{}: interrupt received from backend, signaling guest",
                self.device_name
            );
            interrupt.signal_used_queue();
        }
    }

    fn handle_backend_req_event(&mut self, event: &EpollEvent) {
        let event_set = event.event_set();

        if event_set.contains(EventSet::HANG_UP) || event_set.contains(EventSet::ERROR) {
            warn!("{}: backend request channel disconnected", self.device_name);
            self.backend_req_handler = None;
            return;
        }

        if !event_set.contains(EventSet::IN) {
            return;
        }

        if let Some(ref mut handler) = self.backend_req_handler
            && let Err(e) = handler.handle_request()
        {
            error!(
                "{}: failed to handle backend request: {}",
                self.device_name, e
            );
        }
    }

    fn handle_activate_event(&mut self, event_manager: &mut EventManager) {
        debug!("{}: activate event", self.device_name);

        if let Err(e) = self.activate_evt.read() {
            error!(
                "{}: failed to consume activate event: {}",
                self.device_name, e
            );
        }

        if let Some(ref vring_call_event) = self.vring_call_event {
            let self_subscriber = event_manager
                .subscriber(self.activate_evt.as_raw_fd())
                .unwrap();

            event_manager
                .register(
                    vring_call_event.as_raw_fd(),
                    EpollEvent::new(EventSet::IN, vring_call_event.as_raw_fd() as u64),
                    self_subscriber.clone(),
                )
                .unwrap_or_else(|e| {
                    error!(
                        "{}: failed to register vring_call_event with event manager: {e:?}",
                        self.device_name
                    );
                });

            // Register GPU socket for receiving backend messages
            if let Some(ref gpu_socket) = self.gpu_socket {
                event_manager
                    .register(
                        gpu_socket.as_raw_fd(),
                        EpollEvent::new(EventSet::IN, gpu_socket.as_raw_fd() as u64),
                        self_subscriber.clone(),
                    )
                    .unwrap_or_else(|e| {
                        error!(
                            "{}: failed to register GPU socket with event manager: {e:?}",
                            self.device_name
                        );
                    });
                debug!(
                    "{}: GPU socket registered with event manager",
                    self.device_name
                );
            }

            // Register backend request channel for shmem_map/shmem_unmap
            if let Some(ref handler) = self.backend_req_handler {
                event_manager
                    .register(
                        handler.as_raw_fd(),
                        EpollEvent::new(EventSet::IN, handler.as_raw_fd() as u64),
                        self_subscriber.clone(),
                    )
                    .unwrap_or_else(|e| {
                        error!(
                            "{}: failed to register backend_req_handler with event manager: {e:?}",
                            self.device_name
                        );
                    });
                debug!(
                    "{}: backend request channel registered with event manager",
                    self.device_name
                );
            }
        } else {
            error!(
                "{}: vring_call_event is None during activation",
                self.device_name
            );
        }

        // Unregister activate_evt as it's only needed once
        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!(
                    "{}: failed to unregister activate event: {e:?}",
                    self.device_name
                );
            });
    }
}

impl Subscriber for VhostUserDevice {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let activate_evt_fd = self.activate_evt.as_raw_fd();
        let vring_call_fd = self
            .vring_call_event
            .as_ref()
            .map(|e| e.as_raw_fd())
            .unwrap_or(-1);
        let gpu_socket_fd = self
            .gpu_socket
            .as_ref()
            .map(|s| s.as_raw_fd())
            .unwrap_or(-1);
        let backend_req_fd = self
            .backend_req_handler
            .as_ref()
            .map(|h| h.as_raw_fd())
            .unwrap_or(-1);

        if self.is_activated() {
            match source {
                _ if source == vring_call_fd => self.handle_vring_call_event(event),
                _ if source == gpu_socket_fd => self.handle_gpu_socket_event(event),
                _ if source == backend_req_fd => self.handle_backend_req_event(event),
                _ if source == activate_evt_fd => self.handle_activate_event(event_manager),
                _ => warn!(
                    "{}: unexpected event received: {source:?}",
                    self.device_name
                ),
            }
        } else if source == activate_evt_fd {
            // Allow activation event even before device is activated
            self.handle_activate_event(event_manager);
        } else {
            warn!(
                "{}: device not yet activated, spurious event received: {source:?}",
                self.device_name
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.activate_evt.as_raw_fd() as u64,
        )]
    }
}
