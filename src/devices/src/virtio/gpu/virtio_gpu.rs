use std::collections::BTreeMap;
use std::env;
use std::io::IoSliceMut;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::super::Queue as VirtQueue;
use super::protocol::GpuResponse::*;
use super::protocol::virtio_gpu_update_cursor;
use super::protocol::{
    GpuResponse, GpuResponsePlaneInfo, VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE,
    VIRTIO_GPU_BLOB_MEM_HOST3D, VIRTIO_GPU_MAX_SCANOUTS, VirtioGpuResult,
};
#[cfg(target_os = "macos")]
use crossbeam_channel::{Sender, unbounded};
use krun_display::{
    DisplayBackend, DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendInstance,
    Rect, ResourceFormat,
};
use libc::c_void;
#[cfg(target_os = "macos")]
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_APPLE;
#[cfg(all(feature = "virgl_resource_map2", target_os = "linux"))]
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_DMABUF;
#[cfg(all(not(feature = "virgl_resource_map2"), target_os = "linux"))]
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD;
#[cfg(all(feature = "virgl_resource_map2", target_os = "linux"))]
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_SHM;
#[cfg(target_os = "linux")]
use rutabaga_gfx::{
    RUTABAGA_CHANNEL_TYPE_PW, RUTABAGA_CHANNEL_TYPE_X11, RUTABAGA_MAP_ACCESS_MASK,
    RUTABAGA_MAP_ACCESS_READ, RUTABAGA_MAP_ACCESS_RW, RUTABAGA_MAP_ACCESS_WRITE,
    RutabagaFromRawDescriptor,
};
use rutabaga_gfx::{
    RUTABAGA_CHANNEL_TYPE_WAYLAND, RUTABAGA_MAP_CACHE_MASK, ResourceCreate3D, ResourceCreateBlob,
    Rutabaga, RutabagaBuilder, RutabagaChannel, RutabagaDescriptor, RutabagaFence,
    RutabagaFenceHandler, RutabagaIovec, Transfer3D,
};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, VolatileSlice};

use super::{GpuError, Result};
use crate::virtio::display::DisplayInfo;
use crate::virtio::fs::ExportTable;
use crate::virtio::gpu::protocol::VIRTIO_GPU_FLAG_INFO_RING_IDX;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

fn sglist_to_rutabaga_iovecs(
    vecs: &[(GuestAddress, usize)],
    mem: &GuestMemoryMmap,
) -> Result<Vec<RutabagaIovec>> {
    if vecs
        .iter()
        .any(|&(addr, len)| mem.get_slice(addr, len).is_err())
    {
        return Err(GpuError::GuestMemory);
    }

    let mut rutabaga_iovecs: Vec<RutabagaIovec> = Vec::new();
    for &(addr, len) in vecs {
        let slice = mem.get_slice(addr, len).unwrap();
        rutabaga_iovecs.push(RutabagaIovec {
            base: slice.ptr_guard_mut().as_ptr() as *mut c_void,
            len,
        });
    }
    Ok(rutabaga_iovecs)
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum VirtioGpuRing {
    Global,
    ContextSpecific { ctx_id: u32, ring_idx: u8 },
}

struct FenceDescriptor {
    ring: VirtioGpuRing,
    fence_id: u64,
    desc_index: u16,
    len: u32,
}

#[derive(Default)]
pub struct FenceState {
    descs: Vec<FenceDescriptor>,
    completed_fences: BTreeMap<VirtioGpuRing, u64>,
}

#[derive(Copy, Clone, Debug, Default)]
struct AssociatedScanouts(u32);

impl AssociatedScanouts {
    fn enable(&mut self, scanout_id: u32) {
        self.0 |= 1 << scanout_id;
    }

    fn disable(&mut self, scanout_id: u32) {
        self.0 ^= 1 << scanout_id;
    }

    const fn has_any_enabled(self) -> bool {
        self.0 != 0
    }

    fn iter_enabled(self) -> impl Iterator<Item = u32> {
        (0..VIRTIO_GPU_MAX_SCANOUTS).filter(move |i| ((self.0 >> i) & 1) == 1)
    }
}

#[derive(Copy, Clone)]
struct VirtioGpuResource {
    id: u32,
    width: u32,
    height: u32,
    scanouts: AssociatedScanouts,
    format: Option<ResourceFormat>,
    size: u64, // only for blob resources
    shmem_offset: Option<u64>,
    rutabaga_external_mapping: bool,
}

impl VirtioGpuResource {
    /// Creates a new VirtioGpuResource with the given metadata.  Width and height are used by the
    /// display, while size is useful for hypervisor mapping.
    pub fn new(
        resource_id: u32,
        width: u32,
        height: u32,
        format: Option<ResourceFormat>,
        size: u64,
    ) -> VirtioGpuResource {
        VirtioGpuResource {
            id: resource_id,
            width,
            height,
            scanouts: Default::default(),
            size,
            format,
            shmem_offset: None,
            rutabaga_external_mapping: false,
        }
    }
}

pub struct VirtioGpuScanout {
    resource_id: u32,
    width: u32,
    height: u32,
    /// Set when the scanout holds a blob resource, so a later RESOURCE_FLUSH
    /// can be presented through the renderer instead of the 2D read path.
    blob: Option<BlobScanout>,
}

/// Geometry of a blob resource being put on a scanout.
#[derive(Clone, Copy)]
pub struct BlobScanout {
    pub ctx_id: u32,
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub stride: u32,
    pub offset: u32,
}

/// How a blob's rows map onto a display frame.
struct BlobRows {
    src_stride: usize,
    dst_stride: usize,
    height: usize,
    offset: usize,
}

/// Signature of the renderer's optional pixel readback.
type RendererReadPixels = unsafe extern "C" fn(u32, u32, *mut c_void, u32, u32, u32) -> i32;

/// Looks up the renderer's pixel readback, once.
///
/// Only a renderer that can read back a GPU-rendered image provides this, and
/// resolving it at runtime keeps this crate buildable and linkable against one
/// that does not.
fn renderer_read_resource_pixels() -> Option<RendererReadPixels> {
    static LOOKUP: std::sync::OnceLock<Option<RendererReadPixels>> = std::sync::OnceLock::new();
    *LOOKUP.get_or_init(|| unsafe {
        let name = b"virgl_renderer_read_resource_pixels\0";
        let sym = libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr() as *const libc::c_char);
        if sym.is_null() {
            None
        } else {
            Some(std::mem::transmute::<*mut c_void, RendererReadPixels>(sym))
        }
    })
}

/// Set from the fence handler when a render fence retires, so the display can
/// take a second look at the scanouts. A guest can flush a frame for scanout
/// before the render behind it has reached the host, so the read taken at the
/// flush shows the previous frame; re-reading once that render completes, which
/// is exactly when a fence retires, is what lets a lone change on a quiet
/// screen appear without waiting for the next unrelated redraw.
static SCANOUT_DIRTY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub struct VirtioGpu {
    rutabaga: Rutabaga,
    /// Keep re-presenting until this time; extended each time a render fence
    /// retires, so a frame that was not yet coherent on the first look is
    /// caught on a later one.
    represent_until: Option<std::time::Instant>,
    /// Rate-limits the re-present to a sane cadence.
    last_represent: Option<std::time::Instant>,
    resources: BTreeMap<u32, VirtioGpuResource>,
    fence_state: Arc<Mutex<FenceState>>,
    #[cfg(target_os = "macos")]
    map_sender: Sender<WorkerMessage>,
    scanouts: [Option<VirtioGpuScanout>; VIRTIO_GPU_MAX_SCANOUTS as usize],
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackendInstance,
}

impl VirtioGpu {
    fn create_fence_handler(
        mem: GuestMemoryMmap,
        queue_ctl: Arc<Mutex<VirtQueue>>,
        fence_state: Arc<Mutex<FenceState>>,
        interrupt: InterruptTransport,
    ) -> RutabagaFenceHandler {
        RutabagaFenceHandler::new(move |completed_fence: RutabagaFence| {
            debug!(
                "XXX - fence called: id={}, ring_idx={}",
                completed_fence.fence_id, completed_fence.ring_idx
            );

            let mut queue = queue_ctl.lock().unwrap();
            let mut fence_state = fence_state.lock().unwrap();
            let mut i = 0;

            let ring = match completed_fence.flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                0 => VirtioGpuRing::Global,
                _ => VirtioGpuRing::ContextSpecific {
                    ctx_id: completed_fence.ctx_id,
                    ring_idx: completed_fence.ring_idx,
                },
            };

            // A render just finished; a scanout flushed before it landed can now
            // be re-read to show that render. See SCANOUT_DIRTY.
            if !matches!(ring, VirtioGpuRing::Global) {
                SCANOUT_DIRTY.store(true, std::sync::atomic::Ordering::Release);
            }

            while i < fence_state.descs.len() {
                debug!("XXX - fence_id: {}", fence_state.descs[i].fence_id);
                if fence_state.descs[i].ring == ring
                    && fence_state.descs[i].fence_id <= completed_fence.fence_id
                {
                    let completed_desc = fence_state.descs.remove(i);
                    debug!(
                        "XXX - found fence: desc_index={}",
                        completed_desc.desc_index
                    );

                    if let Err(e) =
                        queue.add_used(&mem, completed_desc.desc_index, completed_desc.len)
                    {
                        error!("failed to add used elements to the queue: {e:?}");
                    }

                    interrupt.signal_used_queue();
                } else {
                    i += 1;
                }
            }
            // Update the last completed fence for this context.
            // Use max() to avoid a race where an out-of-order completion
            // (e.g., immediate-retire for fence N+1 followed by timeline
            // signal for fence N) would overwrite a higher fence_id with
            // a lower one, causing fence N+1 to be stuck forever.
            let entry = fence_state.completed_fences.entry(ring).or_insert(0);
            *entry = (*entry).max(completed_fence.fence_id);
        })
    }

    /// Start `virgl_render_server` as a subprocess and return a socket descriptor
    /// that virglrenderer will use to send GPU commands to it.
    ///
    /// Venus (Vulkan-over-virtio) requires a running render server: during
    /// `virgl_renderer_init`, the Venus init path calls the `get_server_fd`
    /// callback to obtain a connected socket.  If that returns -1 the Venus
    /// capset never initialises and every guest Vulkan call fails.
    ///
    /// We create a `SOCK_SEQPACKET` socketpair, hand one end to the server
    /// subprocess and return the other end as a `RutabagaDescriptor`; rutabaga
    /// stores it in the callback cookie so `get_server_fd` can return it.
    #[cfg(target_os = "linux")]
    fn start_render_server() -> Option<RutabagaDescriptor> {
        use std::os::unix::process::CommandExt;

        let server_path = env::var("VIRGL_RENDER_SERVER_PATH")
            .unwrap_or_else(|_| "/usr/lib/virglrenderer/virgl_render_server".to_string());

        if !std::path::Path::new(&server_path).exists() {
            warn!(
                "virgl_render_server not found at {server_path}: \
                 Venus Vulkan will be unavailable in the guest"
            );
            return None;
        }

        // socketpair without SOCK_CLOEXEC — both fds are inheritable by default.
        // We set CLOEXEC on client_fd ourselves so the subprocess doesn't get it;
        // server_fd stays inheritable so the server subprocess can use it.
        let mut fds = [0i32; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
        if ret != 0 {
            warn!(
                "socketpair for virgl_render_server failed: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }
        let [client_fd, server_fd] = fds;

        // Client fd: mark CLOEXEC so the subprocess doesn't inherit it.
        unsafe { libc::fcntl(client_fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        // server_fd: intentionally no CLOEXEC — the subprocess needs it.

        let server_fd_str = server_fd.to_string();

        // When SMOLVM_GPU_DEBUG is set, redirect the render server's stderr to
        // a debug log file so we can see Vulkan loader / driver messages.
        let stderr_stdio = if std::env::var_os("SMOLVM_GPU_DEBUG").is_some() {
            let log_path = std::env::temp_dir().join("virgl_render_server.log");
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)
                .map(|f| {
                    info!("virgl_render_server stderr → {}", log_path.display());
                    std::process::Stdio::from(f)
                })
                .unwrap_or_else(|_| std::process::Stdio::null())
        } else {
            std::process::Stdio::null()
        };

        // exec-ready pipe: both fds have O_CLOEXEC.  The child inherits
        // exec_write_fd across fork; the kernel closes it on exec().  The
        // parent's read(exec_read_fd) blocks until that happens, giving a
        // deterministic exec-completed signal before the Vulkan-init sleep.
        let mut exec_pipe_fds: [libc::c_int; 2] = [-1, -1];
        let pipe_ok = unsafe { libc::pipe2(exec_pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0;
        if !pipe_ok {
            warn!(
                "pipe2 for exec-ready detection failed: {}; \
                 falling back to fixed-duration sleep before Vulkan init",
                std::io::Error::last_os_error()
            );
        }
        let (exec_read_fd, exec_write_fd) = if pipe_ok {
            (exec_pipe_fds[0], exec_pipe_fds[1])
        } else {
            (-1, -1)
        };

        let mut spawn_cmd = std::process::Command::new(&server_path);
        spawn_cmd
            .arg("--socket-fd")
            .arg(&server_fd_str)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(stderr_stdio);
        if std::env::var_os("SMOLVM_GPU_DEBUG").is_some() {
            spawn_cmd.env("VK_LOADER_DEBUG", "all");
        }
        let spawn_result = unsafe {
            spawn_cmd
                .pre_exec(move || {
                    // In the child after fork, before exec: explicitly clear
                    // CLOEXEC on server_fd in case the Rust stdlib set it.
                    libc::fcntl(server_fd, libc::F_SETFD, 0);
                    // Close read end — child does not need it.
                    if exec_read_fd >= 0 {
                        libc::close(exec_read_fd);
                    }
                    // exec_write_fd is O_CLOEXEC; kernel closes it on exec().
                    Ok(())
                })
                .spawn()
        };

        // Close server_fd in the parent — the child has its own copy.
        unsafe { libc::close(server_fd) };
        // Parent closes write end; child's copy is the only one remaining.
        if exec_write_fd >= 0 {
            unsafe { libc::close(exec_write_fd) };
        }

        match spawn_result {
            Ok(_child) => {
                // Wait for exec: read blocks until child's exec_write_fd is closed
                // by the kernel on exec(), confirming the server binary has been
                // loaded.  No additional sleep is needed: the SOCK_SEQPACKET
                // socketpair is blocking, so virglrenderer's first message to the
                // server will block in recvmsg() until the server's event loop
                // processes it and responds.  If virglrenderer init still fails
                // (e.g., non-blocking I/O path), create_rutabaga retries with
                // exponential backoff.
                if exec_read_fd >= 0 {
                    let mut buf = [0u8; 1];
                    unsafe { libc::read(exec_read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
                    unsafe { libc::close(exec_read_fd) };
                }
                // The server runs as an orphaned subprocess; dropping `_child`
                // here does NOT kill it.  It will be reparented to PID 1 when
                // this process exits and will be reaped there.
                Some(unsafe { RutabagaDescriptor::from_raw_descriptor(client_fd) })
            }
            Err(e) => {
                if exec_read_fd >= 0 {
                    unsafe { libc::close(exec_read_fd) };
                }
                warn!("failed to start virgl_render_server: {e}");
                unsafe { libc::close(client_fd) };
                None
            }
        }
    }

    pub fn create_rutabaga(
        mem: GuestMemoryMmap,
        queue_ctl: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        fence_state: Arc<Mutex<FenceState>>,
        virgl_flags: u32,
        export_table: Option<ExportTable>,
    ) -> Option<Rutabaga> {
        let xdg_runtime_dir = match env::var("XDG_RUNTIME_DIR") {
            Ok(dir) => dir,
            Err(_) => "/run/user/1000".to_string(),
        };
        let wayland_display = match env::var("WAYLAND_DISPLAY") {
            Ok(display) => display,
            Err(_) => "wayland-0".to_string(),
        };
        let path = PathBuf::from(format!("{xdg_runtime_dir}/{wayland_display}"));

        #[allow(unused_mut)]
        let mut rutabaga_channels: Vec<RutabagaChannel> = vec![RutabagaChannel {
            base_channel: path,
            channel_type: RUTABAGA_CHANNEL_TYPE_WAYLAND,
        }];

        #[cfg(target_os = "linux")]
        if let Ok(x_display) = env::var("DISPLAY")
            && let Some(x_display) = x_display.strip_prefix(":")
        {
            let x_path = PathBuf::from(format!("/tmp/.X11-unix/X{x_display}"));
            rutabaga_channels.push(RutabagaChannel {
                base_channel: x_path,
                channel_type: RUTABAGA_CHANNEL_TYPE_X11,
            });
        }
        #[cfg(target_os = "linux")]
        if let Ok(pw_sock_dir) = env::var("PIPEWIRE_RUNTIME_DIR")
            .or_else(|_| env::var("XDG_RUNTIME_DIR"))
            .or_else(|_| env::var("USERPROFILE"))
        {
            let name = env::var("PIPEWIRE_REMOTE").unwrap_or_else(|_| "pipewire-0".to_string());
            let mut pw_path = PathBuf::from(pw_sock_dir);
            pw_path.push(name);
            rutabaga_channels.push(RutabagaChannel {
                base_channel: pw_path,
                channel_type: RUTABAGA_CHANNEL_TYPE_PW,
            });
        }
        let rutabaga_channels_opt = Some(rutabaga_channels);

        // VIRGL_RENDERER_THREAD_SYNC | VIRGL_RENDERER_USE_ASYNC_FENCE_CB.
        // Without these, virglrenderer only retires fences while processing
        // new guest commands, so a client that submits work and then blocks
        // on its final fence never gets it back. This device relies on the
        // async callback path (see create_fence_handler), so the flags are a
        // correctness requirement, not a tuning knob.
        #[cfg(target_os = "linux")]
        let virgl_flags = virgl_flags | (1 << 1) | (1 << 8);

        // KRUN_GPU_BACKEND=2d selects rutabaga's CPU 2D component instead of
        // virglrenderer. Display-only guests (software-rendered compositor
        // scanned out through virtio-gpu KMS) need working 2D resources,
        // transfers, and fences — on hosts whose virglrenderer build has no
        // GL/virgl support (e.g. the Venus-oriented macOS build) all of those
        // fail, so the desktop path selects the 2D component explicitly.
        let component = if env::var("KRUN_GPU_BACKEND").as_deref() == Ok("2d") {
            rutabaga_gfx::RutabagaComponentType::Rutabaga2D
        } else {
            rutabaga_gfx::RutabagaComponentType::VirglRenderer
        };

        let builder = RutabagaBuilder::new(component, virgl_flags, super::advertised_capset_mask())
            .set_rutabaga_channels(rutabaga_channels_opt);
        let builder = if let Some(export_table) = export_table {
            builder.set_export_table(export_table)
        } else {
            builder
        };

        let fence =
            Self::create_fence_handler(mem, queue_ctl.clone(), fence_state.clone(), interrupt);

        #[cfg(target_os = "linux")]
        let render_server_fd = if virgl_flags & (1 << 6) != 0 {
            Self::start_render_server()
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let render_server_fd: Option<rutabaga_gfx::RutabagaDescriptor> = None;

        // When using a render server, the first build() attempt may fail if
        // the server hasn't finished its Vulkan init yet.  Retry with
        // exponential backoff instead of a fixed sleep: this adapts to
        // fast and slow systems, and success means the server is actually
        // responding — no magic numbers.
        #[cfg(target_os = "linux")]
        let has_render_server = render_server_fd.is_some();

        // Dup the fd so we can retry if the first attempt fails (build()
        // consumes the fd by moving it into the virglrenderer cookie).
        #[cfg(target_os = "linux")]
        let retry_fds: Vec<RutabagaDescriptor> = if has_render_server {
            render_server_fd
                .as_ref()
                .map(|fd| {
                    let mut fds = Vec::new();
                    // Backoff schedule: 10ms, 50ms, 200ms.  Total worst-case
                    // wait ≈ 260ms, similar to the old fixed 300ms but adaptive.
                    for _ in 0..3 {
                        match fd.try_clone() {
                            Ok(dup) => fds.push(dup),
                            Err(_) => break,
                        }
                    }
                    fds
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        if let Ok(rutabaga) = builder.clone().build(fence.clone(), render_server_fd) {
            return Some(rutabaga);
        }

        #[cfg(target_os = "linux")]
        if has_render_server {
            const BACKOFF_NS: [i64; 3] = [10_000_000, 50_000_000, 200_000_000];
            for (i, retry_fd) in retry_fds.into_iter().enumerate() {
                let ns = BACKOFF_NS.get(i).copied().unwrap_or(200_000_000);
                warn!(
                    "virglrenderer init failed; retrying after {}ms...",
                    ns / 1_000_000
                );
                unsafe {
                    libc::nanosleep(
                        &libc::timespec {
                            tv_sec: 0,
                            tv_nsec: ns,
                        },
                        std::ptr::null_mut(),
                    );
                }
                if let Ok(rutabaga) = builder.clone().build(fence.clone(), Some(retry_fd)) {
                    return Some(rutabaga);
                }
            }
        }

        None
    }

    pub fn create_fallback_rutabaga(
        mem: GuestMemoryMmap,
        queue_ctl: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        fence_state: Arc<Mutex<FenceState>>,
    ) -> Option<Rutabaga> {
        const VIRGLRENDERER_NO_VIRGL: u32 = 1 << 7;
        let builder = RutabagaBuilder::new(
            rutabaga_gfx::RutabagaComponentType::VirglRenderer,
            VIRGLRENDERER_NO_VIRGL,
            0,
        );

        let fence =
            Self::create_fence_handler(mem, queue_ctl.clone(), fence_state.clone(), interrupt);
        builder.clone().build(fence.clone(), None).ok()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mem: GuestMemoryMmap,
        queue_ctl: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        virgl_flags: u32,
        #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
        export_table: Option<ExportTable>,
        displays: Box<[DisplayInfo]>,
        display_backend: DisplayBackend,
    ) -> Self {
        let fence_state = Arc::new(Mutex::new(Default::default()));

        let rutabaga = match Self::create_rutabaga(
            mem.clone(),
            queue_ctl.clone(),
            interrupt.clone(),
            fence_state.clone(),
            virgl_flags,
            export_table.clone(),
        ) {
            Some(rutabaga) => rutabaga,
            None => {
                warn!(
                    "Failed to create virtio_gpu backend with the requested parameters. Falling back to safe defaults."
                );
                Self::create_fallback_rutabaga(
                    mem.clone(),
                    queue_ctl.clone(),
                    interrupt.clone(),
                    fence_state.clone(),
                )
                .expect("Fallback rutabaga initialization failed")
            }
        };

        let display_backend = display_backend
            .create_instance()
            .expect("Failed to create display backend instance!");

        Self {
            rutabaga,
            resources: Default::default(),
            fence_state,
            represent_until: None,
            last_represent: None,
            scanouts: Default::default(),
            displays,
            display_backend,
            #[cfg(target_os = "macos")]
            map_sender,
        }
    }

    // Non-public function -- no doc comment needed!
    fn result_from_query(&mut self, resource_id: u32) -> GpuResponse {
        match self.rutabaga.query(resource_id) {
            Ok(query) => {
                let mut plane_info = Vec::with_capacity(4);
                for plane_index in 0..4 {
                    plane_info.push(GpuResponsePlaneInfo {
                        stride: query.strides[plane_index],
                        offset: query.offsets[plane_index],
                    });
                }
                let format_modifier = query.modifier;
                OkResourcePlaneInfo {
                    format_modifier,
                    plane_info,
                }
            }
            Err(_) => OkNoData,
        }
    }

    pub fn force_ctx_0(&self) {
        self.rutabaga.force_ctx_0()
    }

    /// Polls the virglrenderer component for pending events.
    ///
    /// Call this when the poll descriptor becomes readable so that render-server
    /// responses are processed and fence callbacks fire, unblocking the guest.
    // Used by the Linux virtio-gpu epoll worker; unused on macOS.
    #[allow(dead_code)]
    pub fn event_poll(&self) {
        self.rutabaga.event_poll();
    }

    /// Returns a descriptor that becomes readable when virglrenderer has pending
    /// events (render-server responses ready to be relayed to the guest).
    ///
    /// Returns `None` when virglrenderer is not the active component or when
    /// `virgl_renderer_get_poll_fd()` returns -1.
    #[allow(dead_code)]
    pub fn poll_descriptor(&self) -> Option<RutabagaDescriptor> {
        self.rutabaga.poll_descriptor()
    }

    /// Poll a specific virglrenderer context for pending completions.
    ///
    /// In render server mode, virglrenderer's global poll fd returns -1, so
    /// `event_poll()` has no effect on fence signaling.  Calling this for each
    /// active Venus context ID processes render-server responses and fires
    /// `write_context_fence` callbacks, advancing the seqno that Venus's cpu sync waits on.
    #[allow(dead_code)]
    pub fn context_event_poll(&self, ctx_id: u32) {
        self.rutabaga.context_event_poll(ctx_id);
    }

    /// Returns an epollable fd for per-context render-server completions.
    ///
    /// When `Some(fd)` is returned, the fd fires EPOLLIN when the render server
    /// has completed work for this context.  Register it with epoll and call
    /// `context_event_poll(ctx_id)` on the event.  Returns `None` if virglrenderer
    /// does not provide a per-context poll fd for this context.
    #[allow(dead_code)]
    pub fn context_poll_fd(&self, ctx_id: u32) -> Option<i32> {
        self.rutabaga.context_poll_fd(ctx_id)
    }

    /// Creates a 3D resource with the given properties and resource_id.
    pub fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .resource_create_3d(resource_id, resource_create_3d)?;

        let format = ResourceFormat::try_from(resource_create_3d.format).ok();
        if format.is_none() {
            debug!(
                "Unknown format {} for resource {}",
                resource_create_3d.format, resource_id
            );
        }

        let resource = VirtioGpuResource::new(
            resource_id,
            resource_create_3d.width,
            resource_create_3d.height,
            format,
            0,
        );

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Releases guest kernel reference on the resource.
    pub fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .remove(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        if resource.scanouts.has_any_enabled() {
            warn!(
                "The driver requested unref_resource, but resource {resource_id} has \
                     associated scanouts, refusing to delete the resource."
            );
            return Err(ErrUnspec);
        }

        if resource.rutabaga_external_mapping {
            self.rutabaga.unmap(resource_id)?;
        }

        self.rutabaga.unref_resource(resource_id)?;
        Ok(OkNoData)
    }

    pub fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        width: u32,
        height: u32,
    ) -> VirtioGpuResult {
        let scanout = self
            .scanouts
            .get_mut(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        // If a resource is already associated with this scanout, make sure to disable
        // this scanout for that resource
        if let Some(resource_id) = scanout.as_ref().map(|scanout| scanout.resource_id) {
            let resource = self
                .resources
                .get_mut(&resource_id)
                .ok_or(ErrInvalidResourceId)?;

            resource.scanouts.disable(scanout_id);
        }

        // Virtio spec: "The driver can use resource_id = 0 to disable a scanout."
        if resource_id == 0 {
            debug!("Disabling scanout {scanout_id:?}");
            *scanout = None;
            self.display_backend.disable_scanout(scanout_id)?;
            return Ok(OkNoData);
        }

        // Enable the scanout
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;
        resource.scanouts.enable(scanout_id);

        let Some(format) = resource.format else {
            warn!("Cannot use resource {resource_id} with unknown format for scanout");
            return Err(ErrUnspec);
        };

        let display_info = self
            .displays
            .get(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        self.display_backend.configure_scanout(
            scanout_id,
            display_info.width,
            display_info.height,
            width,
            height,
            format,
        )?;

        *scanout = Some(VirtioGpuScanout {
            resource_id,
            width,
            height,
            blob: None,
        });

        // Present the newly scanned-out buffer. A page-flipping compositor
        // changes the scanout resource every frame and may never send a
        // RESOURCE_FLUSH for it; the flip itself means "this buffer is now on
        // screen", so a frame must reach the display backend here or such
        // compositors are invisible.
        let resource = *self
            .resources
            .get(&resource_id)
            .ok_or(ErrInvalidResourceId)?;
        let (frame_id, buffer) = self.display_backend.alloc_frame(scanout_id)?;
        if let Err(e) = Self::read_2d_resource(&mut self.rutabaga, resource, buffer, width, height)
        {
            log::error!("Failed to read resource {resource_id} for scanout {scanout_id}: {e}");
            return Err(ErrUnspec);
        }
        self.display_backend
            .present_frame(scanout_id, frame_id, None)?;

        Ok(OkNoData)
    }

    /// Puts a blob resource on a scanout.
    ///
    /// A compositor that renders on the GPU allocates its output as a blob, so
    /// this is the path every accelerated desktop takes; without it the guest
    /// draws frames that never reach the display. Unlike a classic 2D resource
    /// a blob carries no format or geometry of its own, so the command supplies
    /// them.
    pub fn set_scanout_blob(&mut self, scanout_id: u32, blob: BlobScanout) -> VirtioGpuResult {
        let scanout = self
            .scanouts
            .get_mut(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        if let Some(resource) = scanout
            .as_ref()
            .map(|scanout| scanout.resource_id)
            .and_then(|previous| self.resources.get_mut(&previous))
        {
            resource.scanouts.disable(scanout_id);
        }

        if blob.resource_id == 0 {
            *scanout = None;
            self.display_backend.disable_scanout(scanout_id)?;
            return Ok(OkNoData);
        }

        let resource = self
            .resources
            .get_mut(&blob.resource_id)
            .ok_or(ErrInvalidResourceId)?;
        resource.scanouts.enable(scanout_id);
        resource.width = blob.width;
        resource.height = blob.height;

        let Ok(format) = ResourceFormat::try_from(blob.format) else {
            warn!("set_scanout_blob: unsupported format {}", blob.format);
            return Err(ErrUnspec);
        };
        resource.format = Some(format);

        let display_info = self
            .displays
            .get(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        self.display_backend.configure_scanout(
            scanout_id,
            display_info.width,
            display_info.height,
            blob.width,
            blob.height,
            format,
        )?;

        *scanout = Some(VirtioGpuScanout {
            resource_id: blob.resource_id,
            width: blob.width,
            height: blob.height,
            blob: Some(blob),
        });

        self.present_scanout_blob(scanout_id, &blob)
    }

    /// Reads a blob resource's pixels and presents them.
    ///
    /// Where the pixels live depends on who drew them. A compositor rendering
    /// on the GPU leaves them in an image the renderer owns; one rendering on
    /// the CPU writes them into the blob's own memory. Try each in turn rather
    /// than assuming, so a frame reaches the display either way.
    fn present_scanout_blob(&mut self, scanout_id: u32, blob: &BlobScanout) -> VirtioGpuResult {
        let bpp = ResourceFormat::BYTES_PER_PIXEL as u32;
        let rows = BlobRows {
            dst_stride: (blob.width * bpp) as usize,
            src_stride: if blob.stride != 0 {
                blob.stride as usize
            } else {
                (blob.width * bpp) as usize
            },
            height: blob.height as usize,
            offset: blob.offset as usize,
        };
        let (frame_id, buffer) = self.display_backend.alloc_frame(scanout_id)?;

        // 1. the renderer, if it offers a readback. Only a GPU-rendered buffer
        //    needs it, and only a renderer built with it can answer, so this is
        //    resolved at runtime and simply absent otherwise.
        if let Some(read_pixels) = renderer_read_resource_pixels() {
            let rc = unsafe {
                read_pixels(
                    blob.ctx_id,
                    blob.resource_id,
                    buffer.as_mut_ptr() as *mut c_void,
                    rows.dst_stride as u32,
                    blob.width,
                    blob.height,
                )
            };
            if rc == 0 {
                self.display_backend
                    .present_frame(scanout_id, frame_id, None)?;
                return Ok(OkNoData);
            }
        }

        // 2. the blob's own memory, which is where a CPU renderer draws
        if Self::copy_blob_pixels(&self.rutabaga, blob.resource_id, buffer, &rows) {
            self.display_backend
                .present_frame(scanout_id, frame_id, None)?;
            return Ok(OkNoData);
        }

        error!(
            "set_scanout_blob: no readable pixels for resource {}",
            blob.resource_id
        );
        Err(ErrUnspec)
    }

    /// Copies a blob's pixels out of its own storage, row by row.
    fn copy_blob_pixels(
        rutabaga: &Rutabaga,
        resource_id: u32,
        dst: &mut [u8],
        rows: &BlobRows,
    ) -> bool {
        if rows.height == 0 || rows.dst_stride == 0 {
            return false;
        }
        let needed = rows.offset + rows.src_stride * (rows.height - 1) + rows.dst_stride;

        let mut copy_rows = |src: &[u8]| -> bool {
            if src.len() < needed {
                return false;
            }
            for row in 0..rows.height {
                let (s, d) = (rows.offset + row * rows.src_stride, row * rows.dst_stride);
                if s + rows.dst_stride > src.len() || d + rows.dst_stride > dst.len() {
                    return row > 0;
                }
                dst[d..d + rows.dst_stride].copy_from_slice(&src[s..s + rows.dst_stride]);
            }
            true
        };

        // macOS shares a blob through a mapped host pointer
        #[cfg(target_os = "macos")]
        if let Ok(map_ptr) = rutabaga.map_ptr(resource_id) {
            // Safe: the mapping spans the resource, and `needed` is checked
            // against it before any row is read.
            let src = unsafe { std::slice::from_raw_parts(map_ptr as *const u8, needed) };
            if map_ptr != 0 && copy_rows(src) {
                return true;
            }
        }

        // elsewhere a guest-memory blob keeps its pixels in the guest's own pages
        if let Some([iov]) = rutabaga.backing_iovecs(resource_id) {
            // Safe: the iovec describes guest memory the device already owns for
            // this resource, and `needed` is checked to fit inside it.
            let src = unsafe { std::slice::from_raw_parts(iov.base as *const u8, needed) };
            if iov.len >= needed && copy_rows(src) {
                return true;
            }
        }

        let _ = (rutabaga, resource_id);
        false
    }

    fn read_2d_resource(
        rutabaga: &mut Rutabaga,
        resource: VirtioGpuResource,
        output: &mut [u8],
        width: u32,
        height: u32,
    ) -> VirtioGpuResult {
        // The scanout resource may be larger than the display: allocators pad
        // buffers to tiling alignment (e.g. llvmpipe pads 1440x900 to
        // 1472x960). Read only the configured crop, tightly packed into the
        // destination, or the copy overruns the frame buffer.
        let transfer = Transfer3D {
            x: 0,
            y: 0,
            z: 0,
            w: width.min(resource.width),
            h: height.min(resource.height),
            d: 1,
            level: 0,
            stride: width.min(resource.width) * ResourceFormat::BYTES_PER_PIXEL as u32,
            layer_stride: 0,
            offset: 0,
        };

        if let Err(e) =
            rutabaga.transfer_read(0, resource.id, transfer, Some(IoSliceMut::new(output)))
        {
            error!(
                "read_2d_resource: transfer_read failed for resource {}: {e}",
                resource.id
            );
            return Err(ErrUnspec);
        }

        Ok(OkNoData)
    }

    /// The guest replaced its pointer image. The image lives in a small 2D
    /// resource backed by guest pages, so it is read straight from there;
    /// resource 0 hides the pointer. A backend without pointer support just
    /// keeps showing whatever the guest composited.
    pub fn update_cursor(&mut self, info: virtio_gpu_update_cursor) -> VirtioGpuResult {
        let scanout_id = info.pos.scanout_id;
        let result = if info.resource_id == 0 {
            self.display_backend.set_cursor(scanout_id, 0, 0, 0, 0, &[])
        } else {
            let resource = *self
                .resources
                .get(&info.resource_id)
                .ok_or(ErrInvalidResourceId)?;
            // A blob carries no size of its own; the virtio-gpu cursor is
            // defined as 64x64, which is also what the compositor allocates.
            let (width, height) = if resource.width > 0 && resource.height > 0 {
                (resource.width, resource.height)
            } else {
                (64, 64)
            };
            let needed = width as usize * height as usize * 4;
            let mut pixels = Vec::with_capacity(needed);
            if let Some(iovs) = self.rutabaga.backing_iovecs(info.resource_id) {
                // A dumb buffer keeps its pixels in guest pages.
                for iov in iovs {
                    if pixels.len() >= needed {
                        break;
                    }
                    let take = (needed - pixels.len()).min(iov.len);
                    // Safe: the iovec describes guest memory the device owns for
                    // this resource, and `take` stays inside it.
                    pixels.extend_from_slice(unsafe {
                        std::slice::from_raw_parts(iov.base as *const u8, take)
                    });
                }
            }
            if pixels.len() < needed {
                // A GPU-allocated buffer lives in host memory: read it back the
                // way a blob scanout is, if the renderer offers that.
                pixels.clear();
                pixels.resize(needed, 0);
                let read = renderer_read_resource_pixels().map(|read_pixels| unsafe {
                    read_pixels(
                        0,
                        info.resource_id,
                        pixels.as_mut_ptr() as *mut c_void,
                        width * 4,
                        width,
                        height,
                    )
                });
                if read != Some(0) {
                    debug!(
                        "update_cursor: no pixels for resource {} (readback {read:?})",
                        info.resource_id
                    );
                    return Err(ErrUnspec);
                }
            }
            self.display_backend
                .set_cursor(scanout_id, width, height, info.hot_x, info.hot_y, &pixels)
        };
        // An update carries the position too, and a guest that changes the
        // pointer buffer on every move never sends a separate move.
        let moved = self
            .display_backend
            .move_cursor(scanout_id, info.pos.x, info.pos.y);
        match result.and(moved) {
            Ok(()) | Err(DisplayBackendError::MethodNotSupported) => Ok(OkNoData),
            Err(_) => Err(ErrUnspec),
        }
    }

    /// The guest moved its pointer; the position is where the hot spot sits.
    pub fn move_cursor(&mut self, info: virtio_gpu_update_cursor) -> VirtioGpuResult {
        match self
            .display_backend
            .move_cursor(info.pos.scanout_id, info.pos.x, info.pos.y)
        {
            Ok(()) | Err(DisplayBackendError::MethodNotSupported) => Ok(OkNoData),
            Err(_) => Err(ErrUnspec),
        }
    }

    /// Re-present the blob scanouts if a render fence has retired since the last
    /// look, so a frame flushed before its render landed is not left stale.
    /// Called from the worker's idle ticks; rate-limited, and a re-read whose
    /// pixels are unchanged produces no downstream update.
    pub fn represent_dirty_scanouts(&mut self) {
        use std::sync::atomic::Ordering;
        let now = std::time::Instant::now();
        // A render just retired: keep re-reading for a short window so a frame
        // that is not yet coherent on the first look is caught on a later one.
        if SCANOUT_DIRTY.swap(false, Ordering::AcqRel) {
            self.represent_until = Some(now + std::time::Duration::from_millis(250));
        }
        match self.represent_until {
            Some(until) if now < until => {}
            _ => return,
        }
        // Read at roughly 120 Hz within the window.
        if self
            .last_represent
            .is_some_and(|t| now.duration_since(t) < std::time::Duration::from_millis(8))
        {
            return;
        }
        self.last_represent = Some(now);
        let blobs: Vec<(u32, BlobScanout)> = self
            .scanouts
            .iter()
            .enumerate()
            .filter_map(|(id, sc)| sc.as_ref().and_then(|sc| sc.blob).map(|b| (id as u32, b)))
            .collect();
        for (scanout_id, blob) in blobs {
            if let Err(e) = self.present_scanout_blob(scanout_id, &blob) {
                debug!("dirty re-present of scanout {scanout_id} failed: {e:?}");
            }
        }
    }

    /// If the resource is the scanout resource, flush it to the display.
    pub fn flush_resource(&mut self, resource_id: u32, rect: Rect) -> VirtioGpuResult {
        if resource_id == 0 {
            return Ok(OkNoData);
        }

        let resource = *self
            .resources
            .get(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        for scanout_id in resource.scanouts.iter_enabled() {
            // A blob scanout has no 2D backing to read; present it the same
            // way SET_SCANOUT_BLOB did, or every damage-only frame fails.
            let blob = self
                .scanouts
                .get(scanout_id as usize)
                .and_then(|s| s.as_ref())
                .and_then(|s| s.blob)
                .filter(|b| b.resource_id == resource_id);
            if let Some(blob) = blob {
                self.present_scanout_blob(scanout_id, &blob)?;
                continue;
            }
            let (crop_w, crop_h) = self
                .scanouts
                .get(scanout_id as usize)
                .and_then(|s| s.as_ref())
                .map(|s| (s.width, s.height))
                .unwrap_or((resource.width, resource.height));
            let (frame_id, buffer) = self.display_backend.alloc_frame(scanout_id)?;
            if let Err(e) =
                Self::read_2d_resource(&mut self.rutabaga, resource, buffer, crop_w, crop_h)
            {
                log::error!("Failed to read resource {resource_id} for scanout {scanout_id}: {e}");
                return Err(ErrUnspec);
            }
            self.display_backend
                .present_frame(scanout_id, frame_id, Some(&rect))?
        }

        #[cfg(windows)]
        match self.rutabaga.resource_flush(resource_id) {
            Ok(_) => return Ok(OkNoData),
            Err(RutabagaError::Unsupported) => {}
            Err(e) => return Err(ErrRutabaga(e)),
        }

        Ok(OkNoData)
    }

    pub fn display_info(&self) -> VirtioGpuResult {
        let display_info = self
            .displays
            .iter()
            .map(|d| (d.width, d.height, true))
            .collect();

        Ok(OkDisplayInfo(display_info))
    }

    pub fn get_edid(&self, scanout_id: u32) -> VirtioGpuResult {
        let display = self
            .displays
            .get(scanout_id as usize)
            .ok_or(ErrInvalidScanoutId)?;

        Ok(OkEdid(display.edid_bytes()))
    }

    /// Copies data to host resource from the attached iovecs. Can also be used to flush caches.
    pub fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .transfer_write(ctx_id, resource_id, transfer)?;
        Ok(OkNoData)
    }

    /// Copies data from the host resource to:
    ///    1) To the optional volatile slice
    ///    2) To the host resource's attached iovecs
    ///
    /// Can also be used to invalidate caches.
    pub fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> VirtioGpuResult {
        // Reads into a caller-provided slice are not wired up; the only
        // caller targets the resource's attached iovecs.
        if buf.is_some() {
            return Err(ErrUnspec);
        }
        self.rutabaga
            .transfer_read(ctx_id, resource_id, transfer, None)?;
        Ok(OkNoData)
    }

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space. Converts to RutabagaIovec from the memory
    /// mapping.
    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemoryMmap,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let rutabaga_iovecs = sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?;
        self.rutabaga.attach_backing(resource_id, rutabaga_iovecs)?;
        Ok(OkNoData)
    }

    /// Detaches any previously attached iovecs from the resource.
    pub fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.detach_backing(resource_id)?;
        Ok(OkNoData)
    }

    /// Returns a uuid for the resource.
    pub fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult {
        if !self.resources.contains_key(&resource_id) {
            return Err(ErrInvalidResourceId);
        }

        // TODO(stevensd): use real uuids once the virtio wayland protocol is updated to
        // handle more than 32 bits. For now, the virtwl driver knows that the uuid is
        // actually just the resource id.
        let mut uuid: [u8; 16] = [0; 16];
        for (idx, byte) in resource_id.to_be_bytes().iter().enumerate() {
            uuid[12 + idx] = *byte;
        }
        Ok(OkResourceUuid { uuid })
    }

    /// Gets rutabaga's capset information associated with `index`.
    pub fn get_capset_info(&self, index: u32) -> VirtioGpuResult {
        let (capset_id, version, size) = self.rutabaga.get_capset_info(index)?;
        Ok(OkCapsetInfo {
            capset_id,
            version,
            size,
        })
    }

    /// Gets a capset from rutabaga.
    pub fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult {
        let capset = self.rutabaga.get_capset(capset_id, version)?;
        Ok(OkCapset(capset))
    }

    /// Creates a rutabaga context.
    pub fn create_context(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
    ) -> VirtioGpuResult {
        self.rutabaga
            .create_context(ctx_id, context_init, context_name)?;
        Ok(OkNoData)
    }

    /// Destroys a rutabaga context.
    pub fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult {
        self.rutabaga.destroy_context(ctx_id)?;
        Ok(OkNoData)
    }

    /// Attaches a resource to a rutabaga context.
    pub fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_attach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    /// Detaches a resource from a rutabaga context.
    pub fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_detach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    /// Submits a command buffer to a rutabaga context.
    pub fn submit_command(
        &mut self,
        ctx_id: u32,
        commands: &mut [u8],
        fence_ids: &[u64],
    ) -> VirtioGpuResult {
        self.rutabaga.submit_command(ctx_id, commands, fence_ids)?;
        Ok(OkNoData)
    }

    /// Creates a fence with the RutabagaFence that can be used to determine when the previous
    /// command completed.
    pub fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult {
        self.rutabaga.create_fence(rutabaga_fence)?;
        Ok(OkNoData)
    }

    pub fn process_fence(
        &mut self,
        ring: VirtioGpuRing,
        fence_id: u64,
        desc_index: u16,
        len: u32,
    ) -> bool {
        // In case the fence is signaled immediately after creation, don't add a return
        // FenceDescriptor.
        let mut fence_state = self.fence_state.lock().unwrap();
        if fence_id > *fence_state.completed_fences.get(&ring).unwrap_or(&0) {
            fence_state.descs.push(FenceDescriptor {
                ring,
                fence_id,
                desc_index,
                len,
            });

            false
        } else {
            true
        }
    }

    /// Creates a blob resource using rutabaga.
    pub fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        vecs: Vec<(GuestAddress, usize)>,
        mem: &GuestMemoryMmap,
    ) -> VirtioGpuResult {
        let mut rutabaga_iovecs = None;

        if resource_create_blob.blob_flags & VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE != 0 {
            error!("resource_create_blob: GUEST_HANDLE unimplemented");
            return Err(ErrUnspec);
        } else if resource_create_blob.blob_mem != VIRTIO_GPU_BLOB_MEM_HOST3D {
            rutabaga_iovecs =
                Some(sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?);
        }

        self.rutabaga.resource_create_blob(
            ctx_id,
            resource_id,
            resource_create_blob,
            rutabaga_iovecs,
            None,
        )?;

        let resource = VirtioGpuResource::new(resource_id, 0, 0, None, resource_create_blob.size);

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Uses the hypervisor to map the rutabaga blob resource.
    ///
    /// When sandboxing is disabled, external_blob is unset and opaque fds are mapped by
    /// rutabaga as ExternalMapping.
    /// When sandboxing is enabled, external_blob is set and opaque fds must be mapped in the
    /// hypervisor process by Vulkano using metadata provided by Rutabaga::vulkan_info().
    #[cfg(all(not(feature = "virgl_resource_map2"), target_os = "linux"))]
    pub fn resource_map_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
        offset: u64,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;

        if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            if export.handle_type != RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD {
                let prot = match map_info & RUTABAGA_MAP_ACCESS_MASK {
                    RUTABAGA_MAP_ACCESS_READ => libc::PROT_READ,
                    RUTABAGA_MAP_ACCESS_WRITE => libc::PROT_WRITE,
                    RUTABAGA_MAP_ACCESS_RW => libc::PROT_READ | libc::PROT_WRITE,
                    _ => {
                        error!("resource_map_blob: unexpected prot mode {map_info:#x}");
                        return Err(ErrUnspec);
                    }
                };

                // A blob that does not fit the shm region must be rejected, not
                // just logged: falling through to mmap MAP_FIXED with an
                // out-of-range offset writes outside the region (matches the
                // virgl_resource_map2 variant below).
                let end = offset.checked_add(resource.size).ok_or(ErrUnspec)?;
                if end > shm_region.size as u64 {
                    error!("resource map doesn't fit in shm region");
                    return Err(ErrUnspec);
                }
                let addr = shm_region.host_addr.checked_add(offset).ok_or(ErrUnspec)?;
                debug!(
                    "mapping: host_addr={:x}, addr={:x}, size={}",
                    shm_region.host_addr, addr, resource.size
                );
                let ret = unsafe {
                    libc::mmap(
                        addr as *mut libc::c_void,
                        resource.size as usize,
                        prot,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        export.os_handle.as_raw_fd(),
                        0 as libc::off_t,
                    )
                };
                if ret == libc::MAP_FAILED {
                    return Err(ErrUnspec);
                }
            } else {
                return Err(ErrUnspec);
            }
        } else {
            return Err(ErrUnspec);
        }

        resource.shmem_offset = Some(offset);
        // Access flags not a part of the virtio-gpu spec.
        Ok(OkMapInfo {
            map_info: map_info & RUTABAGA_MAP_CACHE_MASK,
        })
    }
    #[cfg(all(feature = "virgl_resource_map2", target_os = "linux"))]
    pub fn resource_map_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
        offset: u64,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;

        let prot = match map_info & RUTABAGA_MAP_ACCESS_MASK {
            RUTABAGA_MAP_ACCESS_READ => libc::PROT_READ,
            RUTABAGA_MAP_ACCESS_WRITE => libc::PROT_WRITE,
            RUTABAGA_MAP_ACCESS_RW => libc::PROT_READ | libc::PROT_WRITE,
            _ => {
                error!("resource_map_blob: unexpected prot mode {map_info:#x}");
                return Err(ErrUnspec);
            }
        };

        let end = offset.checked_add(resource.size).ok_or(ErrUnspec)?;
        if end > shm_region.size as u64 {
            error!("resource map doesn't fit in shm region");
            return Err(ErrUnspec);
        }
        let addr = shm_region.host_addr.checked_add(offset).ok_or(ErrUnspec)?;

        if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            // SHM and DMABUF are both regular host fds whose pages can be exposed
            // to the guest by mmap'ing them directly into the virtio shm region.
            // For SHM (memfd) this has always worked. For DMABUF it had been
            // delegated to virgl_renderer_resource_map2, which only handles
            // virglrenderer-allocated GPU memory and silently no-ops for external
            // dma-bufs — leaving the guest blob backed by zero pages. That broke
            // muvm camera capture, where the v4l2 source exports kernel buffers
            // via VIDIOC_EXPBUF as dma-bufs, the muvm bridge forwards the fd
            // across SCM_RIGHTS, libkrun classifies it as DMABUF, and the guest's
            // CREATE_BLOB allocates a host-backed-by-nothing blob. Mapping the
            // dma-buf fd directly here gives the guest real, live pages.
            if export.handle_type == RUTABAGA_MEM_HANDLE_TYPE_SHM
                || export.handle_type == RUTABAGA_MEM_HANDLE_TYPE_DMABUF
            {
                let ret = unsafe {
                    libc::mmap(
                        addr as *mut libc::c_void,
                        resource.size as usize,
                        prot,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        export.os_handle.as_raw_fd(),
                        0 as libc::off_t,
                    )
                };
                if ret == libc::MAP_FAILED {
                    error!(
                        "failed to mmap resource in shm region (handle_type={:#x})",
                        export.handle_type
                    );
                    return Err(ErrUnspec);
                }
            } else {
                self.rutabaga.resource_map(
                    resource_id,
                    addr,
                    resource.size,
                    prot,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                )?;
            }
        } else {
            // export_blob failing does not mean the resource is unmappable:
            // classic virgl GL memory has no exportable fd. Let rutabaga map
            // it (and propagate a real error if it cannot) instead of falling
            // through and reporting success with the guest pages unmapped.
            self.rutabaga.resource_map(
                resource_id,
                addr,
                resource.size,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
            )?;
        }

        resource.shmem_offset = Some(offset);
        // Access flags not a part of the virtio-gpu spec.
        Ok(OkMapInfo {
            map_info: map_info & RUTABAGA_MAP_CACHE_MASK,
        })
    }
    #[cfg(target_os = "macos")]
    pub fn resource_map_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
        offset: u64,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;
        let map_ptr = self.rutabaga.map_ptr(resource_id).map_err(|_| ErrUnspec)?;

        if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            if export.handle_type == RUTABAGA_MEM_HANDLE_TYPE_APPLE {
                let end = offset.checked_add(resource.size).ok_or(ErrUnspec)?;
                if end > shm_region.size as u64 {
                    error!("mapping DOES NOT FIT");
                    return Err(ErrUnspec);
                }

                let guest_addr = shm_region.guest_addr.checked_add(offset).ok_or(ErrUnspec)?;
                debug!(
                    "mapping: map_ptr={:x}, guest_addr={:x}, size={}",
                    map_ptr, guest_addr, resource.size
                );

                let (reply_sender, reply_receiver) = unbounded();
                self.map_sender
                    .send(WorkerMessage::GpuAddMapping(
                        reply_sender,
                        map_ptr,
                        guest_addr,
                        resource.size,
                    ))
                    .unwrap();
                if !reply_receiver.recv().unwrap() {
                    return Err(ErrUnspec);
                }
            } else {
                return Err(ErrUnspec);
            }
        } else {
            return Err(ErrUnspec);
        }

        resource.shmem_offset = Some(offset);
        // Access flags not a part of the virtio-gpu spec.
        Ok(OkMapInfo {
            map_info: map_info & RUTABAGA_MAP_CACHE_MASK,
        })
    }

    /// Uses the hypervisor to unmap the blob resource.
    #[cfg(target_os = "linux")]
    pub fn resource_unmap_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let shmem_offset = resource.shmem_offset.ok_or(ErrUnspec)?;

        let addr = shm_region
            .host_addr
            .checked_add(shmem_offset)
            .ok_or(ErrUnspec)?;

        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                resource.size as usize,
                libc::PROT_NONE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0_i64,
            )
        };
        // A failed re-map must not abort the whole VMM: surface it as an error
        // to the guest instead of panicking (a guest could otherwise crash the
        // host process by driving unmap into a failing mmap).
        if ret == libc::MAP_FAILED {
            error!("resource_unmap_blob: failed to unmap blob region");
            return Err(ErrUnspec);
        }

        resource.shmem_offset = None;

        Ok(OkNoData)
    }
    #[cfg(target_os = "macos")]
    pub fn resource_unmap_blob(
        &mut self,
        resource_id: u32,
        shm_region: &VirtioShmRegion,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        debug!("resource_unmap_blob");
        let shmem_offset = resource.shmem_offset.ok_or(ErrUnspec)?;

        let guest_addr = shm_region.guest_addr + shmem_offset;
        debug!(
            "unmapping: guest_addr={:x}, size={}",
            guest_addr, resource.size
        );

        let (reply_sender, reply_receiver) = unbounded();
        self.map_sender
            .send(WorkerMessage::GpuRemoveMapping(
                reply_sender,
                guest_addr,
                resource.size,
            ))
            .unwrap();
        if !reply_receiver.recv().unwrap() {
            return Err(ErrUnspec);
        }

        resource.shmem_offset = None;

        Ok(OkNoData)
    }
}
#[cfg(test)]
mod test {
    use crate::virtio::gpu::protocol::VIRTIO_GPU_MAX_SCANOUTS;

    #[test]
    fn test_virtio_gpu_associated_scanouts() {
        use super::AssociatedScanouts;

        let mut scanouts = AssociatedScanouts::default();

        assert!(!scanouts.has_any_enabled());
        assert_eq!(scanouts.iter_enabled().next(), None);

        scanouts.enable(1);
        assert!(scanouts.has_any_enabled());
        scanouts.disable(1);
        assert!(!scanouts.has_any_enabled());

        (0..VIRTIO_GPU_MAX_SCANOUTS).for_each(|scanout| scanouts.enable(scanout));
        assert!(scanouts.has_any_enabled());
        assert_eq!(
            scanouts.iter_enabled().collect::<Vec<u32>>(),
            (0..VIRTIO_GPU_MAX_SCANOUTS).collect::<Vec<u32>>()
        );

        (0..VIRTIO_GPU_MAX_SCANOUTS)
            .filter(|&i| i % 2 == 0)
            .for_each(|scanout| scanouts.disable(scanout));
        assert_eq!(
            scanouts.iter_enabled().collect::<Vec<u32>>(),
            (1..VIRTIO_GPU_MAX_SCANOUTS)
                .step_by(2)
                .collect::<Vec<u32>>()
        );

        (0..VIRTIO_GPU_MAX_SCANOUTS)
            .filter(|&i| i % 2 != 0)
            .for_each(|scanout| scanouts.disable(scanout));
        assert!(!scanouts.has_any_enabled());
    }
}
