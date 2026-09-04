#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex};
use std::thread;

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use utils::eventfd::EventFd;

#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
#[cfg(target_os = "linux")]
use rutabaga_gfx::AsRawDescriptor;
use rutabaga_gfx::{
    RUTABAGA_PIPE_BIND_RENDER_TARGET, RUTABAGA_PIPE_TEXTURE_2D, ResourceCreate3D,
    ResourceCreateBlob, RutabagaFence, Transfer3D,
};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use super::super::descriptor_utils::{Reader, Writer};
use super::super::{GpuError, Queue as VirtQueue};
use super::protocol::{
    GpuCommand, GpuResponse, VirtioGpuResult, virtio_gpu_ctrl_hdr, virtio_gpu_mem_entry,
};
use super::virtio_gpu::{BlobScanout, VirtioGpu};
use crate::virtio::display::DisplayInfo;
use crate::virtio::fs::ExportTable;
use crate::virtio::gpu::protocol::{VIRTIO_GPU_FLAG_FENCE, VIRTIO_GPU_FLAG_INFO_RING_IDX};
use crate::virtio::gpu::virtio_gpu::VirtioGpuRing;
use crate::virtio::{InterruptTransport, VirtioShmRegion};
use krun_display::DisplayBackend;
use krun_display::Rect;

pub struct Worker {
    control_evt: EventFd,
    control_queue: Arc<Mutex<VirtQueue>>,
    /// Cursor queue, drained and acked by the worker: cursor commands carry no
    /// response payload, but their descriptors must be returned or the guest's
    /// cursor ring runs out of free entries and atomic commits block forever.
    cursor_evt: EventFd,
    cursor_queue: Arc<Mutex<VirtQueue>>,
    mem: GuestMemoryMmap,
    interrupt: InterruptTransport,
    shm_region: VirtioShmRegion,
    virgl_flags: u32,
    #[cfg(target_os = "macos")]
    map_sender: Sender<WorkerMessage>,
    export_table: Option<ExportTable>,
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackend<'static>,
    /// Per-context poll fds, populated on CtxCreate.
    /// `Some(fd)` — epollable fd returned by virgl_renderer_context_get_poll_fd.
    /// `None`     — virglrenderer returned -1; context is blind-polled each tick.
    ///
    /// SAFETY: accessed only from the single GPU worker thread; no locking needed.
    /// The fds are owned by virglrenderer — do NOT close them.
    #[cfg(target_os = "linux")]
    context_poll_fds: HashMap<u32, Option<i32>>,
    /// Context IDs whose poll fds need registering with epoll.
    /// Populated by CtxCreate, drained after process_queue.
    #[cfg(target_os = "linux")]
    pending_ctx_registrations: Vec<u32>,
    /// The epoll instance for this worker, set once in `work_loop_epoll`.
    /// Stored on the struct so `CtxDestroy` can deregister fds before the
    /// virglrenderer context (and its fd) is destroyed.
    #[cfg(target_os = "linux")]
    epoll_fd: i32,
}

impl Worker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        control_queue: Arc<Mutex<VirtQueue>>,
        control_event: Arc<EventFd>,
        cursor_queue: Arc<Mutex<VirtQueue>>,
        cursor_event: Arc<EventFd>,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        shm_region: VirtioShmRegion,
        virgl_flags: u32,
        #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
        export_table: Option<ExportTable>,
        displays: Box<[DisplayInfo]>,
        display_backend: DisplayBackend<'static>,
    ) -> Self {
        // Clone the eventfd so we have our own file description, then set it to blocking mode.
        let control_evt = control_event.try_clone().unwrap();
        // SAFETY: control_evt is valid for the duration of the fcntl calls.
        let fd = unsafe { BorrowedFd::borrow_raw(control_evt.as_raw_fd()) };
        let flags =
            OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL).unwrap()) & !OFlag::O_NONBLOCK;
        fcntl(fd, FcntlArg::F_SETFL(flags)).unwrap();

        let cursor_evt = {
            let cursor_evt = cursor_event.try_clone().unwrap();
            // SAFETY: cursor_evt is valid for the duration of the fcntl calls.
            let fd = unsafe { BorrowedFd::borrow_raw(cursor_evt.as_raw_fd()) };
            let flags =
                OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL).unwrap()) & !OFlag::O_NONBLOCK;
            fcntl(fd, FcntlArg::F_SETFL(flags)).unwrap();
            cursor_evt
        };

        Self {
            control_evt,
            control_queue,
            cursor_evt,
            cursor_queue,
            mem,
            interrupt,
            shm_region,
            virgl_flags,
            #[cfg(target_os = "macos")]
            map_sender,
            export_table,
            displays,
            display_backend,
            #[cfg(target_os = "linux")]
            context_poll_fds: HashMap::new(),
            #[cfg(target_os = "linux")]
            pending_ctx_registrations: Vec::new(),
            #[cfg(target_os = "linux")]
            epoll_fd: -1,
        }
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("gpu worker".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn work(mut self) {
        let mut virtio_gpu = VirtioGpu::new(
            self.mem.clone(),
            self.control_queue.clone(),
            self.interrupt.clone(),
            self.virgl_flags,
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
            self.export_table.take(),
            self.displays.clone(),
            self.display_backend,
        );

        #[cfg(target_os = "linux")]
        self.work_loop_epoll(&mut virtio_gpu);

        #[cfg(not(target_os = "linux"))]
        self.work_loop_blocking(&mut virtio_gpu);
    }

    /// Linux GPU worker loop: uses epoll to multiplex the virtio control eventfd,
    /// the virglrenderer global poll fd, and per-context render-server poll fds.
    ///
    /// Per-context fds (from `virgl_renderer_context_get_poll_fd`) fire when the
    /// render server has completed work for a context.  We call `context_event_poll`
    /// on the firing context, which triggers `write_context_fence` callbacks and
    /// advances the seqno that Venus's cpu sync waits on.
    #[cfg(target_os = "linux")]
    fn work_loop_epoll(&mut self, virtio_gpu: &mut VirtioGpu) {
        // Hold the global rutabaga poll descriptor for the loop lifetime.
        let rutabaga_poll_desc = virtio_gpu.poll_descriptor();

        // SAFETY: epoll_create1 is a straightforward syscall; we check the return value.
        // The fd is intentionally never closed: this loop runs for the lifetime of the
        // VM process, and the kernel reclaims it on exit.
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            panic!(
                "gpu worker: epoll_create1 failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // Store on self so CtxDestroy can deregister fds before destroying contexts.
        self.epoll_fd = epoll_fd;

        const TOKEN_CONTROL: u64 = 0;
        const TOKEN_RUTABAGA: u64 = 1;
        const TOKEN_CURSOR: u64 = 2;
        // Per-context tokens: TOKEN_CONTEXT_BASE + ctx_id.  ctx_id values start
        // at 1, so TOKEN_CONTEXT_BASE = 16 leaves room for future global tokens.
        const TOKEN_CONTEXT_BASE: u64 = 16;

        // Register the virtio control eventfd.
        let control_raw = self.control_evt.as_raw_fd();
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: TOKEN_CONTROL,
        };
        // SAFETY: control_raw is valid for the lifetime of self.control_evt.
        let ret = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, control_raw, &mut ev) };
        if ret != 0 {
            panic!(
                "gpu worker: epoll_ctl ADD control fd failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Register the cursor queue eventfd.
        let cursor_raw = self.cursor_evt.as_raw_fd();
        let mut cursor_ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: TOKEN_CURSOR,
        };
        // SAFETY: cursor_raw is valid for the lifetime of self.cursor_evt.
        let ret =
            unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, cursor_raw, &mut cursor_ev) };
        if ret != 0 {
            panic!(
                "gpu worker: epoll_ctl ADD cursor fd failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Register the virglrenderer global poll fd if present (non-render-server mode).
        if let Some(ref desc) = rutabaga_poll_desc {
            let rutabaga_raw = desc.as_raw_descriptor();
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: TOKEN_RUTABAGA,
            };
            // SAFETY: rutabaga_raw is a dup'd fd valid for the lifetime of rutabaga_poll_desc.
            let ret =
                unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, rutabaga_raw, &mut ev) };
            if ret != 0 {
                panic!(
                    "gpu worker: epoll_ctl ADD rutabaga fd failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        const MAX_EVENTS: usize = 8;
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; MAX_EVENTS];

        loop {
            // 1ms timeout: keeps blind-polled fallback contexts (those where
            // virglrenderer returned -1 for the poll fd) drained each tick.
            // SAFETY: epoll_wait with a valid epoll_fd, properly sized buffer.
            let n =
                unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), MAX_EVENTS as i32, 1) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                error!("gpu worker: epoll_wait failed: {err:?}");
                continue;
            }

            // Classic virgl exposes no global poll fd, so pending fences would
            // otherwise only retire while new guest commands are processed —
            // deadlocking any client blocked on its last fence. Poll on idle
            // ticks so fences retire even with no incoming traffic.
            if n == 0 {
                virtio_gpu.event_poll();
            }

            let mut process_queue = false;
            for event in events.iter().take(n as usize) {
                // Copy the token out of the packed epoll_event field before
                // matching: a guard like `t if t >= K` on a packed field would
                // create a misaligned reference (E0793).
                let token = event.u64;
                match token {
                    TOKEN_CONTROL => {
                        if let Err(e) = self.control_evt.read() {
                            error!("Failed to read control_evt: {e:?}");
                        }
                        process_queue = true;
                    }
                    TOKEN_CURSOR => {
                        if let Err(e) = self.cursor_evt.read() {
                            error!("Failed to read cursor_evt: {e:?}");
                        }
                        self.process_cursor_queue(virtio_gpu);
                    }
                    TOKEN_RUTABAGA => {
                        // Global poll fd fired (non-render-server mode): process events.
                        virtio_gpu.event_poll();
                    }
                    t if t >= TOKEN_CONTEXT_BASE => {
                        // Per-context poll fd fired: process this context's completions.
                        let ctx_id = (t - TOKEN_CONTEXT_BASE) as u32;
                        virtio_gpu.context_event_poll(ctx_id);
                    }
                    _ => {}
                }
            }

            if process_queue {
                if self.process_queue(virtio_gpu, &self.control_queue.clone())
                    && let Err(e) = self.interrupt.try_signal_used_queue()
                {
                    error!("Error signaling queue: {e:?}");
                }

                // Register per-context poll fds for newly created contexts.
                // Only contexts added since the last drain are registered.
                // Deregistration on context destroy is handled eagerly in CtxDestroy
                // before virglrenderer invalidates the fd.
                for ctx_id in self.pending_ctx_registrations.drain(..) {
                    if let Some(&Some(fd)) = self.context_poll_fds.get(&ctx_id) {
                        let mut ev = libc::epoll_event {
                            events: libc::EPOLLIN as u32,
                            u64: TOKEN_CONTEXT_BASE + ctx_id as u64,
                        };
                        // SAFETY: fd is owned by virglrenderer and valid while the
                        // context is alive.  CtxDestroy removes it before destroy.
                        let ret =
                            unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
                        if ret != 0 {
                            error!(
                                "gpu worker: epoll_ctl ADD ctx {ctx_id} fd {fd}: {:?}",
                                std::io::Error::last_os_error()
                            );
                        }
                    }
                }
            }

            // Blind-poll contexts whose virglrenderer poll fd was -1.
            // Contexts with a valid poll fd are driven by epoll events above.
            for (&ctx_id, &opt_fd) in &self.context_poll_fds {
                if opt_fd.is_none() {
                    virtio_gpu.context_event_poll(ctx_id);
                }
            }
        }
    }

    /// Non-Linux GPU worker loop: blocks on the virtio control eventfd.
    /// Used on macOS where virglrenderer render-server polling is not needed.
    #[cfg(not(target_os = "linux"))]
    /// Non-Linux worker loop. Mirrors the epoll loop's three duties: process
    /// control-queue commands, drain-and-ack cursor-queue commands, and tick
    /// `event_poll()` on idle so pending fences retire without new guest
    /// traffic. Blocking solely on the control eventfd deadlocks a compositor
    /// twice over: a cursor-plane commit waits on a fence only fence polling
    /// can retire, and its cursor descriptor is never returned.
    fn work_loop_blocking(&mut self, virtio_gpu: &mut VirtioGpu) {
        use nix::errno::Errno;
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        loop {
            let (control_ready, cursor_ready) = {
                // SAFETY: the raw fds outlive the poll call; self owns both
                // eventfds for the lifetime of the loop.
                let control_fd = unsafe { BorrowedFd::borrow_raw(self.control_evt.as_raw_fd()) };
                let cursor_fd = unsafe { BorrowedFd::borrow_raw(self.cursor_evt.as_raw_fd()) };
                let mut fds = [
                    PollFd::new(control_fd, PollFlags::POLLIN),
                    PollFd::new(cursor_fd, PollFlags::POLLIN),
                ];
                match poll(&mut fds, PollTimeout::from(1u8)) {
                    Ok(0) => {
                        virtio_gpu.event_poll();
                        continue;
                    }
                    Ok(_) => (
                        fds[0].revents().is_some_and(|r| !r.is_empty()),
                        fds[1].revents().is_some_and(|r| !r.is_empty()),
                    ),
                    Err(Errno::EINTR) => continue,
                    Err(e) => {
                        error!("gpu worker: poll failed: {e:?}");
                        continue;
                    }
                }
            };
            if control_ready {
                if let Err(e) = self.control_evt.read() {
                    error!("Failed to read control_evt: {e:?}");
                }
                if self.process_queue(virtio_gpu, &self.control_queue.clone())
                    && let Err(e) = self.interrupt.try_signal_used_queue()
                {
                    error!("Error signaling queue: {e:?}");
                }
            }
            if cursor_ready {
                if let Err(e) = self.cursor_evt.read() {
                    error!("Failed to read cursor_evt: {e:?}");
                }
                self.process_cursor_queue(virtio_gpu);
            }
        }
    }

    fn process_gpu_command(
        &mut self,
        virtio_gpu: &mut VirtioGpu,
        mem: &GuestMemoryMmap,
        hdr: virtio_gpu_ctrl_hdr,
        cmd: GpuCommand,
        reader: &mut Reader,
    ) -> VirtioGpuResult {
        virtio_gpu.force_ctx_0();

        match cmd {
            GpuCommand::GetDisplayInfo => virtio_gpu.display_info(),
            GpuCommand::GetEdid(info) => virtio_gpu.get_edid(info.scanout),
            GpuCommand::ResourceCreate2d(info) => {
                let resource_id = info.resource_id;

                let resource_create_3d = ResourceCreate3D {
                    target: RUTABAGA_PIPE_TEXTURE_2D,
                    format: info.format,
                    bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
                    width: info.width,
                    height: info.height,
                    depth: 1,
                    array_size: 1,
                    last_level: 0,
                    nr_samples: 0,
                    flags: 0,
                };

                virtio_gpu.resource_create_3d(resource_id, resource_create_3d)
            }
            GpuCommand::ResourceUnref(info) => virtio_gpu.unref_resource(info.resource_id),
            GpuCommand::SetScanout(info) => virtio_gpu.set_scanout(
                info.scanout_id,
                info.resource_id,
                info.r.width,
                info.r.height,
            ),
            GpuCommand::ResourceFlush(info) => {
                let rect = Rect {
                    x: info.r.x,
                    y: info.r.y,
                    width: info.r.width,
                    height: info.r.height,
                };
                virtio_gpu.flush_resource(info.resource_id, rect)
            }
            GpuCommand::TransferToHost2d(info) => {
                let resource_id = info.resource_id;
                let transfer = Transfer3D::new_2d(info.r.x, info.r.y, info.r.width, info.r.height);
                virtio_gpu.transfer_write(0, resource_id, transfer)
            }
            GpuCommand::ResourceAttachBacking(info) => {
                let available_bytes = reader.available_bytes();
                if available_bytes != 0 {
                    let entry_count = info.nr_entries as usize;
                    let mut vecs = Vec::with_capacity(entry_count);
                    for _ in 0..entry_count {
                        match reader.read_obj::<virtio_gpu_mem_entry>() {
                            Ok(entry) => {
                                let addr = GuestAddress(entry.addr);
                                let len = entry.length as usize;
                                vecs.push((addr, len))
                            }
                            Err(_) => return Err(GpuResponse::ErrUnspec),
                        }
                    }
                    virtio_gpu.attach_backing(info.resource_id, mem, vecs)
                } else {
                    error!("missing data for command {cmd:?}");
                    Err(GpuResponse::ErrUnspec)
                }
            }
            GpuCommand::ResourceDetachBacking(info) => virtio_gpu.detach_backing(info.resource_id),
            GpuCommand::UpdateCursor(_info) => {
                error!("virtio_gpu: GpuCommand::UpdateCursor unimplemented");
                Err(GpuResponse::ErrUnspec)
            }
            GpuCommand::MoveCursor(_info) => {
                error!("virtio_gpu: GpuCommand::MoveCursor unimplemented");
                Err(GpuResponse::ErrUnspec)
            }
            GpuCommand::ResourceAssignUuid(info) => {
                let resource_id = info.resource_id;
                virtio_gpu.resource_assign_uuid(resource_id)
            }
            GpuCommand::GetCapsetInfo(info) => virtio_gpu.get_capset_info(info.capset_index),
            GpuCommand::GetCapset(info) => {
                virtio_gpu.get_capset(info.capset_id, info.capset_version)
            }

            GpuCommand::CtxCreate(info) => {
                let context_name: Option<String> = String::from_utf8(info.debug_name.to_vec()).ok();
                let result = virtio_gpu.create_context(
                    hdr.ctx_id,
                    info.context_init,
                    context_name.as_deref(),
                );
                #[cfg(target_os = "linux")]
                if result.is_ok() {
                    let poll_fd = virtio_gpu.context_poll_fd(hdr.ctx_id);
                    self.context_poll_fds.insert(hdr.ctx_id, poll_fd);
                    self.pending_ctx_registrations.push(hdr.ctx_id);
                }
                result
            }
            GpuCommand::CtxDestroy(_info) => {
                // Deregister from epoll BEFORE destroying the context.
                // virglrenderer owns the poll fd and closes it on context destroy.
                // Calling epoll_ctl(DEL) after destroy would use a stale or reused fd.
                #[cfg(target_os = "linux")]
                if let Some(Some(fd)) = self.context_poll_fds.remove(&hdr.ctx_id)
                    && self.epoll_fd >= 0
                {
                    unsafe {
                        libc::epoll_ctl(
                            self.epoll_fd,
                            libc::EPOLL_CTL_DEL,
                            fd,
                            std::ptr::null_mut(),
                        )
                    };
                }
                virtio_gpu.destroy_context(hdr.ctx_id)
            }
            GpuCommand::CtxAttachResource(info) => {
                virtio_gpu.context_attach_resource(hdr.ctx_id, info.resource_id)
            }
            GpuCommand::CtxDetachResource(info) => {
                virtio_gpu.context_detach_resource(hdr.ctx_id, info.resource_id)
            }
            GpuCommand::ResourceCreate3d(info) => {
                let resource_id = info.resource_id;
                let resource_create_3d = ResourceCreate3D {
                    target: info.target,
                    format: info.format,
                    bind: info.bind,
                    width: info.width,
                    height: info.height,
                    depth: info.depth,
                    array_size: info.array_size,
                    last_level: info.last_level,
                    nr_samples: info.nr_samples,
                    flags: info.flags,
                };

                virtio_gpu.resource_create_3d(resource_id, resource_create_3d)
            }
            GpuCommand::TransferToHost3d(info) => {
                let ctx_id = hdr.ctx_id;
                let resource_id = info.resource_id;

                let transfer = Transfer3D {
                    x: info.box_.x,
                    y: info.box_.y,
                    z: info.box_.z,
                    w: info.box_.w,
                    h: info.box_.h,
                    d: info.box_.d,
                    level: info.level,
                    stride: info.stride,
                    layer_stride: info.layer_stride,
                    offset: info.offset,
                };

                virtio_gpu.transfer_write(ctx_id, resource_id, transfer)
            }
            GpuCommand::TransferFromHost3d(info) => {
                let ctx_id = hdr.ctx_id;
                let resource_id = info.resource_id;

                let transfer = Transfer3D {
                    x: info.box_.x,
                    y: info.box_.y,
                    z: info.box_.z,
                    w: info.box_.w,
                    h: info.box_.h,
                    d: info.box_.d,
                    level: info.level,
                    stride: info.stride,
                    layer_stride: info.layer_stride,
                    offset: info.offset,
                };

                virtio_gpu.transfer_read(ctx_id, resource_id, transfer, None)
            }
            GpuCommand::CmdSubmit3d(info) => {
                if reader.available_bytes() != 0 {
                    let num_in_fences = info.num_in_fences as usize;
                    let cmd_size = info.size as usize;
                    let mut cmd_buf = vec![0; cmd_size];
                    let mut fence_ids: Vec<u64> = Vec::with_capacity(num_in_fences);

                    for _ in 0..num_in_fences {
                        match reader.read_obj::<u64>() {
                            Ok(fence_id) => {
                                fence_ids.push(fence_id);
                            }
                            Err(_) => return Err(GpuResponse::ErrUnspec),
                        }
                    }

                    if reader.read_exact(&mut cmd_buf[..]).is_ok() {
                        virtio_gpu.submit_command(hdr.ctx_id, &mut cmd_buf[..], &fence_ids)
                    } else {
                        Err(GpuResponse::ErrInvalidParameter)
                    }
                } else {
                    // Silently accept empty command buffers to allow for
                    // benchmarking.
                    Ok(GpuResponse::OkNoData)
                }
            }
            GpuCommand::ResourceCreateBlob(info) => {
                let resource_id = info.resource_id;
                let ctx_id = hdr.ctx_id;

                let resource_create_blob = ResourceCreateBlob {
                    blob_mem: info.blob_mem,
                    blob_flags: info.blob_flags,
                    blob_id: info.blob_id,
                    size: info.size,
                };

                let entry_count = info.nr_entries;
                if reader.available_bytes() == 0 && entry_count > 0 {
                    return Err(GpuResponse::ErrUnspec);
                }

                let mut vecs = Vec::with_capacity(entry_count as usize);
                for _ in 0..entry_count {
                    match reader.read_obj::<virtio_gpu_mem_entry>() {
                        Ok(entry) => {
                            let addr = GuestAddress(entry.addr);
                            let len = entry.length as usize;
                            vecs.push((addr, len))
                        }
                        Err(_) => return Err(GpuResponse::ErrUnspec),
                    }
                }

                virtio_gpu.resource_create_blob(
                    ctx_id,
                    resource_id,
                    resource_create_blob,
                    vecs,
                    mem,
                )
            }
            GpuCommand::SetScanoutBlob(info) => virtio_gpu.set_scanout_blob(
                info.scanout_id,
                BlobScanout {
                    ctx_id: hdr.ctx_id,
                    resource_id: info.resource_id,
                    width: info.width,
                    height: info.height,
                    format: info.format,
                    stride: info.strides[0],
                    offset: info.offsets[0],
                },
            ),
            GpuCommand::ResourceMapBlob(info) => {
                let resource_id = info.resource_id;
                let offset = info.offset;
                virtio_gpu.resource_map_blob(resource_id, &self.shm_region, offset)
            }
            GpuCommand::ResourceUnmapBlob(info) => {
                let resource_id = info.resource_id;
                virtio_gpu.resource_unmap_blob(resource_id, &self.shm_region)
            }
        }
    }

    /// Drain and ack the cursor queue. Cursor commands carry no response
    /// payload, so returning the descriptors (len 0) and signaling is enough
    /// to keep the guest's cursor ring from running out of free entries.
    fn process_cursor_queue(&mut self, virtio_gpu: &mut VirtioGpu) {
        let mem = self.mem.clone();
        let mut used_any = false;
        loop {
            let head = self.cursor_queue.lock().unwrap().pop(&mem);
            let Some(head) = head else { break };
            // Cursor commands need no response payload, but they carry the
            // pointer image and position, which a display backend can show
            // itself instead of the guest drawing a software pointer.
            if let Ok(mut reader) = Reader::new(&mem, head.clone()) {
                match GpuCommand::decode(&mut reader) {
                    Ok((_, GpuCommand::UpdateCursor(info))) => {
                        if let Err(e) = virtio_gpu.update_cursor(info) {
                            debug!("update_cursor failed: {e:?}");
                        }
                    }
                    Ok((_, GpuCommand::MoveCursor(info))) => {
                        if let Err(e) = virtio_gpu.move_cursor(info) {
                            debug!("move_cursor failed: {e:?}");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => debug!("cursor queue: undecodable command: {e:?}"),
                }
            }
            if let Err(e) = self
                .cursor_queue
                .lock()
                .unwrap()
                .add_used(&mem, head.index, 0)
            {
                error!("cursor queue add_used: {e:?}");
            }
            used_any = true;
        }
        if used_any && let Err(e) = self.interrupt.try_signal_used_queue() {
            error!("cursor queue signal: {e:?}");
        }
    }

    fn process_queue(
        &mut self,
        virtio_gpu: &mut VirtioGpu,
        control_queue: &Arc<Mutex<VirtQueue>>,
    ) -> bool {
        let mut used_any = false;
        let mem = self.mem.clone();

        loop {
            let head = control_queue.lock().unwrap().pop(&mem);

            if let Some(head) = head {
                let mut reader = Reader::new(&mem, head.clone())
                    .map_err(GpuError::QueueReader)
                    .unwrap();
                let mut writer = Writer::new(&mem, head.clone())
                    .map_err(GpuError::QueueWriter)
                    .unwrap();

                let mut resp = Err(GpuResponse::ErrUnspec);
                let mut gpu_cmd = None;
                let mut ctrl_hdr = None;
                let mut len = 0;

                match GpuCommand::decode(&mut reader) {
                    Ok((hdr, cmd)) => {
                        resp = self.process_gpu_command(virtio_gpu, &mem, hdr, cmd, &mut reader);
                        ctrl_hdr = Some(hdr);
                        gpu_cmd = Some(cmd);
                    }
                    Err(e) => debug!("descriptor decode error: {e:?}"),
                }

                let mut gpu_response = match resp {
                    Ok(gpu_response) => gpu_response,
                    Err(gpu_response) => {
                        debug!("{gpu_cmd:?} -> {gpu_response:?}");
                        gpu_response
                    }
                };

                let mut add_to_queue = true;

                if writer.available_bytes() != 0 {
                    let mut fence_id = 0;
                    let mut ctx_id = 0;
                    let mut flags = 0;
                    let mut ring_idx = 0;
                    let mut fence_created = false;
                    if let Some(_cmd) = gpu_cmd {
                        let ctrl_hdr = ctrl_hdr.unwrap();
                        if ctrl_hdr.flags & VIRTIO_GPU_FLAG_FENCE != 0 {
                            flags = ctrl_hdr.flags;
                            fence_id = ctrl_hdr.fence_id;
                            ctx_id = ctrl_hdr.ctx_id;
                            ring_idx = ctrl_hdr.ring_idx;

                            let fence = RutabagaFence {
                                flags,
                                fence_id,
                                ctx_id,
                                ring_idx,
                            };
                            gpu_response = match virtio_gpu.create_fence(fence) {
                                Ok(_) => {
                                    fence_created = true;
                                    gpu_response
                                }
                                Err(fence_resp) => {
                                    // No fence exists to retire, so the fenced
                                    // command must complete immediately — a
                                    // deferred descriptor would never be
                                    // returned and the guest's dma-fence wait
                                    // (e.g. a cursor-plane commit) would hang
                                    // forever. Seen on macOS, where the Venus
                                    // virglrenderer build rejects ctx0 fences.
                                    static FENCE_ERR_ONCE: std::sync::Once = std::sync::Once::new();
                                    FENCE_ERR_ONCE.call_once(|| {
                                        warn!(
                                            "create_fence failed; completing fenced commands immediately: {fence_resp:?}"
                                        );
                                    });
                                    gpu_response
                                }
                            };
                        }
                    }

                    // Prepare the response now, even if it is going to wait until
                    // fence is complete.
                    match gpu_response.encode(flags, fence_id, ctx_id, ring_idx, &mut writer) {
                        Ok(l) => len = l,
                        Err(e) => debug!("ctrl queue response encode error: {e:?}"),
                    }

                    if flags & VIRTIO_GPU_FLAG_FENCE != 0 && fence_created {
                        let ring = match flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                            0 => VirtioGpuRing::Global,
                            _ => VirtioGpuRing::ContextSpecific { ctx_id, ring_idx },
                        };

                        add_to_queue = virtio_gpu.process_fence(ring, fence_id, head.index, len);
                    }
                }

                if add_to_queue {
                    if let Err(e) = control_queue
                        .lock()
                        .unwrap()
                        .add_used(&mem, head.index, len)
                    {
                        error!("failed to add used elements to the queue: {e:?}");
                    }
                    used_any = true;
                }
            } else {
                break;
            }
        }

        debug!("gpu: process_queue exit");
        used_any
    }
}
