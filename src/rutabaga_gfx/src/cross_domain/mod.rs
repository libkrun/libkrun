// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The cross-domain component type, specialized for allocating and sharing resources across domain
//! boundaries.

#[cfg(feature = "x")]
use libc::{FUTEX_WAKE_BITSET, c_int};
use libc::{O_ACCMODE, O_WRONLY};
use log::{error, info};
use nix::fcntl::{FcntlArg, fcntl};
#[cfg(feature = "x")]
use nix::sys::mman::{MapFlags, ProtFlags, mmap, munmap};
use std::cmp::max;
use std::collections::BTreeMap as Map;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::ffi::c_void;
use std::fs::{File, read_link};
use std::io::{Seek, SeekFrom};
use std::mem::size_of;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
#[cfg(feature = "x")]
use std::ptr;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
#[cfg(feature = "x")]
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

use crate::DrmFormat;
use crate::ImageAllocationInfo;
use crate::ImageMemoryRequirements;
use crate::RutabagaGralloc;
use crate::RutabagaGrallocFlags;
use crate::cross_domain::cross_domain_protocol::*;
use crate::cross_domain::sys::Receiver;
use crate::cross_domain::sys::Sender;
use crate::cross_domain::sys::SystemStream;
use crate::cross_domain::sys::WaitContext;
use crate::cross_domain::sys::channel;
use crate::cross_domain::sys::channel_signal;
use crate::cross_domain::sys::channel_wait;
use crate::cross_domain::sys::read_volatile;
use crate::cross_domain::sys::write_volatile;
use crate::rutabaga_core::ExportTable;
use crate::rutabaga_core::RutabagaComponent;
use crate::rutabaga_core::RutabagaContext;
use crate::rutabaga_core::RutabagaResource;
use crate::rutabaga_os::SafeDescriptor;
use crate::rutabaga_utils::*;

mod cross_domain_protocol;
mod sys;

#[allow(dead_code)]
const WAIT_CONTEXT_MAX: usize = 16;

pub struct CrossDomainEvent {
    token: CrossDomainToken,
    hung_up: bool,
    readable: bool,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CrossDomainToken {
    ContextChannel,
    WaylandReadPipe(u32),
    Resample,
    Kill,
    #[cfg(feature = "x")]
    Futex(u32),
    ReadEventfd(u32),
}

const CROSS_DOMAIN_DEFAULT_BUFFER_SIZE: usize = 4096;
const CROSS_DOMAIN_MAX_SEND_RECV_SIZE: usize =
    CROSS_DOMAIN_DEFAULT_BUFFER_SIZE - size_of::<CrossDomainSendReceive>();
const CROSS_DOMAIN_MAX_SEND_RECV_SIZE_V2: usize =
    CROSS_DOMAIN_DEFAULT_BUFFER_SIZE - size_of::<CrossDomainSendReceiveV2>();

pub(crate) enum CrossDomainItem {
    ImageRequirements(ImageMemoryRequirements),
    ShmBlob(SafeDescriptor),
    DmaBuf(SafeDescriptor),
    #[allow(dead_code)] // `WaylandReadPipe` is never constructed on Windows.
    WaylandReadPipe(File),
    WaylandWritePipe(File),
    Eventfd(File),
}

pub(crate) enum CrossDomainJob {
    HandleFence(RutabagaFence),
    #[allow(dead_code)] // `AddReadPipe` is never constructed on Windows.
    AddReadPipe(u32),
    Finish,
    #[cfg(feature = "x")]
    AddFutex(u32, Arc<Receiver>),
    AddReadEventfd(u32),
}

enum RingWrite<'a, T> {
    Write(T, Option<&'a [u8]>),
    WriteFromFile(CrossDomainReadWrite, &'a mut File, bool),
}

pub(crate) type CrossDomainResources = Arc<Mutex<Map<u32, CrossDomainResource>>>;
type CrossDomainJobs = Mutex<Option<VecDeque<CrossDomainJob>>>;
pub(crate) type CrossDomainItemState = Arc<Mutex<CrossDomainItems>>;
pub(crate) type CrossDomainFutexes = Arc<Mutex<Map<u32, CrossDomainFutex>>>;

pub(crate) struct CrossDomainResource {
    #[allow(dead_code)] // `handle` is never used on Windows.
    pub handle: Option<Arc<RutabagaHandle>>,
    pub backing_iovecs: Option<Vec<RutabagaIovec>>,
}

pub(crate) struct CrossDomainItems {
    descriptor_id: u32,
    read_pipe_id: u32,
    table: Map<u32, CrossDomainItem>,
}

pub(crate) struct CrossDomainState {
    context_resources: CrossDomainResources,
    #[allow(dead_code)] // `futexes` is never used on macOS.
    futexes: CrossDomainFutexes,
    query_ring_id: u32,
    channel_ring_id: u32,
    #[allow(dead_code)] // `connection` is never used on Windows.
    pub(crate) connection: Option<SystemStream>,
    jobs: CrossDomainJobs,
    jobs_cvar: Condvar,
}

struct CrossDomainWorker {
    wait_ctx: WaitContext,
    state: Arc<CrossDomainState>,
    pub(crate) item_state: CrossDomainItemState,
    fence_handler: RutabagaFenceHandler,
    protocol_version: u32,
}

#[allow(dead_code)] // Never used on macOS
struct FutexPtr(NonNull<c_void>);
unsafe impl Send for FutexPtr {}

#[allow(dead_code)] // Never used on macOS
pub(crate) struct CrossDomainFutex {
    address: FutexPtr,
    handle: SafeDescriptor,
    watcher_thread: Option<thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    evt: Arc<Receiver>,
}

#[cfg(feature = "x")]
impl CrossDomainFutex {
    fn watcher_thread(
        address: FutexPtr,
        shutdown: Arc<AtomicBool>,
        sender: Sender,
        initial_value: u32,
    ) {
        let op = libc::FUTEX_WAIT_BITSET;
        let timeout = ptr::null::<()>();
        let uaddr2 = ptr::null::<()>();
        let val3 = 1u32;
        let address = address.0;
        let atomic_val = unsafe { AtomicU32::from_ptr(address.as_ptr() as *mut u32) };
        // The goal of this code is to ensure that the other side observes at least
        // the latest wake event along with the value that the futex had when that
        // wake event was signaled.

        // The initial value is passed in from the futex creation, and therefore
        // was loaded synchronously with the cross domain operation that created
        // the futex, so it cannot have an associated wake event yet.
        let mut val = initial_value;
        let _ = channel_signal(&sender);
        loop {
            // This returns when the futex is woken up OR if the value has changed.
            unsafe {
                libc::syscall(libc::SYS_futex, address, op, val, timeout, uaddr2, val3);
            }
            // Load the new value, which the other side is guaranteed to observe.
            val = atomic_val.load(Ordering::SeqCst);
            // If this wake was triggered by the shutdown code below, just bail.
            // If the shutdown command is issued after this point, then it will
            // change the futex value, which will disagree with the one we read
            // above, so we will still not block in SYS_futex.
            if shutdown.load(Ordering::SeqCst) {
                // Signal the futex to process the shutdown and remove it from
                // the waiter table
                let _ = channel_signal(&sender);
                break;
            }
            // Signal the other side after the load. If another change occurs and
            // another wake is signaled here, we will miss the wake, but the
            // disagreeing value will cause SYS_futex to return early.
            if channel_signal(&sender).is_err() {
                break;
            }
        }
    }

    fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let atomic_val = unsafe { AtomicU32::from_ptr(self.address.0.as_ptr() as *mut u32) };
        let v = atomic_val.load(Ordering::SeqCst);
        atomic_val.store(!v, Ordering::SeqCst);
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                self.address.0,
                libc::FUTEX_WAKE,
                i32::MAX,
                ptr::null::<()>(),
                ptr::null::<()>(),
                0,
            );
        }
        self.watcher_thread.take().unwrap().join().unwrap();
    }

    fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

#[cfg(feature = "x")]
impl Drop for CrossDomainFutex {
    fn drop(&mut self) {
        if !self.is_shutdown() {
            log::info!("Futex dropped without shutdown");
            self.shutdown();
        }
        unsafe {
            munmap(self.address.0, 4).unwrap();
        }
    }
}

pub(crate) struct CrossDomainContext {
    #[allow(dead_code)] // `channels` is unused on Windows.
    pub(crate) channels: Option<Vec<RutabagaChannel>>,
    gralloc: Arc<Mutex<RutabagaGralloc>>,
    pub(crate) state: Option<Arc<CrossDomainState>>,
    pub(crate) context_resources: CrossDomainResources,
    pub(crate) item_state: CrossDomainItemState,
    pub(crate) futexes: CrossDomainFutexes,
    fence_handler: RutabagaFenceHandler,
    #[allow(dead_code)] // `export_table` is never used on macOS.
    export_table: Option<ExportTable>,
    worker_thread: Option<thread::JoinHandle<RutabagaResult<()>>>,
    pub(crate) resample_evt: Option<Sender>,
    kill_evt: Option<Sender>,
    protocol_version: u32,
}

/// The CrossDomain component contains a list of channels that the guest may connect to and the
/// ability to allocate memory.
pub struct CrossDomain {
    channels: Option<Vec<RutabagaChannel>>,
    gralloc: Arc<Mutex<RutabagaGralloc>>,
    fence_handler: RutabagaFenceHandler,
    export_table: Option<ExportTable>,
}

// TODO(gurchetansingh): optimize the item tracker.  Each requirements blob is long-lived and can
// be stored in a Slab or vector.  Descriptors received from the Wayland socket *seem* to come one
// at a time, and can be stored as options.  Need to confirm.
pub(crate) fn add_item(item_state: &CrossDomainItemState, item: CrossDomainItem) -> u32 {
    let mut items = item_state.lock().unwrap();

    let item_id = match item {
        CrossDomainItem::WaylandReadPipe(_) => {
            items.read_pipe_id += 1;
            max(items.read_pipe_id, CROSS_DOMAIN_PIPE_READ_START)
        }
        _ => {
            items.descriptor_id += 1;
            items.descriptor_id
        }
    };

    items.table.insert(item_id, item);

    item_id
}

impl Default for CrossDomainItems {
    fn default() -> Self {
        // Odd for descriptors, and even for requirement blobs.
        CrossDomainItems {
            descriptor_id: 1,
            read_pipe_id: CROSS_DOMAIN_PIPE_READ_START,
            table: Default::default(),
        }
    }
}

impl CrossDomainState {
    fn new(
        query_ring_id: u32,
        channel_ring_id: u32,
        context_resources: CrossDomainResources,
        futexes: CrossDomainFutexes,
        connection: Option<SystemStream>,
    ) -> CrossDomainState {
        CrossDomainState {
            query_ring_id,
            channel_ring_id,
            context_resources,
            futexes,
            connection,
            jobs: Mutex::new(Some(VecDeque::new())),
            jobs_cvar: Condvar::new(),
        }
    }

    pub(crate) fn add_job(&self, job: CrossDomainJob) {
        let mut jobs = self.jobs.lock().unwrap();
        if let Some(queue) = jobs.as_mut() {
            queue.push_back(job);
            self.jobs_cvar.notify_one();
        }
    }

    fn wait_for_job(&self) -> Option<CrossDomainJob> {
        let mut jobs = self.jobs.lock().unwrap();
        loop {
            match jobs.as_mut()?.pop_front() {
                Some(job) => return Some(job),
                None => jobs = self.jobs_cvar.wait(jobs).unwrap(),
            }
        }
    }

    fn write_to_ring<T>(&self, mut ring_write: RingWrite<T>, ring_id: u32) -> RutabagaResult<usize>
    where
        T: FromBytes + IntoBytes + Immutable,
    {
        let mut context_resources = self.context_resources.lock().unwrap();
        let mut bytes_read: usize = 0;

        let resource = context_resources
            .get_mut(&ring_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        let iovecs = resource
            .backing_iovecs
            .as_mut()
            .ok_or(RutabagaError::InvalidIovec)?;

        // Safe because we've verified the iovecs are attached and owned only by this context.
        let slice =
            unsafe { std::slice::from_raw_parts_mut(iovecs[0].base as *mut u8, iovecs[0].len) };

        match ring_write {
            RingWrite::Write(cmd, opaque_data_opt) => {
                if slice.len() < size_of::<T>() {
                    return Err(RutabagaError::InvalidIovec);
                }
                let (cmd_slice, opaque_data_slice) = slice.split_at_mut(size_of::<T>());
                cmd_slice.copy_from_slice(cmd.as_bytes());
                if let Some(opaque_data) = opaque_data_opt {
                    if opaque_data_slice.len() < opaque_data.len() {
                        return Err(RutabagaError::InvalidIovec);
                    }
                    opaque_data_slice[..opaque_data.len()].copy_from_slice(opaque_data);
                }
            }
            RingWrite::WriteFromFile(mut cmd_read, ref mut file, readable) => {
                if slice.len() < size_of::<CrossDomainReadWrite>() {
                    return Err(RutabagaError::InvalidIovec);
                }
                let (cmd_slice, opaque_data_slice) =
                    slice.split_at_mut(size_of::<CrossDomainReadWrite>());

                if readable {
                    bytes_read = read_volatile(file, opaque_data_slice)?;
                }

                if bytes_read == 0 {
                    cmd_read.hang_up = 1;
                }

                cmd_read.opaque_data_size = bytes_read.try_into()?;
                cmd_slice.copy_from_slice(cmd_read.as_bytes());
            }
        }

        Ok(bytes_read)
    }
}

impl CrossDomainWorker {
    fn new(
        wait_ctx: WaitContext,
        state: Arc<CrossDomainState>,
        item_state: CrossDomainItemState,
        fence_handler: RutabagaFenceHandler,
        protocol_version: u32,
    ) -> CrossDomainWorker {
        CrossDomainWorker {
            wait_ctx,
            state,
            item_state,
            fence_handler,
            protocol_version,
        }
    }

    // Handles the fence according the the token according to the event token.  On success, a
    // boolean value indicating whether the worker thread should be stopped is returned.
    fn handle_fence(
        &mut self,
        fence: RutabagaFence,
        thread_resample_evt: &Receiver,
        receive_buf: &mut [u8],
    ) -> RutabagaResult<()> {
        let events = self.wait_ctx.wait()?;

        // The worker thread must:
        //
        // (1) Poll the ContextChannel (usually Wayland)
        // (2) Poll a number of WaylandReadPipes
        // (3) handle jobs from the virtio-gpu thread.
        //
        // We can only process one event at a time, because each `handle_fence` call is associated
        // with a guest virtio-gpu fence.  Signaling the fence means it's okay for the guest to
        // access ring data.  If two events are available at the same time (say a ContextChannel
        // event and a WaylandReadPipe event), and we write responses for both using the same guest
        // fence data, that will break the expected order of events.  We need the guest to generate
        // a new fence before we can resume polling.
        //
        // The CrossDomainJob queue gurantees a new fence has been generated before polling is
        // resumed.
        if let Some(event) = events.first() {
            match event.token {
                CrossDomainToken::ContextChannel => {
                    if self.protocol_version == 0 {
                        self.process_receive::<CrossDomainSendReceive, {CrossDomainSendReceive::MAX_IDENTIFIERS}>(fence, receive_buf)?;
                    } else {
                        self.process_receive::<CrossDomainSendReceiveV2, {CrossDomainSendReceiveV2::MAX_IDENTIFIERS}>(fence, receive_buf)?;
                    }
                }
                CrossDomainToken::Resample => {
                    // The resample event is triggered when the job queue is in the following state:
                    //
                    // [CrossDomain::AddReadPipe(..)] -> END
                    //
                    // After this event, the job queue will be the following state:
                    //
                    // [CrossDomain::AddReadPipe(..)] -> [CrossDomain::HandleFence(..)] -> END
                    //
                    // Fence handling is tied to some new data transfer across a pollable
                    // descriptor.  When we're adding new descriptors, we stop polling.
                    channel_wait(thread_resample_evt)?;
                    self.state.add_job(CrossDomainJob::HandleFence(fence));
                }
                CrossDomainToken::WaylandReadPipe(pipe_id) => {
                    let mut items = self.item_state.lock().unwrap();
                    let mut cmd_read: CrossDomainReadWrite = Default::default();
                    let bytes_read;

                    cmd_read.hdr.cmd = CROSS_DOMAIN_CMD_READ;
                    cmd_read.identifier = pipe_id;

                    let item = items
                        .table
                        .get_mut(&pipe_id)
                        .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

                    match item {
                        CrossDomainItem::WaylandReadPipe(file) => {
                            let ring_write =
                                RingWrite::WriteFromFile(cmd_read, file, event.readable);
                            bytes_read = self.state.write_to_ring::<CrossDomainReadWrite>(
                                ring_write,
                                self.state.channel_ring_id,
                            )?;

                            // Zero bytes read indicates end-of-file on POSIX.
                            if event.hung_up && bytes_read == 0 {
                                self.wait_ctx
                                    .delete(CrossDomainToken::WaylandReadPipe(pipe_id), file)?;
                            }
                        }
                        _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                    }

                    if event.hung_up && bytes_read == 0 {
                        items.table.remove(&pipe_id);
                    }

                    self.fence_handler.call(fence);
                }
                CrossDomainToken::ReadEventfd(efd_id) => {
                    let mut items = self.item_state.lock().unwrap();
                    let mut cmd_read: CrossDomainReadWrite = Default::default();

                    cmd_read.hdr.cmd = CROSS_DOMAIN_CMD_READ;
                    cmd_read.identifier = efd_id;

                    let item = items
                        .table
                        .get_mut(&efd_id)
                        .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

                    match item {
                        CrossDomainItem::Eventfd(file) => {
                            let ring_write =
                                RingWrite::WriteFromFile(cmd_read, file, event.readable);
                            self.state.write_to_ring::<CrossDomainReadWrite>(
                                ring_write,
                                self.state.channel_ring_id,
                            )?;
                        }
                        _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                    }

                    self.fence_handler.call(fence);
                }
                #[cfg(feature = "x")]
                CrossDomainToken::Futex(id) => {
                    let mut futexes = self.state.futexes.lock().unwrap();
                    let mut remove = false;
                    let mut fence = Some(fence);

                    if let Some(ftx) = futexes.get(&id) {
                        if ftx.is_shutdown() {
                            self.wait_ctx
                                .delete(CrossDomainToken::Futex(id), ftx.evt.as_ref())?;
                            remove = true;
                        } else {
                            channel_wait(&ftx.evt)?;

                            let mut cmd_ftx: CrossDomainFutexSignal = Default::default();
                            cmd_ftx.hdr.cmd = CROSS_DOMAIN_CMD_FUTEX_SIGNAL;
                            cmd_ftx.id = id;
                            self.state.write_to_ring(
                                RingWrite::Write(cmd_ftx, None),
                                self.state.channel_ring_id,
                            )?;
                            self.fence_handler.call(fence.take().unwrap());
                        }
                    };

                    if let Some(fence) = fence {
                        self.state.add_job(CrossDomainJob::HandleFence(fence));
                    }

                    if remove {
                        futexes.remove(&id);
                    }
                }
                CrossDomainToken::Kill => {
                    self.fence_handler.call(fence);
                }
            }
        }

        Ok(())
    }

    fn process_receive<T: CrossDomainSendReceiveBase, const MAX_IDENTIFIERS: usize>(
        &mut self,
        fence: RutabagaFence,
        receive_buf: &mut [u8],
    ) -> RutabagaResult<()> {
        let (len, files) = self.state.receive_msg::<MAX_IDENTIFIERS>(receive_buf)?;
        let mut cmd_receive: T = Default::default();

        let num_files = files.len();
        cmd_receive.hdr_mut().cmd = CROSS_DOMAIN_CMD_RECEIVE;
        *cmd_receive.num_identifiers_mut() = files.len().try_into()?;
        *cmd_receive.opaque_data_size_mut() = len.try_into()?;

        let iter = cmd_receive
            .iter_over_identifiers()
            .zip(files)
            .take(num_files);

        for ((identifier, identifier_type, identifier_size), mut file) in iter {
            // Safe since the descriptors from receive_msg(..) are owned by us and valid.
            if let Ok(seek_size) = file.seek(SeekFrom::End(0)) {
                *identifier_type = CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
                *identifier_size = seek_size.try_into()?;
                let fd_path = read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
                    .unwrap()
                    .as_os_str()
                    .to_string_lossy()
                    .into_owned();
                *identifier = if fd_path.starts_with("/dmabuf:") {
                    add_item(&self.item_state, CrossDomainItem::DmaBuf(file.into()))
                } else if fd_path.starts_with("/memfd:") {
                    add_item(&self.item_state, CrossDomainItem::ShmBlob(file.into()))
                } else if fd_path.starts_with("anon_inode:[eventfd]") {
                    *identifier_type = CROSS_DOMAIN_ID_TYPE_EVENTFD;
                    add_item(&self.item_state, CrossDomainItem::Eventfd(file))
                } else {
                    info!("Unknown fd item path {fd_path:?}, treating as a shmem blob");
                    add_item(&self.item_state, CrossDomainItem::ShmBlob(file.into()))
                };
            } else {
                let flags = fcntl(&file, FcntlArg::F_GETFL)?;
                *identifier_type = match flags & O_ACCMODE {
                    O_WRONLY => CROSS_DOMAIN_ID_TYPE_WRITE_PIPE,
                    _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                };
                *identifier = add_item(&self.item_state, CrossDomainItem::WaylandWritePipe(file));
            }
        }

        self.state.write_to_ring(
            RingWrite::Write(cmd_receive, Some(&receive_buf[0..len])),
            self.state.channel_ring_id,
        )?;
        self.fence_handler.call(fence);
        Ok(())
    }

    fn run(
        &mut self,
        thread_kill_evt: Receiver,
        thread_resample_evt: Receiver,
    ) -> RutabagaResult<()> {
        self.wait_ctx
            .add(CrossDomainToken::Resample, &thread_resample_evt)?;
        self.wait_ctx
            .add(CrossDomainToken::Kill, &thread_kill_evt)?;
        let buf_size = if self.protocol_version == 0 {
            CROSS_DOMAIN_MAX_SEND_RECV_SIZE
        } else {
            CROSS_DOMAIN_MAX_SEND_RECV_SIZE_V2
        };
        let mut receive_buf: Vec<u8> = vec![0; buf_size];

        while let Some(job) = self.state.wait_for_job() {
            match job {
                CrossDomainJob::HandleFence(fence) => {
                    match self.handle_fence(fence, &thread_resample_evt, &mut receive_buf) {
                        Ok(()) => (),
                        Err(e) => {
                            error!("Worker halting due to: {e}");
                            return Err(e);
                        }
                    }
                }
                CrossDomainJob::AddReadPipe(read_pipe_id) => {
                    let items = self.item_state.lock().unwrap();
                    let item = items
                        .table
                        .get(&read_pipe_id)
                        .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

                    match item {
                        CrossDomainItem::WaylandReadPipe(file) => self
                            .wait_ctx
                            .add(CrossDomainToken::WaylandReadPipe(read_pipe_id), file)?,
                        _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                    }
                }
                CrossDomainJob::AddReadEventfd(efd_id) => {
                    let items = self.item_state.lock().unwrap();
                    let item = items
                        .table
                        .get(&efd_id)
                        .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

                    match item {
                        CrossDomainItem::Eventfd(file) => self
                            .wait_ctx
                            .add(CrossDomainToken::ReadEventfd(efd_id), file)?,
                        _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                    }
                }
                #[cfg(feature = "x")]
                CrossDomainJob::AddFutex(id, recv) => {
                    self.wait_ctx.add(CrossDomainToken::Futex(id), recv)?;
                }
                CrossDomainJob::Finish => return Ok(()),
            }
        }

        Ok(())
    }
}

impl CrossDomain {
    /// Initializes the cross-domain component by taking the the rutabaga channels (if any) and
    /// initializing rutabaga gralloc.
    pub fn init(
        channels: Option<Vec<RutabagaChannel>>,
        fence_handler: RutabagaFenceHandler,
        export_table: Option<ExportTable>,
    ) -> RutabagaResult<Box<dyn RutabagaComponent>> {
        let gralloc = RutabagaGralloc::new()?;
        Ok(Box::new(CrossDomain {
            channels,
            gralloc: Arc::new(Mutex::new(gralloc)),
            fence_handler,
            export_table,
        }))
    }
}

impl CrossDomainContext {
    fn initialize(&mut self, cmd_init: &CrossDomainInitV1) -> RutabagaResult<()> {
        if !self
            .context_resources
            .lock()
            .unwrap()
            .contains_key(&cmd_init.query_ring_id)
        {
            return Err(RutabagaError::InvalidResourceId);
        }

        let query_ring_id = cmd_init.query_ring_id;
        let channel_ring_id = cmd_init.channel_ring_id;
        let context_resources = self.context_resources.clone();
        let futexes = self.futexes.clone();
        let protocol_version = cmd_init.protocol_version;

        // Zero means no requested channel.
        if cmd_init.channel_type != 0 {
            if !self
                .context_resources
                .lock()
                .unwrap()
                .contains_key(&cmd_init.channel_ring_id)
            {
                return Err(RutabagaError::InvalidResourceId);
            }

            let connection = self.get_connection(cmd_init)?;

            let (kill_evt, thread_kill_evt) = channel()?;
            let (resample_evt, thread_resample_evt) = channel()?;

            let mut wait_ctx = WaitContext::new()?;
            match &connection {
                Some(connection) => {
                    wait_ctx.add(CrossDomainToken::ContextChannel, connection)?;
                }
                None => return Err(RutabagaError::Unsupported),
            };

            let state = Arc::new(CrossDomainState::new(
                query_ring_id,
                channel_ring_id,
                context_resources,
                futexes,
                connection,
            ));

            let thread_state = state.clone();
            let thread_items = self.item_state.clone();
            let thread_fence_handler = self.fence_handler.clone();

            let worker_result = thread::Builder::new()
                .name("cross domain".to_string())
                .spawn(move || -> RutabagaResult<()> {
                    CrossDomainWorker::new(
                        wait_ctx,
                        thread_state,
                        thread_items,
                        thread_fence_handler,
                        protocol_version,
                    )
                    .run(thread_kill_evt, thread_resample_evt)
                });

            self.worker_thread = Some(worker_result.unwrap());
            self.state = Some(state);
            self.resample_evt = Some(resample_evt);
            self.kill_evt = Some(kill_evt);
        } else {
            self.state = Some(Arc::new(CrossDomainState::new(
                query_ring_id,
                channel_ring_id,
                context_resources,
                futexes,
                None,
            )));
        }

        self.protocol_version = protocol_version;

        Ok(())
    }

    fn get_image_requirements(
        &mut self,
        cmd_get_reqs: &CrossDomainGetImageRequirements,
    ) -> RutabagaResult<()> {
        let info = ImageAllocationInfo {
            width: cmd_get_reqs.width,
            height: cmd_get_reqs.height,
            drm_format: DrmFormat::from(cmd_get_reqs.drm_format),
            flags: RutabagaGrallocFlags::new(cmd_get_reqs.flags),
        };

        let reqs = self
            .gralloc
            .lock()
            .unwrap()
            .get_image_memory_requirements(info)?;

        let mut response = CrossDomainImageRequirements {
            strides: reqs.strides,
            offsets: reqs.offsets,
            modifier: reqs.modifier,
            size: reqs.size,
            blob_id: 0,
            map_info: reqs.map_info,
            memory_idx: -1,
            physical_device_idx: -1,
        };

        if let Some(ref vk_info) = reqs.vulkan_info {
            response.memory_idx = vk_info.memory_idx as i32;
            // We return -1 for now since physical_device_idx is deprecated. If this backend is
            // put back into action, it should be using device_id from the request instead.
            response.physical_device_idx = -1;
        }

        if let Some(state) = &self.state {
            response.blob_id = add_item(&self.item_state, CrossDomainItem::ImageRequirements(reqs));
            state.write_to_ring(RingWrite::Write(response, None), state.query_ring_id)?;
            Ok(())
        } else {
            Err(RutabagaError::InvalidCrossDomainState)
        }
    }

    #[cfg(feature = "x")]
    fn futex_signal(&mut self, cmd_futex_signal: &CrossDomainFutexSignal) -> RutabagaResult<()> {
        let futexes = self.futexes.lock().unwrap();
        if let Some(ftx) = futexes.get(&cmd_futex_signal.id) {
            let uaddr = ftx.address.0;
            let op = FUTEX_WAKE_BITSET;
            let val = c_int::MAX;
            let timeout = ptr::null::<()>();
            let uaddr2 = ptr::null::<()>();
            let val3 = !1u32;
            unsafe {
                libc::syscall(libc::SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
            }
            Ok(())
        } else {
            Err(RutabagaError::InvalidCrossDomainItemId)
        }
    }

    #[cfg(feature = "x")]
    fn futex_destroy(&mut self, cmd_futex_destroy: &CrossDomainFutexDestroy) -> RutabagaResult<()> {
        let mut futexes = self.futexes.lock().unwrap();
        futexes
            .get_mut(&cmd_futex_destroy.id)
            .ok_or(RutabagaError::InvalidCrossDomainItemId)?
            .shutdown();
        Ok(())
    }

    #[cfg(feature = "x")]
    fn futex_new(&mut self, cmd_futex_new: &CrossDomainFutexNew) -> RutabagaResult<()> {
        let exports = self
            .export_table
            .as_ref()
            .ok_or(RutabagaError::InvalidCrossDomainItemId)?
            .lock()
            .unwrap();

        let mut futexes = self.futexes.lock().unwrap();
        if futexes.contains_key(&cmd_futex_new.id) {
            return Err(RutabagaError::AlreadyInUse);
        }

        let file = exports
            .get(&(cmd_futex_new.fs_id, cmd_futex_new.handle))
            .ok_or(RutabagaError::InvalidCrossDomainItemId)?
            .try_clone()?;

        let handle = SafeDescriptor::from(file);
        let address = unsafe {
            mmap(
                None,
                4.try_into().unwrap(),
                ProtFlags::PROT_WRITE | ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                handle.as_fd(),
                0,
            )?
        };

        let shutdown = Arc::new(AtomicBool::new(false));
        let (ftx_evt, thread_ftx_evt) = channel()?;

        let thread_ftx_evt = Arc::new(thread_ftx_evt);

        let id = cmd_futex_new.id;

        let state = self
            .state
            .as_ref()
            .ok_or(RutabagaError::InvalidCrossDomainState)?;
        state.add_job(CrossDomainJob::AddFutex(id, thread_ftx_evt.clone()));

        let shutdown2 = shutdown.clone();
        let fptr = FutexPtr(address);
        let initial_value =
            unsafe { AtomicU32::from_ptr(address.as_ptr() as *mut u32) }.load(Ordering::SeqCst);
        let watcher_thread = Some(
            thread::Builder::new()
                .name(format!("futexw {}", cmd_futex_new.id))
                .spawn(move || {
                    CrossDomainFutex::watcher_thread(fptr, shutdown2, ftx_evt, initial_value);
                })?,
        );

        futexes.insert(
            id,
            CrossDomainFutex {
                handle,
                address: FutexPtr(address),
                watcher_thread,
                shutdown,
                evt: thread_ftx_evt,
            },
        );

        Ok(())
    }

    fn read_eventfd_new(
        &mut self,
        cmd_eventfd_new: &CrossDomainReadEventfdNew,
    ) -> RutabagaResult<()> {
        let items = self.item_state.lock().unwrap();

        if let Some(item) = items.table.get(&cmd_eventfd_new.id) {
            if let CrossDomainItem::Eventfd(_) = item {
                self.state
                    .as_ref()
                    .unwrap()
                    .add_job(CrossDomainJob::AddReadEventfd(cmd_eventfd_new.id));
                channel_signal(self.resample_evt.as_ref().unwrap())?;
                Ok(())
            } else {
                Err(RutabagaError::InvalidCrossDomainItemType)
            }
        } else {
            Err(RutabagaError::InvalidCrossDomainItemId)
        }
    }

    fn write(&self, cmd_write: &CrossDomainReadWrite, opaque_data: &[u8]) -> RutabagaResult<()> {
        let len: usize = cmd_write.opaque_data_size.try_into()?;

        // Phase 1 (under lock): look up the item and dup() its fd. We release
        // the lock before the actual write syscall so unrelated operations on
        // item_state aren't serialized behind it. The previous design held
        // the lock across write_volatile, which was the dominant contention
        // source for per-period eventfd writes from active audio streams
        // competing with concurrent stream-create churn (process_receive's
        // add_item path also takes this lock). Cloning the fd is a cheap
        // dup() syscall; the actual write — which can be longer for pipe
        // writes, and rate-limited for eventfds — happens lock-free.
        let fd = {
            let items = self.item_state.lock().unwrap();
            let item = items
                .table
                .get(&cmd_write.identifier)
                .ok_or(RutabagaError::InvalidCrossDomainItemId)?;
            match item {
                CrossDomainItem::WaylandWritePipe(file) | CrossDomainItem::Eventfd(file) => {
                    file.try_clone()?
                }
                _ => return Err(RutabagaError::InvalidCrossDomainItemType),
            }
        };

        // Phase 2 (lock-free): do the actual write.
        if len != 0 {
            write_volatile(&fd, opaque_data)?;
        }

        // Phase 3 (under lock): on hang_up, drop the item from the table.
        // Without hang_up the item stays — common for Eventfd repeated wakeups
        // and for any pipe being held open for further writes. This matches
        // the previous "remove + conditional re-insert" behavior, but in the
        // common (hang_up == 0) case avoids touching the table at all.
        if cmd_write.hang_up != 0 {
            let mut items = self.item_state.lock().unwrap();
            items.table.remove(&cmd_write.identifier);
        }

        Ok(())
    }

    fn process_cmd_send<T: CrossDomainSendReceiveBase, const MAX_IDENTIFIERS: usize>(
        &mut self,
        commands: &mut [u8],
    ) -> RutabagaResult<()> {
        let opaque_data_offset = size_of::<T>();
        let (mut cmd_send, _) = T::read_from_prefix(commands.as_bytes())
            .map_err(|_| RutabagaError::InvalidCommandBuffer)?;

        let opaque_data = commands
            .get_mut(
                opaque_data_offset..opaque_data_offset + *cmd_send.opaque_data_size_mut() as usize,
            )
            .ok_or(RutabagaError::InvalidCommandSize(
                *cmd_send.opaque_data_size_mut() as usize,
            ))?;

        self.send::<T, MAX_IDENTIFIERS>(&mut cmd_send, opaque_data)?;
        Ok(())
    }
}

impl Drop for CrossDomainContext {
    fn drop(&mut self) {
        if let Some(state) = &self.state {
            state.add_job(CrossDomainJob::Finish);
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Log the error, but still try to join the worker thread
            match channel_signal(&kill_evt) {
                Ok(_) => (),
                Err(e) => {
                    error!("failed to write cross domain kill event: {e}");
                }
            }

            if let Some(worker_thread) = self.worker_thread.take() {
                let _ = worker_thread.join();
            }
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, IntoBytes, Immutable, FromBytes)]
struct CrossDomainInitVMinus1 {
    hdr: CrossDomainHeader,
    query_ring_id: u32,
    channel_type: u32,
}

impl CrossDomainInitVMinus1 {
    pub(crate) fn upgrade(&self) -> CrossDomainInitV1 {
        CrossDomainInitV1 {
            hdr: self.hdr,
            query_ring_id: self.query_ring_id,
            channel_ring_id: self.query_ring_id,
            channel_type: self.channel_type,
            protocol_version: 0,
        }
    }
}

impl RutabagaContext for CrossDomainContext {
    fn context_create_blob(
        &mut self,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        handle_opt: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        let item_id = resource_create_blob.blob_id as u32;

        let mut items = self.item_state.lock().unwrap();
        let item = items
            .table
            .get_mut(&item_id)
            .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

        // Items that are kept in the table after usage.
        if let CrossDomainItem::ImageRequirements(reqs) = item {
            if reqs.size != resource_create_blob.size {
                return Err(RutabagaError::SpecViolation("blob size mismatch"));
            }

            // Strictly speaking, it's against the virtio-gpu spec to allocate memory in the context
            // create blob function, which says "the actual allocation is done via
            // VIRTIO_GPU_CMD_SUBMIT_3D."  However, atomic resource creation is easiest for the
            // cross-domain use case, so whatever.
            let hnd = match handle_opt {
                Some(handle) => handle,
                None => self.gralloc.lock().unwrap().allocate_memory(*reqs)?,
            };

            let info_3d = Resource3DInfo {
                width: reqs.info.width,
                height: reqs.info.height,
                drm_fourcc: reqs.info.drm_format.into(),
                strides: reqs.strides,
                offsets: reqs.offsets,
                modifier: reqs.modifier,
            };

            // Keep ImageRequirements items and return immediately, since they can be used for subsequent allocations.
            return Ok(RutabagaResource {
                resource_id,
                handle: Some(Arc::new(hnd)),
                blob: true,
                blob_mem: resource_create_blob.blob_mem,
                blob_flags: resource_create_blob.blob_flags,
                map_info: Some(reqs.map_info | RUTABAGA_MAP_ACCESS_RW),
                #[cfg(target_os = "macos")]
                map_ptr: None,
                info_2d: None,
                info_3d: Some(info_3d),
                vulkan_info: reqs.vulkan_info,
                backing_iovecs: None,
                component_mask: 1 << (RutabagaComponentType::CrossDomain as u8),
                size: resource_create_blob.size,
                mapping: None,
            });
        }

        let item = items
            .table
            .remove(&item_id)
            .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

        fn access_mode(descriptor: &SafeDescriptor) -> RutabagaResult<u32> {
            Ok(
                match fcntl(descriptor.as_fd(), FcntlArg::F_GETFL)? & libc::O_ACCMODE {
                    libc::O_RDWR => RUTABAGA_MAP_ACCESS_RW,
                    libc::O_WRONLY => RUTABAGA_MAP_ACCESS_WRITE,
                    _ => RUTABAGA_MAP_ACCESS_READ,
                    // (there is a "secret fourth option" O_WRONLY|O_RDWR meaning "no access", very unlikely we'd see it)
                },
            )
        }

        // Items that are removed from the table after one usage.
        match item {
            CrossDomainItem::ShmBlob(descriptor) => {
                #[allow(unused_mut)]
                let mut access = access_mode(&descriptor)?;
                // Some compositors actually do send descriptors that are O_RDWR but write-sealed (!)
                #[cfg(target_os = "linux")]
                if fcntl(&descriptor, FcntlArg::F_GET_SEALS)? & libc::F_SEAL_WRITE != 0 {
                    access &= !RUTABAGA_MAP_ACCESS_WRITE;
                }

                let hnd = RutabagaHandle {
                    os_handle: descriptor,
                    handle_type: RUTABAGA_MEM_HANDLE_TYPE_SHM,
                };

                Ok(RutabagaResource {
                    resource_id,
                    handle: Some(Arc::new(hnd)),
                    blob: true,
                    blob_mem: resource_create_blob.blob_mem,
                    blob_flags: resource_create_blob.blob_flags,
                    map_info: Some(RUTABAGA_MAP_CACHE_CACHED | access),
                    #[cfg(target_os = "macos")]
                    map_ptr: None,
                    info_2d: None,
                    info_3d: None,
                    vulkan_info: None,
                    backing_iovecs: None,
                    component_mask: 1 << (RutabagaComponentType::CrossDomain as u8),
                    size: resource_create_blob.size,
                    mapping: None,
                })
            }
            CrossDomainItem::DmaBuf(descriptor) => {
                let access = access_mode(&descriptor)?;

                let hnd = RutabagaHandle {
                    os_handle: descriptor,
                    handle_type: RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
                };

                Ok(RutabagaResource {
                    resource_id,
                    handle: Some(Arc::new(hnd)),
                    blob: true,
                    blob_mem: resource_create_blob.blob_mem,
                    blob_flags: resource_create_blob.blob_flags,
                    map_info: Some(RUTABAGA_MAP_CACHE_CACHED | access),
                    #[cfg(target_os = "macos")]
                    map_ptr: None,
                    info_2d: None,
                    info_3d: None,
                    vulkan_info: None,
                    backing_iovecs: None,
                    component_mask: 1 << (RutabagaComponentType::CrossDomain as u8),
                    size: resource_create_blob.size,
                    mapping: None,
                })
            }
            _ => Err(RutabagaError::InvalidCrossDomainItemType),
        }
    }

    fn submit_cmd(&mut self, mut commands: &mut [u8], fence_ids: &[u64]) -> RutabagaResult<()> {
        if !fence_ids.is_empty() {
            return Err(RutabagaError::Unsupported);
        }

        while !commands.is_empty() {
            let (hdr, _) = CrossDomainHeader::read_from_prefix(commands)
                .map_err(|_e| RutabagaError::InvalidCommandBuffer)?;

            match hdr.cmd {
                CROSS_DOMAIN_CMD_INIT => {
                    let cmd_init = CrossDomainInitV1::read_from_prefix(commands.as_bytes())
                        .map(|(x, _)| x)
                        .or_else(|_| {
                            CrossDomainInitV0::read_from_prefix(commands.as_bytes())
                                .map(|(x, _)| x.upgrade())
                        })
                        .or_else(|_| {
                            CrossDomainInitVMinus1::read_from_prefix(commands.as_bytes())
                                .map(|(x, _)| x.upgrade())
                        })
                        .map_err(|_| RutabagaError::InvalidCommandBuffer)?;
                    self.initialize(&cmd_init)?;
                }
                CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS => {
                    let (cmd_get_reqs, _) =
                        CrossDomainGetImageRequirements::read_from_prefix(commands.as_bytes())
                            .map_err(|_| RutabagaError::InvalidCommandBuffer)?;

                    self.get_image_requirements(&cmd_get_reqs)?;
                }
                CROSS_DOMAIN_CMD_SEND => {
                    if self.protocol_version == 0 {
                        self.process_cmd_send::<CrossDomainSendReceive, {CrossDomainSendReceive::MAX_IDENTIFIERS}>(commands)?;
                    } else {
                        self.process_cmd_send::<CrossDomainSendReceiveV2, {CrossDomainSendReceiveV2::MAX_IDENTIFIERS}>(commands)?;
                    }
                }
                CROSS_DOMAIN_CMD_POLL => {
                    // Actual polling is done in the subsequent when creating a fence.
                }
                CROSS_DOMAIN_CMD_WRITE => {
                    let opaque_data_offset = size_of::<CrossDomainReadWrite>();
                    let (cmd_write, _) =
                        CrossDomainReadWrite::read_from_prefix(commands.as_bytes())
                            .map_err(|_| RutabagaError::InvalidCommandBuffer)?;

                    let opaque_data = commands
                        .get_mut(
                            opaque_data_offset
                                ..opaque_data_offset + cmd_write.opaque_data_size as usize,
                        )
                        .ok_or(RutabagaError::InvalidCommandSize(
                            cmd_write.opaque_data_size as usize,
                        ))?;

                    self.write(&cmd_write, opaque_data)?;
                }
                #[cfg(feature = "x")]
                CROSS_DOMAIN_CMD_FUTEX_NEW => {
                    let (cmd_new_futex, _) =
                        CrossDomainFutexNew::read_from_prefix(commands.as_bytes())
                            .map_err(|_| RutabagaError::InvalidCommandBuffer)?;
                    self.futex_new(&cmd_new_futex)?;
                }
                #[cfg(feature = "x")]
                CROSS_DOMAIN_CMD_FUTEX_SIGNAL => {
                    let (cmd_futex_signal, _) =
                        CrossDomainFutexSignal::read_from_prefix(commands.as_bytes())
                            .map_err(|_| RutabagaError::InvalidCommandBuffer)?;
                    self.futex_signal(&cmd_futex_signal)?;
                }
                #[cfg(feature = "x")]
                CROSS_DOMAIN_CMD_FUTEX_DESTROY => {
                    let (cmd_futex_destroy, _) =
                        CrossDomainFutexDestroy::read_from_prefix(commands.as_bytes())
                            .map_err(|_| RutabagaError::InvalidCommandBuffer)?;
                    self.futex_destroy(&cmd_futex_destroy)?;
                }
                CROSS_DOMAIN_CMD_READ_EVENTFD_NEW => {
                    let (cmd_new_efd, _) =
                        CrossDomainReadEventfdNew::read_from_prefix(commands.as_bytes())
                            .map_err(|_| RutabagaError::InvalidCommandBuffer)?;
                    self.read_eventfd_new(&cmd_new_efd)?;
                }
                _ => return Err(RutabagaError::SpecViolation("invalid cross domain command")),
            }

            commands = commands
                .get_mut(hdr.cmd_size as usize..)
                .ok_or(RutabagaError::InvalidCommandSize(hdr.cmd_size as usize))?;
        }

        Ok(())
    }

    fn attach(&mut self, resource: &mut RutabagaResource) {
        self.context_resources.lock().unwrap().insert(
            resource.resource_id,
            CrossDomainResource {
                handle: resource.handle.clone(),
                backing_iovecs: resource.backing_iovecs.take(),
            },
        );
    }

    fn detach(&mut self, resource: &RutabagaResource) {
        self.context_resources
            .lock()
            .unwrap()
            .remove(&resource.resource_id);
    }

    fn context_create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        match fence.ring_idx as u32 {
            CROSS_DOMAIN_QUERY_RING => self.fence_handler.call(fence),
            CROSS_DOMAIN_CHANNEL_RING => {
                if let Some(state) = &self.state {
                    state.add_job(CrossDomainJob::HandleFence(fence));
                }
            }
            _ => return Err(RutabagaError::SpecViolation("unexpected ring type")),
        }

        Ok(())
    }

    fn component_type(&self) -> RutabagaComponentType {
        RutabagaComponentType::CrossDomain
    }
}

impl RutabagaComponent for CrossDomain {
    fn get_capset_info(&self, _capset_id: u32) -> (u32, u32) {
        (0u32, size_of::<CrossDomainCapabilities>() as u32)
    }

    fn get_capset(&self, _capset_id: u32, _version: u32) -> Vec<u8> {
        let mut caps: CrossDomainCapabilities = Default::default();
        if let Some(ref channels) = self.channels {
            for channel in channels {
                caps.supported_channels |= 1 << channel.channel_type;
            }
        }

        if self.gralloc.lock().unwrap().supports_dmabuf() {
            caps.supports_dmabuf = 1;
        }

        if self.gralloc.lock().unwrap().supports_external_gpu_memory() {
            caps.supports_external_gpu_memory = 1;
        }

        // Version 1 supports all commands up to and including CROSS_DOMAIN_CMD_WRITE.
        caps.version = 1;
        caps.as_bytes().to_vec()
    }

    fn create_blob(
        &mut self,
        _ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        iovec_opt: Option<Vec<RutabagaIovec>>,
        handle_opt: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        if resource_create_blob.blob_mem != RUTABAGA_BLOB_MEM_GUEST {
            return Err(RutabagaError::SpecViolation(
                "expected only guest memory blobs",
            ));
        }

        if resource_create_blob.blob_flags & RUTABAGA_BLOB_FLAG_CREATE_GUEST_HANDLE
            == RUTABAGA_BLOB_FLAG_CREATE_GUEST_HANDLE
        {
            if handle_opt.is_none() {
                return Err(RutabagaError::SpecViolation(
                    "expected a handle when using CREATE_GUEST_HANDLE",
                ));
            }
        } else if resource_create_blob.blob_flags != RUTABAGA_BLOB_FLAG_USE_MAPPABLE {
            return Err(RutabagaError::SpecViolation(
                "expected only create-handle or mappable guest memory blobs",
            ));
        }

        Ok(RutabagaResource {
            resource_id,
            handle: handle_opt.map(Arc::new),
            blob: true,
            blob_mem: resource_create_blob.blob_mem,
            blob_flags: resource_create_blob.blob_flags,
            map_info: None,
            #[cfg(target_os = "macos")]
            map_ptr: None,
            info_2d: None,
            info_3d: None,
            vulkan_info: None,
            backing_iovecs: iovec_opt,
            component_mask: 1 << (RutabagaComponentType::CrossDomain as u8),
            size: resource_create_blob.size,
            mapping: None,
        })
    }

    fn create_context(
        &self,
        _ctx_id: u32,
        _context_init: u32,
        _context_name: Option<&str>,
        fence_handler: RutabagaFenceHandler,
    ) -> RutabagaResult<Box<dyn RutabagaContext>> {
        Ok(Box::new(CrossDomainContext {
            channels: self.channels.clone(),
            gralloc: self.gralloc.clone(),
            state: None,
            context_resources: Arc::new(Mutex::new(Default::default())),
            item_state: Arc::new(Mutex::new(Default::default())),
            fence_handler,
            worker_thread: None,
            resample_evt: None,
            kill_evt: None,
            export_table: self.export_table.clone(),
            futexes: Arc::new(Mutex::new(Default::default())),
            protocol_version: 0,
        }))
    }

    // With "drm/virtio: Conditionally allocate virtio_gpu_fence" in the kernel, global fences for
    // cross-domain aren't created.  However, that change is projected to land in the v6.6 kernel.
    // For older kernels, signal the fence immediately on creation.
    fn create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        self.fence_handler.call(fence);
        Ok(())
    }
}
