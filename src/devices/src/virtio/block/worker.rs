use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::DeviceQueue;
use super::super::Queue;
use super::device::{CacheType, DiskProperties};
use crate::virtio::DescriptorChain;

use crate::virtio::InterruptTransport;
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::result;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
#[cfg(target_os = "windows")]
use utils::windows::AsRawFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{ByteValued, GuestMemoryMmap};

#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    DiscardingToZero(io::Error),
    FlushingToDisk(io::Error),
    InvalidDataLength,
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}
// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DiscardWriteData {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}
// Safe because DiscardWriteData only contains plain data.
unsafe impl ByteValued for DiscardWriteData {}

struct ReadJob {
    head_index: u16,
    sector: u64,
    data_len: usize,
    writer: SendWriter,
}

struct SendWriter(Writer<'static>);

// SAFETY: `Writer` holds `VolatileSlice`s into `SharedState.mem`. Each read
// worker keeps an `Arc<SharedState>` while it owns a job, and the epoll thread
// joins those workers before `SharedState` is dropped.
unsafe impl Send for SendWriter {}

struct SharedState {
    queue: Mutex<Queue>,
    mem: GuestMemoryMmap,
    interrupt: InterruptTransport,
    disk: DiskProperties,
}

impl SharedState {
    fn add_used(&self, head_index: u16, len: u32) {
        let mem = &self.mem;
        let mut queue = self.queue.lock().unwrap();
        if let Err(e) = queue.add_used(mem, head_index, len) {
            error!("failed to add used elements to the queue: {e:?}");
        }

        if queue.needs_notification(mem).unwrap()
            && let Err(e) = self.interrupt.try_signal_used_queue()
        {
            error!("error signalling queue: {e:?}");
        }
    }

    fn complete_request(&self, head_index: u16, mut writer: Writer, status: u8, len: usize) {
        if let Err(e) = writer.write_obj(status) {
            error!("Failed to write virtio block status: {e:?}")
        }
        self.add_used(head_index, len as u32);
    }

    fn complete_ioerr(&self, head_index: u16, writer: Writer) {
        self.complete_request(
            head_index,
            writer,
            VIRTIO_BLK_S_IOERR.try_into().unwrap(),
            0,
        );
    }

    fn complete_invalid_chain(&self, head: DescriptorChain<'_>, head_index: u16) {
        if let Ok(writer) = Writer::new(&self.mem, head) {
            self.complete_ioerr(head_index, writer);
        } else {
            self.add_used(head_index, 0);
        }
    }
}

fn read_worker(rx: Receiver<ReadJob>, shared: Arc<SharedState>) {
    while let Ok(mut job) = rx.recv() {
        let (status, len): (u8, usize) = if !job.data_len.is_multiple_of(512) {
            (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
        } else {
            match job
                .writer
                .0
                .write_from_at(&shared.disk, job.data_len, job.sector * 512)
            {
                Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                Err(e) => {
                    error!("error processing read request: {e:?}");
                    (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                }
            }
        };

        if let Err(e) = job.writer.0.write_obj(status) {
            error!("Failed to write virtio block status: {e:?}");
        }

        shared.add_used(job.head_index, len as u32);
    }
}

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
    parallel_reads: bool,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
        parallel_reads: bool,
    ) -> Self {
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
            parallel_reads,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("block worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(self) {
        let BlockWorker {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
            parallel_reads,
        } = self;
        let DeviceQueue { queue, event } = device_queue;
        let virtq_ev_fd = event.as_raw_fd();
        let stop_ev_fd = stop_fd.as_raw_fd();

        let shared = Arc::new(SharedState {
            queue: Mutex::new(queue),
            mem,
            interrupt,
            disk,
        });

        let (read_tx, mut read_workers) = if parallel_reads {
            let read_pool_size = thread::available_parallelism()
                .map(|n| n.get().clamp(2, 8))
                .unwrap_or(4);
            let (read_tx, read_rx) = unbounded::<ReadJob>();
            let workers: Vec<JoinHandle<()>> = (0..read_pool_size)
                .map(|i| {
                    thread::Builder::new()
                        .name(format!("block read worker {i}"))
                        .spawn({
                            let rx = read_rx.clone();
                            let shared = shared.clone();
                            move || read_worker(rx, shared)
                        })
                        .unwrap()
                })
                .collect();
            (Some(read_tx), workers)
        } else {
            (None, Vec::new())
        };

        let mut epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for epoll_event in &epoll_events[0..ev_cnt] {
                        let source = epoll_event.fd();
                        let event_set = epoll_event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_ev_fd => {
                                if let Err(e) = event.read() {
                                    error!("Failed to get queue event: {e:?}");
                                } else {
                                    Self::process_virtio_queues(&shared, read_tx.as_ref());
                                }
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = stop_fd.read();
                                drop(read_tx);
                                for worker in read_workers.drain(..) {
                                    let _ = worker.join();
                                }
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn process_virtio_queues(shared: &Arc<SharedState>, read_tx: Option<&Sender<ReadJob>>) {
        let mem = &shared.mem;
        loop {
            let requests = {
                let mut queue = shared.queue.lock().unwrap();
                queue.disable_notification(mem).unwrap();
                let mut requests = Vec::new();
                while let Some(head) = queue.pop(mem) {
                    requests.push(head);
                }
                requests
            };

            for head in requests {
                Self::dispatch_request(shared, read_tx, head);
            }

            let more = {
                let mut queue = shared.queue.lock().unwrap();
                queue.enable_notification(mem).unwrap()
            };
            if !more {
                break;
            }
        }
    }

    fn dispatch_request(
        shared: &Arc<SharedState>,
        read_tx: Option<&Sender<ReadJob>>,
        head: DescriptorChain<'_>,
    ) {
        let head_index = head.index;
        let mem = &shared.mem;
        let mut reader = match Reader::new(mem, head.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                shared.complete_invalid_chain(head, head_index);
                return;
            }
        };
        let mut writer = match Writer::new(mem, head.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                shared.complete_invalid_chain(head, head_index);
                return;
            }
        };
        let request_header: RequestHeader = match reader.read_obj() {
            Ok(h) => h,
            Err(e) => {
                error!("invalid request header: {e:?}");
                shared.complete_ioerr(head_index, writer);
                return;
            }
        };

        if request_header.request_type == VIRTIO_BLK_T_IN
            && let Some(read_tx) = read_tx
        {
            let data_len = writer.available_bytes().saturating_sub(1);
            // SAFETY: `writer` was created from `SharedState.mem`. The job is
            // processed only by a worker that holds `Arc<SharedState>`, and
            // those workers are joined on stop before `SharedState` is dropped.
            let writer = unsafe { std::mem::transmute::<Writer<'_>, Writer<'static>>(writer) };
            if let Err(job) = read_tx.send(ReadJob {
                head_index,
                sector: request_header.sector,
                data_len,
                writer: SendWriter(writer),
            }) {
                shared.complete_ioerr(job.0.head_index, job.0.writer.0);
            }
            return;
        }

        let (status, len): (u8, usize) =
            match Self::process_request(request_header, &mut reader, &mut writer, &shared.disk) {
                Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                Err(e) => {
                    error!("error processing request: {e:?}");
                    (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                }
            };

        shared.complete_request(head_index, writer, status, len);
    }

    fn process_request(
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
        disk: &DiskProperties,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes().saturating_sub(1);
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::WritingToDescriptor)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    reader
                        .read_to_at(disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::ReadingFromDescriptor)
                }
            }
            VIRTIO_BLK_T_FLUSH => match disk.cache_type() {
                CacheType::Writeback => {
                    let diskfile = disk.file.write().unwrap();
                    diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                    diskfile.sync().map_err(RequestError::FlushingToDisk)?;
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = disk.image_id();
                if data_len < disk_id.len() {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_all(disk_id)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(disk_id.len())
                }
            }
            VIRTIO_BLK_T_DISCARD => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                disk.file
                    .write()
                    .unwrap()
                    .discard_to_any(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::Discarding)?;
                Ok(0)
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
                let mut diskfile = disk.file.write().unwrap();
                if unmap {
                    diskfile
                        .discard_to_zero(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    diskfile
                        .write_zeroes(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::WritingZeroes)?;
                }
                Ok(0)
            }
            _ => Err(RequestError::UnknownRequest),
        }
    }
}
