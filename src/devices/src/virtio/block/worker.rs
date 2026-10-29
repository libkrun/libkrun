use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::DeviceQueue;
use super::device::{CacheType, DiskProperties};
use crate::virtio::DescriptorChain;

use crate::virtio::InterruptTransport;
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::collections::TryReserveError;
use std::io::{self, Write};
use std::num::NonZeroUsize;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::result;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
#[cfg(target_os = "windows")]
use utils::windows::AsRawFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{ByteValued, GuestAddress, GuestMemoryMmap};

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

#[derive(Debug)]
struct ReadJob {
    head_index: u16,
    sector: u64,
    data_len: usize,
    buffers: Vec<(GuestAddress, u32)>,
    _buffer_permit: ReadBufferPermit,
}

struct ReadCompletion {
    job: ReadJob,
    data: Option<Vec<u8>>,
}

// Aliased guest descriptors can make a read's total length exceed guest RAM and exhaust host memory.
const PARALLEL_READ_BUFFER_BUDGET_BYTES: usize = 64 * 1024 * 1024;

static AVAILABLE_READ_BUFFER_BYTES: Mutex<usize> = Mutex::new(PARALLEL_READ_BUFFER_BUDGET_BYTES);

#[derive(Debug)]
struct ReadBufferPermit(usize);

impl ReadBufferPermit {
    fn try_acquire(bytes: usize) -> Option<Self> {
        let mut available = AVAILABLE_READ_BUFFER_BYTES.lock().unwrap();
        *available = available.checked_sub(bytes)?;
        Some(Self(bytes))
    }
}

impl Drop for ReadBufferPermit {
    fn drop(&mut self) {
        *AVAILABLE_READ_BUFFER_BYTES.lock().unwrap() += self.0;
    }
}

struct ReadPool {
    jobs: Option<Sender<ReadJob>>,
    completions: Receiver<ReadCompletion>,
    event: EventFd,
    workers: Vec<JoinHandle<()>>,
    pending: usize,
}

impl ReadPool {
    fn new(size: usize, disk: &DiskProperties) -> Self {
        let (jobs, rx) = unbounded::<ReadJob>();
        // Workers must be able to finish while the dispatcher joins them on drop.
        let (tx, completions) = unbounded();
        let event = EventFd::new(EFD_NONBLOCK).unwrap();
        let workers = (0..size)
            .map(|i| {
                let rx = rx.clone();
                let tx = tx.clone();
                let event = event.try_clone().unwrap();
                let disk = disk.file.clone();
                thread::Builder::new()
                    .name(format!("block read worker {i}"))
                    .spawn(move || {
                        while let Ok(job) = rx.recv() {
                            let data = (|| {
                                let mut data =
                                    allocate_read_buffer(job.data_len).map_err(io::Error::other)?;
                                let offset = job
                                    .sector
                                    .checked_mul(512)
                                    .ok_or_else(|| io::Error::other("invalid read sector"))?;
                                disk.read().unwrap().read(&mut data, offset)?;
                                Ok::<_, io::Error>(data)
                            })();
                            let data = match data {
                                Ok(data) => Some(data),
                                Err(e) => {
                                    error!("error processing read request: {e:?}");
                                    None
                                }
                            };
                            if tx.send(ReadCompletion { job, data }).is_err() {
                                return;
                            }
                            if let Err(e) = event.write(1) {
                                error!("failed to signal read completion: {e:?}");
                            }
                        }
                    })
                    .unwrap()
            })
            .collect();
        Self {
            jobs: Some(jobs),
            completions,
            event,
            workers,
            pending: 0,
        }
    }
}

impl Drop for ReadPool {
    fn drop(&mut self) {
        self.jobs.take();
        for worker in self.workers.drain(..) {
            if let Err(e) = worker.join() {
                error!("error waiting for read worker thread: {e:?}");
            }
        }
    }
}

// Keep allocation fallible because the size comes from guest descriptors.
#[allow(clippy::slow_vector_initialization)]
fn allocate_read_buffer(len: usize) -> result::Result<Vec<u8>, TryReserveError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(len)?;
    buffer.resize(len, 0);
    Ok(buffer)
}

fn write_read_completion(mem: &GuestMemoryMmap, completion: ReadCompletion) -> (u16, u32) {
    let head_index = completion.job.head_index;
    let mut writer = match Writer::from_guest_buffers(mem, completion.job.buffers.iter().copied()) {
        Ok(writer) => writer,
        Err(e) => {
            error!("invalid read completion descriptor chain: {e:?}");
            return (head_index, 0);
        }
    };
    let mut status_writer = match writer.split_at(completion.job.data_len) {
        Ok(writer) => writer,
        Err(e) => {
            error!("invalid read completion data length: {e:?}");
            return (head_index, 0);
        }
    };

    let (status, len): (u8, usize) = match completion.data {
        Some(data) => match writer.write_all(&data) {
            Ok(()) => (VIRTIO_BLK_S_OK.try_into().unwrap(), data.len()),
            Err(e) => {
                error!("failed to copy read data to guest memory: {e:?}");
                (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
            }
        },
        None => (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0),
    };

    let status_len = match status_writer.write_obj(status) {
        Ok(()) => 1,
        Err(e) => {
            error!("Failed to write virtio block status: {e:?}");
            0
        }
    };

    (head_index, (len + status_len) as u32)
}

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
    parallel_reads: bool,
    read_pool_size: Option<NonZeroUsize>,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
        parallel_reads: bool,
        read_pool_size: Option<NonZeroUsize>,
    ) -> Self {
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
            parallel_reads,
            read_pool_size,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("block worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_ev_fd = self.device_queue.event.as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();
        let read_pool_size = if self.parallel_reads {
            resolve_read_pool_size(
                self.read_pool_size,
                thread::available_parallelism().ok().map(|n| n.get()),
            )
        } else {
            None
        };
        let mut read_pool = read_pool_size.map(|size| ReadPool::new(size, &self.disk));
        let read_completion_ev_fd = read_pool.as_ref().map(|pool| pool.event.as_raw_fd());
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

        if let Some(fd) = read_completion_ev_fd {
            let _ = epoll.ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(EventSet::IN, fd as u64),
            );
        }

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for epoll_event in &epoll_events[0..ev_cnt] {
                        let source = epoll_event.fd();
                        let event_set = epoll_event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_ev_fd => {
                                if let Err(e) = self.device_queue.event.read() {
                                    error!("Failed to get queue event: {e:?}");
                                } else {
                                    self.process_virtio_queues(read_pool.as_mut());
                                }
                            }
                            EventSet::IN if Some(source) == read_completion_ev_fd => {
                                let pool = read_pool.as_mut().unwrap();
                                if let Err(e) = pool.event.read() {
                                    error!("Failed to get read completion event: {e:?}");
                                }
                                self.process_read_completions(pool);
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                if let Some(pool) = read_pool.as_mut() {
                                    pool.jobs.take();
                                    for completion in pool.completions.iter() {
                                        let (head, len) =
                                            write_read_completion(&self.mem, completion);
                                        self.add_used(head, len);
                                    }
                                    self.signal_used_queue();
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

    fn add_used(&mut self, head_index: u16, len: u32) {
        if let Err(e) = self.device_queue.queue.add_used(&self.mem, head_index, len) {
            error!("failed to add used elements to the queue: {e:?}");
        }
    }

    fn signal_used_queue(&mut self) {
        if self
            .device_queue
            .queue
            .needs_notification(&self.mem)
            .unwrap()
            && let Err(e) = self.interrupt.try_signal_used_queue()
        {
            error!("error signalling queue: {e:?}");
        }
    }

    fn process_read_completions(&mut self, pool: &mut ReadPool) {
        let pending = pool.pending;
        for completion in pool.completions.try_iter() {
            pool.pending -= 1;
            let (head, len) = write_read_completion(&self.mem, completion);
            self.add_used(head, len);
        }
        if pool.pending != pending {
            self.signal_used_queue();
        }
    }

    fn process_virtio_queues(&mut self, mut read_pool: Option<&mut ReadPool>) {
        let mem = self.mem.clone();
        loop {
            self.device_queue.queue.disable_notification(&mem).unwrap();
            while let Some(head) = self.device_queue.queue.pop(&mem) {
                self.dispatch_request(&mem, read_pool.as_deref_mut(), head);
            }
            if !self.device_queue.queue.enable_notification(&mem).unwrap() {
                break;
            }
        }
    }

    fn dispatch_request(
        &mut self,
        mem: &GuestMemoryMmap,
        read_pool: Option<&mut ReadPool>,
        head: DescriptorChain<'_>,
    ) {
        let head_index = head.index;
        let buffers: Vec<_> = head
            .clone()
            .into_iter()
            .writable()
            .map(|desc| (desc.addr, desc.len))
            .collect();
        let mut writer = match Writer::from_guest_buffers(mem, buffers.iter().copied()) {
            Ok(writer) => writer,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                self.add_used(head_index, 0);
                self.signal_used_queue();
                return;
            }
        };
        let Some(data_len) = writer.available_bytes().checked_sub(1) else {
            self.add_used(head_index, 0);
            self.signal_used_queue();
            return;
        };
        let status_writer = writer.split_at(data_len).unwrap();
        let mut reader = match Reader::new(mem, head.clone()) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid descriptor chain: {e:?}");
                self.complete_request(
                    head_index,
                    status_writer,
                    Err(RequestError::InvalidDataLength),
                );
                return;
            }
        };
        let request_header: RequestHeader = match reader.read_obj() {
            Ok(h) => h,
            Err(e) => {
                error!("invalid request header: {e:?}");
                self.complete_request(
                    head_index,
                    status_writer,
                    Err(RequestError::ReadingFromDescriptor(e)),
                );
                return;
            }
        };

        if request_header.request_type == VIRTIO_BLK_T_IN
            && let Some(pool) = read_pool
        {
            self.process_read_completions(pool);
            if pool.pending == pool.workers.len() {
                let completion = pool.completions.recv().unwrap();
                pool.pending -= 1;
                let (head, len) = write_read_completion(mem, completion);
                self.add_used(head, len);
                self.signal_used_queue();
            }
            if !data_len.is_multiple_of(512) {
                self.complete_request(
                    head_index,
                    status_writer,
                    Err(RequestError::InvalidDataLength),
                );
                return;
            }
            if let Some(permit) = ReadBufferPermit::try_acquire(data_len) {
                pool.jobs
                    .as_ref()
                    .unwrap()
                    .send(ReadJob {
                        head_index,
                        sector: request_header.sector,
                        data_len,
                        buffers,
                        _buffer_permit: permit,
                    })
                    .unwrap();
                pool.pending += 1;
                return;
            }
        }

        let result = Self::process_request(request_header, &mut reader, &mut writer, &self.disk);
        self.complete_request(head_index, status_writer, result);
    }

    fn complete_request(
        &mut self,
        head_index: u16,
        mut writer: Writer,
        result: result::Result<usize, RequestError>,
    ) {
        let (status, len): (u8, usize) = match result {
            Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
            Err(e) => {
                error!("error processing request: {e:?}");
                (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
            }
        };

        let status_len = match writer.write_obj(status) {
            Ok(()) => 1,
            Err(e) => {
                error!("Failed to write virtio block status: {e:?}");
                0
            }
        };
        self.add_used(head_index, (len + status_len) as u32);
        self.signal_used_queue();
    }

    fn process_request(
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
        disk: &DiskProperties,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes();
                let offset = request_header
                    .sector
                    .checked_mul(512)
                    .ok_or(RequestError::InvalidDataLength)?;
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(disk, data_len, offset)
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

fn resolve_read_pool_size(
    requested: Option<NonZeroUsize>,
    available_parallelism: Option<usize>,
) -> Option<usize> {
    match requested {
        Some(requested) => available_parallelism
            .filter(|available| *available >= requested.get())
            .map(|_| requested.get()),
        None => Some(available_parallelism.map(|n| n.clamp(2, 8)).unwrap_or(4)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::descriptor_utils::{DescriptorType, create_descriptor_chain};
    use crate::virtio::queue::tests::VirtQueue;
    use imago::{DynStorage, FormatAccess, Storage, StorageOpenOptions, file::File, raw::Raw};
    use std::sync::{Arc, RwLock};
    use utils::tempfile::TempFile;
    use vm_memory::Bytes;

    fn test_disk(direct_io: bool) -> DiskProperties {
        let backing = TempFile::new().unwrap();
        let mut file = backing.as_file();
        file.write_all(&[0x11; 512]).unwrap();
        file.write_all(&[0x22; 512]).unwrap();
        let file = File::open(
            StorageOpenOptions::new()
                .filename(backing.as_path().to_str().unwrap())
                .direct(direct_io),
        )
        .unwrap();
        let raw = Raw::<Box<dyn DynStorage>>::open_image(Box::new(file), false).unwrap();
        DiskProperties::new(
            Arc::new(RwLock::new(FormatAccess::new(raw))),
            Vec::new(),
            CacheType::Unsafe,
        )
        .unwrap()
    }

    fn wait_for_completion(pool: &ReadPool) {
        let mut epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                pool.event.as_raw_fd(),
                &EpollEvent::new(EventSet::IN, 0),
            )
            .unwrap();
        let mut events = [EpollEvent::new(EventSet::empty(), 0)];
        assert_eq!(epoll.wait(1, 1000, &mut events).unwrap(), 1);
    }

    #[test]
    fn serialized_and_fallback_reads_keep_status_outside_data() {
        for (parallel, data_len, sector, status, used_len) in [
            (false, 512, 0, VIRTIO_BLK_S_OK, 513),
            (false, 512, u64::MAX, VIRTIO_BLK_S_IOERR, 1),
            (true, 512, 0, VIRTIO_BLK_S_OK, 513),
            (true, 512, u64::MAX, VIRTIO_BLK_S_IOERR, 1),
            (
                true,
                PARALLEL_READ_BUFFER_BUDGET_BYTES + 512,
                u64::MAX,
                VIRTIO_BLK_S_IOERR,
                1,
            ),
            (true, 511, 0, VIRTIO_BLK_S_IOERR, 1),
        ] {
            let mem =
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), data_len + 0x2000)]).unwrap();
            let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
            let head = create_descriptor_chain(
                &mem,
                GuestAddress(0),
                GuestAddress(0x1000),
                vec![
                    (DescriptorType::Readable, 16),
                    (DescriptorType::Writable, (data_len + 1) as u32),
                ],
                0,
            )
            .unwrap();
            mem.write_obj(
                RequestHeader {
                    request_type: VIRTIO_BLK_T_IN,
                    sector,
                    ..Default::default()
                },
                GuestAddress(0x1000),
            )
            .unwrap();
            let data_addr = GuestAddress(0x1010);
            let status_addr = GuestAddress(0x1010 + data_len as u64);
            mem.write_obj(0xaa_u8, data_addr).unwrap();
            mem.write_obj(0xff_u8, status_addr).unwrap();
            let mut worker = BlockWorker::new(
                DeviceQueue::new(
                    queue.create_queue(),
                    Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                ),
                InterruptTransport::new(DummyIrqChip::new().into(), "block test".into()).unwrap(),
                mem.clone(),
                test_disk(false),
                EventFd::new(EFD_NONBLOCK).unwrap(),
                parallel,
                None,
            );
            let mut pool = parallel.then(|| ReadPool::new(2, &worker.disk));
            worker.dispatch_request(&mem, pool.as_mut(), head);
            if let Some(pool) = pool.as_mut()
                && pool.pending != 0
            {
                assert_eq!(mem.read_obj::<u8>(status_addr).unwrap(), 0xff);
                mem.write_slice(&[0; 32], GuestAddress(0)).unwrap();
                wait_for_completion(pool);
                worker.process_read_completions(pool);
            }

            assert_eq!(mem.read_obj::<u8>(status_addr).unwrap(), status as u8);
            assert_eq!(queue.used.idx.get(), 1);
            assert_eq!(queue.used.ring[0].get().len, used_len);
            assert_eq!(
                mem.read_obj::<u8>(data_addr).unwrap(),
                if status == VIRTIO_BLK_S_OK {
                    0x11
                } else {
                    0xaa
                }
            );
            assert!(pool.as_ref().is_none_or(|pool| pool.pending == 0));
        }
    }

    #[test]
    fn read_pool_wakes_dispatcher_and_drains_overlapping_reads_on_drop() {
        for direct_io in [false, true] {
            let disk = test_disk(direct_io);
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
            mem.write_slice(&[0xff; 513], GuestAddress(0x100)).unwrap();
            let mut pool = ReadPool::new(2, &disk);
            let completions = pool.completions.clone();
            for sector in 0..2 {
                pool.jobs
                    .as_ref()
                    .unwrap()
                    .send(ReadJob {
                        head_index: sector as u16,
                        sector,
                        data_len: 512,
                        buffers: vec![(GuestAddress(0x100), 513)],
                        _buffer_permit: ReadBufferPermit::try_acquire(512).unwrap(),
                    })
                    .unwrap();
            }
            wait_for_completion(&pool);
            pool.jobs.take();
            drop(pool);

            let mut data = [0; 513];
            mem.read_slice(&mut data, GuestAddress(0x100)).unwrap();
            assert_eq!(data, [0xff; 513]);
            let mut completed = 0;
            for completion in completions.try_iter() {
                let head = completion.job.head_index;
                assert_eq!(write_read_completion(&mem, completion), (head, 513));
                mem.read_slice(&mut data, GuestAddress(0x100)).unwrap();
                assert_eq!(&data[..512], &[if head == 0 { 0x11 } else { 0x22 }; 512]);
                assert_eq!(data[512], VIRTIO_BLK_S_OK as u8);
                completed += 1;
            }
            assert_eq!(completed, 2);
            assert!(completions.recv().is_err());
        }
    }

    #[test]
    fn read_buffer_budget_rejects_oversized_parallel_reads() {
        assert!(ReadBufferPermit::try_acquire(PARALLEL_READ_BUFFER_BUDGET_BYTES + 1).is_none());
        let permit = ReadBufferPermit::try_acquire(63 * 1024 * 1024).unwrap();
        assert!(ReadBufferPermit::try_acquire(2 * 1024 * 1024).is_none());
        drop(permit);
        assert!(ReadBufferPermit::try_acquire(2 * 1024 * 1024).is_some());
    }

    #[test]
    fn explicit_read_pool_size_requires_enough_available_parallelism() {
        assert_eq!(
            resolve_read_pool_size(NonZeroUsize::new(4), Some(4)),
            Some(4)
        );
        assert_eq!(resolve_read_pool_size(NonZeroUsize::new(5), Some(4)), None);
        assert_eq!(resolve_read_pool_size(NonZeroUsize::new(4), None), None);
    }

    #[test]
    fn automatic_read_pool_size_uses_existing_sizing() {
        assert_eq!(resolve_read_pool_size(None, Some(1)), Some(2));
        assert_eq!(resolve_read_pool_size(None, Some(16)), Some(8));
        assert_eq!(resolve_read_pool_size(None, None), Some(4));
    }

    #[test]
    fn read_completion_uses_snapshot_and_copies_data_before_status() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let permit = ReadBufferPermit::try_acquire(4).unwrap();
        let chain = create_descriptor_chain(
            &mem,
            GuestAddress(0),
            GuestAddress(0x100),
            vec![(DescriptorType::Readable, 8), (DescriptorType::Writable, 5)],
            0,
        )
        .unwrap();
        let buffers: Vec<_> = chain
            .into_iter()
            .writable()
            .map(|desc| (desc.addr, desc.len))
            .collect();
        mem.write_slice(&[0; 32], GuestAddress(0)).unwrap();

        let used = write_read_completion(
            &mem,
            ReadCompletion {
                job: ReadJob {
                    head_index: 0,
                    sector: 0,
                    data_len: 4,
                    buffers,
                    _buffer_permit: permit,
                },
                data: Some(vec![0x11, 0x22, 0x33, 0x44]),
            },
        );

        assert_eq!(used, (0, 5));
        let mut data = [0; 4];
        let mut status = [0; 1];
        mem.read_slice(&mut data, GuestAddress(0x108)).unwrap();
        mem.read_slice(&mut status, GuestAddress(0x10c)).unwrap();
        assert_eq!(data, [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(status, [VIRTIO_BLK_S_OK as u8]);
    }

    #[test]
    fn failed_read_completion_writes_status_after_data_region() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let chain = create_descriptor_chain(
            &mem,
            GuestAddress(0),
            GuestAddress(0x100),
            vec![
                (DescriptorType::Readable, 8),
                (DescriptorType::Writable, 4),
                (DescriptorType::Writable, 1),
            ],
            0,
        )
        .unwrap();
        let buffers: Vec<_> = chain
            .into_iter()
            .writable()
            .map(|desc| (desc.addr, desc.len))
            .collect();

        let used = write_read_completion(
            &mem,
            ReadCompletion {
                job: ReadJob {
                    head_index: 0,
                    sector: 0,
                    data_len: 4,
                    buffers,
                    _buffer_permit: ReadBufferPermit::try_acquire(4).unwrap(),
                },
                data: None,
            },
        );

        assert_eq!(used, (0, 1));
        let mut status = [0; 1];
        mem.read_slice(&mut status, GuestAddress(0x10c)).unwrap();
        assert_eq!(status, [VIRTIO_BLK_S_IOERR as u8]);
    }
}
