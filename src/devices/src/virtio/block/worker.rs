use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::DeviceQueue;
use super::device::{CacheType, DiskProperties};

use crate::virtio::InterruptTransport;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::result;
use std::thread;
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

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
    ) -> Self {
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
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
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_ev_fd => {
                                self.process_queue_event();
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
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

    fn process_queue_event(&mut self) {
        if let Err(e) = self.device_queue.event.read() {
            error!("Failed to get queue event: {e:?}");
        } else {
            self.process_virtio_queues();
        }
    }

    /// Process device virtio queue(s).
    fn process_virtio_queues(&mut self) {
        let mem = self.mem.clone();
        loop {
            self.device_queue.queue.disable_notification(&mem).unwrap();

            self.process_queue(&mem);

            if !self.device_queue.queue.enable_notification(&mem).unwrap() {
                break;
            }
        }
    }

    fn process_queue(&mut self, mem: &GuestMemoryMmap) {
        while let Some(head) = self.device_queue.queue.pop(mem) {
            let mut reader = match Reader::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let mut writer = match Writer::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let request_header: RequestHeader = match reader.read_obj() {
                Ok(h) => h,
                Err(e) => {
                    error!("invalid request header: {e:?}");
                    continue;
                }
            };

            let (status, len): (u8, usize) =
                match self.process_request(request_header, &mut reader, &mut writer) {
                    Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                    Err(e) => {
                        error!("error processing request: {e:?}");
                        (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                    }
                };

            if let Err(e) = writer.write_obj(status) {
                error!("Failed to write virtio block status: {e:?}")
            }

            if let Err(e) = self
                .device_queue
                .queue
                .add_used(mem, head.index, len as u32)
            {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if self.device_queue.queue.needs_notification(mem).unwrap()
                && let Err(e) = self.interrupt.try_signal_used_queue()
            {
                error!("error signalling queue: {e:?}");
            }
        }
    }

    fn process_request(
        &mut self,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes() - 1;
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(&self.disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::WritingToDescriptor)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    reader
                        .read_to_at(&self.disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::ReadingFromDescriptor)
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.disk.cache_type() {
                CacheType::Writeback => {
                    let diskfile = self.disk.file.lock().unwrap();
                    diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                    diskfile.sync().map_err(RequestError::FlushingToDisk)?;
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = self.disk.image_id();
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
                self.disk
                    .file
                    .lock()
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
                if unmap {
                    self.disk
                        .file
                        .lock()
                        .unwrap()
                        .discard_to_zero(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    self.disk
                        .file
                        .lock()
                        .unwrap()
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
