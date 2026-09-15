use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, setsockopt, socket, sockopt,
};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use utils::fd::SetNonblockingExt;
use vm_memory::GuestMemoryMmap;

use crate::virtio::InterruptTransport;
use crate::virtio::batch_queue::aliased_ioslice::{AliasedIoSlice, AliasedIoSliceMut, AnyIoSlice};
use crate::virtio::batch_queue::{RxQueueProducer, TxQueueConsumer};
use crate::virtio::net::backend::ConnectError;
use crate::virtio::queue::Queue;

use super::backend::{NetBackend, ReadError, WriteError};
use super::{FRAME_HEADER_LEN, vnet_hdr_len};

/// Try to read/complete the frame length header using non-blocking recv.
/// Returns Some(frame_len) when complete, None if incomplete or EAGAIN.
fn try_read_frame_header(
    raw_fd: RawFd,
    header_buf: &mut [u8; FRAME_HEADER_LEN],
    header_pos: &mut usize,
    expecting: &mut Option<u32>,
) -> Option<usize> {
    if let Some(len) = *expecting {
        return Some(len as usize);
    }

    while *header_pos < FRAME_HEADER_LEN {
        let remaining = &mut header_buf[*header_pos..];
        let ret = unsafe {
            libc::read(
                raw_fd,
                remaining.as_mut_ptr() as *mut libc::c_void,
                remaining.len(),
            )
        };
        match ret {
            n if n > 0 => {
                *header_pos += n as usize;
            }
            _ => return None,
        }
    }

    let len = u32::from_be_bytes(*header_buf);
    *expecting = Some(len);
    *header_pos = 0;
    Some(len as usize)
}

pub struct Unixstream {
    fd: OwnedFd,
    include_vnet_header: bool,
    interrupt: InterruptTransport,
    tx_consumer: TxQueueConsumer,
    rx_producer: RxQueueProducer,
    /// Stationary heap array of 4-byte frame length headers indexed by queue descriptor head_index (0..1024)
    tx_headers: Box<[[u8; FRAME_HEADER_LEN]; super::QUEUE_SIZE as usize]>,
    /// For RX: partial frame length header buffer
    rx_header_buf: [u8; FRAME_HEADER_LEN],
    /// For RX: bytes read into rx_header_buf so far
    rx_header_pos: usize,
    /// For RX: expected frame length (None when header not yet complete)
    expecting_frame_length: Option<u32>,
    /// For RX: remaining bytes to drain from socket for an oversized frame
    rx_drain_remaining: usize,
}

impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(
        fd: OwnedFd,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Self {
        if let Err(e) = fd.set_nonblocking(true) {
            log::warn!("Failed to set O_NONBLOCK: {e}");
        }

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_RCVBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        let iovec_capacity = tx_queue.size as usize * 2;
        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), iovec_capacity);
        let rx_producer = RxQueueProducer::new(rx_queue, mem, iovec_capacity);

        Self {
            fd,
            include_vnet_header,
            interrupt,
            tx_consumer,
            rx_producer,
            tx_headers: Box::new([[0u8; FRAME_HEADER_LEN]; super::QUEUE_SIZE as usize]),
            rx_header_buf: [0u8; FRAME_HEADER_LEN],
            rx_header_pos: 0,
            expecting_frame_length: None,
            rx_drain_remaining: 0,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(
        path: PathBuf,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Result<Self, ConnectError> {
        #[cfg(target_os = "linux")]
        let flags = SockFlag::SOCK_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = SockFlag::empty();

        let fd = socket(AddressFamily::Unix, SockType::Stream, flags, None)
            .map_err(ConnectError::CreateSocket)?;

        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self::new(
            fd,
            include_vnet_header,
            tx_queue,
            rx_queue,
            mem,
            interrupt,
        ))
    }
}

impl NetBackend for Unixstream {
    fn send(&mut self) -> Result<(), WriteError> {
        log::trace!("Unixstream::send() called");
        let skip = if !self.include_vnet_header {
            vnet_hdr_len()
        } else {
            0
        };

        let mut total_finished = 0;

        self.tx_consumer.disable_notification();

        let headers_ptr = self.tx_headers.as_mut_ptr();
        loop {
            self.tx_consumer.feed_with_transform(|iovecs, out| {
                if !out.reserve(iovecs.len() + 1) {
                    return None;
                }
                let head_idx = iovecs.head_index() as usize;
                let header_ptr = unsafe { (*headers_ptr.add(head_idx)).as_mut_ptr() };
                out.push(unsafe { AliasedIoSlice::from_raw(header_ptr, FRAME_HEADER_LEN) });
                out.extend(AliasedIoSlice::skip_bytes(iovecs, skip));
                let payload_len = out.total_bytes() - FRAME_HEADER_LEN;
                unsafe {
                    std::ptr::write_unaligned(header_ptr as *mut u32, (payload_len as u32).to_be());
                }
                Some(())
            });

            if !self.tx_consumer.has_pending() {
                if self.tx_consumer.enable_notification() {
                    self.tx_consumer.disable_notification();
                    continue;
                }
                break;
            }

            let raw_fd = self.fd.as_raw_fd();

            let finished = self.tx_consumer.consume(|batch| {
                let mut start = 0;
                while start < batch.len() {
                    let (iovecs, chains) = batch.contiguous_io_slices(start, 1024);
                    if iovecs.is_empty() {
                        if chains > 0 {
                            batch.finish_many(start..start + chains);
                            start += chains;
                            continue;
                        }
                        break;
                    }

                    let ret = unsafe {
                        libc::writev(
                            raw_fd,
                            AliasedIoSlice::as_iovec_ptr(iovecs),
                            iovecs.len() as libc::c_int,
                        )
                    };

                    match ret {
                        n if n > 0 => {
                            let mut remaining = n as usize;
                            let end = start + chains;
                            while start < end {
                                let needed = batch.max_bytes(start) - batch.bytes_used(start);
                                if remaining >= needed {
                                    remaining -= needed;
                                    batch.finish(start);
                                    start += 1;
                                } else if remaining > 0 {
                                    batch.advance(start, remaining);
                                    break;
                                } else {
                                    break;
                                }
                            }
                        }
                        _ => {
                            let err = nix::errno::Errno::last();
                            if err != nix::errno::Errno::EAGAIN {
                                log::error!("writev to unixstream failed: {err:?}");
                            }
                            break;
                        }
                    }
                }
            });

            total_finished += finished;
            if finished == 0 || self.tx_consumer.has_pending() {
                break;
            }
        }

        if total_finished > 0 && self.tx_consumer.needs_notification() {
            self.interrupt.signal_used_queue();
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let raw_fd = self.fd.as_raw_fd();
        let vnet_offset = if !self.include_vnet_header {
            vnet_hdr_len()
        } else {
            0
        };

        // If a previous oversized frame was partially received, drain remaining excess bytes first.
        while self.rx_drain_remaining > 0 {
            let mut sink = [0u8; 4096];
            let to_read = self.rx_drain_remaining.min(sink.len());
            let ret =
                unsafe { libc::read(raw_fd, sink.as_mut_ptr() as *mut libc::c_void, to_read) };
            match ret {
                n if n > 0 => {
                    self.rx_drain_remaining -= n as usize;
                }
                _ => return Ok(()),
            }
        }

        let header_buf = &mut self.rx_header_buf;
        let header_pos = &mut self.rx_header_pos;
        let expecting = &mut self.expecting_frame_length;

        self.rx_producer.disable_notification();

        loop {
            self.rx_producer.feed();

            if !self.rx_producer.has_pending() {
                if self.rx_producer.enable_notification() {
                    self.rx_producer.disable_notification();
                    continue;
                }
                break;
            }

            let mut drain_excess = 0;
            let finished = self.rx_producer.produce(|batch| {
                for i in 0..batch.len() {
                    let iovecs = batch.io_slices_mut(i);
                    if iovecs.is_empty() {
                        batch.complete(i, 0);
                        continue;
                    }

                    // Read frame header (non-blocking)
                    let frame_len =
                        match try_read_frame_header(raw_fd, header_buf, header_pos, expecting) {
                            Some(len) => len,
                            None => return,
                        };

                    let total_len = vnet_offset + frame_len;

                    // Write vnet header at start of new frame
                    if batch.bytes_used(i) == 0 && vnet_offset > 0 {
                        let _ = batch.write_advance(i, &super::DEFAULT_VNET_HDR);
                    }

                    while batch.bytes_used(i) < total_len {
                        let remaining = total_len - batch.bytes_used(i);
                        let iovecs = batch.io_slices_mut(i);
                        if iovecs.is_empty() {
                            break;
                        }

                        let ret = if !iovecs.is_empty() && iovecs[0].len() >= remaining {
                            let iov = iovecs[0].to_iovec();
                            unsafe { libc::read(raw_fd, iov.iov_base, remaining) }
                        } else {
                            let truncated = AliasedIoSliceMut::truncate_slices(iovecs, remaining);
                            unsafe {
                                libc::readv(
                                    raw_fd,
                                    AliasedIoSliceMut::as_iovec_ptr(truncated),
                                    truncated.len() as libc::c_int,
                                )
                            }
                        };

                        match ret {
                            n if n > 0 => {
                                batch.advance(i, n as usize);
                            }
                            _ => return,
                        }
                    }

                    if batch.bytes_used(i) >= total_len {
                        batch.finish(i);
                        *expecting = None;
                    } else if batch.io_slices_mut(i).is_empty() {
                        // Frame exceeded descriptor chain capacity: finish the chain with the bytes written
                        // and track remaining excess bytes to drain from the socket stream.
                        let excess = total_len - batch.bytes_used(i);
                        batch.finish(i);
                        *expecting = None;
                        drain_excess = excess;
                        break;
                    } else {
                        return;
                    }
                }
            });

            if drain_excess > 0 {
                self.rx_drain_remaining = drain_excess;
                while self.rx_drain_remaining > 0 {
                    let mut sink = [0u8; 4096];
                    let to_read = self.rx_drain_remaining.min(sink.len());
                    let ret = unsafe {
                        libc::read(raw_fd, sink.as_mut_ptr() as *mut libc::c_void, to_read)
                    };
                    match ret {
                        n if n > 0 => {
                            self.rx_drain_remaining -= n as usize;
                        }
                        _ => break,
                    }
                }
            }

            if finished > 0 && self.rx_producer.needs_notification() {
                self.interrupt.signal_used_queue();
            }
            if finished == 0 {
                break;
            }
        }

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
