use crate::virtio::net::backend::ConnectError;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE};
use crate::virtio::{DeviceQueue, InterruptTransport};

use super::VNET_HDR_LEN;
use super::backend::{NetBackend, ReadError, WriteError};
use super::device::{FrontendError, RxError, TxError, VirtioNetBackend};

#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::thread;
use std::{cmp, result};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

pub struct NetWorker {
    rx_q: DeviceQueue,
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,

    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,
    tx_has_deferred_frame: bool,
}

impl NetWorker {
    pub fn new(
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        _vnet_features: u64,
        cfg_backend: VirtioNetBackend,
    ) -> Result<Self, ConnectError> {
        let backend = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixstreamPath(path) => {
                Box::new(Unixstream::open(path)?) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => {
                Box::new(Unixgram::open(path, vfkit_magic)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => {
                Box::new(Tap::new(tap_name, _vnet_features)?) as Box<dyn NetBackend + Send>
            }
        };

        Ok(Self {
            rx_q,
            tx_q,

            mem,
            backend,
            interrupt,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            tx_has_deferred_frame: false,
        })
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn work(mut self) {
        #[cfg(target_os = "macos")]
        const TX_TIMER_FD: RawFd = -2;

        let virtq_rx_ev_fd = self.rx_q.event.as_raw_fd();
        let virtq_tx_ev_fd = self.tx_q.event.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();

        let mut epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_rx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_rx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_tx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_tx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            backend_socket,
            &EpollEvent::new(
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED | EventSet::READ_HANG_UP,
                backend_socket as u64,
            ),
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_rx_ev_fd => {
                                self.process_rx_queue_event();
                            }
                            EventSet::IN if source == virtq_tx_ev_fd => {
                                self.process_tx_queue_event();
                            }
                            _ if source == backend_socket => {
                                if event_set.contains(EventSet::HANG_UP)
                                    || event_set.contains(EventSet::READ_HANG_UP)
                                {
                                    log::error!(
                                        "Got {event_set:?} on backend fd, virtio-net will stop working"
                                    );
                                    eprintln!(
                                        "LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!"
                                    );
                                } else {
                                    if event_set.contains(EventSet::IN) {
                                        self.process_backend_socket_readable()
                                    }

                                    if event_set.contains(EventSet::OUT) {
                                        self.process_backend_socket_writeable()
                                    }
                                }
                            }
                            #[cfg(target_os = "macos")]
                            _ if event_set.is_empty() && source == TX_TIMER_FD => {
                                self.process_tx_loop();
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }

                    // Arm the retry timer after processing all events, so it
                    // reflects the final state of tx_has_deferred_frame.
                    #[cfg(target_os = "macos")]
                    if self.tx_has_deferred_frame {
                        let delay = self.backend.write_retry_delay_us();
                        if delay > 0 {
                            epoll.add_oneshot_timer(delay, TX_TIMER_FD as u64);
                        }
                    }
                }
                Err(e) => {
                    debug!("vsock: failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    pub(crate) fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.rx_q.event.read() {
            log::error!("Failed to get rx event from queue: {e:?}");
        }
        if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by queue event)")
        };
        if let Err(e) = self.rx_q.queue.enable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
    }

    pub(crate) fn process_tx_queue_event(&mut self) {
        match self.tx_q.event.read() {
            Ok(_) => self.process_tx_loop(),
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    pub(crate) fn process_backend_socket_readable(&mut self) {
        if let Err(e) = self.rx_q.queue.enable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by backend socket readable)");
        };
        if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
    }

    pub(crate) fn process_backend_socket_writeable(&mut self) {
        match self
            .backend
            .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len])
        {
            Ok(()) => self.process_tx_loop(),
            Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
            Err(e @ WriteError::Internal(_)) => {
                log::error!("Failed to finish write: {e:?}");
            }
            Err(e @ WriteError::ProcessNotRunning) => {
                log::debug!("Failed to finish write: {e:?}");
            }
        }
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        // if we have a deferred frame we try to process it first,
        // if that is not possible, we don't continue processing other frames
        if self.rx_has_deferred_frame {
            if self.write_frame_to_guest() {
                self.rx_has_deferred_frame = false;
            } else {
                return Ok(());
            }
        }

        let mut signal_queue = false;

        // Read as many frames as possible.
        let result = loop {
            match self.read_into_rx_frame_buf_from_backend() {
                Ok(()) => {
                    if self.write_frame_to_guest() {
                        signal_queue = true;
                    } else {
                        self.rx_has_deferred_frame = true;
                        break Ok(());
                    }
                }
                Err(ReadError::NothingRead) => break Ok(()),
                Err(e @ ReadError::Internal(_)) => break Err(RxError::Backend(e)),
            }
        };

        // At this point we processed as many Rx frames as possible.
        // We have to wake the guest if at least one descriptor chain has been used.
        if signal_queue {
            self.interrupt
                .try_signal_used_queue()
                .map_err(RxError::DeviceError)?;
        }

        result
    }

    fn process_tx_loop(&mut self) {
        loop {
            self.tx_q.queue.disable_notification(&self.mem).unwrap();

            self.tx_has_deferred_frame = match self.process_tx() {
                Err(TxError::Backend(WriteError::NothingWritten)) => true,
                Err(e) => {
                    log::error!("Failed to process tx: {e:?}");
                    // Re-enable notifications before breaking so the guest
                    // can still kick the TX queue on future descriptors.
                    let _ = self.tx_q.queue.enable_notification(&self.mem);
                    self.tx_has_deferred_frame = false;
                    break;
                }
                _ => false,
            };

            let has_new_entries = self.tx_q.queue.enable_notification(&self.mem).unwrap();
            if self.tx_has_deferred_frame || !has_new_entries {
                break;
            }
        }
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        let tx_queue = &mut self.tx_q.queue;

        if self.backend.has_unfinished_write()
            && self
                .backend
                .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len])
                .is_err()
        {
            log::trace!("Cannot process tx because of unfinished partial write!");
            return Ok(());
        }

        let mut raise_irq = false;
        let mut result = Ok(());

        while let Some(head) = tx_queue.pop(&self.mem) {
            let head_index = head.index;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                next_desc = desc.next_descriptor();
            }

            // Copy buffer from across multiple descriptors.
            let mut read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result = self
                    .mem
                    .read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {e:?}");
                        read_count = 0;
                        break;
                    }
                }
            }

            self.tx_frame_len = read_count;
            match self
                .backend
                .write_frame(VNET_HDR_LEN, &mut self.tx_frame_buf[..read_count])
            {
                Ok(()) => {
                    self.tx_frame_len = 0;
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                }
                Err(WriteError::NothingWritten) => {
                    tx_queue.undo_pop();
                    result = Err(TxError::Backend(WriteError::NothingWritten));
                    break;
                }
                Err(WriteError::PartialWrite) => {
                    log::trace!("process_tx: partial write");
                    /*
                    This situation should be pretty rare, assuming reasonably sized socket buffers.
                    We have written only a part of a frame to the backend socket (the socket is full).

                    The frame we have read from the guest remains in tx_frame_buf, and will be sent
                    later.

                    Note that we cannot wait for the backend to process our sending frames, because
                    the backend could be blocked on sending a remainder of a frame to us - us waiting
                    for backend would cause a deadlock.
                     */
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                    break;
                }
                Err(e @ WriteError::Internal(_) | e @ WriteError::ProcessNotRunning) => {
                    return Err(TxError::Backend(e));
                }
            }
        }

        if raise_irq && tx_queue.needs_notification(&self.mem).unwrap() {
            self.interrupt
                .try_signal_used_queue()
                .map_err(TxError::DeviceError)?;
        }

        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());

        let queue = &mut self.rx_q.queue;
        let head_descriptor = queue.pop(&self.mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match self.mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {e:?}");
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue
            .add_used(&self.mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self) -> bool {
        let max_iterations = self.rx_q.queue.actual_size();
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => {
                    // retry
                    continue;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        false
    }

    /// Fills self.rx_frame_buf with an ethernet frame from backend and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_backend(&mut self) -> result::Result<(), ReadError> {
        self.rx_frame_buf_len = self.backend.read_frame(&mut self.rx_frame_buf)?;
        Ok(())
    }
}
