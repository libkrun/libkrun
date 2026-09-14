use std::io;
use std::os::windows::io::{FromRawSocket, OwnedSocket, RawSocket};
use std::sync::mpsc;
use std::thread;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::windows::AsRawFd;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use crate::virtio::net::backend::ConnectError;
use crate::virtio::net::backend::{NetBackend, ReadError, WriteError, WriteStatus};
use crate::virtio::net::device::{TxError, VirtioNetBackend};
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE, VNET_HDR_LEN};
use crate::virtio::{DeviceQueue, InterruptTransport};

const RX_TOKEN: u64 = 1;
const TX_TOKEN: u64 = 2;
const BACKEND_TOKEN: u64 = 3;
const MAX_PROXY_PAYLOAD_SIZE: usize = MAX_BUFFER_SIZE - VNET_HDR_LEN;

pub struct NetWorker {
    rx_q: DeviceQueue,
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    backend_rx: Box<dyn NetBackend + Send>,
    backend_tx: Box<dyn NetBackend + Send>,
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
        let map_clone_error = ConnectError::CreateSocket;
        let (backend_rx, backend_tx) = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                let owned_socket = unsafe { OwnedSocket::from_raw_socket(fd) };
                let stream_rx = Unixstream::new(owned_socket)?;
                let owned_socket_tx = stream_rx.fd.try_clone().map_err(map_clone_error)?;
                (
                    Box::new(stream_rx) as Box<dyn NetBackend + Send>,
                    Box::new(Unixstream::new(owned_socket_tx)?) as Box<dyn NetBackend + Send>,
                )
            }
            VirtioNetBackend::UnixstreamPath(path) => {
                let stream_rx = Unixstream::open(path)?;
                let owned_socket_tx = stream_rx.fd.try_clone().map_err(map_clone_error)?;
                (
                    Box::new(stream_rx) as Box<dyn NetBackend + Send>,
                    Box::new(Unixstream::new(owned_socket_tx)?) as Box<dyn NetBackend + Send>,
                )
            }
        };

        Ok(Self {
            rx_q,
            tx_q,
            mem,
            backend_rx,
            backend_tx,
            interrupt,
        })
    }

    pub fn run(self) {
        let rx_worker = NetRxWorker {
            rx_q: self.rx_q,
            interrupt: self.interrupt.clone(),
            mem: self.mem.clone(),
            backend: self.backend_rx,
        };
        let tx_worker = NetTxWorker {
            tx_q: self.tx_q,
            interrupt: self.interrupt,
            mem: self.mem,
            backend: self.backend_tx,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            pending_indices: Vec::new(),
        };

        thread::Builder::new()
            .name("virtio-net rx worker".into())
            .spawn(move || rx_worker.work())
            .unwrap();

        thread::Builder::new()
            .name("virtio-net tx worker".into())
            .spawn(move || tx_worker.work())
            .unwrap();
    }
}

struct NetRxWorker {
    rx_q: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,
}

impl NetRxWorker {
    fn work(mut self) {
        if let Err(error) = self.run() {
            log::error!("virtio-net RX worker stopped: {error}");
        }
    }

    fn run(&mut self) -> io::Result<()> {
        let queue_event = self.rx_q.event.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();
        let mut epoll = Epoll::new()?;
        epoll.ctl(
            ControlOperation::Add,
            queue_event,
            &EpollEvent::new(EventSet::IN, RX_TOKEN),
        )?;
        epoll.ctl_socket(
            ControlOperation::Add,
            backend_socket as usize,
            &EpollEvent::new(EventSet::IN | EventSet::READ_HANG_UP, BACKEND_TOKEN),
        )?;
        self.rx_q
            .queue
            .enable_notification(&self.mem)
            .map_err(queue_io_error)?;

        let mut events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            let event_count = epoll.wait(events.len(), -1, &mut events)?;
            let mut needs_interrupt = false;
            for event in &events[..event_count] {
                match event.data() {
                    RX_TOKEN => {
                        self.rx_q.event.read()?;
                        self.set_socket_events(&epoll, backend_socket, true)?;
                        if self.drain_rx(&epoll, backend_socket, &mut needs_interrupt)? {
                            self.signal_if_needed(needs_interrupt)?;
                            return Ok(());
                        }
                    }
                    BACKEND_TOKEN => {
                        let event_set = event.event_set();
                        if (event_set.contains(EventSet::IN)
                            || event_set.contains(EventSet::READ_HANG_UP))
                            && self.drain_rx(&epoll, backend_socket, &mut needs_interrupt)?
                        {
                            self.signal_if_needed(needs_interrupt)?;
                            return Ok(());
                        }
                    }
                    token => log::warn!("unexpected virtio-net RX event token: {token}"),
                }
            }
            self.signal_if_needed(needs_interrupt)?;
        }
    }

    fn drain_rx(
        &mut self,
        epoll: &Epoll,
        backend_socket: RawSocket,
        needs_interrupt: &mut bool,
    ) -> io::Result<bool> {
        loop {
            self.rx_q
                .queue
                .disable_notification(&self.mem)
                .map_err(queue_io_error)?;
            let mut starved = false;
            loop {
                match self
                    .backend
                    .read_frames_to_guest(&self.mem, &mut self.rx_q.queue)
                {
                    Ok(_) => *needs_interrupt = true,
                    Err(ReadError::DescriptorStarvation) => {
                        starved = true;
                        break;
                    }
                    Err(ReadError::NothingRead) => break,
                    Err(ReadError::ProcessNotRunning) => return Ok(true),
                    Err(error) => {
                        *needs_interrupt = true;
                        log::error!("failed to receive virtio-net frame: {error:?}");
                        return Ok(true);
                    }
                }
            }

            let descriptors_available = self
                .rx_q
                .queue
                .enable_notification(&self.mem)
                .map_err(queue_io_error)?;
            if !starved {
                return Ok(false);
            }
            if descriptors_available {
                continue;
            }
            self.set_socket_events(epoll, backend_socket, false)?;
            return Ok(false);
        }
    }

    fn signal_if_needed(&mut self, used: bool) -> io::Result<()> {
        if used
            && self
                .rx_q
                .queue
                .needs_notification(&self.mem)
                .map_err(queue_io_error)?
        {
            self.interrupt
                .try_signal_used_queue()
                .map_err(|error| io::Error::other(format!("interrupt error: {error:?}")))?;
        }
        Ok(())
    }

    fn set_socket_events(
        &self,
        epoll: &Epoll,
        backend_socket: RawSocket,
        readable: bool,
    ) -> io::Result<()> {
        let events = if readable {
            EventSet::IN | EventSet::READ_HANG_UP
        } else {
            EventSet::empty()
        };
        epoll.ctl_socket(
            ControlOperation::Modify,
            backend_socket as usize,
            &EpollEvent::new(events, BACKEND_TOKEN),
        )
    }
}

struct NetTxWorker {
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,
    tx_iovec: Vec<(GuestAddress, usize)>,
    pending_indices: Vec<u16>,
}

impl NetTxWorker {
    fn work(mut self) {
        let result = self.run();
        if !self.pending_indices.is_empty()
            && let Err(error) = self.complete_pending()
        {
            log::error!("failed to release pending virtio-net TX descriptors: {error:?}");
        }
        if let Err(error) = result {
            log::error!("virtio-net TX worker stopped: {error:?}");
        }
    }

    fn run(&mut self) -> Result<(), TxError> {
        let queue_event = self.tx_q.event.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();
        let mut epoll = Epoll::new().map_err(io_tx_error)?;
        epoll
            .ctl(
                ControlOperation::Add,
                queue_event,
                &EpollEvent::new(EventSet::IN, TX_TOKEN),
            )
            .map_err(io_tx_error)?;
        epoll
            .ctl_socket(
                ControlOperation::Add,
                backend_socket as usize,
                &EpollEvent::new(EventSet::READ_HANG_UP, BACKEND_TOKEN),
            )
            .map_err(io_tx_error)?;

        let mut events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            let count = epoll
                .wait(events.len(), -1, &mut events)
                .map_err(io_tx_error)?;
            for event in &events[..count] {
                match event.data() {
                    TX_TOKEN => {
                        self.tx_q.event.read().map_err(io_tx_error)?;
                        if self.pending_indices.is_empty() {
                            self.process_tx_loop(&epoll, backend_socket)?;
                        }
                    }
                    BACKEND_TOKEN => {
                        let event_set = event.event_set();
                        if event_set.contains(EventSet::OUT) && !self.pending_indices.is_empty() {
                            self.resume_tx(&epoll, backend_socket)?;
                        }
                        if event_set.contains(EventSet::READ_HANG_UP) {
                            return Err(TxError::Backend(WriteError::ProcessNotRunning));
                        }
                    }
                    token => log::warn!("unexpected virtio-net TX event token: {token}"),
                }
            }
        }
    }

    fn process_tx_loop(&mut self, epoll: &Epoll, backend_socket: RawSocket) -> Result<(), TxError> {
        loop {
            self.tx_q
                .queue
                .disable_notification(&self.mem)
                .map_err(TxError::QueueError)?;
            let pending = self.process_tx(epoll, backend_socket)?;
            let has_new_entries = self
                .tx_q
                .queue
                .enable_notification(&self.mem)
                .map_err(TxError::QueueError)?;
            if pending || !has_new_entries {
                return Ok(());
            }
        }
    }

    fn process_tx(&mut self, epoll: &Epoll, backend_socket: RawSocket) -> Result<bool, TxError> {
        let tx_queue = &mut self.tx_q.queue;
        let tx_buffer = self.backend.prepare_tx_buffer();
        let mut write_offset = 0;
        let mut completed_invalid = false;

        while self.pending_indices.len() < 32 {
            let Some(head) = tx_queue.pop(&self.mem) else {
                break;
            };
            let head_index = head.index;
            self.tx_iovec.clear();
            let mut valid = true;
            let mut total_len = 0usize;
            let mut descriptor = Some(head);
            while let Some(current) = descriptor {
                let len = current.len as usize;
                if current.is_write_only() || total_len.checked_add(len).is_none() {
                    valid = false;
                } else {
                    total_len += len;
                    self.tx_iovec.push((current.addr, len));
                }
                descriptor = current.next_descriptor();
            }

            let payload_len = total_len.saturating_sub(VNET_HDR_LEN);
            if !valid || total_len <= VNET_HDR_LEN || payload_len > MAX_PROXY_PAYLOAD_SIZE {
                tx_queue
                    .add_used(&self.mem, head_index, 0)
                    .map_err(TxError::QueueError)?;
                completed_invalid = true;
                continue;
            }

            let framed_len = 4 + payload_len;
            if write_offset + framed_len > tx_buffer.len() {
                tx_queue.undo_pop();
                break;
            }
            let frame_start = write_offset;
            tx_buffer[write_offset..write_offset + 4]
                .copy_from_slice(&(payload_len as u32).to_be_bytes());
            write_offset += 4;

            let mut skip = VNET_HDR_LEN;
            for &(mut address, mut len) in &self.tx_iovec {
                if skip != 0 {
                    let skipped = skip.min(len);
                    let Some(next_address) = address.checked_add(skipped as u64) else {
                        valid = false;
                        break;
                    };
                    address = next_address;
                    len -= skipped;
                    skip -= skipped;
                }
                if len == 0 {
                    continue;
                }
                if self
                    .mem
                    .read_slice(&mut tx_buffer[write_offset..write_offset + len], address)
                    .is_err()
                {
                    valid = false;
                    break;
                }
                write_offset += len;
            }
            if !valid {
                write_offset = frame_start;
                tx_queue
                    .add_used(&self.mem, head_index, 0)
                    .map_err(TxError::QueueError)?;
                completed_invalid = true;
                continue;
            }
            self.pending_indices.push(head_index);
        }

        if completed_invalid {
            self.signal_tx()?;
        }
        if self.pending_indices.is_empty() {
            return Ok(false);
        }

        match self
            .backend
            .start_tx(write_offset)
            .map_err(TxError::Backend)?
        {
            WriteStatus::Complete => {
                self.complete_pending()?;
                Ok(false)
            }
            WriteStatus::Pending => {
                self.set_writable_events(epoll, backend_socket, true)?;
                Ok(true)
            }
        }
    }

    fn resume_tx(&mut self, epoll: &Epoll, backend_socket: RawSocket) -> Result<(), TxError> {
        match self.backend.resume_tx().map_err(TxError::Backend)? {
            WriteStatus::Complete => {
                self.complete_pending()?;
                self.set_writable_events(epoll, backend_socket, false)?;
                self.process_tx_loop(epoll, backend_socket)
            }
            WriteStatus::Pending => Ok(()),
        }
    }

    fn complete_pending(&mut self) -> Result<(), TxError> {
        for index in self.pending_indices.drain(..) {
            self.tx_q
                .queue
                .add_used(&self.mem, index, 0)
                .map_err(TxError::QueueError)?;
        }
        self.signal_tx()
    }

    fn signal_tx(&mut self) -> Result<(), TxError> {
        if self
            .tx_q
            .queue
            .needs_notification(&self.mem)
            .map_err(TxError::QueueError)?
        {
            self.interrupt
                .try_signal_used_queue()
                .map_err(TxError::DeviceError)?;
        }
        Ok(())
    }

    fn set_writable_events(
        &self,
        epoll: &Epoll,
        backend_socket: RawSocket,
        writable: bool,
    ) -> Result<(), TxError> {
        let events = if writable {
            EventSet::OUT | EventSet::READ_HANG_UP
        } else {
            EventSet::READ_HANG_UP
        };
        epoll
            .ctl_socket(
                ControlOperation::Modify,
                backend_socket as usize,
                &EpollEvent::new(events, BACKEND_TOKEN),
            )
            .map_err(io_tx_error)
    }
}

fn queue_io_error(error: crate::virtio::queue::Error) -> io::Error {
    io::Error::other(format!("virtio queue error: {error:?}"))
}

fn io_tx_error(error: io::Error) -> TxError {
    TxError::Backend(WriteError::Internal(error))
}
