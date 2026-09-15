use crate::virtio::net::backend::ConnectError;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::{DeviceQueue, InterruptTransport};

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::VirtioNetBackend;

#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::thread;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

pub struct NetWorker {
    rx_evt: Arc<EventFd>,
    tx_evt: Arc<EventFd>,
    backend: Box<dyn NetBackend + Send>,
    tx_needs_retry: bool,
}

impl NetWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        _vnet_features: u64,
        include_vnet_header: bool,
        cfg_backend: VirtioNetBackend,
    ) -> Result<Self, ConnectError> {
        let DeviceQueue {
            queue: rx_queue,
            event: rx_evt,
        } = rx_q;
        let DeviceQueue {
            queue: tx_queue,
            event: tx_evt,
        } = tx_q;

        let backend: Box<dyn NetBackend + Send> = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(
                    owned_fd,
                    include_vnet_header,
                    tx_queue,
                    rx_queue,
                    mem,
                    interrupt,
                ))
            }
            VirtioNetBackend::UnixstreamPath(path) => Box::new(Unixstream::open(
                path,
                include_vnet_header,
                tx_queue,
                rx_queue,
                mem,
                interrupt,
            )?),
            VirtioNetBackend::UnixgramFd(fd) => {
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(
                    owned_fd,
                    include_vnet_header,
                    tx_queue,
                    rx_queue,
                    mem,
                    interrupt,
                ))
            }
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => Box::new(Unixgram::open(
                path,
                vfkit_magic,
                include_vnet_header,
                tx_queue,
                rx_queue,
                mem,
                interrupt,
            )?),
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => Box::new(Tap::new(
                tap_name,
                _vnet_features,
                include_vnet_header,
                tx_queue,
                rx_queue,
                mem,
                interrupt,
            )?),
        };

        Ok(Self {
            rx_evt,
            tx_evt,
            backend,
            tx_needs_retry: false,
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

        let virtq_rx_ev_fd = self.rx_evt.as_raw_fd();
        let virtq_tx_ev_fd = self.tx_evt.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();

        let mut epoll = Epoll::new().unwrap();

        if let Err(e) = epoll.ctl(
            ControlOperation::Add,
            virtq_rx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_rx_ev_fd as u64),
        ) {
            log::error!(
                "Failed to add rx_ev fd {} to epoll: {:?}",
                virtq_rx_ev_fd,
                e
            );
        }
        if let Err(e) = epoll.ctl(
            ControlOperation::Add,
            virtq_tx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_tx_ev_fd as u64),
        ) {
            log::error!(
                "Failed to add tx_ev fd {} to epoll: {:?}",
                virtq_tx_ev_fd,
                e
            );
        }
        if let Err(e) = epoll.ctl(
            ControlOperation::Add,
            backend_socket,
            &EpollEvent::new(
                EventSet::IN | EventSet::OUT | EventSet::READ_HANG_UP | EventSet::EDGE_TRIGGERED,
                backend_socket as u64,
            ),
        ) {
            log::error!(
                "Failed to add backend fd {} to epoll: {:?}",
                backend_socket,
                e
            );
        }

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();

                        if source == virtq_rx_ev_fd && event_set.contains(EventSet::IN) {
                            log::trace!("virtio-net: rx queue event");
                            self.process_rx_queue_event();
                        } else if source == virtq_tx_ev_fd && event_set.contains(EventSet::IN) {
                            log::trace!("virtio-net: tx queue event");
                            self.process_tx_queue_event();
                        } else if source == backend_socket {
                            if event_set.contains(EventSet::HANG_UP)
                                || event_set.contains(EventSet::READ_HANG_UP)
                            {
                                log::error!(
                                    "Got {event_set:?} on backend fd, virtio-net will stop working"
                                );
                                eprintln!(
                                    "LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!"
                                );
                                let _ = epoll.ctl(
                                    ControlOperation::Delete,
                                    backend_socket,
                                    &EpollEvent::default(),
                                );
                            } else {
                                if event_set.contains(EventSet::IN) {
                                    self.process_rx();
                                }

                                if event_set.contains(EventSet::OUT) {
                                    self.process_tx();
                                }
                            }
                        } else {
                            #[cfg(target_os = "macos")]
                            if event_set.is_empty() && source == TX_TIMER_FD {
                                self.process_tx();
                            } else {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                            #[cfg(not(target_os = "macos"))]
                            log::warn!("Received unknown event: {event_set:?} from fd: {source:?}");
                        }
                    }

                    /*if ev_cnt == 0 {
                        self.process_rx();
                        self.process_tx();
                    }*/

                    // Arm the retry timer after processing all events, so it
                    // reflects the final state of tx_needs_retry.
                    #[cfg(target_os = "macos")]
                    if self.tx_needs_retry {
                        let delay = self.backend.write_retry_delay_us();
                        if delay > 0 {
                            epoll.add_oneshot_timer(delay, TX_TIMER_FD as u64);
                        }
                    }
                }
                Err(e) => {
                    debug!("virtio-net: failed to consume epoll event: {e}");
                }
            }
        }
    }

    fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.rx_evt.read() {
            log::error!("Failed to get rx event from queue: {e:?}");
        }
        self.process_rx();
    }

    fn process_tx_queue_event(&mut self) {
        if let Err(e) = self.tx_evt.read() {
            log::error!("Failed to get tx queue event from queue: {e:?}");
        }
        self.process_tx();
    }

    fn process_rx(&mut self) {
        match self.backend.recv() {
            Ok(()) => {}
            Err(ReadError::ProcessNotRunning) => {
                log::error!("RX error: backend process not running");
            }
            Err(ReadError::Internal(e)) => {
                log::error!("RX error: {e:?}");
            }
        }
    }

    fn process_tx(&mut self) {
        self.tx_needs_retry = match self.backend.send() {
            Ok(()) => false,
            Err(WriteError::NothingWritten) => true,
            Err(WriteError::ProcessNotRunning) => {
                log::error!("TX error: backend process not running");
                false
            }
            Err(WriteError::Internal(e)) => {
                log::error!("TX error: {e:?}");
                false
            }
        };
    }
}
