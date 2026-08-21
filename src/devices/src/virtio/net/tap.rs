use libc::{
    IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6, TUN_F_UFO, c_char, c_int,
    ifreq,
};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::{ioctl_write_int, ioctl_write_ptr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::{io, mem, ptr};
use utils::fd::SetNonblockingExt;
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO,
};
use vm_memory::GuestMemoryMmap;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::InterruptTransport;
use crate::virtio::batch_queue::aliased_ioslice::{AliasedIoSlice, AliasedIoSliceMut, AnyIoSlice};
use crate::virtio::batch_queue::{RxQueueProducer, TxQueueConsumer};
use crate::virtio::queue::Queue;

ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
ioctl_write_int!(tunsetoffload, b'T', 208);
ioctl_write_ptr!(tunsetvnethdrsz, b'T', 216, c_int);

pub struct Tap {
    fd: OwnedFd,
    interrupt: InterruptTransport,
    tx_consumer: TxQueueConsumer,
    rx_producer: RxQueueProducer,
}

impl Tap {
    /// Create an endpoint using the file descriptor of a tap device
    pub fn new(
        tap_name: String,
        vnet_features: u64,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Result<Self, ConnectError> {
        let mut req: ifreq = unsafe { mem::zeroed() };
        if tap_name.len() >= req.ifr_name.len() {
            return Err(ConnectError::InvalidAddress(nix::Error::ENAMETOOLONG));
        }

        let fd = match open("/dev/net/tun", OFlag::O_RDWR, Mode::empty()) {
            Ok(fd) => fd,
            Err(err) => return Err(ConnectError::OpenNetTun(err)),
        };

        unsafe {
            ptr::copy_nonoverlapping(
                tap_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tap_name.len(),
            );
        }

        req.ifr_ifru.ifru_flags = IFF_TAP as i16 | IFF_NO_PI as i16 | IFF_VNET_HDR as i16;

        log::info!("Tap::new() fd={} tap={}", fd.as_raw_fd(), tap_name);

        let mut offload_flags: u64 = 0;
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_CSUM)) != 0 {
            offload_flags |= TUN_F_CSUM as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO4)) != 0 {
            offload_flags |= TUN_F_TSO4 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO6)) != 0 {
            offload_flags |= TUN_F_TSO6 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_UFO)) != 0 {
            offload_flags |= TUN_F_UFO as u64;
        }

        unsafe {
            if let Err(err) = tunsetiff(fd.as_raw_fd(), &mut req as *mut _ as *mut _) {
                return Err(ConnectError::TunSetIff(io::Error::from(err)));
            }

            // TODO(slp): replace hardcoded vnet size with const
            if let Err(err) = tunsetvnethdrsz(fd.as_raw_fd(), &12) {
                return Err(ConnectError::TunSetVnetHdrSz(io::Error::from(err)));
            }

            if let Err(err) = tunsetoffload(fd.as_raw_fd(), offload_flags) {
                return Err(ConnectError::TunSetOffload(io::Error::from(err)));
            }
        }

        if let Err(e) = fd.set_nonblocking(true) {
            log::warn!("Failed to set O_NONBLOCK on tap: {e}");
        }

        let iovec_capacity = tx_queue.size as usize * 2;
        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), iovec_capacity);
        let rx_producer = RxQueueProducer::new(rx_queue, mem, iovec_capacity);

        Ok(Self {
            fd,
            interrupt,
            tx_consumer,
            rx_producer,
        })
    }
}

impl NetBackend for Tap {
    fn send(&mut self) -> Result<(), WriteError> {
        let raw_fd = self.fd.as_raw_fd();
        let mut total_finished = 0;

        self.tx_consumer.disable_notification();

        loop {
            self.tx_consumer.feed();

            if !self.tx_consumer.has_pending() {
                if self.tx_consumer.enable_notification() {
                    self.tx_consumer.disable_notification();
                    continue;
                }
                break;
            }

            // Each descriptor chain is one packet. TAP's writev combines iovecs into
            // a single packet, so we can use it directly without flattening.
            let finished = self.tx_consumer.consume(|batch| {
                for i in 0..batch.len() {
                    let chain = batch.io_slices(i);
                    if chain.is_empty() {
                        batch.finish(i);
                        continue;
                    }
                    let ret = unsafe {
                        libc::writev(
                            raw_fd,
                            AliasedIoSlice::as_iovec_ptr(chain),
                            chain.len() as c_int,
                        )
                    };
                    match ret {
                        n if n >= 0 => batch.finish(i),
                        _ => {
                            let err = nix::errno::Errno::last();
                            if err != nix::errno::Errno::EAGAIN {
                                log::error!("writev to tap failed: {err:?}");
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

            let finished = self.rx_producer.produce(|batch| {
                for i in 0..batch.len() {
                    let iovecs = batch.io_slices_mut(i);
                    if iovecs.is_empty() {
                        batch.complete(i, 0);
                        continue;
                    }

                    let ret = unsafe {
                        libc::readv(
                            raw_fd,
                            AliasedIoSliceMut::as_iovec_ptr(iovecs),
                            iovecs.len() as c_int,
                        )
                    };
                    match ret {
                        n if n > 0 => batch.complete(i, n as usize),
                        0 => break, // EOF
                        _ => {
                            let err = nix::errno::Errno::last();
                            if err != nix::errno::Errno::EAGAIN {
                                log::error!("readv from tap failed: {err:?}");
                            }
                            break;
                        }
                    }
                }
            });

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
