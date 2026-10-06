#[cfg(target_os = "macos")]
use libc::c_int;
use libc::iovec;
#[cfg(target_os = "linux")]
use libc::mmsghdr;
use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, bind, connect, getsockopt, send,
    setsockopt, socket, sockopt,
};
use std::fs::remove_file;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU32, Ordering};
use utils::fd::SetNonblockingExt;
use vm_memory::GuestMemoryMmap;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::InterruptTransport;
use crate::virtio::batch_queue::aliased_ioslice::{
    AliasedIoSlice, AliasedIoSliceMut, AnyIoSlice, RawAliasedIoSlice,
};
use crate::virtio::batch_queue::{ReceivedBytes, RxQueueProducer, TxQueueConsumer, WorkItemState};
use crate::virtio::queue::Queue;

#[cfg(target_os = "macos")]
use super::socket_x::msghdr_x;

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";
#[cfg(target_os = "macos")]
const MSG_BATCH_SIZE: usize = 64;
/// Per-process counter to generate unique local unixgram socket filenames.
///
/// The local socket is placed in the same directory as the peer using a short
/// PID+counter name. The peer filename always contains the machine name, so it
/// is longer than our fixed-format name for any reasonably-named machine, keeping
/// the local path within macOS's 104-byte unix socket limit.
static NET_SOCK_COUNTER: AtomicU32 = AtomicU32::new(0);

#[cfg(target_os = "linux")]
type RawMsgHdr = mmsghdr;

#[cfg(target_os = "macos")]
type RawMsgHdr = msghdr_x;

/// User-owned syscall header state aligned with the batch queue's work items.
#[repr(transparent)]
pub struct MsgHdrItem(RawMsgHdr);

unsafe impl Send for MsgHdrItem {}

impl Default for MsgHdrItem {
    #[cfg(target_os = "linux")]
    fn default() -> Self {
        Self(unsafe { std::mem::zeroed() })
    }

    #[cfg(target_os = "macos")]
    fn default() -> Self {
        Self(msghdr_x::default())
    }
}

impl WorkItemState for MsgHdrItem {
    fn set_iovecs(&mut self, iovecs: &[RawAliasedIoSlice]) {
        let ptr = if iovecs.is_empty() {
            std::ptr::null_mut()
        } else {
            iovecs.as_ptr() as *mut iovec
        };

        #[cfg(target_os = "linux")]
        {
            self.0.msg_hdr.msg_iov = ptr;
            self.0.msg_hdr.msg_iovlen = iovecs.len();
        }

        #[cfg(target_os = "macos")]
        {
            self.0.msg_iov = ptr;
            self.0.msg_iovlen = iovecs.len() as c_int;
            self.0.msg_flags = 0;
            self.0.msg_datalen = 0;
        }
    }
}

impl ReceivedBytes for MsgHdrItem {
    #[cfg(target_os = "linux")]
    #[inline]
    fn received_bytes(&self) -> usize {
        self.0.msg_len as usize
    }

    #[cfg(target_os = "macos")]
    #[inline]
    fn received_bytes(&self) -> usize {
        self.0.msg_datalen
    }
}

pub struct Unixgram {
    fd: OwnedFd,
    include_vnet_header: bool,
    interrupt: InterruptTransport,
    tx_consumer: TxQueueConsumer<MsgHdrItem>,
    rx_producer: RxQueueProducer<MsgHdrItem>,
    local_path: Option<PathBuf>,
}

impl Drop for Unixgram {
    fn drop(&mut self) {
        if let Some(path) = &self.local_path {
            _ = remove_file(path);
        }
    }
}

impl Unixgram {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(
        fd: OwnedFd,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Self {
        Self::new_with_path(
            fd,
            include_vnet_header,
            tx_queue,
            rx_queue,
            mem,
            interrupt,
            None,
        )
    }

    fn new_with_path(
        fd: OwnedFd,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        local_path: Option<PathBuf>,
    ) -> Self {
        // Ensure the socket is in non-blocking mode.
        if let Err(e) = fd.set_nonblocking(true) {
            log::error!("Failed to set O_NONBLOCK on unixgram socket: {e}");
        }

        #[cfg(target_os = "macos")]
        {
            // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
            let option_value: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &option_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&option_value) as libc::socklen_t,
                )
            };
        }

        #[cfg(target_os = "macos")]
        let sndbuf_size: usize = super::MAX_BUFFER_SIZE - super::vnet_hdr_len();
        #[cfg(not(target_os = "macos"))]
        let sndbuf_size: usize = 7 * 1024 * 1024;

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &sndbuf_size) {
            log::warn!("Failed to set SO_SNDBUF: {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to set SO_RCVBUF: {e}");
        }

        let iovec_capacity = tx_queue.size as usize * 2;
        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), iovec_capacity);
        let rx_producer = RxQueueProducer::new(rx_queue, mem, iovec_capacity);

        Self {
            fd,
            include_vnet_header,
            interrupt,
            tx_consumer,
            rx_producer,
            local_path,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(
        path: PathBuf,
        send_vfkit_magic: bool,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Result<Self, ConnectError> {
        // We cannot create a non-blocking socket on macOS here. This is done later in new().
        let fd = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::CreateSocket)?;
        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        let socket_name = format!(
            "krun-net-{}-{}.sock",
            process::id(),
            NET_SOCK_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        let local_path = std::env::temp_dir().join(&socket_name);
        let local_addr = UnixAddr::new(&local_path).map_err(ConnectError::InvalidAddress)?;
        if let Some(path) = local_addr.path() {
            _ = remove_file(path);
        }
        bind(fd.as_raw_fd(), &local_addr).map_err(ConnectError::Binding)?;

        // Connect so we don't need to use the peer address again. This also
        // allows the server to remove the socket after the connection.
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if send_vfkit_magic {
            send(fd.as_raw_fd(), &VFKIT_MAGIC, MsgFlags::empty())
                .map_err(ConnectError::SendingMagic)?;
        }

        #[cfg(target_os = "macos")]
        let sndbuf_size: usize = super::MAX_BUFFER_SIZE - super::vnet_hdr_len();
        #[cfg(not(target_os = "macos"))]
        let sndbuf_size: usize = 7 * 1024 * 1024;

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &sndbuf_size) {
            log::warn!("Failed to set SO_SNDBUF: {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to set SO_RCVBUF: {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self::new_with_path(
            fd,
            include_vnet_header,
            tx_queue,
            rx_queue,
            mem,
            interrupt,
            Some(local_path),
        ))
    }
}

impl NetBackend for Unixgram {
    fn send(&mut self) -> Result<(), WriteError> {
        let skip = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };

        let mut total_sent = 0;

        self.tx_consumer.disable_notification();

        loop {
            self.tx_consumer.feed_with_transform(|iovecs, out| {
                if !out.reserve(iovecs.len()) {
                    return None;
                }
                out.extend(AliasedIoSlice::skip_bytes(iovecs, skip));
                Some(MsgHdrItem::default())
            });

            if !self.tx_consumer.has_pending() {
                if self.tx_consumer.enable_notification() {
                    self.tx_consumer.disable_notification();
                    continue;
                }
                break;
            }

            let sent = match self.send_impl() {
                Ok(sent) => sent,
                Err(e) => {
                    if total_sent > 0 && self.tx_consumer.needs_notification() {
                        self.interrupt.signal_used_queue();
                    }
                    return Err(e);
                }
            };
            total_sent += sent;

            // Socket fully blocked — wait for EPOLLOUT.
            if sent == 0 {
                break;
            }
        }

        if total_sent > 0 && self.tx_consumer.needs_notification() {
            self.interrupt.signal_used_queue();
        }

        if self.tx_consumer.has_pending() {
            return Err(WriteError::NothingWritten);
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let vnet_offset = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };
        let mut total_finished = 0;

        self.rx_producer.disable_notification();

        loop {
            self.rx_producer.feed_with_transform(|iovecs, out| {
                if !out.reserve(iovecs.len()) {
                    return None;
                }
                out.extend(AliasedIoSliceMut::write_prefix(
                    iovecs,
                    &super::DEFAULT_VNET_HDR[..vnet_offset],
                ));
                let max_bytes = out.total_bytes() + vnet_offset;
                Some((max_bytes, MsgHdrItem::default()))
            });

            if !self.rx_producer.has_pending() {
                if self.rx_producer.enable_notification() {
                    self.rx_producer.disable_notification();
                    continue;
                }
                break;
            }

            let finished = self.recv_impl();

            total_finished += finished;
            // If we still have pending buffers in the producer, we assume we drained the whole socket
            if finished == 0 {
                break;
            }
        }

        if total_finished > 0 && self.rx_producer.needs_notification() {
            self.interrupt.signal_used_queue();
        }

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    #[cfg(target_os = "macos")]
    fn write_retry_delay_us(&self) -> u64 {
        50
    }
}

#[cfg(target_os = "linux")]
#[inline]
unsafe fn send_batch(fd: RawFd, ptr: *mut RawMsgHdr, len: usize) -> isize {
    unsafe { libc::sendmmsg(fd, ptr, len as libc::c_uint, libc::MSG_DONTWAIT) as isize }
}

#[cfg(target_os = "linux")]
#[inline]
unsafe fn recv_batch(fd: RawFd, ptr: *mut RawMsgHdr, len: usize) -> isize {
    unsafe {
        libc::recvmmsg(
            fd,
            ptr,
            len as libc::c_uint,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        ) as isize
    }
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn send_batch(fd: RawFd, ptr: *mut RawMsgHdr, len: usize) -> isize {
    unsafe {
        super::socket_x::sendmsg_x(
            fd,
            ptr as *const super::socket_x::msghdr_x,
            len as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    }
}

#[cfg(target_os = "macos")]
#[inline]
unsafe fn recv_batch(fd: RawFd, ptr: *mut RawMsgHdr, len: usize) -> isize {
    unsafe { super::socket_x::recvmsg_x(fd, ptr, len as libc::c_uint, libc::MSG_DONTWAIT) }
}

impl Unixgram {
    fn send_impl(&mut self) -> Result<usize, WriteError> {
        let fd = self.fd.as_raw_fd();
        let mut error = None;

        let sent = self.tx_consumer.consume(|batch| {
            let len = batch.len();
            #[cfg(target_os = "macos")]
            let len = len.min(MSG_BATCH_SIZE);
            let headers = batch.transformed_mut(0..len);
            let ptr = headers.as_mut_ptr() as *mut RawMsgHdr;

            let ret = unsafe { send_batch(fd, ptr, len) };

            if ret < 0 {
                let err = nix::errno::Errno::last();
                match err {
                    nix::errno::Errno::EAGAIN | nix::errno::Errno::ENOBUFS => {}
                    nix::errno::Errno::EPIPE => error = Some(WriteError::ProcessNotRunning),
                    _ => error = Some(WriteError::Internal(err)),
                }
                return;
            }

            batch.finish_many(0..ret as usize);
        });

        match error {
            Some(e) => Err(e),
            None => Ok(sent),
        }
    }

    fn recv_impl(&mut self) -> usize {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            let len = batch.len();
            #[cfg(target_os = "macos")]
            let len = len.min(MSG_BATCH_SIZE);
            let ret = {
                let headers = batch.transformed_mut(0..len);
                let ptr = headers.as_mut_ptr() as *mut RawMsgHdr;
                unsafe { recv_batch(fd, ptr, len) }
            };

            match ret {
                n if n > 0 => {
                    batch.complete_received_many(0..n as usize);
                }
                0 => log::warn!("recv returned 0 (unexpected)"),
                _ => {
                    let err = nix::errno::Errno::last();
                    if err != nix::errno::Errno::EAGAIN && err != nix::errno::Errno::ENOBUFS {
                        log::error!("recv failed: {err}");
                    }
                }
            }
        })
    }
}
