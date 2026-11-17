use std::io;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU32, Ordering};

use socket2::Socket;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use super::sys::{self, NetRawHandle};
use super::write_virtio_net_hdr;
#[cfg(target_os = "macos")]
use super::{MAX_BUFFER_SIZE, VNET_HDR_LEN};

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";

/// Per-process counter to generate unique local unixgram socket filenames.
///
/// The local socket is placed in the same directory as the peer using a short
/// PID+counter name. The peer filename always contains the machine name, so it
/// is longer than our fixed-format name for any reasonably-named machine, keeping
/// the local path within macOS's 104-byte unix socket limit.
static NET_SOCK_COUNTER: AtomicU32 = AtomicU32::new(0);

const DEFAULT_SOCKET_BUF_SIZE: usize = 7 * 1024 * 1024;

// On macOS, with UNIX datagram sockets the send buffer is not used for queuing;
// it determines the maximum frame size.
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_usrreq.c#L953
#[cfg(target_os = "macos")]
const SOCKET_SNDBUF: usize = MAX_BUFFER_SIZE - VNET_HDR_LEN;

#[cfg(not(target_os = "macos"))]
const SOCKET_SNDBUF: usize = DEFAULT_SOCKET_BUF_SIZE;

const SOCKET_RCVBUF: usize = DEFAULT_SOCKET_BUF_SIZE;

pub struct Unixgram {
    sock: Socket,
    retries: u64,
    _local_address: Option<utils::SocketPath>,
}

impl Unixgram {
    /// Create the backend from an already-connected datagram socket to the
    /// userspace network proxy. The socket is switched to nonblocking mode.
    pub fn new(sock: Socket) -> Self {
        let _ = sock.set_nonblocking(true);

        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            // socket2 has no SO_NOSIGPIPE abstraction; fall back to libc.
            let option_value: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &option_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&option_value) as libc::socklen_t,
                )
            };
        }

        if let Err(e) = sock.set_send_buffer_size(SOCKET_SNDBUF) {
            log::warn!("Failed to set SO_SNDBUF: {e}");
        }
        if let Err(e) = sock.set_recv_buffer_size(SOCKET_RCVBUF) {
            log::warn!("Failed to set SO_RCVBUF: {e}");
        }

        Self {
            sock,
            retries: 0,
            _local_address: None,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf, send_vfkit_magic: bool) -> Result<Self, ConnectError> {
        let socket_name = format!(
            "krun-net-{}-{}.sock",
            process::id(),
            NET_SOCK_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        let local_path = std::env::temp_dir().join(&socket_name);
        let (sock, address) =
            sys::connect_unix_dgram(&local_path, &path).map_err(ConnectError::Binding)?;

        if send_vfkit_magic {
            sys::send(&sock, &VFKIT_MAGIC).map_err(ConnectError::SendingMagic)?;
        }

        let mut backend = Self::new(sock);
        backend._local_address = Some(address);
        Ok(backend)
    }
}

impl NetBackend for Unixgram {
    /// Try to read a frame the proxy. If no bytes are available reports ReadError::NothingRead
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let hdr_len = write_virtio_net_hdr(buf);
        let frame_length = match sys::recv(&self.sock, &mut buf[hdr_len..]) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(ReadError::NothingRead);
            }
            Err(e) => return Err(ReadError::Internal(e)),
        };
        debug!("Read eth frame from proxy: {frame_length} bytes");
        Ok(hdr_len + frame_length)
    }

    /// Try to write a frame to the proxy.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        let ret = match sys::send(&self.sock, &buf[hdr_len..]) {
            Ok(ret) => ret,
            // macOS returns ENOBUFS when the kernel socket buffer is full,
            // rather than blocking or returning EAGAIN on non-blocking sockets.
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(libc::ENOBUFS) =>
            {
                if self.retries == 0 {
                    info!("write_frame: ENOBUFS/WouldBlock");
                }
                self.retries += 1;
                return Err(WriteError::NothingWritten);
            }
            Err(e) => return Err(WriteError::Internal(e)),
        };
        if self.retries > 0 {
            info!(
                "write_frame: ENOBUFS resolved after {} retries",
                self.retries
            );
            self.retries = 0;
        }
        debug!("Written eth frame to proxy: {ret} bytes");
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        // The unixgram backend doesn't do partial writes.
        Ok(())
    }

    fn raw_socket_fd(&self) -> NetRawHandle {
        sys::raw_handle(&self.sock)
    }

    #[cfg(target_os = "macos")]
    fn write_retry_delay_us(&self) -> u64 {
        50
    }
}
