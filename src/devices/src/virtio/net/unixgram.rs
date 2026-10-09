use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, bind, connect, getsockopt, recv, send,
    setsockopt, socket, sockopt,
};
use nix::unistd::unlink;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicU32, Ordering};

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
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
    fd: OwnedFd,
    retries: u64,
}

impl Unixgram {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: OwnedFd) -> Self {
        // Ensure the socket is in non-blocking mode.
        match fcntl(&fd, FcntlArg::F_GETFL) {
            Ok(flags) => match OFlag::from_bits(flags) {
                Some(flags) => {
                    if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                        warn!("error switching to non-blocking: id={fd:?}, err={e}");
                    }
                }
                None => error!("invalid fd flags id={fd:?}"),
            },
            Err(e) => error!("couldn't obtain fd flags id={fd:?}, err={e}"),
        };

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

        Self { fd, retries: 0 }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf, send_vfkit_magic: bool) -> Result<Self, ConnectError> {
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
            _ = unlink(path);
        }
        bind(fd.as_raw_fd(), &local_addr).map_err(ConnectError::Binding)?;

        // Connect so we don't need to use the peer address again. This also
        // allows the server to remove the socket after the connection.
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if send_vfkit_magic {
            send(fd.as_raw_fd(), &VFKIT_MAGIC, MsgFlags::empty())
                .map_err(ConnectError::SendingMagic)?;
        }

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &SOCKET_SNDBUF) {
            log::warn!("Failed to set SO_SNDBUF: {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &SOCKET_RCVBUF) {
            log::warn!("Failed to set SO_RCVBUF: {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self::new(fd))
    }
}

impl NetBackend for Unixgram {
    /// Try to read a frame the proxy. If no bytes are available reports ReadError::NothingRead
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let hdr_len = write_virtio_net_hdr(buf);
        let frame_length = match recv(self.fd.as_raw_fd(), &mut buf[hdr_len..], MsgFlags::empty()) {
            Ok(f) => f,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                return Err(ReadError::NothingRead);
            }
            Err(e) => {
                return Err(ReadError::Internal(e));
            }
        };
        debug!("Read eth frame from proxy: {frame_length} bytes");
        Ok(hdr_len + frame_length)
    }

    /// Try to write a frame to the proxy.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        let ret = match send(self.fd.as_raw_fd(), &buf[hdr_len..], MsgFlags::empty()) {
            Ok(ret) => ret,
            // macOS returns ENOBUFS; Linux returns EAGAIN when the socket buffer is full.
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK | nix::Error::ENOBUFS) => {
                if self.retries == 0 {
                    info!("write_frame: socket buffer full");
                }
                self.retries += 1;
                return Err(WriteError::NothingWritten);
            }
            Err(e) => return Err(WriteError::Internal(e)),
        };
        if self.retries > 0 {
            info!(
                "write_frame: socket buffer available after {} retries",
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

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    #[cfg(target_os = "macos")]
    fn write_retry_delay_us(&self) -> u64 {
        50
    }
}
