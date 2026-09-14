use super::super::backend::{ReadError, WriteError};
use crate::virtio::net::backend::ConnectError;
use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, connect, getsockopt, recv, send,
    setsockopt, socket, sockopt,
};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use super::Unixstream;

pub type RawStreamHandle = OwnedFd;

pub(crate) fn create(fd: OwnedFd) -> Unixstream {
    if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
        log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
    }

    log::debug!(
        "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
        getsockopt(&fd, sockopt::SndBuf),
        getsockopt(&fd, sockopt::RcvBuf)
    );

    Unixstream {
        fd,
        expecting_frame_length: 0,
        last_partial_write_length: 0,
    }
}

pub(crate) fn open(path: PathBuf) -> Result<Unixstream, ConnectError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
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

    Ok(Unixstream {
        fd,
        expecting_frame_length: 0,
        last_partial_write_length: 0,
    })
}

pub(crate) fn read_loop(
    fd: &OwnedFd,
    buf: &mut [u8],
    block_until_has_data: bool,
) -> Result<(), ReadError> {
    let mut bytes_read = 0;
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::MSG_DONTWAIT;

    if !block_until_has_data {
        match recv(fd.as_raw_fd(), buf, flags) {
            Ok(size) => bytes_read += size,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                return Err(ReadError::NothingRead);
            }
            Err(e) => return Err(ReadError::Internal(e)),
        }
    }

    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_WAITALL | MsgFlags::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::MSG_WAITALL;

    while bytes_read < buf.len() {
        match recv(fd.as_raw_fd(), &mut buf[bytes_read..], flags) {
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                log::warn!("read_loop: unexpected EAGAIN/EWOULDBLOCK on blocking socket");
                continue;
            }
            Err(e) => return Err(ReadError::Internal(e)),
            Ok(size) => {
                bytes_read += size;
                //log::trace!("proxy recv {}/{}", bytes_read, buf.len());
            }
        }
    }

    Ok(())
}

pub(crate) fn write_loop(stream: &mut Unixstream, buf: &[u8]) -> Result<(), WriteError> {
    let mut bytes_send = 0;

    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::MSG_DONTWAIT;

    while bytes_send < buf.len() {
        match send(stream.fd.as_raw_fd(), &buf[bytes_send..], flags) {
            Ok(size) => bytes_send += size,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                if bytes_send == 0 {
                    return Err(WriteError::NothingWritten);
                } else {
                    log::trace!(
                        "Wrote {bytes_send} bytes, but socket blocked, will need try_finish_write() to finish"
                    );

                    stream.last_partial_write_length += bytes_send;
                    return Err(WriteError::PartialWrite);
                }
            }
            Err(nix::Error::EPIPE) => return Err(WriteError::ProcessNotRunning),
            Err(e) => return Err(WriteError::Internal(e)),
        }
    }
    stream.last_partial_write_length = 0;
    Ok(())
}

pub(crate) fn raw_socket_fd(fd: &OwnedFd) -> RawFd {
    fd.as_raw_fd()
}
