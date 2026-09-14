use std::path::PathBuf;

#[cfg(unix)]
use std::os::fd::{OwnedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::RawSocket;

use crate::virtio::net::backend::ConnectError;

use super::backend::{NetBackend, ReadError, WriteError};
#[cfg(unix)]
use super::write_virtio_net_hdr;

// Conditional compilation to pick the right platform implementation
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

/// Each frame the network proxy is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
#[cfg(unix)]
const FRAME_HEADER_LEN: usize = 4;

#[cfg(unix)]
pub struct Unixstream {
    fd: OwnedFd,
    // 0 when a frame length has not been read
    expecting_frame_length: u32,
    // 0 if last write is fully complete, otherwise the length that was written
    last_partial_write_length: usize,
}

#[cfg(unix)]
impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: sys::RawStreamHandle) -> Self {
        sys::create(fd)
    }
    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        sys::open(path)
    }
    /// Try to read until filling the whole slice.
    fn read_loop(&self, buf: &mut [u8], block_until_has_data: bool) -> Result<(), ReadError> {
        sys::read_loop(&self.fd, buf, block_until_has_data)
    }
    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        sys::write_loop(self, buf)
    }
}

#[cfg(unix)]
impl NetBackend for Unixstream {
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if self.expecting_frame_length == 0 {
            self.expecting_frame_length = {
                let mut frame_length_buf = [0u8; FRAME_HEADER_LEN];
                self.read_loop(&mut frame_length_buf, false)?;
                u32::from_be_bytes(frame_length_buf)
            };
        }
        let hdr_len = write_virtio_net_hdr(buf);
        let buf = &mut buf[hdr_len..];
        let frame_length = self.expecting_frame_length as usize;
        self.read_loop(&mut buf[..frame_length], false)?;
        self.expecting_frame_length = 0;
        log::trace!("Read eth frame from network proxy: {frame_length} bytes");
        Ok(hdr_len + frame_length)
    }

    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            panic!("Cannot write a frame to the proxy, while a partial write is not resolved.");
        }
        assert!(
            hdr_len >= FRAME_HEADER_LEN,
            "Not enough space to write the frame header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;
        buf[hdr_len - FRAME_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());
        self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN..])
    }

    fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length != 0
    }

    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            let already_written = self.last_partial_write_length;
            log::trace!("Requested to finish partial write");
            self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN + already_written..])?;
            self.last_partial_write_length = 0;
            log::debug!("Finished partial write ({already_written} bytes written before)");
        }
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        sys::raw_socket_fd(&self.fd)
    }
}

#[cfg(windows)]
pub struct Unixstream {
    pub(crate) fd: sys::RawStreamHandle,
    _winsock: sys::WinsockGuard,
    tx_buffer: Box<[u8]>,
    tx_len: usize,
    tx_offset: usize,
    rx_buffer: Vec<u8>,
    rx_frame_buffer: Box<[u8]>,
    rx_buf_end: usize,
    rx_terminal: Option<sys::RxTerminal>,
}

#[cfg(windows)]
impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: sys::RawStreamHandle) -> Result<Self, ConnectError> {
        sys::create(fd)
    }
    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        sys::open(path)
    }
}

#[cfg(windows)]
impl NetBackend for Unixstream {
    fn raw_socket_fd(&self) -> RawSocket {
        sys::raw_socket_fd(&self.fd)
    }

    fn prepare_tx_buffer(&mut self) -> &mut [u8] {
        sys::prepare_tx_buffer(self)
    }

    fn start_tx(&mut self, total_bytes: usize) -> Result<super::backend::WriteStatus, WriteError> {
        sys::start_tx(self, total_bytes)
    }

    fn resume_tx(&mut self) -> Result<super::backend::WriteStatus, WriteError> {
        sys::resume_tx(self)
    }

    fn read_frames_to_guest(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap,
        rx_queue: &mut crate::virtio::queue::Queue,
    ) -> Result<u32, ReadError> {
        sys::read_frames_to_guest(self, mem, rx_queue)
    }
}
