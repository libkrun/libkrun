#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::Unixstream;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

#[cfg(windows)]
use std::os::windows::io::RawSocket;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use super::backend::{ConnectError, NetBackend, ReadError, WriteError, WriteStatus};

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

    fn start_tx(&mut self, total_bytes: usize) -> Result<WriteStatus, WriteError> {
        sys::start_tx(self, total_bytes)
    }

    fn resume_tx(&mut self) -> Result<WriteStatus, WriteError> {
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
