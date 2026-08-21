use std::io;

#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(windows)]
use std::os::windows::io::RawSocket;

#[cfg(windows)]
use vm_memory::GuestMemoryMmap;

#[cfg(unix)]
pub type SysError = nix::Error;
#[cfg(windows)]
pub type SysError = io::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ConnectError {
    InvalidAddress(SysError),
    CreateSocket(SysError),
    Binding(SysError),
    #[cfg(windows)]
    Worker(SysError),
    #[cfg(not(target_os = "windows"))]
    SendingMagic(nix::Error),
    // Tap backend errors.
    #[cfg(not(target_os = "windows"))]
    OpenNetTun(nix::Error),
    #[cfg(not(target_os = "windows"))]
    TunSetIff(io::Error),
    #[cfg(not(target_os = "windows"))]
    TunSetVnetHdrSz(io::Error),
    #[cfg(not(target_os = "windows"))]
    TunSetOffload(io::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ReadError {
    /// Nothing was written
    #[cfg(windows)]
    NothingRead,
    /// The guest queue ran out of available descriptors
    #[cfg(windows)]
    DescriptorStarvation,
    /// Backend process not running (EPIPE)
    ProcessNotRunning,
    #[cfg(windows)]
    Queue(crate::virtio::queue::Error),
    /// Another internal error occurred
    Internal(SysError),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum WriteError {
    /// Backend process not running (EPIPE)
    ProcessNotRunning,
    /// Nothing was written (e.g. ENOBUFS on macOS); caller should retry later.
    NothingWritten,
    /// Another internal error occurred
    Internal(SysError),
}

#[cfg(unix)]
/// Network backend trait.
///
/// Backends own both the socket and the queue consumers. The send/recv methods
/// operate on internal queues. EAGAIN is not an error - it just means nothing
/// happened this call.
pub trait NetBackend {
    /// Send pending frames from the TX queue to the network.
    ///
    /// Pulls frames from internal TxQueueConsumer and sends using batched I/O.
    /// EAGAIN returns Ok(()) - pending frames kept for retry.
    fn send(&mut self) -> Result<(), WriteError>;

    /// Receive frames from the network into the RX queue.
    ///
    /// Reads from socket into internal RxQueueProvider.
    /// EAGAIN returns Ok(()).
    fn recv(&mut self) -> Result<(), ReadError>;

    /// Returns the raw socket fd for epoll registration.
    fn raw_socket_fd(&self) -> RawFd;

    /// Delay in microseconds before retrying after NothingWritten.
    /// Returns 0 if no delay-based retry is needed (e.g. on Linux where
    /// EAGAIN + EPOLLET handles retries via writable events).
    #[allow(dead_code)]
    fn write_retry_delay_us(&self) -> u64 {
        0
    }
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
pub enum WriteStatus {
    Complete,
    Pending,
}

#[cfg(windows)]
pub trait NetBackend {
    fn prepare_tx_buffer(&mut self) -> &mut [u8];

    fn start_tx(&mut self, total_bytes: usize) -> Result<WriteStatus, WriteError>;

    fn resume_tx(&mut self) -> Result<WriteStatus, WriteError>;

    fn read_frames_to_guest(
        &mut self,
        mem: &GuestMemoryMmap,
        rx_queue: &mut crate::virtio::queue::Queue,
    ) -> Result<u32, ReadError>;

    fn raw_socket_fd(&self) -> RawSocket;
}
