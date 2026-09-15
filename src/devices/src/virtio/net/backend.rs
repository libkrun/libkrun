use std::io;
use std::os::fd::RawFd;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ConnectError {
    InvalidAddress(nix::Error),
    CreateSocket(nix::Error),
    Binding(nix::Error),
    SendingMagic(nix::Error),
    // Tap backend errors.
    OpenNetTun(nix::Error),
    TunSetIff(io::Error),
    TunSetVnetHdrSz(io::Error),
    TunSetOffload(io::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ReadError {
    /// Backend process not running (EPIPE)
    ProcessNotRunning,
    /// Internal I/O error
    Internal(nix::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum WriteError {
    /// Backend process not running (EPIPE)
    ProcessNotRunning,
    /// Nothing was written (e.g. ENOBUFS on macOS); caller should retry later.
    NothingWritten,
    /// Internal I/O error
    Internal(nix::Error),
}

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
