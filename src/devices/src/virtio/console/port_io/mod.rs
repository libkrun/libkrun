use log::Level;
use std::io;
use utils::eventfd::EventFd;
use vm_memory::{VolatileSlice, WriteVolatile};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

pub trait PortInput {
    #[cfg(not(windows))]
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error>;

    #[cfg(windows)]
    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize, io::Error>;

    /// Blocks until input becomes readable, or any fd in `cancel_fds`
    /// becomes readable/signaled, whichever happens first. Used both for
    /// real VM shutdown (`stopfd`) and for a guest-initiated port pause
    /// (`pausefd`) -- either should interrupt an idle wait promptly, since
    /// there's nothing to drain on the input side.
    fn wait_until_readable(&self, cancel_fds: &[&EventFd]);
}

pub trait PortOutput {
    /// Writes `buf` to the output. `pausefd` is a cancellation signal used
    /// only for a guest-initiated port pause: once it becomes
    /// readable/signaled, implementations whose underlying write call may
    /// itself block indefinitely (e.g. a native blocking write on Windows)
    /// must abort the write and return promptly instead of waiting on a
    /// backpressured/non-responsive sink forever. Implementations using a
    /// non-blocking write (e.g. on Unix) can ignore `pausefd` here and rely
    /// on `wait_until_writable` instead. This must NOT be triggered by real
    /// VM shutdown: shutdown is expected to block until all buffered output
    /// is drained.
    fn write_volatile(
        &mut self,
        buf: &VolatileSlice,
        pausefd: Option<&EventFd>,
    ) -> Result<usize, io::Error>;

    /// Blocks until the output becomes writable, or `pausefd` becomes
    /// readable, whichever happens first. Implementations must return
    /// promptly once `pausefd` is signaled, so that callers can bound a
    /// pause operation and avoid blocking indefinitely on a
    /// backpressured/non-responsive sink. Must NOT be interrupted by real
    /// VM shutdown -- shutdown blocks here until the sink is writable, so
    /// buffered output is never silently dropped on exit.
    fn wait_until_writable(&self, pausefd: Option<&EventFd>);
}

/// Terminal properties associated with this port
pub trait PortTerminalProperties: Send + Sync {
    fn get_win_size(&self) -> (u16, u16);
}

pub fn term_fixed_size(width: u16, height: u16) -> Box<dyn PortTerminalProperties + Send + Sync> {
    Box::new(PortTerminalPropertiesFixed((width, height)))
}

pub fn output_to_log_as_err() -> Box<dyn PortOutput + Send> {
    Box::new(PortOutputLog::new())
}

struct PortTerminalPropertiesFixed((u16, u16));

impl PortTerminalProperties for PortTerminalPropertiesFixed {
    fn get_win_size(&self) -> (u16, u16) {
        self.0
    }
}

#[derive(Default)]
pub struct PortOutputLog {
    buf: Vec<u8>,
}

impl PortOutputLog {
    const FORCE_FLUSH_TRESHOLD: usize = 512;
    const LOG_TARGET: &'static str = "init_or_kernel";

    fn new() -> Self {
        Self::default()
    }

    fn force_flush(&mut self) {
        log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "[missing newline]{}", String::from_utf8_lossy(&self.buf));
        self.buf.clear();
    }
}

impl PortOutput for PortOutputLog {
    fn write_volatile(
        &mut self,
        buf: &VolatileSlice,
        _pausefd: Option<&EventFd>,
    ) -> Result<usize, io::Error> {
        self.buf.write_volatile(buf).map_err(io::Error::other)?;

        let mut start = 0;
        for (i, ch) in self.buf.iter().cloned().enumerate() {
            if ch == b'\n' {
                log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "{}", String::from_utf8_lossy(&self.buf[start..i]));
                start = i + 1;
            }
        }
        self.buf.drain(0..start);
        // Make sure to not grow the internal buffer forever!
        if self.buf.len() > PortOutputLog::FORCE_FLUSH_TRESHOLD {
            self.force_flush()
        }
        Ok(buf.len())
    }

    fn wait_until_writable(&self, _pausefd: Option<&EventFd>) {}
}

pub struct PortInputEmpty {}

impl PortInputEmpty {
    pub fn new() -> Self {
        PortInputEmpty {}
    }
}

impl Default for PortInputEmpty {
    fn default() -> Self {
        Self::new()
    }
}
