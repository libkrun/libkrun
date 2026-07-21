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
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_readable(&self, stopfd: Option<&EventFd>);
}

pub trait PortOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_writable(&self);
}

/// Terminal properties associated with this port
pub trait PortTerminalProperties: Send + Sync {
    fn get_win_size(&self) -> (u16, u16);
}

pub fn term_fixed_size(width: u16, height: u16) -> Box<dyn PortTerminalProperties + Send + Sync> {
    Box::new(PortTerminalPropertiesFixed((width, height)))
}

pub fn output_to_log_as_err() -> Box<dyn PortOutput + Send> {
    Box::new(PortOutputLog::new(Level::Error))
}

pub fn output_to_log(level: Level) -> Box<dyn PortOutput + Send> {
    Box::new(PortOutputLog::new(level))
}

struct PortTerminalPropertiesFixed((u16, u16));

impl PortTerminalProperties for PortTerminalPropertiesFixed {
    fn get_win_size(&self) -> (u16, u16) {
        self.0
    }
}

pub struct PortOutputLog {
    buf: Vec<u8>,
    level: Level,
}

impl PortOutputLog {
    const FORCE_FLUSH_TRESHOLD: usize = 512;
    const LOG_TARGET: &'static str = "init_or_kernel";

    fn new(level: Level) -> Self {
        Self {
            buf: Vec::new(),
            level,
        }
    }

    fn force_flush(&mut self) {
        log::log!(target: PortOutputLog::LOG_TARGET, self.level, "[missing newline]{}", String::from_utf8_lossy(&self.buf));
        self.buf.clear();
    }
}

impl PortOutput for PortOutputLog {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.buf.write_volatile(buf).map_err(io::Error::other)?;

        let mut start = 0;
        for (i, ch) in self.buf.iter().cloned().enumerate() {
            if ch == b'\n' {
                log::log!(target: PortOutputLog::LOG_TARGET, self.level, "{}", String::from_utf8_lossy(&self.buf[start..i]));
                start = i + 1;
            }
        }
        self.buf.drain(0..start);
        if self.buf.len() > PortOutputLog::FORCE_FLUSH_TRESHOLD {
            self.force_flush()
        }
        Ok(buf.len())
    }

    fn wait_until_writable(&self) {}
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

/// Open a virtio console port by name.
///
/// Scans `/dev/hvc*` devices for one whose `name` sysfs attribute matches
/// the given name. Returns the opened file if found.
pub fn open_virtio_port(name: &str) -> Option<std::fs::File> {
    use std::fs;
    use std::path::Path;

    for entry in fs::read_dir("/sys/class/virtio-ports").ok()? {
        let entry = entry.ok()?;
        let port_name = fs::read_to_string(entry.path().join("name")).ok()?;
        if port_name.trim() == name {
            let dev_name = entry.file_name();
            let dev_path = Path::new("/dev").join(dev_name);
            return fs::File::open(dev_path).ok();
        }
    }
    None
}
