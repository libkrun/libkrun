use std::fmt;
use std::io::{self, Write};
use std::os::fd::BorrowedFd;

use env_logger::Env;

use super::error::Error;
use super::export_bitflags;

#[cfg_attr(feature = "ffi", ffier::export)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Off = 0,
    #[default]
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl LogLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogStyle {
    #[default]
    Auto = 0,
    Always = 1,
    Never = 2,
}

impl LogStyle {
    pub const fn as_str(&self) -> &'static str {
        match self {
            LogStyle::Auto => "auto",
            LogStyle::Always => "always",
            LogStyle::Never => "never",
        }
    }
}

impl fmt::Display for LogStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

export_bitflags! {
    bitflags::bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct LogOptions: u32 {
            const NO_ENV = 1;
        }
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
pub fn init_log(
    target: Option<BorrowedFd<'static>>,
    level: LogLevel,
    style: LogStyle,
    options: LogOptions,
) -> Result<(), Error> {
    struct FdWriter(BorrowedFd<'static>);

    impl Write for FdWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            nix::unistd::write(self.0, buf).map_err(io::Error::from)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let target = match target {
        None => env_logger::Target::default(),
        Some(fd) => env_logger::Target::Pipe(Box::new(FdWriter(fd))),
    };

    let filter = level.as_str();
    let write_style = style.as_str();

    let mut builder = if options.contains(LogOptions::NO_ENV) {
        let mut builder = env_logger::Builder::new();
        builder.parse_filters(filter).parse_write_style(write_style);
        builder
    } else {
        env_logger::Builder::from_env(
            Env::new()
                .default_filter_or(filter)
                .default_write_style_or(write_style),
        )
    };
    builder.format_timestamp_micros().target(target).init();

    Ok(())
}
