// SPDX-License-Identifier: Apache-2.0
//
//! Host side of the control protocol: talk to the init of a running guest
//! through the Unix socket the VMM maps to the control vsock port.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::control::{
    self, ExecSpec, ExitStatus, Failure, IO_CHUNK_LEN, PROTOCOL_VERSION, Request, Response,
    WindowSize,
};

/// Stop reading stdin while this much data is waiting to be sent to the guest.
const STDIN_HIGH_WATER: usize = 256 * 1024;
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    /// The guest did not answer before the deadline.
    Timeout,
    Protocol(&'static str),
    VersionMismatch {
        guest: u32,
    },
    /// The guest could not find the executable.
    ExecutableNotFound(Failure),
    /// The guest found the executable but could not start it.
    SpawnFailed(Failure),
    /// The guest refused a request for another reason.
    Rejected(Failure),
    /// The connection ended before the process did.
    Disconnected,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "{e}"),
            ClientError::Timeout => write!(f, "the guest control server did not answer in time"),
            ClientError::Protocol(what) => write!(f, "protocol error: {what}"),
            ClientError::VersionMismatch { guest } => {
                write!(
                    f,
                    "guest speaks control protocol {guest}, host {PROTOCOL_VERSION}"
                )
            }
            ClientError::ExecutableNotFound(e)
            | ClientError::SpawnFailed(e)
            | ClientError::Rejected(e) => {
                write!(f, "{}", e.message)
            }
            ClientError::Disconnected => write!(f, "connection to the guest lost"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// A connection to the guest control server, after the Hello exchange.
#[derive(Debug)]
pub struct Connection {
    stream: UnixStream,
}

fn not_ready_yet(e: &io::Error) -> bool {
    // Until the guest listens on the port the VMM accepts the Unix connection
    // and then resets it; a slow guest shows up as a read timeout.
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::BrokenPipe
    )
}

impl Connection {
    /// Connect to `path` and complete the Hello exchange, retrying until
    /// `timeout` while the guest is still booting.
    pub fn open(path: &Path, timeout: Duration) -> Result<Connection, ClientError> {
        let deadline = Instant::now() + timeout;
        loop {
            match Self::try_open(path, deadline) {
                Ok(connection) => return Ok(connection),
                Err(ClientError::Io(e)) if not_ready_yet(&e) || is_absent(&e) => {}
                Err(e) => return Err(e),
            }
            if Instant::now() >= deadline {
                return Err(ClientError::Timeout);
            }
            thread::sleep(RETRY_INTERVAL);
        }
    }

    fn try_open(path: &Path, deadline: Instant) -> Result<Connection, ClientError> {
        let stream = UnixStream::connect(path)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        stream.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))?;
        Self::from_stream(stream)
    }

    /// Complete the Hello exchange on an already connected stream.
    pub fn from_stream(mut stream: UnixStream) -> Result<Connection, ClientError> {
        control::write(
            &mut stream,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )?;
        match control::read::<Response>(&mut stream)? {
            Response::Hello { version } if version == PROTOCOL_VERSION => {}
            Response::Hello { version } => {
                return Err(ClientError::VersionMismatch { guest: version });
            }
            Response::Failed(f) => return Err(ClientError::Rejected(f)),
            _ => return Err(ClientError::Protocol("unexpected reply to hello")),
        }
        stream.set_read_timeout(None)?;
        Ok(Connection { stream })
    }

    /// Deliver `signal` to the guest's main workload.
    pub fn signal_entrypoint(mut self, signal: i32) -> Result<(), ClientError> {
        control::write(&mut self.stream, &Request::SignalEntrypoint { signal })?;
        match control::read::<Response>(&mut self.stream)? {
            Response::Ok => Ok(()),
            Response::Failed(f) => Err(ClientError::Rejected(f)),
            _ => Err(ClientError::Protocol("unexpected reply to signal request")),
        }
    }

    /// Start a process in the guest. I/O is relayed by [`Session::run`].
    pub fn exec(mut self, spec: &ExecSpec) -> Result<Session, ClientError> {
        control::write(&mut self.stream, &Request::Exec(spec.clone()))?;
        match control::read::<Response>(&mut self.stream)? {
            Response::Started { pid } => Ok(Session {
                stream: self.stream,
                pid,
            }),
            Response::Failed(f) if f.errno == libc::ENOENT => {
                Err(ClientError::ExecutableNotFound(f))
            }
            Response::Failed(f) => Err(ClientError::SpawnFailed(f)),
            _ => Err(ClientError::Protocol("unexpected reply to exec request")),
        }
    }
}

fn is_absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    ) || e.raw_os_error() == Some(libc::EAGAIN)
}

/// Where a session's stdio goes on the host.
pub enum SessionIo {
    Pipes {
        stdin: Option<OwnedFd>,
        stdout: OwnedFd,
        stderr: OwnedFd,
    },
    /// A terminal: input and output share it and it is switched to raw mode,
    /// the line discipline lives in the guest pty.
    Tty(OwnedFd),
}

/// Query the window size of a terminal descriptor.
pub fn window_size(tty: BorrowedFd) -> Option<WindowSize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCGWINSZ as _, &mut ws) } < 0 {
        return None;
    }
    Some(WindowSize {
        rows: ws.ws_row,
        cols: ws.ws_col,
    })
}

fn set_raw(tty: BorrowedFd) {
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut termios) } == 0 {
        unsafe {
            libc::cfmakeraw(&mut termios);
            libc::tcsetattr(tty.as_raw_fd(), libc::TCSANOW, &termios);
        }
    }
}

fn write_all(fd: BorrowedFd, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
        if n > 0 {
            data = &data[n as usize..];
        } else if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        } else {
            return;
        }
    }
}

fn poll(fds: &mut [libc::pollfd]) -> io::Result<()> {
    loop {
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if ret >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn pollfd(fd: BorrowedFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd: fd.as_raw_fd(),
        events,
        revents: 0,
    }
}

const READABLE: libc::c_short = libc::POLLIN | libc::POLLHUP | libc::POLLERR;

/// A process running in the guest.
#[derive(Debug)]
pub struct Session {
    stream: UnixStream,
    pid: i32,
}

impl Session {
    /// Pid of the process inside the guest.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Relay stdio until the process exits and return its status.
    ///
    /// `signals`, if given, delivers signal numbers as single bytes (a
    /// self-pipe written by the caller's signal handlers): `SIGWINCH` resizes
    /// the guest pty to the size of the host terminal, everything else is
    /// forwarded to the process.
    pub fn run(self, io: SessionIo, signals: Option<OwnedFd>) -> Result<ExitStatus, ClientError> {
        let Session { stream, pid: _ } = self;
        let (input, output, errput, tty) = match io {
            SessionIo::Pipes {
                stdin,
                stdout,
                stderr,
            } => (stdin, stdout, Some(stderr), false),
            SessionIo::Tty(fd) => {
                set_raw(fd.as_fd());
                let output = fd.as_fd().try_clone_to_owned()?;
                (Some(fd), output, None, true)
            }
        };
        let mut relay = Relay {
            stream,
            outbound: VecDeque::new(),
            input,
            output,
            errput,
            tty,
            signals,
        };
        relay.run()
    }
}

struct Relay {
    stream: UnixStream,
    outbound: VecDeque<u8>,
    input: Option<OwnedFd>,
    output: OwnedFd,
    errput: Option<OwnedFd>,
    tty: bool,
    signals: Option<OwnedFd>,
}

impl Relay {
    fn queue(&mut self, request: &Request) {
        self.outbound.extend(control::encode(request));
    }

    fn flush_some(&mut self) -> Result<(), ClientError> {
        let (front, _) = self.outbound.as_slices();
        let n = unsafe {
            libc::send(
                self.stream.as_raw_fd(),
                front.as_ptr().cast(),
                front.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if n >= 0 {
            self.outbound.drain(..n as usize);
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(()),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => {
                Err(ClientError::Disconnected)
            }
            _ => Err(err.into()),
        }
    }

    fn run(&mut self) -> Result<ExitStatus, ClientError> {
        let mut chunk = vec![0u8; IO_CHUNK_LEN];
        loop {
            let mut fds = vec![pollfd(
                self.stream.as_fd(),
                libc::POLLIN
                    | if self.outbound.is_empty() {
                        0
                    } else {
                        libc::POLLOUT
                    },
            )];
            let signals_idx = self.signals.as_ref().map(|fd| {
                fds.push(pollfd(fd.as_fd(), libc::POLLIN));
                fds.len() - 1
            });
            let input_idx = match &self.input {
                Some(fd) if self.outbound.len() < STDIN_HIGH_WATER => {
                    fds.push(pollfd(fd.as_fd(), libc::POLLIN));
                    Some(fds.len() - 1)
                }
                _ => None,
            };
            poll(&mut fds)?;

            if fds[0].revents & libc::POLLOUT != 0 {
                self.flush_some()?;
            }
            if fds[0].revents & READABLE != 0
                && let Some(status) = self.handle_response()?
            {
                return Ok(status);
            }
            if let Some(idx) = signals_idx
                && fds[idx].revents & READABLE != 0
            {
                self.handle_signals();
            }
            if let Some(idx) = input_idx
                && fds[idx].revents & READABLE != 0
            {
                self.handle_input(&mut chunk);
            }
        }
    }

    fn handle_response(&mut self) -> Result<Option<ExitStatus>, ClientError> {
        match control::read::<Response>(&mut self.stream) {
            Ok(Response::Stdout(data)) => write_all(self.output.as_fd(), &data),
            Ok(Response::Stderr(data)) => {
                let target = self.errput.as_ref().unwrap_or(&self.output);
                write_all(target.as_fd(), &data);
            }
            Ok(Response::Exited(status)) => return Ok(Some(status)),
            Ok(Response::Failed(f)) => return Err(ClientError::Rejected(f)),
            Ok(_) => return Err(ClientError::Protocol("unexpected message during session")),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(ClientError::Disconnected);
            }
            Err(e) => return Err(e.into()),
        }
        Ok(None)
    }

    fn handle_signals(&mut self) {
        let Some(fd) = &self.signals else { return };
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            self.signals = None;
            return;
        }
        for &signal in &buf[..n as usize] {
            if i32::from(signal) == libc::SIGWINCH {
                if let (true, Some(size)) = (self.tty, window_size(self.output.as_fd())) {
                    self.queue(&Request::Resize(size));
                }
            } else {
                self.queue(&Request::Signal {
                    signal: i32::from(signal),
                });
            }
        }
    }

    fn handle_input(&mut self, chunk: &mut [u8]) {
        let Some(fd) = &self.input else { return };
        let n = unsafe { libc::read(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
        if n > 0 {
            self.queue(&Request::Stdin(chunk[..n as usize].to_vec()));
        } else if n == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            self.queue(&Request::StdinEof);
            self.input = None;
        }
    }
}
