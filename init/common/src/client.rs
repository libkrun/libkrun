// SPDX-License-Identifier: Apache-2.0
//
//! Host side of the control protocol: talk to the init of a running guest
//! through the Unix socket the VMM maps to the control vsock port.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use crate::control::{
    self, ExecSpec, ExitStatus, Failure, IO_CHUNK_LEN, PROTOCOL_VERSION, Request, Response,
    STDIN_WINDOW, WindowSize,
};

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

fn connect_nonblocking(path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    let path = path.as_os_str().as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    if path.is_empty() || path.len() >= addr.sun_path.len() || path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socket path",
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, src) in addr.sun_path.iter_mut().zip(path) {
        *dst = *src as libc::c_char;
    }
    let addr_len =
        (mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t;
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        addr.sun_len = addr_len as u8;
    }

    #[cfg(target_os = "macos")]
    let socket_type = libc::SOCK_STREAM;
    #[cfg(not(target_os = "macos"))]
    let socket_type = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    let fd = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    stream.set_nonblocking(true)?;
    if unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), addr_len) } < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        wait_for_connect(&stream, deadline)?;
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn wait_for_connect(stream: &UnixStream, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let timeout_ms = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut ready = pollfd(stream.as_fd(), libc::POLLOUT);
        let result = unsafe { libc::poll(&mut ready, 1, timeout_ms) };
        if result == 0 {
            continue;
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
        return Ok(());
    }
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
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::Timeout);
            }
            thread::sleep(RETRY_INTERVAL.min(remaining));
        }
    }

    fn try_open(path: &Path, deadline: Instant) -> Result<Connection, ClientError> {
        if Instant::now() >= deadline {
            return Err(ClientError::Timeout);
        }
        let stream = connect_nonblocking(path, deadline)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ClientError::Timeout);
        }
        stream.set_read_timeout(Some(remaining))?;
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
    ) || matches!(
        e.raw_os_error(),
        Some(libc::EAGAIN) | Some(libc::EINPROGRESS) | Some(libc::EALREADY) | Some(libc::EINTR)
    )
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

struct RawTerminal {
    fd: OwnedFd,
    original: libc::termios,
}

impl RawTerminal {
    fn new(tty: BorrowedFd) -> io::Result<Option<Self>> {
        let fd = tty.try_clone_to_owned()?;
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut original) } < 0 {
            return Ok(None);
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, &raw) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self { fd, original }))
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd.as_raw_fd(), libc::TCSANOW, &self.original) };
    }
}

fn sigpipe_pending() -> bool {
    let mut pending: libc::sigset_t = unsafe { mem::zeroed() };
    unsafe {
        libc::sigpending(&mut pending);
        libc::sigismember(&pending, libc::SIGPIPE) == 1
    }
}

fn write_without_sigpipe(fd: BorrowedFd, data: &[u8]) -> io::Result<usize> {
    let mut blocked: libc::sigset_t = unsafe { mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGPIPE);
    }
    let mut previous: libc::sigset_t = unsafe { mem::zeroed() };
    let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }

    let was_pending = sigpipe_pending();
    let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
    let error = (n < 0).then(io::Error::last_os_error);
    if error
        .as_ref()
        .is_some_and(|e| e.raw_os_error() == Some(libc::EPIPE))
        && !was_pending
        && sigpipe_pending()
    {
        let mut received = 0;
        unsafe { libc::sigwait(&blocked, &mut received) };
    }

    let result = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, ptr::null_mut()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    match error {
        Some(error) => Err(error),
        None => Ok(n as usize),
    }
}

fn write_all(fd: BorrowedFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = match write_without_sigpipe(fd, data) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                poll(&mut [pollfd(fd, libc::POLLOUT)])?;
                continue;
            }
            Err(e) => return Err(e),
        };
        if n > 0 {
            data = &data[n..];
        } else {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write guest output",
            ));
        }
    }
    Ok(())
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
                let output = fd.as_fd().try_clone_to_owned()?;
                (Some(fd), output, None, true)
            }
        };
        let _raw_terminal = if tty {
            RawTerminal::new(output.as_fd())?
        } else {
            None
        };
        let mut relay = Relay {
            stream,
            outbound: VecDeque::new(),
            stdin_credit: STDIN_WINDOW,
            input,
            output,
            errput,
            tty,
            signals,
        };
        if relay.input.is_none() {
            relay.queue(&Request::StdinEof);
        }
        relay.run()
    }
}

struct Relay {
    stream: UnixStream,
    outbound: VecDeque<u8>,
    stdin_credit: usize,
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

    fn flush_some(&mut self) -> Result<bool, ClientError> {
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
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(true),
            io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected => {
                self.outbound.clear();
                self.input = None;
                self.signals = None;
                Ok(false)
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
            let can_read_input = self.stdin_credit > 0 && self.outbound.len() < STDIN_WINDOW;
            let input_idx = self.input.as_ref().and_then(|fd| {
                if !can_read_input && !self.tty {
                    return None;
                }
                // poll still reports a terminal hangup when no read events are requested.
                let events = if can_read_input { libc::POLLIN } else { 0 };
                fds.push(pollfd(fd.as_fd(), events));
                Some(fds.len() - 1)
            });
            poll(&mut fds)?;

            if fds[0].revents & libc::POLLOUT != 0 && !self.flush_some()? {
                continue;
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
            if let Some(idx) = input_idx {
                let revents = fds[idx].revents;
                if self.tty && revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                    self.input_eof();
                } else if can_read_input && revents & READABLE != 0 {
                    self.handle_input(&mut chunk);
                }
            }
        }
    }

    fn handle_response(&mut self) -> Result<Option<ExitStatus>, ClientError> {
        match control::read::<Response>(&mut self.stream) {
            Ok(Response::Stdout(data)) => write_all(self.output.as_fd(), &data)?,
            Ok(Response::Stderr(data)) => {
                let target = self.errput.as_ref().unwrap_or(&self.output);
                write_all(target.as_fd(), &data)?;
            }
            Ok(Response::StdinCredit(bytes)) => self.stdin_credit += bytes as usize,
            Ok(Response::Exited(status)) => return Ok(Some(status)),
            Ok(Response::Failed(f)) => return Err(ClientError::Rejected(f)),
            Ok(_) => return Err(ClientError::Protocol("unexpected message during session")),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::NotConnected
                ) =>
            {
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
        if n == 0 {
            self.signals = None;
            return;
        }
        if n < 0 {
            if !matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                self.signals = None;
            }
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
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                chunk.as_mut_ptr().cast(),
                chunk.len().min(self.stdin_credit),
            )
        };
        if n > 0 {
            self.stdin_credit -= n as usize;
            self.queue(&Request::Stdin(chunk[..n as usize].to_vec()));
        } else if n == 0
            || !matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            )
        {
            self.input_eof();
        }
    }

    fn input_eof(&mut self) {
        self.queue(&Request::StdinEof);
        self.input = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::net::Shutdown;
    use std::os::fd::FromRawFd;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixListener;
    use std::process::Command;
    #[cfg(target_os = "linux")]
    use std::sync::mpsc;
    #[cfg(target_os = "linux")]
    use std::time::{SystemTime, UNIX_EPOCH};

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn set_nonblocking(fd: BorrowedFd) {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
    }

    #[test]
    fn closed_output_pipe_does_not_deliver_sigpipe() {
        const CHILD: &str = "KRUN_INIT_TEST_SIGPIPE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "client::tests::closed_output_pipe_does_not_deliver_sigpipe",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
        let (read, write) = pipe_pair();
        drop(read);
        let error = write_all(write.as_fd(), b"output").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));

        let mut blocked: libc::sigset_t = unsafe { mem::zeroed() };
        let mut previous: libc::sigset_t = unsafe { mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, libc::SIGPIPE);
        }
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) },
            0
        );
        let error = write_all(write.as_fd(), b"output").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
        assert!(!sigpipe_pending());

        assert_eq!(unsafe { libc::raise(libc::SIGPIPE) }, 0);
        assert!(sigpipe_pending());
        let error = write_all(write.as_fd(), b"output").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
        assert!(sigpipe_pending());
        let mut received = 0;
        assert_eq!(unsafe { libc::sigwait(&blocked, &mut received) }, 0);
        assert_eq!(received, libc::SIGPIPE);
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, ptr::null_mut()) },
            0
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_listener_backlog_respects_open_timeout() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "krun-init-connect-{}-{unique}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);

        let mut queued = Vec::new();
        for _ in 0..16 {
            match connect_nonblocking(&path, Instant::now() + Duration::from_millis(100)) {
                Ok(stream) => queued.push(stream),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("unexpected connect error: {e}"),
            }
        }
        assert!(queued.len() < 16, "listener backlog did not fill");

        let (tx, rx) = mpsc::channel();
        let connect_path = path.clone();
        let worker = thread::spawn(move || {
            tx.send(Connection::open(&connect_path, Duration::from_millis(100)))
                .unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(1));
        drop(queued);
        drop(listener);
        std::fs::remove_file(path).unwrap();
        assert!(
            matches!(result, Ok(Err(ClientError::Timeout))),
            "{result:?}"
        );
        worker.join().unwrap();
    }

    #[test]
    fn transient_nonblocking_reads_preserve_input_and_signals() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let (input, _input_writer) = pipe_pair();
        let (signals, _signal_writer) = pipe_pair();
        let (_output_reader, output) = pipe_pair();
        set_nonblocking(input.as_fd());
        set_nonblocking(signals.as_fd());
        let mut relay = Relay {
            stream,
            outbound: VecDeque::new(),
            stdin_credit: STDIN_WINDOW,
            input: Some(input),
            output,
            errput: None,
            tty: false,
            signals: Some(signals),
        };

        relay.handle_input(&mut [0; 1]);
        relay.handle_signals();
        assert!(relay.input.is_some());
        assert!(relay.signals.is_some());
        assert!(relay.outbound.is_empty());
    }

    #[test]
    fn tty_hangup_is_forwarded_without_stdin_credit() {
        let (input, input_peer) = UnixStream::pair().unwrap();
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let (_output_reader, output) = pipe_pair();
        let mut relay = Relay {
            stream,
            outbound: VecDeque::new(),
            stdin_credit: 0,
            input: Some(OwnedFd::from(input)),
            output,
            errput: None,
            tty: true,
            signals: None,
        };
        let worker = thread::spawn(move || relay.run());
        drop(input_peer);

        let mut ready = pollfd(peer.as_fd(), libc::POLLIN);
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 5000) }, 1);
        assert!(matches!(
            control::read::<Request>(&mut peer).unwrap(),
            Request::StdinEof
        ));
        control::write(&mut peer, &Response::Exited(ExitStatus::Exited(0))).unwrap();
        assert_eq!(worker.join().unwrap().unwrap(), ExitStatus::Exited(0));
    }

    #[test]
    fn buffered_exit_survives_closed_peer_with_pending_input() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let (output_reader, output) = pipe_pair();
        let mut relay = Relay {
            stream,
            outbound: VecDeque::new(),
            stdin_credit: STDIN_WINDOW,
            input: None,
            output,
            errput: None,
            tty: false,
            signals: None,
        };
        relay.queue(&Request::StdinEof);

        control::write(&mut peer, &Response::Stdout(b"done".to_vec())).unwrap();
        control::write(&mut peer, &Response::Exited(ExitStatus::Exited(7))).unwrap();
        peer.shutdown(Shutdown::Both).unwrap();

        assert_eq!(relay.run().unwrap(), ExitStatus::Exited(7));
        let mut output = [0; 4];
        File::from(output_reader).read_exact(&mut output).unwrap();
        assert_eq!(&output, b"done");
    }
}
