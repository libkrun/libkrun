// SPDX-License-Identifier: Apache-2.0
//
//! Host-side handle on the control server of a running guest init.
//!
//! Wraps [`krun_init_common::client`] in types that the C API can carry. The
//! wire protocol stays private to libkrun; callers only see processes, exit
//! codes and errors.

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::time::Duration;

use krun_init_common::client::{self, ClientError, Connection, Session, SessionIo};
use krun_init_common::control::{ExecSpec, WindowSize};

#[cfg(feature = "ffi")]
use crate::{FfiBorrow, FfiType};

/// Error type for control server operations.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(ffier::FfiError))]
#[non_exhaustive]
pub enum ControlError {
    /// I/O error talking to the control socket.
    #[error("{0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 1))]
    Io(Box<str>),
    /// The guest did not answer before the timeout expired.
    #[error("the guest control server did not answer in time")]
    #[cfg_attr(feature = "ffi", ffier(code = 2))]
    Timeout(),
    /// The guest answered something unexpected.
    #[error("control protocol error: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 3))]
    Protocol(Box<str>),
    /// The executable does not exist in the guest.
    #[error("{0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 4))]
    ExecutableNotFound(Box<str>),
    /// The guest could not start the process for another reason.
    #[error("{0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 5))]
    SpawnFailed(Box<str>),
    /// The guest refused the request.
    #[error("{0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 6))]
    Rejected(Box<str>),
    /// The connection ended before the process did.
    #[error("connection to the guest lost")]
    #[cfg_attr(feature = "ffi", ffier(code = 7))]
    Disconnected(),
    /// The process was already waited for.
    #[error("the process has already been waited for")]
    #[cfg_attr(feature = "ffi", ffier(code = 8))]
    AlreadyWaited(),
}

impl From<ClientError> for ControlError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Io(e) => ControlError::Io(e.to_string().into()),
            ClientError::Timeout => ControlError::Timeout(),
            ClientError::Protocol(what) => ControlError::Protocol(what.into()),
            ClientError::VersionMismatch { .. } => ControlError::Protocol(e.to_string().into()),
            ClientError::ExecutableNotFound(f) => {
                ControlError::ExecutableNotFound(f.message.into())
            }
            ClientError::SpawnFailed(f) => ControlError::SpawnFailed(f.message.into()),
            ClientError::Rejected(f) => ControlError::Rejected(f.message.into()),
            ClientError::Disconnected => ControlError::Disconnected(),
        }
    }
}

/// Describes a process to start in the guest.
#[derive(Clone, Debug)]
pub struct ExecRequest {
    spec: ExecSpec,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl ExecRequest {
    /// Start describing a process; `program` is the path of the executable
    /// inside the guest.
    pub fn new(program: &str) -> Self {
        Self {
            spec: ExecSpec {
                program: program.to_string(),
                ..ExecSpec::default()
            },
        }
    }

    /// Append an argument. The first one is `argv[0]`; without any, the
    /// program path is used.
    pub fn arg(mut self, arg: &str) -> Self {
        self.spec.args.push(arg.to_string());
        self
    }

    /// Append an environment variable (`"KEY=value"`). The process gets
    /// exactly the variables given here.
    pub fn env_var(mut self, var: &str) -> Self {
        self.spec.env.push(var.to_string());
        self
    }

    /// Set the working directory.
    pub fn cwd(mut self, dir: &str) -> Self {
        self.spec.cwd = Some(dir.to_string());
        self
    }

    pub fn uid(mut self, uid: u32) -> Self {
        self.spec.uid = Some(uid);
        self
    }

    pub fn gid(mut self, gid: u32) -> Self {
        self.spec.gid = Some(gid);
        self
    }

    /// Append a supplementary group.
    pub fn additional_gid(mut self, gid: u32) -> Self {
        self.spec.additional_gids.push(gid);
        self
    }

    pub fn umask(mut self, umask: u32) -> Self {
        self.spec.umask = Some(umask);
        self
    }

    /// Give the process a pseudo-terminal of this size instead of pipes.
    /// [`Controller::exec_tty`] sets this from the terminal it is given.
    pub fn window_size(mut self, rows: u16, cols: u16) -> Self {
        self.spec.tty = Some(WindowSize { rows, cols });
        self
    }
}

/// The control server of a running guest init. Each operation opens its own
/// connection, so one controller serves any number of processes.
pub struct Controller {
    socket_path: PathBuf,
    timeout: Duration,
}

fn dup(fd: BorrowedFd<'_>) -> Result<OwnedFd, ControlError> {
    fd.try_clone_to_owned()
        .map_err(|e| ControlError::Io(e.to_string().into()))
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl Controller {
    /// Reach the control server behind `socket_path`, the path given to
    /// [`Builder::control_socket`](crate::Builder::control_socket). Waits up
    /// to `timeout_ms` for the guest to start listening, and every later
    /// operation waits the same way.
    pub fn open(socket_path: &str, timeout_ms: u32) -> Result<Self, ControlError> {
        let controller = Self {
            socket_path: PathBuf::from(socket_path),
            timeout: Duration::from_millis(u64::from(timeout_ms)),
        };
        drop(controller.connect()?);
        Ok(controller)
    }

    /// Deliver `signal` to the guest's main workload.
    pub fn signal_entrypoint(&self, signal: i32) -> Result<(), ControlError> {
        Ok(self.connect()?.signal_entrypoint(signal)?)
    }

    /// Start `request` with its stdio connected to the given descriptors,
    /// which are duplicated. Pass no `stdin` to give the process an empty one.
    pub fn exec_pipes(
        &self,
        request: &ExecRequest,
        stdin: Option<BorrowedFd<'_>>,
        stdout: BorrowedFd<'_>,
        stderr: BorrowedFd<'_>,
    ) -> Result<Process, ControlError> {
        let io = SessionIo::Pipes {
            stdin: stdin.map(dup).transpose()?,
            stdout: dup(stdout)?,
            stderr: dup(stderr)?,
        };
        let mut spec = request.spec.clone();
        spec.tty = None;
        self.start(spec, io)
    }

    /// Start `request` on a pseudo-terminal mirroring `tty`: the guest pty
    /// gets the size of `tty`, which is switched to raw mode and relays the
    /// bytes both ways.
    pub fn exec_tty(
        &self,
        request: &ExecRequest,
        tty: BorrowedFd<'_>,
    ) -> Result<Process, ControlError> {
        let mut spec = request.spec.clone();
        spec.tty = Some(client::window_size(tty).unwrap_or_default());
        self.start(spec, SessionIo::Tty(dup(tty)?))
    }
}

impl Controller {
    fn connect(&self) -> Result<Connection, ControlError> {
        Ok(Connection::open(&self.socket_path, self.timeout)?)
    }

    fn start(&self, spec: ExecSpec, io: SessionIo) -> Result<Process, ControlError> {
        let session = self.connect()?.exec(&spec)?;
        Ok(Process {
            pid: session.pid(),
            session: Some((session, io)),
        })
    }
}

/// A process started in the guest. Its I/O is only relayed while
/// [`wait`](Self::wait) runs.
pub struct Process {
    pid: i32,
    session: Option<(Session, SessionIo)>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl Process {
    /// Pid of the process inside the guest.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Relay stdio until the process exits and return its exit code as a
    /// shell reports it (128 plus the signal number when it was killed).
    ///
    /// `signals`, if given, delivers signal numbers as single bytes, for
    /// example from a self-pipe written by the caller's signal handlers:
    /// `SIGWINCH` resizes the guest terminal, everything else is forwarded
    /// to the process.
    pub fn wait(&mut self, signals: Option<BorrowedFd<'_>>) -> Result<i32, ControlError> {
        let (session, io) = self.session.take().ok_or(ControlError::AlreadyWaited())?;
        let signals = signals.map(dup).transpose()?;
        Ok(session.run(io, signals)?.shell_code())
    }
}
