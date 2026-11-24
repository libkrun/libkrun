// SPDX-License-Identifier: Apache-2.0
//
//! Guest side of the control protocol: accept connections from the host on a
//! vsock port, spawn processes and relay their I/O, deliver signals.
//!
//! Processes are started through a short-lived helper child (double fork) so
//! that the server never has to reap them itself: init keeps its plain
//! `waitpid(-1)` loop, and the server works the same inside init and in
//! tests. The helper hands back a pidfd for the process, which keeps signal
//! delivery safe against pid reuse, and reports the wait status when the
//! process is gone.

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::control::{
    self, ExecSpec, ExitStatus, Failure, IO_CHUNK_LEN, PROTOCOL_VERSION, Request, Response,
    STDIN_WINDOW, WindowSize,
};

pub struct Server {
    listener: OwnedFd,
}

impl Server {
    /// Listen before the workload fork so early host connections queue.
    pub fn bind(port: u32) -> io::Result<Server> {
        let listener = vsock_listen(port)?;
        Ok(Server { listener })
    }

    /// Start accepting after the workload fork so init forks while
    /// single-threaded. Only the host CID is accepted.
    pub fn start(self, workload: i32) -> io::Result<()> {
        let workload = Arc::new(pidfd_open(workload)?);
        thread::Builder::new()
            .name("krun-control".into())
            .spawn(move || accept_loop(self.listener, workload))?;
        Ok(())
    }
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0 as libc::c_uint) as RawFd };
    if fd < 0 {
        return Err(last_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn vsock_listen(port: u32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(last_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    addr.svm_port = port;
    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(last_error());
    }
    if unsafe { libc::listen(fd.as_raw_fd(), 16) } < 0 {
        return Err(last_error());
    }
    Ok(fd)
}

fn accept_loop(listener: OwnedFd, workload: Arc<OwnedFd>) {
    loop {
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                ptr::null_mut(),
                ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = last_error();
            if matches!(
                err.raw_os_error(),
                Some(libc::EINTR) | Some(libc::ECONNABORTED)
            ) {
                continue;
            }
            eprintln!("krun-init: control server: accept: {err}");
            return;
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if !peer_is_host(&fd) {
            continue;
        }
        let workload = workload.clone();
        thread::spawn(move || {
            if let Err(e) = handle_connection(fd, Some(workload)) {
                eprintln!("krun-init: control server: {e}");
            }
        });
    }
}

fn peer_is_host(fd: &OwnedFd) -> bool {
    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
    let ret = unsafe {
        libc::getpeername(
            fd.as_raw_fd(),
            &mut addr as *mut libc::sockaddr_vm as *mut libc::sockaddr,
            &mut len,
        )
    };
    ret == 0
        && addr.svm_family == libc::AF_VSOCK as libc::sa_family_t
        && addr.svm_cid == libc::VMADDR_CID_HOST
}

/// Plain read/write on a borrowed descriptor, so the same code serves vsock
/// connections in the guest and Unix socket pairs in tests.
struct FdIo<'a>(BorrowedFd<'a>);

impl Read for FdIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = unsafe { libc::read(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = last_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

impl Write for FdIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let n = unsafe { libc::write(self.0.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = last_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn failure(errno: i32, what: &str) -> Failure {
    Failure {
        errno,
        message: format!("{what}: {}", io::Error::from_raw_os_error(errno)),
    }
}

/// Serve one connection until its request is complete.
pub fn handle_connection(sock: OwnedFd, workload: Option<Arc<OwnedFd>>) -> io::Result<()> {
    let sock = Arc::new(sock);
    let mut io = FdIo(sock.as_fd());

    match control::read::<Request>(&mut io)? {
        Request::Hello { version } if version == PROTOCOL_VERSION => {}
        Request::Hello { .. } => {
            let f = failure(libc::EPROTONOSUPPORT, "protocol version");
            return control::write(&mut io, &Response::Failed(f));
        }
        _ => return Err(invalid("expected hello")),
    }
    control::write(
        &mut io,
        &Response::Hello {
            version: PROTOCOL_VERSION,
        },
    )?;

    // Controller::open only checks that the guest answers, then hangs up.
    let request = match control::read::<Request>(&mut io) {
        Ok(request) => request,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e),
    };
    match request {
        Request::SignalEntrypoint { signal } => {
            let response = match workload {
                Some(pidfd) => match pidfd_send_signal(pidfd.as_fd(), signal) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Failed(io_failure(e, "signal workload")),
                },
                None => Response::Failed(failure(libc::ESRCH, "workload pid unknown")),
            };
            control::write(&mut io, &response)
        }
        Request::Exec(spec) => match spawn(&spec) {
            Ok(child) => start_relay(sock, child),
            Err(f) => control::write(&mut io, &Response::Failed(f)),
        },
        _ => Err(invalid("expected an exec or signal request")),
    }
}

fn start_relay(sock: Arc<OwnedFd>, mut child: Child) -> io::Result<()> {
    if let Err(e) = control::write(
        &mut FdIo(sock.as_fd()),
        &Response::Started { pid: child.pid },
    ) {
        hangup(&mut child.input, &child.pidfd);
        return Err(e);
    }
    relay(sock, child)
}

struct Child {
    pid: i32,
    pidfd: Arc<OwnedFd>,
    /// The helper writes the raw wait status here once the process is gone.
    status: OwnedFd,
    input: Input,
    stdout: Arc<OwnedFd>,
    stderr: Option<OwnedFd>,
}

enum Input {
    Pipe(Option<OwnedFd>),
    Pty(Arc<OwnedFd>),
    Closed,
}

impl Input {
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        match self {
            Input::Pipe(fd) => fd.as_ref().map(|fd| fd.as_fd()),
            Input::Pty(master) => Some(master.as_fd()),
            Input::Closed => None,
        }
    }

    fn eof(&mut self) {
        match self {
            Input::Pipe(fd) => *fd = None,
            Input::Pty(_) => *self = Input::Closed,
            Input::Closed => {}
        }
    }
}

/// Raw descriptors the process inherits; `stdin == stdout` for a pty slave.
struct ChildFds {
    stdin: RawFd,
    stdout: RawFd,
    stderr: RawFd,
    tty: bool,
}

struct Credentials {
    uid: Option<libc::uid_t>,
    gid: Option<libc::gid_t>,
    groups: Vec<libc::gid_t>,
    umask: Option<libc::mode_t>,
}

impl Credentials {
    fn switches_identity(&self) -> bool {
        self.uid.is_some() || self.gid.is_some() || !self.groups.is_empty()
    }
}

const STEP_CHDIR: u8 = 1;
const STEP_CREDENTIALS: u8 = 2;
const STEP_EXEC: u8 = 3;

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(last_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if ret < 0 {
        return Err(last_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn openpty(size: &WindowSize) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut master = -1;
    let mut slave = -1;
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            ptr::null_mut(),
            ptr::null(),
            &winsize,
        )
    };
    if ret < 0 {
        return Err(last_error());
    }
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    for fd in [&master, &slave] {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(last_error());
        }
    }
    Ok((master, slave))
}

fn set_nonblocking(fd: BorrowedFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(last_error());
    }
    Ok(())
}

fn cstring(s: &str, what: &'static str) -> Result<CString, Failure> {
    CString::new(s).map_err(|_| failure(libc::EINVAL, what))
}

fn io_failure(e: io::Error, what: &str) -> Failure {
    failure(e.raw_os_error().unwrap_or(libc::EIO), what)
}

fn spawn(spec: &ExecSpec) -> Result<Child, Failure> {
    if spec.uid == Some(u32::MAX) || spec.gid == Some(u32::MAX) {
        return Err(failure(libc::EINVAL, "uid or gid"));
    }
    let program = cstring(&spec.program, "program path")?;
    let args: Vec<CString> = if spec.args.is_empty() {
        vec![program.clone()]
    } else {
        spec.args
            .iter()
            .map(|a| cstring(a, "argument"))
            .collect::<Result<_, _>>()?
    };
    let env: Vec<CString> = spec
        .env
        .iter()
        .map(|e| cstring(e, "environment variable"))
        .collect::<Result<_, _>>()?;
    let cwd = spec
        .cwd
        .as_deref()
        .map(|d| cstring(d, "working directory"))
        .transpose()?;
    let argv: Vec<*const libc::c_char> = args
        .iter()
        .map(|s| s.as_ptr())
        .chain([ptr::null()])
        .collect();
    let envp: Vec<*const libc::c_char> = env
        .iter()
        .map(|s| s.as_ptr())
        .chain([ptr::null()])
        .collect();
    let credentials = Credentials {
        uid: spec.uid,
        gid: spec.gid,
        groups: spec.additional_gids.clone(),
        umask: spec.umask.map(|m| m as libc::mode_t),
    };

    let (exec_err_rx, exec_err_tx) = pipe().map_err(|e| io_failure(e, "pipe"))?;
    let (helper_sock, server_sock) = socketpair().map_err(|e| io_failure(e, "socketpair"))?;

    let (input, stdout, stderr, child_fds, child_only) = match &spec.tty {
        Some(size) => {
            let (master, slave) = openpty(size).map_err(|e| io_failure(e, "openpty"))?;
            let fds = ChildFds {
                stdin: slave.as_raw_fd(),
                stdout: slave.as_raw_fd(),
                stderr: slave.as_raw_fd(),
                tty: true,
            };
            let master = Arc::new(master);
            (Input::Pty(master.clone()), master, None, fds, vec![slave])
        }
        None => {
            let (in_r, in_w) = pipe().map_err(|e| io_failure(e, "pipe"))?;
            let (out_r, out_w) = pipe().map_err(|e| io_failure(e, "pipe"))?;
            let (err_r, err_w) = pipe().map_err(|e| io_failure(e, "pipe"))?;
            let fds = ChildFds {
                stdin: in_r.as_raw_fd(),
                stdout: out_w.as_raw_fd(),
                stderr: err_w.as_raw_fd(),
                tty: false,
            };
            (
                Input::Pipe(Some(in_w)),
                Arc::new(out_r),
                Some(err_r),
                fds,
                vec![in_r, out_w, err_w],
            )
        }
    };

    let helper = unsafe { libc::fork() };
    if helper < 0 {
        return Err(io_failure(last_error(), "fork"));
    }
    if helper == 0 {
        helper_main(
            helper_sock.as_raw_fd(),
            exec_err_tx.as_raw_fd(),
            &child_fds,
            cwd.as_deref(),
            &credentials,
            &program,
            argv.as_ptr(),
            envp.as_ptr(),
        );
    }
    drop(helper_sock);
    drop(exec_err_tx);
    drop(child_only);

    let (pidfd, pid) = recv_pidfd(&server_sock).map_err(|e| io_failure(e, "receive pidfd"))?;

    let mut report = [0u8; 5];
    if FdIo(exec_err_rx.as_fd()).read_exact(&mut report).is_ok() {
        let errno = i32::from_ne_bytes([report[1], report[2], report[3], report[4]]);
        let what = match report[0] {
            STEP_CHDIR => "chdir",
            STEP_CREDENTIALS => "set credentials",
            _ => "execve",
        };
        return Err(failure(errno, what));
    }

    if let Some(fd) = input.fd() {
        set_nonblocking(fd).map_err(|e| io_failure(e, "fcntl"))?;
    }

    Ok(Child {
        pid,
        pidfd: Arc::new(pidfd),
        status: server_sock,
        input,
        stdout,
        stderr,
    })
}

/// Runs in the forked helper: only async-signal-safe calls, no allocation.
#[allow(clippy::too_many_arguments)]
fn helper_main(
    sock: RawFd,
    exec_err_tx: RawFd,
    fds: &ChildFds,
    cwd: Option<&CStr>,
    credentials: &Credentials,
    program: &CStr,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> ! {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            libc::_exit(127);
        }
        if pid == 0 {
            child_main(fds, cwd, credentials, program, argv, envp, exec_err_tx);
        }

        // Nobody but this helper can reap the child yet, so the pid cannot be
        // reused before the pidfd exists.
        let pidfd = libc::syscall(libc::SYS_pidfd_open, pid, 0 as libc::c_uint) as RawFd;
        if pidfd < 0 || send_pidfd(sock, pidfd, pid) < 0 {
            libc::kill(pid, libc::SIGKILL);
            libc::_exit(127);
        }

        // Every other inherited descriptor would keep pipes of this or other
        // sessions open, so the server would never see their EOF.
        libc::syscall(
            libc::SYS_close_range,
            3 as libc::c_uint,
            (sock - 1) as libc::c_uint,
            0 as libc::c_uint,
        );
        libc::syscall(
            libc::SYS_close_range,
            (sock + 1) as libc::c_uint,
            libc::c_uint::MAX,
            0 as libc::c_uint,
        );

        let mut status: libc::c_int = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 {
            if *libc::__errno_location() != libc::EINTR {
                status = 0;
                break;
            }
        }
        let bytes = status.to_ne_bytes();
        libc::write(sock, bytes.as_ptr().cast(), bytes.len());
        libc::_exit(0)
    }
}

/// Runs in the grandchild between fork and exec: only async-signal-safe calls.
unsafe fn child_main(
    fds: &ChildFds,
    cwd: Option<&CStr>,
    credentials: &Credentials,
    program: &CStr,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    exec_err_tx: RawFd,
) -> ! {
    unsafe {
        if fds.tty {
            libc::setsid();
            libc::ioctl(fds.stdin, libc::TIOCSCTTY as _, 0);
        }
        libc::dup2(fds.stdin, libc::STDIN_FILENO);
        libc::dup2(fds.stdout, libc::STDOUT_FILENO);
        libc::dup2(fds.stderr, libc::STDERR_FILENO);

        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        let mut set: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, ptr::null_mut());

        if let Some(cwd) = cwd
            && libc::chdir(cwd.as_ptr()) < 0
        {
            child_fail(exec_err_tx, STEP_CHDIR);
        }
        if let Some(mask) = credentials.umask {
            libc::umask(mask);
        }
        // Switching identity needs CAP_SETGID/CAP_SETUID; a request without
        // credentials keeps the server's and must work unprivileged too.
        if credentials.switches_identity() {
            if libc::setgroups(credentials.groups.len(), credentials.groups.as_ptr()) < 0 {
                child_fail(exec_err_tx, STEP_CREDENTIALS);
            }
            if let Some(gid) = credentials.gid
                && libc::setresgid(gid, gid, gid) < 0
            {
                child_fail(exec_err_tx, STEP_CREDENTIALS);
            }
            if let Some(uid) = credentials.uid
                && libc::setresuid(uid, uid, uid) < 0
            {
                child_fail(exec_err_tx, STEP_CREDENTIALS);
            }
        }
        libc::execve(program.as_ptr(), argv, envp);
        child_fail(exec_err_tx, STEP_EXEC)
    }
}

unsafe fn child_fail(exec_err_tx: RawFd, step: u8) -> ! {
    unsafe {
        let errno = (*libc::__errno_location()).to_ne_bytes();
        let report = [step, errno[0], errno[1], errno[2], errno[3]];
        libc::write(exec_err_tx, report.as_ptr().cast(), report.len());
        libc::_exit(127)
    }
}

#[repr(C)]
struct PidfdControl {
    header: libc::cmsghdr,
    fd: RawFd,
}

/// Send `pidfd` with `pid` as payload over `sock` (async-signal-safe).
unsafe fn send_pidfd(sock: RawFd, pidfd: RawFd, pid: i32) -> isize {
    unsafe {
        let payload = pid.to_ne_bytes();
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut control: PidfdControl = mem::zeroed();
        control.header.cmsg_level = libc::SOL_SOCKET;
        control.header.cmsg_type = libc::SCM_RIGHTS;
        control.header.cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        control.fd = pidfd;
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (&mut control as *mut PidfdControl).cast();
        msg.msg_controllen = mem::size_of::<PidfdControl>() as _;
        libc::sendmsg(sock, &msg, 0)
    }
}

fn recv_pidfd(sock: &OwnedFd) -> io::Result<(OwnedFd, i32)> {
    let mut payload = [0u8; 4];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control: PidfdControl = unsafe { mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&mut control as *mut PidfdControl).cast();
    msg.msg_controllen = mem::size_of::<PidfdControl>() as _;

    let n = loop {
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n;
        }
        let err = last_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    };
    if n != payload.len() as isize {
        return Err(invalid("helper exited before starting the process"));
    }
    let expected_len = unsafe { libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) } as usize;
    if msg.msg_flags & libc::MSG_CTRUNC != 0
        || (msg.msg_controllen as usize) < expected_len
        || control.header.cmsg_len as usize != expected_len
        || control.header.cmsg_level != libc::SOL_SOCKET
        || control.header.cmsg_type != libc::SCM_RIGHTS
    {
        return Err(invalid("helper sent no pidfd"));
    }
    Ok((
        unsafe { OwnedFd::from_raw_fd(control.fd) },
        i32::from_ne_bytes(payload),
    ))
}

fn pidfd_send_signal(pidfd: BorrowedFd, signal: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            ptr::null::<libc::siginfo_t>(),
            0 as libc::c_uint,
        )
    };
    if ret < 0 {
        return Err(last_error());
    }
    Ok(())
}

fn poll(fds: &mut [libc::pollfd]) -> io::Result<()> {
    loop {
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if ret >= 0 {
            return Ok(());
        }
        let err = last_error();
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

fn hangup(input: &mut Input, pidfd: &OwnedFd) {
    input.eof();
    let _ = pidfd_send_signal(pidfd.as_fd(), libc::SIGHUP);
}

fn relay(sock: Arc<OwnedFd>, child: Child) -> io::Result<()> {
    let Child {
        pid: _,
        pidfd,
        status,
        input,
        stdout,
        stderr,
    } = child;

    let writer = Arc::new(Mutex::new(()));
    let reader = {
        let sock = sock.clone();
        let pidfd = pidfd.clone();
        let writer = writer.clone();
        thread::spawn(move || host_to_guest(&sock, input, &pidfd, &writer))
    };
    let result = guest_to_host(&sock, &stdout, stderr.as_ref(), &status, &writer);
    unsafe { libc::shutdown(sock.as_raw_fd(), libc::SHUT_RDWR) };
    let _ = reader.join();
    result
}

fn write_response(sock: &OwnedFd, writer: &Mutex<()>, response: &Response) -> io::Result<()> {
    let _guard = writer.lock().unwrap();
    control::write(&mut FdIo(sock.as_fd()), response)
}

/// Forward one read from `src`. Returns false once it has nothing more to deliver.
fn forward(
    sock: &OwnedFd,
    writer: &Mutex<()>,
    src: &OwnedFd,
    stderr: bool,
    buf: &mut [u8],
) -> io::Result<bool> {
    match FdIo(src.as_fd()).read(buf) {
        Ok(0) => Ok(false),
        Ok(n) => {
            let data = buf[..n].to_vec();
            let msg = if stderr {
                Response::Stderr(data)
            } else {
                Response::Stdout(data)
            };
            write_response(sock, writer, &msg)?;
            Ok(true)
        }
        Err(e) if e.raw_os_error() == Some(libc::EIO) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(true),
        Err(e) => Err(e),
    }
}

fn drain(
    sock: &OwnedFd,
    writer: &Mutex<()>,
    src: &OwnedFd,
    stderr: bool,
    buf: &mut [u8],
) -> io::Result<()> {
    set_nonblocking(src.as_fd())?;
    loop {
        match FdIo(src.as_fd()).read(buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                let data = buf[..n].to_vec();
                let msg = if stderr {
                    Response::Stderr(data)
                } else {
                    Response::Stdout(data)
                };
                write_response(sock, writer, &msg)?;
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::EIO) =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }
}

fn exit_status(wait_status: libc::c_int) -> ExitStatus {
    if libc::WIFEXITED(wait_status) {
        ExitStatus::Exited(libc::WEXITSTATUS(wait_status))
    } else if libc::WIFSIGNALED(wait_status) {
        ExitStatus::Signaled(libc::WTERMSIG(wait_status))
    } else {
        ExitStatus::Exited(125)
    }
}

fn guest_to_host(
    sock: &OwnedFd,
    stdout: &OwnedFd,
    stderr: Option<&OwnedFd>,
    status: &OwnedFd,
    writer: &Mutex<()>,
) -> io::Result<()> {
    let mut buf = vec![0u8; IO_CHUNK_LEN];
    let mut stdout_open = true;
    let mut stderr_open = stderr.is_some();

    loop {
        let mut fds = vec![pollfd(status.as_fd(), libc::POLLIN)];
        if stdout_open {
            fds.push(pollfd(stdout.as_fd(), libc::POLLIN));
        }
        if let (true, Some(stderr)) = (stderr_open, stderr) {
            fds.push(pollfd(stderr.as_fd(), libc::POLLIN));
        }
        poll(&mut fds)?;

        let mut idx = 1;
        if stdout_open {
            if fds[idx].revents & READABLE != 0 {
                stdout_open = forward(sock, writer, stdout, false, &mut buf)?;
            }
            idx += 1;
        }
        if let (true, Some(stderr)) = (stderr_open, stderr)
            && fds[idx].revents & READABLE != 0
        {
            stderr_open = forward(sock, writer, stderr, true, &mut buf)?;
        }

        if fds[0].revents & READABLE != 0 {
            let mut raw = [0u8; 4];
            let status = match FdIo(status.as_fd()).read_exact(&mut raw) {
                Ok(()) => exit_status(libc::c_int::from_ne_bytes(raw)),
                Err(_) => ExitStatus::Exited(125),
            };
            if stdout_open {
                drain(sock, writer, stdout, false, &mut buf)?;
            }
            if let (true, Some(stderr)) = (stderr_open, stderr) {
                drain(sock, writer, stderr, true, &mut buf)?;
            }
            return write_response(sock, writer, &Response::Exited(status));
        }
    }
}

fn host_to_guest(sock: &OwnedFd, mut input: Input, pidfd: &OwnedFd, writer: &Mutex<()>) {
    let mut pending: VecDeque<u8> = VecDeque::new();
    let mut stdin_eof = false;
    let mut stdin_eof_delivered = false;

    loop {
        if stdin_eof && pending.is_empty() && !stdin_eof_delivered {
            input.eof();
            stdin_eof_delivered = true;
        }
        if input.fd().is_none() {
            pending.clear();
        }
        // The host limits stdin by credit, so signals remain readable when
        // the process stops consuming stdin.
        let mut fds = Vec::with_capacity(2);
        fds.push(pollfd(sock.as_fd(), libc::POLLIN));
        if let (Some(fd), false) = (input.fd(), pending.is_empty()) {
            fds.push(pollfd(fd, libc::POLLOUT));
        }
        if poll(&mut fds).is_err() {
            hangup(&mut input, pidfd);
            return;
        }
        let sock_ready = fds[0].revents != 0;
        let input_ready = !pending.is_empty() && fds[fds.len() - 1].revents != 0;

        if input_ready {
            if fds[fds.len() - 1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                input.eof();
                pending.clear();
            } else {
                let written = input.fd().map(|fd| FdIo(fd).write(pending.as_slices().0));
                match written {
                    Some(Ok(n)) => {
                        drop(pending.drain(..n));
                        if write_response(sock, writer, &Response::StdinCredit(n as u32)).is_err() {
                            hangup(&mut input, pidfd);
                            return;
                        }
                    }
                    Some(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Some(Err(_)) => {
                        input.eof();
                        pending.clear();
                    }
                    None => {}
                }
            }
        }

        if !sock_ready {
            continue;
        }
        let request = match control::read::<Request>(&mut FdIo(sock.as_fd())) {
            Ok(request) => request,
            Err(_) => {
                hangup(&mut input, pidfd);
                return;
            }
        };
        match request {
            Request::Stdin(data) if !stdin_eof => {
                if pending.len() + data.len() > STDIN_WINDOW {
                    hangup(&mut input, pidfd);
                    return;
                }
                pending.extend(data);
            }
            Request::StdinEof if !stdin_eof => {
                stdin_eof = true;
                if matches!(input, Input::Pty(_)) {
                    pending.clear();
                    hangup(&mut input, pidfd);
                    stdin_eof_delivered = true;
                }
            }
            Request::Resize(size) => {
                if let Input::Pty(master) = &input {
                    let winsize = libc::winsize {
                        ws_row: size.rows,
                        ws_col: size.cols,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &winsize) };
                }
            }
            Request::Signal { signal } => {
                let _ = pidfd_send_signal(pidfd.as_fd(), signal);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Connection, Session, SessionIo};
    use crate::control::STDIN_WINDOW;
    use std::fs::File;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn connect(workload: Option<i32>) -> Connection {
        let (host, guest) = UnixStream::pair().unwrap();
        let workload = workload.map(|pid| Arc::new(pidfd_open(pid).unwrap()));
        thread::spawn(move || handle_connection(OwnedFd::from(guest), workload));
        Connection::from_stream(host).unwrap()
    }

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        pipe().unwrap()
    }

    fn read_all(fd: OwnedFd) -> Vec<u8> {
        let mut out = Vec::new();
        File::from(fd).read_to_end(&mut out).unwrap();
        out
    }

    fn sh(script: &str) -> ExecSpec {
        ExecSpec {
            program: "/bin/sh".into(),
            args: vec!["sh".into(), "-c".into(), script.into()],
            ..ExecSpec::default()
        }
    }

    /// Run `session` with piped stdio; returns (status, stdout, stderr).
    fn run_piped(session: Session, stdin: Option<OwnedFd>) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let (out_r, out_w) = pipe_pair();
        let (err_r, err_w) = pipe_pair();
        let status = session
            .run(
                SessionIo::Pipes {
                    stdin,
                    stdout: out_w,
                    stderr: err_w,
                },
                None,
            )
            .unwrap();
        (status, read_all(out_r), read_all(err_r))
    }

    #[test]
    fn exec_relays_output_env_cwd_and_exit_code() {
        let mut spec = sh("pwd; echo $FOO; echo err >&2; exit 7");
        spec.env = vec!["FOO=bar".into()];
        spec.cwd = Some("/tmp".into());
        let session = connect(None).exec(&spec).unwrap();
        let (status, out, err) = run_piped(session, None);
        assert_eq!(status, ExitStatus::Exited(7));
        assert_eq!(out, b"/tmp\nbar\n");
        assert_eq!(err, b"err\n");
    }

    #[test]
    fn exec_relays_all_output_to_nonblocking_pipe() {
        let session = connect(None).exec(&sh("printf '%131072s' x")).unwrap();
        let (out_r, out_w) = pipe_pair();
        set_nonblocking(out_w.as_fd()).unwrap();
        assert!(unsafe { libc::fcntl(out_w.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) } > 0);
        let reader = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            read_all(out_r)
        });
        let (_err_r, err_w) = pipe_pair();

        let status = session
            .run(
                SessionIo::Pipes {
                    stdin: None,
                    stdout: out_w,
                    stderr: err_w,
                },
                None,
            )
            .unwrap();
        let output = reader.join().unwrap();
        assert_eq!(status, ExitStatus::Exited(0));
        assert_eq!(output.len(), 131072);
        assert_eq!(output.last(), Some(&b'x'));
    }

    #[test]
    fn exec_forwards_stdin_until_eof() {
        let (in_r, in_w) = pipe_pair();
        FdIo(in_w.as_fd()).write_all(b"ping").unwrap();
        drop(in_w);
        let spec = ExecSpec {
            program: "/bin/cat".into(),
            ..ExecSpec::default()
        };
        let session = connect(None).exec(&spec).unwrap();
        let (status, out, _) = run_piped(session, Some(in_r));
        assert_eq!(status, ExitStatus::Exited(0));
        assert_eq!(out, b"ping");
    }

    #[test]
    fn exec_without_stdin_receives_eof() {
        let session = connect(None).exec(&sh("cat")).unwrap();
        let (sig_r, sig_w) = pipe_pair();
        let signaller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            let _ = FdIo(sig_w.as_fd()).write_all(&[libc::SIGTERM as u8]);
        });
        let (out_r, out_w) = pipe_pair();
        let (_err_r, err_w) = pipe_pair();
        let status = session
            .run(
                SessionIo::Pipes {
                    stdin: None,
                    stdout: out_w,
                    stderr: err_w,
                },
                Some(sig_r),
            )
            .unwrap();
        signaller.join().unwrap();
        assert_eq!(status, ExitStatus::Exited(0));
        assert!(read_all(out_r).is_empty());
    }

    #[test]
    fn tty_stdin_eof_hangs_up_child() {
        let (mut host, guest) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || handle_connection(OwnedFd::from(guest), None));

        control::write(
            &mut host,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .unwrap();
        assert!(matches!(
            control::read::<Response>(&mut host).unwrap(),
            Response::Hello { .. }
        ));

        let spec = ExecSpec {
            program: "/bin/cat".into(),
            tty: Some(WindowSize { rows: 24, cols: 80 }),
            ..ExecSpec::default()
        };
        control::write(&mut host, &Request::Exec(spec)).unwrap();
        assert!(matches!(
            control::read::<Response>(&mut host).unwrap(),
            Response::Started { .. }
        ));
        control::write(&mut host, &Request::StdinEof).unwrap();

        loop {
            let mut ready = pollfd(host.as_fd(), READABLE);
            assert_eq!(unsafe { libc::poll(&mut ready, 1, 5000) }, 1);
            match control::read::<Response>(&mut host).unwrap() {
                Response::Exited(status) => {
                    assert_eq!(status, ExitStatus::Signaled(libc::SIGHUP));
                    break;
                }
                Response::Stdout(_) | Response::Stderr(_) | Response::StdinCredit(_) => {}
                response => panic!("unexpected response: {response:?}"),
            }
        }

        drop(host);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn tty_stdin_eof_hangs_up_with_pending_input() {
        let mut workload = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pidfd = pidfd_open(workload.id() as i32).unwrap();
        let (master, _slave) = openpty(&WindowSize::default()).unwrap();
        set_nonblocking(master.as_fd()).unwrap();
        let (mut host, guest) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            host_to_guest(
                &OwnedFd::from(guest),
                Input::Pty(Arc::new(master)),
                &pidfd,
                &Mutex::new(()),
            );
        });

        control::write(&mut host, &Request::Stdin(vec![b'x'; STDIN_WINDOW / 2])).unwrap();
        control::write(&mut host, &Request::StdinEof).unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = workload.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = workload.kill();
                let _ = workload.wait();
                drop(host);
                server.join().unwrap();
                panic!("terminal EOF did not hang up the child");
            }
            thread::sleep(Duration::from_millis(10));
        };
        drop(host);
        server.join().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGHUP));
    }

    #[test]
    fn tty_write_error_stops_polling_input() {
        let mut workload = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pidfd = pidfd_open(workload.id() as i32).unwrap();
        let (master, slave) = openpty(&WindowSize::default()).unwrap();
        set_nonblocking(master.as_fd()).unwrap();
        drop(slave);
        let master = Arc::new(master);
        let weak = Arc::downgrade(&master);
        let (mut host, guest) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            host_to_guest(
                &OwnedFd::from(guest),
                Input::Pty(master),
                &pidfd,
                &Mutex::new(()),
            );
        });
        control::write(&mut host, &Request::Stdin(b"x".to_vec())).unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        while weak.upgrade().is_some() {
            if Instant::now() >= deadline {
                drop(host);
                server.join().unwrap();
                let _ = workload.kill();
                let _ = workload.wait();
                panic!("closed terminal input remained in the poll loop");
            }
            thread::sleep(Duration::from_millis(10));
        }
        drop(host);
        server.join().unwrap();
        workload.wait().unwrap();
    }

    #[test]
    fn exec_rejects_setresuid_and_setresgid_sentinels() {
        for (uid, gid) in [(Some(u32::MAX), None), (None, Some(u32::MAX))] {
            let spec = ExecSpec {
                uid,
                gid,
                ..sh("id -u")
            };
            match connect(None).exec(&spec) {
                Err(crate::client::ClientError::SpawnFailed(f)) => {
                    assert_eq!(f.errno, libc::EINVAL)
                }
                other => panic!("unexpected result: {other:?}"),
            }
        }
    }

    #[test]
    fn exec_rejects_stdin_beyond_credit_window() {
        let (mut host, guest) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || handle_connection(OwnedFd::from(guest), None));
        control::write(
            &mut host,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .unwrap();
        assert!(matches!(
            control::read::<Response>(&mut host).unwrap(),
            Response::Hello { .. }
        ));
        control::write(&mut host, &Request::Exec(sh("exec sleep 30"))).unwrap();
        assert!(matches!(
            control::read::<Response>(&mut host).unwrap(),
            Response::Started { .. }
        ));
        control::write(&mut host, &Request::Stdin(vec![b'x'; STDIN_WINDOW + 1])).unwrap();
        loop {
            match control::read::<Response>(&mut host).unwrap() {
                Response::Exited(status) => {
                    assert_eq!(status, ExitStatus::Signaled(libc::SIGHUP));
                    break;
                }
                Response::StdinCredit(_) => {}
                response => panic!("unexpected response: {response:?}"),
            }
        }
        drop(host);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn failed_started_response_hangs_up_process() {
        let child = spawn(&sh("exec sleep 30")).unwrap();
        let status = child.status.try_clone().unwrap();
        let (host, guest) = socketpair().unwrap();
        drop(host);

        let error = start_relay(Arc::new(guest), child).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
        let mut raw = [0u8; 4];
        FdIo(status.as_fd()).read_exact(&mut raw).unwrap();
        assert_eq!(
            exit_status(libc::c_int::from_ne_bytes(raw)),
            ExitStatus::Signaled(libc::SIGHUP)
        );
    }

    #[test]
    fn failed_stdin_credit_hangs_up_process() {
        let mut workload = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pidfd = pidfd_open(workload.id() as i32).unwrap();
        let (mut host, guest) = UnixStream::pair().unwrap();
        let (input_read, input_write) = pipe_pair();
        control::write(&mut host, &Request::Stdin(b"x".to_vec())).unwrap();
        drop(host);

        host_to_guest(
            &OwnedFd::from(guest),
            Input::Pipe(Some(input_write)),
            &pidfd,
            &Mutex::new(()),
        );
        drop(input_read);
        let status = workload.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGHUP));
    }

    #[test]
    fn exec_forwards_stdin_larger_than_window() {
        let (in_r, in_w) = pipe_pair();
        let writer = thread::spawn(move || File::from(in_w).write_all(&vec![b'x'; 1024 * 1024]));
        let session = connect(None).exec(&sh("wc -c")).unwrap();
        let (status, out, err) = run_piped(session, Some(in_r));
        writer.join().unwrap().unwrap();
        assert_eq!(status, ExitStatus::Exited(0));
        assert_eq!(out, b"1048576\n");
        assert!(err.is_empty());
    }

    #[test]
    fn exec_flushes_queued_stdin_before_eof() {
        let (mut host, guest) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || handle_connection(OwnedFd::from(guest), None));
        control::write(
            &mut host,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .unwrap();
        assert!(matches!(
            control::read::<Response>(&mut host).unwrap(),
            Response::Hello { .. }
        ));
        control::write(&mut host, &Request::Exec(sh("sleep 0.2; cat"))).unwrap();
        assert!(matches!(
            control::read::<Response>(&mut host).unwrap(),
            Response::Started { .. }
        ));

        let input = vec![b'x'; 128 * 1024];
        control::write(&mut host, &Request::Stdin(input.clone())).unwrap();
        control::write(&mut host, &Request::StdinEof).unwrap();

        let mut output = Vec::new();
        loop {
            match control::read::<Response>(&mut host).unwrap() {
                Response::Stdout(data) => output.extend(data),
                Response::StdinCredit(_) => {}
                Response::Exited(status) => {
                    assert_eq!(status, ExitStatus::Exited(0));
                    break;
                }
                response => panic!("unexpected response: {response:?}"),
            }
        }
        assert_eq!(output, input);
        drop(host);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn exec_reports_a_missing_executable() {
        let spec = ExecSpec {
            program: "/nonexistent/binary".into(),
            ..ExecSpec::default()
        };
        match connect(None).exec(&spec) {
            Err(crate::client::ClientError::ExecutableNotFound(f)) => {
                assert_eq!(f.errno, libc::ENOENT)
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn exec_forwards_signals_from_the_signal_fd() {
        let (sig_r, sig_w) = pipe_pair();
        FdIo(sig_w.as_fd())
            .write_all(&[libc::SIGTERM as u8])
            .unwrap();
        let spec = ExecSpec {
            program: "/bin/sleep".into(),
            args: vec!["sleep".into(), "30".into()],
            ..ExecSpec::default()
        };
        let session = connect(None).exec(&spec).unwrap();
        let (out_r, out_w) = pipe_pair();
        let (_err_r, err_w) = pipe_pair();
        let status = session
            .run(
                SessionIo::Pipes {
                    stdin: None,
                    stdout: out_w,
                    stderr: err_w,
                },
                Some(sig_r),
            )
            .unwrap();
        drop(out_r);
        assert_eq!(status, ExitStatus::Signaled(libc::SIGTERM));
    }

    #[test]
    fn exec_forwards_signal_while_stdin_is_blocked() {
        let session = connect(None).exec(&sh("exec sleep 3")).unwrap();
        let (in_r, in_w) = pipe_pair();
        let (filled_tx, filled_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            let mut input = File::from(in_w);
            let chunk = vec![b'x'; IO_CHUNK_LEN];
            let filled = (0..STDIN_WINDOW / IO_CHUNK_LEN).all(|_| input.write_all(&chunk).is_ok());
            filled_tx.send(filled).unwrap();
            if filled {
                let _ = input.write_all(&vec![b'x'; 1024 * 1024]);
            }
        });
        let (sig_r, sig_w) = pipe_pair();
        let signaller = thread::spawn(move || {
            assert!(filled_rx.recv_timeout(Duration::from_secs(2)).unwrap());
            thread::sleep(Duration::from_millis(100));
            FdIo(sig_w.as_fd())
                .write_all(&[libc::SIGTERM as u8])
                .unwrap();
        });
        let (out_r, out_w) = pipe_pair();
        let (err_r, err_w) = pipe_pair();
        let status = session
            .run(
                SessionIo::Pipes {
                    stdin: Some(in_r),
                    stdout: out_w,
                    stderr: err_w,
                },
                Some(sig_r),
            )
            .unwrap();
        writer.join().unwrap();
        signaller.join().unwrap();
        drop(out_r);
        drop(err_r);
        assert_eq!(status, ExitStatus::Signaled(libc::SIGTERM));
    }

    #[test]
    fn exec_on_a_tty_gets_the_requested_size() {
        let mut spec = sh("tty >/dev/null && stty size");
        spec.tty = Some(WindowSize { rows: 24, cols: 80 });
        let session = connect(None).exec(&spec).unwrap();
        let (master, slave) = openpty(&WindowSize { rows: 1, cols: 1 }).unwrap();
        let mut before: libc::termios = unsafe { mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut before) },
            0
        );
        let status = session.run(SessionIo::Tty(slave), None).unwrap();
        assert_eq!(status, ExitStatus::Exited(0));
        let mut after: libc::termios = unsafe { mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(master.as_raw_fd(), &mut after) },
            0
        );
        assert_eq!(after.c_iflag, before.c_iflag);
        assert_eq!(after.c_oflag, before.c_oflag);
        assert_eq!(after.c_cflag, before.c_cflag);
        assert_eq!(after.c_lflag, before.c_lflag);
        assert_eq!(after.c_cc, before.c_cc);
        let mut out = vec![0u8; 64];
        let n = FdIo(master.as_fd()).read(&mut out).unwrap();
        assert_eq!(String::from_utf8_lossy(&out[..n]).trim_end(), "24 80");
    }

    #[test]
    fn signal_entrypoint_targets_the_workload_pid() {
        let mut workload = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        connect(Some(workload.id() as i32))
            .signal_entrypoint(libc::SIGTERM)
            .unwrap();
        let status = workload.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn signal_entrypoint_rejects_exited_workload() {
        let mut workload = Command::new("/bin/true").spawn().unwrap();
        let pidfd = Arc::new(pidfd_open(workload.id() as i32).unwrap());
        assert!(workload.wait().unwrap().success());
        let (host, guest) = UnixStream::pair().unwrap();
        thread::spawn(move || handle_connection(OwnedFd::from(guest), Some(pidfd)));
        match Connection::from_stream(host)
            .unwrap()
            .signal_entrypoint(libc::SIGTERM)
        {
            Err(crate::client::ClientError::Rejected(f)) => assert_eq!(f.errno, libc::ESRCH),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn hanging_up_after_hello_is_not_an_error() {
        let (host, guest) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || handle_connection(OwnedFd::from(guest), None));
        drop(Connection::from_stream(host).unwrap());
        server.join().unwrap().unwrap();
    }

    #[test]
    fn signal_entrypoint_without_workload_is_rejected() {
        match connect(None).signal_entrypoint(libc::SIGTERM) {
            Err(crate::client::ClientError::Rejected(f)) => assert_eq!(f.errno, libc::ESRCH),
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
