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
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;

use crate::control::{
    self, ExecSpec, ExitStatus, Failure, IO_CHUNK_LEN, PROTOCOL_VERSION, Request, Response,
    WindowSize,
};

/// Stop reading host requests while this much stdin is waiting for the process.
const STDIN_HIGH_WATER: usize = 256 * 1024;

pub struct Server {
    workload: Arc<AtomicI32>,
}

impl Server {
    /// Bind `port` on the guest vsock and accept connections on a background
    /// thread. Only the host CID is accepted.
    pub fn start(port: u32) -> io::Result<Server> {
        let listener = vsock_listen(port)?;
        let workload = Arc::new(AtomicI32::new(0));
        let accepted = workload.clone();
        thread::Builder::new()
            .name("krun-control".into())
            .spawn(move || accept_loop(listener, accepted))?;
        Ok(Server { workload })
    }

    /// Tell the server which pid `SignalEntrypoint` requests should target.
    pub fn set_workload(&self, pid: i32) {
        self.workload.store(pid, Ordering::SeqCst);
    }
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
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

fn accept_loop(listener: OwnedFd, workload: Arc<AtomicI32>) {
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
            if let Err(e) = handle_connection(fd, workload) {
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
pub fn handle_connection(sock: OwnedFd, workload: Arc<AtomicI32>) -> io::Result<()> {
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
            let pid = workload.load(Ordering::SeqCst);
            let response = if pid <= 0 {
                Response::Failed(failure(libc::ESRCH, "workload pid unknown"))
            } else if unsafe { libc::kill(pid, signal) } < 0 {
                Response::Failed(failure(last_error().raw_os_error().unwrap_or(0), "kill"))
            } else {
                Response::Ok
            };
            control::write(&mut io, &response)
        }
        Request::Exec(spec) => match spawn(&spec) {
            Ok(child) => {
                control::write(&mut io, &Response::Started { pid: child.pid })?;
                relay(sock, child)
            }
            Err(f) => control::write(&mut io, &Response::Failed(f)),
        },
        _ => Err(invalid("expected an exec or signal request")),
    }
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
}

impl Input {
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        match self {
            Input::Pipe(fd) => fd.as_ref().map(|fd| fd.as_fd()),
            Input::Pty(master) => Some(master.as_fd()),
        }
    }

    fn eof(&mut self) {
        if let Input::Pipe(fd) = self {
            *fd = None;
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

/// Send `pidfd` with `pid` as payload over `sock` (async-signal-safe).
unsafe fn send_pidfd(sock: RawFd, pidfd: RawFd, pid: i32) -> isize {
    unsafe {
        let payload = pid.to_ne_bytes();
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut cmsg_buf = [0u8; 32];
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut RawFd, pidfd);
        libc::sendmsg(sock, &msg, 0)
    }
}

fn recv_pidfd(sock: &OwnedFd) -> io::Result<(OwnedFd, i32)> {
    let mut payload = [0u8; 4];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut cmsg_buf = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len() as _;

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
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null()
        || unsafe { (*cmsg).cmsg_level } != libc::SOL_SOCKET
        || unsafe { (*cmsg).cmsg_type } != libc::SCM_RIGHTS
    {
        return Err(invalid("helper sent no pidfd"));
    }
    let pidfd = unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd) };
    Ok((
        unsafe { OwnedFd::from_raw_fd(pidfd) },
        i32::from_ne_bytes(payload),
    ))
}

fn pidfd_send_signal(pidfd: BorrowedFd, signal: i32) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            ptr::null::<libc::siginfo_t>(),
            0 as libc::c_uint,
        );
    }
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

fn relay(sock: Arc<OwnedFd>, child: Child) -> io::Result<()> {
    let Child {
        pid: _,
        pidfd,
        status,
        input,
        stdout,
        stderr,
    } = child;

    let reader = {
        let sock = sock.clone();
        let pidfd = pidfd.clone();
        thread::spawn(move || host_to_guest(&sock, input, &pidfd))
    };
    let result = guest_to_host(&sock, &stdout, stderr.as_ref(), &status);
    unsafe { libc::shutdown(sock.as_raw_fd(), libc::SHUT_RDWR) };
    let _ = reader.join();
    result
}

/// Forward one read from `src`. Returns false once it has nothing more to deliver.
fn forward(sock: &OwnedFd, src: &OwnedFd, stderr: bool, buf: &mut [u8]) -> io::Result<bool> {
    match FdIo(src.as_fd()).read(buf) {
        Ok(0) => Ok(false),
        Ok(n) => {
            let data = buf[..n].to_vec();
            let msg = if stderr {
                Response::Stderr(data)
            } else {
                Response::Stdout(data)
            };
            control::write(&mut FdIo(sock.as_fd()), &msg)?;
            Ok(true)
        }
        Err(e) if e.raw_os_error() == Some(libc::EIO) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(true),
        Err(e) => Err(e),
    }
}

fn drain(sock: &OwnedFd, src: &OwnedFd, stderr: bool, buf: &mut [u8]) -> io::Result<()> {
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
                control::write(&mut FdIo(sock.as_fd()), &msg)?;
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
                stdout_open = forward(sock, stdout, false, &mut buf)?;
            }
            idx += 1;
        }
        if let (true, Some(stderr)) = (stderr_open, stderr)
            && fds[idx].revents & READABLE != 0
        {
            stderr_open = forward(sock, stderr, true, &mut buf)?;
        }

        if fds[0].revents & READABLE != 0 {
            let mut raw = [0u8; 4];
            let status = match FdIo(status.as_fd()).read_exact(&mut raw) {
                Ok(()) => exit_status(libc::c_int::from_ne_bytes(raw)),
                Err(_) => ExitStatus::Exited(125),
            };
            if stdout_open {
                drain(sock, stdout, false, &mut buf)?;
            }
            if let (true, Some(stderr)) = (stderr_open, stderr) {
                drain(sock, stderr, true, &mut buf)?;
            }
            return control::write(&mut FdIo(sock.as_fd()), &Response::Exited(status));
        }
    }
}

fn host_to_guest(sock: &OwnedFd, mut input: Input, pidfd: &OwnedFd) {
    let mut pending: VecDeque<u8> = VecDeque::new();

    loop {
        if input.fd().is_none() {
            pending.clear();
        }
        let want_requests = pending.len() < STDIN_HIGH_WATER;

        let mut fds = Vec::with_capacity(2);
        if want_requests {
            fds.push(pollfd(sock.as_fd(), libc::POLLIN));
        }
        if let (Some(fd), false) = (input.fd(), pending.is_empty()) {
            fds.push(pollfd(fd, libc::POLLOUT));
        }
        if poll(&mut fds).is_err() {
            return;
        }
        let sock_ready = want_requests && fds[0].revents != 0;
        let input_ready = !pending.is_empty() && fds[fds.len() - 1].revents != 0;

        if input_ready {
            let written = input.fd().map(|fd| FdIo(fd).write(pending.as_slices().0));
            match written {
                Some(Ok(n)) => drop(pending.drain(..n)),
                Some(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {}
                Some(Err(_)) => input.eof(),
                None => {}
            }
        }

        if !sock_ready {
            continue;
        }
        let request = match control::read::<Request>(&mut FdIo(sock.as_fd())) {
            Ok(request) => request,
            Err(_) => {
                // The host is gone: hang up on the process like a lost terminal.
                input.eof();
                pidfd_send_signal(pidfd.as_fd(), libc::SIGHUP);
                return;
            }
        };
        match request {
            Request::Stdin(data) => pending.extend(data),
            Request::StdinEof => input.eof(),
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
            Request::Signal { signal } => pidfd_send_signal(pidfd.as_fd(), signal),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Connection, Session, SessionIo};
    use std::fs::File;
    use std::os::unix::net::UnixStream;
    use std::process::Command;

    fn connect(workload: Option<i32>) -> Connection {
        let (host, guest) = UnixStream::pair().unwrap();
        let pid = Arc::new(AtomicI32::new(workload.unwrap_or(0)));
        thread::spawn(move || handle_connection(OwnedFd::from(guest), pid));
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
    fn exec_on_a_tty_gets_the_requested_size() {
        let mut spec = sh("tty >/dev/null && stty size");
        spec.tty = Some(WindowSize { rows: 24, cols: 80 });
        let session = connect(None).exec(&spec).unwrap();
        let (master, slave) = openpty(&WindowSize { rows: 1, cols: 1 }).unwrap();
        let status = session.run(SessionIo::Tty(slave), None).unwrap();
        assert_eq!(status, ExitStatus::Exited(0));
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
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGTERM)
        );
    }

    #[test]
    fn hanging_up_after_hello_is_not_an_error() {
        let (host, guest) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            handle_connection(OwnedFd::from(guest), Arc::new(AtomicI32::new(0)))
        });
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
