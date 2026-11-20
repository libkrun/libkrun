use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
use std::num::Wrapping;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(test, target_os = "macos"))]
use std::os::unix::fs::FileTypeExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use libc::EINVAL;
#[cfg(target_os = "macos")]
use libc::EINVAL;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, Backlog, MsgFlags, Shutdown, SockFlag, SockType, SockaddrLike, SockaddrStorage,
    accept, bind, connect, getpeername, getsockname, listen, recv, send, setsockopt, shutdown,
    socket, sockopt,
};

#[cfg(target_os = "macos")]
use super::super::super::linux_errno::linux_errno_raw;
use super::super::defs;
use super::super::muxer::{MuxerRx, push_packet, tsi_unix_path};
use super::super::packet::{TsiAcceptReq, TsiConnectReq, TsiGetnameRsp, TsiListenReq, VsockPacket};
use super::super::proxy::{
    NewProxyType, Proxy, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt,
};
use super::super::tsi_wire::ECONNREFUSED;
use utils::epoll::EventSet;

#[cfg(target_os = "linux")]
pub(super) struct PinnedUnixPath {
    parent: OwnedFd,
    name: CString,
    owned_identity: Option<(libc::dev_t, libc::ino_t)>,
}

#[cfg(target_os = "linux")]
impl PinnedUnixPath {
    fn from_addr(addr: &SockaddrStorage) -> Result<Option<Self>, Errno> {
        let Some(path) = tsi_unix_path(addr) else {
            return Ok(None);
        };
        let name = path.file_name().ok_or(Errno::EINVAL)?;
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = CString::new(name.as_bytes()).expect("TSI Unix path has no interior NUL");
        let parent =
            CString::new(parent.as_os_str().as_bytes()).expect("TSI Unix path has no interior NUL");
        let fd = unsafe {
            libc::open(
                parent.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Errno::last());
        }
        Ok(Some(Self {
            parent: unsafe { OwnedFd::from_raw_fd(fd) },
            name,
            owned_identity: None,
        }))
    }

    fn stat_at(&self, flags: libc::c_int) -> Result<Option<libc::stat>, Errno> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        if unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                &mut stat,
                flags,
            )
        } == 0
        {
            return Ok(Some(stat));
        }
        match Errno::last() {
            Errno::ENOENT => Ok(None),
            error => Err(error),
        }
    }

    fn remove_existing_socket(&self, protected: &[PathBuf]) -> Result<bool, Errno> {
        if !protected.is_empty() {
            let mut parent_stat: libc::stat = unsafe { mem::zeroed() };
            if unsafe { libc::fstat(self.parent.as_raw_fd(), &mut parent_stat) } < 0 {
                return Err(Errno::last());
            }
            for path in protected {
                if path
                    .file_name()
                    .is_some_and(|name| name.as_bytes() == self.name.as_bytes())
                {
                    let parent = path.parent().ok_or(Errno::EACCES)?;
                    let metadata = fs::metadata(parent).map_err(|_| Errno::EACCES)?;
                    if metadata.dev() == parent_stat.st_dev && metadata.ino() == parent_stat.st_ino
                    {
                        return Err(Errno::EACCES);
                    }
                }
            }
        }

        let Some(stat) = self.stat_at(0)? else {
            return Ok(false);
        };
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Ok(false);
        }
        if protected.iter().any(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.dev() == stat.st_dev && metadata.ino() == stat.st_ino
            })
        }) {
            return Err(Errno::EACCES);
        }
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) } < 0 {
            return Err(Errno::last());
        }
        Ok(true)
    }

    fn record_bound_socket(&mut self) {
        self.owned_identity = self
            .stat_at(libc::AT_SYMLINK_NOFOLLOW)
            .ok()
            .flatten()
            .filter(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFSOCK)
            .map(|stat| (stat.st_dev, stat.st_ino));
    }
}

#[cfg(target_os = "linux")]
impl Drop for PinnedUnixPath {
    fn drop(&mut self) {
        let Some(identity) = self.owned_identity else {
            return;
        };
        if self
            .stat_at(libc::AT_SYMLINK_NOFOLLOW)
            .ok()
            .flatten()
            .is_some_and(|stat| (stat.st_dev, stat.st_ino) == identity)
        {
            // The directory fd keeps a guest-controlled parent symlink from
            // redirecting this unlink to a host listener.
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

pub(crate) fn create_socket(
    _id: u64,
    linux_family: u16,
) -> Result<(OwnedFd, AddressFamily), ProxyError> {
    let family = match linux_family {
        defs::LINUX_AF_INET => AddressFamily::Inet,
        defs::LINUX_AF_INET6 => AddressFamily::Inet6,
        #[cfg(target_os = "linux")]
        defs::LINUX_AF_UNIX => AddressFamily::Unix,
        _ => return Err(ProxyError::InvalidFamily),
    };
    let fd = socket(family, SockType::Stream, SockFlag::empty(), None)
        .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;

    set_stream_socket_options(&fd).map_err(|e| ProxyError::CreatingSocket(e.into()))?;

    setsockopt(&fd, sockopt::ReuseAddr, &true)
        .map_err(|e| ProxyError::SettingReuseAddr(e.into()))?;

    Ok((fd, family))
}

fn try_listen(
    proxy: &mut super::TsiStreamProxy,
    req: &TsiListenReq,
    host_port_map: &Option<HashMap<u16, u16>>,
) -> i32 {
    if proxy.status == ProxyStatus::Listening || proxy.status == ProxyStatus::WaitingOnAccept {
        return 0;
    }

    let addr: SockaddrStorage = if let Some(port_map) = host_port_map {
        if let Some(sin) = req.addr.as_sockaddr_in() {
            debug!("sockaddr is ipv4");
            if let Some(port) = port_map.get(&sin.port()) {
                SocketAddrV4::new(sin.ip(), *port).into()
            } else {
                req.addr
            }
        } else if let Some(sin6) = req.addr.as_sockaddr_in6() {
            debug!("sockaddr is ipv6");
            if let Some(port) = port_map.get(&sin6.port()) {
                SocketAddrV6::new(sin6.ip(), *port, sin6.flowinfo(), sin6.flowinfo()).into()
            } else {
                req.addr
            }
        } else if req.addr.as_unix_addr().is_some() {
            debug!("sockaddr is unix");
            req.addr
        } else {
            return -libc::EINVAL;
        }
    } else {
        req.addr
    };

    #[cfg(target_os = "linux")]
    let mut unixsock_path = match PinnedUnixPath::from_addr(&addr) {
        Ok(path) => path,
        Err(e) => return -(e as i32),
    };
    #[cfg(target_os = "linux")]
    let removed_socket = if let Some(path) = &unixsock_path {
        match path.remove_existing_socket(&proxy.protected_unix_paths) {
            Ok(removed) => removed,
            Err(e) => return -(e as i32),
        }
    } else {
        false
    };

    #[cfg(target_os = "macos")]
    let unixsock_path = get_unixsock_path(&addr);
    #[cfg(target_os = "macos")]
    if let Some(path) = &unixsock_path
        && let Err(e) = fs::remove_file(path)
    {
        debug!("error removing socket: {e}");
    }

    match bind(proxy.fd.as_raw_fd(), &addr) {
        Ok(_) => {
            debug!("tcp bind: id={}", proxy.id);

            #[cfg(target_os = "linux")]
            if removed_socket && let Some(mut path) = unixsock_path.take() {
                path.record_bound_socket();
                proxy.unixsock_path = Some(path);
            }
            #[cfg(target_os = "macos")]
            {
                proxy.unixsock_path = unixsock_path;
            }

            // Clamp backlog to SOMAXCONN, mirroring Linux kernel's __sys_listen behavior.
            // The nix crate's Backlog::new() rejects values above SOMAXCONN with EINVAL.
            let clamped_backlog = req.backlog.clamp(0, libc::SOMAXCONN);
            match Backlog::new(clamped_backlog) {
                Ok(backlog) => match listen(&proxy.fd, backlog) {
                    Ok(_) => {
                        debug!("proxy: id={}", proxy.id);
                        0
                    }
                    Err(e) => {
                        warn!("proxy: id={} err={}", proxy.id, e);
                        #[cfg(target_os = "macos")]
                        let errno = -linux_errno_raw(e as i32);
                        #[cfg(target_os = "linux")]
                        let errno = -(e as i32);
                        errno
                    }
                },
                Err(e) => {
                    warn!("proxy: id={} err={}", proxy.id, e);
                    #[cfg(target_os = "macos")]
                    let errno = -linux_errno_raw(e as i32);
                    #[cfg(target_os = "linux")]
                    let errno = -(e as i32);
                    errno
                }
            }
        }
        Err(e) => {
            warn!("tcp bind: id={} err={}", proxy.id, e);
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(e as i32);
            #[cfg(target_os = "linux")]
            let errno = -(e as i32);
            errno
        }
    }
}

pub(crate) fn recv_to_pkt(
    proxy: &super::TsiStreamProxy,
    pkt: &mut VsockPacket,
) -> io::Result<RecvPkt> {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);

        debug!(
            "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
            proxy.peer_avail_credit(),
            buf.len(),
            max_len,
        );

        if max_len == 0 {
            return Ok(RecvPkt::WaitForCredit);
        }

        match recv(
            proxy.fd.as_raw_fd(),
            &mut buf[..max_len],
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(cnt) => {
                debug!("recv cnt={cnt}");
                if cnt > 0 {
                    debug!("recv rx_cnt={}", proxy.rx_cnt);
                    Ok(RecvPkt::Read(cnt))
                } else {
                    Ok(RecvPkt::Close)
                }
            }
            Err(Errno::EAGAIN | Errno::EINTR) => Ok(RecvPkt::Error),
            Err(e) => Err(e.into()),
        }
    } else {
        debug!("recv_pkt: pkt without buf");
        Ok(RecvPkt::BadBuffer)
    }
}

pub(crate) fn try_write(fd: &OwnedFd, buf: &[u8]) -> io::Result<usize> {
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::empty();
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_NOSIGNAL;
    send(fd.as_raw_fd(), buf, flags).map_err(|e| e.into())
}

pub(crate) fn is_retryable_write_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

pub(super) fn shutdown_write(fd: &OwnedFd) {
    if let Err(e) = shutdown(fd.as_raw_fd(), Shutdown::Write) {
        debug!("error sending shutdown(Write) to socket: {e}");
    }
}

pub(super) fn shutdown_read(fd: &OwnedFd) {
    if let Err(e) = shutdown(fd.as_raw_fd(), Shutdown::Read) {
        debug!("error sending shutdown(Read) to socket: {e}");
    }
}

fn set_stream_socket_options(fd: &OwnedFd) -> Result<(), Errno> {
    let flags = fcntl(fd, FcntlArg::F_GETFL)?;
    fcntl(
        fd,
        FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
    )?;
    #[cfg(target_os = "macos")]
    {
        // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
        let option_value: libc::c_int = 1;
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &option_value as *const _ as *const libc::c_void,
                mem::size_of_val(&option_value) as libc::socklen_t,
            )
        } < 0
        {
            return Err(Errno::last());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_connected_peer(fd: RawFd, protected_paths: &[PathBuf]) -> Result<(), Errno> {
    let peer: SockaddrStorage = getpeername(fd)?;
    if tsi_unix_path(&peer)
        .as_ref()
        .is_some_and(|path| protected_paths.contains(path))
    {
        return Err(Errno::EACCES);
    }
    Ok(())
}

fn finish_connect(proxy: &mut super::TsiStreamProxy) -> i32 {
    #[cfg(target_os = "linux")]
    if proxy.family == AddressFamily::Unix
        && !proxy.protected_unix_paths.is_empty()
        && let Err(e) = verify_connected_peer(proxy.fd.as_raw_fd(), &proxy.protected_unix_paths)
    {
        proxy.status = ProxyStatus::Closed;
        return -(e as i32);
    }
    // The host socket is connected, but the vsock transport is not
    // established until the guest sends OP_REQUEST; read polling starts in
    // `confirm_connect`.
    proxy.status = ProxyStatus::AwaitingRequest;
    0
}

fn get_addr_len(proxy: &super::TsiStreamProxy, addr: &SockaddrStorage) -> Option<u32> {
    let addr_len = match proxy.family {
        AddressFamily::Inet => addr.as_sockaddr_in()?.len(),
        AddressFamily::Inet6 => addr.as_sockaddr_in6()?.len(),
        AddressFamily::Unix => addr.as_unix_addr()?.len(),
        _ => 0,
    };

    Some(addr_len)
}

#[cfg(any(test, target_os = "macos"))]
fn get_unixsock_path(addr: &SockaddrStorage) -> Option<PathBuf> {
    let path = tsi_unix_path(addr)?;
    debug!("unix socket path={path:?}");

    match fs::metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => Some(path),
        Ok(_) => {
            debug!("unix socket path is NOT a socket");
            None
        }
        Err(e) => {
            debug!("metadata failed with {e}");
            None
        }
    }
}

pub(crate) fn do_connect(
    proxy: &mut super::TsiStreamProxy,
    _pkt: &VsockPacket,
    req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let result = match connect(proxy.fd.as_raw_fd(), &req.addr) {
        Ok(()) => {
            debug!("connect: Connected");
            finish_connect(proxy)
        }
        Err(nix::errno::Errno::EINPROGRESS) => {
            debug!("connect: Connecting");
            proxy.status = ProxyStatus::Connecting;
            0
        }
        Err(e) => {
            debug!("TcpProxy: Error connecting: {e}");
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(Errno::last_raw());
            #[cfg(target_os = "linux")]
            let errno = -Errno::last_raw();
            errno
        }
    };

    if proxy.status == ProxyStatus::Connecting {
        update.polling = Some((
            proxy.id,
            proxy.fd.as_raw_fd(),
            EventSet::OUT | EventSet::EDGE_TRIGGERED,
        ));
    } else {
        if proxy.status == ProxyStatus::Closed {
            update.remove_proxy = ProxyRemoval::Immediate;
        }
        proxy.push_connect_rsp(result);
    }

    update
}

#[cfg(all(test, target_os = "linux"))]
mod protected_path_tests {
    use super::super::{MuxerRxQ, TsiStreamProxy, VirtQueue};
    use super::*;
    use std::mem;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::slice::from_ref;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn guest_unix_addr(path: &[u8]) -> SockaddrStorage {
        let mut raw: libc::sockaddr_un = unsafe { mem::zeroed() };
        raw.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (dst, src) in raw.sun_path.iter_mut().zip(path) {
            *dst = *src as libc::c_char;
        }
        unsafe {
            SockaddrStorage::from_raw(
                &raw as *const libc::sockaddr_un as *const libc::sockaddr,
                Some(mem::size_of::<libc::sockaddr_un>() as libc::socklen_t),
            )
        }
        .unwrap()
    }

    #[test]
    fn existing_socket_lookup_stops_at_first_nul() {
        let prefix = format!("/tmp/krun-tsi-unlink-{}", std::process::id());
        let protected = PathBuf::from(format!("{prefix}X"));
        let listener = UnixListener::bind(&protected).unwrap();

        let normal = guest_unix_addr(protected.to_str().unwrap().as_bytes());
        let mut crafted_path = prefix.into_bytes();
        crafted_path.extend_from_slice(b"\0X");
        let crafted = guest_unix_addr(&crafted_path);
        let normal_result = get_unixsock_path(&normal);
        let crafted_result = get_unixsock_path(&crafted);
        let still_exists = protected.exists();

        drop(listener);
        fs::remove_file(&protected).unwrap();
        assert_eq!(normal_result, Some(protected));
        assert_eq!(crafted_result, None);
        assert!(still_exists);
    }

    #[test]
    fn listening_socket_cleanup_stays_in_pinned_directory() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = PathBuf::from(format!(
            "/tmp/krun-tsi-listen-{}-{nonce}",
            std::process::id()
        ));
        let benign_dir = root.join("benign");
        let protected_dir = root.join("protected");
        let alias = root.join("alias");
        let benign = benign_dir.join("control.sock");
        let protected = protected_dir.join("control.sock");
        fs::create_dir_all(&benign_dir).unwrap();
        fs::create_dir_all(&protected_dir).unwrap();
        let benign_listener = UnixListener::bind(&benign).unwrap();
        let protected_listener = UnixListener::bind(&protected).unwrap();
        symlink(&benign_dir, &alias).unwrap();

        let addr = guest_unix_addr(alias.join("control.sock").as_os_str().as_bytes());
        let mut path = PinnedUnixPath::from_addr(&addr).unwrap().unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(&protected_dir, &alias).unwrap();
        assert_eq!(path.remove_existing_socket(from_ref(&protected)), Ok(true));
        assert!(protected.exists());
        assert!(!benign.exists());

        drop(benign_listener);
        fs::remove_file(&alias).unwrap();
        symlink(&benign_dir, &alias).unwrap();
        let replacement = UnixListener::bind(&benign).unwrap();
        path.record_bound_socket();
        fs::remove_file(&alias).unwrap();
        symlink(&protected_dir, &alias).unwrap();
        drop(path);
        assert!(protected.exists());
        assert!(!benign.exists());
        let protected_path = PinnedUnixPath::from_addr(&addr).unwrap().unwrap();
        assert_eq!(
            protected_path.remove_existing_socket(from_ref(&protected)),
            Err(Errno::EACCES)
        );

        drop((replacement, protected_listener));
        fs::remove_file(alias).unwrap();
        fs::remove_file(protected).unwrap();
        fs::remove_dir(benign_dir).unwrap();
        fs::remove_dir(protected_dir).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn connected_peer_check_survives_symlink_swap() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let prefix = format!("/tmp/krun-tsi-peer-{}-{nonce}", std::process::id());
        let protected = PathBuf::from(format!("{prefix}-protected"));
        let unprotected = PathBuf::from(format!("{prefix}-unprotected"));
        let alias = PathBuf::from(format!("{prefix}-alias"));
        let protected_listener = UnixListener::bind(&protected).unwrap();
        let unprotected_listener = UnixListener::bind(&unprotected).unwrap();

        symlink(&unprotected, &alias).unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(&protected, &alias).unwrap();
        let protected_client = UnixStream::connect(&alias).unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(&unprotected, &alias).unwrap();
        let unprotected_client = UnixStream::connect(&alias).unwrap();

        assert_eq!(
            verify_connected_peer(protected_client.as_raw_fd(), from_ref(&protected)),
            Err(Errno::EACCES)
        );
        assert_eq!(
            verify_connected_peer(unprotected_client.as_raw_fd(), from_ref(&protected)),
            Ok(())
        );

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x3000)]).unwrap();
        let queue = Arc::new(Mutex::new(VirtQueue::new(256)));
        let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));
        let mut proxy = TsiStreamProxy::new(
            1,
            3,
            defs::LINUX_AF_UNIX,
            defs::TSI_PROXY_PORT,
            4000,
            4001,
            mem,
            queue,
            rxq.clone(),
        )
        .unwrap();
        proxy.fd = protected_client.into();
        proxy.protected_unix_paths = vec![protected.clone()];
        proxy.status = ProxyStatus::Connecting;
        let update = process_event(&mut proxy, EventSet::OUT);
        assert_eq!(proxy.status, ProxyStatus::Closed);
        assert!(matches!(update.remove_proxy, ProxyRemoval::Immediate));
        assert!(matches!(
            rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { result, .. }) if result == -libc::EACCES
        ));

        drop((proxy, unprotected_client));
        drop((protected_listener, unprotected_listener));
        fs::remove_file(alias).unwrap();
        fs::remove_file(protected).unwrap();
        fs::remove_file(unprotected).unwrap();
    }
}

pub(crate) fn do_getname(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket, peer: bool) {
    debug!("getpeername: id={}", proxy.id);

    let (result, addr_len, addr): (i32, u32, SockaddrStorage) = match if peer {
        getpeername(proxy.fd.as_raw_fd())
    } else {
        getsockname(proxy.fd.as_raw_fd())
    } {
        Ok(addr) => {
            if let Some(addr_len) = get_addr_len(proxy, &addr) {
                (0, addr_len, addr)
            } else {
                #[cfg(target_os = "macos")]
                let errno = -linux_errno_raw(EINVAL);
                #[cfg(target_os = "linux")]
                let errno = -EINVAL;
                (errno, 0, addr)
            }
        }
        Err(e) => {
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(e as i32);
            #[cfg(target_os = "linux")]
            let errno = -(e as i32);
            (
                errno,
                0,
                SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
            )
        }
    };

    let data = TsiGetnameRsp {
        result,
        addr_len,
        addr,
    };

    debug!("getpeername: reply={data:?}");

    // This response goes to the control port (DGRAM).
    let rx = MuxerRx::GetnameResponse {
        request_id: pkt.control_request_id(),
        operation: pkt.control_operation(),
        peer_port: pkt.src_port(),
        data,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn do_listen(
    proxy: &mut super::TsiStreamProxy,
    pkt: &VsockPacket,
    req: TsiListenReq,
    host_port_map: &Option<HashMap<u16, u16>>,
) -> ProxyUpdate {
    debug!(
        "listen: id={} addr={}, vm_port={} backlog={}",
        proxy.id, req.addr, req.vm_port, req.backlog
    );
    let mut update = ProxyUpdate::default();

    let result = try_listen(proxy, &req, host_port_map);

    // This packet goes to the control port (DGRAM).
    let rx = MuxerRx::ListenResponse {
        request_id: pkt.control_request_id(),
        operation: pkt.control_operation(),
        peer_port: pkt.src_port(),
        result,
        flags: req.response_flags(),
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    if result == 0 {
        proxy.peer_port = req.vm_port;
        proxy.status = ProxyStatus::Listening;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
    }

    update
}

pub(crate) fn do_accept(proxy: &mut super::TsiStreamProxy, req: TsiAcceptReq) -> ProxyUpdate {
    debug!("accept: id={} flags={}", req.peer_port, req.flags);

    let mut update = ProxyUpdate::default();

    if proxy.pending_accepts > 0 {
        proxy.pending_accepts -= 1;
        proxy.push_accept_rsp(0);
        update.signal_queue = true;
    } else {
        proxy.status = ProxyStatus::WaitingOnAccept;
    }

    update
}

pub(crate) fn update_peer_credit(
    proxy: &mut super::TsiStreamProxy,
    pkt: &VsockPacket,
) -> ProxyUpdate {
    debug!(
        "update_credit: buf_alloc={} rx_cnt={} fwd_cnt={}",
        pkt.buf_alloc(),
        proxy.rx_cnt,
        pkt.fwd_cnt()
    );
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    if proxy.status != ProxyStatus::WaitingCreditUpdate || proxy.peer_avail_credit() == 0 {
        return ProxyUpdate::default();
    }

    let previous = proxy.event_interest();
    proxy.status = ProxyStatus::Connected;
    ProxyUpdate {
        polling: proxy.polling_change(previous),
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::TsiStreamProxy, evset: EventSet) -> ProxyUpdate {
    if proxy.status == ProxyStatus::Connecting {
        let result = if evset.contains(EventSet::HANG_UP) {
            proxy.status = ProxyStatus::Closed;
            -ECONNREFUSED
        } else if evset.contains(EventSet::OUT) {
            finish_connect(proxy)
        } else {
            return ProxyUpdate::default();
        };
        proxy.push_connect_rsp(result);
        let remove_proxy =
            if proxy.status == ProxyStatus::Closed && !evset.contains(EventSet::HANG_UP) {
                ProxyRemoval::Immediate
            } else {
                ProxyRemoval::Keep
            };
        return ProxyUpdate {
            polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty())),
            signal_queue: true,
            remove_proxy,
            ..Default::default()
        };
    }

    if !matches!(
        proxy.status,
        ProxyStatus::Listening | ProxyStatus::WaitingOnAccept
    ) {
        return ProxyUpdate::default();
    }
    if evset.contains(EventSet::HANG_UP) {
        return proxy.reset_after_error();
    }
    if !evset.contains(EventSet::IN) {
        return ProxyUpdate::default();
    }

    let fd = match accept(proxy.fd.as_raw_fd()) {
        Ok(fd) => fd,
        Err(Errno::EAGAIN | Errno::EINTR) => return ProxyUpdate::default(),
        Err(e) => {
            warn!("error accepting connection: id={}, err={e}", proxy.id);
            return ProxyUpdate::default();
        }
    };
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if let Err(e) = set_stream_socket_options(&fd) {
        warn!("error setting up accepted socket: id={}, err={e}", proxy.id);
        return ProxyUpdate::default();
    }
    ProxyUpdate {
        new_proxy: Some((proxy.peer_port, fd, proxy.family, NewProxyType::Tcp)),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::getsockopt;
    use std::net::Ipv6Addr;

    fn bound_listener(family: u16, sharing: bool) -> (OwnedFd, SockaddrStorage) {
        let (fd, _) = create_socket(0, family).unwrap();
        if sharing {
            setsockopt(&fd, sockopt::ReusePort, &true).unwrap();
        }
        let addr: SockaddrStorage = if family == defs::LINUX_AF_INET {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into()
        };
        bind(fd.as_raw_fd(), &addr).unwrap();
        listen(&fd, Backlog::new(8).unwrap()).unwrap();
        let addr = getsockname(fd.as_raw_fd()).unwrap();
        (fd, addr)
    }

    #[test]
    fn default_tcp_reuse_options() {
        for family in [defs::LINUX_AF_INET, defs::LINUX_AF_INET6] {
            let (fd, _) = create_socket(0, family).unwrap();
            assert!(getsockopt(&fd, sockopt::ReuseAddr).unwrap());
            assert!(!getsockopt(&fd, sockopt::ReusePort).unwrap());
        }
    }

    #[test]
    fn default_tcp_listener_owns_address() {
        for family in [defs::LINUX_AF_INET, defs::LINUX_AF_INET6] {
            let (_first, addr) = bound_listener(family, false);
            let (second, _) = create_socket(1, family).unwrap();
            assert_eq!(bind(second.as_raw_fd(), &addr), Err(Errno::EADDRINUSE));
        }
    }

    #[test]
    fn explicit_reuseport_shares_listener() {
        for family in [defs::LINUX_AF_INET, defs::LINUX_AF_INET6] {
            let (_first, addr) = bound_listener(family, true);
            let (second, _) = create_socket(1, family).unwrap();
            setsockopt(&second, sockopt::ReusePort, &true).unwrap();
            bind(second.as_raw_fd(), &addr).unwrap();
            listen(&second, Backlog::new(8).unwrap()).unwrap();
        }
    }
}
