use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};

use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, AF_UNIX, FIONBIO, INVALID_SOCKET, IPPROTO_IPV6, IPV6_V6ONLY, SD_RECEIVE, SD_SEND,
    SOCK_STREAM, SOCKADDR, SOCKET, SOCKET_ERROR, WSAEINTR, WSAESHUTDOWN, WSAEWOULDBLOCK,
    WSAGetLastError, accept, bind, closesocket, connect, getpeername, getsockname, ioctlsocket,
    listen, recv, send, setsockopt, shutdown, socket,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo,
    FileDispositionInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
};
use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_AF_UNIX;

use crate::virtio::vsock::windows::sockaddr_storage::{
    SockaddrStorage, storage_to_winsock, winsock_to_storage,
};

use super::super::super::linux_errno::wsa_errno_to_linux;
use super::super::defs::uapi;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiAcceptReq, TsiConnectReq, TsiGetnameRsp, TsiListenReq, VsockPacket};
use super::super::proxy::{
    AddressFamily, AsRawFd, NewProxyType, OwnedFd, Proxy, ProxyError, ProxyStatus, ProxyUpdate,
    RecvPkt, address_family_from_linux,
};
use super::super::tsi_wire::{EADDRINUSE, EINVAL, EIO};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

pub(super) struct BoundUnixSocket(File);

impl BoundUnixSocket {
    fn open(path: &str) -> io::Result<Self> {
        // Keep the entry from being replaced while this listener owns it.
        let file = File::options()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileAttributeTagInfo,
                (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if tag.ReparseTag != IO_REPARSE_TAG_AF_UNIX {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self(file))
    }
}

impl Drop for BoundUnixSocket {
    fn drop(&mut self) {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                self.0.as_raw_handle(),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            debug!(
                "failed to remove closed UNIX socket: {}",
                io::Error::last_os_error()
            );
        }
    }
}

fn create_stream_socket(win_family: i32) -> Result<SOCKET, i32> {
    let sock = unsafe { socket(win_family, SOCK_STREAM, 0) };
    if sock == INVALID_SOCKET {
        return Err(unsafe { WSAGetLastError() });
    }
    let mut mode: u32 = 1;
    if unsafe { ioctlsocket(sock, FIONBIO, &mut mode) } == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        unsafe {
            closesocket(sock);
        }
        return Err(e);
    }
    // Linux guests expect dual-stack IPv6 sockets (bindv6only=0), but Winsock
    // defaults to v6-only.
    if win_family == AF_INET6 as i32
        && unsafe {
            setsockopt(
                sock,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (&0u32 as *const u32).cast(),
                size_of::<u32>() as i32,
            )
        } == SOCKET_ERROR
    {
        let e = unsafe { WSAGetLastError() };
        unsafe {
            closesocket(sock);
        }
        return Err(e);
    }
    Ok(sock)
}

pub(crate) fn create_socket(
    _id: u64,
    linux_family: u16,
) -> Result<(OwnedFd, AddressFamily), ProxyError> {
    let af = address_family_from_linux(linux_family).ok_or(ProxyError::InvalidFamily)?;
    let win_family = af as i32;
    let sock = create_stream_socket(win_family)
        .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e)))?;

    Ok((
        unsafe { OwnedSocket::from_raw_socket(sock as RawSocket) },
        af,
    ))
}

fn sock(proxy: &super::TsiStreamProxy) -> SOCKET {
    proxy.fd.as_raw_socket() as SOCKET
}

pub(crate) fn try_write(fd: &OwnedSocket, buf: &[u8]) -> io::Result<usize> {
    let sock = fd.as_raw_socket() as SOCKET;
    let mut written = 0;
    // A short successful send alone does not arrange another FD_WRITE wakeup.
    while written < buf.len() {
        let remaining = &buf[written..];
        let res = unsafe { send(sock, remaining.as_ptr() as _, remaining.len() as i32, 0) };
        if res == SOCKET_ERROR {
            let error = unsafe { WSAGetLastError() };
            if written > 0 && error == WSAEWOULDBLOCK {
                break;
            }
            return Err(io::Error::from_raw_os_error(error));
        }
        if res == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        written += res as usize;
    }
    Ok(written)
}

pub(crate) fn is_retryable_write_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(WSAEWOULDBLOCK)
}

pub(super) fn shutdown_write(fd: &OwnedSocket) {
    let res = unsafe { shutdown(fd.as_raw_socket() as SOCKET, SD_SEND) };
    if res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        debug!("error sending shutdown(SD_SEND) to socket: {e}");
    }
}

pub(super) fn shutdown_read(fd: &OwnedSocket) {
    let res = unsafe { shutdown(fd.as_raw_socket() as SOCKET, SD_RECEIVE) };
    if res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        debug!("error sending shutdown(SD_RECEIVE) to socket: {e}");
    }
}

pub(crate) fn recv_to_pkt(
    proxy: &super::TsiStreamProxy,
    pkt: &mut VsockPacket,
) -> io::Result<RecvPkt> {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);

        if max_len == 0 {
            return Ok(RecvPkt::WaitForCredit);
        }

        let res = unsafe { recv(sock(proxy), buf.as_mut_ptr() as _, max_len as i32, 0) };

        if res > 0 {
            Ok(RecvPkt::Read(res as usize))
        } else if res == 0 {
            Ok(RecvPkt::Close)
        } else {
            let err = unsafe { WSAGetLastError() };
            if err == WSAEWOULDBLOCK || err == WSAEINTR {
                Ok(RecvPkt::Error)
            } else if err == WSAESHUTDOWN
                && proxy.peer_shutdown & uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0
            {
                Ok(RecvPkt::Close)
            } else {
                Err(io::Error::from_raw_os_error(err))
            }
        }
    } else {
        Ok(RecvPkt::BadBuffer)
    }
}

fn listen_error(family: u16, strict: bool, error: i32) -> i32 {
    use super::super::defs::{LINUX_AF_INET, LINUX_AF_INET6};
    use super::super::tsi_wire::{EACCES, EPERM};
    use windows_sys::Win32::Networking::WinSock::WSAEACCES;

    // Best-effort publication can leave a guest-local listener when the
    // host denies publication. EPERM is the existing TSI fallback result.
    if error == WSAEACCES && matches!(family, LINUX_AF_INET | LINUX_AF_INET6) {
        if strict { -EACCES } else { -EPERM }
    } else {
        -wsa_errno_to_linux(error)
    }
}

#[cfg(test)]
mod publication_tests {
    use super::{listen_error, wsa_errno_to_linux};
    use crate::virtio::vsock::defs::{LINUX_AF_INET, LINUX_AF_INET6, LINUX_AF_UNIX};
    use crate::virtio::vsock::tsi_wire::{EACCES, EADDRINUSE, EPERM};
    use windows_sys::Win32::Networking::WinSock::{WSAEACCES, WSAEADDRINUSE};

    #[test]
    fn access_denied_is_a_fallback_result_only_for_best_effort_inet() {
        for family in [LINUX_AF_INET, LINUX_AF_INET6] {
            assert_eq!(listen_error(family, false, WSAEACCES), -EPERM);
            assert_eq!(listen_error(family, true, WSAEACCES), -EACCES);
            assert_eq!(listen_error(family, false, WSAEADDRINUSE), -EADDRINUSE);
        }
        assert_eq!(
            listen_error(LINUX_AF_UNIX, false, WSAEACCES),
            -wsa_errno_to_linux(WSAEACCES)
        );
    }
}

fn try_listen(
    proxy: &mut super::TsiStreamProxy,
    req: &TsiListenReq,
    host_port_map: &Option<HashMap<u16, u16>>,
) -> i32 {
    try_listen_with(proxy, req, host_port_map, BoundUnixSocket::open)
}

fn try_listen_with(
    proxy: &mut super::TsiStreamProxy,
    req: &TsiListenReq,
    host_port_map: &Option<HashMap<u16, u16>>,
    pin: impl Fn(&str) -> io::Result<BoundUnixSocket>,
) -> i32 {
    if proxy.status == ProxyStatus::Listening || proxy.status == ProxyStatus::WaitingOnAccept {
        return 0;
    }

    let effective_addr: SockaddrStorage = if let Some(port_map) = host_port_map {
        if let Some(v4) = req.addr.to_std_v4() {
            if let Some(&mapped_port) = port_map.get(&v4.port()) {
                SocketAddrV4::new(*v4.ip(), mapped_port).into()
            } else {
                req.addr.clone()
            }
        } else if let Some(v6) = req.addr.to_std_v6() {
            // Port overrides apply to IPv6 listeners too; without this a
            // guest dual-stack listener publishes its IPv6 socket on the
            // unmapped host port.
            if let Some(&mapped_port) = port_map.get(&v6.port()) {
                SocketAddrV6::new(*v6.ip(), mapped_port, v6.flowinfo(), v6.scope_id()).into()
            } else {
                req.addr.clone()
            }
        } else {
            req.addr.clone()
        }
    } else {
        req.addr.clone()
    };

    let Some((sa_bytes, sa_len)) = storage_to_winsock(&effective_addr) else {
        return -EINVAL;
    };

    // Winsock cannot distinguish an abandoned path from a socket that is
    // bound but has yet to listen. Keep existing entries intact.
    let bind_res = unsafe { bind(sock(proxy), sa_bytes.as_ptr() as *const SOCKADDR, sa_len) };
    if bind_res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        warn!(
            "bind failed: id={} addr={:?} err={e}",
            proxy.id, effective_addr
        );
        return listen_error(req.addr.family(), req.strict, e);
    }

    if let Some(path) = effective_addr.unix_path().filter(|path| !path.is_empty()) {
        match pin(path) {
            Ok(socket_file) => proxy.bound_unix_socket = Some(socket_file),
            Err(e) => {
                // Closing the bound socket does not remove its entry, and
                // without the pin the entry can no longer be proven ours,
                // so the path stays behind as an abandoned socket. Replace
                // the socket so the proxy can still listen elsewhere, and
                // report the path as taken.
                warn!("cannot pin bound UNIX socket path for cleanup: {e}");
                if let Ok(sock) = create_stream_socket(AF_UNIX as i32) {
                    proxy.fd = unsafe { OwnedSocket::from_raw_socket(sock as RawSocket) };
                }
                return -EADDRINUSE;
            }
        }
    }

    // Fixed: Constrain the network queue size utilizing the configuration parameters sent by the guest
    let clamped_backlog = req.backlog.clamp(0, 0x7fff_ffff);
    let listen_res = unsafe { listen(sock(proxy), clamped_backlog) };
    if listen_res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        warn!("listen failed: id={} err={e}", proxy.id);
        return listen_error(req.addr.family(), req.strict, e);
    }

    0
}

pub(crate) fn do_connect(
    proxy: &mut super::TsiStreamProxy,
    _pkt: &VsockPacket,
    req: TsiConnectReq,
    epoll: &Epoll,
) -> ProxyUpdate {
    let (sa_bytes, sa_len) = match storage_to_winsock(&req.addr) {
        Some(v) => v,
        None => {
            proxy.push_connect_rsp(-22); // EINVAL
            return ProxyUpdate::default();
        }
    };

    // Register first so a fast completion cannot race the FD_CONNECT watch.
    let event = EpollEvent::new(EventSet::CONNECT | EventSet::EDGE_TRIGGERED, proxy.id);
    if let Err(error) = epoll.ctl_socket(ControlOperation::Add, sock(proxy), &event) {
        warn!(
            "could not watch connect completion: id={} err={error}",
            proxy.id
        );
        proxy.push_connect_rsp(-EIO);
        return ProxyUpdate::default();
    }

    let res = unsafe { connect(sock(proxy), sa_bytes.as_ptr() as *const SOCKADDR, sa_len) };

    let result = if res == 0 {
        proxy.status = ProxyStatus::AwaitingRequest;
        0
    } else {
        let e = unsafe { WSAGetLastError() };
        if e == WSAEWOULDBLOCK {
            proxy.status = ProxyStatus::Connecting;
            return ProxyUpdate::default();
        }
        debug!("connect error: id={} err={e}", proxy.id);
        -wsa_errno_to_linux(e)
    };

    proxy.push_connect_rsp(result);
    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty())),
        ..Default::default()
    }
}

pub(super) fn finish_connect(proxy: &mut super::TsiStreamProxy, error: i32) -> ProxyUpdate {
    debug!("FD_CONNECT completed: id={} err={error}", proxy.id);
    let result = if error == 0 {
        proxy.status = ProxyStatus::AwaitingRequest;
        0
    } else {
        proxy.status = ProxyStatus::Closed;
        -wsa_errno_to_linux(error)
    };
    proxy.push_connect_rsp(result);
    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty())),
        signal_queue: true,
        ..Default::default()
    }
}

pub(crate) fn do_getname(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket, peer: bool) {
    let mut sa_buf = [0u8; 128];
    let mut sa_len: i32 = 128;

    let res = unsafe {
        if peer {
            getpeername(sock(proxy), sa_buf.as_mut_ptr().cast(), &mut sa_len)
        } else {
            getsockname(sock(proxy), sa_buf.as_mut_ptr().cast(), &mut sa_len)
        }
    };

    let (result, addr_len, addr) = if res == 0 {
        match winsock_to_storage(&sa_buf, sa_len) {
            Some(storage) => {
                let len = storage.len();
                (0i32, len, storage)
            }
            None => (
                -22i32,
                0,
                SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
            ),
        }
    } else {
        let e = unsafe { WSAGetLastError() };
        (
            -wsa_errno_to_linux(e),
            0,
            SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
        )
    };

    let data = TsiGetnameRsp {
        result,
        addr_len,
        addr,
    };
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
    let mut update = ProxyUpdate::default();

    let result = try_listen(proxy, &req, host_port_map);

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

pub(crate) fn process_event(proxy: &mut super::TsiStreamProxy, evset: EventSet) -> ProxyUpdate {
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

    let socket = unsafe { accept(sock(proxy), std::ptr::null_mut(), std::ptr::null_mut()) };
    if socket == INVALID_SOCKET {
        let e = unsafe { WSAGetLastError() };
        if e != WSAEWOULDBLOCK {
            warn!("accept error: id={} err={e}", proxy.id);
        }
        return ProxyUpdate::default();
    }
    let fd = unsafe { OwnedSocket::from_raw_socket(socket as RawSocket) };
    let mut mode = 1;
    if unsafe { ioctlsocket(socket, FIONBIO, &mut mode) } == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
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
    use crate::virtio::Queue;
    use crate::virtio::vsock::defs::{LINUX_AF_UNIX, TSI_CONTROL_PORT, TSI_PROXY_PORT};
    use crate::virtio::vsock::muxer_rxq::MuxerRxQ;
    use crate::virtio::vsock::tsi_stream::TsiStreamProxy;
    use crate::virtio::vsock::tsi_wire::EADDRINUSE;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use utils::epoll::Epoll;
    use vm_memory::{GuestAddress, GuestMemoryMmap};
    use windows_sys::Win32::Networking::WinSock::AF_UNIX;

    struct TestPath {
        dir: PathBuf,
        socket: PathBuf,
    }

    impl TestPath {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("krun-{:08x}", rand::random::<u32>()));
            fs::create_dir(&dir).unwrap();
            let socket = dir.join("s");
            Self { dir, socket }
        }

        fn request(&self) -> TsiListenReq {
            let mut bytes = LINUX_AF_UNIX.to_le_bytes().to_vec();
            bytes.extend_from_slice(self.socket.to_str().unwrap().as_bytes());
            bytes.push(0);
            TsiListenReq {
                peer_port: 4000,
                vm_port: 4001,
                backlog: 1,
                addr: SockaddrStorage::from_linux_bytes(&bytes, bytes.len() as u32).unwrap(),
                strict: true,
            }
        }
    }

    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.socket);
            let _ = fs::remove_dir(&self.dir);
        }
    }

    fn proxy(req: &TsiListenReq) -> TsiStreamProxy {
        TsiStreamProxy::new(
            1,
            3,
            LINUX_AF_UNIX,
            TSI_PROXY_PORT,
            req.peer_port,
            TSI_CONTROL_PORT,
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap(),
            Arc::new(Mutex::new(Queue::new(8))),
            Arc::new(Mutex::new(MuxerRxQ::new())),
        )
        .unwrap()
    }

    fn unix_socket() -> OwnedSocket {
        let fd = unsafe { socket(AF_UNIX as i32, SOCK_STREAM, 0) };
        assert_ne!(fd, INVALID_SOCKET, "Winsock error {}", unsafe {
            WSAGetLastError()
        });
        unsafe { OwnedSocket::from_raw_socket(fd as RawSocket) }
    }

    fn assert_connects(req: &TsiListenReq) {
        let client = unix_socket();
        let (addr, len) = storage_to_winsock(&req.addr).unwrap();
        let result =
            unsafe { connect(client.as_raw_socket() as SOCKET, addr.as_ptr().cast(), len) };
        assert_eq!(result, 0, "Winsock error {}", unsafe { WSAGetLastError() });
    }

    #[test]
    fn unix_listen_preserves_regular_file() {
        let _epoll = Epoll::new().unwrap();
        let path = TestPath::new();
        let req = path.request();
        fs::write(&path.socket, b"sentinel").unwrap();

        assert_eq!(try_listen(&mut proxy(&req), &req, &None), -EADDRINUSE);
        assert_eq!(fs::read(&path.socket).unwrap(), b"sentinel");
    }

    #[test]
    fn unix_listen_preserves_existing_socket() {
        let _epoll = Epoll::new().unwrap();
        let path = TestPath::new();
        let req = path.request();
        let listener = unix_socket();
        let fd = listener.as_raw_socket() as SOCKET;
        let (addr, len) = storage_to_winsock(&req.addr).unwrap();
        assert_eq!(unsafe { bind(fd, addr.as_ptr().cast(), len) }, 0);

        assert_eq!(try_listen(&mut proxy(&req), &req, &None), -EADDRINUSE);
        assert_eq!(unsafe { listen(fd, req.backlog) }, 0);
        assert_eq!(try_listen(&mut proxy(&req), &req, &None), -EADDRINUSE);
        assert_connects(&req);

        drop(listener);
        assert_eq!(try_listen(&mut proxy(&req), &req, &None), -EADDRINUSE);
        assert!(fs::symlink_metadata(&path.socket).is_ok());
    }

    #[test]
    fn unix_listener_removes_its_socket_on_close() {
        let _epoll = Epoll::new().unwrap();
        let path = TestPath::new();
        let req = path.request();
        let mut listener = proxy(&req);
        assert_eq!(try_listen(&mut listener, &req, &None), 0);
        assert_connects(&req);

        drop(listener);
        assert_eq!(
            fs::symlink_metadata(&path.socket).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(try_listen(&mut proxy(&req), &req, &None), 0);
    }

    #[test]
    fn unix_listen_pin_failure_leaves_an_abandoned_path() {
        let _epoll = Epoll::new().unwrap();
        let path = TestPath::new();
        let req = path.request();
        let mut listener = proxy(&req);

        let result = try_listen_with(&mut listener, &req, &None, |_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });
        assert_eq!(result, -EADDRINUSE);
        assert!(listener.bound_unix_socket.is_none());

        // Without the pin, closing the bound socket leaves its entry
        // behind, so the path stays taken like any abandoned socket.
        assert_eq!(try_listen(&mut listener, &req, &None), -EADDRINUSE);
        assert!(fs::symlink_metadata(&path.socket).is_ok());

        // The socket was replaced, so the proxy can listen on another path.
        let other = TestPath::new();
        let other_req = other.request();
        assert_eq!(try_listen(&mut listener, &other_req, &None), 0);
        assert_connects(&other_req);
    }
}
