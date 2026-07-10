use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
use std::num::Wrapping;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(target_os = "linux")]
use libc::EINVAL;
#[cfg(target_os = "macos")]
use libc::EINVAL;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, Backlog, MsgFlags, Shutdown, SockFlag, SockType, SockaddrLike, SockaddrStorage,
    accept, bind, connect, getpeername, listen, recv, send, setsockopt, shutdown, socket, sockopt,
};

#[cfg(target_os = "macos")]
use super::super::super::linux_errno::linux_errno_raw;
use super::super::defs;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiAcceptReq, TsiConnectReq, TsiGetnameRsp, TsiListenReq, VsockPacket};
use super::super::proxy::{
    NewProxyType, Proxy, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt,
};
use utils::epoll::EventSet;

pub(crate) fn create_socket(
    id: u64,
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

    // macOS forces us to do this here instead of just using SockFlag::SOCK_NONBLOCK above.
    match fcntl(&fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!("error switching to non-blocking: id={id}, err={e}");
                }
            }
            None => error!("invalid fd flags id={id}"),
        },
        Err(e) => error!("couldn't obtain fd flags id={id}, err={e}"),
    };

    if family == AddressFamily::Unix {
        setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(|e| {
            ProxyError::SettingReuseAddr(std::io::Error::from_raw_os_error(e as i32))
        })?;
    } else {
        setsockopt(&fd, sockopt::ReusePort, &true).map_err(|e| {
            ProxyError::SettingReusePort(std::io::Error::from_raw_os_error(e as i32))
        })?;
    }

    #[cfg(target_os = "macos")]
    {
        // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
        let option_value: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &option_value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&option_value) as libc::socklen_t,
            )
        };
    }

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

    let unixsock_path = get_unixsock_path(proxy, &addr);
    // If the userspace process in the guest has already created the socket,
    // we need to unlink it to take ownership of the node in the filesystem.
    if let Some(path) = &unixsock_path
        && let Err(e) = fs::remove_file(path)
    {
        debug!("error removing socket: {e}");
    }

    match bind(proxy.fd.as_raw_fd(), &addr) {
        Ok(_) => {
            debug!("tcp bind: id={}", proxy.id);

            // For unix sockets we need to unlink the path on Drop, since
            // it's possible the userspace application can't do it itself.
            proxy.unixsock_path = unixsock_path;

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

pub(crate) fn recv_to_pkt(proxy: &super::TsiStreamProxy, pkt: &mut VsockPacket) -> RecvPkt {
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
            return RecvPkt::WaitForCredit;
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
                    RecvPkt::Read(cnt)
                } else {
                    RecvPkt::Close
                }
            }
            Err(e) => {
                debug!("recv_pkt: recv error: {e:?}");
                RecvPkt::Error
            }
        }
    } else {
        debug!("recv_pkt: pkt without buf");
        RecvPkt::Error
    }
}

pub(crate) fn switch_to_connected(proxy: &mut super::TsiStreamProxy) {
    proxy.status = ProxyStatus::Connected;
    match fcntl(&proxy.fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&proxy.fd, FcntlArg::F_SETFL(flags & !OFlag::O_NONBLOCK)) {
                    warn!("error switching to blocking: id={}, err={}", proxy.id, e);
                }
            }
            None => error!("invalid fd flags id={}", proxy.id),
        },
        Err(e) => error!("couldn't obtain fd flags id={}, err={}", proxy.id, e),
    };
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

fn get_unixsock_path(_proxy: &super::TsiStreamProxy, addr: &SockaddrStorage) -> Option<PathBuf> {
    if let Some(addr) = addr.as_unix_addr()
        && let Some(path) = addr.path()
    {
        // SockaddrStorage doesn't clean up NULLs. This is fine when
        // using addr with other nix methods, but we need to clean them
        // up to be able to treat it as a path with other Rust crates.
        let path_str = path.to_str()?.replace("\0", "");
        debug!("unix socket path_str={path_str}");

        match fs::metadata(&path_str) {
            Ok(metadata) => {
                if metadata.file_type().is_socket() {
                    debug!("unix socket path is socket");
                    return PathBuf::from_str(&path_str).ok();
                } else {
                    debug!("unix socket path is NOT a socket");
                }
            }
            Err(e) => debug!("metadata failed with {e}"),
        }
    }

    None
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
            switch_to_connected(proxy);
            0
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
        if proxy.status == ProxyStatus::Connected {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        }
        proxy.push_connect_rsp(result);
    }

    update
}

pub(crate) fn do_getpeername(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket) {
    debug!("getpeername: id={}", proxy.id);

    let (result, addr_len, addr): (i32, u32, SockaddrStorage) =
        match getpeername(proxy.fd.as_raw_fd()) {
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
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        data,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn sendmsg(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket) -> ProxyUpdate {
    debug!("sendmsg");

    let mut update = ProxyUpdate::default();

    let ret = if let Some(buf) = pkt.buf() {
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::empty();
        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_NOSIGNAL;

        match send(proxy.fd.as_raw_fd(), buf, flags) {
            Ok(sent) => {
                if sent != buf.len() {
                    error!("couldn't set everything: buf={}, sent={}", buf.len(), sent);
                }
                proxy.tx_cnt += Wrapping(sent as u32);
                sent as i32
            }
            Err(err) => {
                #[cfg(target_os = "macos")]
                let errno = -linux_errno_raw(err as i32);
                #[cfg(target_os = "linux")]
                let errno = -(err as i32);
                errno
            }
        }
    } else {
        -libc::EINVAL
    };

    if ret > 0 && (proxy.tx_cnt - proxy.last_tx_cnt_sent).0 >= proxy.peer_buf_alloc / 2 {
        debug!(
            "sending credit update: id={}, tx_cnt={}, last_tx_cnt={}",
            proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
        );
        proxy.last_tx_cnt_sent = proxy.tx_cnt;
        // This packet goes to the connection.
        let rx = MuxerRx::CreditUpdate {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            fwd_cnt: proxy.tx_cnt.0,
        };
        push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
        update.signal_queue = true;
    }

    debug!("sendmsg ret={ret}");
    update
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
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
        result,
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
    } else if (req.flags & libc::O_NONBLOCK as u32) != 0 {
        proxy.push_accept_rsp(-libc::EWOULDBLOCK);
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

    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    }
}

pub(crate) fn process_op_response(
    proxy: &mut super::TsiStreamProxy,
    pkt: &VsockPacket,
) -> ProxyUpdate {
    debug!(
        "process_op_response: id={} src_port={} dst_port={}",
        proxy.id,
        pkt.src_port(),
        pkt.dst_port()
    );

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    switch_to_connected(proxy);

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        push_accept: Some((proxy.id, proxy.parent_id)),
        ..Default::default()
    }
}

pub(crate) fn do_shutdown(proxy: &mut super::TsiStreamProxy, pkt: &VsockPacket) {
    let recv_off = pkt.flags() & super::uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
    let send_off = pkt.flags() & super::uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;

    let how = if recv_off && send_off {
        Shutdown::Both
    } else if recv_off {
        Shutdown::Read
    } else {
        Shutdown::Write
    };

    if let Err(e) = shutdown(proxy.fd.as_raw_fd(), how) {
        warn!("error sending shutdown to socket: {e}");
    }
}

pub(crate) fn process_event(proxy: &mut super::TsiStreamProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        debug!("process_event: HANG_UP");
        if proxy.status == ProxyStatus::Connecting {
            proxy.push_connect_rsp(-libc::ECONNREFUSED);
        } else {
            proxy.push_reset();
        }

        proxy.status = ProxyStatus::Closed;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = if proxy.status == ProxyStatus::Listening {
            ProxyRemoval::Immediate
        } else {
            ProxyRemoval::Deferred
        };
        return update;
    }

    if evset.contains(EventSet::IN) {
        debug!("process_event: IN");
        if proxy.status == ProxyStatus::Connected {
            let (signal_queue, wait_credit) = proxy.recv_pkt();
            update.signal_queue = signal_queue;

            if wait_credit && proxy.status != ProxyStatus::WaitingCreditUpdate {
                proxy.status = ProxyStatus::WaitingCreditUpdate;
                let rx = MuxerRx::CreditRequest {
                    local_port: proxy.local_port,
                    peer_port: proxy.peer_port,
                    fwd_cnt: proxy.tx_cnt.0,
                };
                update.push_credit_req = Some(rx);
            }

            if proxy.status == ProxyStatus::Closed {
                debug!(
                    "process_event: endpoint closed, sending reset: id={}",
                    proxy.id
                );
                proxy.push_reset();
                update.signal_queue = true;
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
                return update;
            } else if proxy.status == ProxyStatus::WaitingCreditUpdate {
                debug!("process_event: WaitingCreditUpdate");
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
            }
        } else if proxy.status == ProxyStatus::Listening
            || proxy.status == ProxyStatus::WaitingOnAccept
        {
            match accept(proxy.fd.as_raw_fd()) {
                Ok(accept_fd) => {
                    // Safe because we've just obtained the FD from the `accept` call above.
                    let new_fd = unsafe { OwnedFd::from_raw_fd(accept_fd) };
                    update.new_proxy =
                        Some((proxy.peer_port, new_fd, proxy.family, NewProxyType::Tcp));
                }
                Err(e) => warn!("error accepting connection: id={}, err={}", proxy.id, e),
            };
            update.signal_queue = true;
            return update;
        } else {
            debug!("EventSet::IN while not connected: {:?}", proxy.status);
        }
    }

    if evset.contains(EventSet::OUT) {
        debug!("process_event: OUT");
        if proxy.status == ProxyStatus::Connecting {
            switch_to_connected(proxy);
            proxy.push_connect_rsp(0);
            update.signal_queue = true;
            // Stop listening for events in the TCP socket until we receive
            // OP_REQUEST and the vsock transport is fully established.
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        } else {
            debug!("EventSet::OUT while not connecting");
        }
    }

    update
}
