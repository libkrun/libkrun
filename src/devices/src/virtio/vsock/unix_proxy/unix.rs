use std::fs;
use std::num::Wrapping;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, Backlog, MsgFlags, Shutdown, SockFlag, SockType, UnixAddr, accept, bind,
    connect, listen, recv, send, shutdown, socket,
};

#[cfg(target_os = "macos")]
use super::super::super::linux_errno::linux_errno_raw;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiConnectReq, VsockPacket};
use super::super::proxy::{
    NewProxyType, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt,
};
use utils::epoll::EventSet;

pub type PlatformHandle = OwnedFd;

pub(crate) fn create_socket(id: u64) -> Result<PlatformHandle, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
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

    Ok(fd)
}

pub(crate) fn switch_to_connected(proxy: &mut super::UnixProxy) {
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

fn push_connect_rsp(proxy: &super::UnixProxy, result: i32) {
    debug!(
        "push_connect_rsp: id: {}, control_port: {}, result: {}",
        proxy.id, proxy.control_port, result
    );

    // This response goes to the control port (DGRAM).
    let rx = MuxerRx::ConnResponse {
        local_port: 1025,
        peer_port: proxy.control_port,
        result,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn recv_to_pkt(proxy: &super::UnixProxy, pkt: &mut VsockPacket) -> RecvPkt {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);

        debug!(
            "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
            proxy.peer_avail_credit(),
            buf.len(),
            max_len
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
                match e {
                    Errno::EAGAIN | Errno::EINTR => RecvPkt::Error,
                    _ => RecvPkt::Close,
                }
            }
        }
    } else {
        debug!("recv_pkt: pkt without buf");
        RecvPkt::Error
    }
}

pub(crate) fn do_connect(
    proxy: &mut super::UnixProxy,
    _pkt: &VsockPacket,
    _req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let addr = UnixAddr::new(&proxy.path).unwrap();

    let result = match connect(proxy.fd.as_raw_fd(), &addr) {
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
            debug!("Error connecting: {e}");
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(Errno::last_raw());
            #[cfg(target_os = "linux")]
            let errno = -Errno::last_raw();
            errno
        }
    };

    if proxy.status == ProxyStatus::Connecting {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN | EventSet::OUT));
    } else {
        if proxy.status == ProxyStatus::Connected {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        }
        push_connect_rsp(proxy, result);
    }
    update
}

pub(crate) fn confirm_connect(
    proxy: &mut super::UnixProxy,
    pkt: &VsockPacket,
) -> Option<ProxyUpdate> {
    debug!(
        "confirm_connect: local_port={} peer_port={}, src_port={}, dst_port={}",
        pkt.dst_port(),
        pkt.src_port(),
        proxy.local_port,
        proxy.peer_port,
    );

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    proxy.local_port = pkt.dst_port();
    proxy.peer_port = pkt.src_port();

    // This response goes to the connection.
    let rx = MuxerRx::OpResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    None
}

pub(crate) fn sendmsg(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
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

pub(crate) fn update_peer_credit(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
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

    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    }
}

pub(crate) fn push_op_request(proxy: &super::UnixProxy) {
    debug!(
        "push_op_request: id={}, local_port={} peer_port={}",
        proxy.id, proxy.local_port, proxy.peer_port
    );

    // This packet goes to the connection.
    let rx = MuxerRx::OpRequest {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn process_op_response(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
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
        ..Default::default()
    }
}

pub(crate) fn do_shutdown(proxy: &mut super::UnixProxy, pkt: &VsockPacket) {
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

pub(crate) fn release(proxy: &mut super::UnixProxy) -> ProxyUpdate {
    debug!(
        "release: id={}, tx_cnt={}, last_tx_cnt={}",
        proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
    );

    // A connection that never reached Connected carries no data and is not
    // registered for polling yet, so there is nothing to reserve its id for.
    // Keeping it would leave the accepted host socket open, and its peer
    // blocked, until the reaper reclaims the proxy.
    let remove_proxy = match proxy.status {
        ProxyStatus::ReverseInit | ProxyStatus::Connecting => ProxyRemoval::Immediate,
        _ => ProxyRemoval::Deferred,
    };

    ProxyUpdate {
        remove_proxy,
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::UnixProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    // A hung-up stream can still contain data, including more than the guest
    // currently has buffers or credit for. Only recv() can establish EOF.
    if evset.contains(EventSet::HANG_UP)
        && !matches!(
            proxy.status,
            ProxyStatus::Connected | ProxyStatus::WaitingCreditUpdate
        )
    {
        debug!("process_event: HANG_UP");

        if proxy.status == ProxyStatus::Connecting {
            push_connect_rsp(proxy, -libc::ECONNREFUSED);
        } else {
            proxy.push_reset();
        }

        proxy.status = ProxyStatus::Closed;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;

        return update;
    }

    if evset.intersects(EventSet::IN | EventSet::HANG_UP) {
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
                update.remove_proxy = ProxyRemoval::Deferred;
                return update;
            } else if proxy.status == ProxyStatus::WaitingCreditUpdate {
                debug!("process_event: WaitingCreditUpdate");
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
            }
        } else {
            debug!("EventSet::IN while not connected: {:?}", proxy.status);
        }
    }

    if evset.contains(EventSet::OUT) {
        debug!("process_event: OUT");
        if proxy.status == ProxyStatus::Connecting {
            switch_to_connected(proxy);
            push_connect_rsp(proxy, 0);
            update.signal_queue = true;
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        } else {
            error!("EventSet::OUT while not connecting");
        }
    }

    update
}

pub(crate) fn as_raw_fd(proxy: &super::UnixProxy) -> RawFd {
    proxy.fd.as_raw_fd()
}

pub(crate) fn new_acceptor_proxy(
    id: u64,
    path: &Path,
    peer_port: u32,
) -> Result<super::UnixAcceptorProxy, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    let addr = UnixAddr::new(path)
        .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    let bound = bind(fd.as_raw_fd(), &addr);
    let bound = if bound == Err(Errno::EADDRINUSE) && remove_stale_socket(path) {
        bind(fd.as_raw_fd(), &addr)
    } else {
        bound
    };
    bound.map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    let metadata = fs::symlink_metadata(path).map_err(ProxyError::CreatingSocket)?;
    let proxy = super::UnixAcceptorProxy {
        id,
        fd,
        peer_port,
        path: path.to_path_buf(),
        identity: (metadata.dev(), metadata.ino()),
    };
    listen(
        &proxy.fd,
        Backlog::new(5)
            .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    Ok(proxy)
}

fn remove_stale_socket(path: &Path) -> bool {
    let Ok(original) = fs::symlink_metadata(path) else {
        return false;
    };
    if !original.file_type().is_socket() {
        return false;
    }
    let Ok(probe) = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    ) else {
        return false;
    };
    let Ok(flags) = fcntl(&probe, FcntlArg::F_GETFL) else {
        return false;
    };
    let Some(flags) = OFlag::from_bits(flags) else {
        return false;
    };
    if fcntl(&probe, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).is_err() {
        return false;
    }
    let Ok(addr) = UnixAddr::new(path) else {
        return false;
    };
    if connect(probe.as_raw_fd(), &addr) != Err(Errno::ECONNREFUSED) {
        return false;
    }
    let Ok(current) = fs::symlink_metadata(path) else {
        return false;
    };
    original.dev() == current.dev()
        && original.ino() == current.ino()
        && fs::remove_file(path).is_ok()
}

impl Drop for super::UnixAcceptorProxy {
    fn drop(&mut self) {
        if let Ok(current) = fs::symlink_metadata(&self.path)
            && current.dev() == self.identity.0
            && current.ino() == self.identity.1
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn process_acceptor_event(
    proxy: &mut super::UnixAcceptorProxy,
    evset: EventSet,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        debug!("process_event: HANG_UP");
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
        return update;
    }
    if evset.contains(EventSet::IN) {
        match accept(proxy.fd.as_raw_fd()) {
            Ok(accept_fd) => {
                // Safe because we've just obtained the FD from the `accept` call above.
                let new_fd = unsafe { OwnedFd::from_raw_fd(accept_fd) };
                update.new_proxy = Some((
                    proxy.peer_port,
                    new_fd,
                    AddressFamily::Unix,
                    NewProxyType::Unix,
                ));
            }
            Err(e) => warn!("error accepting connection: id={}, err={}", proxy.id, e),
        };
        update.signal_queue = true;
    }
    update
}

pub(crate) fn as_raw_acceptor_fd(proxy: &super::UnixAcceptorProxy) -> RawFd {
    proxy.fd.as_raw_fd()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn socket_path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("krun-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn acceptor_replaces_stale_socket_and_cleans_up_on_drop() {
        let path = socket_path("stale");
        drop(UnixListener::bind(&path).unwrap());
        let proxy = new_acceptor_proxy(1, &path, 1234).unwrap();
        assert!(UnixStream::connect(&path).is_ok());
        drop(proxy);
        assert!(!path.exists());
    }

    #[test]
    fn acceptor_preserves_live_listener() {
        let path = socket_path("live");
        let listener = UnixListener::bind(&path).unwrap();
        assert!(new_acceptor_proxy(1, &path, 1234).is_err());
        assert!(UnixStream::connect(&path).is_ok());
        drop(listener);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn acceptor_drop_preserves_replacement_file() {
        let path = socket_path("replaced");
        let proxy = new_acceptor_proxy(1, &path, 1234).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        drop(proxy);
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_live_backlog_does_not_block_acceptor_startup() {
        let path = socket_path("full-backlog");
        let listener = UnixListener::bind(&path).unwrap();
        listen(&listener, Backlog::new(1).unwrap()).unwrap();
        let addr = UnixAddr::new(&path).unwrap();
        let mut clients = Vec::new();
        let mut backlog_full = false;
        for _ in 0..16 {
            let client = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::SOCK_NONBLOCK,
                None,
            )
            .unwrap();
            match connect(client.as_raw_fd(), &addr) {
                Ok(()) => clients.push(client),
                Err(Errno::EAGAIN) => {
                    backlog_full = true;
                    break;
                }
                Err(e) => panic!("unexpected connect error: {e}"),
            }
        }
        assert!(backlog_full);

        let (tx, rx) = mpsc::channel();
        let probe_path = path.clone();
        let probe = thread::spawn(move || {
            tx.send(new_acceptor_proxy(1, &probe_path, 1234).is_err())
                .unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        probe.join().unwrap();
        assert!(path.exists());
        drop(clients);
        drop(listener);
        fs::remove_file(path).unwrap();
    }
}
