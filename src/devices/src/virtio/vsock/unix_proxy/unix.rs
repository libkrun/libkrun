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

use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::VsockPacket;
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
    set_nosigpipe(&fd);

    Ok(fd)
}

#[cfg(target_os = "macos")]
fn set_nosigpipe(fd: &OwnedFd) {
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

pub(crate) fn recv_to_pkt(
    proxy: &super::UnixProxy,
    pkt: &mut VsockPacket,
) -> std::io::Result<RecvPkt> {
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

pub(crate) fn do_connect(proxy: &mut super::UnixProxy) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let addr = UnixAddr::new(&proxy.path).unwrap();

    match connect(proxy.fd.as_raw_fd(), &addr) {
        Ok(()) => {
            debug!("connect: Connected");
            switch_to_connected(proxy);
        }
        Err(nix::errno::Errno::EINPROGRESS) => {
            debug!("connect: Connecting");
            proxy.status = ProxyStatus::Connecting;
        }
        Err(e) => {
            debug!("Error connecting: {e}");
        }
    }

    if proxy.status == ProxyStatus::Connecting {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN | EventSet::OUT));
    } else {
        if proxy.status == ProxyStatus::Connected {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
            proxy.push_op_response();
        }
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
            Err(Errno::EAGAIN | Errno::EINTR) => 0,
            Err(err) => {
                // The host side is gone (e.g. the peer fully closed): reset the
                // connection instead of silently dropping the guest's writes, or
                // the guest blocks once its send window fills.
                warn!("unix proxy send error: id={}, err={}", proxy.id, err);
                proxy.push_reset();
                proxy.status = ProxyStatus::Closed;
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
                update.remove_proxy = ProxyRemoval::Deferred;
                update.signal_queue = true;
                return update;
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

pub(crate) fn push_op_request(proxy: &super::UnixProxy) -> bool {
    debug!(
        "push_op_request: id={}, local_port={} peer_port={}",
        proxy.id, proxy.local_port, proxy.peer_port
    );

    // This packet goes to the connection.
    let rx = MuxerRx::OpRequest {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem)
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

    // Shutdown each direction independently: on macOS, shutdown(SHUT_RDWR) on
    // a socket whose peer already shut down its write side returns ENOTCONN,
    // and the host never sees EOF until the proxy is reaped.
    if send_off && let Err(e) = shutdown(proxy.fd.as_raw_fd(), Shutdown::Write) {
        debug!("error sending shutdown(Write) to socket: {e}");
    }
    if recv_off && let Err(e) = shutdown(proxy.fd.as_raw_fd(), Shutdown::Read) {
        debug!("error sending shutdown(Read) to socket: {e}");
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

        proxy.push_reset();

        proxy.status = ProxyStatus::Closed;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;

        return update;
    }

    if evset.intersects(EventSet::IN | EventSet::HANG_UP) {
        debug!("process_event: IN");
        if proxy.status == ProxyStatus::Connected && !proxy.rx_starved {
            let (signal_queue, wait_credit) = proxy.recv_pkt();
            update.signal_queue = signal_queue;
            update.rx_starved = proxy.rx_starved;

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
            } else if proxy.host_read_closed
                || proxy.status == ProxyStatus::WaitingCreditUpdate
                || proxy.rx_starved
            {
                debug!("process_event: disabling read polling");
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
            proxy.push_op_response();
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
                // The guest can keep writing after the host side stops, and the
                // host side may be gone by then: report EPIPE, don't raise SIGPIPE.
                #[cfg(target_os = "macos")]
                set_nosigpipe(&new_fd);
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
    use std::io::Write;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::super::UnixProxy;
    use super::*;
    use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::muxer_rxq::MuxerRxQ;
    use crate::virtio::vsock::packet::VSOCK_PKT_HDR_SIZE;
    use crate::virtio::vsock::proxy::Proxy;

    fn socket_path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("krun-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn rx_queue_refill_resumes_pending_stream_reads() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &mem, 2);
        let mut proxy = UnixProxy::new_reverse(
            1,
            3,
            620,
            1024,
            socket.into(),
            mem.clone(),
            Arc::new(Mutex::new(ring.create_queue())),
            Arc::new(Mutex::new(MuxerRxQ::new())),
        );
        proxy.status = ProxyStatus::Connected;
        proxy.peer_buf_alloc = 256;
        peer.write_all(b"payload").unwrap();

        ring.dtable[0].set(0x1000, VSOCK_PKT_HDR_SIZE as u32 + 3, VIRTQ_DESC_F_WRITE, 0);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        let update = proxy.process_event(EventSet::IN);
        assert!(update.rx_starved);
        assert!(update.signal_queue);
        assert_eq!(update.polling.unwrap().2, EventSet::empty());
        assert_eq!(ring.used.idx.get(), 1);

        ring.dtable[1].set(
            0x2000,
            VSOCK_PKT_HDR_SIZE as u32 + 32,
            VIRTQ_DESC_F_WRITE,
            0,
        );
        ring.avail.ring[1].set(1);
        ring.avail.idx.set(2);
        assert_eq!(proxy.resume_rx().unwrap().2, EventSet::IN);
        assert!(proxy.process_event(EventSet::IN).signal_queue);
        assert_eq!(ring.used.idx.get(), 2);
        let mut payload = [0; 4];
        mem.read_slice(
            &mut payload,
            GuestAddress(0x2000 + VSOCK_PKT_HDR_SIZE as u64),
        )
        .unwrap();
        assert_eq!(&payload, b"load");
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
