use std::num::Wrapping;
use std::os::fd::{FromRawFd, OwnedFd};
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
    // Stay non-blocking (accepted sockets start blocking): a host peer that stops
    // reading must not block the thread that also runs the other vsock
    // connections and devices. Data the socket doesn't take waits in `pending_tx`.
    match fcntl(&proxy.fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&proxy.fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!(
                        "error switching to non-blocking: id={}, err={}",
                        proxy.id, e
                    );
                }
            }
            None => error!("invalid fd flags id={}", proxy.id),
        },
        Err(e) => error!("couldn't obtain fd flags id={}, err={}", proxy.id, e),
    };
}

/// The events to poll for: input while the guest has credit for it, and output
/// while guest data waits for room in the host socket.
fn interest(proxy: &super::UnixProxy) -> EventSet {
    let mut events = EventSet::empty();
    if proxy.status == ProxyStatus::Connected && !proxy.host_read_closed {
        events |= EventSet::IN;
    }
    if !proxy.pending_tx.is_empty() {
        events |= EventSet::OUT;
    }
    events
}

/// Writes as much of `buf` as the host socket takes, counting it as forwarded.
fn send_host(proxy: &mut super::UnixProxy, buf: &[u8]) -> Result<usize, Errno> {
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::empty();

    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_NOSIGNAL;

    let mut sent = 0;
    while sent < buf.len() {
        match send(proxy.fd.as_raw_fd(), &buf[sent..], flags) {
            Ok(n) => sent += n,
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => break,
            Err(e) => return Err(e),
        }
    }
    proxy.tx_cnt += Wrapping(sent as u32);
    Ok(sent)
}

/// Returns credit to the guest once enough data was forwarded to the host.
fn credit_update(proxy: &mut super::UnixProxy, update: &mut ProxyUpdate) {
    if (proxy.tx_cnt - proxy.last_tx_cnt_sent).0 < proxy.peer_buf_alloc / 2 {
        return;
    }
    debug!(
        "sending credit update: id={}, tx_cnt={}, last_tx_cnt={}",
        proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
    );
    proxy.last_tx_cnt_sent = proxy.tx_cnt;

    let rx = MuxerRx::CreditUpdate {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
        fwd_cnt: proxy.tx_cnt.0,
    };

    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
    update.signal_queue = true;
}

/// The host side is gone (e.g. the peer fully closed): resets the connection
/// instead of silently dropping the guest's writes, or the guest blocks once
/// its send window fills.
fn reset_after_send_error(proxy: &mut super::UnixProxy, update: &mut ProxyUpdate, err: Errno) {
    warn!("unix proxy send error: id={}, err={}", proxy.id, err);
    proxy.pending_tx.clear();
    proxy.push_reset();
    proxy.status = ProxyStatus::Closed;
    update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
    update.remove_proxy = ProxyRemoval::Deferred;
    update.signal_queue = true;
}

/// Writes the guest data that was waiting for room in the host socket.
fn flush_pending(proxy: &mut super::UnixProxy, update: &mut ProxyUpdate) {
    let pending = std::mem::take(&mut proxy.pending_tx);
    match send_host(proxy, &pending) {
        Ok(sent) => proxy.pending_tx = pending[sent..].to_vec(),
        Err(e) => {
            reset_after_send_error(proxy, update, e);
            return;
        }
    }
    credit_update(proxy, update);
    if proxy.pending_tx.is_empty() && proxy.shutdown_write_pending {
        proxy.shutdown_write_pending = false;
        if let Err(e) = shutdown(proxy.fd.as_raw_fd(), Shutdown::Write) {
            debug!("error sending shutdown(Write) to socket: {e}");
        }
    }
    if proxy.pending_tx.is_empty() && proxy.close_after_flush {
        proxy.close_after_flush = false;
        let close = proxy.close();
        update.polling = close.polling;
        update.remove_proxy = close.remove_proxy;
        update.signal_queue = true;
        return;
    }
    update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy)));
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
        Ok(RecvPkt::Error)
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

    let Some(buf) = pkt.buf() else {
        debug!("sendmsg: pkt without buf");
        return update;
    };

    // Keep the order: while older data waits, newer data waits behind it.
    if !proxy.pending_tx.is_empty() {
        proxy.pending_tx.extend_from_slice(buf);
        return update;
    }

    match send_host(proxy, buf) {
        Ok(sent) if sent < buf.len() => {
            debug!("sendmsg: host socket full, id={} sent={sent}", proxy.id);
            proxy.pending_tx.extend_from_slice(&buf[sent..]);
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy)));
        }
        Ok(_) => {}
        Err(e) => {
            reset_after_send_error(proxy, &mut update, e);
            return update;
        }
    }
    credit_update(proxy, &mut update);

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

    if proxy.host_read_closed
        || proxy.status != ProxyStatus::WaitingCreditUpdate
        || proxy.peer_avail_credit() == 0
    {
        return ProxyUpdate::default();
    }

    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy))),
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

    // Shutdown each direction independently: on macOS, shutdown(SHUT_RDWR) on
    // a socket whose peer already shut down its write side returns ENOTCONN,
    // and the host never sees EOF until the proxy is reaped.
    // Data still waiting for the host goes out before the write side closes.
    if send_off && !proxy.pending_tx.is_empty() {
        proxy.shutdown_write_pending = true;
    } else if send_off && let Err(e) = shutdown(proxy.fd.as_raw_fd(), Shutdown::Write) {
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
            } else if proxy.host_read_closed || proxy.status == ProxyStatus::WaitingCreditUpdate {
                debug!("process_event: disabling read polling");
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), interest(proxy)));
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
        } else if !proxy.pending_tx.is_empty() {
            flush_pending(proxy, &mut update);
        } else {
            debug!("EventSet::OUT with nothing to send: {:?}", proxy.status);
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
    bind(
        fd.as_raw_fd(),
        &UnixAddr::new(path)
            .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    listen(
        &fd,
        Backlog::new(5)
            .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    Ok(super::UnixAcceptorProxy { id, fd, peer_port })
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
