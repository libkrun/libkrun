// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::virtio::queue::tests::VirtQueue as TestQueue;
use std::net::IpAddr;
use utils::epoll::{ControlOperation, Epoll, EpollEvent};
use vm_memory::{Bytes, GuestAddress};

fn stream_fixture(ip: IpAddr) -> (TsiStreamProxy, VsockPacket) {
    stream_payload_fixture(ip, &[])
}

fn stream_payload_fixture(ip: IpAddr, payload: &[u8]) -> (TsiStreamProxy, VsockPacket) {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    let queue = TestQueue::new(GuestAddress(0x1000), &mem, 8).create_queue();
    let proxy = TsiStreamProxy::new(
        1,
        3,
        if ip.is_ipv4() {
            defs::LINUX_AF_INET
        } else {
            defs::LINUX_AF_INET6
        },
        1024,
        7000,
        7100,
        mem.clone(),
        Arc::new(Mutex::new(queue)),
        Arc::new(Mutex::new(MuxerRxQ::new())),
        Arc::new(SnapshotGate::default()),
        true,
    )
    .unwrap();
    let tx = TestQueue::new(GuestAddress(0x3000), &mem, 8);
    mem.write_slice(&[0; 44], GuestAddress(0x8000)).unwrap();
    mem.write_obj(payload.len() as u32, GuestAddress(0x8000 + 24))
        .unwrap();
    mem.write_slice(payload, GuestAddress(0x8000 + 44)).unwrap();
    tx.dtable[0].set(0x8000, 44 + payload.len() as u32, 0, 0);
    tx.avail.ring[0].set(0);
    tx.avail.idx.set(1);
    let mut pkt = VsockPacket::from_tx_virtq_head(&tx.create_queue().pop(&mem).unwrap()).unwrap();
    pkt.set_src_port(7300); // Distinct from the proxy creation control port.
    (proxy, pkt)
}

fn connecting(ip: IpAddr, listening: bool) -> (TsiStreamProxy, Option<Socket>) {
    let domain = if ip.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let destination = Socket::new(domain, Type::STREAM, None).unwrap();
    destination.bind(&SocketAddr::new(ip, 0).into()).unwrap();
    if listening {
        destination.listen(8).unwrap();
    }
    let address = destination.local_addr().unwrap();
    // macOS drops SYNs to a bound, non-listening socket instead of refusing
    // them. Close this ephemeral reservation before testing refusal.
    let destination = if listening {
        Some(destination)
    } else {
        drop(destination);
        None
    };
    let (mut proxy, pkt) = stream_fixture(ip);
    proxy.connect(
        &pkt,
        TsiConnectReq {
            peer_port: 7000,
            addr: address.as_socket().unwrap().into(),
        },
    );
    assert_eq!(proxy.status, ProxyStatus::Connecting);
    let mut epoll = Epoll::new().unwrap();
    epoll
        .ctl(
            ControlOperation::Add,
            raw_handle(&proxy.sock),
            &EpollEvent::new(EventSet::OUT, 1),
        )
        .unwrap();
    let mut events = [EpollEvent::default()];
    assert_eq!(epoll.wait(1, 2000, &mut events).unwrap(), 1);
    (proxy, destination)
}

fn check_connect_result(events: EventSet, listening: bool) {
    for ip in [
        Ipv4Addr::LOCALHOST.into(),
        std::net::Ipv6Addr::LOCALHOST.into(),
    ] {
        let (mut proxy, _destination) = connecting(ip, listening);
        // Readiness is only a notification. In particular, OUT can indicate
        // either success or failure; SO_ERROR carries the actual result.
        let update = proxy.process_event(events);
        let expected = if listening { 0 } else { -LINUX_ECONNREFUSED };
        assert!(matches!(proxy.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { result, peer_port: 7300, .. }) if result == expected));
        assert!(proxy.rxq.lock().unwrap().is_empty());
        assert!(update.signal_queue);
        assert!(update.polling.unwrap().2.is_empty());
        if listening {
            assert_eq!(proxy.status, ProxyStatus::Connected);
            assert!(matches!(update.remove_proxy, ProxyRemoval::Keep));
        } else {
            assert_eq!(proxy.status, ProxyStatus::Closed);
            assert!(matches!(update.remove_proxy, ProxyRemoval::Deferred));
        }
    }
}

#[test]
fn receive_window_cannot_suppress_send_credit() {
    for receive_window in [0, 32 * 1024 * 1024] {
        let (mut proxy, _) = stream_fixture(IpAddr::V4(Ipv4Addr::LOCALHOST));
        proxy.peer_buf_alloc = receive_window;
        proxy.tx_cnt = Wrapping(defs::CONN_TX_BUF_SIZE as u32);
        assert!(
            proxy.maybe_send_credit_update(),
            "guest exhausted its send window without an acknowledgement"
        );
        assert!(
            matches!(proxy.rxq.lock().unwrap().pop(), Some(MuxerRx::CreditUpdate { fwd_cnt, .. }) if fwd_cnt == proxy.tx_cnt.0)
        );
    }
}

#[test]
fn queued_credit_precedes_tcp_data_carrying_newer_credit() {
    let (mut proxy, listener) = connecting(Ipv4Addr::LOCALHOST.into(), true);
    proxy.process_event(EventSet::OUT);
    let (peer, _) = listener.unwrap().accept().unwrap();
    proxy.rxq.lock().unwrap().clear();
    proxy.peer_buf_alloc = 4096;
    proxy.tx_cnt = Wrapping(4096);
    let mem = proxy.mem.clone();
    let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
    proxy.queue = Arc::new(Mutex::new(rx.create_queue()));
    proxy.rxq.lock().unwrap().push(MuxerRx::CreditUpdate {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
        fwd_cnt: 1024,
    });
    for i in 0..2 {
        rx.dtable[i].set(0x8000 + i as u64 * 0x1000, 108, 2, 0);
        rx.avail.ring[i].set(i as u16);
    }
    rx.avail.idx.set(2);
    assert_eq!(peer.send(b"ok").unwrap(), 2);
    let mut epoll = Epoll::new().unwrap();
    epoll
        .ctl(
            ControlOperation::Add,
            raw_handle(&proxy.sock),
            &EpollEvent::new(EventSet::IN, 1),
        )
        .unwrap();
    let mut events = [EpollEvent::default()];
    assert_eq!(epoll.wait(1, 2000, &mut events).unwrap(), 1);

    assert!(proxy.process_event(EventSet::IN).signal_queue);

    assert_eq!(rx.used.idx.get(), 2);
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x8000 + 40)).unwrap(),
        1024
    );
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x9000 + 40)).unwrap(),
        4096
    );
    let mut bytes = [0; 2];
    mem.read_slice(&mut bytes, GuestAddress(0x9000 + 44))
        .unwrap();
    assert_eq!(&bytes, b"ok");
    assert!(proxy.rxq.lock().unwrap().is_empty());
}

#[test]
fn writable_connect_reports_pending_socket_error() {
    check_connect_result(EventSet::OUT, false);
}

#[test]
fn writable_connect_reports_success() {
    check_connect_result(EventSet::OUT, true);
}

#[test]
fn hung_up_connect_reports_pending_socket_error() {
    check_connect_result(EventSet::OUT | EventSet::HANG_UP, false);
}

#[cfg(target_os = "linux")]
#[test]
fn error_only_connect_reports_pending_socket_error() {
    check_connect_result(EventSet::ERROR, false);
}

fn get_address(proxy: &mut TsiStreamProxy, peer: bool) -> SocketAddr {
    let tx = TestQueue::new(GuestAddress(0x5000), &proxy.mem, 8);
    let mut wire = [0u8; 56];
    wire[24..28].copy_from_slice(&12u32.to_le_bytes());
    wire[52..56].copy_from_slice(&u32::from(peer).to_le_bytes());
    proxy.mem.write_slice(&wire, GuestAddress(0x9000)).unwrap();
    tx.dtable[0].set(0x9000, 56, 0, 0);
    tx.avail.ring[0].set(0);
    tx.avail.idx.set(1);
    let pkt = VsockPacket::from_tx_virtq_head(&tx.create_queue().pop(&proxy.mem).unwrap()).unwrap();
    proxy.getpeername(&pkt);
    let reply = proxy.rxq.lock().unwrap().pop().unwrap();
    let MuxerRx::GetnameResponse { data, .. } = reply else {
        panic!("unexpected reply: {reply:?}")
    };
    assert_eq!(data.result, 0);
    assert_eq!(
        data.addr_len,
        if proxy.family == Family::Inet { 16 } else { 28 }
    );
    data.addr.inet().unwrap()
}

#[test]
fn redirected_connections_keep_guest_address_family_and_explicit_reservations() {
    // Isolate close/rebind checks from other tests' fork/exec windows, during
    // which their children may briefly retain even CLOEXEC descriptors.
    const CHILD: &str = "LIBKRUN_INTERCEPT_BIND_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "virtio::vsock::tsi_stream::tests::redirected_connections_keep_guest_address_family_and_explicit_reservations", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use std::io::{Read, Write};
    use std::net::{Ipv6Addr, TcpListener};
    use std::time::Duration;

    for guest_ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        for endpoint_ip in [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()] {
            for binding in [
                None,
                Some(guest_ip),
                Some(if guest_ip.is_ipv4() {
                    Ipv4Addr::UNSPECIFIED.into()
                } else {
                    Ipv6Addr::UNSPECIFIED.into()
                }),
            ] {
                let (mut proxy, pkt) = stream_fixture(guest_ip);
                proxy.sock.set_nodelay(true).unwrap();
                assert!(!proxy.sock.keepalive().unwrap());
                let domain = if guest_ip.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                };
                let bound = binding.map(|ip| {
                    let addr = VsockAddr::from(SocketAddr::new(ip, 0));
                    let wire = [
                        &7000u32.to_le_bytes()[..],
                        &addr.linux_len().to_le_bytes(),
                        &0u32.to_le_bytes(),
                        &addr.to_linux_bytes(),
                    ]
                    .concat();
                    proxy
                        .bind_host(&BindRequest::parse(&wire).unwrap())
                        .unwrap()
                        .inet()
                        .unwrap()
                });
                let listener = TcpListener::bind(SocketAddr::new(endpoint_ip, 0)).unwrap();
                let intercept = StreamIntercept {
                    endpoint: listener.local_addr().unwrap(),
                    token: [0; 32],
                    port: 18443,
                };
                let destination = SocketAddr::new(guest_ip, 18443);
                proxy.connect_intercepted(
                    &pkt,
                    TsiConnectReq {
                        peer_port: 7000,
                        addr: destination.into(),
                    },
                    &intercept,
                );
                assert!(proxy.sock.nodelay().unwrap());
                assert!(
                    !proxy.sock.keepalive().unwrap(),
                    "redirect must not enable idle probes"
                );
                // Accepting the TCP connection does not complete the guest dial;
                // the interceptor must receive the preamble and give a verdict.
                let (mut remote, _) = listener.accept().unwrap();
                remote
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                proxy.process_event(EventSet::OUT);
                let mut preamble = vec![0; intercept.preamble(destination).len()];
                remote.read_exact(&mut preamble).unwrap();
                assert_eq!(preamble, intercept.preamble(destination));
                let local = get_address(&mut proxy, false);
                assert_eq!(local.is_ipv4(), guest_ip.is_ipv4());
                assert!(!local.ip().is_unspecified());
                assert_ne!(local.port(), 0);
                if let Some(bound) = bound {
                    assert_eq!(local.port(), bound.port());
                    if !bound.ip().is_unspecified() {
                        assert_eq!(local.ip(), bound.ip());
                    }
                    let contender = Socket::new(domain, Type::STREAM, None).unwrap();
                    assert_eq!(
                        sys::to_linux_errno(&contender.bind(&bound.into()).unwrap_err()),
                        98
                    );
                }
                remote.write_all(&[0]).unwrap();
                let mut epoll = Epoll::new().unwrap();
                epoll
                    .ctl(
                        ControlOperation::Add,
                        raw_handle(&proxy.sock),
                        &EpollEvent::new(EventSet::IN, 1),
                    )
                    .unwrap();
                assert_eq!(
                    epoll.wait(1, 2000, &mut [EpollEvent::default()]).unwrap(),
                    1
                );
                proxy.process_event(EventSet::IN);
                assert_eq!(proxy.status, ProxyStatus::Connected);
                assert!(matches!(
                    proxy.rxq.lock().unwrap().pop(),
                    Some(MuxerRx::ConnResponse { result: 0, .. })
                ));
                assert_eq!(get_address(&mut proxy, false), local);
                assert_eq!(get_address(&mut proxy, true), destination);
                // For cross-family redirection the retained original socket
                // never connected, so releasing it must not leave TIME_WAIT.
                drop(epoll);
                drop(proxy);
                drop(remote);
                if guest_ip.is_ipv4() != endpoint_ip.is_ipv4()
                    && let Some(bound) = bound
                {
                    Socket::new(domain, Type::STREAM, None)
                        .unwrap()
                        .bind(&bound.into())
                        .unwrap();
                }
            }
        }
    }
}

#[test]
fn host_stream_does_not_enable_keepalive_without_a_guest_request() {
    for ip in ["127.0.0.1", "::1"] {
        let (proxy, _) = stream_fixture(ip.parse().unwrap());
        assert!(!proxy.sock.keepalive().unwrap());
    }
}

#[test]
fn shutdown_delivers_queued_bytes_before_eof() {
    use std::io::{Read, Write};
    use std::net::{Ipv6Addr, TcpStream};
    use std::time::{Duration, Instant};

    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        for saturated in [false, true] {
            for waiting_credit in [false, true] {
                for flags in [
                    uapi::VSOCK_FLAGS_SHUTDOWN_SEND,
                    uapi::VSOCK_FLAGS_SHUTDOWN_SEND | uapi::VSOCK_FLAGS_SHUTDOWN_RCV,
                ] {
                    let (mut proxy, listener) = connecting(ip, true);
                    proxy.process_event(EventSet::OUT);
                    proxy.rxq.lock().unwrap().pop();
                    let (remote, _) = listener.unwrap().accept().unwrap();
                    let mut remote = TcpStream::from(remote);
                    remote
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    proxy.sock.set_send_buffer_size(4096).unwrap();
                    let mut expected = Vec::new();
                    if saturated {
                        let bytes = [0x31; 16384];
                        loop {
                            match proxy.sock.send(&bytes) {
                                Ok(n) => {
                                    assert!(n > 0);
                                    expected.extend_from_slice(&bytes[..n]);
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(e) => panic!("{e}"),
                            }
                            assert!(
                                expected.len() < 16 * 1024 * 1024,
                                "host socket never backpressured"
                            );
                        }
                    }
                    let payload = vec![0x72; 32768];
                    expected.extend_from_slice(&payload);
                    proxy.tx_buf.extend(&payload);
                    if waiting_credit {
                        proxy.status = ProxyStatus::WaitingCreditUpdate;
                        proxy.rx_paused = true;
                    }
                    let (_packet_memory, mut packet) = stream_fixture(ip);
                    packet.set_flags(flags);
                    proxy.shutdown(&packet);
                    // Repeated shutdown must neither truncate the queue nor
                    // re-enable a receive half that has already been closed.
                    proxy.shutdown(&packet);
                    let reader = std::thread::spawn(move || {
                        let mut bytes = Vec::new();
                        remote.read_to_end(&mut bytes).unwrap();
                        if flags == uapi::VSOCK_FLAGS_SHUTDOWN_SEND {
                            remote.write_all(b"response").unwrap();
                        }
                        bytes
                    });
                    let deadline = Instant::now() + Duration::from_secs(3);
                    while !proxy.tx_buf.is_empty() && Instant::now() < deadline {
                        let update = proxy.process_event(EventSet::OUT);
                        assert_ne!(
                            proxy.status,
                            ProxyStatus::Closed,
                            "shutdown discarded queued output"
                        );
                        assert!(matches!(update.remove_proxy, ProxyRemoval::Keep));
                        std::thread::yield_now();
                    }
                    assert!(
                        proxy.tx_buf.is_empty(),
                        "queued output stalled while receive credit was exhausted"
                    );
                    assert_eq!(
                        reader.join().unwrap(),
                        expected,
                        "remote saw EOF before all bytes"
                    );
                    assert_eq!(proxy.tx_cnt.0, payload.len() as u32);
                    assert!(!proxy.conn_evset().contains(EventSet::OUT));
                    if flags == uapi::VSOCK_FLAGS_SHUTDOWN_SEND {
                        let mut response = [0; 8];
                        let mut received = 0;
                        let deadline = Instant::now() + Duration::from_secs(3);
                        while received < response.len() {
                            match sys::recv_into(&proxy.sock, &mut response[received..]) {
                                Ok(0) => panic!("response truncated"),
                                Ok(n) => received += n,
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    assert!(Instant::now() < deadline, "response timed out");
                                    std::thread::sleep(Duration::from_millis(1));
                                }
                                Err(e) => panic!("response: {e}"),
                            }
                        }
                        assert_eq!(&response, b"response");
                    } else {
                        proxy.update_peer_credit(&packet);
                        assert!(!proxy.conn_evset().contains(EventSet::IN));
                    }
                }
            }
        }
    }
}

#[test]
fn release_drains_accepted_output_without_the_closed_proxy_timer() {
    use std::io::Read;
    use std::net::{Ipv6Addr, TcpStream};
    use std::time::{Duration, Instant};

    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        for waiting_credit in [false, true] {
            let (mut proxy, listener) = connecting(ip, true);
            proxy.process_event(EventSet::OUT);
            proxy.rxq.lock().unwrap().pop();
            let (remote, _) = listener.unwrap().accept().unwrap();
            let mut remote = TcpStream::from(remote);
            remote
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            proxy.sock.set_send_buffer_size(4096).unwrap();
            // A large queue makes the real socket backpressure before the
            // reader starts, independently of host TCP autotuning defaults.
            let expected = vec![0x72; 4 * 1024 * 1024];
            proxy.tx_buf.extend(&expected);
            proxy.flush_tx().unwrap();
            assert!(!proxy.tx_buf.is_empty());
            if waiting_credit {
                proxy.status = ProxyStatus::WaitingCreditUpdate;
                proxy.rx_paused = true;
            }
            let (_memory, packet) = stream_fixture(ip);
            // Release can arrive both on the control port and as a vsock RST.
            for _ in 0..2 {
                let update = proxy.release();
                assert!(matches!(update.remove_proxy, ProxyRemoval::Drain));
                assert!(update.polling.unwrap().2.contains(EventSet::OUT));
                assert!(!proxy.conn_evset().contains(EventSet::IN));
            }
            proxy.update_peer_credit(&packet);
            assert!(!proxy.conn_evset().contains(EventSet::IN));
            remote.shutdown(std::net::Shutdown::Write).unwrap();
            // Windows reports an orderly remote half-close as HANG_UP. The
            // peer still receives output, so that event cannot discard it.
            let update = proxy.process_event(EventSet::HANG_UP);
            assert!(!proxy.tx_buf.is_empty());
            assert!(matches!(update.remove_proxy, ProxyRemoval::Keep));
            let reader = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                remote.read_to_end(&mut bytes).unwrap();
                bytes
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let update = proxy.process_event(EventSet::OUT);
                assert!(!update.signal_queue);
                assert!(proxy.rxq.lock().unwrap().is_empty());
                if matches!(update.remove_proxy, ProxyRemoval::Immediate) {
                    assert!(proxy.tx_buf.is_empty());
                    break;
                }
                assert!(matches!(update.remove_proxy, ProxyRemoval::Keep));
                assert!(
                    Instant::now() < deadline,
                    "released stream stopped draining"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(proxy);
            assert_eq!(reader.join().unwrap(), expected);
        }
    }
}

#[test]
fn forced_teardown_with_pending_output_resets_instead_of_truncating() {
    use std::io::{ErrorKind, Read};
    use std::net::{Ipv6Addr, TcpStream};
    use std::time::Duration;

    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let (mut proxy, listener) = connecting(ip, true);
        proxy.process_event(EventSet::OUT);
        let (remote, _) = listener.unwrap().accept().unwrap();
        let mut remote = TcpStream::from(remote);
        remote
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        proxy.tx_buf.extend(b"accepted but not yet forwarded");
        drop(proxy);
        let mut bytes = Vec::new();
        assert_eq!(
            remote.read_to_end(&mut bytes).unwrap_err().kind(),
            ErrorKind::ConnectionReset
        );
    }
}

#[test]
fn empty_shutdown_flags_leave_stream_writable() {
    use std::io::Read;
    use std::net::TcpStream;
    use std::time::Duration;
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let (mut proxy, listener) = connecting(ip, true);
    proxy.process_event(EventSet::OUT);
    let (remote, _) = listener.unwrap().accept().unwrap();
    let mut remote = TcpStream::from(remote);
    remote
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (_packet_memory, packet) = stream_fixture(ip);
    proxy.shutdown(&packet);
    proxy.tx_buf.extend(b"still writable");
    assert!(proxy.flush_tx().unwrap());
    let mut received = [0; 14];
    remote.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"still writable");
}

#[test]
fn buffer_shrink_and_small_send_windows_preserve_credit_accounting() {
    let (mut proxy, _) = stream_fixture(Ipv4Addr::LOCALHOST.into());
    proxy.peer_buf_alloc = 8192;
    proxy.rx_cnt = Wrapping(16384);
    proxy.peer_fwd_cnt = Wrapping(0);
    assert_eq!(
        proxy.peer_avail_credit(),
        0,
        "shrinking must not wrap to unlimited credit"
    );
    proxy.peer_fwd_cnt = Wrapping(12288);
    assert_eq!(proxy.peer_avail_credit(), 4096);
    proxy.peer_buf_alloc = 262144;
    proxy.buffers.send = Some(8192);
    proxy.tx_cnt = Wrapping(4096);
    assert!(proxy.maybe_send_credit_update());
    assert!(matches!(
        proxy.rxq.lock().unwrap().pop(),
        Some(MuxerRx::CreditUpdate { fwd_cnt: 4096, .. })
    ));
    assert!(!proxy.maybe_send_credit_update());
    proxy.status = ProxyStatus::WaitingCreditUpdate;
    proxy.tx_cnt = Wrapping(4100);
    let update = proxy.request_credit();
    assert!(update.signal_queue);
    assert_eq!(proxy.status, ProxyStatus::WaitingCreditUpdate);
    assert!(matches!(
        proxy.rxq.lock().unwrap().pop(),
        Some(MuxerRx::CreditUpdate { fwd_cnt: 4100, .. })
    ));
    proxy.status = ProxyStatus::Closed;
    assert!(!proxy.request_credit().signal_queue);
    assert!(proxy.rxq.lock().unwrap().is_empty());
}

#[test]
fn accepted_connections_inherit_credit_budgets_without_retuning() {
    for ip in [
        Ipv4Addr::LOCALHOST.into(),
        std::net::Ipv6Addr::LOCALHOST.into(),
    ] {
        let (mut listener, _) = stream_fixture(ip);
        listener.sock.bind(&SocketAddr::new(ip, 0).into()).unwrap();
        listener.sock.listen(1).unwrap();
        listener.status = ProxyStatus::Listening;
        listener.buffers.send = Some(8192);
        listener.buffers.receive = Some(32768);
        let _client =
            std::net::TcpStream::connect(listener.sock.local_addr().unwrap().as_socket().unwrap())
                .unwrap();
        let mut epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                raw_handle(&listener.sock),
                &EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap();
        let mut events = [EpollEvent::default()];
        assert_eq!(epoll.wait(1, 2000, &mut events).unwrap(), 1);
        let update = listener.process_event(EventSet::IN);
        let (peer_port, socket, family, NewProxyType::Tcp(buffers)) = update.new_proxy.unwrap()
        else {
            panic!("expected an accepted TCP connection");
        };
        // Linux does not inherit O_NONBLOCK from the listening socket.
        // A blocking child can stall the entire muxer when its peer stops reading.
        #[cfg(unix)]
        assert!(socket.nonblocking().unwrap());
        let mut child = TsiStreamProxy::new_reverse(
            2,
            listener.cid,
            listener.id,
            family,
            7500,
            peer_port,
            socket,
            buffers,
            listener.mem.clone(),
            listener.queue.clone(),
            listener.rxq.clone(),
            listener.snapshot_gate.clone(),
        );
        listener.buffers.send = Some(1048576);
        assert_eq!(child.buffers.receive, Some(32768));
        child.peer_buf_alloc = 32768;
        child.tx_cnt = Wrapping(8192);
        assert!(child.maybe_send_credit_update());
        assert!(matches!(
            child.rxq.lock().unwrap().pop(),
            Some(MuxerRx::CreditUpdate { fwd_cnt: 8192, .. })
        ));
    }
}

#[test]
fn explicit_abort_resets_even_without_queued_output() {
    use std::io::{ErrorKind, Read};
    use std::net::{Ipv6Addr, TcpStream};
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let (mut proxy, listener) = connecting(ip, true);
        proxy.process_event(EventSet::OUT);
        let mut remote = TcpStream::from(listener.unwrap().accept().unwrap().0);
        remote
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (result, update) = proxy.close_host_stream(&CloseRequest {
            peer_port: 0,
            local_port: 0,
            tx_count: 0,
            flags: host_close::ABORT,
        });
        assert_eq!(result, 0);
        assert!(matches!(update.remove_proxy, ProxyRemoval::Immediate));
        drop(proxy);
        assert_eq!(
            remote.read(&mut [0]).unwrap_err().kind(),
            ErrorKind::ConnectionReset
        );
    }
}

#[test]
fn close_watermark_preserves_data_that_arrives_after_release() {
    use std::io::{ErrorKind, Read};
    use std::net::{Ipv6Addr, TcpStream};
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let (mut proxy, listener) = connecting(ip, true);
        proxy.process_event(EventSet::OUT);
        let mut remote = TcpStream::from(listener.unwrap().accept().unwrap().0);
        remote.set_nonblocking(true).unwrap();
        let payload = b"late payload";
        proxy.tx_cnt = Wrapping(u32::MAX - 3);
        let expected = (proxy.tx_cnt + Wrapping(payload.len() as u32)).0;
        let req = CloseRequest {
            peer_port: 0,
            local_port: 0,
            tx_count: expected,
            flags: host_close::WAIT,
        };
        assert_eq!(proxy.close_host_stream(&req).0, 1);
        assert!(!proxy.close_fin_sent);
        assert_eq!(
            remote.read(&mut [0]).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        assert!(matches!(proxy.release().remove_proxy, ProxyRemoval::Drain));
        // Reordered shutdown must not put FIN before the missing payload.
        let (_memory, mut pkt) = stream_fixture(ip);
        pkt.set_flags(uapi::VSOCK_FLAGS_SHUTDOWN_SEND);
        proxy.shutdown(&pkt);
        assert_eq!(
            remote.read(&mut [0]).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        let (_memory, packet) = stream_payload_fixture(ip, payload);
        assert!(matches!(
            proxy.sendmsg(&packet).remove_proxy,
            ProxyRemoval::Immediate
        ));
        assert_eq!(proxy.tx_cnt.0, expected);
        drop(proxy);
        remote.set_nonblocking(false).unwrap();
        remote
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut actual = Vec::new();
        remote.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, payload);
    }
}

#[test]
fn payload_beyond_the_close_watermark_is_rejected_before_transmission() {
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let (mut proxy, _listener) = connecting(ip, true);
    proxy.process_event(EventSet::OUT);
    let req = CloseRequest {
        peer_port: 0,
        local_port: 0,
        tx_count: 1,
        flags: host_close::WAIT,
    };
    assert_eq!(proxy.close_host_stream(&req).0, 1);
    let (_memory, packet) = stream_payload_fixture(ip, b"too many bytes");
    let update = proxy.sendmsg(&packet);
    assert!(matches!(update.remove_proxy, ProxyRemoval::Deferred));
    assert_eq!(proxy.status, ProxyStatus::Closed);
    assert_eq!(proxy.tx_cnt.0, 0);
    assert!(proxy.tx_buf.is_empty());
}

#[test]
fn linger_completion_waits_for_output_and_fin_acknowledgment() {
    use std::io::Read;
    use std::net::{Ipv6Addr, TcpStream};
    use std::time::Instant;
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let (mut proxy, listener) = connecting(ip, true);
        proxy.process_event(EventSet::OUT);
        let mut remote = TcpStream::from(listener.unwrap().accept().unwrap().0);
        remote
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        proxy.sock.set_send_buffer_size(4096).unwrap();
        let payload = vec![0x45; 4 * 1024 * 1024];
        proxy.tx_buf.extend(&payload);
        let req = CloseRequest {
            peer_port: 0,
            local_port: 0,
            tx_count: payload.len() as u32,
            flags: host_close::WAIT,
        };
        assert_eq!(proxy.close_host_stream(&req).0, 1);
        assert!(!proxy.close_fin_sent);
        let reader = std::thread::spawn(move || {
            let mut actual = Vec::new();
            remote.read_to_end(&mut actual).unwrap();
            actual
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let update = proxy.process_event(EventSet::OUT);
            assert!(matches!(update.remove_proxy, ProxyRemoval::Keep));
            let (result, _) = proxy.close_host_stream(&req);
            if result == 0 {
                break;
            }
            assert_eq!(result, 1);
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(proxy.close_fin_sent);
        assert!(matches!(
            proxy.release().remove_proxy,
            ProxyRemoval::Immediate
        ));
        drop(proxy);
        assert_eq!(reader.join().unwrap(), payload);
    }
}

#[test]
fn released_stream_idle_deadline_requires_forwarding_progress() {
    let (mut proxy, pkt) = stream_fixture(Ipv4Addr::LOCALHOST.into());
    proxy.record_drain_progress();
    assert_eq!(
        proxy.drain_deadline(),
        None,
        "active streams have no drain timer"
    );
    proxy.status = ProxyStatus::Connected;
    // Missing guest bytes count as outstanding output, even with an empty queue.
    proxy.close_watermark = Some(Wrapping(10));
    assert!(matches!(proxy.release().remove_proxy, ProxyRemoval::Drain));
    let first = proxy.drain_progress.unwrap();
    assert_eq!(proxy.drain_deadline(), Some(first + DRAIN_IDLE_TIMEOUT));
    proxy.release();
    proxy.update_peer_credit(&pkt);
    proxy.process_event(EventSet::OUT);
    assert_eq!(
        proxy.drain_progress,
        Some(first),
        "control/readiness is not progress"
    );
    let progressed = first + Duration::from_secs(119);
    proxy.drain_progress = Some(progressed);
    proxy.release();
    assert_eq!(
        proxy.drain_deadline(),
        Some(progressed + DRAIN_IDLE_TIMEOUT)
    );
}

#[test]
fn writes_to_host_extend_only_released_stream_deadlines() {
    let (mut proxy, listener) = connecting(Ipv4Addr::LOCALHOST.into(), true);
    proxy.process_event(EventSet::OUT);
    let (_remote, _) = listener.unwrap().accept().unwrap();
    proxy.tx_buf.extend(b"first");
    proxy.flush_tx().unwrap();
    assert_eq!(proxy.drain_deadline(), None);
    proxy.close_watermark = Some(proxy.tx_cnt + Wrapping(10));
    proxy.release();
    let previous = Instant::now() - Duration::from_secs(119);
    proxy.drain_progress = Some(previous);
    proxy.tx_buf.extend(b"second");
    assert!(proxy.flush_tx().unwrap());
    assert!(proxy.drain_progress.unwrap() > previous);
    assert!(proxy.output_pending());
}
