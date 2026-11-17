// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::virtio::queue::tests::VirtQueue as TestQueue;
use std::net::IpAddr;
use utils::epoll::{ControlOperation, Epoll, EpollEvent};
use vm_memory::{Bytes, GuestAddress};

fn stream_fixture(ip: IpAddr) -> (TsiStreamProxy, VsockPacket) {
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
    tx.dtable[0].set(0x8000, 44, 0, 0);
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
                if guest_ip.is_ipv4() != endpoint_ip.is_ipv4() {
                    if let Some(bound) = bound {
                        Socket::new(domain, Type::STREAM, None)
                            .unwrap()
                            .bind(&bound.into())
                            .unwrap();
                    }
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
