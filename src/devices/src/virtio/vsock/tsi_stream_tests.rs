// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::virtio::queue::tests::VirtQueue as TestQueue;
use utils::epoll::{ControlOperation, Epoll, EpollEvent};
use vm_memory::GuestAddress;

fn connecting(ip: std::net::IpAddr, listening: bool) -> (TsiStreamProxy, Option<Socket>) {
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
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    let queue = TestQueue::new(GuestAddress(0x1000), &mem, 8).create_queue();
    let mut proxy = TsiStreamProxy::new(
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
        mem,
        Arc::new(Mutex::new(queue)),
        Arc::new(Mutex::new(MuxerRxQ::new())),
        Arc::new(SnapshotGate::default()),
    )
    .unwrap();
    proxy.dial(Ok(address));
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
            Some(MuxerRx::ConnResponse { result, .. }) if result == expected));
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
