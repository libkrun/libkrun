// SPDX-License-Identifier: Apache-2.0

//! Exercise actual guest packet dispatch, proxy state, and host sockets.
use super::super::packet::VSOCK_PKT_HDR_SIZE;
use super::*;
use crate::virtio::queue::tests::VirtQueue as TestQueue;
use std::net::{Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress};

const GUEST: u32 = 7000;
const CONTROL: u32 = 7100;

struct Fixture {
    muxer: VsockMuxer,
    mem: GuestMemoryMmap,
}

impl Fixture {
    fn new(flags: TsiFlags, map: Option<HashMap<u16, u16>>) -> Self {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
        let mut muxer = VsockMuxer::new(3, map, None, flags, None, None, None, None, None);
        muxer.mem = Some(mem.clone());
        muxer.queue = Some(Arc::new(Mutex::new(rx.create_queue())));
        Self { muxer, mem }
    }

    fn packet(&self, dst: u32, data: &[u8]) -> VsockPacket {
        let tx = TestQueue::new(GuestAddress(0x1000), &self.mem, 8);
        let hdr = GuestAddress(0x10000);
        self.mem.write_slice(&[0; VSOCK_PKT_HDR_SIZE], hdr).unwrap();
        self.mem
            .write_obj(data.len() as u32, GuestAddress(0x10000 + 24))
            .unwrap();
        self.mem
            .write_slice(data, GuestAddress(0x10000 + VSOCK_PKT_HDR_SIZE as u64))
            .unwrap();
        tx.dtable[0].set(0x10000, (VSOCK_PKT_HDR_SIZE + data.len()) as u32, 0, 0);
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        let mut pkt =
            VsockPacket::from_tx_virtq_head(&tx.create_queue().pop(&self.mem).unwrap()).unwrap();
        pkt.set_op(uapi::VSOCK_OP_RW)
            .set_src_port(CONTROL)
            .set_dst_port(dst)
            .set_src_cid(3)
            .set_dst_cid(uapi::VSOCK_HOST_CID)
            .set_type(uapi::VSOCK_TYPE_DGRAM);
        pkt
    }

    fn send(&mut self, dst: u32, data: &[u8]) {
        let pkt = self.packet(dst, data);
        self.muxer.send_dgram_pkt(&pkt).unwrap();
    }

    fn create(&mut self, kind: u16, family: u16) {
        self.send(
            defs::TSI_PROXY_CREATE,
            &[
                &GUEST.to_le_bytes()[..],
                &family.to_le_bytes(),
                &kind.to_le_bytes(),
            ]
            .concat(),
        );
    }

    fn bind(&mut self, addr: SocketAddr) -> Result<SocketAddr, i32> {
        let addr = VsockAddr::from(addr);
        self.send(
            defs::TSI_BIND,
            &[
                &GUEST.to_le_bytes()[..],
                &addr.linux_len().to_le_bytes(),
                &0u32.to_le_bytes(),
                &addr.to_linux_bytes(),
            ]
            .concat(),
        );
        self.bind_result()
    }

    fn bind_result(&self) -> Result<SocketAddr, i32> {
        let rx = self.muxer.rxq.lock().unwrap().pop().unwrap();
        let MuxerRx::BindResponse {
            local_port,
            peer_port,
            data,
        } = rx
        else {
            panic!("unexpected reply: {rx:?}");
        };
        assert_eq!(local_port, defs::TSI_BIND);
        assert_eq!(peer_port, CONTROL);
        let mut buf = [0; 136];
        assert_eq!(data.write(&mut buf), 136);
        let result = i32::from_le_bytes(buf[..4].try_into().unwrap());
        if result != 0 {
            return Err(result);
        }
        let len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        Ok(VsockAddr::parse_linux(&buf[8..], len)
            .unwrap()
            .inet()
            .unwrap())
    }

    fn release(&mut self) {
        self.send(
            defs::TSI_PROXY_RELEASE,
            &[
                &GUEST.to_le_bytes()[..],
                &defs::TSI_PROXY_PORT.to_le_bytes(),
            ]
            .concat(),
        );
        assert!(self.muxer.proxy_map.read().unwrap().is_empty());
    }
}

fn granted() -> TsiFlags {
    TsiFlags::HIJACK_INET | TsiFlags::HOST_BIND
}

#[test]
fn host_bind_requires_explicit_grant_and_no_publishing_map() {
    for (flags, map) in [
        (TsiFlags::empty(), None),
        (TsiFlags::HIJACK_INET, None),
        (TsiFlags::HOST_BIND, None),
        (granted(), Some(HashMap::new())),
        (granted(), Some(HashMap::from([(12345, 12345)]))),
    ] {
        let mut f = Fixture::new(flags, map);
        f.create(defs::SOCK_STREAM, defs::LINUX_AF_INET);
        assert_eq!(f.bind((Ipv4Addr::LOCALHOST, 0).into()), Err(-libc::EPERM));
    }
}

#[test]
fn host_bind_returns_errors_for_bad_packets_and_missing_proxies() {
    let mut f = Fixture::new(granted(), None);
    assert_eq!(f.bind((Ipv4Addr::LOCALHOST, 0).into()), Err(-libc::EBADF));
    f.send(defs::TSI_BIND, &[0; 7]);
    assert_eq!(f.bind_result(), Err(-libc::EINVAL));
    f.create(defs::SOCK_STREAM, defs::LINUX_AF_INET);
    assert_eq!(f.bind((Ipv6Addr::LOCALHOST, 0).into()), Err(-97));
    // A failed bind does not consume the socket.
    assert!(f.bind((Ipv4Addr::LOCALHOST, 0).into()).is_ok());
}

#[test]
fn host_bind_reserves_ports_across_vms_and_releases_them_on_close() {
    // Other tests spawn children concurrently. Even CLOEXEC sockets remain
    // referenced between clone and exec, so closing the parent's copy need
    // not release a port immediately. Own these sockets in an isolated test
    // process, with no concurrent spawns, instead of retrying a failed release.
    const CHILD: &str = "LIBKRUN_BIND_RELEASE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "virtio::vsock::muxer::host_bind_tests::host_bind_reserves_ports_across_vms_and_releases_them_on_close", "--nocapture"])
            .env(CHILD, "1")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for kind in [defs::SOCK_STREAM, defs::SOCK_DGRAM] {
        for (family, ip) in [
            (defs::LINUX_AF_INET, Ipv4Addr::LOCALHOST.into()),
            (defs::LINUX_AF_INET6, Ipv6Addr::LOCALHOST.into()),
        ] {
            let mut first = Fixture::new(granted(), None);
            let mut second = Fixture::new(granted(), None);
            first.create(kind, family);
            second.create(kind, family);
            let bound = first.bind(SocketAddr::new(ip, 0)).unwrap();
            assert_ne!(bound.port(), 0);
            assert_eq!(second.bind(bound), Err(-98)); // Linux EADDRINUSE on macOS too.
            assert_eq!(first.bind(bound), Err(-libc::EINVAL));
            first.release();
            assert_eq!(second.bind(bound), Ok(bound));
            second.release();
        }
    }
}

#[test]
fn host_bound_stream_listens_on_its_reserved_port() {
    let mut f = Fixture::new(granted(), None);
    f.create(defs::SOCK_STREAM, defs::LINUX_AF_INET);
    let bound = f.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = VsockAddr::from(bound);
    f.send(
        defs::TSI_LISTEN,
        &[
            &GUEST.to_le_bytes()[..],
            &GUEST.to_le_bytes(),
            &4u32.to_le_bytes(),
            &addr.linux_len().to_le_bytes(),
            &addr.to_linux_bytes(),
        ]
        .concat(),
    );
    assert!(matches!(
        f.muxer.rxq.lock().unwrap().pop(),
        Some(MuxerRx::ListenResponse { result: 0, .. })
    ));
    let _client = TcpStream::connect_timeout(&bound, Duration::from_secs(2)).unwrap();
    f.release();
}

fn listener_fixture(family: u16, ip: std::net::IpAddr) -> (Fixture, Vec<u8>) {
    let mut f = Fixture::new(granted(), None);
    f.create(defs::SOCK_STREAM, family);
    let addr = VsockAddr::from(f.bind((ip, 0).into()).unwrap());
    let listen = [
        &GUEST.to_le_bytes()[..],
        &GUEST.to_le_bytes(),
        &4u32.to_le_bytes(),
        &addr.linux_len().to_le_bytes(),
        &addr.to_linux_bytes(),
    ]
    .concat();
    f.send(defs::TSI_LISTEN, &listen);
    assert!(matches!(
        f.muxer.rxq.lock().unwrap().pop(),
        Some(MuxerRx::ListenResponse { result: 0, .. })
    ));
    (f, listen)
}

#[test]
fn host_listener_snapshot_restores_without_a_publishing_map() {
    // Isolate port release assertions from unrelated tests spawning processes.
    const CHILD: &str = "LIBKRUN_LISTENER_RESTORE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "virtio::vsock::muxer::host_bind_tests::host_listener_snapshot_restores_without_a_publishing_map", "--nocapture"])
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
    for (family, ip) in [
        (defs::LINUX_AF_INET, Ipv4Addr::LOCALHOST.into()),
        (defs::LINUX_AF_INET6, Ipv6Addr::LOCALHOST.into()),
    ] {
        let (mut source, listen) = listener_fixture(family, ip);
        let bound = VsockAddr::parse_linux(
            &listen[16..],
            u32::from_le_bytes(listen[12..16].try_into().unwrap()),
        )
        .unwrap()
        .inet()
        .unwrap();
        for (level, option, value) in [
            (1u32, 2u32, 0u32),
            (1, 9, 1),
            (6, 1, 1),
            (6, 4, 42),
            (1, 8, 16384),
        ] {
            source.send(
                defs::TSI_HOST_SETSOCKOPT,
                &[GUEST, defs::TSI_PROXY_PORT, level, option, value]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
            );
            let response = source.muxer.rxq.lock().unwrap().pop().unwrap();
            let MuxerRx::BindResponse { data, .. } = response else {
                panic!("{response:?}")
            };
            let mut bytes = [0; 136];
            data.write(&mut bytes);
            assert_eq!(i32::from_le_bytes(bytes[..4].try_into().unwrap()), 0);
        }
        let saved = source.muxer.snapshot_listeners();
        assert!(saved[0].socket.as_ref().unwrap().is_ok());
        let encoded = serde_json::to_vec(&saved).unwrap();
        let decoded = serde_json::from_slice(&encoded).unwrap();
        // An occupied source must fail restore, never disappear silently.
        let conflict = Fixture::new(granted(), None);
        let error = conflict.muxer.restore_listeners(saved.clone()).unwrap_err();
        assert!(error.contains(&bound.to_string()), "{error}");
        assert!(conflict.muxer.proxy_map.read().unwrap().is_empty());
        source.release();
        let mut restored = Fixture::new(granted(), None);
        restored.muxer.restore_listeners(decoded).unwrap();
        assert_eq!(
            restored.muxer.snapshot_listeners(),
            saved,
            "restore changed binding/options"
        );
        let mut client = TcpStream::connect_timeout(&bound, Duration::from_secs(2)).unwrap();
        client.write_all(b"restored").unwrap();
        let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        let accepted = restored.muxer.proxy_map.read().unwrap()[&id]
            .lock()
            .unwrap()
            .process_event(EventSet::IN)
            .new_proxy
            .unwrap()
            .1;
        let mut accepted = TcpStream::from(accepted);
        accepted.set_nonblocking(false).unwrap();
        accepted
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = [0; 8];
        accepted.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"restored");
        // The next assertion checks ownership release, not TCP TIME_WAIT.
        socket2::SockRef::from(&accepted)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(accepted);
        drop(client);
        restored.release();

        // Bind failures late in a batch roll back every prepared listener.
        let occupied = std::net::TcpListener::bind((ip, 0)).unwrap();
        let mut batch = saved.clone();
        let mut second = saved[0].clone();
        second.peer_port += 1;
        second.socket.as_mut().unwrap().as_mut().unwrap().address = occupied.local_addr().unwrap();
        batch.push(second);
        let rolled_back = Fixture::new(granted(), None);
        assert!(rolled_back.muxer.restore_listeners(batch).is_err());
        assert!(rolled_back.muxer.proxy_map.read().unwrap().is_empty());
        let released = std::net::TcpListener::bind(bound).unwrap();
        drop(released);

        // Old records remain readable through explicit port mappings.
        let mut value = serde_json::to_value(&saved[0]).unwrap();
        value.as_object_mut().unwrap().remove("socket");
        value.as_object_mut().unwrap().remove("accept_pending");
        let old: ListenerDesc = serde_json::from_value(value).unwrap();
        let mut legacy = Fixture::new(
            TsiFlags::HIJACK_INET,
            Some(HashMap::from([(old.guest_port, bound.port())])),
        );
        legacy.muxer.restore_listeners(vec![old]).unwrap();
        let _client = TcpStream::connect_timeout(&bound, Duration::from_secs(2)).unwrap();
        legacy.release();
    }
}

#[test]
fn paused_host_accept_leaves_proxy_table_available_for_restore() {
    use crate::legacy::DummyIrqChip;
    use std::sync::mpsc;
    use std::thread;

    let (f, _) = listener_fixture(defs::LINUX_AF_INET, Ipv4Addr::LOCALHOST.into());
    let saved = f.muxer.snapshot_listeners();
    let address = saved[0].socket.as_ref().unwrap().as_ref().unwrap().address;
    let (sender, _receiver) = unbounded();
    let worker = MuxerThread::new(
        3,
        f.muxer.epoll.clone(),
        f.muxer.rxq.clone(),
        f.muxer.proxy_map.clone(),
        f.mem.clone(),
        f.muxer.queue.as_ref().unwrap().clone(),
        InterruptTransport::new(DummyIrqChip::new().into(), "paused accept test".into()).unwrap(),
        sender,
        HashMap::new(),
        f.muxer.snapshot_gate.clone(),
        f.muxer.host_event_gate.clone(),
        #[cfg(target_os = "macos")]
        None,
        #[cfg(target_os = "macos")]
        None,
    );
    f.muxer.quiesce_for_snapshot();
    let _client = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
    let handler = thread::spawn(move || {
        started_tx.send(()).unwrap();
        worker.process_host_event(id, EventSet::IN, &mut rand::rng());
        finished_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let held = finished_rx.recv_timeout(Duration::from_millis(50)).is_err();
    // Before the fix the handler accepted the socket, installed its child and
    // blocked inside push_op_request while retaining the table's read lock.
    let table_available = f.muxer.proxy_map.try_write().is_ok();
    // Always release the worker before asserting, including on the old code.
    f.muxer.rearm_after_snapshot();
    finished_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    handler.join().unwrap();
    assert!(held, "host handler ran while snapshot was paused");
    assert!(
        table_available,
        "paused host handler retained proxy table lock"
    );
    assert_eq!(f.muxer.snapshot_listeners(), saved);
    assert!(f.muxer.proxy_map.read().unwrap().len() > 1);
}

#[test]
fn listener_accept_replies_follow_the_request_channel() {
    for (family, ip) in [
        (defs::LINUX_AF_INET, Ipv4Addr::LOCALHOST.into()),
        (defs::LINUX_AF_INET6, Ipv6Addr::LOCALHOST.into()),
    ] {
        for flags in [0u32, defs::LINUX_O_NONBLOCK] {
            let (mut f, _) = listener_fixture(family, ip);
            let mut request = f.packet(
                defs::TSI_ACCEPT,
                &[&GUEST.to_le_bytes()[..], &flags.to_le_bytes()].concat(),
            );
            request.set_src_port(CONTROL + 1);
            f.muxer.send_dgram_pkt(&request).unwrap();
            if flags == 0 {
                assert!(f.muxer.rxq.lock().unwrap().is_empty());
                let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
                // Complete the pending guest accept, as a connected child does.
                f.muxer.proxy_map.read().unwrap()[&id]
                    .lock()
                    .unwrap()
                    .enqueue_accept();
            }
            let response = f.muxer.rxq.lock().unwrap().pop().unwrap();
            assert!(
                matches!(response, MuxerRx::AcceptResponse {
                peer_port, result, ..
            } if peer_port == CONTROL + 1 && result == if flags == 0 { 0 } else { -11 }),
                "wrong accept reply: {response:?}"
            );
            f.release();
        }
    }
}

#[test]
fn listener_backlog_update_preserves_a_pending_accept() {
    for (family, ip) in [
        (defs::LINUX_AF_INET, Ipv4Addr::LOCALHOST.into()),
        (defs::LINUX_AF_INET6, Ipv6Addr::LOCALHOST.into()),
    ] {
        let (mut f, mut listen) = listener_fixture(family, ip);
        f.send(
            defs::TSI_ACCEPT,
            &[&GUEST.to_le_bytes()[..], &0u32.to_le_bytes()].concat(),
        );
        assert!(f.muxer.rxq.lock().unwrap().is_empty());
        listen[8..12].copy_from_slice(&32u32.to_le_bytes());
        f.send(defs::TSI_LISTEN, &listen);
        assert!(matches!(
            f.muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ListenResponse { result: 0, .. })
        ));
        let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        {
            let map = f.muxer.proxy_map.read().unwrap();
            let mut listener = map[&id].lock().unwrap();
            assert_eq!(listener.status(), ProxyStatus::WaitingOnAccept);
            assert_eq!(listener.listener_desc().unwrap().backlog, 32);
            listener.enqueue_accept();
        }
        assert!(matches!(
            f.muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::AcceptResponse {
                result: 0,
                peer_port: CONTROL,
                ..
            })
        ));
        f.release();
    }
}

#[test]
fn host_udp_preserves_datagrams_across_queue_refills_and_replies_to_each_sender() {
    use super::super::host_datagram::FRAME_HEADER;
    let mut f = Fixture::new(granted(), None);
    // A local host-network launch explicitly permits host loopback; binding
    // alone must not override the transport's independent egress policy.
    f.muxer.floor = FloorMode::MetadataOnly;
    f.create(defs::SOCK_DGRAM, defs::LINUX_AF_INET);
    let bound = f.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let mem = f.mem.clone();
    let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
    let clients: Vec<_> = (0..2)
        .map(|_| {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
        })
        .collect();
    let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
    let mut available = 0u16;
    for (index, len) in [0, 4096, 65_507, 1].into_iter().enumerate() {
        let client = &clients[index % 2];
        socket2::SockRef::from(client)
            .set_send_buffer_size(128 * 1024)
            .unwrap();
        let data: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
        client.send_to(&data, bound).unwrap();
        let fd = f
            .muxer
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .unwrap()
            .lock()
            .unwrap()
            .poll_handle();
        super::super::host_datagram::wait_readable(fd);
        // The socket becomes readable while the guest has no RX buffers.
        let proxy = f.muxer.proxy_map.read().unwrap();
        proxy
            .get(&id)
            .unwrap()
            .lock()
            .unwrap()
            .process_event(EventSet::IN);
        drop(proxy);
        assert!(f.muxer.pending_datagram_rx.lock().unwrap().contains(&id));
        let mut recovered = Vec::new();
        let mut sequence = None;
        loop {
            let buffer = 0x30000;
            rx.dtable[0].set(buffer, (VSOCK_PKT_HDR_SIZE + 512) as u32, 2, 0);
            rx.avail.ring[available as usize % 8].set(0);
            available += 1;
            rx.avail.idx.set(available);
            // A guest refill alone must resume a partially delivered message,
            // even after the host socket has been drained and is no longer readable.
            assert!(f.muxer.resume_datagram_rx());
            assert_eq!(rx.used.idx.get(), available);
            let used = rx.used.ring[(available as usize - 1) % 8].get();
            let bytes = used.len as usize - VSOCK_PKT_HDR_SIZE;
            let mut frame = vec![0; bytes];
            mem.read_slice(&mut frame, GuestAddress(buffer + VSOCK_PKT_HDR_SIZE as u64))
                .unwrap();
            assert_eq!(
                mem.read_obj::<u64>(GuestAddress(buffer)).unwrap(),
                uapi::VSOCK_HOST_CID
            );
            assert_eq!(mem.read_obj::<u64>(GuestAddress(buffer + 8)).unwrap(), 3);
            let word = |at| u32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
            assert_eq!(word(4) as usize, len);
            assert_eq!(word(8) as usize, recovered.len());
            if let Some(sequence) = sequence {
                assert_eq!(word(0), sequence);
            } else {
                sequence = Some(word(0));
            }
            let sender = VsockAddr::parse_linux(&frame[16..FRAME_HEADER], word(12)).unwrap();
            assert_eq!(sender.inet(), Some(client.local_addr().unwrap()));
            recovered.extend_from_slice(&frame[FRAME_HEADER..]);
            if recovered.len() == len {
                break;
            }
        }
        assert_eq!(recovered, data);
        // Reply through the existing guest sendto path; the client must see the
        // exact bound port, not an independently autobound ephemeral socket.
        let sender = VsockAddr::from(client.local_addr().unwrap());
        f.send(
            defs::TSI_SENDTO_ADDR,
            &[
                &GUEST.to_le_bytes()[..],
                &sender.linux_len().to_le_bytes(),
                &sender.to_linux_bytes(),
            ]
            .concat(),
        );
        let response = if index == 0 { &b""[..] } else { &b"reply"[..] };
        let mut pkt = f.packet(defs::TSI_SENDTO_DATA, response);
        pkt.set_src_port(GUEST);
        f.muxer.send_dgram_pkt(&pkt).unwrap();
        let mut reply = [0; 16];
        let (len, sender) = client.recv_from(&mut reply).unwrap();
        assert_eq!(&reply[..len], response);
        assert_eq!(sender, bound);
    }
    f.release();
    assert!(f.muxer.pending_datagram_rx.lock().unwrap().is_empty());
}

#[test]
fn host_udp_connected_sends_preserve_empty_payloads_and_bound_port() {
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let mut f = Fixture::new(granted(), None);
        f.muxer.floor = FloorMode::MetadataOnly;
        let family = if ip.is_ipv4() {
            defs::LINUX_AF_INET
        } else {
            defs::LINUX_AF_INET6
        };
        f.create(defs::SOCK_DGRAM, family);
        let bound = f.bind(SocketAddr::new(ip, 0)).unwrap();
        let receiver = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let destination = VsockAddr::from(receiver.local_addr().unwrap());
        let request = [
            &GUEST.to_le_bytes()[..],
            &destination.linux_len().to_le_bytes(),
            &destination.to_linux_bytes(),
        ]
        .concat();
        f.send(defs::TSI_CONNECT, &request);
        assert!(matches!(
            f.muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { result: 0, .. })
        ));
        for payload in [&b""[..], &b"connected"[..]] {
            f.send(defs::TSI_SENDTO_ADDR, &request);
            let mut packet = f.packet(defs::TSI_SENDTO_DATA, payload);
            packet.set_src_port(GUEST);
            f.muxer.send_dgram_pkt(&packet).unwrap();
            let mut data = [0; 32];
            let (len, sender) = receiver.recv_from(&mut data).unwrap();
            assert_eq!(&data[..len], payload);
            assert_eq!(sender, bound);
        }
        f.release();
    }
}

impl Fixture {
    fn acknowledged_send(&mut self, sequence: u64, destination: SocketAddr, payload: &[u8]) -> i32 {
        let addr = VsockAddr::from(destination);
        self.send(
            defs::TSI_HOST_SENDTO_ADDR,
            &[
                &GUEST.to_le_bytes()[..],
                &addr.linux_len().to_le_bytes(),
                &sequence.to_le_bytes(),
                &addr.to_linux_bytes(),
            ]
            .concat(),
        );
        let mut packet = self.packet(defs::TSI_SENDTO_DATA, payload);
        packet.set_src_port(GUEST);
        self.muxer.send_dgram_pkt(&packet).unwrap();
        match self.muxer.rxq.lock().unwrap().pop().unwrap() {
            MuxerRx::HostSendResponse {
                peer_port,
                sequence: actual,
                result,
            } => {
                assert_eq!(peer_port, CONTROL);
                assert_eq!(actual, sequence);
                result
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}

#[test]
fn host_udp_acknowledges_actual_send_errors_and_denied_destinations() {
    let mut f = Fixture::new(granted(), None);
    f.muxer.floor = FloorMode::MetadataOnly;
    f.create(defs::SOCK_DGRAM, defs::LINUX_AF_INET);
    let bound = f.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let destination = receiver.local_addr().unwrap();
    let mut buf = [0; 32];
    for (seq, payload) in [(1, &b""[..]), (2, &b"sent"[..])] {
        assert_eq!(
            f.acknowledged_send(seq, destination, payload),
            payload.len() as i32
        );
        let (len, sender) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], payload);
        assert_eq!(sender, bound);
    }
    // The host rejects a real oversized IPv4 datagram; report its Linux errno.
    assert_eq!(f.acknowledged_send(3, destination, &vec![0; 65_508]), -90);
    f.muxer.floor = FloorMode::Strict;
    assert_eq!(f.acknowledged_send(4, destination, b"denied"), -13);
    receiver.set_nonblocking(true).unwrap();
    assert_eq!(
        receiver.recv_from(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    f.muxer.floor = FloorMode::MetadataOnly;
    assert_eq!(f.acknowledged_send(5, destination, b"recovered"), 9);
    receiver.set_nonblocking(false).unwrap();
    let (len, _) = receiver.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..len], b"recovered");
    f.release();
}

#[test]
fn a_denied_legacy_udp_destination_cannot_reuse_the_last_allowed_one() {
    let mut f = Fixture::new(TsiFlags::HIJACK_INET, None);
    f.muxer.floor = FloorMode::MetadataOnly;
    f.create(defs::SOCK_DGRAM, defs::LINUX_AF_INET);
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let destination = VsockAddr::from(receiver.local_addr().unwrap());
    let request = [
        &GUEST.to_le_bytes()[..],
        &destination.linux_len().to_le_bytes(),
        &destination.to_linux_bytes(),
    ]
    .concat();
    f.send(defs::TSI_SENDTO_ADDR, &request);
    let mut pkt = f.packet(defs::TSI_SENDTO_DATA, b"allowed");
    pkt.set_src_port(GUEST);
    f.muxer.send_dgram_pkt(&pkt).unwrap();
    let mut buf = [0; 32];
    assert_eq!(receiver.recv_from(&mut buf).unwrap().0, 7);
    f.muxer.floor = FloorMode::Strict;
    f.send(defs::TSI_SENDTO_ADDR, &request);
    let mut pkt = f.packet(defs::TSI_SENDTO_DATA, b"must not be sent");
    pkt.set_src_port(GUEST);
    f.muxer.send_dgram_pkt(&pkt).unwrap();
    receiver.set_nonblocking(true).unwrap();
    assert_eq!(
        receiver.recv_from(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    f.release();
}

#[test]
fn host_dns_replies_resume_after_refill_and_do_not_reach_reused_sockets() {
    use super::super::host_datagram::FRAME_HEADER;
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let mut f = Fixture::new(granted(), None);
        f.muxer.floor = FloorMode::MetadataOnly;
        let (sender, receiver) = crossbeam_channel::unbounded();
        f.muxer.dns_sender = Some(sender);
        let family = if ip.is_ipv4() {
            defs::LINUX_AF_INET
        } else {
            defs::LINUX_AF_INET6
        };
        f.create(defs::SOCK_DGRAM, family);
        f.bind(SocketAddr::new(ip, 0)).unwrap();
        let resolver = SocketAddr::new(ip, 53);
        assert_eq!(f.acknowledged_send(1, resolver, b"query"), 5);
        let request = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(request.query, b"query");
        let reply = request.host_reply.unwrap();
        assert_eq!(reply.source.inet(), Some(resolver));
        let identity = reply.identity.clone();
        let gate = f.muxer.snapshot_gate.clone();
        let activity = gate.enter();
        let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
        let payload: Vec<_> = (0..8192).map(|i| (i % 251) as u8).collect();
        // No guest descriptors: keep the whole answer until buffers arrive.
        assert!(
            !f.muxer
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .unwrap()
                .lock()
                .unwrap()
                .receive_dns(reply, payload.clone(), &activity)
        );
        assert!(f.muxer.pending_datagram_rx.lock().unwrap().contains(&id));
        let mem = f.mem.clone();
        let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
        let mut available = 0u16;
        let mut recovered = Vec::new();
        let mut sequence = None;
        while recovered.len() < payload.len() {
            let buffer = 0x30000;
            rx.dtable[0].set(buffer, (VSOCK_PKT_HDR_SIZE + 512) as u32, 2, 0);
            rx.avail.ring[available as usize % 8].set(0);
            available += 1;
            rx.avail.idx.set(available);
            assert!(f.muxer.resume_datagram_rx());
            let used = rx.used.ring[(available as usize - 1) % 8].get();
            let mut frame = vec![0; used.len as usize - VSOCK_PKT_HDR_SIZE];
            mem.read_slice(&mut frame, GuestAddress(buffer + VSOCK_PKT_HDR_SIZE as u64))
                .unwrap();
            let word = |at| u32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
            assert_eq!(word(4) as usize, payload.len());
            assert_eq!(word(8) as usize, recovered.len());
            assert_eq!(
                VsockAddr::parse_linux(&frame[16..FRAME_HEADER], word(12))
                    .unwrap()
                    .inet(),
                Some(resolver)
            );
            if let Some(previous) = sequence {
                assert_eq!(word(0), previous);
            }
            sequence = Some(word(0));
            recovered.extend_from_slice(&frame[FRAME_HEADER..]);
        }
        assert_eq!(recovered, payload);
        let current_peer = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        let current_addr = current_peer.local_addr().unwrap();
        let current = VsockAddr::from(current_addr);
        f.send(
            defs::TSI_CONNECT,
            &[
                &GUEST.to_le_bytes()[..],
                &current.linux_len().to_le_bytes(),
                &current.to_linux_bytes(),
            ]
            .concat(),
        );
        assert!(matches!(
            f.muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { result: 0, .. })
        ));
        rx.dtable[0].set(0x30000, (VSOCK_PKT_HDR_SIZE + 512) as u32, 2, 0);
        rx.avail.ring[available as usize % 8].set(0);
        rx.avail.idx.set(available + 1);
        let stale_peer = super::super::dns_filter::HostDnsReply {
            identity: identity.clone(),
            source: resolver.into(),
        };
        assert!(
            !f.muxer
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .unwrap()
                .lock()
                .unwrap()
                .receive_dns(stale_peer, b"old peer".to_vec(), &activity)
        );
        assert_eq!(
            rx.used.idx.get(),
            available,
            "reconnected socket must reject the old resolver"
        );
        let current_reply = super::super::dns_filter::HostDnsReply {
            identity: identity.clone(),
            source: current_addr.into(),
        };
        assert!(
            f.muxer
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .unwrap()
                .lock()
                .unwrap()
                .receive_dns(current_reply, b"current".to_vec(), &activity)
        );
        assert_eq!(rx.used.idx.get(), available + 1);
        f.release();
        f.create(defs::SOCK_DGRAM, family);
        f.bind(SocketAddr::new(ip, 0)).unwrap();
        let old = super::super::dns_filter::HostDnsReply {
            identity,
            source: resolver.into(),
        };
        assert!(
            !f.muxer
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .unwrap()
                .lock()
                .unwrap()
                .receive_dns(old, b"stale".to_vec(), &activity)
        );
        assert!(f.muxer.pending_datagram_rx.lock().unwrap().is_empty());
        f.release();
    }
}

#[test]
fn host_udp_failed_reconnect_keeps_dns_interception() {
    let mut f = Fixture::new(granted(), None);
    f.muxer.floor = FloorMode::MetadataOnly;
    let (sender, receiver) = crossbeam_channel::unbounded();
    f.muxer.dns_sender = Some(sender);
    f.create(defs::SOCK_DGRAM, defs::LINUX_AF_INET);
    let bound = f.bind("127.0.0.1:0".parse().unwrap()).unwrap();

    // A rejected family change leaves the original kernel socket connected.
    for (destination, expected) in [("127.0.0.1:53", 0), ("[::1]:53", -97)] {
        let addr = VsockAddr::from(destination.parse::<SocketAddr>().unwrap());
        f.send(
            defs::TSI_CONNECT,
            &[
                &GUEST.to_le_bytes()[..],
                &addr.linux_len().to_le_bytes(),
                &addr.to_linux_bytes(),
            ]
            .concat(),
        );
        let reply = f.muxer.rxq.lock().unwrap().pop();
        assert!(
            matches!(&reply, Some(MuxerRx::ConnResponse { result, .. }) if *result == expected),
            "connect to {destination}: {reply:?}"
        );
    }
    // Ask through the guest protocol to verify that the rejected reconnect
    // preserves the application's existing peer.
    f.send(
        defs::TSI_GETNAME,
        &[
            &GUEST.to_le_bytes()[..],
            &defs::TSI_PROXY_PORT.to_le_bytes(),
            &1u32.to_le_bytes(),
        ]
        .concat(),
    );
    let reply = f.muxer.rxq.lock().unwrap().pop();
    match reply {
        Some(MuxerRx::GetnameResponse { data, .. }) => {
            assert_eq!(data.result, 0);
            assert_eq!(data.addr.inet(), Some("127.0.0.1:53".parse().unwrap()));
        }
        other => panic!("unexpected peer response: {other:?}"),
    }
    let mut packet = f.packet(defs::TSI_PROXY_PORT, b"query");
    packet.set_src_port(GUEST);
    f.muxer.send_dgram_pkt(&packet).unwrap();
    let request = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(request.query, b"query");
    assert_eq!(
        request.host_reply.unwrap().source.inet(),
        Some("127.0.0.1:53".parse().unwrap())
    );

    // A successful reconnect away from DNS must clear interception instead.
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let addr = VsockAddr::from(peer.local_addr().unwrap());
    f.send(
        defs::TSI_CONNECT,
        &[
            &GUEST.to_le_bytes()[..],
            &addr.linux_len().to_le_bytes(),
            &addr.to_linux_bytes(),
        ]
        .concat(),
    );
    assert!(matches!(
        f.muxer.rxq.lock().unwrap().pop(),
        Some(MuxerRx::ConnResponse { result: 0, .. })
    ));
    let mut packet = f.packet(defs::TSI_PROXY_PORT, b"data");
    packet.set_src_port(GUEST);
    f.muxer.send_dgram_pkt(&packet).unwrap();
    let mut bytes = [0; 16];
    let (length, source) = peer.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..length], b"data");
    assert_eq!(source, bound);
    assert!(receiver.try_recv().is_err());
    f.release();
}

#[test]
fn host_udp_disconnect_is_capability_gated_and_does_not_allow_short_requests() {
    let mut f = Fixture::new(granted(), None);
    f.muxer.floor = FloorMode::MetadataOnly;
    f.create(defs::SOCK_DGRAM, defs::LINUX_AF_INET);
    f.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = VsockAddr::from(peer.local_addr().unwrap());
    f.send(
        defs::TSI_CONNECT,
        &[
            &GUEST.to_le_bytes()[..],
            &address.linux_len().to_le_bytes(),
            &address.to_linux_bytes(),
        ]
        .concat(),
    );
    assert!(matches!(
        f.muxer.rxq.lock().unwrap().pop(),
        Some(MuxerRx::ConnResponse { result: 0, .. })
    ));

    let disconnect = [&GUEST.to_le_bytes()[..], &2u32.to_le_bytes(), &[0, 0]].concat();
    for malformed in [
        disconnect[..9].to_vec(),
        [&GUEST.to_le_bytes()[..], &129u32.to_le_bytes(), &[0; 129]].concat(),
    ] {
        f.send(defs::TSI_CONNECT, &malformed);
        assert!(matches!(
            f.muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { result: -22, .. })
        ));
    }
    f.muxer.tsi_flags.remove(TsiFlags::HOST_BIND);
    f.send(defs::TSI_CONNECT, &disconnect);
    assert!(matches!(
        f.muxer.rxq.lock().unwrap().pop(),
        Some(MuxerRx::ConnResponse { result: -95, .. })
    ));
    f.send(
        defs::TSI_GETNAME,
        &[
            &GUEST.to_le_bytes()[..],
            &defs::TSI_PROXY_PORT.to_le_bytes(),
            &1u32.to_le_bytes(),
        ]
        .concat(),
    );
    match f.muxer.rxq.lock().unwrap().pop() {
        Some(MuxerRx::GetnameResponse { data, .. }) => {
            assert_eq!(data.result, 0);
            assert_eq!(data.addr.inet(), Some(peer.local_addr().unwrap()));
        }
        other => panic!("unexpected peer response: {other:?}"),
    }
    f.muxer.tsi_flags.insert(TsiFlags::HOST_BIND);
    for _ in 0..2 {
        f.send(defs::TSI_CONNECT, &disconnect);
        let expected = if cfg!(windows) { -95 } else { 0 };
        assert!(matches!(f.muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { result, .. }) if result == expected));
    }
    f.send(
        defs::TSI_GETNAME,
        &[
            &GUEST.to_le_bytes()[..],
            &defs::TSI_PROXY_PORT.to_le_bytes(),
            &1u32.to_le_bytes(),
        ]
        .concat(),
    );
    match f.muxer.rxq.lock().unwrap().pop() {
        Some(MuxerRx::GetnameResponse { data, .. }) => {
            assert_eq!(data.result, if cfg!(windows) { 0 } else { -107 });
            if cfg!(windows) {
                assert_eq!(data.addr.inet(), Some(peer.local_addr().unwrap()));
            }
        }
        other => panic!("unexpected peer response: {other:?}"),
    }
    f.release();
}

#[cfg(not(windows))]
#[test]
fn host_udp_queued_replies_survive_peer_changes_and_rx_backpressure() {
    use super::super::host_datagram::{FRAME_HEADER, wait_readable};
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
    ] {
        let host_ip = match ip {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip.into()),
            ip => ip,
        };
        for fixed in [false, true] {
            for transition in ["connect", "reconnect", "disconnect"] {
                let mut f = Fixture::new(granted(), None);
                f.muxer.floor = FloorMode::MetadataOnly;
                f.create(
                    defs::SOCK_DGRAM,
                    if ip.is_ipv4() {
                        defs::LINUX_AF_INET
                    } else {
                        defs::LINUX_AF_INET6
                    },
                );
                let requested = if fixed {
                    let reservation = UdpSocket::bind(SocketAddr::new(host_ip, 0)).unwrap();
                    SocketAddr::new(ip, reservation.local_addr().unwrap().port())
                } else {
                    SocketAddr::new(ip, 0)
                };
                let bound = f.bind(requested).unwrap();
                let first = UdpSocket::bind(SocketAddr::new(host_ip, 0)).unwrap();
                let second = UdpSocket::bind(SocketAddr::new(host_ip, 0)).unwrap();
                let first_addr = SocketAddr::new(ip, first.local_addr().unwrap().port());
                let connect = |f: &mut Fixture, addr: SocketAddr| {
                    let addr = VsockAddr::from(addr);
                    f.send(
                        defs::TSI_CONNECT,
                        &[
                            &GUEST.to_le_bytes()[..],
                            &addr.linux_len().to_le_bytes(),
                            &addr.to_linux_bytes(),
                        ]
                        .concat(),
                    );
                    assert!(matches!(
                        f.muxer.rxq.lock().unwrap().pop(),
                        Some(MuxerRx::ConnResponse { result: 0, .. })
                    ));
                };
                if transition != "connect" {
                    connect(&mut f, first_addr);
                }
                let destination = SocketAddr::new(host_ip, bound.port());
                first.send_to(b"", destination).unwrap();
                first.send_to(b"queued before change", destination).unwrap();
                let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
                {
                    let proxies = f.muxer.proxy_map.read().unwrap();
                    let mut proxy = proxies.get(&id).unwrap().lock().unwrap();
                    wait_readable(proxy.poll_handle());
                    proxy.process_event(EventSet::IN);
                }
                assert!(f.muxer.pending_datagram_rx.lock().unwrap().contains(&id));
                if transition == "disconnect" {
                    f.send(
                        defs::TSI_CONNECT,
                        &[&GUEST.to_le_bytes()[..], &2u32.to_le_bytes(), &[0, 0]].concat(),
                    );
                    assert!(matches!(
                        f.muxer.rxq.lock().unwrap().pop(),
                        Some(MuxerRx::ConnResponse { result: 0, .. })
                    ));
                } else {
                    connect(
                        &mut f,
                        SocketAddr::new(ip, second.local_addr().unwrap().port()),
                    );
                }
                if fixed {
                    assert_eq!(
                        UdpSocket::bind(destination).unwrap_err().kind(),
                        std::io::ErrorKind::AddrInUse
                    );
                }
                let mem = f.mem.clone();
                let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
                for (index, expected) in [b"".as_slice(), b"queued before change".as_slice()]
                    .iter()
                    .enumerate()
                {
                    rx.dtable[0].set(0x30000, (VSOCK_PKT_HDR_SIZE + 512) as u32, 2, 0);
                    rx.avail.ring[index].set(0);
                    rx.avail.idx.set((index + 1) as u16);
                    assert!(
                        f.muxer.resume_datagram_rx(),
                        "{ip} fixed={fixed} {transition} packet={index}"
                    );
                    let mut frame =
                        vec![0; rx.used.ring[index].get().len as usize - VSOCK_PKT_HDR_SIZE];
                    mem.read_slice(
                        &mut frame,
                        GuestAddress(0x30000 + VSOCK_PKT_HDR_SIZE as u64),
                    )
                    .unwrap();
                    let addr_len = u32::from_le_bytes(frame[12..16].try_into().unwrap());
                    let sender =
                        VsockAddr::parse_linux(&frame[16..FRAME_HEADER], addr_len).unwrap();
                    assert_eq!(sender.inet(), Some(first_addr));
                    assert_eq!(&frame[FRAME_HEADER..], *expected);
                }
                f.release();
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn host_udp_errors_clear_native_readiness_and_survive_rx_backpressure() {
    use super::super::host_datagram::wait_readable;
    let mut f = Fixture::new(granted(), None);
    f.muxer.floor = FloorMode::MetadataOnly;
    f.create(defs::SOCK_DGRAM, defs::LINUX_AF_INET);
    f.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let reserved = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = VsockAddr::from(reserved.local_addr().unwrap());
    drop(reserved);
    f.send(
        defs::TSI_CONNECT,
        &[
            &GUEST.to_le_bytes()[..],
            &destination.linux_len().to_le_bytes(),
            &destination.to_linux_bytes(),
        ]
        .concat(),
    );
    assert!(matches!(
        f.muxer.rxq.lock().unwrap().pop(),
        Some(MuxerRx::ConnResponse { result: 0, .. })
    ));
    let mut packet = f.packet(defs::TSI_PROXY_PORT, b"closed port");
    packet.set_src_port(GUEST);
    f.muxer.send_dgram_pkt(&packet).unwrap();
    let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
    let fd;
    {
        let proxies = f.muxer.proxy_map.read().unwrap();
        let mut proxy = proxies.get(&id).unwrap().lock().unwrap();
        fd = proxy.poll_handle();
        wait_readable(fd);
        assert!(!proxy.process_event(EventSet::ERROR).signal_queue);
    }
    assert!(f.muxer.pending_datagram_rx.lock().unwrap().contains(&id));
    let mut poll = Epoll::new().unwrap();
    poll.ctl(ControlOperation::Add, fd, &EpollEvent::new(EventSet::IN, 1))
        .unwrap();
    let mut events = [EpollEvent::default(); 1];
    assert_eq!(
        poll.wait(1, 0, &mut events).unwrap(),
        0,
        "unconsumed native error would spin the muxer"
    );
    let mem = f.mem.clone();
    let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
    rx.dtable[0].set(0x30000, (VSOCK_PKT_HDR_SIZE + 512) as u32, 2, 0);
    rx.avail.ring[0].set(0);
    rx.avail.idx.set(1);
    assert!(f.muxer.resume_datagram_rx());
    assert_eq!(rx.used.ring[0].get().len, VSOCK_PKT_HDR_SIZE as u32);
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x30000 + 16)).unwrap(),
        defs::TSI_PROXY_PORT
    );
    assert_eq!(
        mem.read_obj::<u16>(GuestAddress(0x30000 + 30)).unwrap(),
        uapi::VSOCK_OP_RST
    );
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x30000 + 32)).unwrap(),
        111
    );
    rx.avail.ring[1].set(0);
    rx.avail.idx.set(2);
    assert!(
        !f.muxer.resume_datagram_rx(),
        "an error must be delivered only once"
    );
    assert_eq!(rx.used.idx.get(), 1);
    f.release();
}

#[cfg(target_os = "macos")]
#[test]
fn host_udp_error_routing_rejects_other_flows_and_preserves_backpressure() {
    use super::super::macos_icmp::DatagramError;

    let mut f = Fixture::new(granted(), None);
    f.muxer.floor = FloorMode::MetadataOnly;
    f.create(defs::SOCK_DGRAM, defs::LINUX_AF_INET);
    let source = f.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").unwrap();
    let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
    for peer in [&first, &second] {
        let destination = VsockAddr::from(peer.local_addr().unwrap());
        f.send(
            defs::TSI_CONNECT,
            &[
                &GUEST.to_le_bytes()[..],
                &destination.linux_len().to_le_bytes(),
                &destination.to_linux_bytes(),
            ]
            .concat(),
        );
        assert!(matches!(
            f.muxer.rxq.lock().unwrap().pop(),
            Some(MuxerRx::ConnResponse { result: 0, .. })
        ));
        let proxies = f.muxer.proxy_map.read().unwrap();
        let mut proxy = proxies.get(&id).unwrap().lock().unwrap();
        let mut error = DatagramError {
            source,
            destination: peer.local_addr().unwrap(),
            errno: 111,
        };
        error.source.set_port(0);
        assert!(proxy.receive_host_error(&error).is_none());
        error.source = source;
        error.destination = if std::ptr::eq(peer, &first) {
            second.local_addr().unwrap()
        } else {
            first.local_addr().unwrap()
        };
        assert!(
            proxy.receive_host_error(&error).is_none(),
            "a different or previously connected peer must not receive the error"
        );
    }
    {
        let proxies = f.muxer.proxy_map.read().unwrap();
        let mut proxy = proxies.get(&id).unwrap().lock().unwrap();
        let update = proxy
            .receive_host_error(&DatagramError {
                source,
                destination: second.local_addr().unwrap(),
                errno: 111,
            })
            .unwrap();
        assert!(!update.signal_queue);
    }
    assert!(f.muxer.pending_datagram_rx.lock().unwrap().contains(&id));
    let mem = f.mem.clone();
    let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
    rx.dtable[0].set(0x30000, (VSOCK_PKT_HDR_SIZE + 512) as u32, 2, 0);
    rx.avail.ring[0].set(0);
    rx.avail.idx.set(1);
    assert!(f.muxer.resume_datagram_rx());
    assert_eq!(rx.used.ring[0].get().len, VSOCK_PKT_HDR_SIZE as u32);
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x30000 + 16)).unwrap(),
        defs::TSI_PROXY_PORT
    );
    assert_eq!(
        mem.read_obj::<u16>(GuestAddress(0x30000 + 30)).unwrap(),
        uapi::VSOCK_OP_RST
    );
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x30000 + 32)).unwrap(),
        111
    );
    rx.avail.ring[1].set(0);
    rx.avail.idx.set(2);
    assert!(!f.muxer.resume_datagram_rx());
    assert_eq!(rx.used.idx.get(), 1);
    f.release();
}

#[test]
fn host_socket_options_require_permission_and_an_existing_proxy() {
    let wire = [
        GUEST.to_le_bytes(),
        defs::TSI_PROXY_PORT.to_le_bytes(),
        1u32.to_le_bytes(),
        6u32.to_le_bytes(),
        1u32.to_le_bytes(),
    ]
    .concat();
    for (flags, map, body, expected) in [
        (TsiFlags::HIJACK_INET, None, wire.as_slice(), -1),
        (granted(), Some(HashMap::new()), wire.as_slice(), -1),
        (granted(), None, &wire[..19], -22),
        (granted(), None, wire.as_slice(), -9),
    ] {
        let mut f = Fixture::new(flags, map);
        f.send(defs::TSI_HOST_SETSOCKOPT, body);
        let Some(MuxerRx::BindResponse { data, .. }) = f.muxer.rxq.lock().unwrap().pop() else {
            panic!("missing option status");
        };
        let mut response = [0xa5; 136];
        assert_eq!(data.write(&mut response), 136);
        assert_eq!(
            i32::from_le_bytes(response[..4].try_into().unwrap()),
            expected
        );
        assert!(response[4..].iter().all(|byte| *byte == 0));
        assert!(f.muxer.proxy_map.read().unwrap().is_empty());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn shared_udp_redirects_survive_guest_receive_backpressure() {
    use super::super::host_datagram::{FRAME_HEADER, wait_readable};
    let mut f = Fixture::new(granted(), None);
    f.muxer.floor = FloorMode::MetadataOnly;
    f.create(defs::SOCK_DGRAM, defs::LINUX_AF_INET);
    let bound = f.bind("0.0.0.0:0".parse().unwrap()).unwrap();
    f.send(
        defs::TSI_HOST_SETSOCKOPT,
        &[
            GUEST.to_le_bytes(),
            defs::TSI_PROXY_PORT.to_le_bytes(),
            1u32.to_le_bytes(),
            2u32.to_le_bytes(),
            1u32.to_le_bytes(),
        ]
        .concat(),
    );
    let Some(MuxerRx::BindResponse { data, .. }) = f.muxer.rxq.lock().unwrap().pop() else {
        panic!("missing option status");
    };
    let mut status = [0; 136];
    data.write(&mut status);
    assert_eq!(i32::from_le_bytes(status[..4].try_into().unwrap()), 0);
    let second = GUEST + 1;
    f.send(
        defs::TSI_PROXY_CREATE,
        &[
            &second.to_le_bytes()[..],
            &defs::LINUX_AF_INET.to_le_bytes(),
            &defs::SOCK_DGRAM.to_le_bytes(),
        ]
        .concat(),
    );
    let addr = VsockAddr::from(bound);
    f.send(
        defs::TSI_BIND,
        &[
            &second.to_le_bytes()[..],
            &addr.linux_len().to_le_bytes(),
            &1u32.to_le_bytes(),
            &addr.to_linux_bytes(),
        ]
        .concat(),
    );
    assert_eq!(f.bind_result().unwrap(), bound);
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = SocketAddr::from(([127, 0, 0, 1], bound.port()));
    for payload in [b"".as_slice(), b"redirected".as_slice()] {
        sender.send_to(payload, destination).unwrap();
    }
    let first_id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
    let second_id = ((second as u64) << 32) | defs::TSI_PROXY_PORT as u64;
    {
        let map = f.muxer.proxy_map.read().unwrap();
        let mut proxy = map[&first_id].lock().unwrap();
        wait_readable(proxy.poll_handle());
        assert!(!proxy.process_event(EventSet::IN).signal_queue);
    }
    assert!(
        f.muxer
            .pending_datagram_rx
            .lock()
            .unwrap()
            .contains(&first_id)
    );
    // The packets already arrived for the second (latest) binding before
    // it changes peer, even though Darwin stored them on the first FD.
    let alternate = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = VsockAddr::from(alternate.local_addr().unwrap());
    f.send(
        defs::TSI_CONNECT,
        &[
            &second.to_le_bytes()[..],
            &peer.linux_len().to_le_bytes(),
            &peer.to_linux_bytes(),
        ]
        .concat(),
    );
    assert!(matches!(
        f.muxer.rxq.lock().unwrap().pop(),
        Some(MuxerRx::ConnResponse { result: 0, .. })
    ));
    let mem = f.mem.clone();
    let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
    rx.dtable[0].set(0x30000, (VSOCK_PKT_HDR_SIZE + 512) as u32, 2, 0);
    rx.avail.ring[0].set(0);
    rx.avail.idx.set(1);
    let delivered = f.muxer.resume_datagram_rx();
    let router = f.muxer.host_udp_router.as_ref().unwrap().as_ref().unwrap();
    assert_eq!(router.take_ready(), [second_id]);
    if !delivered {
        let map = f.muxer.proxy_map.read().unwrap();
        assert!(
            map[&second_id]
                .lock()
                .unwrap()
                .process_event(EventSet::IN)
                .signal_queue
        );
    }
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x30000 + 20)).unwrap(),
        second,
        "queued packets must retain the recipient selected before the peer change"
    );
    assert_eq!(
        rx.used.ring[0].get().len as usize,
        VSOCK_PKT_HDR_SIZE + FRAME_HEADER
    );
    assert!(
        f.muxer
            .pending_datagram_rx
            .lock()
            .unwrap()
            .contains(&second_id)
    );
    rx.avail.ring[1].set(0);
    rx.avail.idx.set(2);
    assert!(f.muxer.resume_datagram_rx());
    let mut payload = [0; 10];
    mem.read_slice(
        &mut payload,
        GuestAddress(0x30000 + (VSOCK_PKT_HDR_SIZE + FRAME_HEADER) as u64),
    )
    .unwrap();
    assert_eq!(&payload, b"redirected");
    rx.avail.ring[2].set(0);
    rx.avail.idx.set(3);
    assert!(!f.muxer.resume_datagram_rx());
    assert_eq!(rx.used.idx.get(), 2);
    f.send(
        defs::TSI_PROXY_RELEASE,
        &[
            &second.to_le_bytes()[..],
            &defs::TSI_PROXY_PORT.to_le_bytes(),
        ]
        .concat(),
    );
    f.release();
}

#[test]
fn accepted_socket_options_target_the_child_not_its_listener() {
    use super::super::proxy::Family;
    use socket2::{Domain, Socket, Type};
    let mut f = Fixture::new(granted(), None);
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    let accepted = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    let child_port = 4242u32;
    for (port, socket) in [(defs::TSI_PROXY_PORT, &listener), (child_port, &accepted)] {
        let id = ((GUEST as u64) << 32) | port as u64;
        let proxy = TsiStreamProxy::new_reverse(
            id,
            3,
            0,
            Family::Inet,
            port,
            GUEST,
            socket.try_clone().unwrap(),
            Default::default(),
            f.mem.clone(),
            f.muxer.queue.as_ref().unwrap().clone(),
            f.muxer.rxq.clone(),
            f.muxer.snapshot_gate.clone(),
        );
        f.muxer
            .proxy_map
            .write()
            .unwrap()
            .insert(id, Arc::new(Mutex::new(Box::new(proxy))));
    }
    f.send(
        defs::TSI_HOST_SETSOCKOPT,
        &[
            GUEST.to_le_bytes(),
            child_port.to_le_bytes(),
            6u32.to_le_bytes(),
            1u32.to_le_bytes(),
            1u32.to_le_bytes(),
        ]
        .concat(),
    );
    let Some(MuxerRx::BindResponse { data, .. }) = f.muxer.rxq.lock().unwrap().pop() else {
        panic!("missing option reply");
    };
    let mut status = [0u8; 136];
    data.write(&mut status);
    assert_eq!(i32::from_le_bytes(status[..4].try_into().unwrap()), 0);
    assert!(
        accepted.nodelay().unwrap(),
        "accepted transport must receive the option"
    );
    assert!(
        !listener.nodelay().unwrap(),
        "listener must retain its options"
    );
}

#[cfg(unix)]
#[test]
fn explicit_udp_buffers_survive_bind_and_update_the_actual_transport() {
    use socket2::SockRef;
    use std::os::fd::BorrowedFd;
    for family in [defs::LINUX_AF_INET, defs::LINUX_AF_INET6] {
        for before_bind in [false, true] {
            let mut f = Fixture::new(granted(), None);
            f.create(defs::SOCK_DGRAM, family);
            let addr = if family == defs::LINUX_AF_INET {
                "127.0.0.1:0"
            } else {
                "[::1]:0"
            }
            .parse()
            .unwrap();
            if !before_bind {
                f.bind(addr).unwrap();
            }
            for option in [7u32, 8u32] {
                f.send(
                    defs::TSI_HOST_SETSOCKOPT,
                    &[
                        GUEST.to_le_bytes(),
                        defs::TSI_PROXY_PORT.to_le_bytes(),
                        1u32.to_le_bytes(),
                        option.to_le_bytes(),
                        8192u32.to_le_bytes(),
                    ]
                    .concat(),
                );
                let Some(MuxerRx::BindResponse { data, .. }) = f.muxer.rxq.lock().unwrap().pop()
                else {
                    panic!("missing option result")
                };
                let mut response = [0; 136];
                data.write(&mut response);
                assert_eq!(i32::from_le_bytes(response[..4].try_into().unwrap()), 0);
            }
            if before_bind {
                f.bind(addr).unwrap();
            }
            let map = f.muxer.proxy_map.read().unwrap();
            let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
            let proxy = map.get(&id).unwrap().lock().unwrap();
            // The locked proxy owns the descriptor for the entire borrow.
            let fd = unsafe { BorrowedFd::borrow_raw(proxy.poll_handle()) };
            let socket = SockRef::from(&fd);
            assert_eq!(socket.recv_buffer_size().unwrap(), 8192);
            assert_eq!(
                socket.send_buffer_size().unwrap(),
                if cfg!(target_os = "macos") {
                    128 * 1024
                } else {
                    8192
                }
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn receive_buffer_options_control_routed_datagrams_before_and_after_bind() {
    use super::super::host_datagram::FRAME_HEADER;
    for (family, address) in [
        (defs::LINUX_AF_INET, "127.0.0.1:0"),
        (defs::LINUX_AF_INET6, "[::1]:0"),
    ] {
        for before_bind in [true, false] {
            for capacity in [8192u32, 2 * 1024 * 1024] {
                let mut f = Fixture::new(granted(), None);
                f.create(defs::SOCK_DGRAM, family);
                let mut bound = None;
                if !before_bind {
                    bound = Some(f.bind(address.parse().unwrap()).unwrap());
                }
                f.send(
                    defs::TSI_HOST_SETSOCKOPT,
                    &[
                        GUEST.to_le_bytes(),
                        defs::TSI_PROXY_PORT.to_le_bytes(),
                        1u32.to_le_bytes(),
                        8u32.to_le_bytes(),
                        capacity.to_le_bytes(),
                    ]
                    .concat(),
                );
                let Some(MuxerRx::BindResponse { data, .. }) = f.muxer.rxq.lock().unwrap().pop()
                else {
                    panic!("missing option status")
                };
                let mut status = [0; 136];
                data.write(&mut status);
                assert_eq!(i32::from_le_bytes(status[..4].try_into().unwrap()), 0);
                let bound = bound.unwrap_or_else(|| f.bind(address.parse().unwrap()).unwrap());
                let router = f
                    .muxer
                    .host_udp_router
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .clone();
                let sender = SocketAddr::new(bound.ip(), 4500);
                for index in 0..640u32 {
                    let mut payload = [83; 1024];
                    payload[..4].copy_from_slice(&index.to_le_bytes());
                    assert!(!router.route(0, bound.port(), sender, Some(bound.ip()), &payload));
                }
                let expected = if capacity == 8192 { 5 } else { 640 };
                let mem = f.mem.clone();
                let rx = TestQueue::new(GuestAddress(0x4000), &mem, 8);
                rx.dtable[0].set(0x30000, 2048, 2, 0);
                let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
                for index in 0..=expected {
                    rx.avail.ring[index % 8].set(0);
                    rx.avail.idx.set((index + 1) as u16);
                    let map = f.muxer.proxy_map.read().unwrap();
                    map[&id].lock().unwrap().process_event(EventSet::IN);
                    assert_eq!(rx.used.idx.get() as usize, (index + 1).min(expected));
                    if index < expected {
                        let mut payload = [0; 1024];
                        mem.read_slice(
                            &mut payload,
                            GuestAddress(0x30000 + (VSOCK_PKT_HDR_SIZE + FRAME_HEADER) as u64),
                        )
                        .unwrap();
                        assert_eq!(
                            u32::from_le_bytes(payload[..4].try_into().unwrap()),
                            index as u32
                        );
                        assert!(payload[4..].iter().all(|byte| *byte == 83));
                    }
                }
                f.release();
            }
        }
    }
}

#[test]
fn host_close_validates_permissions_and_wire_before_removing_a_socket() {
    let wire = [
        GUEST.to_le_bytes(),
        defs::TSI_PROXY_PORT.to_le_bytes(),
        0u32.to_le_bytes(),
        2u32.to_le_bytes(),
    ]
    .concat();
    let mut invalid = wire.clone();
    invalid[12] = 3;
    for (flags, map, body, expected) in [
        (TsiFlags::HIJACK_INET, None, wire.as_slice(), -1),
        (granted(), Some(HashMap::new()), wire.as_slice(), -1),
        (granted(), None, &wire[..15], -22),
        (granted(), None, invalid.as_slice(), -22),
    ] {
        let mut f = Fixture::new(flags, map);
        f.create(defs::SOCK_STREAM, defs::LINUX_AF_INET);
        f.send(defs::TSI_HOST_STREAM_CLOSE, body);
        let Some(MuxerRx::BindResponse {
            local_port,
            peer_port,
            data,
        }) = f.muxer.rxq.lock().unwrap().pop()
        else {
            panic!("missing close status")
        };
        assert_eq!(local_port, defs::TSI_HOST_STREAM_CLOSE);
        assert_eq!(peer_port, CONTROL);
        let mut response = [0xa5; 136];
        assert_eq!(data.write(&mut response), 136);
        assert_eq!(
            i32::from_le_bytes(response[..4].try_into().unwrap()),
            expected
        );
        assert!(response[4..].iter().all(|b| *b == 0));
        assert_eq!(f.muxer.proxy_map.read().unwrap().len(), 1);
        f.release();
    }
}

#[test]
fn only_waiting_closes_receive_status_and_repeated_close_is_complete() {
    for flags in [0u32, 1, 2] {
        let mut f = Fixture::new(granted(), None);
        f.create(defs::SOCK_STREAM, defs::LINUX_AF_INET);
        let wire = [
            GUEST.to_le_bytes(),
            defs::TSI_PROXY_PORT.to_le_bytes(),
            0u32.to_le_bytes(),
            flags.to_le_bytes(),
        ]
        .concat();
        for _ in 0..2 {
            f.send(defs::TSI_HOST_STREAM_CLOSE, &wire);
            assert!(f.muxer.proxy_map.read().unwrap().is_empty());
            let response = f.muxer.rxq.lock().unwrap().pop();
            if flags == 2 {
                let Some(MuxerRx::BindResponse { data, .. }) = response else {
                    panic!("missing close status")
                };
                let mut bytes = [0xa5; 136];
                data.write(&mut bytes);
                assert_eq!(bytes, [0; 136]);
            } else {
                assert!(response.is_none());
            }
        }
    }
}

#[test]
fn listener_shutdown_closes_only_the_listener_and_can_listen_again() {
    use std::io::{Read, Write};
    for (family, ip) in [
        (defs::LINUX_AF_INET, Ipv4Addr::LOCALHOST.into()),
        (defs::LINUX_AF_INET6, Ipv6Addr::LOCALHOST.into()),
    ] {
        for mode in [0u32, 1, 2] {
            let (mut f, listen) = listener_fixture(family, ip);
            let address = VsockAddr::parse_linux(
                &listen[16..],
                u32::from_le_bytes(listen[12..16].try_into().unwrap()),
            )
            .unwrap()
            .inet()
            .unwrap();
            let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let id = ((GUEST as u64) << 32) | defs::TSI_PROXY_PORT as u64;
            let update = {
                let proxies = f.muxer.proxy_map.read().unwrap();
                let mut listener = proxies[&id].lock().unwrap();
                // connect() can return before the nonblocking listener is
                // readable on macOS. Deliver an actual readiness event, as
                // the production muxer does, before attempting accept().
                super::super::host_datagram::wait_readable(listener.poll_handle());
                listener.process_event(EventSet::IN)
            };
            let (_, child, _, _) = update.new_proxy.unwrap();
            let mut child = TcpStream::from(child);
            let mut request = f.packet(
                defs::TSI_ACCEPT,
                &[&GUEST.to_le_bytes()[..], &0u32.to_le_bytes()].concat(),
            );
            request.set_src_port(CONTROL + 1);
            f.muxer.send_dgram_pkt(&request).unwrap();
            f.send(
                defs::TSI_LISTENER_SHUTDOWN,
                &[&GUEST.to_le_bytes()[..], &mode.to_le_bytes()].concat(),
            );
            if mode != 1 {
                assert!(
                    matches!(f.muxer.rxq.lock().unwrap().pop(), Some(MuxerRx::AcceptResponse { result: -22, peer_port, .. }) if peer_port == CONTROL + 1)
                );
            }
            let response = f.muxer.rxq.lock().unwrap().pop().unwrap();
            let MuxerRx::BindResponse {
                local_port,
                peer_port,
                data,
            } = response
            else {
                panic!("wrong shutdown response: {response:?}")
            };
            assert_eq!(local_port, defs::TSI_LISTENER_SHUTDOWN);
            assert_eq!(peer_port, CONTROL);
            let mut wire = [0; 136];
            data.write(&mut wire);
            assert_eq!(i32::from_le_bytes(wire[..4].try_into().unwrap()), 0);
            assert!(f.muxer.rxq.lock().unwrap().is_empty());
            child.write_all(b"alive").unwrap();
            let mut bytes = [0; 5];
            client.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"alive");
            if mode != 1 {
                assert!(TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err());
            } else {
                assert_eq!(
                    f.muxer.proxy_map.read().unwrap()[&id]
                        .lock()
                        .unwrap()
                        .status(),
                    ProxyStatus::WaitingOnAccept
                );
            }
            f.send(defs::TSI_LISTEN, &listen);
            assert!(matches!(
                f.muxer.rxq.lock().unwrap().pop(),
                Some(MuxerRx::ListenResponse { result: 0, .. })
            ));
            f.send(
                defs::TSI_GETNAME,
                &[
                    &GUEST.to_le_bytes()[..],
                    &defs::TSI_PROXY_PORT.to_le_bytes(),
                    &0u32.to_le_bytes(),
                ]
                .concat(),
            );
            let address = match f.muxer.rxq.lock().unwrap().pop().unwrap() {
                MuxerRx::GetnameResponse { data, .. } => {
                    assert_eq!(data.result, 0);
                    data.addr.inet().unwrap()
                }
                response => panic!("wrong local address response: {response:?}"),
            };
            let _next = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
            f.release();
        }
    }
}

#[test]
fn transport_reset_ack_is_not_blocked_by_a_guest_tx_reply() {
    use crate::legacy::DummyIrqChip;
    use crate::virtio::DeviceState;
    use polly::event_manager::{EventManager, Subscriber};
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;
    use std::thread;
    use utils::eventfd::EventFd;
    #[cfg(windows)]
    use utils::windows::AsRawFd;

    let f = Fixture::new(TsiFlags::empty(), None);
    let tx = TestQueue::new(GuestAddress(0x1000), &f.mem, 8);
    let tx_queue = tx.create_queue();
    // A restored guest can send on an obsolete stream before processing its
    // reset event. That packet requires an RST response through the RX gate.
    let mut packet = f.packet(12345, &[]);
    packet.set_type(uapi::VSOCK_TYPE_STREAM);
    let gate = f.muxer.snapshot_gate.clone();
    gate.hold_for_transport_reset();
    let mut device = super::super::device::Vsock::new(
        3,
        None,
        None,
        TsiFlags::empty(),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    device.queue_rx = f.muxer.queue.clone();
    device.queue_tx = Some(Arc::new(Mutex::new(tx_queue)));
    device.queue_events = (0..3)
        .map(|_| Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap()))
        .collect();
    device.device_state = DeviceState::Activated(
        f.mem.clone(),
        InterruptTransport::new(
            DummyIrqChip::new().into(),
            "reset acknowledgement test".into(),
        )
        .unwrap(),
    );
    device.muxer = f.muxer;
    device.awaiting_transport_reset_ack = true;
    let (finished, ready) = mpsc::channel();
    let (acknowledge, acknowledged) = mpsc::channel();
    let worker = thread::spawn(move || {
        let used = device.process_stream_tx();
        finished.send(used).unwrap();
        acknowledged.recv().unwrap();
        let event = device.queue_events[super::super::device::EVQ_INDEX].clone();
        event.write(1).unwrap();
        device.process(
            &EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64),
            &mut EventManager::new().unwrap(),
        );
        device
    });
    let returned_before_ack = ready.recv_timeout(Duration::from_secs(1));
    let used_before_ack = tx.used.idx.get();
    // Always release a broken implementation too, so regression failure does
    // not strand a thread blocked in the very deadlock this test reproduces.
    if returned_before_ack.is_err() {
        gate.release_transport_reset();
    }
    acknowledge.send(()).unwrap();
    let device = worker.join().unwrap();
    assert!(
        !returned_before_ack.unwrap(),
        "TX must wait without blocking the event loop"
    );
    assert_eq!(used_before_ack, 0);
    assert_eq!(
        tx.used.idx.get(),
        1,
        "acknowledgement must drain the held TX without another guest kick"
    );
    assert!(!gate.is_held_for_transport_reset());
    assert!(matches!(
        device.muxer.rxq.lock().unwrap().pop(),
        Some(MuxerRx::Reset {
            peer_port: CONTROL,
            ..
        })
    ));
}

#[test]
fn reset_ack_timeout_wakes_tx_after_releasing_the_matching_hold() {
    use std::time::Instant;
    use utils::eventfd::EventFd;

    let f = Fixture::new(TsiFlags::empty(), None);
    let event = Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
    f.muxer.hold_rx_for_transport_reset();
    f.muxer
        .arm_transport_reset_timeout(Duration::from_millis(1), event.clone());
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match event.read() {
            Ok(value) => {
                assert_eq!(value, 1);
                break;
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
        }
        assert!(
            Instant::now() < deadline,
            "reset timeout did not wake the device loop"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!f.muxer.rx_held_for_transport_reset());
}
