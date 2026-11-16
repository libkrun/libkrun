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
