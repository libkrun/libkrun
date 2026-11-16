// SPDX-License-Identifier: Apache-2.0

//! Exercise actual guest packet dispatch, proxy state, and host sockets.
use super::super::packet::VSOCK_PKT_HDR_SIZE;
use super::*;
use crate::virtio::queue::tests::VirtQueue as TestQueue;
use std::net::{Ipv6Addr, SocketAddr, TcpStream};
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
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
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
