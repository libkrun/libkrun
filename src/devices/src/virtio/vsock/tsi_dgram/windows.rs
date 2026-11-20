use std::collections::HashMap;
use std::io::Error as IoError;
use std::mem::{size_of, size_of_val};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::Wrapping;
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};
use std::ptr::{from_ref, null_mut, read_unaligned, write_unaligned};
use std::slice;
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, CMSGHDR, FIONBIO, IN_PKTINFO, IN6_PKTINFO, INVALID_SOCKET, IP_PKTINFO,
    IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO, IPV6_V6ONLY, LPFN_WSARECVMSG, MSG_CTRUNC, MSG_TRUNC,
    SIO_GET_EXTENSION_FUNCTION_POINTER, SIO_UDP_CONNRESET, SOCK_DGRAM, SOCKADDR, SOCKET,
    SOCKET_ERROR, WSABUF, WSAECONNRESET, WSAEMSGSIZE, WSAEOPNOTSUPP, WSAEWOULDBLOCK,
    WSAGetLastError, WSAID_WSARECVMSG, WSAIoctl, WSAMSG, WSASendMsg, bind, closesocket, connect,
    getpeername, getsockname, ioctlsocket, sendto, setsockopt, socket,
};

use super::super::super::Queue as VirtQueue;
use super::super::super::linux_errno::wsa_errno_to_linux;
use super::super::defs;
use super::super::defs::uapi;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::muxer_rxq::MuxerRxQ;
use super::super::packet::{
    TsiBindReq, TsiConnectReq, TsiDatagram, TsiGetnameRsp, TsiProxyCreate, VsockPacket,
};
use super::super::proxy::{
    AsRawFd, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt, address_family_from_linux,
};
use super::super::tsi_wire::{
    DGRAM_HEADER_LEN, DGRAM_MAX_SIZE, DatagramInfo, ECONNREFUSED, encode_header,
};
use super::super::windows::sockaddr_storage::{
    SockaddrStorage, storage_to_winsock, winsock_to_storage,
};
use utils::epoll::EventSet;
use vm_memory::GuestMemoryMmap;

#[derive(Default)]
struct PacketControl([usize; 16]);

impl PacketControl {
    fn packet_info(&self, len: usize, ipv6: bool) -> Option<DatagramInfo> {
        let bytes = unsafe {
            slice::from_raw_parts(self.0.as_ptr().cast::<u8>(), len.min(size_of::<Self>()))
        };
        let mut offset = 0;
        let mut info = None;
        while bytes.len() - offset >= size_of::<CMSGHDR>() {
            let header = unsafe { read_unaligned(bytes[offset..].as_ptr().cast::<CMSGHDR>()) };
            if header.cmsg_len < size_of::<CMSGHDR>() || header.cmsg_len > bytes.len() - offset {
                return None;
            }
            let data = &bytes[offset + size_of::<CMSGHDR>()..offset + header.cmsg_len];
            if header.cmsg_level == IPPROTO_IP
                && header.cmsg_type == IP_PKTINFO
                && data.len() >= size_of::<IN_PKTINFO>()
            {
                let native = unsafe { read_unaligned(data.as_ptr().cast::<IN_PKTINFO>()) };
                let mut address = [0; 16];
                let v4 = unsafe { native.ipi_addr.S_un.S_addr }.to_ne_bytes();
                if ipv6 {
                    address[10..12].fill(0xff);
                    address[12..].copy_from_slice(&v4);
                } else {
                    address[..4].copy_from_slice(&v4);
                }
                info = Some(DatagramInfo {
                    address,
                    ifindex: native.ipi_ifindex,
                    hop_limit: None,
                });
            } else if header.cmsg_level == IPPROTO_IPV6
                && header.cmsg_type == IPV6_PKTINFO
                && data.len() >= size_of::<IN6_PKTINFO>()
            {
                let native = unsafe { read_unaligned(data.as_ptr().cast::<IN6_PKTINFO>()) };
                info = Some(DatagramInfo {
                    address: unsafe { native.ipi6_addr.u.Byte },
                    ifindex: native.ipi6_ifindex,
                    hop_limit: None,
                });
            }
            let next = (header.cmsg_len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
            if next > bytes.len() - offset {
                break;
            }
            offset += next;
        }
        info
    }

    fn source(&mut self, address: [u8; 16], ipv4: bool) -> usize {
        let pointer = self.0.as_mut_ptr().cast::<u8>();
        let len;
        let header;
        if ipv4 {
            let mut info = IN_PKTINFO::default();
            info.ipi_addr.S_un.S_addr = u32::from_ne_bytes(address[..4].try_into().unwrap());
            len = size_of::<CMSGHDR>() + size_of::<IN_PKTINFO>();
            header = CMSGHDR {
                cmsg_len: len,
                cmsg_level: IPPROTO_IP,
                cmsg_type: IP_PKTINFO,
            };
            unsafe {
                write_unaligned(pointer.add(size_of::<CMSGHDR>()).cast::<IN_PKTINFO>(), info);
            }
        } else {
            let mut info = IN6_PKTINFO::default();
            info.ipi6_addr.u.Byte = address;
            len = size_of::<CMSGHDR>() + size_of::<IN6_PKTINFO>();
            header = CMSGHDR {
                cmsg_len: len,
                cmsg_level: IPPROTO_IPV6,
                cmsg_type: IPV6_PKTINFO,
            };
            unsafe {
                write_unaligned(
                    pointer.add(size_of::<CMSGHDR>()).cast::<IN6_PKTINFO>(),
                    info,
                );
            }
        }
        unsafe {
            write_unaligned(pointer.cast::<CMSGHDR>(), header);
        }
        (len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
    }
}

fn create_dgram_socket(win_family: i32) -> Result<SOCKET, i32> {
    let sock = unsafe { socket(win_family, SOCK_DGRAM, 0) };
    if sock == INVALID_SOCKET {
        return Err(unsafe { WSAGetLastError() });
    }
    let mut mode: u32 = 1;
    if unsafe { ioctlsocket(sock, FIONBIO, &mut mode) } == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        unsafe {
            closesocket(sock);
        }
        return Err(e);
    }
    Ok(sock)
}

fn sock(proxy: &super::TsiDgramProxy) -> SOCKET {
    proxy.fd.as_raw_socket() as SOCKET
}

fn datagram_error(error: i32, host_connected: bool) -> Option<i32> {
    if error == WSAECONNRESET {
        host_connected.then_some(ECONNREFUSED)
    } else {
        Some(wsa_errno_to_linux(error))
    }
}

/// Winsock turns ICMP port-unreachable into WSAECONNRESET on the next receive
/// even for unconnected sockets, while Linux reports it only on connected ones.
fn report_port_unreachable(sock: SOCKET, enabled: bool) {
    let enabled = u32::from(enabled);
    let mut returned = 0;
    let result = unsafe {
        WSAIoctl(
            sock,
            SIO_UDP_CONNRESET,
            from_ref(&enabled).cast(),
            size_of::<u32>() as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR {
        warn!("SIO_UDP_CONNRESET failed: err={}", unsafe {
            WSAGetLastError()
        });
    }
}

pub(crate) fn create(
    id: u64,
    cid: u64,
    req: TsiProxyCreate,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
) -> Result<super::TsiDgramProxy, ProxyError> {
    let af = address_family_from_linux(req.family).ok_or(ProxyError::InvalidFamily)?;
    let win_family = af as i32;
    let sock = create_dgram_socket(win_family)
        .map_err(|e| ProxyError::CreatingSocket(IoError::from_raw_os_error(e)))?;

    let fd = unsafe { OwnedSocket::from_raw_socket(sock as RawSocket) };
    report_port_unreachable(sock, false);
    let mut recv_msg: LPFN_WSARECVMSG = None;
    let mut returned = 0;
    let result = unsafe {
        WSAIoctl(
            sock,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            from_ref(&WSAID_WSARECVMSG).cast(),
            size_of_val(&WSAID_WSARECVMSG) as u32,
            (&mut recv_msg as *mut LPFN_WSARECVMSG).cast(),
            size_of::<LPFN_WSARECVMSG>() as u32,
            &mut returned,
            null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR || recv_msg.is_none() {
        let error = if result == SOCKET_ERROR {
            unsafe { WSAGetLastError() }
        } else {
            WSAEOPNOTSUPP
        };
        return Err(ProxyError::CreatingSocket(IoError::from_raw_os_error(
            error,
        )));
    }
    let enabled = 1u32;
    if win_family == AF_INET6 as i32 {
        // Winsock IPv6 sockets default to v6-only, where IPPROTO_IP options
        // such as IP_PKTINFO fail. The dual-stack packet-info setup below
        // (both IP_PKTINFO and IPV6_PKTINFO, with mapped IPv4 handling in
        // PacketControl) requires a dual-stack socket: clear V6ONLY first.
        if unsafe {
            setsockopt(
                sock,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (&0u32 as *const u32).cast(),
                size_of::<u32>() as i32,
            )
        } == SOCKET_ERROR
        {
            return Err(ProxyError::CreatingSocket(IoError::from_raw_os_error(
                unsafe { WSAGetLastError() },
            )));
        }
    }
    // Winsock needs IP_PKTINFO on IPv6 sockets for mapped IPv4 packets.
    let mut options = vec![(IPPROTO_IP, IP_PKTINFO)];
    if win_family == AF_INET6 as i32 {
        options.push((IPPROTO_IPV6, IPV6_PKTINFO));
    }
    for (level, option) in options {
        if unsafe {
            setsockopt(
                sock,
                level,
                option,
                (&enabled as *const u32).cast(),
                size_of::<u32>() as i32,
            )
        } == SOCKET_ERROR
        {
            return Err(ProxyError::CreatingSocket(IoError::from_raw_os_error(
                unsafe { WSAGetLastError() },
            )));
        }
    }
    Ok(super::TsiDgramProxy {
        id,
        cid,
        local_port: defs::TSI_PROXY_PORT,
        peer_port: req.peer_port,
        fd,
        recv_msg,
        host_connected: false,
        status: ProxyStatus::Idle,
        pending_error: std::sync::atomic::AtomicI32::new(0),
        listening: false,
        family: af,
        protocol: req.protocol,
        mem,
        queue,
        rxq,
        rx_cnt: Wrapping(0),
        tx_cnt: Wrapping(0),
        peer_buf_alloc: 0,
        peer_fwd_cnt: Wrapping(0),
        guest_options: Default::default(),
    })
}

pub(crate) fn init_pkt(proxy: &super::TsiDgramProxy, pkt: &mut VsockPacket) {
    pkt.set_op(uapi::VSOCK_OP_RW)
        .set_src_cid(uapi::VSOCK_HOST_CID)
        .set_dst_cid(proxy.cid)
        .set_src_port(defs::TSI_DATAGRAM)
        .set_dst_port(proxy.peer_port)
        .set_type(uapi::VSOCK_TYPE_DGRAM)
        .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
        .set_fwd_cnt(proxy.tx_cnt.0);
}

pub(crate) fn recv_to_pkt(proxy: &super::TsiDgramProxy, pkt: &mut VsockPacket) -> RecvPkt {
    let Some(buf) = pkt.buf_mut() else {
        return RecvPkt::BadBuffer;
    };
    if buf.len() < DGRAM_HEADER_LEN {
        return RecvPkt::BadBuffer;
    }
    let capacity = buf.len().min(DGRAM_MAX_SIZE) - DGRAM_HEADER_LEN;
    let mut addr = [0u8; 128];
    let mut addr_len = addr.len() as i32;
    let mut data = WSABUF {
        len: capacity as u32,
        buf: buf[DGRAM_HEADER_LEN..].as_mut_ptr(),
    };
    let mut control = PacketControl::default();
    let mut message = WSAMSG {
        name: addr.as_mut_ptr().cast(),
        namelen: addr_len,
        lpBuffers: &mut data,
        dwBufferCount: 1,
        Control: WSABUF {
            len: size_of::<PacketControl>() as u32,
            buf: control.0.as_mut_ptr().cast(),
        },
        dwFlags: 0,
    };
    let mut received = 0;
    let result = unsafe {
        proxy.recv_msg.unwrap()(sock(proxy), &mut message, &mut received, null_mut(), None)
    };
    addr_len = message.namelen;
    let (count, truncated) = if result >= 0 {
        (received as usize, message.dwFlags & MSG_TRUNC != 0)
    } else {
        let error = unsafe { WSAGetLastError() };
        if error == WSAEMSGSIZE {
            (capacity, true)
        } else {
            if let Some(error) = datagram_error(error, proxy.host_connected) {
                proxy.record_error(error);
            }
            return RecvPkt::Error;
        }
    };
    let Some(address) = winsock_to_storage(&addr, addr_len) else {
        return RecvPkt::Error;
    };
    let bytes = unsafe { slice::from_raw_parts(address.as_ptr(), address.len() as usize) };
    if message.dwFlags & MSG_CTRUNC != 0 {
        return RecvPkt::Error;
    }
    let info = control.packet_info(message.Control.len as usize, proxy.family == AF_INET6);
    encode_header(buf, bytes, count, truncated, info);
    RecvPkt::Read(DGRAM_HEADER_LEN + count)
}

pub(crate) fn bind_datagram(
    proxy: &mut super::TsiDgramProxy,
    req: TsiBindReq,
    host_port_map: &Option<HashMap<u16, u16>>,
) -> Result<ProxyUpdate, i32> {
    let addr: SockaddrStorage = if let Some(mut inet) = req.addr.to_std_v4() {
        if proxy.family != AF_INET {
            return Err(-super::super::tsi_wire::EAFNOSUPPORT);
        }
        if let Some(port) = host_port_map
            .as_ref()
            .filter(|_| matches!(proxy.protocol, 0 | 17))
            .and_then(|map| map.get(&inet.port()))
        {
            inet.set_port(*port);
        }
        inet.into()
    } else if let Some(mut inet) = req.addr.to_std_v6() {
        if proxy.family != AF_INET6 {
            return Err(-super::super::tsi_wire::EAFNOSUPPORT);
        }
        if let Some(port) = host_port_map
            .as_ref()
            .filter(|_| matches!(proxy.protocol, 0 | 17))
            .and_then(|map| map.get(&inet.port()))
        {
            inet.set_port(*port);
        }
        inet.into()
    } else {
        return Err(-super::super::tsi_wire::EOPNOTSUPP);
    };
    let (bytes, len) = storage_to_winsock(&addr).ok_or(-super::super::tsi_wire::EINVAL)?;
    if unsafe { bind(sock(proxy), bytes.as_ptr().cast(), len) } == SOCKET_ERROR {
        return Err(-wsa_errno_to_linux(unsafe { WSAGetLastError() }));
    }
    proxy.listening = true;
    Ok(ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    })
}

pub(crate) fn do_connect(
    proxy: &mut super::TsiDgramProxy,
    pkt: &VsockPacket,
    req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let (sa_bytes, sa_len) = match storage_to_winsock(&req.addr) {
        Some(v) => v,
        None => return update,
    };

    let res = unsafe { connect(sock(proxy), sa_bytes.as_ptr() as *const SOCKADDR, sa_len) };

    let err_code = if res == SOCKET_ERROR {
        let e = unsafe { WSAGetLastError() };
        if e != WSAEWOULDBLOCK {
            debug!("dgram connect error: id={} err={e}", proxy.id);
        }
        -wsa_errno_to_linux(e as i32)
    } else {
        report_port_unreachable(sock(proxy), true);
        proxy.host_connected = true;
        proxy.status = ProxyStatus::Connected;
        0
    };

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    // Push the connection response packet back to the guest virtual queue
    let rx = MuxerRx::ConnResponse {
        request_id: pkt.control_request_id(),
        operation: pkt.control_operation(),
        peer_port: pkt.src_port(),
        result: err_code,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    if err_code == 0 && !proxy.listening {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
    }

    update
}

pub(crate) fn do_disconnect(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket) -> ProxyUpdate {
    let mut addr = [0u8; 28];
    let len = if proxy.family == AF_INET { 16 } else { 28 };
    // Winsock dissolves a UDP association with a zero destination address.
    addr[..2].copy_from_slice(&proxy.family.to_ne_bytes());
    let res = unsafe { connect(sock(proxy), addr.as_ptr().cast(), len) };
    let result = if res == SOCKET_ERROR {
        -wsa_errno_to_linux(unsafe { WSAGetLastError() })
    } else {
        report_port_unreachable(sock(proxy), false);
        proxy.host_connected = false;
        proxy.status = ProxyStatus::Idle;
        0
    };
    let rx = MuxerRx::ConnResponse {
        request_id: pkt.control_request_id(),
        operation: pkt.control_operation(),
        peer_port: pkt.src_port(),
        result,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
    ProxyUpdate::default()
}

pub(crate) fn do_getname(proxy: &mut super::TsiDgramProxy, pkt: &VsockPacket, peer: bool) {
    let mut sa_buf = [0u8; 128]; // Size matching SOCKADDR_STORAGE
    let mut sa_len = sa_buf.len() as i32;

    let res = unsafe {
        if peer {
            getpeername(sock(proxy), sa_buf.as_mut_ptr().cast(), &mut sa_len)
        } else {
            getsockname(sock(proxy), sa_buf.as_mut_ptr().cast(), &mut sa_len)
        }
    };

    let (result, addr) = if res == 0 && (0..=128).contains(&sa_len) {
        // Adjust the method slice match based on your tsi_stream implementation format
        match winsock_to_storage(&sa_buf, sa_len) {
            Some(storage) => (0, storage),
            None => (-1, SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into()),
        }
    } else {
        let e = unsafe { WSAGetLastError() };
        (
            -wsa_errno_to_linux(e as i32),
            SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
        )
    };

    let data = TsiGetnameRsp {
        result,
        addr_len: addr.len(),
        addr,
    };
    let rx = MuxerRx::GetnameResponse {
        request_id: pkt.control_request_id(),
        operation: pkt.control_operation(),
        peer_port: pkt.src_port(),
        data,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn send_datagram(
    proxy: &mut super::TsiDgramProxy,
    datagram: TsiDatagram<'_>,
) -> ProxyUpdate {
    let wire_len = datagram.wire_len();
    let TsiDatagram {
        address: addr,
        info,
        payload: data,
    } = datagram;
    let Some((bytes, len)) = storage_to_winsock(&addr) else {
        return ProxyUpdate::default();
    };
    let result = if let Some(info) = info {
        let mapped = addr
            .to_std_v6()
            .is_some_and(|address| address.ip().to_ipv4_mapped().is_some());
        let mut source = info.address;
        if mapped {
            if source[..12] != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                proxy.record_error(super::super::tsi_wire::EINVAL);
                return ProxyUpdate::default();
            }
            source.copy_within(12..16, 0);
            source[4..].fill(0);
        }
        let mut control = PacketControl::default();
        let control_len = control.source(source, proxy.family == AF_INET || mapped);
        let mut buffer = WSABUF {
            len: data.len() as u32,
            buf: data.as_ptr() as _,
        };
        let message = WSAMSG {
            name: bytes.as_ptr() as _,
            namelen: len,
            lpBuffers: &mut buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: control_len as u32,
                buf: control.0.as_mut_ptr().cast(),
            },
            dwFlags: 0,
        };
        let mut sent = 0;
        unsafe { WSASendMsg(sock(proxy), &message, 0, &mut sent, null_mut(), None) }
    } else {
        unsafe {
            sendto(
                sock(proxy),
                data.as_ptr() as _,
                data.len() as i32,
                0,
                bytes.as_ptr() as *const SOCKADDR,
                len,
            )
        }
    };
    if result < 0 {
        let error = unsafe { WSAGetLastError() };
        if let Some(error) = datagram_error(error, proxy.host_connected) {
            proxy.record_error(error);
        }
        return ProxyUpdate::default();
    }
    proxy.tx_cnt += Wrapping(wire_len);
    proxy.listening = true;
    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    }
}

pub(crate) fn update_peer_credit(
    proxy: &mut super::TsiDgramProxy,
    pkt: &VsockPacket,
) -> ProxyUpdate {
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());
    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    }
}

pub(crate) fn release(_proxy: &mut super::TsiDgramProxy) -> ProxyUpdate {
    ProxyUpdate {
        remove_proxy: ProxyRemoval::Immediate,
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::TsiDgramProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        update.remove_proxy = if proxy.status == ProxyStatus::Listening {
            ProxyRemoval::Immediate
        } else {
            ProxyRemoval::Deferred
        };
        return update;
    }

    if evset.contains(EventSet::IN) {
        let (signal_queue, wait_credit) = proxy.recv_pkt();
        update.signal_queue = signal_queue || wait_credit;

        // Correctly handle credit depletion state transitions and alert the guest
        if wait_credit && proxy.status != ProxyStatus::WaitingCreditUpdate {
            proxy.status = ProxyStatus::WaitingCreditUpdate;
            let rx = MuxerRx::CreditRequest {
                local_port: proxy.local_port,
                peer_port: proxy.peer_port,
                fwd_cnt: proxy.tx_cnt.0,
            };
            update.push_credit_req = Some(rx);
        }

        // Suppress incoming event loop reads until credit constraints clear to block a 100% CPU spin-loop
        if proxy.status == ProxyStatus::WaitingCreditUpdate {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        }
    }

    update
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_unreachable_only_reports_an_error_with_a_connected_host_peer() {
        assert_eq!(datagram_error(WSAECONNRESET, false), None);
        assert_eq!(datagram_error(WSAECONNRESET, true), Some(ECONNREFUSED));
        for connected in [false, true] {
            let expected = wsa_errno_to_linux(WSAEOPNOTSUPP);
            assert_eq!(datagram_error(WSAEOPNOTSUPP, connected), Some(expected));
        }
    }
}
