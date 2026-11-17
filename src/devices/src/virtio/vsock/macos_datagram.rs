// SPDX-License-Identifier: Apache-2.0

//! Linux UDP peer semantics over a permanently unconnected Darwin socket.
//! Connecting a separate route probe avoids changing the reserved receive
//! socket; per-message packet info supplies the selected source address.

use std::collections::VecDeque;
use std::io;
use std::mem::{MaybeUninit, size_of, size_of_val, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::{Arc, Mutex};

use super::macos_udp_router::{DatagramRouter, Endpoint};

use socket2::{Domain, SockAddr, Socket, Type};

const MAX_SAVED_BYTES: usize = 256 * 1024;
const MAX_SAVED_DATAGRAMS: usize = 512;
#[cfg(test)]
const MAX_DATAGRAM: usize = super::host_datagram::MAX_DATAGRAM;

pub struct MacDatagram {
    original: SocketAddr,
    selected: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    deferred_bind: bool,
    saved: VecDeque<(SocketAddr, Box<[u8]>)>,
    saved_bytes: usize,
    router: Arc<DatagramRouter>,
    endpoint: Arc<Mutex<Endpoint>>,
    registered_port: Option<u16>,
}

pub(super) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

pub(super) fn canonical_peer(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V6(peer) => match peer.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(ip.into(), peer.port()),
            None => SocketAddrV6::new(*peer.ip(), peer.port(), 0, peer.scope_id()).into(),
        },
        peer => peer,
    }
}

fn receive_packet_info(socket: &Socket, ipv4: bool) -> io::Result<()> {
    let (level, option) = if ipv4 {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    };
    let enabled = 1i32;
    // SAFETY: the option is an integer and the socket remains owned by caller.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&enabled as *const i32).cast(),
            size_of::<i32>() as _,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn is_broadcast(ip: Ipv4Addr) -> io::Result<bool> {
    if ip.is_broadcast() {
        return Ok(true);
    }
    let mut head = ptr::null_mut();
    // SAFETY: getifaddrs initializes an owned list; all pointers below are
    // checked before access and the list is freed exactly once.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut current = head;
        let mut found = false;
        while let Some(interface) = current.as_ref() {
            if interface.ifa_flags & libc::IFF_BROADCAST as u32 != 0
                && !interface.ifa_dstaddr.is_null()
                && (*interface.ifa_dstaddr).sa_family as i32 == libc::AF_INET
            {
                let address = &*interface.ifa_dstaddr.cast::<libc::sockaddr_in>();
                if Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()) == ip {
                    found = true;
                    break;
                }
            }
            current = interface.ifa_next;
        }
        libc::freeifaddrs(head);
        Ok(found)
    }
}

impl MacDatagram {
    pub fn new(
        socket: &Arc<Socket>,
        original: SocketAddr,
        ipv4: bool,
        id: u64,
        router: Arc<DatagramRouter>,
    ) -> io::Result<Self> {
        receive_packet_info(socket, ipv4)?;
        Ok(Self {
            original,
            selected: None,
            peer: None,
            deferred_bind: false,
            saved: VecDeque::new(),
            saved_bytes: 0,
            router,
            endpoint: Arc::new(Mutex::new(Endpoint::new(id, original, false))),
            registered_port: None,
        })
    }

    pub fn bound(
        &mut self,
        socket: &Arc<Socket>,
        actual: SocketAddr,
        reuse_port: bool,
        only_v6: bool,
    ) {
        let id = self.endpoint.lock().unwrap().id;
        if let Some(port) = self.registered_port
            && port != actual.port()
        {
            self.router.unregister(id, port);
        }
        {
            let mut entry = self.endpoint.lock().unwrap();
            entry.bound = actual;
            entry.socket = Arc::downgrade(socket);
            entry.only_v6 = only_v6;
            entry.reuse_port = reuse_port;
            entry.order = self.router.next_order();
        }
        self.router.register(&self.endpoint);
        self.registered_port = Some(actual.port());
    }

    pub fn set_reuse_port(&self, enabled: bool) {
        self.endpoint.lock().unwrap().reuse_port = enabled;
    }

    fn update_peer(&self) {
        let mut entry = self.endpoint.lock().unwrap();
        entry.peer = self.peer;
        entry.selected = self.selected;
        entry.order = self.router.next_order();
    }

    fn guest_address(&self, address: SocketAddr) -> SocketAddr {
        let address = canonical_peer(address);
        if self.original.is_ipv6()
            && let SocketAddr::V4(address) = address
        {
            return SocketAddrV6::new(address.ip().to_ipv6_mapped(), address.port(), 0, 0).into();
        }
        address
    }

    fn bind_if_needed(&mut self, socket: &Arc<Socket>) -> io::Result<()> {
        if self.deferred_bind {
            socket.bind(&self.original.into())?;
            let actual = socket
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            let (reuse_port, only_v6) = {
                let entry = self.endpoint.lock().unwrap();
                (entry.reuse_port, entry.only_v6)
            };
            self.bound(socket, actual, reuse_port, only_v6);
            self.deferred_bind = false;
        }
        Ok(())
    }

    pub fn connect(&mut self, socket: &Arc<Socket>, destination: SocketAddr) -> io::Result<()> {
        if !socket.broadcast()?
            && let IpAddr::V4(ip) = canonical_ip(destination.ip())
            && is_broadcast(ip)?
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        self.bind_if_needed(socket)?;
        let probe = Socket::new(Domain::for_address(self.original), Type::DGRAM, None)?;
        probe.set_broadcast(socket.broadcast()?)?;
        if self.original.is_ipv6() {
            probe.set_only_v6(socket.only_v6()?)?;
        }
        let mut source = self.original;
        source.set_port(0);
        probe.bind(&source.into())?;
        probe.connect(&destination.into())?;
        let peer = probe
            .peer_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let mut selected = probe
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        selected.set_port(socket.local_addr()?.as_socket().unwrap().port());
        self.save_received(socket)?;
        self.peer = Some(self.guest_address(peer));
        self.selected = Some(self.guest_address(selected));
        self.update_peer();
        Ok(())
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTCONN))
    }

    pub fn local_addr(&self, socket: &Socket) -> io::Result<SocketAddr> {
        if self.deferred_bind {
            return Ok(self.original);
        }
        if let Some(selected) = self.selected {
            return Ok(selected);
        }
        socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
    }

    /// Prepare before altering poll registration or dropping the old socket.
    /// A fixed port keeps its original descriptor and exclusive reservation.
    pub fn replacement_for_disconnect(&self, socket: &Socket) -> io::Result<Option<Socket>> {
        if self.original.port() != 0 || self.deferred_bind {
            return Ok(None);
        }
        let replacement = Socket::new(Domain::for_address(self.original), Type::DGRAM, None)?;
        replacement.set_nonblocking(true)?;
        replacement.set_reuse_address(socket.reuse_address()?)?;
        replacement.set_reuse_port(socket.reuse_port()?)?;
        replacement.set_broadcast(socket.broadcast()?)?;
        replacement.set_keepalive(socket.keepalive()?)?;
        replacement.set_send_buffer_size(socket.send_buffer_size()?)?;
        replacement.set_recv_buffer_size(socket.recv_buffer_size()?)?;
        if self.original.is_ipv6() {
            replacement.set_only_v6(socket.only_v6()?)?;
            replacement.set_unicast_hops_v6(socket.unicast_hops_v6()?)?;
        } else {
            replacement.set_ttl(socket.ttl()?)?;
        }
        receive_packet_info(&replacement, self.original.is_ipv4())?;
        Ok(Some(replacement))
    }

    pub fn disconnected(&mut self) {
        self.selected = None;
        self.peer = None;
        self.deferred_bind = self.original.port() == 0;
        self.update_peer();
        if self.deferred_bind
            && let Some(port) = self.registered_port.take()
        {
            self.router
                .unregister(self.endpoint.lock().unwrap().id, port);
        }
    }

    pub fn send_to(
        &mut self,
        socket: &Arc<Socket>,
        bytes: &[u8],
        destination: SocketAddr,
    ) -> io::Result<usize> {
        self.bind_if_needed(socket)?;
        let Some(selected) = self.selected else {
            return socket.send_to(bytes, &destination.into());
        };
        let address = SockAddr::from(destination);
        let mut control = [0usize; 16];
        let mut vector = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: every pointer references live, correctly sized storage for the
        // duration of sendmsg; the aligned control buffer is larger than either
        // packet-info record and is initialized before the kernel reads it.
        unsafe {
            let mut message: libc::msghdr = zeroed();
            message.msg_name = address.as_ptr().cast_mut().cast();
            message.msg_namelen = address.len();
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            let header = message.msg_control.cast::<libc::cmsghdr>();
            let payload_size = match canonical_ip(selected.ip()) {
                IpAddr::V4(ip) => {
                    let info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(ip.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    (*header).cmsg_level = libc::IPPROTO_IP;
                    (*header).cmsg_type = libc::IP_PKTINFO;
                    ptr::write_unaligned(libc::CMSG_DATA(header).cast(), info);
                    size_of::<libc::in_pktinfo>()
                }
                IpAddr::V6(ip) => {
                    let info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: ip.octets(),
                        },
                        ipi6_ifindex: 0,
                    };
                    (*header).cmsg_level = libc::IPPROTO_IPV6;
                    (*header).cmsg_type = libc::IPV6_PKTINFO;
                    ptr::write_unaligned(libc::CMSG_DATA(header).cast(), info);
                    size_of::<libc::in6_pktinfo>()
                }
            };
            (*header).cmsg_len = libc::CMSG_LEN(payload_size as _) as _;
            message.msg_controllen = libc::CMSG_SPACE(payload_size as _) as _;
            let result = libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_DONTWAIT);
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as usize)
            }
        }
    }

    pub fn matches_error(&self, source: SocketAddr, destination: SocketAddr) -> bool {
        self.peer
            .is_some_and(|peer| canonical_peer(peer) == canonical_peer(destination))
            && self
                .selected
                .is_some_and(|local| canonical_peer(local) == canonical_peer(source))
    }

    pub fn has_saved(&self) -> bool {
        !self.saved.is_empty() || self.endpoint.lock().unwrap().has_packets()
    }

    fn admits(&self, sender: SocketAddr, destination: Option<IpAddr>) -> bool {
        !self
            .peer
            .is_some_and(|peer| canonical_peer(peer) != canonical_peer(sender))
            && !self.selected.is_some_and(|selected| {
                Some(canonical_ip(selected.ip())) != destination.map(canonical_ip)
            })
    }

    /// Linux retains packets already received under the previous peer policy.
    /// Capture them before changing that policy or replacing an auto-bound FD.
    /// Limit both storage and work; on pressure the caller keeps the old peer,
    /// delivers captured packets, and the guest can retry the transition.
    pub fn save_received(&mut self, _socket: &Socket) -> io::Result<()> {
        if let Some(port) = self.registered_port {
            self.router.capture_port(port)?;
        }
        loop {
            let packet = {
                let mut entry = self.endpoint.lock().unwrap();
                if let Some(length) = entry.next_len()
                    && (self.saved.len() == MAX_SAVED_DATAGRAMS
                        || self.saved_bytes + length > MAX_SAVED_BYTES)
                {
                    return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
                }
                entry.pop()
            };
            let Some((sender, payload)) = packet else {
                return Ok(());
            };
            self.saved_bytes += payload.len();
            self.saved.push_back((self.guest_address(sender), payload));
        }
    }

    pub fn receive(
        &mut self,
        socket: &Socket,
        bytes: &mut [MaybeUninit<u8>],
    ) -> io::Result<(usize, SocketAddr)> {
        if let Some((sender, payload)) = self.saved.pop_front() {
            self.saved_bytes -= payload.len();
            let length = bytes.len().min(payload.len());
            for (byte, value) in bytes.iter_mut().zip(&payload[..length]) {
                byte.write(*value);
            }
            return Ok((length, sender));
        }
        let routed = self.endpoint.lock().unwrap().pop();
        if let Some((sender, payload)) = routed {
            let length = bytes.len().min(payload.len());
            for (byte, value) in bytes.iter_mut().zip(&payload[..length]) {
                byte.write(*value);
            }
            return Ok((length, self.guest_address(sender)));
        }
        // Bound work even if another host process floods this port with packets
        // from a peer which the Linux guest has not connected to.
        for _ in 0..32 {
            let (id, port) = {
                let entry = self.endpoint.lock().unwrap();
                (entry.id, entry.bound.port())
            };
            let Some((length, sender, destination)) =
                self.router.receive(id, port, socket, bytes)?
            else {
                continue;
            };
            if self.admits(sender, destination) {
                return Ok((length, self.guest_address(sender)));
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Drop for MacDatagram {
    fn drop(&mut self) {
        if let Some(port) = self.registered_port {
            self.router
                .unregister(self.endpoint.lock().unwrap().id, port);
        }
    }
}

pub(super) fn receive_with_destination(
    socket: &Socket,
    bytes: &mut [MaybeUninit<u8>],
    flags: i32,
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let mut control = [0usize; 16];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: recvmsg writes only within the supplied address, payload, and
    // ancillary buffers; returned lengths bound all later interpretation.
    unsafe {
        let mut address: libc::sockaddr_storage = zeroed();
        let mut message: libc::msghdr = zeroed();
        message.msg_name = (&mut address as *mut libc::sockaddr_storage).cast();
        message.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control) as _;
        let result = libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_DONTWAIT | flags);
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let sender = SockAddr::new(address, message.msg_namelen)
            .as_socket()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let mut destination = None;
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::IPPROTO_IP
                && (*header).cmsg_type == libc::IP_PKTINFO
                && (*header).cmsg_len as usize
                    >= libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as _) as usize
            {
                let info: libc::in_pktinfo = ptr::read_unaligned(libc::CMSG_DATA(header).cast());
                destination = Some(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into());
            }
            if (*header).cmsg_level == libc::IPPROTO_IPV6
                && (*header).cmsg_type == libc::IPV6_PKTINFO
                && (*header).cmsg_len as usize
                    >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as _) as usize
            {
                let info: libc::in6_pktinfo = ptr::read_unaligned(libc::CMSG_DATA(header).cast());
                destination = Some(Ipv6Addr::from(info.ipi6_addr.s6_addr).into());
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        Ok((result as usize, sender, destination))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    #[test]
    fn disconnect_replacement_retains_host_socket_options() {
        for original in ["127.0.0.1:0", "[::1]:0"] {
            let original: SocketAddr = original.parse().unwrap();
            let socket =
                Arc::new(Socket::new(Domain::for_address(original), Type::DGRAM, None).unwrap());
            socket.set_keepalive(true).unwrap();
            socket.set_broadcast(true).unwrap();
            socket.set_reuse_address(true).unwrap();
            socket.set_reuse_port(true).unwrap();
            if original.is_ipv6() {
                socket.set_only_v6(true).unwrap();
                socket.set_unicast_hops_v6(83).unwrap();
            } else {
                socket.set_ttl(37).unwrap();
            }
            let adapter = MacDatagram::new(
                &socket,
                original,
                original.is_ipv4(),
                1,
                Arc::new(DatagramRouter::new(&utils::epoll::Epoll::new().unwrap()).unwrap()),
            )
            .unwrap();
            let replacement = adapter
                .replacement_for_disconnect(&socket)
                .unwrap()
                .unwrap();
            assert!(replacement.keepalive().unwrap());
            assert!(replacement.broadcast().unwrap());
            assert!(replacement.reuse_address().unwrap());
            assert!(replacement.reuse_port().unwrap());
            if original.is_ipv6() {
                assert!(replacement.only_v6().unwrap());
                assert_eq!(replacement.unicast_hops_v6().unwrap(), 83);
            } else {
                assert_eq!(replacement.ttl().unwrap(), 37);
            }
        }
    }

    #[test]
    fn mapped_ipv4_replies_keep_the_guest_ipv6_family() {
        for bind in ["[::ffff:127.0.0.1]:0", "[::]:0"] {
            let original: SocketAddr = bind.parse().unwrap();
            let socket = Arc::new(Socket::new(Domain::IPV6, Type::DGRAM, None).unwrap());
            socket.set_only_v6(false).unwrap();
            socket.set_nonblocking(true).unwrap();
            socket.bind(&original.into()).unwrap();
            let mut adapter = MacDatagram::new(
                &socket,
                original,
                false,
                1,
                Arc::new(DatagramRouter::new(&utils::epoll::Epoll::new().unwrap()).unwrap()),
            )
            .unwrap();
            adapter.bound(
                &socket,
                socket.local_addr().unwrap().as_socket().unwrap(),
                false,
                false,
            );
            let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let destination = SocketAddrV6::new(
                Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
                peer.local_addr().unwrap().port(),
                0,
                0,
            )
            .into();
            adapter.connect(&socket, destination).unwrap();
            assert_eq!(adapter.peer_addr().unwrap(), destination);
            adapter.send_to(&socket, b"request", destination).unwrap();
            let mut payload = [0; 64];
            let (_, sender) = peer.recv_from(&mut payload).unwrap();
            peer.send_to(b"reply", sender).unwrap();
            super::super::host_datagram::wait_readable(socket.as_raw_fd());
            let mut bytes = [MaybeUninit::new(0); 64];
            let (length, source) = adapter.receive(&socket, &mut bytes).unwrap();
            assert_eq!(length, 5);
            assert_eq!(source, destination);
        }
    }
    #[test]
    fn queued_reply_limits_preserve_the_old_peer_and_allow_retry() {
        for (payload_size, count) in [(0, MAX_SAVED_DATAGRAMS), (65_507, 4)] {
            let original: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let socket = Arc::new(Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap());
            socket.set_recv_buffer_size(128 * 1024).unwrap();
            socket.set_nonblocking(true).unwrap();
            socket.bind(&original.into()).unwrap();
            let bound = socket.local_addr().unwrap().as_socket().unwrap();
            let mut adapter = MacDatagram::new(
                &socket,
                original,
                true,
                1,
                Arc::new(DatagramRouter::new(&utils::epoll::Epoll::new().unwrap()).unwrap()),
            )
            .unwrap();
            adapter.bound(
                &socket,
                socket.local_addr().unwrap().as_socket().unwrap(),
                false,
                false,
            );
            let first = UdpSocket::bind(original).unwrap();
            socket2::SockRef::from(&first)
                .set_send_buffer_size(128 * 1024)
                .unwrap();
            let first_addr = first.local_addr().unwrap();
            let second = UdpSocket::bind(original).unwrap();
            let second_addr = second.local_addr().unwrap();
            adapter.connect(&socket, first_addr).unwrap();
            let payload = vec![42; payload_size];
            for _ in 0..count {
                first.send_to(&payload, bound).unwrap();
                super::super::host_datagram::wait_readable(socket.as_raw_fd());
                adapter.save_received(&socket).unwrap();
            }
            assert_eq!(adapter.saved_bytes, count * payload_size);
            assert_eq!(adapter.saved.len(), count);
            first.send_to(&payload, bound).unwrap();
            super::super::host_datagram::wait_readable(socket.as_raw_fd());
            assert_eq!(
                adapter
                    .connect(&socket, second_addr)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ENOBUFS)
            );
            assert_eq!(adapter.peer_addr().unwrap(), first_addr);
            let mut bytes = vec![MaybeUninit::new(0); MAX_DATAGRAM];
            for _ in 0..count {
                let (length, source) = adapter.receive(&socket, &mut bytes).unwrap();
                assert_eq!((length, source), (payload_size, first_addr));
            }
            assert_eq!(adapter.saved_bytes, 0);
            adapter.connect(&socket, second_addr).unwrap();
            assert_eq!(adapter.peer_addr().unwrap(), second_addr);
            assert_eq!(
                adapter.receive(&socket, &mut bytes).unwrap(),
                (payload_size, first_addr)
            );
            assert!(!adapter.has_saved());
        }
    }
}
