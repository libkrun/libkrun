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

use socket2::{Domain, SockAddr, Socket, Type};

const MAX_SAVED_BYTES: usize = 256 * 1024;
const MAX_SAVED_DATAGRAMS: usize = 512;
const MAX_DATAGRAM: usize = super::host_datagram::MAX_DATAGRAM;

pub struct MacDatagram {
    original: SocketAddr,
    selected: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    deferred_bind: bool,
    saved: VecDeque<(SocketAddr, Box<[u8]>)>,
    saved_bytes: usize,
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn canonical_peer(peer: SocketAddr) -> SocketAddr {
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

impl MacDatagram {
    pub fn new(socket: &Socket, original: SocketAddr, ipv4: bool) -> io::Result<Self> {
        receive_packet_info(socket, ipv4)?;
        Ok(Self {
            original,
            selected: None,
            peer: None,
            deferred_bind: false,
            saved: VecDeque::new(),
            saved_bytes: 0,
        })
    }

    fn guest_address(&self, address: SocketAddr) -> SocketAddr {
        if self.original.is_ipv6()
            && let SocketAddr::V4(address) = address
        {
            return SocketAddrV6::new(address.ip().to_ipv6_mapped(), address.port(), 0, 0).into();
        }
        address
    }

    fn bind_if_needed(&mut self, socket: &Socket) -> io::Result<()> {
        if self.deferred_bind {
            socket.bind(&self.original.into())?;
            self.deferred_bind = false;
        }
        Ok(())
    }

    pub fn connect(&mut self, socket: &Socket, destination: SocketAddr) -> io::Result<()> {
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
        replacement.set_send_buffer_size(socket.send_buffer_size()?)?;
        replacement.set_recv_buffer_size(socket.recv_buffer_size()?)?;
        if self.original.is_ipv6() {
            replacement.set_only_v6(socket.only_v6()?)?;
        }
        receive_packet_info(&replacement, self.original.is_ipv4())?;
        Ok(Some(replacement))
    }

    pub fn disconnected(&mut self) {
        self.selected = None;
        self.peer = None;
        self.deferred_bind = self.original.port() == 0;
    }

    pub fn send_to(
        &mut self,
        socket: &Socket,
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

    pub fn has_saved(&self) -> bool {
        !self.saved.is_empty()
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
    pub fn save_received(&mut self, socket: &Socket) -> io::Result<()> {
        let mut probe = [MaybeUninit::uninit(); 1];
        match socket.recv_from_with_flags(&mut probe, libc::MSG_PEEK | libc::MSG_DONTWAIT) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let mut bytes = vec![MaybeUninit::new(0); MAX_DATAGRAM];
        for _ in 0..MAX_SAVED_DATAGRAMS {
            let (length, sender, destination) =
                match receive_with_destination(socket, &mut bytes, libc::MSG_PEEK) {
                    Ok(packet) => packet,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(error) => return Err(error),
                };
            let admitted = self.admits(sender, destination);
            if admitted
                && (self.saved.len() == MAX_SAVED_DATAGRAMS
                    || self.saved_bytes + length > MAX_SAVED_BYTES)
            {
                return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
            }
            // The proxy lock owns the only reader; the peeked datagram remains
            // first in the socket queue until this receive consumes it.
            let (length, sender, _) = receive_with_destination(socket, &mut bytes, 0)?;
            if admitted {
                // SAFETY: recvmsg initialized exactly the returned prefix.
                let payload =
                    unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), length) };
                self.saved
                    .push_back((self.guest_address(sender), payload.into()));
                self.saved_bytes += length;
            }
        }
        match socket.recv_from_with_flags(&mut probe, libc::MSG_PEEK | libc::MSG_DONTWAIT) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(io::ErrorKind::WouldBlock.into()),
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
        // Bound work even if another host process floods this port with packets
        // from a peer which the Linux guest has not connected to.
        for _ in 0..32 {
            let (length, sender, destination) = receive_with_destination(socket, bytes, 0)?;
            if self.admits(sender, destination) {
                return Ok((length, self.guest_address(sender)));
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
}

fn receive_with_destination(
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
    fn mapped_ipv4_replies_keep_the_guest_ipv6_family() {
        for bind in ["[::ffff:127.0.0.1]:0", "[::]:0"] {
            let original: SocketAddr = bind.parse().unwrap();
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, None).unwrap();
            socket.set_only_v6(false).unwrap();
            socket.set_nonblocking(true).unwrap();
            socket.bind(&original.into()).unwrap();
            let mut adapter = MacDatagram::new(&socket, original, false).unwrap();
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
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
            socket.set_recv_buffer_size(128 * 1024).unwrap();
            socket.set_nonblocking(true).unwrap();
            socket.bind(&original.into()).unwrap();
            let bound = socket.local_addr().unwrap().as_socket().unwrap();
            let mut adapter = MacDatagram::new(&socket, original, true).unwrap();
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
