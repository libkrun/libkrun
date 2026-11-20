use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};

use super::super::tsi_wire::DatagramInfo;

struct EchoRequest {
    guest_id: [u8; 2],
    address: IpAddr,
    payload_hash: u64,
}

pub(super) struct IcmpSocket {
    _reservation: UdpSocket,
    identifier: u16,
    ipv6: bool,
    requests: HashMap<u16, EchoRequest>,
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in data.chunks(2) {
        sum += u32::from(word[0]) << 8 | u32::from(*word.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn payload_hash(data: &[u8]) -> u64 {
    let mut hash = DefaultHasher::new();
    data.hash(&mut hash);
    hash.finish()
}

fn address_ip(address: &SockaddrStorage) -> Option<IpAddr> {
    address
        .as_sockaddr_in()
        .map(|a| a.ip().into())
        .or_else(|| address.as_sockaddr_in6().map(|a| a.ip().into()))
}

impl IcmpSocket {
    pub(super) fn new(fd: &OwnedFd, ipv6: bool) -> io::Result<Self> {
        let (level, option) = if ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
        } else {
            (libc::IPPROTO_IP, libc::IP_RECVTTL)
        };
        let enabled: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                option,
                (&enabled as *const libc::c_int).cast(),
                size_of_val(&enabled) as _,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // Reserving a loopback UDP port gives independent VMM processes distinct
        // echo IDs. Darwin's ICMP datagram sockets do not reserve identifiers.
        let reservation = UdpSocket::bind(("127.0.0.1", 0))?;
        let identifier = reservation.local_addr()?.port();
        Ok(Self {
            _reservation: reservation,
            identifier,
            ipv6,
            requests: HashMap::new(),
        })
    }

    pub(super) fn rewrite_request(
        &mut self,
        data: &[u8],
        address: &SockaddrStorage,
    ) -> Result<Vec<u8>, Errno> {
        if data.len() < 8 || data[0] != if self.ipv6 { 128 } else { 8 } || data[1] != 0 {
            return Err(Errno::EINVAL);
        }
        let request = EchoRequest {
            guest_id: data[4..6].try_into().unwrap(),
            address: address_ip(address).ok_or(Errno::EAFNOSUPPORT)?,
            payload_hash: payload_hash(&data[8..]),
        };
        self.requests
            .insert(u16::from_be_bytes(data[6..8].try_into().unwrap()), request);
        let mut packet = data.to_vec();
        packet[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        packet[2..4].fill(0);
        log::trace!(
            "ICMP request: ipv6={} id={} sequence={} target={address:?}",
            self.ipv6,
            self.identifier,
            u16::from_be_bytes(data[6..8].try_into().unwrap())
        );
        if !self.ipv6 {
            let checksum = checksum(&packet);
            packet[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        Ok(packet)
    }

    pub(super) fn receive(
        &self,
        fd: RawFd,
        output: &mut [u8],
    ) -> Result<(usize, bool, SockaddrStorage, DatagramInfo), Errno> {
        let mut packet = vec![0; 65536];
        for _ in 0..64 {
            let mut iov = [IoSliceMut::new(&mut packet)];
            let mut control = nix::cmsg_space!(
                libc::in6_pktinfo,
                libc::sockaddr_dl,
                libc::in_addr,
                libc::c_int
            );
            let msg =
                recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut control), MsgFlags::empty())?;
            let Some(address) = msg.address else { continue };
            let count = msg.bytes;
            let truncated = msg.flags.contains(MsgFlags::MSG_TRUNC);
            let mut info = DatagramInfo {
                address: [0; 16],
                ifindex: 0,
                hop_limit: None,
            };
            for message in msg.cmsgs()? {
                match message {
                    ControlMessageOwned::Ipv4RecvDstAddr(native) => {
                        info.address[..4].copy_from_slice(&native.s_addr.to_ne_bytes());
                    }
                    ControlMessageOwned::Ipv4RecvIf(native) => {
                        info.ifindex = u32::from(native.sdl_index)
                    }
                    ControlMessageOwned::Ipv6PacketInfo(native) => {
                        info.address = native.ipi6_addr.s6_addr;
                        info.ifindex = native.ipi6_ifindex;
                    }
                    ControlMessageOwned::Unknown(native) => {
                        match (native.cmsg_header.cmsg_level, native.cmsg_header.cmsg_type) {
                            (libc::IPPROTO_IP, libc::IP_RECVTTL) => {
                                info.hop_limit = native.data_bytes.first().copied()
                            }
                            (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT)
                                if native.data_bytes.len() == 4 =>
                            {
                                info.hop_limit = u8::try_from(i32::from_ne_bytes(
                                    native.data_bytes.try_into().unwrap(),
                                ))
                                .ok();
                            }
                            _ => (),
                        }
                    }
                    _ => (),
                }
            }
            let offset = if self.ipv6 {
                0
            } else {
                if count < 20 || packet[0] >> 4 != 4 || packet[9] != libc::IPPROTO_ICMP as u8 {
                    continue;
                }
                let size = usize::from(packet[0] & 15) * 4;
                if size < 20 || size > count {
                    continue;
                }
                if info.address == [0; 16] {
                    info.address[..4].copy_from_slice(&packet[16..20]);
                }
                info.hop_limit = info.hop_limit.or(Some(packet[8]));
                size
            };
            let data = &mut packet[offset..count];
            log::trace!(
                "ICMP received: ipv6={} peer={address:?} len={} header={:?}",
                self.ipv6,
                data.len(),
                data.get(..8)
            );
            if data.len() < 8
                || data[0] != if self.ipv6 { 129 } else { 0 }
                || data[1] != 0
                || data[4..6] != self.identifier.to_be_bytes()
            {
                continue;
            }
            let Some(request) = self
                .requests
                .get(&u16::from_be_bytes(data[6..8].try_into().unwrap()))
            else {
                continue;
            };
            if address_ip(&address) != Some(request.address)
                || payload_hash(&data[8..]) != request.payload_hash
            {
                log::trace!(
                    "ICMP reply mismatch: expected={} hash={} actual={}",
                    request.address,
                    request.payload_hash,
                    payload_hash(&data[8..])
                );
                continue;
            }
            let old_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
            data[4..6].copy_from_slice(&request.guest_id);
            let adjusted = if self.ipv6 {
                let mut sum = u32::from(!u16::from_be_bytes(data[2..4].try_into().unwrap()))
                    + u32::from(!old_id)
                    + u32::from(u16::from_be_bytes(request.guest_id));
                while sum >> 16 != 0 {
                    sum = (sum & 65535) + (sum >> 16);
                }
                !(sum as u16)
            } else {
                data[2..4].fill(0);
                checksum(data)
            };
            data[2..4].copy_from_slice(&adjusted.to_be_bytes());
            let copied = data.len().min(output.len());
            output[..copied].copy_from_slice(&data[..copied]);
            return Ok((data.len(), truncated || copied < data.len(), address, info));
        }
        Err(Errno::EAGAIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use nix::sys::socket::{
        AddressFamily, SockFlag, SockProtocol, SockType, sendto, setsockopt, socket, sockopt,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::thread;
    use std::time::{Duration, Instant};

    fn native(ipv6: bool) -> (OwnedFd, IcmpSocket) {
        let (family, protocol) = if ipv6 {
            (AddressFamily::Inet6, SockProtocol::IcmpV6)
        } else {
            (AddressFamily::Inet, SockProtocol::Icmp)
        };
        let fd = socket(
            family,
            SockType::Datagram,
            SockFlag::empty(),
            Some(protocol),
        )
        .unwrap();
        fcntl(&fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        if ipv6 {
            setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true).unwrap();
        } else {
            setsockopt(&fd, sockopt::Ipv4RecvDstAddr, &true).unwrap();
            setsockopt(&fd, sockopt::Ipv4RecvIf, &true).unwrap();
        }
        let state = IcmpSocket::new(&fd, ipv6).unwrap();
        (fd, state)
    }

    fn collision(ipv6: bool) {
        let mut sockets = [native(ipv6), native(ipv6)];
        assert_ne!(sockets[0].1.identifier, sockets[1].1.identifier);
        let address: SockaddrStorage = if ipv6 {
            SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into()
        } else {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into()
        };
        for (index, (fd, state)) in sockets.iter_mut().enumerate() {
            let mut request = vec![0; 63 + index];
            request[0] = if ipv6 { 128 } else { 8 };
            request[4..6].copy_from_slice(&4242u16.to_be_bytes());
            request[6..8].copy_from_slice(&1u16.to_be_bytes());
            request[8..].fill(index as u8 + 0xa0);
            let packet = state.rewrite_request(&request, &address).unwrap();
            sendto(fd.as_raw_fd(), &packet, &address, MsgFlags::empty()).unwrap();
        }
        for (index, (fd, state)) in sockets.iter().enumerate() {
            let mut reply = [0; 128];
            let deadline = Instant::now() + Duration::from_secs(2);
            let (count, truncated, peer, info) = loop {
                match state.receive(fd.as_raw_fd(), &mut reply) {
                    Ok(packet) => break packet,
                    Err(Errno::EAGAIN) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("ICMP reply: {error}"),
                }
            };
            assert_eq!(count, 63 + index);
            assert!(!truncated);
            assert_eq!(address_ip(&peer), address_ip(&address));
            assert_eq!(reply[0], if ipv6 { 129 } else { 0 });
            assert_eq!(&reply[4..6], &4242u16.to_be_bytes());
            assert!(reply[8..count].iter().all(|b| *b == index as u8 + 0xa0));
            assert!(info.ifindex > 0);
            assert!(info.hop_limit.unwrap() > 0);
            if ipv6 {
                assert_eq!(info.address, Ipv6Addr::LOCALHOST.octets());
                let mut pseudo = Ipv6Addr::LOCALHOST.octets().to_vec();
                pseudo.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
                pseudo.extend_from_slice(&(count as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, 58]);
                pseudo.extend_from_slice(&reply[..count]);
                assert_eq!(checksum(&pseudo), 0);
            } else {
                assert_eq!(&info.address[..4], &Ipv4Addr::LOCALHOST.octets());
                assert_eq!(checksum(&reply[..count]), 0);
            }
            assert!(matches!(
                state.receive(fd.as_raw_fd(), &mut reply),
                Err(Errno::EAGAIN)
            ));
        }
        let identifier = sockets[0].1.identifier;
        drop(sockets);
        assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, identifier)).is_ok());
    }

    #[test]
    fn ipv4_echo_identifier_collision_and_checksum() {
        collision(false);
    }

    #[test]
    fn ipv6_echo_identifier_collision_and_checksum() {
        collision(true);
    }
}
