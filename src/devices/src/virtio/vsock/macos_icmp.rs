// SPDX-License-Identifier: Apache-2.0

//! Passive, unprivileged ICMP error collection for Darwin host UDP sockets.
//! Two descriptors share the existing muxer; no helper process or polling timer.
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

// The high word is VMADDR_PORT_ANY, never an allocated guest source port.
const IPV4_EVENT: u64 = u64::MAX;
const IPV6_EVENT: u64 = u64::MAX - 1;

#[derive(Debug, PartialEq, Eq)]
pub struct DatagramError {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub errno: i32,
}

pub struct MacIcmp {
    ipv4: Socket,
    ipv6: Socket,
}

impl MacIcmp {
    pub fn new(epoll: &Epoll) -> io::Result<Self> {
        let ipv4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        let ipv6 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?;
        ipv4.set_nonblocking(true)?;
        ipv6.set_nonblocking(true)?;
        epoll.ctl(
            ControlOperation::Add,
            ipv4.as_raw_fd(),
            &EpollEvent::new(EventSet::IN, IPV4_EVENT),
        )?;
        if let Err(error) = epoll.ctl(
            ControlOperation::Add,
            ipv6.as_raw_fd(),
            &EpollEvent::new(EventSet::IN, IPV6_EVENT),
        ) {
            let _ = epoll.ctl(
                ControlOperation::Delete,
                ipv4.as_raw_fd(),
                &EpollEvent::default(),
            );
            return Err(error);
        }
        Ok(Self { ipv4, ipv6 })
    }

    pub fn owns_event(id: u64) -> bool {
        id == IPV4_EVENT || id == IPV6_EVENT
    }

    pub fn receive(&self, id: u64) -> Vec<DatagramError> {
        let ipv6 = id == IPV6_EVENT;
        let socket = if ipv6 { &self.ipv6 } else { &self.ipv4 };
        let mut errors = Vec::new();
        let mut bytes = [MaybeUninit::new(0u8); 2048];
        for _ in 0..64 {
            match socket.recv_from_with_flags(&mut bytes, libc::MSG_DONTWAIT) {
                Ok((length, _)) => {
                    // SAFETY: recv_from initialized the returned prefix.
                    let packet =
                        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), length) };
                    if let Some(error) = parse_error(packet, ipv6) {
                        errors.push(error);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    debug!("host ICMP receive: {error}");
                    break;
                }
            }
        }
        errors
    }
}

fn parse_error(packet: &[u8], ipv6: bool) -> Option<DatagramError> {
    let (quote, source, destination, udp) = if ipv6 {
        // Darwin returns ICMPv6 payloads without the outer IPv6 header.
        if packet.len() < 8 + 40 + 8 || packet[0..2] != [1, 4] {
            return None;
        }
        let quote = &packet[8..];
        if quote[0] >> 4 != 6 || quote[6] != 17 {
            return None;
        }
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&quote[8..24]).ok()?);
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&quote[24..40]).ok()?);
        (quote, source.into(), destination.into(), 40)
    } else {
        // IPv4 ICMP datagrams retain the outer IP header, including options.
        if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 1 {
            return None;
        }
        let outer = usize::from(packet[0] & 15) * 4;
        if outer < 20 {
            return None;
        }
        let icmp = packet.get(outer..)?;
        if icmp.len() < 8 + 20 + 8 || icmp[0..2] != [3, 3] {
            return None;
        }
        let quote = &icmp[8..];
        let udp = usize::from(quote[0] & 15) * 4;
        if quote[0] >> 4 != 4
            || udp < 20
            || quote[9] != 17
            || u16::from_be_bytes([quote[6], quote[7]]) & 0x1fff != 0
        {
            return None;
        }
        let source = Ipv4Addr::new(quote[12], quote[13], quote[14], quote[15]);
        let destination = Ipv4Addr::new(quote[16], quote[17], quote[18], quote[19]);
        (quote, source.into(), destination.into(), udp)
    };
    let header = quote.get(udp..udp + 8)?;
    if u16::from_be_bytes([header[4], header[5]]) < 8 {
        return None;
    }
    Some(DatagramError {
        source: SocketAddr::new(source, u16::from_be_bytes([header[0], header[1]])),
        destination: SocketAddr::new(destination, u16::from_be_bytes([header[2], header[3]])),
        errno: 111, // Linux ECONNREFUSED, for a port-unreachable error only.
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    #[test]
    fn unprivileged_collection_matches_only_the_quoted_udp_flow() {
        let poll = Epoll::new().unwrap();
        let collector = MacIcmp::new(&poll).unwrap();
        for (ip, id) in [("127.0.0.1", IPV4_EVENT), ("::1", IPV6_EVENT)] {
            let local = SocketAddr::new(ip.parse().unwrap(), 0);
            let source = UdpSocket::bind(local).unwrap();
            let reserved = UdpSocket::bind(local).unwrap();
            let destination = reserved.local_addr().unwrap();
            drop(reserved);
            source.send_to(b"probe", destination).unwrap();
            let fd = if id == IPV4_EVENT {
                collector.ipv4.as_raw_fd()
            } else {
                collector.ipv6.as_raw_fd()
            };
            super::super::host_datagram::wait_readable(fd);
            let errors = collector.receive(id);
            assert!(
                errors
                    .iter()
                    .any(|error| error.source == source.local_addr().unwrap()
                        && error.destination == destination
                        && error.errno == 111),
                "{errors:?}"
            );
        }
    }

    #[test]
    fn malformed_or_unrelated_icmp_cannot_become_a_udp_error() {
        let mut v4 = vec![0u8; 56];
        v4[0] = 0x45;
        v4[9] = 1;
        v4[20] = 3;
        v4[21] = 3;
        v4[28] = 0x45;
        v4[37] = 17;
        v4[40..44].copy_from_slice(&[127, 0, 0, 1]);
        v4[44..48].copy_from_slice(&[127, 0, 0, 2]);
        v4[48..56].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0, 8, 0, 0]);
        let error = parse_error(&v4, false).unwrap();
        assert_eq!(error.source, "127.0.0.1:4660".parse().unwrap());
        assert_eq!(error.destination, "127.0.0.2:22136".parse().unwrap());
        let mut v6 = vec![0u8; 56];
        v6[0] = 1;
        v6[1] = 4;
        v6[8] = 0x60;
        v6[14] = 17;
        v6[31] = 1;
        v6[47] = 2;
        v6[48..56].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0, 8, 0, 0]);
        let error = parse_error(&v6, true).unwrap();
        assert_eq!(error.source, "[::1]:4660".parse().unwrap());
        assert_eq!(error.destination, "[::2]:22136".parse().unwrap());
        for (packet, ipv6) in [(&v4, false), (&v6, true)] {
            for length in 0..packet.len() {
                assert!(parse_error(&packet[..length], ipv6).is_none());
            }
            let mut other = packet.clone();
            other[if ipv6 { 0 } else { 20 }] = 8;
            assert!(parse_error(&other, ipv6).is_none());
            let mut other = packet.clone();
            other[if ipv6 { 14 } else { 37 }] = 6;
            assert!(parse_error(&other, ipv6).is_none());
        }
        v4[34] = 1;
        assert!(parse_error(&v4, false).is_none());
    }
}
