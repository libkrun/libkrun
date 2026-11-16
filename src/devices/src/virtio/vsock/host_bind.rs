// SPDX-License-Identifier: Apache-2.0

//! Synchronous host INET binding for the TSI transport.
//!
//! Request (little endian): peer vsock port, sockaddr length, option bits,
//! then a Linux sockaddr (16 bytes IPv4, 28 bytes IPv6). Replies have the same
//! fixed 136-byte shape as TSI_GETNAME: Linux errno, address length, and a
//! zero-padded 128-byte sockaddr. A successful port-zero bind returns the
//! actual host-selected port, already reserved by the proxy's socket.
//!
//! Only callers granted HOST_BIND, with no publishing map, may use this.
//! Legacy guests and port mappings keep their existing behavior. Guest kernel
//! integration is separate; this capability alone does not enable host mode.

use std::net::SocketAddr;

use socket2::Socket;

use super::proxy::Family;
use super::sys;
use super::vsock_addr::VsockAddr;

const REUSE_ADDR: u32 = 1;
const REUSE_PORT: u32 = 2;
const V6_ONLY: u32 = 4;
const BROADCAST: u32 = 8;
const KNOWN_OPTIONS: u32 = REUSE_ADDR | REUSE_PORT | V6_ONLY | BROADCAST;

#[derive(Debug)]
pub struct BindRequest {
    pub peer_port: u32,
    pub addr: VsockAddr,
    options: u32,
}

impl BindRequest {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = data.get(..12)?;
        let peer_port = u32::from_le_bytes(header[0..4].try_into().ok()?);
        let addr_len = u32::from_le_bytes(header[4..8].try_into().ok()?);
        let options = u32::from_le_bytes(header[8..12].try_into().ok()?);
        let bytes = data.get(12..12usize.checked_add(addr_len as usize)?)?;
        let addr = VsockAddr::parse_linux(bytes, addr_len)?;
        // Never accept AF_UNIX paths or sockaddr lengths inconsistent with
        // their family, even when the descriptor has extra padded bytes.
        if addr.inet().is_none() || addr.linux_len() != addr_len || options & !KNOWN_OPTIONS != 0 {
            return None;
        }
        Some(Self {
            peer_port,
            addr,
            options,
        })
    }
}

#[derive(Debug)]
pub struct BindResponse {
    result: i32,
    addr: Option<VsockAddr>,
}

impl From<Result<VsockAddr, i32>> for BindResponse {
    fn from(value: Result<VsockAddr, i32>) -> Self {
        match value {
            Ok(addr) => Self {
                result: 0,
                addr: Some(addr),
            },
            Err(result) => Self { result, addr: None },
        }
    }
}

impl BindResponse {
    /// Return the exact initialized reply length, never the descriptor size.
    pub fn write(&self, buf: &mut [u8]) -> usize {
        let Some(buf) = buf.get_mut(..136) else {
            return 0;
        };
        buf.fill(0);
        buf[..4].copy_from_slice(&self.result.to_le_bytes());
        if let Some(addr) = &self.addr {
            let bytes = addr.to_linux_bytes();
            buf[4..8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf[8..8 + bytes.len()].copy_from_slice(&bytes);
        }
        buf.len()
    }
}

/// Apply the guest's pre-bind options, then reserve the exact host address.
/// OS errors are translated to Linux errno numbers on every host platform.
pub fn bind_inet(sock: &Socket, family: Family, req: &BindRequest) -> Result<SocketAddr, i32> {
    if !req.addr.suits_family(family) {
        return Err(-22); // EINVAL
    }
    let addr = req.addr.inet().ok_or(-97)?; // EAFNOSUPPORT
    if (addr.is_ipv4() && family != Family::Inet) || (addr.is_ipv6() && family != Family::Inet6) {
        return Err(-97); // EAFNOSUPPORT
    }
    if addr.is_ipv4() && req.options & V6_ONLY != 0 {
        return Err(-22);
    }
    #[cfg(windows)]
    if req.options & REUSE_PORT != 0 {
        return Err(-95); // EOPNOTSUPP, no equivalent Winsock option.
    }
    let apply = || -> std::io::Result<SocketAddr> {
        // Stream proxies historically set reuseaddr unconditionally. An
        // explicit bind must honor the guest instead, including the default
        // exclusive reservation before listen().
        sock.set_reuse_address(req.options & REUSE_ADDR != 0)?;
        #[cfg(unix)]
        sock.set_reuse_port(req.options & REUSE_PORT != 0)?;
        if addr.is_ipv6() {
            sock.set_only_v6(req.options & V6_ONLY != 0)?;
        }
        sock.set_broadcast(req.options & BROADCAST != 0)?;
        sock.bind(&addr.into())?;
        sock.local_addr()?.as_socket().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "host INET socket returned no address",
            )
        })
    };
    apply().map_err(|e| -sys::to_linux_errno(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Type};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpStream, UdpSocket};
    use std::time::Duration;

    fn request(addr: SocketAddr) -> BindRequest {
        BindRequest {
            peer_port: 7000,
            addr: addr.into(),
            options: 0,
        }
    }

    #[test]
    fn bind_parser_rejects_truncation_unknown_options_and_non_inet() {
        let mut wire = Vec::from(7000u32.to_le_bytes());
        wire.extend(16u32.to_le_bytes());
        wire.extend(0u32.to_le_bytes());
        wire.extend(VsockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_linux_bytes());
        assert!(BindRequest::parse(&wire).is_some());
        for end in 0..wire.len() {
            assert!(BindRequest::parse(&wire[..end]).is_none(), "length {end}");
        }
        for invalid_len in [0u32, 2, 15, 17, u32::MAX] {
            wire[4..8].copy_from_slice(&invalid_len.to_le_bytes());
            assert!(BindRequest::parse(&wire).is_none());
        }
        wire[4..8].copy_from_slice(&16u32.to_le_bytes());
        wire[8..12].copy_from_slice(&16u32.to_le_bytes());
        assert!(BindRequest::parse(&wire).is_none());
        wire[8..12].fill(0);
        wire[12..14].copy_from_slice(&1u16.to_le_bytes());
        assert!(BindRequest::parse(&wire).is_none());
    }

    #[test]
    fn bind_replies_initialize_only_the_fixed_wire_payload() {
        for result in [
            Ok(request((Ipv4Addr::LOCALHOST, 12345).into()).addr),
            Err(-98),
        ] {
            let reply = BindResponse::from(result);
            let mut data = [0xa5; 256];
            assert_eq!(reply.write(&mut data), 136);
            assert_eq!(&data[136..], &[0xa5; 120]);
            assert!(data[36..136].iter().all(|b| *b == 0));
            if reply.result != 0 {
                assert_eq!(i32::from_le_bytes(data[..4].try_into().unwrap()), -98);
                assert!(data[4..136].iter().all(|b| *b == 0));
            }
            assert_eq!(reply.write(&mut [0; 135]), 0);
        }
    }

    #[test]
    fn tcp_port_zero_reserves_until_close_and_can_listen_without_rebinding() {
        for ip in [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()] {
            let req = request(SocketAddr::new(ip, 0));
            let (domain, family) = if ip.is_ipv4() {
                (Domain::IPV4, Family::Inet)
            } else {
                (Domain::IPV6, Family::Inet6)
            };
            let sock = Socket::new(domain, Type::STREAM, None).unwrap();
            let bound = bind_inet(&sock, family, &req).unwrap();
            assert_ne!(bound.port(), 0);
            assert_eq!(bound.ip(), ip);
            let other = Socket::new(domain, Type::STREAM, None).unwrap();
            assert_eq!(bind_inet(&other, family, &request(bound)), Err(-98));
            sock.listen(4).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let client = TcpStream::connect_timeout(&bound, Duration::from_secs(2)).unwrap();
            let (accepted, _) = sock.accept().unwrap();
            drop(accepted);
            drop(client);
            drop(sock);
            // A distinct unused reservation verifies immediate release without
            // involving TCP's legitimate TIME_WAIT after the connection above.
            let sock = Socket::new(domain, Type::STREAM, None).unwrap();
            let bound = bind_inet(&sock, family, &req).unwrap();
            drop(sock);
            assert_eq!(bind_inet(&other, family, &request(bound)).unwrap(), bound);
        }
    }

    #[test]
    fn udp_bound_port_receives_and_replies_from_the_same_address() {
        for ip in [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()] {
            let req = request(SocketAddr::new(ip, 0));
            let (domain, family) = if ip.is_ipv4() {
                (Domain::IPV4, Family::Inet)
            } else {
                (Domain::IPV6, Family::Inet6)
            };
            let sock = Socket::new(domain, Type::DGRAM, None).unwrap();
            let bound = bind_inet(&sock, family, &req).unwrap();
            let other = Socket::new(domain, Type::DGRAM, None).unwrap();
            assert_eq!(bind_inet(&other, family, &request(bound)), Err(-98));
            let server: UdpSocket = sock.into();
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let client = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client.send_to(b"request", bound).unwrap();
            let mut data = [0; 32];
            let (len, peer) = server.recv_from(&mut data).unwrap();
            assert_eq!(&data[..len], b"request");
            server.send_to(b"reply", peer).unwrap();
            let (len, peer) = client.recv_from(&mut data).unwrap();
            assert_eq!(&data[..len], b"reply");
            assert_eq!(peer, bound);
            drop(server);
            assert_eq!(bind_inet(&other, family, &request(bound)).unwrap(), bound);
        }
    }
}
