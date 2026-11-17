// SPDX-License-Identifier: Apache-2.0

//! Linux integer socket options applied to the actual host socket.
use socket2::Socket;

use super::sys;

pub struct OptionRequest {
    pub peer_port: u32,
    level: i32,
    option: i32,
    value: i32,
}

impl OptionRequest {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 16 {
            return None;
        }
        Some(Self {
            peer_port: u32::from_le_bytes(data[0..4].try_into().ok()?),
            level: i32::from_le_bytes(data[4..8].try_into().ok()?),
            option: i32::from_le_bytes(data[8..12].try_into().ok()?),
            value: i32::from_le_bytes(data[12..16].try_into().ok()?),
        })
    }

    #[cfg(target_os = "macos")]
    pub fn apply_datagram(&self, socket: &Socket, reuse: &mut [bool; 2]) -> Result<(), i32> {
        let index = match (self.level, self.option) {
            (1, 2) => 0,
            (1, 15) => 1,
            _ => return self.apply(socket),
        };
        let mut updated = *reuse;
        updated[index] = self.value != 0;
        socket
            .set_reuse_address(updated[0])
            .map_err(|error| -sys::to_linux_errno(&error))?;
        if let Err(error) = socket.set_reuse_port(updated[0] || updated[1]) {
            let _ = socket.set_reuse_address(reuse[0]);
            return Err(-sys::to_linux_errno(&error));
        }
        *reuse = updated;
        Ok(())
    }

    pub fn apply(&self, socket: &Socket) -> Result<(), i32> {
        let enabled = self.value != 0;
        let result = match (self.level, self.option) {
            (1, 2) => socket.set_reuse_address(enabled), // SO_REUSEADDR
            (1, 6) => socket.set_broadcast(enabled),     // SO_BROADCAST
            (1, 9) => socket.set_keepalive(enabled),     // SO_KEEPALIVE
            #[cfg(unix)]
            (1, 15) => socket.set_reuse_port(enabled), // SO_REUSEPORT
            #[cfg(windows)]
            (1, 15) => return Err(-95),
            (6, 1) => socket.set_nodelay(enabled), // TCP_NODELAY
            (0, 2) => {
                // IP_TTL
                if !(1..=255).contains(&self.value) {
                    return Err(-22);
                }
                socket.set_ttl(self.value as u32)
            }
            (41, 16) => {
                // IPV6_UNICAST_HOPS
                if !(0..=255).contains(&self.value) {
                    return Err(-22);
                }
                socket.set_unicast_hops_v6(self.value as u32)
            }
            _ => return Err(-92), // ENOPROTOOPT; never pretend to apply an option.
        };
        result.map_err(|error| -sys::to_linux_errno(&error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Type};

    fn request(level: i32, option: i32, value: i32) -> OptionRequest {
        OptionRequest {
            peer_port: 7000,
            level,
            option,
            value,
        }
    }

    #[test]
    fn host_options_update_bound_sockets_and_invalid_values_preserve_state() {
        for domain in [Domain::IPV4, Domain::IPV6] {
            let socket = Socket::new(domain, Type::DGRAM, None).unwrap();
            let address: std::net::SocketAddr = if domain == Domain::IPV4 {
                "127.0.0.1:0"
            } else {
                "[::1]:0"
            }
            .parse()
            .unwrap();
            socket.bind(&address.into()).unwrap();
            for value in [1, 0] {
                request(1, 2, value).apply(&socket).unwrap();
                assert_eq!(socket.reuse_address().unwrap(), value != 0);
                request(1, 6, value).apply(&socket).unwrap();
                assert_eq!(socket.broadcast().unwrap(), value != 0);
                request(1, 9, value).apply(&socket).unwrap();
                assert_eq!(socket.keepalive().unwrap(), value != 0);
                #[cfg(unix)]
                {
                    request(1, 15, value).apply(&socket).unwrap();
                    assert_eq!(socket.reuse_port().unwrap(), value != 0);
                }
            }
            let (level, option) = if domain == Domain::IPV4 {
                (0, 2)
            } else {
                (41, 16)
            };
            request(level, option, 37).apply(&socket).unwrap();
            assert_eq!(request(level, option, 256).apply(&socket), Err(-22));
            assert_eq!(request(level, option, -2).apply(&socket), Err(-22));
            let value = if domain == Domain::IPV4 {
                socket.ttl().unwrap()
            } else {
                socket.unicast_hops_v6().unwrap()
            };
            assert_eq!(value, 37);
            assert_eq!(request(1, 9999, 1).apply(&socket), Err(-92));
        }
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        request(6, 1, 1).apply(&socket).unwrap();
        assert!(socket.nodelay().unwrap());
        request(6, 1, 0).apply(&socket).unwrap();
        assert!(!socket.nodelay().unwrap());
    }

    #[test]
    fn option_wire_rejects_truncated_and_extended_messages() {
        let wire = [
            7000u32.to_le_bytes(),
            1u32.to_le_bytes(),
            6u32.to_le_bytes(),
            1u32.to_le_bytes(),
        ]
        .concat();
        let parsed = OptionRequest::parse(&wire).unwrap();
        assert_eq!(parsed.peer_port, 7000);
        for end in 0..wire.len() {
            assert!(OptionRequest::parse(&wire[..end]).is_none());
        }
        let mut extended = wire;
        extended.push(0);
        assert!(OptionRequest::parse(&extended).is_none());
    }
}
