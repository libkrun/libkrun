// SPDX-License-Identifier: Apache-2.0

//! Linux integer socket options applied to the actual host socket.
use socket2::Socket;

#[cfg(unix)]
use libc as socket_sys;
use std::io;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock as socket_sys;

use super::{proxy::raw_handle, sys};

fn keepalive_option(option: i32) -> i32 {
    match option {
        #[cfg(target_os = "macos")]
        4 => socket_sys::TCP_KEEPALIVE,
        #[cfg(not(target_os = "macos"))]
        4 => socket_sys::TCP_KEEPIDLE,
        5 => socket_sys::TCP_KEEPINTVL,
        6 => socket_sys::TCP_KEEPCNT,
        _ => unreachable!(),
    }
}

fn last_socket_error() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::last_os_error()
    }
    #[cfg(windows)]
    // SAFETY: WSAGetLastError reads this thread's socket error.
    {
        io::Error::from_raw_os_error(unsafe { socket_sys::WSAGetLastError() })
    }
}

fn set_tcp_integer(socket: &Socket, option: i32, value: i32) -> io::Result<()> {
    // SAFETY: socket owns the handle; value is valid for the stated length.
    let result = unsafe {
        socket_sys::setsockopt(
            raw_handle(socket) as _,
            socket_sys::IPPROTO_TCP,
            option,
            std::ptr::from_ref(&value).cast(),
            size_of::<i32>() as _,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(last_socket_error())
    }
}

fn tcp_integer(socket: &Socket, option: i32) -> io::Result<i32> {
    let mut value = 0i32;
    let mut length = size_of::<i32>() as _;
    // SAFETY: socket owns the handle; value and length are writable buffers.
    let result = unsafe {
        socket_sys::getsockopt(
            raw_handle(socket) as _,
            socket_sys::IPPROTO_TCP,
            option,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    if result == 0 {
        Ok(value)
    } else {
        Err(last_socket_error())
    }
}

/// Interceptors may replace the transport with one of a different family.
/// Preserve TCP settings without enabling probes or resetting other parameters.
pub fn copy_tcp_options(source: &Socket, destination: &Socket) -> io::Result<()> {
    for option in 4..=6 {
        let native = keepalive_option(option);
        set_tcp_integer(destination, native, tcp_integer(source, native)?)?;
    }
    destination.set_nodelay(source.nodelay()?)?;
    destination.set_keepalive(source.keepalive()?)
}

pub struct OptionRequest {
    pub peer_port: u32,
    pub local_port: u32,
    level: i32,
    option: i32,
    value: i32,
}

impl OptionRequest {
    fn apply_tcp_keepalive(&self, socket: &Socket) -> Result<(), i32> {
        let max = if self.option == 6 { 127 } else { 32767 };
        if !(1..=max).contains(&self.value) {
            return Err(-22);
        }
        // socket2's set_tcp_keepalive also enables SO_KEEPALIVE; the
        // individual Linux TCP_KEEP* options must leave that flag unchanged.
        set_tcp_integer(socket, keepalive_option(self.option), self.value)
            .map_err(|error| -sys::to_linux_errno(&error))
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 20 {
            return None;
        }
        Some(Self {
            peer_port: u32::from_le_bytes(data[0..4].try_into().ok()?),
            local_port: u32::from_le_bytes(data[4..8].try_into().ok()?),
            level: i32::from_le_bytes(data[8..12].try_into().ok()?),
            option: i32::from_le_bytes(data[12..16].try_into().ok()?),
            value: i32::from_le_bytes(data[16..20].try_into().ok()?),
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
            (6, 4..=6) => return self.apply_tcp_keepalive(socket),
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
    #[cfg(unix)]
    use std::os::fd::AsRawFd;

    fn request(level: i32, option: i32, value: i32) -> OptionRequest {
        OptionRequest {
            peer_port: 7000,
            local_port: super::super::defs::TSI_PROXY_PORT,
            level,
            option,
            value,
        }
    }

    #[cfg(unix)]
    #[test]
    fn tcp_keepalive_tuning_updates_only_the_requested_host_parameter() {
        fn read(socket: &Socket, option: i32) -> i32 {
            let mut value = 0i32;
            let mut size = size_of::<i32>() as libc::socklen_t;
            // SAFETY: valid socket and writable buffers of their stated lengths.
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        option,
                        std::ptr::from_mut(&mut value).cast(),
                        &mut size,
                    )
                },
                0
            );
            value
        }
        #[cfg(target_os = "macos")]
        let idle = libc::TCP_KEEPALIVE;
        #[cfg(not(target_os = "macos"))]
        let idle = libc::TCP_KEEPIDLE;
        for domain in [Domain::IPV4, Domain::IPV6] {
            let socket = Socket::new(domain, Type::STREAM, None).unwrap();
            for enabled in [false, true] {
                socket.set_keepalive(enabled).unwrap();
                for (guest, host, value, max) in [
                    (4, idle, 17, 32767),
                    (5, libc::TCP_KEEPINTVL, 7, 32767),
                    (6, libc::TCP_KEEPCNT, 3, 127),
                ] {
                    request(6, guest, value).apply(&socket).unwrap();
                    assert_eq!(read(&socket, host), value);
                    assert_eq!(socket.keepalive().unwrap(), enabled);
                    for invalid in [-1, 0, max + 1] {
                        assert_eq!(request(6, guest, invalid).apply(&socket), Err(-22));
                        assert_eq!(read(&socket, host), value);
                        assert_eq!(socket.keepalive().unwrap(), enabled);
                    }
                }
                assert_eq!(
                    (
                        read(&socket, idle),
                        read(&socket, libc::TCP_KEEPINTVL),
                        read(&socket, libc::TCP_KEEPCNT)
                    ),
                    (17, 7, 3)
                );
                let replacement = Socket::new(
                    if domain == Domain::IPV4 {
                        Domain::IPV6
                    } else {
                        Domain::IPV4
                    },
                    Type::STREAM,
                    None,
                )
                .unwrap();
                socket.set_nodelay(true).unwrap();
                copy_tcp_options(&socket, &replacement).unwrap();
                assert_eq!(replacement.keepalive().unwrap(), enabled);
                assert!(replacement.nodelay().unwrap());
                assert_eq!(
                    (
                        read(&replacement, idle),
                        read(&replacement, libc::TCP_KEEPINTVL),
                        read(&replacement, libc::TCP_KEEPCNT)
                    ),
                    (17, 7, 3)
                );
            }
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
            super::super::defs::TSI_PROXY_PORT.to_le_bytes(),
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
