use super::super::defs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use utils::byte_order;

use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNIX, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_UN,
};

/// Stores a socket address in Linux wire format.
/// The first 2 bytes are a LE u16 sa_family (Linux AF_* constant).
#[repr(C)]
#[derive(Clone, Debug)]
pub struct SockaddrStorage {
    buf: [u8; 128],
    len: u32,
}

impl SockaddrStorage {
    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    /// Return the Linux AF_* family stored in the first two bytes.
    pub fn family(&self) -> u16 {
        byte_order::read_le_u16(&self.buf[0..2])
    }

    /// Interpret as IPv4 sockaddr (AF_INET).
    pub fn to_std_v4(&self) -> Option<SocketAddrV4> {
        if self.family() != defs::LINUX_AF_INET {
            return None;
        }
        let port = byte_order::read_be_u16(&self.buf[2..4]);
        let addr = Ipv4Addr::new(self.buf[4], self.buf[5], self.buf[6], self.buf[7]);
        Some(SocketAddrV4::new(addr, port))
    }

    /// Interpret as IPv6 sockaddr (AF_INET6).
    pub fn to_std_v6(&self) -> Option<SocketAddrV6> {
        if self.family() != defs::LINUX_AF_INET6 {
            return None;
        }
        let port = byte_order::read_be_u16(&self.buf[2..4]);
        let flowinfo = byte_order::read_le_u32(&self.buf[4..8]);
        let addr = Ipv6Addr::new(
            byte_order::read_be_u16(&self.buf[8..10]),
            byte_order::read_be_u16(&self.buf[10..12]),
            byte_order::read_be_u16(&self.buf[12..14]),
            byte_order::read_be_u16(&self.buf[14..16]),
            byte_order::read_be_u16(&self.buf[16..18]),
            byte_order::read_be_u16(&self.buf[18..20]),
            byte_order::read_be_u16(&self.buf[20..22]),
            byte_order::read_be_u16(&self.buf[22..24]),
        );
        let scope_id = byte_order::read_le_u32(&self.buf[24..28]);
        Some(SocketAddrV6::new(addr, port, flowinfo, scope_id))
    }

    /// Return the Unix socket path as a &str (AF_UNIX).
    pub fn unix_path(&self) -> Option<&str> {
        if self.family() != defs::LINUX_AF_UNIX {
            return None;
        }
        let end = (self.len as usize).min(110);
        if end < 2 {
            return None;
        }
        let path_bytes = &self.buf[2..end];
        let null_pos = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        std::str::from_utf8(&path_bytes[..null_pos]).ok()
    }

    /// Parse from raw Linux wire-format bytes received from the guest.
    pub fn from_linux_bytes(buf: &[u8], len: u32) -> Option<Self> {
        if len < 2 || buf.len() < len as usize {
            return None;
        }

        let family = byte_order::read_le_u16(&buf[0..2]);
        match family {
            defs::LINUX_AF_INET => {
                if len < 16 {
                    return None;
                }
            }
            defs::LINUX_AF_INET6 => {
                if len < 28 {
                    return None;
                }
            }
            defs::LINUX_AF_UNIX => {
                if len < 3 {
                    return None;
                }
            }
            _ => return None,
        }

        let mut storage = SockaddrStorage {
            buf: [0u8; 128],
            len,
        };
        let copy_len = (len as usize).min(128);
        storage.buf[..copy_len].copy_from_slice(&buf[..copy_len]);

        let family = byte_order::read_le_u16(&storage.buf[0..2]);
        match family {
            defs::LINUX_AF_INET | defs::LINUX_AF_INET6 | defs::LINUX_AF_UNIX => Some(storage),
            _ => None,
        }
    }

    /// Return a view of the IPv4 sockaddr for use in `write_getname_rsp`.
    pub fn as_sockaddr_in(&self) -> Option<SockaddrInRef<'_>> {
        if self.family() == defs::LINUX_AF_INET {
            Some(SockaddrInRef(self))
        } else {
            None
        }
    }
}

impl From<SocketAddrV4> for SockaddrStorage {
    fn from(addr: SocketAddrV4) -> Self {
        let mut storage = SockaddrStorage {
            buf: [0u8; 128],
            len: 16,
        };
        byte_order::write_le_u16(&mut storage.buf[0..], defs::LINUX_AF_INET);
        byte_order::write_be_u16(&mut storage.buf[2..], addr.port());
        let octets = addr.ip().octets();
        storage.buf[4..8].copy_from_slice(&octets);
        storage
    }
}

impl From<SocketAddrV6> for SockaddrStorage {
    fn from(addr: SocketAddrV6) -> Self {
        let mut storage = SockaddrStorage {
            buf: [0u8; 128],
            len: 28,
        };
        byte_order::write_le_u16(&mut storage.buf[0..], defs::LINUX_AF_INET6);
        byte_order::write_be_u16(&mut storage.buf[2..], addr.port());
        byte_order::write_le_u32(&mut storage.buf[4..], addr.flowinfo());
        let segments = addr.ip().segments();
        for (i, seg) in segments.iter().enumerate() {
            byte_order::write_be_u16(&mut storage.buf[8 + i * 2..], *seg);
        }
        byte_order::write_le_u32(&mut storage.buf[24..], addr.scope_id());
        storage
    }
}

pub struct SockaddrInRef<'a>(&'a SockaddrStorage);

impl<'a> SockaddrInRef<'a> {
    pub fn len(&self) -> u32 {
        self.0.len
    }
}

pub fn storage_to_winsock(addr: &SockaddrStorage) -> Option<(Vec<u8>, i32)> {
    match addr.family() {
        defs::LINUX_AF_INET => {
            let v4 = addr.to_std_v4()?;
            let mut sa: SOCKADDR_IN = unsafe { std::mem::zeroed() };
            sa.sin_family = AF_INET;
            sa.sin_port = v4.port().to_be();

            sa.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
            };

            let len = std::mem::size_of::<SOCKADDR_IN>() as i32;
            let bytes = unsafe {
                std::slice::from_raw_parts(&sa as *const _ as *const u8, len as usize).to_vec()
            };
            Some((bytes, len))
        }
        defs::LINUX_AF_INET6 => {
            let v6 = addr.to_std_v6()?;
            let mut sa: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = AF_INET6;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_flowinfo = v6.flowinfo();
            sa.Anonymous.sin6_scope_id = v6.scope_id();

            sa.sin6_addr = IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: v6.ip().octets(),
                },
            };

            let len = std::mem::size_of::<SOCKADDR_IN6>() as i32;
            let buf = unsafe {
                std::slice::from_raw_parts(&sa as *const _ as *const u8, len as usize).to_vec()
            };
            Some((buf, len))
        }
        defs::LINUX_AF_UNIX => {
            let path = addr.unix_path()?;
            let mut sa: SOCKADDR_UN = unsafe { std::mem::zeroed() };
            sa.sun_family = AF_UNIX;

            let pb = path.as_bytes();
            for (i, &b) in pb.iter().enumerate() {
                if i >= sa.sun_path.len() - 1 {
                    break;
                }
                sa.sun_path[i] = b as i8;
            }

            let len = std::mem::size_of::<SOCKADDR_UN>() as i32;
            let buf = unsafe {
                std::slice::from_raw_parts(&sa as *const _ as *const u8, len as usize).to_vec()
            };
            Some((buf, len))
        }
        _ => None,
    }
}

pub fn winsock_to_storage(buf: &[u8], len: i32) -> Option<SockaddrStorage> {
    if len < 2 || buf.len() < len as usize {
        return None;
    }

    let win_family = u16::from_ne_bytes([buf[0], buf[1]]);
    match win_family {
        v if v == AF_INET as u16 => {
            if len < std::mem::size_of::<SOCKADDR_IN>() as i32 {
                return None;
            }
            let sa: SOCKADDR_IN = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
            let port = u16::from_be(sa.sin_port);
            let addr_bytes = unsafe { sa.sin_addr.S_un.S_addr }.to_ne_bytes();
            let ip = Ipv4Addr::from(addr_bytes);
            Some(SocketAddrV4::new(ip, port).into())
        }
        v if v == AF_INET6 as u16 => {
            if len < std::mem::size_of::<SOCKADDR_IN6>() as i32 {
                return None;
            }
            let sa: SOCKADDR_IN6 = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
            let port = u16::from_be(sa.sin6_port);
            let (raw, scope_id) = unsafe { (sa.sin6_addr.u.Byte, sa.Anonymous.sin6_scope_id) };
            let segs = [
                u16::from_be_bytes([raw[0], raw[1]]),
                u16::from_be_bytes([raw[2], raw[3]]),
                u16::from_be_bytes([raw[4], raw[5]]),
                u16::from_be_bytes([raw[6], raw[7]]),
                u16::from_be_bytes([raw[8], raw[9]]),
                u16::from_be_bytes([raw[10], raw[11]]),
                u16::from_be_bytes([raw[12], raw[13]]),
                u16::from_be_bytes([raw[14], raw[15]]),
            ];
            let ip = Ipv6Addr::new(
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
            );
            Some(SocketAddrV6::new(ip, port, sa.sin6_flowinfo, scope_id).into())
        }
        v if v == AF_UNIX as u16 => {
            let path_end = (len as usize).min(110);
            let path_bytes = match buf.get(2..path_end) {
                Some(bytes) => bytes,
                None => return None,
            };

            let mut storage_buf = [0u8; 128];
            utils::byte_order::write_le_u16(&mut storage_buf[0..2], defs::LINUX_AF_UNIX);

            let mut actual_len = 2;
            for (i, &b) in path_bytes.iter().enumerate() {
                storage_buf[2 + i] = b;
                actual_len += 1;
                if b == 0 {
                    break;
                }
            }

            Some(SockaddrStorage {
                buf: storage_buf,
                len: actual_len as u32,
            })
        }
        _ => None,
    }
}
