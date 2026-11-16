// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-platform socket address for the TSI guest ABI.
//!
//! The guest always speaks the **Linux** sockaddr wire format (AF_INET = 2,
//! AF_INET6 = 10, AF_UNIX = 1; port and address in network byte order). The
//! host, however, may lay sockaddrs out differently (macOS uses a `sa_len` byte
//! and different AF_* values; Windows uses AF_INET6 = 23 and has no AF_UNIX).
//! The old code carried a `nix::SockaddrStorage` and patched the bytes per-OS,
//! but `nix` does not build on Windows at all.
//!
//! [`VsockAddr`] replaces `SockaddrStorage` in the vsock/TSI path. It parses the
//! guest's Linux-layout bytes into a host-neutral value and serializes back to
//! Linux layout regardless of host, so the guest ABI stays identical on every
//! platform. INET addresses are represented as [`std::net::SocketAddr`] and feed
//! `socket2` for the host socket calls; AF_UNIX is preserved as raw guest bytes
//! on Linux only (macOS and Windows do not support AF_UNIX over TSI).
//!
//! See WINDOWS_NETWORKING_PORT.md (Phase 1).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use super::defs;
use super::proxy::Family;

/// Length of a Linux `struct sockaddr_in`.
const LINUX_SOCKADDR_IN_LEN: usize = 16;
/// Length of a Linux `struct sockaddr_in6`.
const LINUX_SOCKADDR_IN6_LEN: usize = 28;

/// A socket address in the guest's (Linux) sockaddr ABI, stored host-neutrally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VsockAddr {
    /// An IPv4 or IPv6 address (portable to every host).
    Inet(SocketAddr),
    /// A Linux AF_UNIX address, kept as the raw guest `sockaddr_un` bytes.
    /// Linux-only: macOS and Windows do not proxy AF_UNIX over TSI.
    #[cfg(target_os = "linux")]
    Unix(Vec<u8>),
}

impl VsockAddr {
    /// Parse the first `addr_len` bytes of a guest-supplied Linux sockaddr.
    ///
    /// `buf` and `addr_len` are guest-controlled, so every read is bounds-checked
    /// against both `addr_len` and the actual buffer length. Returns `None` for a
    /// truncated buffer or an unsupported address family.
    pub fn parse_linux(buf: &[u8], addr_len: u32) -> Option<Self> {
        let len = addr_len as usize;
        if len < 2 || len > buf.len() {
            return None;
        }
        let family = u16::from_le_bytes([buf[0], buf[1]]);
        match family {
            defs::LINUX_AF_INET => {
                if len < LINUX_SOCKADDR_IN_LEN {
                    return None;
                }
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                Some(VsockAddr::Inet(SocketAddrV4::new(ip, port).into()))
            }
            defs::LINUX_AF_INET6 => {
                if len < LINUX_SOCKADDR_IN6_LEN {
                    return None;
                }
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let flowinfo = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[8..24]);
                let scope_id = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
                Some(VsockAddr::Inet(
                    SocketAddrV6::new(Ipv6Addr::from(octets), port, flowinfo, scope_id).into(),
                ))
            }
            #[cfg(target_os = "linux")]
            defs::LINUX_AF_UNIX => Some(VsockAddr::Unix(buf[..len].to_vec())),
            _ => None,
        }
    }

    /// Serialize to the guest's Linux sockaddr wire format. INET addresses always
    /// emit Linux layout regardless of host, so the value can be copied straight
    /// into a guest getname reply; AF_UNIX echoes back the raw bytes.
    pub fn to_linux_bytes(&self) -> Vec<u8> {
        match self {
            VsockAddr::Inet(SocketAddr::V4(a)) => {
                let mut b = vec![0u8; LINUX_SOCKADDR_IN_LEN];
                b[0..2].copy_from_slice(&defs::LINUX_AF_INET.to_le_bytes());
                b[2..4].copy_from_slice(&a.port().to_be_bytes());
                b[4..8].copy_from_slice(&a.ip().octets());
                b
            }
            VsockAddr::Inet(SocketAddr::V6(a)) => {
                let mut b = vec![0u8; LINUX_SOCKADDR_IN6_LEN];
                b[0..2].copy_from_slice(&defs::LINUX_AF_INET6.to_le_bytes());
                b[2..4].copy_from_slice(&a.port().to_be_bytes());
                b[4..8].copy_from_slice(&a.flowinfo().to_be_bytes());
                b[8..24].copy_from_slice(&a.ip().octets());
                b[24..28].copy_from_slice(&a.scope_id().to_le_bytes());
                b
            }
            #[cfg(target_os = "linux")]
            VsockAddr::Unix(raw) => raw.clone(),
        }
    }

    /// Length of the Linux sockaddr this address serializes to.
    pub fn linux_len(&self) -> u32 {
        match self {
            VsockAddr::Inet(SocketAddr::V4(_)) => LINUX_SOCKADDR_IN_LEN as u32,
            VsockAddr::Inet(SocketAddr::V6(_)) => LINUX_SOCKADDR_IN6_LEN as u32,
            #[cfg(target_os = "linux")]
            VsockAddr::Unix(raw) => raw.len() as u32,
        }
    }

    /// The INET address, for handing to `socket2`/`std::net`. `None` for AF_UNIX.
    pub fn inet(&self) -> Option<SocketAddr> {
        match self {
            VsockAddr::Inet(a) => Some(*a),
            #[cfg(target_os = "linux")]
            VsockAddr::Unix(_) => None,
        }
    }

    /// Filesystem path of an AF_UNIX address, if any (Linux only). The guest
    /// `sockaddr_un` is `family:u16` followed by a NUL-terminated path.
    #[cfg(target_os = "linux")]
    pub fn unix_path(&self) -> Option<PathBuf> {
        match self {
            VsockAddr::Unix(raw) if raw.len() > 2 => {
                let path = &raw[2..];
                let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
                let s = std::str::from_utf8(&path[..end]).ok()?;
                if s.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(s))
                }
            }
            _ => None,
        }
    }
}

impl VsockAddr {
    /// Whether this guest-supplied address may be used on a proxy of `family`.
    ///
    /// The family is fixed when the proxy is created, and that is where the TSI
    /// flags gate AF_UNIX. An address arrives later, in a listen, connect or
    /// sendto, and must not switch an INET proxy over to host filesystem paths.
    /// INET addresses are allowed on either INET family: the host socket decides
    /// whether a v4 address suits a v6 socket, as Linux does for the guest.
    pub fn suits_family(&self, family: Family) -> bool {
        match self {
            VsockAddr::Inet(_) => matches!(family, Family::Inet | Family::Inet6),
            #[cfg(target_os = "linux")]
            VsockAddr::Unix(_) => family == Family::Unix,
        }
    }
}

/// Clear the way for binding an AF_UNIX listener at a guest-chosen host path.
///
/// Only a stale socket node is removed. Anything else at the path, whether a
/// file, a directory or a symlink, is refused with `EADDRINUSE`, as `bind(2)`
/// itself would, so a guest can never use a listen to delete a host file.
#[cfg(target_os = "linux")]
pub fn remove_stale_unix_socket(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        Ok(_) => Err(std::io::Error::from_raw_os_error(libc::EADDRINUSE)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether `path` is still a socket node, without following a symlink.
#[cfg(target_os = "linux")]
pub fn is_unix_socket_node(path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
}

impl From<SocketAddr> for VsockAddr {
    fn from(addr: SocketAddr) -> Self {
        VsockAddr::Inet(addr)
    }
}

impl From<SocketAddrV4> for VsockAddr {
    fn from(addr: SocketAddrV4) -> Self {
        VsockAddr::Inet(SocketAddr::V4(addr))
    }
}

impl From<SocketAddrV6> for VsockAddr {
    fn from(addr: SocketAddrV6) -> Self {
        VsockAddr::Inet(SocketAddr::V6(addr))
    }
}

impl std::fmt::Display for VsockAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VsockAddr::Inet(a) => write!(f, "{a}"),
            #[cfg(target_os = "linux")]
            VsockAddr::Unix(_) => match self.unix_path() {
                Some(p) => write!(f, "unix:{}", p.display()),
                None => write!(f, "unix:<unnamed>"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_round_trip() {
        let buf = [
            2, 0, // AF_INET (LE)
            0x1f, 0x90, // port 8080 (BE)
            127, 0, 0, 1, // 127.0.0.1
            0, 0, 0, 0, 0, 0, 0, 0, // padding
        ];
        let addr = VsockAddr::parse_linux(&buf, 16).unwrap();
        assert_eq!(
            addr.inet().unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(addr.linux_len(), 16);
        assert_eq!(&addr.to_linux_bytes()[..8], &buf[..8]);
    }

    #[test]
    fn ipv6_round_trip() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let original = VsockAddr::Inet(SocketAddrV6::new(ip, 443, 0, 7).into());
        let bytes = original.to_linux_bytes();
        assert_eq!(bytes.len(), 28);
        assert_eq!(
            u16::from_le_bytes([bytes[0], bytes[1]]),
            defs::LINUX_AF_INET6
        );
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 443);
        // Linux sin6_scope_id is native endian, unlike port and flowinfo.
        assert_eq!(&bytes[24..28], &[7, 0, 0, 0]);

        let parsed = VsockAddr::parse_linux(&bytes, 28).unwrap();
        assert_eq!(parsed, original);
        match parsed.inet().unwrap() {
            SocketAddr::V6(a) => {
                assert_eq!(*a.ip(), ip);
                assert_eq!(a.port(), 443);
                assert_eq!(a.scope_id(), 7);
            }
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn rejects_short_and_unknown() {
        assert!(VsockAddr::parse_linux(&[2, 0, 0, 0], 16).is_none());
        assert!(VsockAddr::parse_linux(&[2, 0, 0], 3).is_none());
        let mut buf = [0u8; 16];
        buf[0] = 99;
        assert!(VsockAddr::parse_linux(&buf, 16).is_none());
        assert!(VsockAddr::parse_linux(&buf, 0).is_none());
        buf[0] = defs::LINUX_AF_INET as u8;
        assert!(VsockAddr::parse_linux(&buf, 2).is_none());
        let mut v6 = [0; 28];
        v6[0] = defs::LINUX_AF_INET6 as u8;
        assert!(VsockAddr::parse_linux(&v6, 16).is_none());
    }

    #[test]
    fn ipv4_port_and_addr_byte_order() {
        let addr = VsockAddr::Inet(SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 2), 53).into());
        let b = addr.to_linux_bytes();
        assert_eq!(&b[0..2], &[2, 0]);
        assert_eq!(&b[2..4], &53u16.to_be_bytes());
        assert_eq!(&b[4..8], &[10, 0, 2, 2]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_path_round_trip() {
        let mut buf = vec![1u8, 0]; // AF_UNIX (LE)
        buf.extend_from_slice(b"/tmp/sock\0");
        let addr = VsockAddr::parse_linux(&buf, buf.len() as u32).unwrap();
        assert_eq!(addr.unix_path().unwrap(), PathBuf::from("/tmp/sock"));
        assert_eq!(addr.inet(), None);
        assert_eq!(addr.to_linux_bytes(), buf);
    }

    #[test]
    fn an_inet_address_cannot_switch_a_proxy_to_another_family() {
        let v4 = VsockAddr::from("127.0.0.1:80".parse::<SocketAddr>().unwrap());
        assert!(v4.suits_family(Family::Inet));
        assert!(v4.suits_family(Family::Inet6));
        #[cfg(target_os = "linux")]
        {
            assert!(!v4.suits_family(Family::Unix));
            let mut buf = vec![1, 0];
            buf.extend_from_slice(b"/home/someone/notes\0");
            let unix = VsockAddr::parse_linux(&buf, buf.len() as u32).unwrap();
            assert!(!unix.suits_family(Family::Inet));
            assert!(!unix.suits_family(Family::Inet6));
            assert!(unix.suits_family(Family::Unix));
        }
    }

    /// A guest's listen names a host path; only a stale socket there may go.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_listen_path_removes_only_a_stale_socket() {
        let dir = std::env::temp_dir().join(format!("tsi-unlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let file = dir.join("notes");
        std::fs::write(&file, "keep").unwrap();
        let err = remove_stale_unix_socket(&file).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EADDRINUSE));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep");

        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(remove_stale_unix_socket(&link).is_err());
        assert!(std::fs::symlink_metadata(&link).is_ok());
        assert!(!is_unix_socket_node(&link));

        let sub = dir.join("dir");
        std::fs::create_dir(&sub).unwrap();
        assert!(remove_stale_unix_socket(&sub).is_err());
        assert!(sub.is_dir());

        let sock = dir.join("sock");
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
        assert!(is_unix_socket_node(&sock));
        remove_stale_unix_socket(&sock).unwrap();
        assert!(std::fs::symlink_metadata(&sock).is_err());

        remove_stale_unix_socket(&dir.join("missing")).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
