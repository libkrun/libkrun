//! Only explicit Linux option numbers cross the TSI boundary.
use super::defs;
use super::proxy::{AddressFamily, RawFd};
use super::tsi_wire;
#[cfg(unix)]
use libc as native;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock as native;

fn option(
    family: AddressFamily,
    kind: u16,
    level: u32,
    name: u32,
    set: bool,
) -> Result<(i32, i32), i32> {
    #[cfg(unix)]
    let (inet, inet6) = (
        family == AddressFamily::Inet,
        family == AddressFamily::Inet6,
    );
    #[cfg(windows)]
    let (inet, inet6) = (family == native::AF_INET, family == native::AF_INET6);
    let mapped = match (level, name) {
        (1, 2) => (native::SOL_SOCKET, native::SO_REUSEADDR),
        #[cfg(unix)]
        (1, 15) if inet || inet6 => (native::SOL_SOCKET, native::SO_REUSEPORT),
        (1, 9) => (native::SOL_SOCKET, native::SO_KEEPALIVE),
        (1, 6) => (native::SOL_SOCKET, native::SO_BROADCAST),
        (1, 7) => (native::SOL_SOCKET, native::SO_SNDBUF),
        (1, 8) => (native::SOL_SOCKET, native::SO_RCVBUF),
        (1, 4) if !set => (native::SOL_SOCKET, native::SO_ERROR),
        (6, 1) if (inet || inet6) && kind == defs::SOCK_STREAM => {
            (native::IPPROTO_TCP, native::TCP_NODELAY)
        }
        (41, 26) if inet6 => (native::IPPROTO_IPV6, native::IPV6_V6ONLY),
        _ => return Err(-tsi_wire::ENOPROTOOPT),
    };
    Ok(mapped)
}

/// Linux SO_REUSEADDR only permits rebinding over TIME_WAIT, which Winsock
/// already allows by default. Winsock SO_REUSEADDR would instead let the guest
/// bind ports that host processes are actively using, so the guest value is
/// kept without touching the host socket.
#[cfg(windows)]
#[derive(Default)]
pub(super) struct GuestOnlyOptions {
    reuse_addr: AtomicBool,
}

#[cfg(windows)]
impl GuestOnlyOptions {
    pub(super) fn apply(&self, level: u32, name: u32, value: Option<i32>) -> Option<i32> {
        if (level, name) != (1, 2) {
            return None;
        }
        Some(match value {
            Some(value) => {
                self.reuse_addr.store(value != 0, Ordering::Relaxed);
                0
            }
            None => i32::from(self.reuse_addr.load(Ordering::Relaxed)),
        })
    }
}

fn linux_error(code: i32) -> i32 {
    if code == 0 {
        return 0;
    }
    #[cfg(target_os = "linux")]
    {
        code
    }
    #[cfg(target_os = "macos")]
    {
        super::super::linux_errno::linux_errno_raw(code)
    }
    #[cfg(windows)]
    {
        super::super::linux_errno::wsa_errno_to_linux(code)
    }
}

pub(super) fn socket_option(
    fd: RawFd,
    family: AddressFamily,
    kind: u16,
    level: u32,
    name: u32,
    value: Option<i32>,
) -> Result<i32, i32> {
    let (native_level, native_name) = option(family, kind, level, name, value.is_some())?;
    let mut data = value.unwrap_or(0);
    #[cfg(unix)]
    let result = unsafe {
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        if value.is_some() {
            libc::setsockopt(
                fd,
                native_level,
                native_name,
                (&data as *const i32).cast(),
                len,
            )
        } else {
            libc::getsockopt(
                fd,
                native_level,
                native_name,
                (&mut data as *mut i32).cast(),
                &mut len,
            )
        }
    };
    #[cfg(windows)]
    let result = unsafe {
        let mut len = std::mem::size_of::<i32>() as i32;
        if value.is_some() {
            native::setsockopt(
                fd as usize,
                native_level,
                native_name,
                (&data as *const i32).cast(),
                len,
            )
        } else {
            native::getsockopt(
                fd as usize,
                native_level,
                native_name,
                (&mut data as *mut i32).cast(),
                &mut len,
            )
        }
    };
    if result != 0 {
        #[cfg(unix)]
        let error = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(tsi_wire::EIO);
        #[cfg(windows)]
        let error = unsafe { native::WSAGetLastError() };
        return Err(-linux_error(error));
    }
    if level == 1 && name == 4 {
        data = linux_error(data);
    } else if value.is_none() && matches!((level, name), (1, 2 | 15 | 9 | 6) | (6, 1) | (41, 26)) {
        data = i32::from(data != 0);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::fd::AsRawFd;

    #[test]
    fn reject_options_outside_allowlist() {
        #[cfg(unix)]
        let family = AddressFamily::Inet;
        #[cfg(windows)]
        let family = native::AF_INET;
        for (level, name) in [(1, 1), (1, 32), (1, 33), (1, 25), (1, 50), (0, 2), (6, 99)] {
            assert_eq!(
                option(family, defs::SOCK_STREAM, level, name, true),
                Err(-tsi_wire::ENOPROTOOPT)
            );
        }
        assert_eq!(
            option(family, defs::SOCK_DGRAM, 6, 1, true),
            Err(-tsi_wire::ENOPROTOOPT)
        );
        assert_eq!(
            option(family, defs::SOCK_STREAM, 41, 26, true),
            Err(-tsi_wire::ENOPROTOOPT)
        );
        assert_eq!(
            option(family, defs::SOCK_STREAM, 1, 4, true),
            Err(-tsi_wire::ENOPROTOOPT)
        );
    }

    #[cfg(windows)]
    #[test]
    fn reuse_addr_stays_guest_only() {
        let options = GuestOnlyOptions::default();
        assert_eq!(options.apply(1, 2, None), Some(0));
        assert_eq!(options.apply(1, 2, Some(5)), Some(0));
        assert_eq!(options.apply(1, 2, None), Some(1));
        assert_eq!(options.apply(1, 2, Some(0)), Some(0));
        assert_eq!(options.apply(1, 2, None), Some(0));
        assert_eq!(options.apply(1, 9, Some(1)), None);
    }

    #[test]
    fn no_pending_error_is_zero() {
        assert_eq!(linux_error(0), 0);
    }

    #[cfg(unix)]
    #[test]
    fn changes_the_native_socket() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();
        socket_option(fd, AddressFamily::Inet, defs::SOCK_DGRAM, 1, 6, Some(1)).unwrap();
        assert!(socket.broadcast().unwrap());
        socket_option(fd, AddressFamily::Inet, defs::SOCK_DGRAM, 1, 6, Some(0)).unwrap();
        assert!(!socket.broadcast().unwrap());
        assert_eq!(
            socket_option(fd, AddressFamily::Inet, defs::SOCK_DGRAM, 1, 4, None).unwrap(),
            0
        );
    }
}
