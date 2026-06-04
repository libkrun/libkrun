use std::env;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::mem;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::ptr;

#[cfg(target_os = "linux")]
use nix::errno::Errno;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};

#[cfg(target_os = "linux")]
pub fn setup_network(iface: &str) {
    let Ok(sock) = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    ) else {
        return;
    };
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let lo = c"lo";
    unsafe {
        ptr::copy_nonoverlapping(
            lo.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            lo.to_bytes_with_nul().len(),
        );
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &ifr);
    }

    setup_dhcp(iface, sock.as_raw_fd());
}

#[cfg(target_os = "freebsd")]
pub fn setup_network() {
    // Bring up the loopback interface on FreeBSD.
    //
    // libc does not export SIOCSIFFLAGS for FreeBSD targets; the ioctl number
    // is _IOW('i', 16, struct ifreq) = 0x80206910 on both aarch64 and x86_64
    // (sizeof(struct ifreq) == 32 on both).
    const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;

    let Ok(sock) = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    ) else {
        return;
    };
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let lo = c"lo";
    unsafe {
        ptr::copy_nonoverlapping(
            lo.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            lo.to_bytes_with_nul().len(),
        );
        // On FreeBSD, ifru_flags is [c_short; 2]; index 0 holds the flags value.
        ifr.ifr_ifru.ifru_flags[0] |= libc::IFF_UP as libc::c_short;
        libc::ioctl(sock.as_raw_fd(), SIOCSIFFLAGS as _, &ifr);
    }
}

// On macOS host builds and other non-Linux, non-FreeBSD platforms the
// loopback interface is already configured by the OS.
#[cfg(all(not(target_os = "linux"), not(target_os = "freebsd")))]
pub fn setup_network() {}

#[cfg(target_os = "linux")]
fn setup_dhcp(iface: &str, sock: i32) {
    if std::env::var("KRUN_DHCP").as_deref() != Ok("1") {
        return;
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = iface.as_bytes();
    unsafe {
        ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            name_bytes.len().min(libc::IFNAMSIZ - 1),
        );
    }
    let exists = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) } == 0;
    if exists {
        unsafe {
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr);
        }
        if let Err(e) = crate::dhcp::do_dhcp(iface) {
            eprintln!("Warning: DHCP configuration for {iface} failed: {e}");
        }
    }
}

/// Returns true if `tsi_hijack` appears in the kernel command line before any
/// `--` delimiter. Mirrors `tsi_enabled()` in init.c.
#[cfg(target_os = "linux")]
pub fn tsi_enabled() -> bool {
    let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") else {
        return false;
    };
    cmdline
        .split_whitespace()
        .take_while(|tok| *tok != "--")
        .any(|tok| tok == "tsi_hijack")
}

/// Brings up `dummy0` and assigns it 203.0.113.1/24 (IANA TEST-NET-3) so
/// that applications probing for network availability see a configured
/// interface when TSI is in use. Silently succeeds when the dummy driver is
/// absent.
/// Mirrors `enable_dummy_interface()` in init.c.
#[cfg(target_os = "linux")]
pub fn enable_dummy_interface() {
    use std::net::Ipv4Addr;

    let Ok(sock) = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    ) else {
        eprintln!("Warning: dummy interface socket failed");
        return;
    };

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name = c"dummy0";
    unsafe {
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            name.to_bytes_with_nul().len(),
        );
        ifr.ifr_ifru.ifru_flags = libc::IFF_UP as libc::c_short;
    }

    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &ifr) };
    if ret < 0 {
        if Errno::last() != Errno::ENODEV {
            eprintln!("Warning: dummy interface up failed");
        }
        return;
    }

    // Set IP address to 203.0.113.1 (IANA TEST-NET-3).
    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes(Ipv4Addr::new(203, 0, 113, 1).octets());
    unsafe {
        ifr.ifr_ifru.ifru_addr = *(&sin as *const libc::sockaddr_in as *const libc::sockaddr);
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR as _, &ifr) < 0 {
            eprintln!("Warning: dummy interface address failed");
            return;
        }
    }

    // Set netmask to 255.255.255.0.
    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes(Ipv4Addr::new(255, 255, 255, 0).octets());
    unsafe {
        ifr.ifr_ifru.ifru_netmask = *(&sin as *const libc::sockaddr_in as *const libc::sockaddr);
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK as _, &ifr) < 0 {
            eprintln!("Warning: dummy interface mask failed");
        }
    }
}

pub fn apply_hostname() {
    let hostname = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into());
    let _ = nix::unistd::sethostname(&hostname);
}

pub fn apply_env() {
    if let Ok(home) = env::var("KRUN_HOME") {
        unsafe { env::set_var("HOME", home) };
    }
    if let Ok(term) = env::var("KRUN_TERM") {
        unsafe { env::set_var("TERM", term) };
    }
}

pub fn apply_rlimits() {
    let Ok(rlimits) = env::var("KRUN_RLIMITS") else {
        return;
    };
    // krun_set_rlimits() wraps the value in outer double-quotes; strip them.
    let s = rlimits.trim_matches('"');
    for item in s.split(',') {
        if let Some((id, cur, max)) = parse_rlimit_entry(item) {
            let rlim = libc::rlimit {
                rlim_cur: cur,
                rlim_max: max,
            };
            unsafe { libc::setrlimit(id as _, &rlim) };
        }
    }
}

// Accept both "ID=CUR:MAX" (Rust format) and "ID:CUR:MAX" (C format) by
// splitting on the first two occurrences of either '=' or ':'.
fn parse_rlimit_entry(item: &str) -> Option<(u32, libc::rlim_t, libc::rlim_t)> {
    let item = item.trim_matches('"');
    let parts: Vec<&str> = item.splitn(3, ['=', ':']).collect();
    let [id, cur, max] = parts.as_slice() else {
        return None;
    };
    let id = id.parse::<u32>().ok()?;
    let cur = cur.parse::<libc::rlim_t>().ok()?;
    let max = max.parse::<libc::rlim_t>().ok()?;
    Some((id, cur, max))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlimit_equals_format() {
        assert_eq!(parse_rlimit_entry("7=1024:4096"), Some((7, 1024, 4096)));
    }

    #[test]
    fn rlimit_colon_format() {
        assert_eq!(parse_rlimit_entry("7:1024:4096"), Some((7, 1024, 4096)));
    }

    #[test]
    fn rlimit_outer_quotes_stripped() {
        assert_eq!(parse_rlimit_entry("\"7=1024:4096\""), Some((7, 1024, 4096)));
    }

    #[test]
    fn rlimit_trailing_quote_stripped() {
        // Last item in a quoted list has a trailing '"'.
        assert_eq!(parse_rlimit_entry("11=512:1024\""), Some((11, 512, 1024)));
    }

    #[test]
    fn rlimit_too_few_parts_is_none() {
        assert_eq!(parse_rlimit_entry("7:1024"), None);
    }

    #[test]
    fn rlimit_non_numeric_is_none() {
        assert_eq!(parse_rlimit_entry("invalid"), None);
    }
}
