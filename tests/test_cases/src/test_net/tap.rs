//! TAP backend for virtio-net test

use nix::libc;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use std::fs::OpenOptions;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

use crate::{ShouldRun, TestSetup};

const DEFAULT_TAP_NAME: &str = "tap0";
const HOST_IP: [u8; 4] = [10, 0, 0, 1];
const NETMASK: [u8; 4] = [255, 255, 255, 0];

fn interface_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}", name)).exists()
}

// TAP device setup
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const TUNSETPERSIST: libc::c_ulong = 0x400454cb;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_VNET_HDR: libc::c_short = 0x4000;
const IFNAMSIZ: usize = 16;
const IFF_UP: libc::c_short = 0x1;
const IFF_RUNNING: libc::c_short = 0x40;

#[repr(C)]
struct Ifreq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifru: IfreqIfru,
}

#[repr(C)]
#[derive(Copy, Clone)]
union IfreqIfru {
    ifru_flags: libc::c_short,
    ifru_addr: libc::sockaddr,
    _pad: [u8; 24],
}

nix::ioctl_write_ptr_bad!(ioctl_tunsetiff, TUNSETIFF, Ifreq);
nix::ioctl_write_int_bad!(ioctl_tunsetpersist, TUNSETPERSIST);
nix::ioctl_readwrite_bad!(ioctl_siocsifaddr, 0x8916, Ifreq);
nix::ioctl_readwrite_bad!(ioctl_siocsifnetmask, 0x891c, Ifreq);
nix::ioctl_readwrite_bad!(ioctl_siocgifflags, 0x8913, Ifreq);
nix::ioctl_readwrite_bad!(ioctl_siocsifflags, 0x8914, Ifreq);

fn set_interface_name(ifr: &mut Ifreq, name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(IFNAMSIZ - 1);
    ifr.ifr_name = [0u8; IFNAMSIZ];
    ifr.ifr_name[..len].copy_from_slice(&bytes[..len]);
}

fn make_sockaddr_in(ip: [u8; 4]) -> libc::sockaddr {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from_ne_bytes(ip);
    unsafe { std::mem::transmute(addr) }
}

fn create_tap(name: &str) -> std::io::Result<()> {
    let tun = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    set_interface_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
    unsafe { ioctl_tunsetiff(tun.as_raw_fd(), &ifr) }.map_err(std::io::Error::other)?;
    unsafe { ioctl_tunsetpersist(tun.as_raw_fd(), 1) }.map_err(std::io::Error::other)?;
    Ok(())
}

fn configure_host_interface(name: &str, ip: [u8; 4], netmask: [u8; 4]) -> nix::Result<()> {
    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;
    let fd = sock.as_raw_fd();

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    set_interface_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_addr = make_sockaddr_in(ip);
    unsafe { ioctl_siocsifaddr(fd, &mut ifr)? };

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    set_interface_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_addr = make_sockaddr_in(netmask);
    unsafe { ioctl_siocsifnetmask(fd, &mut ifr)? };

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    set_interface_name(&mut ifr, name);
    unsafe { ioctl_siocgifflags(fd, &mut ifr)? };
    unsafe { ifr.ifr_ifru.ifru_flags |= IFF_UP | IFF_RUNNING };
    unsafe { ioctl_siocsifflags(fd, &mut ifr)? };

    Ok(())
}

fn dnsmasq_available() -> bool {
    Command::new("which")
        .arg("dnsmasq")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub(crate) fn should_run() -> ShouldRun {
    if cfg!(target_os = "macos") {
        return ShouldRun::No("TAP not supported on macOS");
    }
    if let Ok(tap_name) = std::env::var("LIBKRUN_TAP_NAME") {
        if !interface_exists(&tap_name) {
            return ShouldRun::No("TAP interface not found");
        }
    } else if !std::path::Path::new("/dev/net/tun").exists() {
        return ShouldRun::No("/dev/net/tun not available");
    }
    if !dnsmasq_available() {
        return ShouldRun::No("dnsmasq not installed");
    }
    ShouldRun::Yes
}

pub(crate) fn cleanup() {
    if let Ok(tun) = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
    {
        let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
        set_interface_name(&mut ifr, DEFAULT_TAP_NAME);
        ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;
        if unsafe { ioctl_tunsetiff(tun.as_raw_fd(), &ifr) }.is_ok() {
            let _ = unsafe { ioctl_tunsetpersist(tun.as_raw_fd(), 0) };
        }
    }
}

fn start_dhcp_server(tap_name: &str, test_setup: &TestSetup) -> anyhow::Result<()> {
    let lease_file = test_setup.tmp_dir.join("dnsmasq.leases");
    let child = Command::new("dnsmasq")
        .arg("--no-daemon")
        .arg(format!("--interface={tap_name}"))
        .arg("--dhcp-range=10.0.0.2,10.0.0.10,255.255.255.0")
        .arg("--dhcp-option=3,10.0.0.1") // gateway
        .arg("--dhcp-rapid-commit") // init's DHCP client uses Rapid Commit
        .arg("--no-ping") // skip ARP probe delay before assigning
        .arg(format!("--dhcp-leasefile={}", lease_file.display()))
        .arg("--bind-dynamic")
        .arg("--except-interface=lo")
        .arg("--port=0") // disable DNS, we only need DHCP
        .arg("--no-resolv")
        .arg("--no-hosts")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to start dnsmasq: {e}"))?;
    test_setup.register_cleanup_pid(child.id());

    // Wait for dnsmasq to bind port 67 before proceeding
    for _ in 0..50 {
        if UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67)).is_err() {
            return Ok(()); // port 67 is taken — dnsmasq is ready
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    anyhow::bail!("dnsmasq did not start in time");
}

pub(crate) fn setup_backend(test_setup: &TestSetup) -> anyhow::Result<krun::NetDevice> {
    let tap_name = if let Ok(name) = std::env::var("LIBKRUN_TAP_NAME") {
        name
    } else {
        create_tap(DEFAULT_TAP_NAME)?;
        configure_host_interface(DEFAULT_TAP_NAME, HOST_IP, NETMASK)
            .map_err(|e| anyhow::anyhow!("Failed to configure TAP: {}", e))?;
        start_dhcp_server(DEFAULT_TAP_NAME, test_setup)?;
        DEFAULT_TAP_NAME.to_string()
    };

    let mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

    krun::NetDevice::new_tap(
        "net0",
        &tap_name,
        &mac,
        crate::test_net::COMPAT_NET_FEATURES,
    )
    .map_err(|e| anyhow::anyhow!("NetDevice: {e:?}"))
}
