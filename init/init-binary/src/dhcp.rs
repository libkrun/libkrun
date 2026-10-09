use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Error as IoError;
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::slice;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use nix::errno::Errno;
use nix::net::if_;
use nix::sys::socket::{
    self, AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType, SockaddrIn, sockopt,
};
use nix::sys::time::{TimeVal, TimeValLike};
use nix::unistd::{self, ForkResult};

const DHCP_BUFFER_SIZE: usize = 576;
/// How long to keep retransmitting a request before giving up. A TAP attached
/// to a bridge with STP can take several seconds to start forwarding, so a
/// single-shot request is easily lost.
const DHCP_RETRY_WINDOW: Duration = Duration::from_secs(8);
/// Receive timeout, and therefore retransmit interval, for each attempt.
const DHCP_RETRY_INTERVAL: Duration = Duration::from_millis(250);
/// How long to wait for a reply to a renewal request.
const DHCP_RENEW_TIMEOUT: Duration = Duration::from_secs(3);
/// BOOTP vendor-specific area size (64) - magic cookie (4)
const DHCP_OPTIONS_SIZE: usize = 60;
const DHCP_OPTIONS_OFFSET: usize = 240;
const DHCP_OPTIONS_END: u8 = 0xff;
const DHCP_MSG_OFFER: u8 = 2;
const DHCP_MSG_REQUEST: u8 = 3;
const DHCP_MSG_ACK: u8 = 5;
const DHCP_MSG_NAK: u8 = 6;
/// RFC 2131: BOOTP/DHCP server
const DHCP_SERVER_PORT: u16 = 67;
/// RFC 2131: BOOTP/DHCP client
const DHCP_CLIENT_PORT: u16 = 68;
/// RFC 2131: client-to-server message
const BOOTREQUEST: u8 = 1;
/// IANA hardware type for Ethernet
const HTYPE_ETHERNET: u8 = 1;
/// Ethernet MAC address length in bytes
const HLEN_ETHERNET: u8 = 6;
/// RFC 2131 §2: request broadcast reply (client has no IP yet)
const DHCP_FLAG_BROADCAST: u16 = 0x8000;
/// RFC 2132: marks options as DHCP format (99.130.83.99)
const DHCP_MAGIC_COOKIE: u32 = 0x6382_5363;

// libc doesn't expose ifinfomsg, ifaddrmsg, or rtmsg — define them locally.

#[repr(C)]
struct IfInfoMsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

/// DHCP Packet structure  (RFC 2131)
#[repr(C, packed)]
struct DhcpPacket {
    /// Message op code / message type
    op: u8,
    /// Hardware address type
    htype: u8,
    /// Hardware address length
    hlen: u8,
    // Client sets to zero
    hops: u8,
    /// Transaction ID
    xid: u32,
    /// Seconds elapsed since client began address acquisition
    secs: u16,
    /// Flags
    flags: u16,
    /// Client IP address
    ciaddr: u32,
    /// 'Your' (client) IP address
    yiaddr: u32,
    /// IP address of next server to use in bootstrap
    siaddr: u32,
    /// Relay agent IP address
    giaddr: u32,
    /// Client hardware address
    chaddr: [u8; 16],
    /// Optional server host name
    sname: [u8; 64],
    /// Boot file name
    file: [u8; 128],
    /// Magic cookie
    magic: u32,
    /// Options
    options: [u8; DHCP_OPTIONS_SIZE],
}

impl DhcpPacket {
    fn zeroed() -> Self {
        // SAFETY: DhcpPacket is plain-old-data with no padding invariants.
        unsafe { mem::zeroed() }
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: packed repr, no padding; reading as bytes is valid.
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, mem::size_of::<Self>()) }
    }
}

struct DhcpOptionsWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> DhcpOptionsWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn push(&mut self, code: u8, data: &[u8]) {
        self.buf[self.pos] = code;
        self.buf[self.pos + 1] = data.len() as u8;
        self.buf[self.pos + 2..self.pos + 2 + data.len()].copy_from_slice(data);
        self.pos += 2 + data.len();
    }

    fn finish(self) {
        self.buf[self.pos] = DHCP_OPTIONS_END;
    }
}

/// Iterator over DHCP options in a TLV (type-length-value) encoded buffer (RFC 2132).
///
/// Each call to `next()` yields `(option_code, data)`. Padding bytes (0x00)
/// are skipped automatically. Iteration stops at the end marker (0xFF) or
/// when the buffer is too short to contain a well-formed option.
struct DhcpOptions<'a> {
    remaining: &'a [u8],
}

impl<'a> DhcpOptions<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { remaining: buf }
    }
}

impl<'a> Iterator for DhcpOptions<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (&opt, rest) = self.remaining.split_first()?;
            if opt == DHCP_OPTIONS_END {
                self.remaining = &[];
                return None;
            }
            self.remaining = rest;
            if opt == 0 {
                continue;
            }
            let (&len, rest) = self.remaining.split_first()?;
            let (data, rest) = rest.split_at_checked(len as usize)?;
            self.remaining = rest;
            return Some((opt, data));
        }
    }
}

fn struct_as_bytes<T: Sized>(v: &T) -> &[u8] {
    unsafe { slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>()) }
}

/// Add up to half of `d` based on the current time, so concurrently booting
/// VMs do not retransmit in lockstep.
fn jitter(d: Duration) -> Duration {
    let spread = (d.as_millis() as u64 / 2).max(1);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |t| u64::from(t.subsec_nanos()));
    d + Duration::from_millis(now % spread)
}

/// Helper function to send netlink message
fn nl_send(sock: libc::c_int, buf: &[u8]) -> anyhow::Result<()> {
    // Use mem::zeroed() so the opaque nl_pad field is correctly initialised.
    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;

    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut _,
        iov_len: buf.len(),
    };
    // Use zeroed() rather than a struct literal: musl's msghdr has private
    // padding fields (__pad1, __pad2) that cannot be named in a literal.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &sa as *const _ as *mut _;
    msg.msg_namelen = mem::size_of_val(&sa) as u32;
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
    if ret < 0 {
        bail!("nl_send: {}", IoError::last_os_error());
    }
    Ok(())
}

/// Helper function to receive netlink response
fn nl_recv(sock: libc::c_int, buf: &mut [u8]) -> anyhow::Result<usize> {
    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut sa as *mut _ as *mut _;
    msg.msg_namelen = mem::size_of_val(&sa) as u32;
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if ret < 0 {
        bail!("nl_recv: {}", IoError::last_os_error());
    }
    Ok(ret as usize)
}

/// Add routing attribute to netlink message
fn add_rtattr(buf: &mut [u8], msg_len: &mut usize, rta_type: u16, data: &[u8]) {
    let rta_len = (4 + data.len()) as u16;
    let aligned_start = (*msg_len + 3) & !3;
    let end = aligned_start + ((rta_len as usize + 3) & !3);
    assert!(end <= buf.len(), "netlink buffer too small");

    buf[aligned_start..aligned_start + 2].copy_from_slice(&rta_len.to_ne_bytes());
    buf[aligned_start + 2..aligned_start + 4].copy_from_slice(&rta_type.to_ne_bytes());
    buf[aligned_start + 4..aligned_start + 4 + data.len()].copy_from_slice(data);
    buf[aligned_start + 4 + data.len()..end].fill(0);

    *msg_len = end;
    buf[0..4].copy_from_slice(&(*msg_len as u32).to_ne_bytes());
}

fn nl_check_ack(buf: &[u8], recv_len: usize, op: &str) -> anyhow::Result<()> {
    let min = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<libc::nlmsgerr>();
    if recv_len < min {
        bail!("{op}: netlink response too short");
    }
    let nlmsg_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
    if nlmsg_type != libc::NLMSG_ERROR as u16 {
        bail!("{op}: expected NLMSG_ERROR ACK, got type {nlmsg_type}");
    }
    let err_offset = mem::size_of::<libc::nlmsghdr>();
    let err = i32::from_ne_bytes(buf[err_offset..err_offset + 4].try_into().unwrap());
    if err != 0 {
        bail!("{op}: netlink error {err}");
    }
    Ok(())
}

fn nl_hdr(buf: &mut [u8], msg_len: usize, nlmsg_type: u16, flags: u16) {
    let nlh = libc::nlmsghdr {
        nlmsg_len: msg_len as u32,
        nlmsg_type,
        nlmsg_flags: flags,
        nlmsg_seq: 1,
        nlmsg_pid: unistd::getpid().as_raw() as u32,
    };
    buf[..mem::size_of_val(&nlh)].copy_from_slice(struct_as_bytes(&nlh));
}

fn set_mtu(nl_sock: libc::c_int, iface_index: i32, mtu: u32) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let base = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<IfInfoMsg>();
    let mut msg_len = base;

    nl_hdr(
        &mut buf,
        base,
        libc::RTM_NEWLINK,
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
    );

    let ifi = IfInfoMsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: libc::ARPHRD_ETHER,
        ifi_index: iface_index,
        ifi_flags: 0,
        ifi_change: 0,
    };
    let ifi_off = mem::size_of::<libc::nlmsghdr>();
    buf[ifi_off..ifi_off + mem::size_of_val(&ifi)].copy_from_slice(struct_as_bytes(&ifi));

    add_rtattr(&mut buf, &mut msg_len, libc::IFLA_MTU, &mtu.to_ne_bytes());

    nl_send(nl_sock, &buf[..msg_len])?;
    // Receive ACK
    let recv_len = nl_recv(nl_sock, &mut buf)?;
    nl_check_ack(&buf, recv_len, "set_mtu")
}

/// Add or delete IPv4 address
fn mod_addr4(
    nl_sock: libc::c_int,
    iface_index: i32,
    cmd: u16,
    addr: u32,
    prefix_len: u8,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let base = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<IfAddrMsg>();
    let mut msg_len = base;

    nl_hdr(
        &mut buf,
        base,
        cmd,
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16,
    );

    let ifa = IfAddrMsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: prefix_len,
        ifa_flags: 0,
        ifa_scope: libc::RT_SCOPE_UNIVERSE,
        ifa_index: iface_index as u32,
    };
    let ifa_off = mem::size_of::<libc::nlmsghdr>();
    buf[ifa_off..ifa_off + mem::size_of_val(&ifa)].copy_from_slice(struct_as_bytes(&ifa));

    let addr_bytes = addr.to_ne_bytes();
    add_rtattr(&mut buf, &mut msg_len, libc::IFA_LOCAL, &addr_bytes);
    add_rtattr(&mut buf, &mut msg_len, libc::IFA_ADDRESS, &addr_bytes);

    nl_send(nl_sock, &buf[..msg_len])?;
    // Receive ACK
    let recv_len = nl_recv(nl_sock, &mut buf)?;
    nl_check_ack(&buf, recv_len, "mod_addr4")
}

/// Add or delete IPv4 route
fn mod_route4(
    nl_sock: libc::c_int,
    iface_index: i32,
    cmd: u16,
    gateway: u32,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let base = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<RtMsg>();
    let mut msg_len = base;

    nl_hdr(
        &mut buf,
        base,
        cmd,
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16,
    );

    let rtm = RtMsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: libc::RT_TABLE_MAIN,
        rtm_protocol: libc::RTPROT_BOOT,
        rtm_scope: libc::RT_SCOPE_UNIVERSE,
        rtm_type: libc::RTN_UNICAST,
        rtm_flags: 0,
    };
    let rtm_off = mem::size_of::<libc::nlmsghdr>();
    buf[rtm_off..rtm_off + mem::size_of_val(&rtm)].copy_from_slice(struct_as_bytes(&rtm));

    add_rtattr(
        &mut buf,
        &mut msg_len,
        libc::RTA_OIF,
        &(iface_index as u32).to_ne_bytes(),
    );
    add_rtattr(&mut buf, &mut msg_len, libc::RTA_DST, &0u32.to_ne_bytes());
    add_rtattr(
        &mut buf,
        &mut msg_len,
        libc::RTA_GATEWAY,
        &gateway.to_ne_bytes(),
    );

    nl_send(nl_sock, &buf[..msg_len])?;
    // Receive ACK
    let recv_len = nl_recv(nl_sock, &mut buf)?;
    nl_check_ack(&buf, recv_len, "mod_route4")
}

/// Return the raw data for the first occurrence of `code` in a response.
fn dhcp_option(response: &[u8], code: u8) -> Option<&[u8]> {
    DhcpOptions::new(response.get(DHCP_OPTIONS_OFFSET..).unwrap_or(&[]))
        .find(|&(c, _)| c == code)
        .map(|(_, data)| data)
}

/// Return the big-endian u32 value of a four-octet option, if present.
fn dhcp_option_u32(response: &[u8], code: u8) -> Option<u32> {
    dhcp_option(response, code)
        .and_then(|data| data.get(..4))
        .map(|data| u32::from_be_bytes(data.try_into().unwrap()))
}

/// Return the DHCP message type (option 53) from a response, or 0
fn dhcp_msg_type(response: &[u8]) -> u8 {
    dhcp_option(response, 53)
        .and_then(|data| data.first().copied())
        .unwrap_or(0)
}

/// The address and timers granted by a DHCPACK (RFC 2131 section 4.4.5).
struct Lease {
    addr: u32,
    server_id: [u8; 4],
    lease_secs: u32,
    t1: u32,
    t2: u32,
}

impl Lease {
    fn parse(response: &[u8]) -> anyhow::Result<Self> {
        // Need at least 240 bytes (DHCP header + magic cookie) + 1 for options
        if response.len() < DHCP_OPTIONS_OFFSET + 1 {
            bail!("DHCPACK too short ({} bytes)", response.len());
        }

        // yiaddr is at offset 16-19 in network byte order
        let addr = u32::from_ne_bytes(response[16..20].try_into().unwrap());
        if addr == libc::INADDR_ANY {
            bail!("DHCPACK: yiaddr is 0.0.0.0");
        }

        let lease_secs = dhcp_option_u32(response, 51).unwrap_or(0);
        let server_id = dhcp_option(response, 54)
            .and_then(|data| data.get(..4))
            .map(|data| <[u8; 4]>::try_from(data).unwrap())
            .unwrap_or([0; 4]);
        // RFC 2131 section 4.4.5 defaults when the server sends no T1/T2.
        let t1 = dhcp_option_u32(response, 58).unwrap_or(lease_secs / 2);
        let t2 = dhcp_option_u32(response, 59).unwrap_or(lease_secs - lease_secs / 8);

        Ok(Self {
            addr,
            server_id,
            lease_secs,
            t1,
            t2,
        })
    }
}

/// Parse a DHCP ACK and configure the interface
fn handle_dhcp_ack(
    nl_sock: libc::c_int,
    iface_index: i32,
    response: &[u8],
) -> anyhow::Result<Lease> {
    let lease = Lease::parse(response)?;

    let mut netmask: u32 = 0;
    let mut router: u32 = 0;
    // Clamp MTU to passt's limit
    let mut mtu: u16 = 65520;
    let mut resolv_conf = String::new();

    // Parse DHCP options (start at offset 240 after magic cookie)
    for (opt, data) in DhcpOptions::new(response.get(DHCP_OPTIONS_OFFSET..).unwrap_or(&[])) {
        match opt {
            // Subnet mask
            1 if data.len() >= 4 => {
                netmask = u32::from_ne_bytes(data[..4].try_into().unwrap());
            }
            // Router
            3 if data.len() >= 4 => {
                router = u32::from_ne_bytes(data[..4].try_into().unwrap());
            }
            // Domain Name Server
            6 => {
                for chunk in data.as_chunks::<4>().0 {
                    let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                    let _ = writeln!(resolv_conf, "nameserver {ip}");
                }
            }
            // Interface MTU
            26 if data.len() >= 2 => {
                // We don't know yet if IPv6 is available: don't go below 1280 B
                mtu = u16::from_be_bytes(data[..2].try_into().unwrap()).clamp(1280, 65520);
            }
            _ => {}
        }
    }

    if !resolv_conf.is_empty()
        && let Err(e) = std::fs::write("/etc/resolv.conf", &resolv_conf)
    {
        eprintln!("Warning: couldn't write /etc/resolv.conf: {e}");
    }

    // Calculate the prefix length from netmask
    let prefix_len = u32::from_be(netmask).leading_ones() as u8;

    mod_addr4(
        nl_sock,
        iface_index,
        libc::RTM_NEWADDR,
        lease.addr,
        prefix_len,
    )
    .context("add address from DHCP")?;
    mod_route4(nl_sock, iface_index, libc::RTM_NEWROUTE, router)
        .context("add default route from DHCP")?;
    let _ = set_mtu(nl_sock, iface_index, mtu as u32);

    Ok(lease)
}

fn ipv4(addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(addr.to_ne_bytes())
}

enum Reply {
    Ack(Lease),
    Nak,
    None,
}

/// Send a DHCPREQUEST for the current lease and wait DHCP_RENEW_TIMEOUT for a
/// reply. Per RFC 2131 section 4.4.5 the request carries the client's address
/// in 'ciaddr' and, while RENEWING, is unicast to the issuing server.
fn renew(sock: &OwnedFd, mac: [u8; 16], lease: &Lease, server: Ipv4Addr) -> Reply {
    let mut pkt = DhcpPacket::zeroed();
    pkt.op = BOOTREQUEST;
    pkt.htype = HTYPE_ETHERNET;
    pkt.hlen = HLEN_ETHERNET;
    pkt.xid = (unistd::getpid().as_raw() as u32).to_be();
    pkt.ciaddr = lease.addr;
    pkt.magic = DHCP_MAGIC_COOKIE.to_be();
    pkt.chaddr = mac;
    let mut opts = DhcpOptionsWriter::new(&mut pkt.options);
    opts.push(53, &[DHCP_MSG_REQUEST]);
    opts.finish();

    let dest = SockaddrIn::from(SocketAddrV4::new(server, DHCP_SERVER_PORT));
    if socket::sendto(sock.as_raw_fd(), pkt.as_bytes(), &dest, MsgFlags::empty()).is_err() {
        return Reply::None;
    }

    let mut response = [0u8; DHCP_BUFFER_SIZE];
    let Ok((n, _)) = socket::recvfrom::<SockaddrIn>(sock.as_raw_fd(), &mut response) else {
        return Reply::None;
    };
    match dhcp_msg_type(&response[..n]) {
        DHCP_MSG_ACK => Lease::parse(&response[..n]).map_or(Reply::None, Reply::Ack),
        DHCP_MSG_NAK => Reply::Nak,
        _ => Reply::None,
    }
}

/// Spawn a child that keeps the lease alive so the server keeps listing the VM
/// as an active client.
///
/// Forks rather than spawning a thread so the loop survives when the parent
/// execs the workload in PID1 mode (a thread would be destroyed by exec; a
/// separate process is not). Safe to call here because do_dhcp() runs before
/// any other threads exist.
fn spawn_renewer(sock: &OwnedFd, mac: [u8; 16], lease: Lease) {
    if let Ok(ForkResult::Child) = unsafe { unistd::fork() } {
        renew_loop(sock, mac, lease);
        unsafe { libc::_exit(0) };
    }
}

/// Renew at T1 (unicast) and rebind at T2 (broadcast), per RFC 2131 section
/// 4.4.5. Gives up on NAK; otherwise keeps rebinding until a server answers.
fn renew_loop(sock: &OwnedFd, mac: [u8; 16], mut lease: Lease) {
    let timeout = TimeVal::seconds(DHCP_RENEW_TIMEOUT.as_secs() as i64);
    let _ = socket::setsockopt(sock, sockopt::ReceiveTimeout, &timeout);

    'renew: loop {
        std::thread::sleep(Duration::from_secs(lease.t1.max(1) as u64));

        // RENEWING: unicast to the server that issued the lease.
        match renew(sock, mac, &lease, Ipv4Addr::from(lease.server_id)) {
            Reply::Ack(next) => {
                lease = next;
                eprintln!(
                    "[krun-dhcp] renewed {} (next in {}s)",
                    ipv4(lease.addr),
                    lease.t1
                );
                continue 'renew;
            }
            Reply::Nak => break,
            Reply::None => {}
        }

        std::thread::sleep(Duration::from_secs(lease.t2.saturating_sub(lease.t1) as u64));

        // REBINDING: broadcast, so any server can extend the lease. Keep trying
        // after expiry too: the workload is already running, so the client
        // cannot stop using the address.
        loop {
            match renew(sock, mac, &lease, Ipv4Addr::BROADCAST) {
                Reply::Ack(next) => {
                    lease = next;
                    eprintln!(
                        "[krun-dhcp] renewed {} (next in {}s)",
                        ipv4(lease.addr),
                        lease.t1
                    );
                    continue 'renew;
                }
                Reply::Nak => break 'renew,
                Reply::None => {}
            }
            std::thread::sleep(Duration::from_secs(
                lease.lease_secs.saturating_sub(lease.t2).max(1) as u64,
            ));
        }
    }
    eprintln!("[krun-dhcp] lease for {} lost", ipv4(lease.addr));
}

/// Perform DHCP discover and configuration for a network interface
///
/// This function:
/// 1. Binds a UDP socket to the interface using SO_BINDTODEVICE
/// 2. Sends a DHCP DISCOVER message with Rapid Commit option
/// 3. Retransmits the DISCOVER for up to DHCP_RETRY_WINDOW:
///     - If DHCPACK (Rapic Commit): applies configuration directly
///     - If DHCPOFFER: sends DHCPREQUEST and waits for DHCPACK
///     - If no response: returns success (VM may be IPv6-only)
/// 4. Parses the ACK and configures:
///     - IPv4 address with appropriate prefix length
///     - Default gateway route
///     - DNS servers (overwriting /etc/resolv.conf)
///     - Interface MTU
pub fn do_dhcp(iface: &str) -> anyhow::Result<()> {
    let iface_index =
        if_::if_nametoindex(iface).with_context(|| format!("if_nametoindex({iface})"))?;

    let raw = Errno::result(unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)
    })
    .context("socket(AF_NETLINK)")?;
    let nl_sock = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut nl_sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    nl_sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    nl_sa.nl_pid = unistd::getpid().as_raw() as u32;
    Errno::result(unsafe {
        libc::bind(
            nl_sock.as_raw_fd(),
            &nl_sa as *const _ as *const libc::sockaddr,
            mem::size_of_val(&nl_sa) as u32,
        )
    })
    .context("bind(netlink)")?;

    // Send Request (DHCPDISCOVER)
    let sock = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        Some(SockProtocol::Udp),
    )
    .context("socket(AF_INET)")?;

    // Allow broadcast
    socket::setsockopt(&sock, sockopt::Broadcast, &true).context("setsockopt(SO_BROADCAST)")?;
    socket::setsockopt(&sock, sockopt::BindToDevice, &OsString::from(iface))
        .context("setsockopt(SO_BINDTODEVICE)")?;

    // Bind to port 68 (DHCP client)
    let bind_addr = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DHCP_CLIENT_PORT));
    socket::bind(sock.as_raw_fd(), &bind_addr).context("bind(UDP DHCP client)")?;

    let mut pkt = DhcpPacket::zeroed();
    pkt.op = BOOTREQUEST;
    pkt.htype = HTYPE_ETHERNET;
    pkt.hlen = HLEN_ETHERNET;
    pkt.xid = (unistd::getpid().as_raw() as u32).to_be();
    pkt.flags = DHCP_FLAG_BROADCAST.to_be();
    pkt.magic = DHCP_MAGIC_COOKIE.to_be();

    // Populate chaddr with the interface's MAC address
    let mut mac_ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = iface.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const libc::c_char,
            mac_ifr.ifr_name.as_mut_ptr(),
            name_bytes.len().min(libc::IFNAMSIZ - 1),
        );
    }
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR as _, &mut mac_ifr) } < 0 {
        bail!("ioctl(SIOCGIFHWADDR): {}", IoError::last_os_error());
    }
    let sa_data = unsafe { mac_ifr.ifr_ifru.ifru_hwaddr.sa_data };
    for (dst, src) in pkt.chaddr.iter_mut().zip(sa_data.iter().take(6)) {
        // We need to allow the unnecessary cast, because this will cause clippy to fail on aarch64
        // without it
        #[allow(clippy::unnecessary_cast)]
        {
            *dst = *src as u8;
        }
    }

    // Build DHCP options

    let mut opts = DhcpOptionsWriter::new(&mut pkt.options);
    opts.push(53, &[1]); // Discover
    opts.push(80, &[]); // Rapid Commit
    opts.finish();

    let dest = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT));

    let interval = jitter(DHCP_RETRY_INTERVAL);
    socket::setsockopt(
        &sock,
        sockopt::ReceiveTimeout,
        &TimeVal::microseconds(interval.as_micros() as i64),
    )
    .context("setsockopt(SO_RCVTIMEO)")?;

    let pkt_bytes = pkt.as_bytes();
    let mut response = [0u8; DHCP_BUFFER_SIZE];
    let deadline = Instant::now() + DHCP_RETRY_WINDOW;
    let (recv_len, from) = loop {
        socket::sendto(sock.as_raw_fd(), pkt_bytes, &dest, MsgFlags::empty())
            .context("sendto(DISCOVER)")?;

        match socket::recvfrom::<SockaddrIn>(sock.as_raw_fd(), &mut response) {
            Ok(r) => break r,
            Err(Errno::EAGAIN) => {
                if Instant::now() >= deadline {
                    return Ok(()); // no DHCP server answered within the window
                }
            }
            Err(e) => bail!("recvfrom: {e}"),
        }
    };

    let msg_type = dhcp_msg_type(&response[..recv_len]);

    let lease = match msg_type {
        // Rapid Commit - server sent ACK directly
        DHCP_MSG_ACK => handle_dhcp_ack(
            nl_sock.as_raw_fd(),
            iface_index as i32,
            &response[..recv_len],
        )?,
        // DHCPOFFER - complete the 4-way handshake by sending DHCPREQUEST and waiting for DHCPACK.
        // Servers without Rapid Commit (e.g. gvproxy) require this.
        DHCP_MSG_OFFER => {
            let offered_addr = u32::from_ne_bytes(response[16..20].try_into().unwrap());
            let server_addr = from.map(|a| a.ip().octets()).unwrap_or([0; 4]);

            pkt.options = [0; DHCP_OPTIONS_SIZE];
            let mut opts = DhcpOptionsWriter::new(&mut pkt.options);
            opts.push(53, &[3]); // Request
            opts.push(50, &offered_addr.to_ne_bytes()); // Requested IP
            opts.push(54, &server_addr); // Server ID
            opts.finish();

            let pkt_bytes = pkt.as_bytes();
            let deadline = Instant::now() + DHCP_RETRY_WINDOW;
            let (recv_len2, _) = loop {
                socket::sendto(sock.as_raw_fd(), pkt_bytes, &dest, MsgFlags::empty())
                    .context("sendto(REQUEST)")?;

                match socket::recvfrom::<SockaddrIn>(sock.as_raw_fd(), &mut response) {
                    Ok(r) => {
                        // Retransmitted DISCOVERs can leave duplicate OFFERs in
                        // the socket buffer; only an ACK completes the handshake.
                        if dhcp_msg_type(&response[..r.0]) == DHCP_MSG_ACK {
                            break r;
                        }
                    }
                    Err(Errno::EAGAIN) => {
                        if Instant::now() >= deadline {
                            bail!("no DHCPACK received");
                        }
                    }
                    Err(e) => bail!("recvfrom(DHCPACK): {e}"),
                }
            };
            handle_dhcp_ack(
                nl_sock.as_raw_fd(),
                iface_index as i32,
                &response[..recv_len2],
            )?
        }
        _ => bail!("unexpected DHCP message type {msg_type}"),
    };

    // A zero or infinite lease has nothing to renew.
    if lease.lease_secs > 0 && lease.lease_secs != u32::MAX {
        spawn_renewer(&sock, pkt.chaddr, lease);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(addr: [u8; 4], opts: &[(u8, &[u8])]) -> Vec<u8> {
        let mut buf = vec![0u8; DHCP_OPTIONS_OFFSET - 4];
        buf[16..20].copy_from_slice(&addr);
        buf.extend_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());
        for (code, data) in opts {
            buf.push(*code);
            buf.push(data.len() as u8);
            buf.extend_from_slice(data);
        }
        buf.push(DHCP_OPTIONS_END);
        buf
    }

    #[test]
    fn lease_defaults_to_rfc_timers() {
        let r = ack(
            [192, 168, 1, 5],
            &[(51, &3600u32.to_be_bytes()), (54, &[192, 168, 1, 1])],
        );
        let lease = Lease::parse(&r).unwrap();
        assert_eq!(lease.addr, u32::from_ne_bytes([192, 168, 1, 5]));
        assert_eq!(lease.lease_secs, 3600);
        assert_eq!(lease.server_id, [192, 168, 1, 1]);
        assert_eq!((lease.t1, lease.t2), (1800, 3150));
    }

    #[test]
    fn lease_honours_server_timers() {
        let r = ack(
            [10, 0, 0, 5],
            &[
                (51, &300u32.to_be_bytes()),
                (58, &150u32.to_be_bytes()),
                (59, &262u32.to_be_bytes()),
            ],
        );
        let lease = Lease::parse(&r).unwrap();
        assert_eq!((lease.t1, lease.t2), (150, 262));
    }

    #[test]
    fn infinite_lease_does_not_overflow() {
        let r = ack([10, 0, 0, 5], &[(51, &u32::MAX.to_be_bytes())]);
        let lease = Lease::parse(&r).unwrap();
        assert_eq!(lease.lease_secs, u32::MAX);
        assert!(lease.t2 >= lease.t1);
    }

    #[test]
    fn rejects_unset_yiaddr() {
        let r = ack([0, 0, 0, 0], &[(51, &3600u32.to_be_bytes())]);
        assert!(Lease::parse(&r).is_err());
    }

    #[test]
    fn reads_options_and_message_type() {
        let r = ack(
            [10, 0, 0, 5],
            &[(53, &[DHCP_MSG_ACK]), (51, &3600u32.to_be_bytes())],
        );
        assert_eq!(dhcp_msg_type(&r), DHCP_MSG_ACK);
        assert_eq!(dhcp_option_u32(&r, 51), Some(3600));
        assert_eq!(dhcp_option_u32(&r, 58), None);
    }

    #[test]
    fn jitter_stays_within_half_interval() {
        let d = Duration::from_millis(250);
        for _ in 0..100 {
            let j = jitter(d);
            assert!(j >= d && j <= d + d / 2, "{j:?}");
        }
    }
}
