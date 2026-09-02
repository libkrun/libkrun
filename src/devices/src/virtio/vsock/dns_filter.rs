//! Egress DNS filtering for TSI networking.
//!
//! When an egress policy carries an allow-host list plus one or more trusted
//! upstream resolvers, guest UDP DNS queries (destination port 53) are
//! intercepted here instead of reaching the host network directly:
//!
//!   * The query name is checked against the allow-host list. A denied name
//!     gets an NXDOMAIN answer and never touches an upstream.
//!   * An allowed name is forwarded to a HOST-TRUSTED resolver — never the
//!     resolver IP the guest chose. This is the crux of the security model: a
//!     malicious guest cannot point DNS at its own server to map an allowed
//!     hostname onto an arbitrary IP, because libkrun ignores the guest's
//!     chosen destination and only ever queries the configured resolvers.
//!   * A/AAAA answers from an allowed response are "learned" as temporary
//!     egress entries (TTL-clamped), so the subsequent connect to that IP
//!     passes the egress check.
//!
//! The blocking upstream resolution runs on a dedicated worker thread
//! ([`DnsWorker`], modelled on the vsock reaper) so it never stalls the muxer
//! thread that services all host<->guest vsock traffic.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use vm_memory::GuestMemoryMmap;

use super::vsock_addr::VsockAddr;

use super::super::Queue as VirtQueue;
use super::muxer::{MuxerRx, push_packet};
use super::muxer_rxq::MuxerRxQ;
use super::snapshot_gate::SnapshotGate;
use crate::virtio::InterruptTransport;

pub(super) const DNS_PORT: u16 = 53;
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DNS_PACKET_SIZE: usize = 65_535;
// Learned IPs live at least this long (smooths sub-second TTLs) and at most
// this long (bounds how long a single answer keeps an IP reachable before the
// guest must resolve again).
const MIN_LEARNED_TTL: u64 = 60;
const MAX_LEARNED_TTL: u64 = 3600;

const DNS_HEADER_LEN: usize = 12;
const DNS_ID_LEN: usize = 2;
const DNS_U16_LEN: usize = 2;
const DNS_U32_LEN: usize = 4;
const DNS_FLAGS_OFFSET: usize = 2;
const DNS_QDCOUNT_OFFSET: usize = 4;
const DNS_ANCOUNT_OFFSET: usize = 6;
const DNS_QUESTION_FIXED_LEN: usize = 4;
const DNS_RR_FIXED_LEN: usize = 10;
const DNS_RR_TYPE_OFFSET: usize = 0;
const DNS_RR_CLASS_OFFSET: usize = 2;
const DNS_RR_TTL_OFFSET: usize = 4;
const DNS_RR_RDLEN_OFFSET: usize = 8;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_A_RDATA_LEN: usize = 4;
const DNS_AAAA_RDATA_LEN: usize = 16;
const DNS_RCODE_SERVFAIL: u16 = 2;
const DNS_RCODE_NXDOMAIN: u16 = 3;
const DNS_RCODE_MASK: u16 = 0x000f;
const DNS_COUNT_ZERO: u16 = 0;
const DNS_ONE_QUESTION: u16 = 1;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const DNS_POINTER_TAG: u8 = 0xc0;
const DNS_POINTER_MASK: u8 = 0xc0;
const DNS_POINTER_OFFSET_MASK: u8 = 0x3f;
const DNS_MAX_COMPRESSION_JUMPS: usize = 16;
const DNS_MAX_LABEL_LEN: usize = 63;

/// Shared egress policy: static CIDR allow-list, DNS allow-host list, the
/// host-trusted resolvers, and the IPs learned from allowed DNS answers.
#[derive(Debug)]
pub(super) struct EgressPolicy {
    /// Static allowed CIDRs. Empty means "no CIDR is statically allowed"
    /// (egress is then gated entirely by learned IPs).
    allowed_cidrs: Vec<(IpAddr, u8)>,
    /// Allow-host list (normalized). `None` = no DNS filtering.
    allowed_hosts: Option<Vec<String>>,
    /// Host-trusted upstream resolvers. DNS queries are forwarded ONLY here.
    resolvers: Vec<IpAddr>,
    /// IPs learned from allowed DNS answers → expiry instant.
    allowed_ips: HashMap<IpAddr, Instant>,
}

#[derive(Debug)]
struct DnsQuestion {
    name: String,
    end: usize,
}

impl EgressPolicy {
    /// Build a policy. Returns `None` when there is nothing to enforce (no
    /// CIDRs and no hosts) — callers treat `None` as "allow all", preserving
    /// the pre-existing no-policy behavior.
    pub(super) fn new(
        allowed_cidrs: Option<Vec<(IpAddr, u8)>>,
        egress_hosts: Option<Vec<String>>,
        resolvers: Option<Vec<IpAddr>>,
    ) -> Option<Self> {
        if allowed_cidrs.is_none() && egress_hosts.is_none() {
            return None;
        }

        let allowed_hosts = egress_hosts.map(|hosts| {
            hosts
                .into_iter()
                .filter_map(|host| normalize_hostname(&host))
                .collect()
        });

        Some(Self {
            allowed_cidrs: allowed_cidrs.unwrap_or_default(),
            allowed_hosts,
            resolvers: resolvers.unwrap_or_default(),
            allowed_ips: HashMap::new(),
        })
    }

    /// DNS interception is active only when both an allow-host list and at
    /// least one trusted resolver are configured.
    pub(super) fn dns_active(&self) -> bool {
        self.allowed_hosts.is_some() && !self.resolvers.is_empty()
    }

    pub(super) fn resolvers(&self) -> Vec<IpAddr> {
        self.resolvers.clone()
    }

    /// Egress allow check for a connect/sendto destination: a statically
    /// allowed CIDR, or an unexpired learned IP. Non-IP addresses are allowed
    /// (matches prior behavior for e.g. unix sockets).
    pub(super) fn is_addr_allowed(&self, addr: &VsockAddr) -> bool {
        let Some(ip) = sockaddr_ip(addr) else {
            return true;
        };

        if ip_matches_cidrs(ip, &self.allowed_cidrs) {
            return true;
        }

        self.allowed_ips
            .get(&ip)
            .is_some_and(|expires_at| *expires_at > Instant::now())
    }

    /// Whether `addr` is named by a STATIC allow-list CIDR (`--allow-cidr`,
    /// `--outbound-localhost-only`) — as opposed to a learned DNS answer. Used by
    /// the muxer to let a deliberate allow-list entry re-open a floored
    /// destination in the local (non-`Strict`) modes without letting DNS
    /// rebinding do the same. Non-IP addresses are never explicitly allowed here.
    pub(super) fn is_addr_explicitly_allowed(&self, addr: &VsockAddr) -> bool {
        sockaddr_ip(addr).is_some_and(|ip| ip_matches_cidrs(ip, &self.allowed_cidrs))
    }

    fn is_hostname_allowed(&self, hostname: &str) -> bool {
        let Some(allowed_hosts) = &self.allowed_hosts else {
            return true;
        };
        let Some(hostname) = normalize_hostname(hostname) else {
            return false;
        };
        allowed_hosts.iter().any(|allowed| {
            hostname == *allowed
                || hostname
                    .strip_suffix(allowed)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }

    fn learn_ips(&mut self, ips: Vec<(IpAddr, u32)>) {
        let now = Instant::now();
        self.prune_allowed_ips(now);
        for (ip, ttl) in ips {
            let ttl = u64::from(ttl).clamp(MIN_LEARNED_TTL, MAX_LEARNED_TTL);
            let expires_at = now + Duration::from_secs(ttl);
            self.allowed_ips
                .entry(ip)
                .and_modify(|existing| *existing = (*existing).max(expires_at))
                .or_insert(expires_at);
        }
    }

    fn prune_allowed_ips(&mut self, now: Instant) {
        self.allowed_ips.retain(|_, expires_at| *expires_at > now);
    }
}

/// How much of the platform hard-floor applies, chosen once per VM from the
/// deployment context. This mirrors the virtio-net gateway's floor
/// (`smolvm-network::egress`) so a TSI (default `--net`) guest gets the same
/// protection as a virtio-net one: even with NO egress allow-list, a guest must
/// never reach cloud-metadata, and under fleet mode also the host/control
/// internal subnets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum FloorMode {
    /// Trusted single-tenant/local override (`SMOLVM_EGRESS_ALLOW_PRIVATE=1`):
    /// floor nothing — the guest reaches exactly what the host can.
    Off,
    /// Loopback-permitted local mode (`SMOLVM_ALLOW_HOST_LOOPBACK=1`, e.g. the
    /// `--allow-host-loopback` CLI flag): deny ONLY the cloud-metadata link-local
    /// range, leaving the host's own loopback reachable so a developer can hit a
    /// service on their host's `127.0.0.1` from the sandbox on purpose.
    MetadataOnly,
    /// Local DEFAULT: deny the cloud-metadata link-local range AND the host's own
    /// loopback (`127.0.0.0/8`, `::1`, `0.0.0.0`/`::`). A guest connecting to
    /// `127.0.0.1` means "myself", but TSI would forward it to the HOST's
    /// loopback — a confused-deputy path onto host debuggers, Docker, and local
    /// databases. The host's LAN stays reachable (legitimate local dev), and an
    /// explicit allow-list entry can also re-open loopback (see the muxer).
    MetadataAndLoopback,
    /// Multi-tenant/fleet (`SMOLVM_PUBLISH_ADDR` set): the full floor — metadata,
    /// host/control internal subnets, loopback, link/unique-local, and the
    /// gateway CGNAT range — so a guest can't steal host credentials, pivot to
    /// the control plane / worker API, or reach co-resident tenants.
    Strict,
}

/// Parse an explicit `SMOLVM_EGRESS_FLOOR` value into a mode. Returns `None`
/// for an absent/unrecognized value so the caller falls back to the inferred
/// default. Pure (no env) so it is unit-testable.
fn parse_floor_override(v: &str) -> Option<FloorMode> {
    match v.trim().to_ascii_lowercase().as_str() {
        "strict" => Some(FloorMode::Strict),
        "metadata" | "metadata-only" | "metadataonly" => Some(FloorMode::MetadataOnly),
        "off" | "none" => Some(FloorMode::Off),
        _ => None,
    }
}

/// Resolve the floor from the deployment context. Read once at muxer creation
/// (never per-packet): explicit `SMOLVM_EGRESS_FLOOR` override wins, else the
/// `ALLOW_PRIVATE` opt-out, else fleet ⇒ strict, else the metadata-only default.
pub(super) fn floor_mode() -> FloorMode {
    // Explicit override wins (highest precedence). A multi-tenant node sets
    // `SMOLVM_EGRESS_FLOOR=strict` so the TSI floor is fail-closed and never
    // silently degrades to metadata-only (loopback/RFC1918 reachable) if
    // `SMOLVM_PUBLISH_ADDR` is missing from the environment — a dropped env var
    // must NOT expose the host loopback control door / co-tenants to a guest.
    if let Some(mode) = std::env::var("SMOLVM_EGRESS_FLOOR")
        .ok()
        .and_then(|v| parse_floor_override(&v))
    {
        return mode;
    }
    let allow_private = std::env::var("SMOLVM_EGRESS_ALLOW_PRIVATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_private {
        return FloorMode::Off;
    }
    // Fleet mode is absolute: `SMOLVM_ALLOW_HOST_LOOPBACK` only relaxes the LOCAL
    // default, never Strict, so it can't re-expose the host loopback / control
    // door on a multi-tenant node.
    if std::env::var_os("SMOLVM_PUBLISH_ADDR").is_some() {
        return FloorMode::Strict;
    }
    let allow_host_loopback = std::env::var("SMOLVM_ALLOW_HOST_LOOPBACK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_host_loopback {
        FloorMode::MetadataOnly
    } else {
        FloorMode::MetadataAndLoopback
    }
}

/// The cloud-metadata link-local range (`169.254.0.0/16` / `fe80::/10`) — the one
/// destination floored in every mode except `Off`, including via an IPv4-mapped
/// IPv6 address so it can't be smuggled past.
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_link_local())
        }
    }
}

/// The host's own loopback / unspecified addresses — what `127.0.0.1` and `::1`
/// mean to the guest, but which TSI forwards to the HOST. Floored in every mode
/// except `Off`; re-openable in the local modes only by an explicit static
/// allow-list entry (never a learned DNS IP, so it can't be reached by
/// rebinding). Covers the IPv4-mapped IPv6 form so it can't be smuggled past.
pub(super) fn is_host_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
    }
}

/// The full multi-tenant IPv4 floor (metadata + internal + loopback + CGNAT).
fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()        // 127.0.0.0/8
        || v4.is_link_local() // 169.254.0.0/16 — incl. 169.254.169.254 (cloud metadata)
        || v4.is_private()    // 10/8, 172.16/12, 192.168/16 — host/control internal subnet
        || v4.is_unspecified()
        || v4.is_broadcast()
        // 100.64.0.0/10 (CGNAT) — the gateway's own guest/gateway addresses live here.
        || matches!(v4.octets(), [100, b, ..] if (64..=127).contains(&b))
}

/// Whether `ip` is floored under `mode` — the single hard-floor predicate. Also
/// defeats DNS-rebinding (a learned IP in a floored range is still denied).
fn is_floored(ip: IpAddr, mode: FloorMode) -> bool {
    match mode {
        FloorMode::Off => false,
        FloorMode::MetadataOnly => is_link_local(ip),
        FloorMode::MetadataAndLoopback => is_link_local(ip) || is_host_loopback(ip),
        FloorMode::Strict => match ip {
            IpAddr::V4(v4) => is_reserved_v4(v4),
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                    || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                    || v6.to_ipv4_mapped().is_some_and(is_reserved_v4)
            }
        },
    }
}

/// The hard-floor check for a connect/sendto destination, applied BEFORE any
/// allow-list (and even when there is no policy at all). Non-IP destinations
/// (e.g. unix sockets) are never floored.
pub(super) fn is_addr_floored(addr: &VsockAddr, mode: FloorMode) -> bool {
    sockaddr_ip(addr).is_some_and(|ip| is_floored(ip, mode))
}

/// Whether `addr` is the host's own loopback / unspecified address — the only
/// part of the floor an explicit allow-list may re-open in the local modes.
/// Cloud-metadata and (under `Strict`) the internal ranges are never re-openable.
pub(super) fn is_addr_host_loopback(addr: &VsockAddr) -> bool {
    sockaddr_ip(addr).is_some_and(is_host_loopback)
}

/// Work item handed from the muxer thread to the DNS worker thread. Carries an
/// owned copy of the query and the vsock addressing needed to deliver the
/// response — no shared handles, so passing it is cheap and lock-free.
pub(super) struct DnsRequest {
    pub query: Vec<u8>,
    pub peer_port: u32,
    pub fwd_cnt: u32,
    pub cid: u64,
}

/// Dedicated worker that performs the blocking upstream DNS resolution off the
/// muxer thread and pushes the answer back onto the guest RX queue. Modelled on
/// [`super::reaper::ReaperThread`].
pub(super) struct DnsWorker {
    receiver: Receiver<DnsRequest>,
    policy: Arc<RwLock<EgressPolicy>>,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    interrupt: InterruptTransport,
    snapshot_gate: Arc<SnapshotGate>,
}

impl DnsWorker {
    pub(super) fn new(
        receiver: Receiver<DnsRequest>,
        policy: Arc<RwLock<EgressPolicy>>,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        interrupt: InterruptTransport,
        snapshot_gate: Arc<SnapshotGate>,
    ) -> Self {
        Self {
            receiver,
            policy,
            mem,
            queue,
            rxq,
            interrupt,
            snapshot_gate,
        }
    }

    pub(super) fn run(self) {
        thread::Builder::new()
            .name("vsock dns".into())
            .spawn(move || self.work())
            .unwrap();
    }

    fn work(self) {
        for req in self.receiver.iter() {
            let response = handle_dns_query(&self.policy, &req.query);
            push_packet(
                req.cid,
                MuxerRx::DgramDataDnsResponse {
                    peer_port: req.peer_port,
                    data: response,
                    fwd_cnt: req.fwd_cnt,
                },
                &self.rxq,
                &self.queue,
                &self.mem,
                &self.snapshot_gate,
            );
            self.interrupt.signal_used_queue();
        }
    }
}

/// Resolve a guest DNS query against the policy, forwarding allowed queries to
/// the host-trusted resolvers only. Returns the raw DNS response bytes to hand
/// back to the guest.
fn handle_dns_query(policy: &Arc<RwLock<EgressPolicy>>, query: &[u8]) -> Vec<u8> {
    let question = match parse_question(query) {
        Ok(question) => question,
        Err(_) => return build_error_response(query, DNS_RCODE_SERVFAIL),
    };

    // Snapshot the allow decision and the trusted resolvers under a short read
    // lock; never hold the lock across the blocking upstream I/O below.
    let (allowed, resolvers) = match policy.read() {
        Ok(policy) => (
            policy.is_hostname_allowed(&question.name),
            policy.resolvers(),
        ),
        Err(_) => return build_error_response(query, DNS_RCODE_SERVFAIL),
    };

    if !allowed {
        return build_error_response(query, DNS_RCODE_NXDOMAIN);
    }

    for resolver in resolvers {
        let target = SocketAddr::new(resolver, DNS_PORT);
        match forward_dns_udp(query, target) {
            Ok(response) => {
                if let Ok(ips) = parse_answer_ips(&response)
                    && let Ok(mut policy) = policy.write()
                {
                    policy.learn_ips(ips);
                }
                return response;
            }
            Err(err) => debug!("DNS upstream {target} failed: {err}"),
        }
    }

    build_error_response(query, DNS_RCODE_SERVFAIL)
}

pub(super) fn sockaddr_port(addr: &VsockAddr) -> Option<u16> {
    addr.inet().map(|a| a.port())
}

fn sockaddr_ip(addr: &VsockAddr) -> Option<IpAddr> {
    addr.inet().map(|a| a.ip())
}

/// CIDR membership test. Public to the vsock module so the muxer can reuse it.
pub(super) fn ip_matches_cidrs(ip: IpAddr, cidrs: &[(IpAddr, u8)]) -> bool {
    for (cidr_ip, prefix_len) in cidrs {
        match (ip, cidr_ip) {
            (IpAddr::V4(addr_v4), IpAddr::V4(cidr_v4)) => {
                let mask = match *prefix_len {
                    0 => 0u32,
                    p if p >= 32 => u32::MAX,
                    _ => u32::MAX << (32 - prefix_len),
                };
                if u32::from(addr_v4) & mask == u32::from(*cidr_v4) & mask {
                    return true;
                }
            }
            (IpAddr::V6(addr_v6), IpAddr::V6(cidr_v6)) => {
                let mask = match *prefix_len {
                    0 => 0u128,
                    p if p >= 128 => u128::MAX,
                    _ => u128::MAX << (128 - prefix_len),
                };
                if u128::from(addr_v6) & mask == u128::from(*cidr_v6) & mask {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn normalize_hostname(hostname: &str) -> Option<String> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}

fn forward_dns_udp(query: &[u8], resolver: SocketAddr) -> std::io::Result<Vec<u8>> {
    let bind_addr = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(DNS_TIMEOUT))?;
    socket.set_write_timeout(Some(DNS_TIMEOUT))?;
    socket.connect(resolver)?;
    socket.send(query)?;

    let mut response = vec![0u8; MAX_DNS_PACKET_SIZE];
    let len = socket.recv(&mut response)?;
    response.truncate(len);
    Ok(response)
}

fn parse_question(packet: &[u8]) -> Result<DnsQuestion, ()> {
    if packet.len() < DNS_HEADER_LEN || read_u16(packet, DNS_QDCOUNT_OFFSET)? != DNS_ONE_QUESTION {
        return Err(());
    }

    let (name, after_name) = read_name(packet, DNS_HEADER_LEN)?;
    if after_name + DNS_QUESTION_FIXED_LEN > packet.len() {
        return Err(());
    }

    Ok(DnsQuestion {
        name,
        end: after_name + DNS_QUESTION_FIXED_LEN,
    })
}

fn parse_answer_ips(packet: &[u8]) -> Result<Vec<(IpAddr, u32)>, ()> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(());
    }

    let qdcount = read_u16(packet, DNS_QDCOUNT_OFFSET)? as usize;
    let ancount = read_u16(packet, DNS_ANCOUNT_OFFSET)? as usize;
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..qdcount {
        let (_, after_name) = read_name(packet, offset)?;
        if after_name + DNS_QUESTION_FIXED_LEN > packet.len() {
            return Err(());
        }
        offset = after_name + DNS_QUESTION_FIXED_LEN;
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        let (_, after_name) = read_name(packet, offset)?;
        if after_name + DNS_RR_FIXED_LEN > packet.len() {
            return Err(());
        }
        offset = after_name;

        let rr_type = read_u16(packet, offset + DNS_RR_TYPE_OFFSET)?;
        let class = read_u16(packet, offset + DNS_RR_CLASS_OFFSET)?;
        let ttl = read_u32(packet, offset + DNS_RR_TTL_OFFSET)?;
        let rdlen = read_u16(packet, offset + DNS_RR_RDLEN_OFFSET)? as usize;
        offset += DNS_RR_FIXED_LEN;

        if offset + rdlen > packet.len() {
            return Err(());
        }

        if class == DNS_CLASS_IN && rr_type == DNS_TYPE_A && rdlen == DNS_A_RDATA_LEN {
            ips.push((
                IpAddr::V4(Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                )),
                ttl,
            ));
        } else if class == DNS_CLASS_IN && rr_type == DNS_TYPE_AAAA && rdlen == DNS_AAAA_RDATA_LEN {
            ips.push((
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; DNS_AAAA_RDATA_LEN]>::try_from(
                        &packet[offset..offset + DNS_AAAA_RDATA_LEN],
                    )
                    .map_err(|_| ())?,
                )),
                ttl,
            ));
        }

        offset += rdlen;
    }

    Ok(ips)
}

fn build_error_response(query: &[u8], rcode: u16) -> Vec<u8> {
    let id = if query.len() >= DNS_ID_LEN {
        &query[..DNS_ID_LEN]
    } else {
        &[0, 0]
    };
    let req_flags = if query.len() >= DNS_FLAGS_OFFSET + DNS_U16_LEN {
        read_u16(query, DNS_FLAGS_OFFSET).unwrap_or(0)
    } else {
        0
    };
    let flags = DNS_FLAG_RESPONSE
        | (req_flags & DNS_FLAG_RECURSION_DESIRED)
        | DNS_FLAG_RECURSION_AVAILABLE
        | (rcode & DNS_RCODE_MASK);

    let question = parse_question(query).ok();
    let mut response =
        Vec::with_capacity(question.as_ref().map(|q| q.end).unwrap_or(DNS_HEADER_LEN));
    response.extend_from_slice(id);
    response.extend_from_slice(&flags.to_be_bytes());
    if let Some(question) = question {
        response.extend_from_slice(&DNS_ONE_QUESTION.to_be_bytes());
        response.extend_from_slice(&DNS_COUNT_ZERO.to_be_bytes());
        response.extend_from_slice(&DNS_COUNT_ZERO.to_be_bytes());
        response.extend_from_slice(&DNS_COUNT_ZERO.to_be_bytes());
        response.extend_from_slice(&query[DNS_HEADER_LEN..question.end]);
    } else {
        for _ in 0..4 {
            response.extend_from_slice(&DNS_COUNT_ZERO.to_be_bytes());
        }
    }
    response
}

fn read_name(packet: &[u8], offset: usize) -> Result<(String, usize), ()> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut next_offset = offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        if pos >= packet.len() {
            return Err(());
        }

        let len = packet[pos];
        if len & DNS_POINTER_MASK == DNS_POINTER_TAG {
            if pos + 1 >= packet.len() {
                return Err(());
            }
            let pointer =
                (((len & DNS_POINTER_OFFSET_MASK) as usize) << 8) | packet[pos + 1] as usize;
            if pointer >= packet.len() {
                return Err(());
            }
            if !jumped {
                next_offset = pos + DNS_U16_LEN;
            }
            pos = pointer;
            jumped = true;
            jumps += 1;
            if jumps > DNS_MAX_COMPRESSION_JUMPS {
                return Err(());
            }
            continue;
        }

        if len & DNS_POINTER_MASK != 0 {
            return Err(());
        }

        pos += 1;
        if len == 0 {
            if !jumped {
                next_offset = pos;
            }
            break;
        }

        let len = len as usize;
        if len > DNS_MAX_LABEL_LEN || pos + len > packet.len() {
            return Err(());
        }

        let label = std::str::from_utf8(&packet[pos..pos + len]).map_err(|_| ())?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
        if !jumped {
            next_offset = pos;
        }
    }

    Ok((labels.join("."), next_offset))
}

fn read_u16(buf: &[u8], offset: usize) -> Result<u16, ()> {
    let bytes = buf.get(offset..offset + DNS_U16_LEN).ok_or(())?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> Result<u32, ()> {
    let bytes = buf.get(offset..offset + DNS_U32_LEN).ok_or(())?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    #[test]
    fn floor_override_parsing() {
        assert_eq!(parse_floor_override("strict"), Some(FloorMode::Strict));
        assert_eq!(parse_floor_override("  STRICT "), Some(FloorMode::Strict));
        assert_eq!(
            parse_floor_override("metadata"),
            Some(FloorMode::MetadataOnly)
        );
        assert_eq!(parse_floor_override("off"), Some(FloorMode::Off));
        assert_eq!(parse_floor_override("none"), Some(FloorMode::Off));
        assert_eq!(parse_floor_override(""), None);
        assert_eq!(parse_floor_override("bogus"), None);
    }

    fn query_for(name: &str) -> Vec<u8> {
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    fn response_with_a(name: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut response = query_for(name);
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = 0x01;
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&ip);
        response
    }

    fn sockaddr_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> VsockAddr {
        VsockAddr::Inet(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port).into())
    }

    fn host_policy(hosts: Vec<&str>) -> EgressPolicy {
        EgressPolicy::new(
            None,
            Some(hosts.into_iter().map(String::from).collect()),
            Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
        )
        .unwrap()
    }

    #[test]
    fn hostname_matching_allows_exact_and_subdomain_only() {
        let policy = host_policy(vec!["Example.COM."]);
        assert!(policy.is_hostname_allowed("example.com"));
        assert!(policy.is_hostname_allowed("api.example.com"));
        assert!(!policy.is_hostname_allowed("badexample.com"));
        assert!(!policy.is_hostname_allowed("example.org"));
    }

    #[test]
    fn empty_allow_list_blocks_all_hostnames() {
        let policy = EgressPolicy::new(
            None,
            Some(vec![]),
            Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        )
        .unwrap();
        assert!(!policy.is_hostname_allowed("example.com"));
    }

    #[test]
    fn dns_active_requires_hosts_and_resolvers() {
        // hosts but no resolvers → not active
        assert!(
            !EgressPolicy::new(None, Some(vec!["a.com".into()]), None)
                .unwrap()
                .dns_active()
        );
        // cidrs only → not active
        assert!(
            !EgressPolicy::new(
                Some(vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)]),
                None,
                None
            )
            .unwrap()
            .dns_active()
        );
        // both → active
        assert!(host_policy(vec!["a.com"]).dns_active());
    }

    #[test]
    fn parses_dns_query_name() {
        let question = parse_question(&query_for("api.example.com")).unwrap();
        assert_eq!(question.name, "api.example.com");
    }

    #[test]
    fn builds_nxdomain_with_original_question() {
        let query = query_for("blocked.example.com");
        let response = build_error_response(&query, DNS_RCODE_NXDOMAIN);
        assert_eq!(&response[..DNS_ID_LEN], &query[..DNS_ID_LEN]);
        assert_eq!(
            read_u16(&response, DNS_QDCOUNT_OFFSET).unwrap(),
            DNS_ONE_QUESTION
        );
        assert_eq!(
            read_u16(&response, DNS_ANCOUNT_OFFSET).unwrap(),
            DNS_COUNT_ZERO
        );
        assert_eq!(
            read_u16(&response, DNS_FLAGS_OFFSET).unwrap() & DNS_RCODE_MASK,
            DNS_RCODE_NXDOMAIN
        );
        assert_eq!(&response[DNS_HEADER_LEN..], &query[DNS_HEADER_LEN..]);
    }

    #[test]
    fn builds_servfail_for_malformed_query() {
        let response = build_error_response(&[0xab, 0xcd], DNS_RCODE_SERVFAIL);
        assert_eq!(&response[..2], &[0xab, 0xcd]);
        assert_eq!(
            read_u16(&response, DNS_FLAGS_OFFSET).unwrap() & DNS_RCODE_MASK,
            DNS_RCODE_SERVFAIL
        );
    }

    #[test]
    fn parses_compressed_a_answer() {
        let response = response_with_a("allowed.example.com", [203, 0, 113, 5], 60);
        let ips = parse_answer_ips(&response).unwrap();
        assert_eq!(ips, vec![(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 60)]);
    }

    #[test]
    fn dns_policy_denies_before_learn_and_allows_after_learn() {
        let mut policy = host_policy(vec!["example.com"]);
        let addr = sockaddr_v4(203, 0, 113, 10, 443);
        assert!(!policy.is_addr_allowed(&addr));
        policy.learn_ips(vec![(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 60)]);
        assert!(policy.is_addr_allowed(&addr));
    }

    #[test]
    fn learn_ips_prunes_expired_ips() {
        let mut policy = host_policy(vec!["example.com"]);
        let now = Instant::now();
        policy.allowed_ips.insert(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22)),
            now - Duration::from_secs(1),
        );
        policy.allowed_ips.insert(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 23)),
            now + Duration::from_secs(60),
        );
        policy.learn_ips(vec![]);
        assert!(!policy.is_addr_allowed(&sockaddr_v4(203, 0, 113, 22, 443)));
        assert!(policy.is_addr_allowed(&sockaddr_v4(203, 0, 113, 23, 443)));
    }

    #[test]
    fn allowed_cidrs_still_allow_with_dns_filter_enabled() {
        let policy = EgressPolicy::new(
            Some(vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)]),
            Some(vec!["example.com".into()]),
            Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
        )
        .unwrap();
        assert!(policy.is_addr_allowed(&sockaddr_v4(10, 1, 2, 3, 443)));
        assert!(!policy.is_addr_allowed(&sockaddr_v4(11, 1, 2, 3, 443)));
    }

    #[test]
    fn resolver_is_pinned_and_independent_of_guest() {
        // The trusted resolver(s) come only from the policy; nothing the guest
        // supplies (no dest field exists on DnsRequest) can change them.
        let policy = host_policy(vec!["example.com"]);
        assert_eq!(
            policy.resolvers(),
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
        );
    }

    #[test]
    fn blocked_query_returns_nxdomain_without_learning() {
        let policy = Arc::new(RwLock::new(host_policy(vec!["allowed.example.com"])));
        let response = handle_dns_query(&policy, &query_for("blocked.example.com"));
        assert_eq!(
            read_u16(&response, DNS_FLAGS_OFFSET).unwrap() & DNS_RCODE_MASK,
            DNS_RCODE_NXDOMAIN
        );
        assert!(policy.read().unwrap().allowed_ips.is_empty());
    }

    #[test]
    fn sockaddr_port_extracts_port() {
        assert_eq!(sockaddr_port(&sockaddr_v4(1, 1, 1, 1, 53)), Some(53));
        assert_eq!(sockaddr_port(&sockaddr_v4(1, 1, 1, 1, 853)), Some(853));
    }

    #[test]
    fn default_floor_blocks_link_local_and_host_loopback() {
        let meta = FloorMode::MetadataAndLoopback;
        // Cloud-metadata is denied even with no allow-list.
        assert!(is_addr_floored(&sockaddr_v4(169, 254, 169, 254, 80), meta));
        assert!(is_addr_floored(&sockaddr_v4(169, 254, 0, 1, 80), meta));
        // Host loopback / unspecified are denied too: `127.0.0.1` means the guest
        // itself, but TSI would forward it to the HOST's loopback services.
        assert!(is_addr_floored(&sockaddr_v4(127, 0, 0, 1, 80), meta));
        assert!(is_addr_floored(&sockaddr_v4(127, 1, 2, 3, 80), meta));
        assert!(is_addr_floored(&sockaddr_v4(0, 0, 0, 0, 80), meta));
        // Host LAN / public stay reachable in the local default.
        assert!(!is_addr_floored(&sockaddr_v4(192, 168, 1, 1, 80), meta));
        assert!(!is_addr_floored(&sockaddr_v4(10, 0, 0, 5, 80), meta));
        assert!(!is_addr_floored(&sockaddr_v4(1, 1, 1, 1, 443), meta));
    }

    #[test]
    fn metadata_only_mode_allows_host_loopback() {
        // The `--allow-host-loopback` mode floors cloud-metadata but lets a guest
        // reach the host's own 127.0.0.1 on purpose.
        let meta = FloorMode::MetadataOnly;
        assert!(is_addr_floored(&sockaddr_v4(169, 254, 169, 254, 80), meta));
        assert!(!is_addr_floored(&sockaddr_v4(127, 0, 0, 1, 80), meta));
        assert!(!is_addr_floored(&sockaddr_v4(0, 0, 0, 0, 80), meta));
    }

    #[test]
    fn default_floor_blocks_ipv6_and_mapped_loopback() {
        let meta = FloorMode::MetadataAndLoopback;
        // ::1 and the IPv4-mapped 127.x form must both be floored so loopback
        // can't be smuggled past via the v6 encoding.
        let v6_loopback = VsockAddr::Inet(
            std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 80, 0, 0).into(),
        );
        assert!(is_addr_floored(&v6_loopback, meta));
        let mapped = Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped();
        let mapped_addr = VsockAddr::Inet(std::net::SocketAddrV6::new(mapped, 80, 0, 0).into());
        assert!(is_addr_floored(&mapped_addr, meta));
    }

    #[test]
    fn strict_floor_blocks_metadata_internal_and_loopback() {
        let strict = FloorMode::Strict;
        // Metadata + every internal/loopback/CGNAT range is denied under fleet mode.
        assert!(is_addr_floored(
            &sockaddr_v4(169, 254, 169, 254, 80),
            strict
        ));
        assert!(is_addr_floored(&sockaddr_v4(127, 0, 0, 1, 80), strict));
        assert!(is_addr_floored(&sockaddr_v4(10, 0, 0, 5, 80), strict));
        assert!(is_addr_floored(&sockaddr_v4(172, 16, 0, 1, 80), strict));
        assert!(is_addr_floored(&sockaddr_v4(192, 168, 1, 1, 80), strict));
        assert!(is_addr_floored(&sockaddr_v4(100, 64, 0, 1, 80), strict)); // CGNAT gateway
        // A genuine public destination is still reachable.
        assert!(!is_addr_floored(&sockaddr_v4(1, 1, 1, 1, 443), strict));
        assert!(!is_addr_floored(&sockaddr_v4(140, 82, 121, 4, 443), strict)); // github
    }

    #[test]
    fn off_floor_allows_everything() {
        let off = FloorMode::Off;
        assert!(!is_addr_floored(&sockaddr_v4(169, 254, 169, 254, 80), off));
        assert!(!is_addr_floored(&sockaddr_v4(10, 0, 0, 5, 80), off));
        assert!(!is_addr_floored(&sockaddr_v4(127, 0, 0, 1, 80), off));
    }

    #[test]
    fn explicit_allow_recognizes_static_cidr_not_learned_ip() {
        // `--allow-cidr 127.0.0.1/32` (or `--outbound-localhost-only`) marks
        // loopback as explicitly allowed, so the muxer re-opens it in the local
        // modes. A learned DNS answer for the same IP must NOT count — that path
        // is how the floor also defeats DNS rebinding.
        let mut policy = EgressPolicy::new(
            Some(vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)]),
            None,
            None,
        )
        .unwrap();
        assert!(policy.is_addr_explicitly_allowed(&sockaddr_v4(127, 0, 0, 1, 80)));
        // A different loopback address is not covered by the /32.
        assert!(!policy.is_addr_explicitly_allowed(&sockaddr_v4(127, 0, 0, 2, 80)));

        // Only loopback/unspecified count as host-loopback for the re-open path;
        // cloud-metadata is never re-openable even if allow-listed, so it must
        // NOT be classified as host-loopback.
        assert!(is_addr_host_loopback(&sockaddr_v4(127, 0, 0, 1, 80)));
        assert!(is_addr_host_loopback(&sockaddr_v4(0, 0, 0, 0, 80)));
        assert!(!is_addr_host_loopback(&sockaddr_v4(169, 254, 169, 254, 80)));
        assert!(!is_addr_host_loopback(&sockaddr_v4(10, 0, 0, 5, 80)));

        // Learn 127.0.0.2 via DNS: is_addr_allowed sees it, but the *explicit*
        // check still rejects it, so it can never punch the floor.
        policy.learn_ips(vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 300)]);
        assert!(policy.is_addr_allowed(&sockaddr_v4(127, 0, 0, 2, 80)));
        assert!(!policy.is_addr_explicitly_allowed(&sockaddr_v4(127, 0, 0, 2, 80)));
    }

    #[test]
    fn ipv4_mapped_metadata_cannot_smuggle_past_floor() {
        // ::ffff:169.254.169.254 must be floored just like the bare v4 form.
        let mapped = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
        let addr = VsockAddr::Inet(std::net::SocketAddrV6::new(mapped, 80, 0, 0).into());
        assert!(is_addr_floored(&addr, FloorMode::MetadataOnly));
        assert!(is_addr_floored(&addr, FloorMode::Strict));
    }
}
