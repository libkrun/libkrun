use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::time::Instant;

use socket2::Socket;

use super::host_bind::BindRequest;
use super::host_send::PendingHostSend;
use super::host_sockopt::{ListenerOptions, SocketBuffers};
use super::muxer::MuxerRx;
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket};
use super::vsock_addr::VsockAddr;
use serde::{Deserialize, Serialize};
use utils::epoll::EventSet;

/// Raw handle a proxy hands to the epoll layer for readiness registration. On
/// Unix this is the socket's file descriptor; on Windows it is the Winsock
/// SOCKET cast to the epoll shim's `HANDLE`-shaped `RawFd` (the shim detects
/// sockets and bridges them via `WSAEventSelect`).
#[cfg(unix)]
pub type ProxyRawHandle = RawFd;
#[cfg(windows)]
pub type ProxyRawHandle = utils::windows::RawFd;

/// Polling interest for an established proxied stream.
///
/// Keep this level-triggered. Host input can remain readable while the guest
/// temporarily has no RX descriptors. In that case the receive loop cannot
/// drain the socket to `WouldBlock`; edge-triggered polling would consume the
/// only readiness edge and leave the stream stalled after the guest replenishes
/// its virtqueue.
pub(super) fn connected_event_set(rx_paused: bool, tx_pending: bool) -> EventSet {
    let mut events = EventSet::empty();
    if !rx_paused {
        events |= EventSet::IN;
    }
    if tx_pending {
        events |= EventSet::OUT;
    }
    events
}

/// Compute the [`ProxyRawHandle`] for a socket2 socket, cross-platform.
#[cfg(unix)]
pub fn raw_handle(sock: &Socket) -> ProxyRawHandle {
    use std::os::unix::io::AsRawFd;
    sock.as_raw_fd()
}
#[cfg(windows)]
pub fn raw_handle(sock: &Socket) -> ProxyRawHandle {
    use std::os::windows::io::AsRawSocket;
    sock.as_raw_socket() as ProxyRawHandle
}

/// Address family of a TSI proxy, replacing the Unix-only `nix::AddressFamily`.
/// AF_UNIX is Linux-only (macOS/Windows do not proxy AF_UNIX over TSI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Inet,
    Inet6,
    /// AF_UNIX: available on Unix hosts (used by the host-IPC `UnixProxy`); not
    /// on Windows.
    #[cfg(unix)]
    Unix,
}

/// Snapshot of a live TSI inbound-port-forward listener, captured so a
/// cross-process fork clone can re-establish it. The guest's `listen()` is
/// intercepted by TSI and only ever issued once, so a snapshot-restored clone
/// (whose app is already past `listen()`) never re-arms the host-side listener —
/// the muxer's `proxy_map` is not part of the device snapshot. On restore the
/// muxer rebuilds each listener from this descriptor, retaining host-network
/// bindings or applying the clone's explicit publishing map. `peer_port`/`control_port`
/// are the guest socket's TSI ports (preserved verbatim so host-accepted
/// connections route to the guest's still-listening, CoW-restored socket).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerDesc {
    /// Address family as a Linux AF_* value (`defs::LINUX_AF_INET`/`INET6`).
    pub family: u16,
    /// Guest socket's TSI port (the `id` high word).
    pub peer_port: u32,
    /// Reply port for creation or the latest legacy accept request.
    pub control_port: u32,
    /// Guest listen port — the key into the host port map.
    pub guest_port: u16,
    /// Listen backlog the guest requested.
    pub backlog: i32,
    /// Absent in older snapshots, which restore through explicit port maps.
    /// Capture errors remain explicit rather than silently losing a listener.
    #[serde(default)]
    pub socket: Option<Result<ListenerSocketState, String>>,
    #[serde(default)]
    pub accept_pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerSocketState {
    pub address: SocketAddr,
    pub requested_bind: Option<SocketAddr>,
    pub host_network: bool,
    pub options: ListenerOptions,
    pub buffers: SocketBuffers,
}

#[derive(Debug)]
pub enum RecvPkt {
    Close,
    Error,
    Read(usize),
    WaitForCredit,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ProxyError {
    CreatingSocket(io::Error),
    InvalidFamily,
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum ProxyStatus {
    Idle,
    Connecting,
    Connected,
    Listening,
    Closed,
    PeerClosed,
    WaitingCreditUpdate,
    ReverseInit,
    WaitingOnAccept,
}

#[derive(Default)]
pub enum ProxyRemoval {
    #[default]
    Keep,
    Immediate,
    Deferred,
    /// Guest has closed; drain accepted output with a bounded idle lifetime.
    Drain,
}

pub enum NewProxyType {
    Tcp(SocketBuffers),
    /// Host-IPC AF_UNIX connection accepted by `UnixAcceptorProxy`. Available on
    /// all platforms with AF_UNIX support (Unix and Windows).
    Unix,
}

#[derive(Default)]
pub struct ProxyUpdate {
    pub signal_queue: bool,
    pub remove_proxy: ProxyRemoval,
    pub polling: Option<(u64, ProxyRawHandle, EventSet)>,
    pub new_proxy: Option<(u32, Socket, Family, NewProxyType)>,
    pub push_accept: Option<(u64, u64)>,
    pub push_credit_req: Option<MuxerRx>,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Host-side interception of guest TSI stream connects.
///
/// Guest flows to `port` are dialed to `endpoint` (a loopback listener the VMM
/// owner runs, e.g. a credential-substituting HTTPS interceptor) instead of the
/// destination the guest asked for. The proxy writes a fixed preamble first so
/// the listener learns the real destination and can verify the flow came from
/// this VM rather than from any process that found the port.
///
/// Wire layout, all integers big-endian: `"SMOLICPT"`, version `1`, the
/// 32-byte token, family (`4`/`6`), destination port, destination address.
/// The listener answers with one byte before any payload flows: `0` once it
/// has connected to the destination, otherwise the Linux errno of that
/// connect, which the guest then sees as the result of its own connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamIntercept {
    pub endpoint: SocketAddr,
    pub token: [u8; 32],
    pub port: u16,
}

impl StreamIntercept {
    /// Preamble announcing `destination` to the interceptor.
    pub fn preamble(&self, destination: SocketAddr) -> Vec<u8> {
        let mut out = Vec::with_capacity(60);
        out.extend_from_slice(b"SMOLICPT");
        out.push(1);
        out.extend_from_slice(&self.token);
        match destination.ip() {
            IpAddr::V4(_) => out.push(4),
            IpAddr::V6(_) => out.push(6),
        }
        out.extend_from_slice(&destination.port().to_be_bytes());
        match destination.ip() {
            IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
        }
        out
    }
}

pub trait Proxy: Send {
    /// Deadline for a guest-released stream that still owns accepted output.
    fn drain_deadline(&self) -> Option<Instant> {
        None
    }

    fn close_host_stream(
        &mut self,
        _request: &super::host_close::CloseRequest,
    ) -> (i32, ProxyUpdate) {
        (-95, ProxyUpdate::default())
    }
    /// Raw handle the muxer registers with the epoll layer for this proxy's host
    /// socket. Cross-platform replacement for the former `AsRawFd` supertrait.
    fn poll_handle(&self) -> ProxyRawHandle;
    fn id(&self) -> u64;
    #[allow(dead_code)]
    fn status(&self) -> ProxyStatus;
    /// Whether this proxy is a UDP/datagram proxy. The muxer uses this to gate
    /// DNS interception to datagram sockets only.
    fn is_dgram(&self) -> bool {
        false
    }
    /// Reserve a host address before listen/send, returning the actual address
    /// chosen for port zero. Host IPC and other proxies cannot use this path.
    fn set_host_option(&mut self, _req: &super::host_sockopt::OptionRequest) -> Result<(), i32> {
        Err(-95)
    }

    fn bind_host(&mut self, _req: &BindRequest) -> Result<VsockAddr, i32> {
        Err(-95) // Linux EOPNOTSUPP, including on non-Linux hosts.
    }
    fn prepare_host_send(&mut self, _send: PendingHostSend) -> Result<(), i32> {
        Err(-95)
    }
    #[cfg(target_os = "macos")]
    fn receive_host_error(
        &mut self,
        _error: &super::macos_icmp::DatagramError,
    ) -> Option<ProxyUpdate> {
        None
    }
    fn clear_sendto_addr(&mut self) {}
    fn disconnect_host_datagram(&mut self) -> (Result<(), i32>, ProxyUpdate) {
        (Err(-95), ProxyUpdate::default())
    }
    fn receive_dns(
        &mut self,
        _reply: super::dns_filter::HostDnsReply,
        _data: Vec<u8>,
        _activity: &super::snapshot_gate::SnapshotActivity<'_>,
    ) -> bool {
        false
    }
    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate;
    /// Connect through a [`StreamIntercept`] instead of to `req.addr` directly.
    /// Proxies without a redirected path fall back to a plain connect.
    fn connect_intercepted(
        &mut self,
        pkt: &VsockPacket,
        req: TsiConnectReq,
        _intercept: &StreamIntercept,
    ) -> ProxyUpdate {
        self.connect(pkt, req)
    }
    fn confirm_connect(&mut self, _pkt: &VsockPacket) -> Option<ProxyUpdate> {
        None
    }
    fn getpeername(&mut self, pkt: &VsockPacket);
    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    fn sendto_addr(&mut self, req: TsiSendtoAddr) -> ProxyUpdate;
    fn sendto_data(&mut self, _pkt: &VsockPacket) {}
    fn listen(
        &mut self,
        pkt: &VsockPacket,
        req: TsiListenReq,
        host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate;
    fn accept(&mut self, control_port: u32, req: TsiAcceptReq) -> ProxyUpdate;
    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    fn request_credit(&mut self) -> ProxyUpdate {
        ProxyUpdate::default()
    }
    fn push_op_request(&self) {}
    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    fn enqueue_accept(&mut self) {}
    fn push_accept_rsp(&self, _result: i32) {}
    fn shutdown(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
        ProxyUpdate::default()
    }
    fn shutdown_listener(&mut self, _mode: u32) -> (i32, ProxyUpdate) {
        (-95, ProxyUpdate::default())
    }
    fn release(&mut self) -> ProxyUpdate;
    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate;
    /// True if this proxy is a passive listener/acceptor (e.g. a host unix-IPC
    /// socket awaiting inbound connections), as opposed to a live connection.
    /// Listeners are preserved across a VM restore so the muxer keeps accepting
    /// new connections; active connection proxies are dropped and re-established
    /// (see [`super::muxer::VsockMuxer::reset_connections`]).
    fn is_listener(&self) -> bool {
        false
    }
    /// If this proxy is a live TSI inbound-port-forward listener, return its
    /// descriptor so it can be snapshotted and re-established on a fork clone
    /// (see [`ListenerDesc`]). `None` for everything else (connections, the
    /// agent unix acceptor, datagram proxies).
    fn listener_desc(&self) -> Option<ListenerDesc> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::connected_event_set;
    use utils::epoll::EventSet;

    #[test]
    fn connected_stream_readiness_is_level_triggered() {
        let events = connected_event_set(false, true);

        assert!(events.contains(EventSet::IN));
        assert!(events.contains(EventSet::OUT));
        assert!(!events.contains(EventSet::EDGE_TRIGGERED));
    }

    #[test]
    fn connected_stream_can_pause_reads_without_dropping_writes() {
        let events = connected_event_set(true, true);

        assert!(!events.contains(EventSet::IN));
        assert!(events.contains(EventSet::OUT));
    }
}
