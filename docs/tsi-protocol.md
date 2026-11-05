# TSIv4 wire protocol (development)

TSIv4 requires a matching guest kernel. The paired Linux implementation is
`net/tsi/af_tsi.{h,c}`; its contract is documented in
`Documentation/networking/tsi.rst`. There is no TSIv3 negotiation or fallback.
Firmware loading will require libkrunfw ABI 6 as part of the coordinated release.

Control messages carry a 24-byte common header before their operation body:

| Offset | Bytes | Field (little endian) |
| --- | --- | --- |
| 0 | 4 | Version = 4 |
| 4 | 4 | Operation = request destination / response source VSOCK port |
| 8 | 8 | Nonzero request ID, echoed unchanged |
| 16 | 4 | Payload length, excluding this header |
| 20 | 4 | Flags: 0 request, 1 response, 2 one-way request |

Other flag bits are reserved. Packet lengths must be exact. Responses originate
at host CID 2 and the operation's port. The guest validates source, version,
operation, ID, flags, result and length. IDs remain distinct across sockets and
control port reuse within a guest boot; late replies do not extend the deadline.
Async TCP connect and accept replies retain the originating request ID.

| Port | Request body | Reply body | Operation |
| --- | --- | --- | --- |
| 1024 | 12 | 4 | Create proxy |
| 1025 | 136 | 4 | Connect: data port, address length, 128-byte address |
| 1026 | 12 | 136 | Get name: data port, peer port, peer selector |
| 1027 | 136 | None | Legacy UNIX sendto address, one-way |
| 1029 | 144 | 4 | Listen: data port, listener port, backlog, address length, address |
| 1030 | 8 | 4 | Accept accounting: data port, flags = 0 |
| 1031 | 8 | None | Release: data port, peer port, one-way |
| 1033 | 4 | 4 | Disconnect INET datagram proxy: data port |
| 1034 | 20 | 4 | Set integer socket option |
| 1035 | 16 | 8 | Get integer socket option |
| 1036 | 136 | 4 | Bind INET datagram: data port, address length, 128-byte address |

Fields are 32-bit unless stated otherwise; unused address bytes are zero.
Replies begin with a signed 32-bit result: zero or a negative Linux errno.
GETNAME adds a 32-bit address length and a zero-padded 128-byte Linux sockaddr;
on errors, both are zero. Selector 0 requests the local name; selector 1 requests
the peer. The guest normalizes internal nonzero Linux peer selectors to 1.
Address lengths are concrete sockaddr sizes, not sockaddr_storage capacity.
Malformed recoverable requests receive EPROTO, unsupported versions receive
EPROTONOSUPPORT. Invalid one-way requests or unidentifiable headers are dropped.

Local control waits have a five-second deadline. Blocking stream connect is
interruptible and uses the smaller of SO_SNDTIMEO and 120 seconds. GETNAME and
ordinary GETOPT are also interruptible. Create, datagram connect, listen, accept accounting and
SETOPT finish their bounded wait despite signals. GETOPT of SO_ERROR also waits
through signals because the read clears the host error. Failed GETNAME/GETOPT
exchanges do not break the control channel. A failed state-changing exchange leaves host state uncertain:
the guest returns the exchange error and later control/data operations fail with
EIO until close. Close still releases the proxy; an interrupted connect requires
a new socket. Normal host-reported errors do not break the control channel.

IPv4/IPv6 nonblocking stream connects return EINPROGRESS and continue in the
guest, first attempting the native endpoint and then the host proxy on failure.
A repeated pending connect returns EALREADY. The application socket becomes
ready only after native success or both host TCP and data VSOCK completion.
SO_ERROR is zero while pending; a failed completion wakes writable/error
waiters and supplies its errno once, then zero. Connecting an established
stream returns EISCONN. This uses the existing CONNECT wire operation.

The total async setup deadline is the smaller of the initial SO_SNDTIMEO and
120 seconds; timeout requires close because host state may be uncertain.
Closing cancels guest setup and releases the proxy without waiting for the
remote TCP deadline. Transport/control notifications and a timer drive setup;
there is no worker parked for every pending TCP connection. While pending,
send/recv and ioctl return EAGAIN, getpeername returns ENOTCONN, and getsockname
reports the native local endpoint. Option getters read local values, and
setters return EAGAIN except local receive/send timeouts. Updating a timeout
does not extend the active deadline. bind/listen/accept return EINVAL and
shutdown returns ENOTCONN. UNIX streams retain the existing connect path.
These rules prioritize event-loop progress over full native equivalence.

Proxy creation's 12-byte body is:

| Offset | Bytes | Field (little endian) |
| --- | --- | --- |
| 0 | 4 | Guest data VSOCK port |
| 4 | 2 | Linux address family |
| 6 | 2 | Linux socket type |
| 8 | 4 | Linux socket protocol |

INET streams support protocol 0 or TCP (6); INET datagrams support 0 or UDP (17).
Linux hosts also support IPv4 ICMP (1) and IPv6 ICMPv6 (58) datagram ping sockets.
UNIX sockets support protocol 0, subject to platform support. Other protocols
return EPROTONOSUPPORT instead of silently becoming TCP/UDP. Creation errors and
host permission failures are explicit. Duplicate creation returns EADDRINUSE
without replacing the existing proxy. The guest retains the data port for
close-time cleanup if creation's reply is lost.

Explicit INET datagram bind reserves a native guest endpoint, creates the host
proxy, replays cached options, then sends BIND (1036). Its body has the same
layout as CONNECT. The host binds the requested address and guest-selected port,
applying an existing guest:host port override, and registers receive interest
before replying. Incoming host datagrams work before the first outgoing send.
No automatic SO_REUSEPORT is added. Mappings override ports; they are not an
allowlist, and existing impersonation flags and host bind permissions apply.

For bind(0), the guest chooses a nonzero port. Explicitly bound local names
continue to describe the guest endpoint even with a mapped host port or after
proxy sends. That port stays reserved through AF_UNSPEC disconnect. Unconnected
receive still checks both guest-native and proxy queues; a matching native
listener retains destination precedence, so identical host/guest tuples remain
ambiguous. Implicitly bound outgoing UDP keeps lazy host allocation and host
endpoint reporting. UNIX datagrams keep the existing binding path.

Host publication failures are returned to the application. After a partial bind,
close is required and later operations return EIO: the two endpoints cannot be
rolled back atomically while retaining arbitrary native socket tuning. Datagram
proxy release is immediate, without TCP's deferred reaper. This requires the
paired TSIv4 host implementation; it does not negotiate with older kernels.

INET datagrams use port 1032 with one frame for address and payload. Replies
originate at host CID 2, port 1032, and carry the actual sender of each packet.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | Version = 4, little endian |
| 4 | 4 | Address length, little endian: IPv4 16 / IPv6 28 |
| 8 | 4 | Original payload length, little endian |
| 12 | 4 | Flags, little endian: bit 0 = truncated, bit 1 = packet-info, bit 2 = TTL/hop-limit |
| 16 | 128 | Linux IPv4/IPv6 socket address followed by zero padding |
| 144 | 4 | Host ingress interface index, little endian; zero on guest sends |
| 148 | 4 | Reply TTL/hop-limit, little endian; zero without bit 2 |
| 152 | 16 | Destination IP on receive; selected source IP on send |
| 168 | N | Payload, including an empty payload |

Address family and IPv6 scope ID are little endian; ports, IP bytes and IPv6
flowinfo are in network order. The frame is limited to 65536 bytes, leaving a
65368-byte proxied send payload limit. Oversized guest sends return EMSGSIZE.
Receivers validate all fields before delivering data. A truncated receive may
carry fewer bytes than the original payload length, up to 65535. Hosts report the
original length when their socket API provides it; truncation is always flagged.

The application never sees framing. Zero-length UDP packets remain packets;
MSG_PEEK retains them and MSG_TRUNC follows guest receive semantics. Ordinary UDP
sends do not gain a synchronous host round trip. The guest data socket can connect
to the canonical host VSOCK tuple even when the application UDP socket is
unconnected. The host UDP socket enforces connected peer filtering.

When packet-info is present, the IP address is nonzero. IPv4 occupies the first
four bytes with twelve zero bytes; IPv6 uses all sixteen. Absent packet-info
requires zero interface/address fields. Reply flag bit 2 requires packet-info and
a TTL/hop-limit in the range 0..255; without that flag the word at offset 148 is
zero. Guest sends cannot specify a host interface index or use truncation or
TTL/hop-limit flags.
This 168-byte header replaces the unreleased 144-byte development layout and
requires the updated host/guest pair; LISTEN and control framing stay unchanged.

The host captures destination IP and ingress interface using native packet-info.
When enabled, guest `IP_PKTINFO` / `IPV6_PKTINFO` reports the destination IP,
including for wildcard/implicit binds. Its interface index is guest-local: use
the socket's bound device, otherwise an interface owning that IP, otherwise
loopback. Host interface indices are not exposed as guest indices. Short
control buffers set `MSG_CTRUNC`. A fixed guest-local bind can supply packet-info
when a frame lacks it.

Linux hosts also capture the reply IPv4 TTL / IPv6 hop-limit. When the guest
enables `IP_RECVTTL` / `IPV6_RECVHOPLIMIT`, `recvmsg` delivers the corresponding
`IP_TTL` / `IPV6_HOPLIMIT` control message. This is receive metadata only.

Proxy send accepts `IP_PKTINFO.ipi_spec_dst` and `IPV6_PKTINFO.ipi6_addr` as source
selection. A guest interface index must be zero or match the logical guest
interface for that source. The wire send interface field stays zero, and the
host applies the chosen IP through native sendmsg/WSASendMsg. Native host errors
use the existing asynchronous UDP socket-error path. An unspecified address and
zero interface index express no preference.

Interface-only source selection, scoped IPv6 link-local routing and other proxy
ancillary messages remain unsupported. There is no host/guest mapping of IPv6
scope IDs; multicast and broadcast semantics are outside this extension. Native
delivery keeps native ancillary handling; wildcard native-listener lookup uses
the selected source or native route source to preserve connected guest clients.

Winsock dual-stack sockets need both IPv4 and IPv6 packet-info options; mapped
IPv4 source selection uses an IPv4 control message. See Microsoft's
[dual-stack documentation](https://learn.microsoft.com/windows/win32/winsock/dual-stack-sockets)
and [WSASendMsg reference](https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-wsasendmsg).

On Linux, ICMP datagram ping sockets use the same framing and the host's native
ping socket implementation. The guest keeps echo requests to guest-local IPs
native; other destinations use the host proxy. An explicit ICMP bind can use
the host-selected source from a route probe even if the guest does not own
that IP; the host still validates the requested bind. Both guest and host must permit
the socket owner's group in `net.ipv4.ping_group_range`. Echo identifiers are
managed by the native ping sockets and are not UDP ports; UDP port mappings do
not apply. This supports ordinary iputils `ping`, including `-C` and nonzero
`-e` identifiers, without `CAP_NET_RAW`. Raw ICMP (`-e 0`), other raw protocols,
host error-queue forwarding and outgoing TTL/hop-limit controls remain outside
this contract. ICMP proxy creation on other hosts returns `EPROTONOSUPPORT`.

INET datagrams and control messages now use TSIv4 framing. UNIX datagram payloads
retain the legacy two-message path (their address control message is enveloped).
Firmware version checks remain in the TSIv4 implementation plan.

Application UDP `connect(AF_UNSPEC)` sends an acknowledged DISCONNECT request
before publishing the disconnected guest state. The host dissolves its socket's
peer association and remains available for later sendto/connect operations.
Repeated disconnects are supported. Switching a connected UDP socket to a guest
peer also disconnects a previous host peer. The canonical VSOCK data endpoint
stays connected to CID 2, port 1032. Ordinary UDP payloads remain asynchronous.

Proxied outgoing/accepted sockets use host-selected IP addresses; wildcard
accepts return their concrete local address. UDP names expose the active host
endpoint, including an implicitly assigned sendto port. Guest-local operations
use the native endpoint. Listeners and explicit guest binds keep their logical
ports across host mappings; UNIX bind names remain guest names. Explicit client
binds are still not forwarded to the host, and hybrid sockets retain separate
native and host endpoints.

A shut-down or failed stream disables event polling and remains owned by the
guest descriptor. Retain its host socket for name queries until guest release;
shutdown alone does not schedule deferred proxy removal. Peer-name errors follow
the native host socket's state.

## Socket options

SETOPT (1034) contains five little-endian 32-bit fields: guest data port,
peer port, Linux level, Linux option number and signed integer value.
GETOPT (1035) omits the value. The port pair identifies an outgoing or accepted
proxy. SETOPT returns a result; GETOPT returns result plus effective signed
integer value (zero on error). Linux numbers are mapped explicitly to native
host constants, and errors are translated to Linux errno values.

The host allowlist includes SOL_SOCKET REUSEADDR, REUSEPORT, KEEPALIVE,
BROADCAST, SNDBUF and RCVBUF; read-only SO_ERROR; TCP_NODELAY on INET streams;
and IPV6_V6ONLY on IPv6 sockets. SO_REUSEPORT is unavailable on UNIX sockets and
Windows. Host wire requests for unlisted or privileged options return
ENOPROTOOPT, including forced buffer sizes or host device binding.

The guest caches successful native setters before lazy creation and replays
allowed values before host bind/listen/connect. Active getters return effective
host values, including native buffer limits/accounting; boolean values are
normalized to zero or one. Buffer setters also configure guest transports.
Host setter errors preserve the previous guest setting. Uncertain partial
application requires closing the socket.

Guest wait timeouts remain on the wrapper and private transports, including
accepted sockets. Device binding affects guest routing only. TYPE, DOMAIN,
PROTOCOL and ACCEPTCONN report application metadata. Options outside the remote
allowlist are applied to and read from the private guest-native socket when it
exists, including after proxy creation. They do not configure or describe the
host endpoint and do not prevent proxy networking. Local TCP keepalive timing,
maximum-segment size, user timeout and UDP path-MTU settings are examples of
values not forwarded. This best-effort policy favors application compatibility.
Proxy-only accepted sockets have no guest-native endpoint and return ENOPROTOOPT
for these options; unsupported guest-native options still fail. Direct wire
requests remain restricted to the host allowlist.

SO_ERROR reads and clears pending errors. The datagram broker retains the first
pending error consumed by host I/O or Linux error readiness for one guest read.
Ordinary UDP sends remain asynchronous. This does not relay host UDP POLLERR to
the guest; error readiness and platform-specific socket semantics remain gaps.
The host's existing listener reuse defaults and exposure policy remain in force
unless explicitly overridden. REUSEPORT forwarding does not isolate ports
between VMs.
