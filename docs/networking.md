# Networking

In `libkrun`, guest networking can use two approaches:
1. **Transparent Socket Impersonation (TSI)** via `virtio-vsock`.
2. **Virtual Network Interface (`virtio-net`)** via userspace proxies such as [`passt`](https://passt.top/passt/about/) or [`gvproxy`](https://github.com/containers/gvisor-tap-vsock).

---

## 1. Transparent Socket Impersonation (TSI)

Transparent Socket Impersonation (TSI) allows guest applications to communicate over the network without requiring a virtual network interface (`eth0`) or guest IP configuration.

Instead of routing IP packets through virtual TUN/TAP devices, the guest kernel (provided by `libkrunfw`) hooks standard socket syscalls (`socket`, `connect`, `bind`, `listen`, `accept`) and multiplexes them over `virtio-vsock` to the host VMM. The VMM executes the socket calls directly in the host's network namespace on behalf of the guest.

### Features
- **Zero Configuration**: No network interface configuration, DHCP, or IP subnet allocation needed in the guest.
- **Bi-directional**: Supports both outgoing connections and incoming port forwarding from the host into the guest.
- **Supported Address Families**: `AF_INET` and `AF_INET6` (stream and datagram sockets), plus `AF_UNIX` on Linux.

### Enabling TSI

#### Rust API (Linux example)
```rust
use krun::{TsiFlags, VsockDevice};

// Create a vsock device on guest CID 3 with Internet and Unix socket hijacking enabled
let mut vsock = VsockDevice::new(3, TsiFlags::HIJACK_INET | TsiFlags::HIJACK_UNIX)?;

// Forward host port 8080 to guest port 80
vsock.add_port_forward("80:8080")?;

devices.add(vsock);
```

#### C API (Linux example)
```c
#include <libkrun.h>

KrunVsockDevice vsock = krun_vsock_device_new(3, KRUN_TSI_FLAGS_HIJACK_INET | KRUN_TSI_FLAGS_HIJACK_UNIX, &err);
krun_vsock_device_add_port_forward(vsock, KRUN_STR("80:8080"), &err);
krun_mmio_device_manager_add(devices, vsock);
```

On macOS, use only `TsiFlags::HIJACK_INET` (C:
`KRUN_TSI_FLAGS_HIJACK_INET`). Requesting `HIJACK_UNIX` returns
`VmmError::FeatureDisabled` from `VsockDevice::new` before VM startup because
host UNIX proxying is unsupported. Guest UNIX sockets, including nscd/NSS
lookups, retain their native guest behavior when UNIX hijacking is disabled.

Host TCP proxies on Unix enable `SO_REUSEADDR` for rapid restart. Sharing a
listening port through `SO_REUSEPORT` requires an explicit application request;
automatic exposure of application-selected ports remains enabled.

### TCP publication failures

Automatic guest fallback is the default when selected host publication errors
occur. To return the original host error from guest `listen()` instead, enable
`FAIL_ON_TCP_PUBLICATION_ERROR` for that VM:

```rust
let flags = TsiFlags::HIJACK_INET | TsiFlags::FAIL_ON_TCP_PUBLICATION_ERROR;
let mut vsock = VsockDevice::new(3, flags)?;
```

```c
KrunVsockDevice vsock = krun_vsock_device_new(
    3, KRUN_TSI_FLAGS_HIJACK_INET | KRUN_TSI_FLAGS_FAIL_ON_TCP_PUBLICATION_ERROR,
    &err);
```

Strict mode applies to INET TCP listeners, including configured port overrides.
It leaves the guest socket bound without starting a guest-only listener when
publication fails. A normal host error keeps the control channel usable, so
`listen()` can be retried after resolving a bind conflict. UNIX and UDP behavior
is unchanged. This requires the matching TSIv4 kernel/host pair.

Linux and macOS TSI hosts support ordinary iputils `ping` using ICMP datagram sockets,
including IPv4, IPv6, connected mode and explicit nonzero echo identifiers.
Allow the application/VMM groups in `net.ipv4.ping_group_range` in the guest
and Linux host respectively. macOS uses its unprivileged native ICMP sockets.
`CAP_NET_RAW` is unnecessary. Guest-local destinations
stay inside the guest; other destinations use the host network. UDP port
mappings do not apply to echo identifiers. Raw ping (`-e 0`), outgoing TTL/hop-limit
controls and host error-queue forwarding are unsupported; other host platforms
do not currently proxy ICMP ping sockets.

### Known Limitations
- In the default fallback mode, successful guest TCP `listen()` does not guarantee host reachability. Selected host bind/listen failures (including a busy port) can leave a guest-only listener while returning success. This also applies with configured port overrides. The listener is not automatically exposed when the conflict disappears; close and recreate it to retry publication.
- Requires a kernel with TSI support (bundled in `libkrunfw`).
- Limited to `SOCK_STREAM` and `SOCK_DGRAM` sockets across `AF_INET`, `AF_INET6`, and `AF_UNIX`. Linux and macOS hosts support ICMP datagram ping sockets for IPv4 and IPv6. Raw sockets (`SOCK_RAW`) and netlink are not supported.
- For `AF_UNIX` sockets, only absolute filesystem paths are supported.
- Host-side `AF_UNIX` TSI handling is not implemented on macOS.
- On macOS, ICMP support covers unicast echo requests/replies. Connected UDP sends to another explicit destination require disconnect/reconnect; see the [wire contract](tsi-protocol.md) for native datagram limits.

---

## 2. Virtual Network Interface (`virtio-net`)

`virtio-net` provides a conventional virtual Ethernet interface inside the guest (often `eth0`). The guest gets a full TCP/IP stack and communicates with the host or external networks through a userspace network proxy like [`passt`](https://passt.top/passt/about/) or [`gvproxy`](https://github.com/containers/gvisor-tap-vsock).

### Enabling `virtio-net`

A `NetDevice` is created by passing a Unix stream socket connected to the network proxy:

#### Rust API
```rust
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use krun::{NetDevice, NetFlags};

let mac = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

let socket_fd: OwnedFd = UnixStream::connect("/path/to/proxy.sock")?.into();
let net = NetDevice::new_unixstream_fd("net0", socket_fd, &mac, 0, NetFlags::empty())?;
devices.add(net);
```

#### C API
```c
#include <libkrun.h>

uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};
KrunNetDevice net = krun_net_device_new_unixstream_fd(
    KRUN_STR("net0"), socket_fd, KRUN_BYTES(mac), 0, 0, &err);
krun_mmio_device_manager_add(devices, net);
```

---

## Security Considerations

- **TSI Context**: When TSI is enabled, the VMM executes socket syscalls directly in the host's network context. Host network access restrictions should be applied directly to the host VMM process (e.g. via network namespaces).
- **virtio-net Context**: Traffic flows through the userspace proxy (`passt`/`gvproxy`); the proxy's configuration determines what networks the guest can reach.
