# Networking

In `libkrun`, guest networking is provided by two distinct, mutually exclusive techniques:
1. **Transparent Socket Impersonation (TSI)** via `virtio-vsock`.
2. **Virtual Network Interface (`virtio-net`)** via userspace proxies such as [`passt`](https://passt.top/passt/about/) or [`gvproxy`](https://github.com/containers/gvisor-tap-vsock).

---

## 1. Transparent Socket Impersonation (TSI)

Transparent Socket Impersonation (TSI) allows guest applications to communicate over the network without requiring a virtual network interface (`eth0`) or guest IP configuration.

Instead of routing IP packets through virtual TUN/TAP devices, the guest kernel (provided by `libkrunfw`) hooks standard socket syscalls (`socket`, `connect`, `bind`, `listen`, `accept`) and multiplexes them over `virtio-vsock` to the host VMM. The VMM executes the socket calls directly in the host's network namespace on behalf of the guest.

### Features
- **Zero Configuration**: No network interface configuration, DHCP, or IP subnet allocation needed in the guest.
- **Bi-directional**: Supports both outgoing connections and incoming port forwarding from the host into the guest.
- **Supported Address Families**: `AF_INET`, `AF_INET6`, and `AF_UNIX` (stream and datagram sockets).

### Enabling TSI

#### Rust API
```rust
use krun::{TsiFlags, VsockDevice};

// Create a vsock device on guest CID 3 with Internet and Unix socket hijacking enabled
let mut vsock = VsockDevice::new(3, TsiFlags::HIJACK_INET | TsiFlags::HIJACK_UNIX)?;

// Forward host port 8080 to guest port 80
vsock.add_port_forward("80:8080")?;

devices.add(vsock);
```

#### C API
```c
#include <libkrun.h>

KrunVsockDevice vsock = krun_vsock_device_new(3, KRUN_TSI_FLAGS_HIJACK_INET | KRUN_TSI_FLAGS_HIJACK_UNIX, &err);
krun_vsock_device_add_port_forward(vsock, KRUN_STR("80:8080"), &err);
krun_mmio_device_manager_add(devices, vsock);
```

### Known Limitations
- Requires a kernel with TSI support (bundled in `libkrunfw`).
- Limited to `SOCK_STREAM` and `SOCK_DGRAM` sockets across `AF_INET`, `AF_INET6`, and `AF_UNIX`. Raw sockets (`SOCK_RAW`), ICMP ping sockets, and netlink are not supported.
- Listening on `SOCK_DGRAM` sockets from inside the guest is not supported.
- For `AF_UNIX` sockets, only absolute filesystem paths are supported.

---

## 2. Virtual Network Interface (`virtio-net`)

`virtio-net` provides a conventional virtual Ethernet interface inside the guest (`eth0`). The guest gets a full TCP/IP stack and communicates with the host or external networks through a userspace network proxy like [`passt`](https://passt.top/passt/about/) or [`gvproxy`](https://github.com/containers/gvisor-tap-vsock).

### Enabling `virtio-net`

A `NetDevice` is created by passing a Unix stream socket connected to the network proxy:

#### Rust API
```rust
use krun::NetDevice;

let mac = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

// Connected via an open socket file descriptor
let net = NetDevice::new_unixstream_fd("net0", socket_fd, &mac, 0)?;
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
- **virtio-net Context**: Traffic flows through the userspace proxy (`passt`/`gvproxy`), isolating guest traffic within the proxy's network filtering rules.
