# Security Model

The guest runs inside a VM. When configured devices forward guest requests to the host, the VMM handles those requests with its host process permissions. The VM boundary alone does not restrict the host resources exposed through those devices.

For many operations, the VMM acts as a proxy for the guest within the host. Host resources that are accessible to the VMM can potentially be accessed by the guest through it.

---

## Isolation Strategy

When defining the security implementation for your environment, limit what the VMM can access on the guest's behalf:

- **Host Namespace Isolation**: To prevent the guest from accessing host resources, use host OS security features to run the VMM inside an isolated context. On Linux, the primary mechanism is namespaces (user, mount, network, PID, IPC).
- **UID / GID Constraints**: Single-user systems may use relaxed policies, but should still ensure the VMM runs with dedicated, unprivileged UID/GID mappings.
- **Resource Limits**: Controls should be placed on host processes to limit memory consumption, file descriptor exhaustion, and CPU usage.

---

## Device-Specific Security Considerations

While most virtio devices allow the guest to access resources from the host, two devices require special consideration: **virtio-fs** and **virtio-vsock + TSI**.

### 1. virtio-fs

When exposing a host directory to the guest through `FsDevice` (virtiofs):

- **Filesystem Traversal**: Do not treat the virtio-fs export path as a sandbox for the VMM process. The passthrough implementation recommends a mount namespace and `pivot_root` when a specific directory must be confined. Export only the paths the guest needs.
- **Resource Exhaustion**: A guest may exhaust host filesystem resources such as inode limits, file descriptor limits, and disk capacity. Storage quotas and resource limits should be enforced on the host.

### 2. virtio-vsock + TSI (Transparent Socket Impersonation)

When TSI is enabled on `VsockDevice`:

- **Network Proxying**: The VMM acts as a direct proxy for `AF_INET`, `AF_INET6`, and `AF_UNIX` sockets, for both incoming and outgoing connections.
- **Network Context**: Proxied TSI socket calls use the VMM's host network context. Apply firewall, routing, or socket restrictions to the VMM process (e.g. by running it in a dedicated network namespace).
- **AF_UNIX Access**: On Linux, enabling `AF_UNIX` socket hijacking allows the guest to connect to host Unix domain sockets accessible to the VMM process.

### Guest init control socket

On Unix hosts, when `Builder::control_socket` and `Config::apply_with_vsock`
are used, the VMM listens on the configured host Unix socket and forwards
connections to the guest init's vsock control server. Any local process
allowed to connect can start a process in the guest or signal its main workload.
An exec request runs
with the guest init's identity (normally root) unless the caller supplies a
different UID and GID. Put the socket in a directory accessible only to the
intended runtime and its trusted controllers; Unix filesystem permissions on
the path and its parent directories form the host access boundary.

Guest init accepts control connections only from the host vsock CID. On Linux,
the vsock muxer reserves host listener proxy IDs so guest TSI packets cannot
claim or use them. It rejects guest TSI `AF_UNIX` connect and listen requests
whose paths resolve to a host listening socket, including filesystem aliases.
Relative listener paths are resolved before binding, so a later change to the
VMM's working directory cannot bypass the checks.

After an `AF_UNIX` connect, the muxer also checks the kernel-reported peer
before reporting success. This catches a symlink changed between the pathname
check and the connect. For a guest TSI listen, it pins the resolved parent
directory before removing an existing socket and uses that directory and the
socket's inode for cleanup; changing a parent symlink cannot redirect either
unlink to the host listener. These checks protect the listener from the guest.
They do not authenticate local host clients.

---

## Getting in contact

If you think you've identified a security issue in the project, please DO NOT report the issue publicly via the GitHub issue tracker or Matrix. Instead, send an email with as many details as possible to `libkrun-security@redhat.com`. This is a private mailing list for the core maintainers.
