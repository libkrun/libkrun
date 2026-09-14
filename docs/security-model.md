# Security Model

The `libkrun` security model is primarily defined by the consideration that **both the guest and the VMM operate in the same security context**.

For many operations, the VMM acts as a proxy for the guest within the host. Host resources that are accessible to the VMM can potentially be accessed by the guest through it.

---

## Isolation Strategy

When defining the security implementation for your environment, you should consider the guest and the VMM as a single entity:

- **Host Namespace Isolation**: To prevent the guest from accessing host resources, use host OS security features to run the VMM inside an isolated context. On Linux, the primary mechanism is namespaces (user, mount, network, PID, IPC).
- **UID / GID Constraints**: Single-user systems may use relaxed policies, but should still ensure the VMM runs with dedicated, unprivileged UID/GID mappings.
- **Resource Limits**: Controls should be placed on host processes to limit memory consumption, file descriptor exhaustion, and CPU usage.

---

## Device-Specific Security Considerations

While most virtio devices allow the guest to access resources from the host, two devices require special consideration: **virtio-fs** and **virtio-vsock + TSI**.

### 1. virtio-fs

When exposing a host directory to the guest through `FsDevice` (virtiofs):

- **Filesystem Traversal**: `libkrun` **does not** provide protection against the guest attempting to access other directories in the same filesystem or other filesystems on the host if not constrained by mount isolation. A host mount namespace or mount point isolation mechanism should always be used with virtio-fs.
- **Resource Exhaustion**: A guest may exhaust host filesystem resources such as inode limits, file descriptor limits, and disk capacity. Storage quotas and resource limits should be enforced on the host.

### 2. virtio-vsock + TSI (Transparent Socket Impersonation)

When TSI is enabled on `VsockDevice`:

- **Network Proxying**: The VMM acts as a direct proxy for `AF_INET`, `AF_INET6`, and `AF_UNIX` sockets, for both incoming and outgoing connections.
- **Network Context**: The VMM and guest run in the same network context. Any firewall, routing, or socket restrictions intended for the guest must be applied to the host VMM process (e.g. running the VMM in a dedicated network namespace).
- **AF_UNIX Access**: Exposing `AF_UNIX` socket hijacking allows the guest to connect to host Unix domain sockets accessible to the VMM process.

---

## Getting in contact

If you think you've identified a security issue in the project, please DO NOT report the issue publicly via the GitHub issue tracker or Matrix. Instead, send an email with as many details as possible to `libkrun-security@redhat.com`. This is a private mailing list for the core maintainers.
