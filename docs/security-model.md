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

On macOS, call `FsDevice::set_permission_semantics(PermissionSemantics::Restricted)` before attaching a host-backed filesystem to enable restricted access. This is available for both writable and read-only exports. It uses `LinuxSimplified` permissions: the guest sees its requesting UID/GID, and permission bits are stored on the host.

Restricted access pins the export root and tracked inodes with file descriptors. Every inode and open-handle operation checks that the object remains beneath that root. Root-relative traversal opens each component without dereferencing host symlinks. When an operation requires a symlink target, the backend expands its contents manually: absolute targets start at the export root, relative targets start at the link's directory, and `..` cannot leave the export. Normal guest symlink traversal still uses FUSE lookup/readlink and the guest's mount namespace.

This mode deliberately restricts filesystem semantics:

- Non-directory objects with multiple hard links are rejected, including when a host hard link is added after a guest opens a file. Creating hard links is rejected.
- Only regular files, directories, and symbolic links are accessible. Device nodes, FIFOs, and sockets are rejected. Changing symlink permissions or size is rejected.
- Moved-out, unlinked, and overwritten objects become inaccessible, including through existing open handles. Handles can still be released. Moving the export root preserves the original directory's identity.
- Cross-device traversal, xattrs, security-context extensions, idmaps, writeback caching, and DAX are unavailable. File opens use direct I/O and metadata has zero cache lifetime. Both `set_dax_window_size()` and `set_permission_semantics()` reject combining a DAX window with restricted access, leaving the previous configuration unchanged.
- Empty names, names containing `/`, and explicit `.`/`..` lookup or mutation names are rejected. Symlink expansion is limited to 40 links. Rename whiteouts are unsupported.

The configured export path must contain no symbolic-link components. Containment checks and filesystem operations are separate syscalls: concurrent host renames, replacements, or hard-link creation can race them. Restricted access prevents guest-directed traversal under a stable host namespace; deployments requiring protection against concurrent host namespace changes must additionally restrict the VMM with host OS isolation. Each tracked inode retains a descriptor, so descriptor limits should account for the guest's lookup workload.

### 2. virtio-vsock + TSI (Transparent Socket Impersonation)

When TSI is enabled on `VsockDevice`:

- **Network Proxying**: The VMM acts as a direct proxy for `AF_INET`, `AF_INET6`, and `AF_UNIX` sockets, for both incoming and outgoing connections.
- **Network Context**: Proxied TSI socket calls use the VMM's host network context. Apply firewall, routing, or socket restrictions to the VMM process (e.g. by running it in a dedicated network namespace).
- **AF_UNIX Access**: On Linux, enabling `AF_UNIX` socket hijacking allows the guest to connect to host Unix domain sockets accessible to the VMM process.

---

## Getting in contact

If you think you've identified a security issue in the project, please DO NOT report the issue publicly via the GitHub issue tracker or Matrix. Instead, send an email with as many details as possible to `libkrun-security@redhat.com`. This is a private mailing list for the core maintainers.
