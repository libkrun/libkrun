<picture>
   <source media="(prefers-color-scheme: dark)" srcset="docs/images/libkrun_logo_horizontal_darkmode.png">
   <source media="(prefers-color-scheme: light)" srcset="docs/images/libkrun_logo_horizontal.png">
   <img alt="libkrun logo" src="docs/images/libkrun_logo_horizontal.png">
</picture>

# libkrun

```libkrun``` is a dynamic library that allows programs to easily acquire the ability to run processes in a partially isolated environment using [KVM](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt) Virtualization on Linux, [HVF](https://developer.apple.com/documentation/hypervisor) on macOS/ARM64, and [WHP](https://learn.microsoft.com/en-us/virtualization/api/) on Windows (upcoming).

It integrates a VMM (Virtual Machine Monitor, the userspace side of an Hypervisor) with the minimum amount of emulated devices required to its purpose, abstracting most of the complexity that comes from Virtual Machine management, offering users either a Rust or C API.

> [!NOTE]
> The `main` branch is now **libkrun 2.0**, which will not be backwards
> compatible with the 1.x API/ABI. The 2.0 API is also still under active
> development and may change further before the first stable release. If
> you are building from source for production use, please use the newest
> [`stable-*` release branch](https://github.com/libkrun/libkrun/branches)
> instead.

> [!CAUTION]
> The VM boundary does not restrict host resources exposed through devices. Limit the VMM's host permissions and exposed paths. Read the [Security Model](docs/security-model.md) before embedding or deploying `libkrun`.

## Use cases

* [crun](https://github.com/containers/crun/blob/main/krun.1.md): Adding virtualization-based isolation to container and confidential workloads (used by Podman via `--runtime=krun` or OCI annotations).
* [krunkit](https://github.com/containers/krunkit): Running GPU-enabled (via [venus](https://docs.mesa3d.org/drivers/venus.html)) lightweight VMs on macOS.
* [muvm](https://github.com/AsahiLinux/muvm): Launching a microVM with GPU acceleration (via [native context](https://www.youtube.com/watch?v=9sFP_yddLLQ)) for running games that require 4k pages.

For details on common workload models and boot strategies, see [Common Workload Models & Use Cases](docs/workloads.md).

## Variants

This project provides the following variants of the library:

- **libkrun**: Generic variant compatible with all Virtualization-capable systems.
- **libkrun-sev**: Variant including support for AMD SEV (SEV, SEV-ES and SEV-SNP) memory encryption and remote attestation. Requires an SEV-capable CPU.
- **libkrun-tdx**: Variant including support for Intel TDX memory encryption. Requires a TDX-capable CPU.

Each variant generates a dynamic library with a different name (and ```soname```), so both can be installed at the same time in the same system.

## Supported Virtio devices
* virtio-console
* virtio-block
* virtio-fs
* virtio-gpu (venus and native-context)
* virtio-net
* virtio-vsock (for TSI and socket redirection)
* virtio-balloon (only free-page reporting)
* virtio-rng
* other virtio devices via vhost-user support

## Networking

In `libkrun`, guest networking can use two approaches:
- **Transparent Socket Impersonation (TSI)**: Hooks guest socket syscalls over `virtio-vsock` to share host network connectivity without a virtual network interface.

  > [!CAUTION]
  > TSI uses the VMM's host network access. Restrict the VMM's network permissions; see [Security Model](docs/security-model.md).

- **Virtual Network Interface (`virtio-net`)**: Connects a virtual Ethernet interface inside the guest to a userspace network proxy like [`passt`](https://passt.top/passt/about/) or [`gvproxy`](https://github.com/containers/gvisor-tap-vsock).

For full configuration details, port forwarding, and security models, see [Networking](docs/networking.md).

## Linux Quickstart

Build and install `libkrun`, then run a shell inside an isolated microVM using the `chroot_vm` example:

### 1. Build and install libkrun

```bash
# Build with common features, then install to a user-owned prefix
make -j11 BLK=1 NET=1 VHOST_USER=1
make -j11 BLK=1 NET=1 VHOST_USER=1 PREFIX="$HOME/.local" install
```

> For complete prerequisites, platform instructions (macOS / SEV / TDX), and feature flags, see [Building and Installing libkrun](docs/building.md).

### 2. Build the example and prepare a rootfs

```bash
cd examples
gcc -O2 -g -I"$HOME/.local/include" -L"$HOME/.local/lib64" \
    -o chroot_vm chroot_vm.c -lkrun -lkrun_init
make rootfs  # extracts a Fedora root filesystem (requires podman)
```

The `-I` and `-L` flags use headers and libraries installed in `$HOME/.local`, without a system-wide libkrun installation. Running the VM also requires [libkrunfw](https://github.com/containers/libkrunfw) to be installed and discoverable by the dynamic linker.

### 3. Run an isolated process

```bash
LD_LIBRARY_PATH="$HOME/.local/lib64" ./chroot_vm ./rootfs_fedora /bin/sh
```

If you installed to another prefix, use its `include` directory for `-I` and its `lib64` directory for `-L` and `LD_LIBRARY_PATH`.

## Architecture & Development Guides

`libkrun` provides both a native Rust API and an autogenerated C API defined in [include/libkrun.h](include/libkrun.h) and [include/libkrun_init.h](include/libkrun_init.h).

- [Building & Installation](docs/building.md): Complete platform prerequisites, confidential computing variants, and feature toggles.
- [Common Workload Models & Use Cases](docs/workloads.md): Supported workload patterns and consumers.
- [VM Lifecycle & Execution](docs/vm-lifecycle.md): Configuration pipeline and runtime control.
- [Guest Init Subsystem](docs/init.md): Guest PID 1, OCI spec conversion, and overlay injection.
- [Networking Architecture](docs/networking.md): Transparent Socket Impersonation (TSI), virtio-net, and proxy integration.
- [Security Model](docs/security-model.md): Isolation strategy, mount boundaries, and device security considerations.
- [Bindings Generation (ffier)](docs/bindings-generation.md): ffier schema derivation and C/Rust bindings regeneration.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting changes.

## Getting in contact

If you think you've identified a security issue in the project, please DO NOT report the issue publicly via the GitHub issue tracker or Matrix. Instead, send an email with as many details as possible to `libkrun-security@redhat.com`. This is a private mailing list for the core maintainers.

The main communication channel is the [libkrun Matrix channel](https://matrix.to/#/#libkrun:matrix.org).

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).
