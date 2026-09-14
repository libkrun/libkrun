# Workspace Crates & Feature Architecture

libkrun is structured as a modular Rust workspace (`Cargo.toml`) split across four functional tiers:

---

## 1. Core & API Crates

| Crate | Directory | Description |
|---|---|---|
| **`libkrun`** | `src/libkrun/` | Main entry point. Exposes the native Rust API and the ffier C bridge (`libkrun.so`), and embeds the merged VMM core (vCPU threads, guest memory layout, device manager, event loop). |
| **`krun-via-cdylib-weak`** | `src/libkrun-via-cdylib-weak/` | Weak dynamic-linking Rust client. Generated at build time from the committed JSON schema (`ffier-krun.json`) to load `libkrun.so` dynamically at runtime. |
| **`krun-devices`** | `src/devices/` | Implementations of virtio devices: console, block, fs (virtiofs passthrough + read-only overlay), net, vsock (TSI), gpu, input, balloon, rng, and vhost-user. |
| **`krun-kernel`** | `src/kernel/` | Kernel image loader. Parses and loads ELF, PE/bzImage, and raw binary kernels, and sets up boot parameters. |
| **`krun-arch`** | `src/arch/` | Low-level architecture setup: GDT/IDT/paging for x86_64, Flattened Device Tree (FDT) generation for aarch64 and riscv64. |

---

## 2. Init Subsystem Crates (`init/`)

See [docs/init.md](init.md) for full details on the guest init subsystem.

| Crate / Directory | Description |
|---|---|
| **`init/init-binary`** | Statically-linked guest PID 1 binary for Linux musl or FreeBSD. Mounts runtime pseudofs, reads `.krun_config.json`, and execs the workload. |
| **`init/init-blob`** (`krun-init-blob`) | Embeds the compiled init binary via `include_bytes!`, provides `InitConfig` and OCI container spec builders, and exports the `libkrun_init` C bridge via ffier. |
| **`init/init-blob-via-cdylib`** | Weak dynamic-linking Rust client for `libkrun_init.so`, generated from `ffier-krun_init.json`. |
| **`init/aws-nitro`** | Dedicated enclave init implementation used when building for AWS Nitro Enclaves (`AWS_NITRO=1`). |

---

## 3. Hypervisor Backends

| Backend | Location | Supported Platforms | Implementation Details |
|---|---|---|---|
| **KVM** | `src/libkrun/src/vmm/linux/` | Linux x86_64, aarch64, riscv64 | Directly uses `kvm-ioctls` and `kvm-bindings`. |
| **HVF** | `src/hvf/` | macOS aarch64 | Bindings to Apple's Hypervisor.framework. |
| **WHP** | `src/whp/` | Windows x86_64 | Bindings to Windows Hypervisor Platform APIs. |

---

## 4. Support & Utility Crates

- **`src/display` & `src/input`**: Host display and input drivers for graphical microVMs (used by the `gpu` and `input` features).
- **`src/aws_nitro`**: AWS Nitro Enclave support and device communication.
- **`src/cpuid`**: x86_64 CPUID leaf manipulation and filtering for vCPUs.
- **`src/smbios`**: SMBIOS table generator.
- **`src/arch_gen`**: Architecture register and instruction definitions.
- **`src/polly`**: Epoll and event notification abstractions.
- **`src/utils`**: Shared utilities, byte manipulation, and terminal helpers.

---

## Feature Flags Matrix

Feature flags are controlled at the `libkrun` crate level and configured via the top-level `Makefile`:

| Feature Flag | Makefile Toggle | Crates Activated | Description |
|---|---|---|---|
| `blk` | `BLK=1` | `libkrun`, `devices` | Virtio block device (`BlockDevice`) with raw and qcow2 support. |
| `net` | `NET=1` | `libkrun`, `devices` | Virtio network device (`NetDevice`) with Unix socket support. |
| `gpu` | `GPU=1` | `libkrun`, `devices`, `display` | Virtio GPU (`GpuDevice`) via virglrenderer (Venus/native-context). |
| `input` | `INPUT=1` | `libkrun`, `devices`, `input` | Virtio input (`InputDevice`) for mouse/keyboard. |
| `vhost-user` | `VHOST_USER=1` | `libkrun`, `devices` | Vhost-user device bridge (`VhostUserDevice`, Linux only). |
| `timesync` | `TIMESYNC=1` | `libkrun`, `devices` | PTP time synchronization device. |
| `amd-sev` | `SEV=1` | `libkrun`, `devices` | AMD SEV/SEV-SNP confidential computing (produces `libkrun-sev.so`). |
| `tdx` | `TDX=1` | `libkrun`, `devices` | Intel TDX confidential computing (produces `libkrun-tdx.so`). |
| `aws-nitro` | `AWS_NITRO=1` | `libkrun`, `aws_nitro` | AWS Nitro Enclaves support (produces `libkrun-awsnitro.so`). |
| `ffi` | `FFI=1` | `libkrun`, `ffier` | Generates C ABI export bridge and JSON schemas. |
