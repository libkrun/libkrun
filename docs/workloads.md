# Common Workload Models & Use Cases

Over time, `libkrun`'s scope has grown from a specialized container isolation library into a versatile microVM engine supporting diverse virtualization workloads. With the 2.0 architecture, `libkrun` is designed to be fully modular, replacing monolithic VM context setup with explicit, composable primitives (`Payload`, `MmioDeviceManager`, `FsOverlay`, `InitConfig`, and individual virtio device models).

This allows callers to combine and configure components independently. This document describes the primary use-case patterns and downstream consumers that `libkrun` actively supports. This list is **non-exhaustive** — these building blocks can be mixed and matched to suit new or custom virtualization workloads.

---

## Container Process Isolation (`crun` / Podman `krun` runtime)

Provides virtualization-based isolation for standard OCI container workloads (e.g. running containers via `podman --runtime=krun`, `crun --krun`, or OCI annotations) with sub-millisecond startup times.

- **Boot Source**: `Payload::load_krunfw()` (bundled Linux kernel provided by `libkrunfw`).
- **Guest PID 1**: Statically-linked guest binary (`init/init-binary`) embedded directly in the host crate `krun-init-blob`.
- **Configuration**: Guest parameters (argv, environment, working directory, rlimits, mounts) constructed using `krun_init_blob::Builder` or parsed directly from OCI `config.json` via `Builder::from_oci_json()`.
- **Filesystem**: Root filesystem mapped via `FsDevice` (virtiofs) with in-memory injection of the init binary (`/init.krun`) and configuration (`/.krun_config.json`) via `FsOverlay`.
- **Networking**: Transparent Socket Impersonation (TSI) via `VsockDevice` (zero-configuration host network sharing) or virtual network interface via `NetDevice` paired with `passt` or `gvproxy`.
- **Consumers**: Podman / [`crun --krun`](https://github.com/containers/crun/blob/main/krun.1.md), `examples/chroot_vm.c`.

---

## UEFI Virtual Machines (`krunkit` / macOS Podman Machine)

Boots standard operating system disk images (e.g. Fedora CoreOS, Ubuntu, Debian) using UEFI firmware.

- **Boot Source**: `Payload::load_firmware()` / `krun_payload_load_efi` (UEFI firmware binary, such as OVMF or EDK2).
- **Guest Operating System**: Standard guest OS kernel, initrd, and init system (e.g. `systemd`) loaded directly from the disk image by EFI firmware. Neither `krun-init` nor `libkrunfw` are involved in this model.
- **Storage**: Primary OS disk attached via `BlockDevice` (raw or qcow2 format).
- **Networking**: Virtual network interface via `NetDevice` (typically connected to `gvproxy` on macOS).
- **Consumers**: [`krunkit`](https://github.com/containers/krunkit) (used by Podman machine on macOS for GPU-enabled VM virtualization).

---

## Direct Kernel Boot (External Kernel & Initramfs)

Boots user-provided host kernel binaries and optional initramfs images directly, without using `libkrunfw`.

- **Boot Source**: `Payload::load_external(kernel_path, format, initrd_path, cmdline)` / `krun_payload_load_external`.
- **Supported Formats**: Uncompressed ELF (`KernelFormat::Elf`), PE/bzImage (`KernelFormat::Pe`), or raw binary (Linux and FreeBSD kernels).
- **Container Runtimes (`crun`)**: `crun` supports booting custom guest kernels via OCI annotations (`run.oci.krun.kernel_path` and `run.oci.krun.initrd_path`).
- **FreeBSD Workloads**: Used by projects like `anylinuxfs` to boot upstream FreeBSD kernel images.
- **Consumers**: `crun` custom kernel workloads, `anylinuxfs`, FreeBSD integration tests, `examples/external_kernel.c`.

---

## Confidential Computing (AMD SEV & Intel TDX)

Runs microVMs with hardware-encrypted memory isolated from the host and hypervisor using AMD SEV or Intel TDX.

- **Boot Source**: `Payload::load_krunfw_tee(tee_config_path, firmware_path)` paired with `libkrunfw-sev.so` or `libkrunfw-tdx.so`.
- **Build Variants**:
  - `make SEV=1` produces `libkrun-sev.so` for AMD SEV.
  - `make TDX=1` produces `libkrun-tdx.so` for Intel TDX.
- **TEE Configuration**: A JSON file supplying hardware TEE parameters (CPU generation, platform data, and optional Key Broker Service / KBS attestation endpoint).
- **Storage**: Encrypted root and data disk images attached via `BlockDevice`.
- **Consumers**: Confidential containers in `crun`, `examples/launch-tee.c`.

---

## AWS Nitro Enclaves

AWS Nitro Enclaves do not allow virtual devices to be controlled by the VMM (there is no virtio-net, virtio-block, or virtio-fs). The only available interface is the provided built-in vsock device. Because the architecture is so different, this uses a completely separate init implementation.

- **Boot Source**: `Payload::nitro_enclave(config)` compiled with `make AWS_NITRO=1` (produces `libkrun-awsnitro.so`).
- **Guest PID 1**: Dedicated enclave init located in `init/aws-nitro/` (separate from the standard `init-binary` / `init-blob` workflow).
- **Communication**: Interacts with the parent EC2 host exclusively over `AF_VSOCK`.
- **Consumers**: `krun` / `podman` Nitro Enclave workloads, `examples/nitro.c`.

---

## 4K-Page Workloads & Wayland GPU Passthrough (`muvm`)

The Linux kernel does not support mixed page sizes within a single kernel instance. On 16 KiB-page hosts (such as Apple Silicon running Asahi Linux), x86 emulators like **FEX-Emu** cannot run binaries that require 4 KiB memory page semantics.

`libkrun` solves this by running a 4 KiB-page guest Linux kernel inside a lightweight microVM where FEX-Emu executes, while providing hardware-accelerated graphics:

- **Graphics & Display**: `GpuDevice` provides 3D acceleration via virglrenderer (DRM native-context) paired with host Wayland socket forwarding (e.g. via `sommelier`).
- **Filesystem**: Host filesystem shared into the guest via `FsDevice` (virtiofs).
- **Consumers**: [`muvm`](https://github.com/AsahiLinux/muvm).

---

## Embedded GUI MicroVMs (Display & Input Backends)

`libkrun` does not depend on any specific GUI toolkit. Instead, it exposes low-level display scanout and input event interfaces, allowing embedders to integrate graphical microVMs into their own UI frameworks or window managers. This can run in-process or out-of-process (where the embedder provides their own IPC mechanism to transport scanout buffers and input events).

- **Display**: `DisplayBackend` is a low-level callback interface that receives raw guest framebuffer scanouts, EDID configuration, and display mode changes.
- **Input**: `InputDevice` accepts input events either directly from host evdev descriptors (`InputDevice::new_from_fd`) or via custom event provider callbacks fed by the host UI event loop.
- **Examples**: `examples/gui_vm` demonstrates in-process GTK4 embedding using the unstable helper crate in `examples/krun_gtk_display`.
