# VM Lifecycle

In libkrun 2.0, the VM lifecycle is structured around explicit configuration objects: **Payload**, **MmioDeviceManager**, **FsOverlay**, **krun_init_blob::Config**, and **VmmBuilder**.

---

## Lifecycle Overview

1. **Payload Definition**: Configure the boot source (`load_krunfw`, `load_external`, `load_firmware`, `nitro_enclave`, `load_krunfw_tee`, ...).
2. If you are using krun-init, construct `krun_init_blob::Config` (args, env, rlimits, workdir, OCI spec) and apply it to an `FsOverlay`.
3. **Device Setup**: Populate `MmioDeviceManager` with devices (`ConsoleDevice`, `FsDevice`, `NetDevice`, `BlockDevice`, `VsockDevice`, etc.).
4. **VMM Assembly**: Configure `VmmBuilder` (vCPUs, RAM size, payload, MMIO devices, irqchip).
5. **Execution & Control**: Build `Vmm` and call `vmm.run()` (or manage via `VmmHandle`).

---

## 1. Payload

The `Payload` specifies what kernel or firmware image the VM boots into:

- **`Payload::load_krunfw()`** (C API: `krun_payload_load_krunfw`): Boots using the kernel bundled via `libkrunfw`.
- **`Payload::load_external(kernel_path, format, initrd_path, cmdline)`** (C API: `krun_payload_load_external`): Boots a kernel from a host path. `format` is a `KernelFormat` and `initrd_path` is an `Option<&str>`.
- **`Payload::load_firmware(path, cmdline)`** (C API: `krun_payload_load_firmware`): Boots UEFI firmware (e.g. OVMF / EDK2).
- **`Payload::nitro_enclave(...)`**: Boots an AWS Nitro Enclave image.

## 2. Guest Init & Filesystem Overlay

When running container or process-isolation workloads:
1. Create an `FsOverlay` (C API: `krun_fs_overlay_new()`).
2. Build a `krun_init_blob::Config` using `krun_init_blob::Builder` (or `Builder::from_oci_json()`). The C API represents it with a `KrunInitConfig` handle.
3. Call `config.apply(&mut overlay, &mut payload)` (C API: `krun_init_config_apply()`).
   - Injects the compiled `init.krun` binary into `/init.krun`.
   - Injects `.krun_config.json` containing argv, env, rlimits, mounts, etc.
   - Appends `init=/init.krun` to the kernel command line in `Payload`.
4. Attach `FsOverlay` to the root `FsDevice` (C API: `krun_fs_device_set_overlay()`).

## 3. Devices & MMIO Device Manager

Create an `MmioDeviceManager` with `MmioDeviceManager::new()` (C API: `krun_mmio_device_manager_new()`). Construct devices individually, then add them with `MmioDeviceManager::add()` (C API: `krun_mmio_device_manager_add()`):

- **Console**: `ConsoleBuilder` configures standard or multiport virtio-console streams.
- **Filesystem**: `FsDevice` exposes host directories via virtiofs with optional overlays.
- **Network**:
  - **TSI (Transparent Socket Impersonation)**: Built into `VsockDevice` with `TsiFlags::HIJACK_INET` and port forwarding.
  - **Virtio-net**: `NetDevice` connected via Unix stream or datagram socket (e.g. to `passt` or `gvproxy`).
- **Storage**: `BlockDevice` backed by raw or qcow2 disk images.
- **Acceleration & GUI**: `GpuDevice` (Venus / native context) and `InputDevice` (mouse/keyboard).
- **vhost-user**: `VhostUserDevice` for external virtio backends (RNG, RTC, GPU, Sound, CAN, Media).
- **Utilities**: `RngDevice` (virtio-rng) and `BalloonDevice` (virtio-balloon page reporting).

## 4. VMM Builder

`VmmBuilder` (C API: `krun_vmm_builder_new()`) combines all configuration components:

- `vcpus(count)`: Number of virtual CPUs.
- `ram_mib(size_mib)`: Guest physical memory size in MiB.
- `payload(payload)`: The configured boot payload.
- `devices(device_manager)`: The registered MMIO devices.
- `split_irqchip(enabled)`: Configures interrupt controller mode on x86_64.

## 5. Execution & Control

Building the `VmmBuilder` produces a `Vmm` instance:

- **Foreground Execution**: Calling `vmm.run()` (C API: `krun_vmm_run()`) starts vCPUs, enters the guest event loop, and blocks until VM termination.
- **Background Control**: Call `vmm.handle()` (C API: `krun_vmm_handle`) on the built `Vmm` before `vmm.run()` consumes it, then move the `VmmHandle` to another thread. Pause and resume are supported on macOS. Shutdown is supported on aarch64 macOS when `VmmBuilder::shutdown_support(true)` was enabled. These control methods return `FeatureDisabled` on Linux.
