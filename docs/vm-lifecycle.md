# VM Lifecycle

In libkrun 2.0, the VM lifecycle is structured around explicit configuration objects: **Payload**, **DeviceManager**, **FsOverlay**, **InitConfig**, and **VmmBuilder**.

---

## Lifecycle Overview

1. **Payload Definition**: Configure boot source (`kernel_bundle`, `external_kernel`, `efi`, `nitro_enclave`, `load_krunfw_tee`, ...).
2. If you are using krun-init construct `InitConfig` (args, env, rlimits, workdir, OCI spec) and apply to an `FsOverlay`.
3. **Device Setup**: Populate `MmioDeviceManager` with devices (`ConsoleDevice`, `FsDevice`, `NetDevice`, `BlockDevice`, `VsockDevice`, etc.).
4. **VMM Assembly**: Configure `VmmBuilder` (vCPUs, RAM size, payload, MMIO devices, irqchip).
5. **Execution & Control**: Build `Vmm` and call `vmm.run()` (or manage via `VmmHandle`).

---

## 1. Payload

The `Payload` specifies what kernel or firmware image the VM boots into:

- **`Payload::kernel_bundle()`** (C: `krun_payload_load_krunfw`): Boots using the embedded kernel bundled via `libkrunfw`.
- **`Payload::external_kernel(format, kernel_path, initramfs_path)`** (C: `krun_payload_load_external`): Boots an uncompressed ELF or PE kernel from a specified host path with an optional initramfs.
- **`Payload::efi(firmware_path)`** (C: `krun_payload_load_efi`): Boots UEFI firmware (e.g. OVMF / EDK2).
- **`Payload::nitro_enclave(...)`**: Boots an AWS Nitro Enclave image.

## 2. Guest Init & Filesystem Overlay

When running container or process-isolation workloads:
1. Create an `FsOverlay` (C: `krun_fs_overlay_new()`).
2. Build an `InitConfig` using `krun_init_blob::Builder` (or `from_oci_json()`).
3. Call `config.apply(&mut overlay, &mut payload)` (C: `krun_init_config_apply()`).
   - Injects the compiled `init.krun` binary into `/init.krun`.
   - Injects `.krun_config.json` containing argv, env, rlimits, mounts, etc.
   - Appends `init=/init.krun` to the kernel command line in `Payload`.
4. Attach `FsOverlay` to the root `FsDevice` (C: `krun_fs_device_set_overlay()`).

## 3. Devices & MMIO Device Manager

Devices are constructed individually and registered into an `MmioDeviceManager` (C: `krun_mmio_device_manager_new()`):

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

`VmmBuilder` (C: `krun_vmm_builder_new()`) combines all configuration components:

- `vcpus(count)`: Number of virtual CPUs.
- `ram_mib(size_mib)`: Guest physical memory size in MiB.
- `payload(payload)`: The configured boot payload.
- `devices(device_manager)`: The registered MMIO devices.
- `split_irqchip(enabled)`: Configures interrupt controller mode on x86_64.

## 5. Execution & Control

Building the `VmmBuilder` produces a `Vmm` instance:

- **Foreground Execution**: Calling `vmm.run()` (C: `krun_vmm_run()`) starts vCPUs, enters the guest event loop, and blocks until VM termination.
- **Background Control**: `vmm.build_with_handle()` (or `vmm.handle()`) produces a `VmmHandle` (C: `krun_vmm_handle`) that allows pausing, resuming, or shutting down the VM from another thread.
