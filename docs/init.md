# Guest Init Subsystem

libkrun provides guest initialization through the `init/` subsystem. In a standard container/microVM workload, the guest init runs as PID 1, mounts runtime filesystems, configures networking and environment variables, and launches the target process.

> **Note**: `krun-init` (paired with `libkrunfw`) is designed for lightweight container workloads (e.g. `crun`'s `krun` runtime). It is not used when booting full VM images with EFI firmware (such as Podman machine on macOS via `krunkit`) or when booting an external kernel with its own rootfs/initramfs.

## Subsystem Components

- **`init/init-binary`**: Guest PID 1 binary compiled statically for the target guest OS/arch.
- **`init/init-blob`**: Host-side configuration builder (`Config`), OCI spec ingestion. This embeds init binary.
- **`init/aws-nitro`**: Standalone enclave init implementation for AWS Nitro Enclaves (`AWS_NITRO=1`).

### 1. `init/init-binary` (Guest PID 1)

`init-binary` is the binary executed by the guest kernel at boot. It is statically compiled for the guest target (e.g. `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, or `x86_64-unknown-freebsd`).

At startup, `init-binary`:
1. Ensures standard I/O descriptors (stdin, stdout, stderr) are open.
2. Mounts essential pseudofilesystems (`/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm`, `/sys/fs/cgroup`).
3. If root disk remount is requested (`KRUN_BLOCK_ROOT_DEVICE` or TEE block storage), mounts the block device and pivots root.
4. Reads the configuration file (`/.krun_config.json`) exposed by the virtio-fs overlay.
5. Sets up guest networking (DHCP or TSI dummy interface).
6. Applies environment variables, hostname, resource limits (`rlimit`), and changes working directory.
7. Rewires stdio to configured virtio-console ports (`krun-stdin`, `krun-stdout`, `krun-stderr`).
8. Spawns and supervises the workload (capturing its exit code to notify the VMM via virtiofs ioctl and shutting down the VM), or directly execs as PID 1 if `KRUN_INIT_PID1=1`.

### 2. `init/init-blob` (Host Configuration & Embedding)

`init-blob` is the host-side manager and configuration builder:

- **Host Payload Ownership**: The host `init-blob` crate owns the embedded guest binary data and the serialized configuration buffer (`Config`).
- **Filesystem Overlay Injection (`Config::apply`)**: When `config.apply(&mut overlay, &mut payload)` is invoked, it writes the embedded init binary (at `/init.krun`) and the configuration file (`/.krun_config.json`) as in-memory files into `FsOverlay` (the virtio-fs overlay), and appends `init=/init.krun` to the kernel command line in `Payload`.
- **Lifetime Requirement**: Because `apply` passes borrowed memory pointers into `FsOverlay` that are read when the guest boots and executes `/init.krun`, the `Config` (or `KrunInitConfig`) instance **must remain allocated for the entire lifetime of the VM**.
- **OCI Spec Ingestion**: Provides `Builder::from_oci_json()` to convert standard container `config.json` specifications into guest initialization structures.
- **FFI Bridge**: Exports the `libkrun_init` C ABI using ffier (`ffier::library_definition!("krun_init", ...)`).

### 3. Cross-Crate Symbol Resolution

When `krun-init-blob` is consumed as a standalone shared library (`libkrun_init.so`) or built with `feature = "ffi-client"`:
- It interacts with `libkrun` without compile-time linkage by using foreign handle types (`FsOverlay`, `Payload`) from `krun-via-cdylib-weak`.
- In `Config::apply`, `init-blob` dynamically resolves required `libkrun` functions (such as `krun_fs_overlay_add_file` and `krun_payload_append_cmdline`) from the process's global symbol table (`RTLD_DEFAULT`) using `krun_via_cdylib_weak::require()`.
- Callers can also supply an explicit `dlopen` library handle via `Config::apply_in`.
- When built with `feature = "direct"` (e.g. in-tree static Rust builds), `init-blob` links directly against `krun::FsOverlay` and `krun::Payload` types without dynamic symbol lookups.

### 4. `init/init-blob-via-cdylib` (Weak Rust Client)

Provides a Rust client that dynamically loads `libkrun_init.so` at runtime. The client code is generated at build time from `init/init-blob-via-cdylib/ffier-krun_init.json` using `ffier-gen-rust-client`.

### 5. `init/aws-nitro` (AWS Nitro Enclaves Init)

> **Important**: `init/aws-nitro` is an entirely separate, standalone init implementation. It is **unrelated** to the `init-binary` / `init-blob` architecture described above.
