# Building and Installing libkrun

All builds go through the top-level `Makefile`, which handles feature flag configuration, platform detection, and cross-compilation toolchains.

---

## Linux

### Prerequisites

- [libkrunfw](https://github.com/containers/libkrunfw)
- A working [Rust](https://www.rust-lang.org/) toolchain with the musl cross-target for the guest init binary:
  ```bash
  rustup target add x86_64-unknown-linux-musl   # on x86_64
  rustup target add aarch64-unknown-linux-musl  # on aarch64
  ```
- `patchelf`

### Optional Build Features

- `BLK=1`: Enables virtio-block support (`BlockDevice`).
- `NET=1`: Enables virtio-net support (`NetDevice`).
- `GPU=1`: Enables virtio-gpu support (`GpuDevice`). Requires `virglrenderer-devel`.
- `INPUT=1`: Enables virtio-input support (`InputDevice`).
- `VHOST_USER=1`: Enables vhost-user device bridge support (`VhostUserDevice`).
- `TIMESYNC=1`: Enables PTP time synchronization device support.

### Compiling

```bash
# Minimal build (no optional devices)
make

# Build with common optional features
make BLK=1 NET=1 GPU=1 INPUT=1

# Debug build
make debug
```

### Installing

```bash
sudo make [FEATURE_OPTIONS] install

# Custom install prefix (e.g. $HOME/.local)
make PREFIX=$HOME/.local install
```

---

## Linux (AMD SEV & Intel TDX Variants)

The confidential computing variants produce standalone libraries (`libkrun-sev.so` and `libkrun-tdx.so`) with distinct sonames.

### Requirements

- The corresponding variant of [libkrunfw](https://github.com/containers/libkrunfw) (`libkrunfw-sev.so` or `libkrunfw-tdx.so`).
- Rust toolchain with musl target.
- OpenSSL development headers (`openssl-devel` on Fedora, `libssl-dev` on Debian/Ubuntu).
- `patchelf`

### Compiling & Installing AMD SEV

```bash
make SEV=1
sudo make SEV=1 install
```

### Compiling & Installing Intel TDX

```bash
make TDX=1
sudo make TDX=1 install
```

> **Note**: The TDX variant currently supports guests with 1 vCPU and memory up to 3072 MiB.

---

## macOS (Apple Silicon / aarch64)

### Prerequisites

- macOS 14 (Sonoma) or newer.
- Working Rust toolchain (`aarch64-apple-darwin`).
- Homebrew packages:
  ```bash
  brew install lld xz
  ```

### Compiling & Installing

```bash
# Build libkrun on macOS (the Linux guest init is cross-compiled automatically via clang+lld)
make [FEATURE_OPTIONS]

sudo make [FEATURE_OPTIONS] install
```

---

## Cross-Compiling FreeBSD Init

To build with FreeBSD guest support:

```bash
# Linux / macOS
make BUILD_BSD_INIT=1 -- init/init-binary/init-freebsd
```

This automatically downloads the FreeBSD sysroot base and builds the FreeBSD static init binary using clang and lld.
