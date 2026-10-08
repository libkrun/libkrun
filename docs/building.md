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

### Optional Build Features

- `BLK=1`: Enables virtio-block support (`BlockDevice`).
- `NET=1`: Enables virtio-net support (`NetDevice`).
- `GPU=1`: Enables virtio-gpu support (`GpuDevice`). Requires virglrenderer development libraries.
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
# Install to a user-owned prefix
make BLK=1 NET=1
make BLK=1 NET=1 PREFIX="$HOME/.local" install

# System-wide install
make BLK=1 NET=1
sudo make BLK=1 NET=1 install
```

`make install` does not build the libraries. Build with the same feature options before installing.

---

## Linux (AMD SEV & Intel TDX Variants)

The confidential computing variants produce standalone libraries (`libkrun-sev.so` and `libkrun-tdx.so`) with distinct sonames.

### Requirements

- The corresponding variant of [libkrunfw](https://github.com/containers/libkrunfw) (`libkrunfw-sev.so` or `libkrunfw-tdx.so`).
- Rust toolchain with musl target.

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

> **Note**: The legacy qboot firmware path supports only 1 vCPU and up to 3072 MiB of memory. Use TD-Shim (for example, `launch-tee --td-shim PATH`) for guests with multiple vCPUs or more memory.

---

## macOS (Apple Silicon / aarch64)

### Prerequisites

- macOS 14 (Sonoma) or newer.
- Working Rust toolchain (`aarch64-apple-darwin`).
- Linux guest init target: `rustup target add aarch64-unknown-linux-musl`.
- `libkrunfw` for running guests (see [the macOS test setup](../tests/README.md#running-on-macos)).
- Homebrew packages:
  ```bash
  brew install lld xz
  ```

### Compiling & Installing

```bash
# Build libkrun on macOS (the Linux guest init is cross-compiled automatically via clang+lld)
make BLK=1 NET=1

make BLK=1 NET=1 PREFIX="$HOME/.local" install
```

---

## Cross-Compiling FreeBSD Init

To build with FreeBSD guest support:

```bash
# Linux / macOS
make BUILD_BSD_INIT=1 -- init/init-binary/init-freebsd
```

This automatically downloads the FreeBSD sysroot base and builds the FreeBSD static init binary using clang and lld.
Install the FreeBSD Rust target first on x86_64, or the nightly toolchain with `rust-src` on aarch64, as described in [the FreeBSD test prerequisites](../tests/README.md#freebsd-guest-tests).
