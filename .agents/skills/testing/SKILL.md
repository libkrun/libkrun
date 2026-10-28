---
name: testing
description: Run unit tests, integration tests, and FreeBSD guest tests for libkrun, or check CI test feature matrix. Use when running tests, executing make test or cargo test, or verifying test suites.
---

# Testing libkrun

## Unit tests

Unit tests run directly via `cargo test`. Some VMM tests on Linux require read/write access to `/dev/kvm`.

```bash
cargo test
```

If `/dev/kvm` is unavailable, `cargo test -p krun-kernel` runs the kernel crate's unit tests without exercising the VMM tests.

## Integration tests

Integration tests live in `tests/` as a separate Cargo workspace. By default, `make test` builds the FFI libraries, installs them to `test-prefix/`, and runs the dynamically linked tests. Pass `FFI=0` to run the statically linked tests without installing libkrun. A custom `libkrunfw` installed in `test-prefix/` remains available to either mode.

Running guest tests requires host hypervisor access (KVM on Linux or HVF on macOS) and `libkrunfw`. Some cases also need tools such as `passt`, `gvproxy`, and container tooling; see the [CI setup](../../../.github/workflows/integration_tests.yml) for the full environment.

```bash
# Run all integration tests
make test

# Run the statically linked integration tests
make test FFI=0

# Run a single integration test
make test TEST=net-gvproxy

# Glob / wildcard matching
make test TEST="net-*"

# Comma-separated list of tests
make test TEST="net-gvproxy,pjdfstest"

# Run tests with optional features enabled
make test BLK=1

# Build and test against custom libkrunfw from source
make test LIBKRUNFW_SRC=/path/to/libkrunfw
```

## FreeBSD guest tests

FreeBSD guest tests require building the FreeBSD init and sysroot first. They are automatically skipped if `init-freebsd` or the FreeBSD sysroot are not present.

```bash
# Build FreeBSD init and sysroot
make BUILD_BSD_INIT=1

# Run FreeBSD guest tests
make test TEST="freebsd-*"
```

## CI Feature Matrix

The CI runs the following test and lint matrix across platforms. Every clippy
command uses `-D warnings`, matching the workflows. Build the local library
with `make test-prefix NET=1 BLK=1 FFI=1` before running the Linux test-crate
clippy commands that use `test-prefix/`.

### Linux (x86_64)
- **Unit tests:** `cargo test` (requires KVM access)
- **Clippy:**
  - Default: `cargo clippy --locked -- -D warnings`
  - AMD SEV: `cargo clippy --locked --features amd-sev -- -D warnings`
  - Intel TDX: `cargo clippy --locked --features tdx -- -D warnings`
  - Devices: `cargo clippy --locked --features net,blk,gpu,input -- -D warnings`
  - AWS Nitro: `cargo clippy --locked --features aws-nitro,net -- -D warnings`
- **Integration tests:** `make test FFI=0 NET=1 BLK=1` and `make test FFI=1 NET=1 BLK=1` (include FreeBSD guest tests when their prerequisites are present)
- **Test crate clippy:**
  - From `tests/`: `cargo clippy --locked -p test_cases --features guest -- -D warnings`
  - From `tests/`, with the test prefix environment: `PKG_CONFIG_PATH="$(realpath ../test-prefix/lib64/pkgconfig/)" LD_LIBRARY_PATH="$(realpath ../test-prefix/lib64/)" cargo clippy --locked -p test_cases --features dynamic-linking -- -D warnings`
  - From `tests/`, with the test prefix environment: `PKG_CONFIG_PATH="$(realpath ../test-prefix/lib64/pkgconfig/)" LD_LIBRARY_PATH="$(realpath ../test-prefix/lib64/)" cargo clippy --locked -p runner -- -D warnings`
  - From `tests/`: `cargo clippy --locked --target x86_64-unknown-linux-musl -p guest-agent -- -D warnings`
- **Examples clippy:** From `examples/`, after installing libkrun with `GPU=1 NET=1 INPUT=1`, run `PKG_CONFIG_PATH="$HOME/libkrun-prefix/lib64/pkgconfig:$PKG_CONFIG_PATH" LD_LIBRARY_PATH="$HOME/libkrun-prefix/lib64:$LD_LIBRARY_PATH" cargo clippy --locked -- -D warnings`
- **Bindings verification:** Install `ffier-gen-c-header` as described in [the bindings guide](../../../docs/bindings-generation.md), run `make gen-libkrun-bindings` and `make gen-init-blob-bindings`, then verify `git diff --exit-code bindings/ include/`

### Linux (aarch64)
- **Unit tests:** `cargo test`
- **Clippy:**
  - Default: `cargo clippy --locked -- -D warnings`
  - Devices: `cargo clippy --locked --features net,blk,gpu,input -- -D warnings`
- **Integration tests:** `make test FFI=0 NET=1 BLK=1` and `make test FFI=1 NET=1 BLK=1` (include FreeBSD guest tests when their prerequisites are present)
- **Test crate clippy:**
  - From `tests/`: `cargo clippy --locked -p test_cases --features guest -- -D warnings`
  - From `tests/`, with the test prefix environment: `PKG_CONFIG_PATH="$(realpath ../test-prefix/lib64/pkgconfig/)" LD_LIBRARY_PATH="$(realpath ../test-prefix/lib64/)" cargo clippy --locked -p test_cases --features dynamic-linking -- -D warnings`
  - From `tests/`, with the test prefix environment: `PKG_CONFIG_PATH="$(realpath ../test-prefix/lib64/pkgconfig/)" LD_LIBRARY_PATH="$(realpath ../test-prefix/lib64/)" cargo clippy --locked -p runner -- -D warnings`
  - From `tests/`: `cargo clippy --locked --target aarch64-unknown-linux-musl -p guest-agent -- -D warnings`
- **Examples clippy:** From `examples/`, after installing libkrun with `GPU=1 NET=1 INPUT=1`, run `PKG_CONFIG_PATH="$HOME/libkrun-prefix/lib64/pkgconfig:$PKG_CONFIG_PATH" LD_LIBRARY_PATH="$HOME/libkrun-prefix/lib64:$LD_LIBRARY_PATH" cargo clippy --locked -- -D warnings`

### macOS (aarch64)
- **Clippy:** `cargo clippy --locked --features gpu -- -D warnings`
- **Cross-compilation build:** `make` (Linux init) and `make BUILD_BSD_INIT=1` (FreeBSD init)
