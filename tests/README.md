# End-to-end tests
The testing framework here allows you to write code to configure libkrun (using the public API) and run some specific code in the guest.

## Running the tests:
The tests can be run using `make test` (from the main libkrun directory).
You can also run `./run.sh` inside the `tests` directory. When using the `./run.sh` script you probably want specify the `PKG_CONFIG_PATH` environment variable, otherwise you will be testing the system wide installation of libkrun.

## Running on macOS

### Prerequisites

1. Install required build tools:
   ```bash
   brew install lld xz
   rustup target add aarch64-unknown-linux-musl
   ```

2. Install libkrunfw - either via homebrew:
   ```bash
   brew install libkrunfw
   ```

   Or build from source:
   ```bash
   curl -LO https://github.com/containers/libkrunfw/releases/download/v5.2.0/libkrunfw-prebuilt-aarch64.tgz
   tar -xzf libkrunfw-prebuilt-aarch64.tgz
   cd libkrunfw
   make
   sudo make install
   ```

   If installed from source, add `/usr/local/lib` to your library path:
   ```bash
   export DYLD_LIBRARY_PATH="/usr/local/lib:${DYLD_LIBRARY_PATH}"
   ```

   The test harness automatically handles the library path for homebrew installations.

### Running tests

```bash
make test
```

## Adding tests
To add a test you need to add a new rust module in the `test_cases` directory, implement the  required host and guest side methods (see existing tests) and register the test in the `test_cases/src/lib.rs` to be ran.

## FreeBSD guest tests

FreeBSD guest tests run on Linux (amd64, arm64) and macOS (arm64) hosts. They require two external assets that are not bundled in the repository.

### Prerequisites

1. Install required tools:
   - **macOS**: `bsdtar` is built-in (`/usr/bin/bsdtar`)
   - **Linux**: `sudo apt-get install libarchive-tools` (provides `bsdtar`)
   - **Linux/macOS amd64**: add the Rust cross-compilation target:
     ```bash
     rustup target add x86_64-unknown-freebsd
     ```
   - **Linux/macOS arm64**: `aarch64-unknown-freebsd` has no prebuilt stdlib in rustup,
     so a nightly toolchain with rust-src component is needed:
     ```bash
     rustup +nightly-2026-01-25 component add rust-src
     ```

2. Build the FreeBSD sysroot and `init-freebsd` (from the libkrun root directory):
   ```bash
   make BUILD_BSD_INIT=1 -- init/init-binary/init-freebsd
   ```
   This downloads `freebsd-sysroot/base.txz`, extracts it to `freebsd-sysroot/`, and compiles `init/init-binary/init-freebsd`.

3. The FreeBSD kernel is downloaded and cached automatically by `run.sh` (from
   `download.freebsd.org`). To use a locally-provided kernel instead, set
   `KRUN_TEST_FREEBSD_KERNEL_PATH` before running:
   ```bash
   export KRUN_TEST_FREEBSD_KERNEL_PATH="/path/to/boot/kernel/kernel"      # amd64
   export KRUN_TEST_FREEBSD_KERNEL_PATH="/path/to/boot/kernel/kernel.bin"  # arm64
   ```

### Running FreeBSD tests

With the sysroot/init assets built, `run.sh` (or `make test`) will automatically:
- Download and cache `target/freebsd-kernel/boot/kernel/kernel[.bin]` if not already present
- Cross-compile the `guest-agent` for FreeBSD
- Build `target/freebsd-test-rootfs.iso` from `init-freebsd` + the FreeBSD `guest-agent`
- Set `KRUN_TEST_FREEBSD_KERNEL_PATH` and `KRUN_TEST_FREEBSD_ISO_PATH` for the runner

FreeBSD tests are **skipped** (not failed) when the kernel or ISO are unavailable, so the test suite still passes without FreeBSD assets.
