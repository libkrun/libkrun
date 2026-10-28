# End-to-end tests
The testing framework here allows you to write code to configure libkrun (using the public API) and run some specific code in the guest.

## Running the tests:
The tests can be run using `make test` (from the main libkrun directory).
You can also run `./run.sh` inside the `tests` directory. It uses static linking by default. To test the shared libraries directly on Linux, build the local prefix and set the library paths from inside `tests/`:

```bash
make test-prefix                 # from the repository root
cd tests
KRUN_TEST_FFI=1 \
  PKG_CONFIG_PATH="$(realpath ../test-prefix/lib64/pkgconfig)" \
  LIBKRUN_LIB_PATH="$(realpath ../test-prefix/lib64)" \
  ./run.sh test
```

## Running on macOS

### Prerequisites

1. Install required build tools:
   ```bash
   brew install lld xz
   rustup target add aarch64-unknown-linux-musl
   ```

2. Install libkrunfw from the [libkrun Homebrew tap](https://github.com/libkrun/homebrew-krun):
   ```bash
   brew tap libkrun/krun
   brew trust libkrun/krun
   brew install libkrunfw
   ```

   For a source build, follow the [libkrunfw macOS instructions](https://github.com/libkrun/libkrunfw#macos), then run `make test LIBKRUNFW_SRC=/path/to/libkrunfw` to install that firmware into `test-prefix/` for the tests.

   `make test` includes the Homebrew libkrunfw path automatically.

### Running tests

```bash
make test
```

## Adding tests
To add a test, add a Rust module under `tests/test_cases/src/`, implement the required host and guest methods (see existing tests), and register it in `tests/test_cases/src/lib.rs`.

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
   a Firecracker-optimized release on x86_64 or `download.freebsd.org` on aarch64). To use a locally provided kernel instead, set
   `KRUN_TEST_FREEBSD_KERNEL_PATH` before running:
   ```bash
   export KRUN_TEST_FREEBSD_KERNEL_PATH="/path/to/boot/kernel/kernel"      # amd64
   export KRUN_TEST_FREEBSD_KERNEL_PATH="/path/to/boot/kernel/kernel.bin"  # arm64
   ```

### Running FreeBSD tests

With the sysroot/init assets built, `run.sh` (or `make test`) will automatically:
- Cache the x86_64 kernel at `target/freebsd-kernel/freebsd-kern.bin` or the aarch64 kernel at `target/freebsd-kernel/boot/kernel/kernel.bin`
- Cross-compile the `guest-agent` for FreeBSD
- Build `target/freebsd-test-rootfs.iso` from `init-freebsd` + the FreeBSD `guest-agent`
- Set `KRUN_TEST_FREEBSD_KERNEL_PATH` and `KRUN_TEST_FREEBSD_ISO_PATH` for the runner

FreeBSD tests are **skipped** (not failed) when the kernel or ISO are unavailable, so the test suite still passes without FreeBSD assets.
