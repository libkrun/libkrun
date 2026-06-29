# AGENTS.md

This file provides guidance to Agents when working with code in this repository.

## What this project is

**libkrun** is a Rust dynamic library that provides virtualization-based process isolation via KVM (Linux) and HVF (macOS). It exposes a C API (`include/libkrun.h`) that lets callers run a process inside a lightweight VM with configurable vCPUs, RAM, virtio devices, and an embedded init binary.

## Build commands

All builds go through the Makefile, which handles feature flags, platform detection, and sysroot management for cross-compilation. Direct `cargo build` skips that plumbing.

```bash
# Release build (minimal — no optional devices)
make

# Release build with common optional devices
make BLK=1 NET=1 GPU=1 INPUT=1

# Debug build
make debug

# TEE variants (mutually exclusive with each other and GPU/INPUT)
make SEV=1        # AMD SEV — produces libkrun-sev.so
make TDX=1        # Intel TDX — produces libkrun-tdx.so

# Other optional features
make VHOST_USER=1
make VIRGL_RESOURCE_MAP2=1

# Install to /usr/local (or PREFIX=...)
make install
make PREFIX=$HOME/.local install
```

On macOS the Makefile exports `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER` and `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS` to configure clang+lld as the cross-linker for musl targets.

## Lint and format

Clippy is run with `-D warnings` — zero warnings are allowed. The CI checks several feature combinations; you should too when touching device or feature-gated code:

```bash
# Required before every PR — same as CI
cargo clippy --locked -- -D warnings
cargo clippy --locked --features amd-sev -- -D warnings
cargo clippy --locked --features tdx -- -D warnings
cargo clippy --locked --features net,blk,gpu,input -- -D warnings

# Format check
cargo fmt -- --check
```

## Tests

```bash
# Unit tests (requires init/init to exist and KVM access on Linux)
touch init/init
cargo test

# Integration tests (builds and installs the library first)
make test
make test TEST=test_name       # run a single integration test
make test BLK=1                # integration tests with blk feature
```

Integration tests live in `tests/` as a separate Cargo workspace. They require the library to be installed to a local prefix (`test-prefix/`) which `make test` handles automatically.

## Crate architecture

The workspace (`Cargo.toml`) contains these crates under `src/`:

| Crate | Role |
|---|---|
| **libkrun** | C API surface. Manages `KrunContext` instances (one per VM), translates API calls into VMM configuration, and drives startup via `krun_start_enter()`. |
| **vmm** (krun-vmm) | VMM core: builds and runs the VM, owns the vCPU threads, wires devices to memory and IRQs. |
| **devices** (krun-devices) | All virtio device implementations: console, block, fs (virtiofs passthrough + read-only wrapper), net, gpu, sound, input, vsock. |
| **arch** (krun-arch) | Platform-specific VM setup: GDT/IDT (x86_64), FDT (aarch64/riscv), boot protocol. |
| **kernel** | Loads the kernel image and sets up the boot parameters passed to the VMM. |
| **hvf** | macOS HVF hypervisor bindings (Linux uses kvm-ioctls directly in vmm). |
| **cpuid** | x86_64 CPUID leaf manipulation for vCPU feature exposure. |
| **rutabaga_gfx** | Wraps virglrenderer for virtio-gpu. |
| **display** / **input** | Host-side display and input backends (used by the gpu feature). |
| **utils**, **polly**, **smbios**, **arch_gen** | Shared utilities, event loop, SMBIOS table generation, architecture codegen. |
| **aws_nitro** | AWS Nitro Enclave support. |

### How a VM starts

1. Caller invokes `krun_create_ctx()` → allocates a `KrunContext`
2. Caller configures it (vCPUs, RAM, disks, network, exec path, etc.)
3. `krun_start_enter()` calls into **vmm**, which:
   - Loads the kernel via **kernel**
   - Instantiates virtio devices from **devices**
   - Starts vCPU threads (KVM ioctls on Linux, HVF on macOS)
   - The guest boots, the init binary runs as PID 1, reads `.krun_config.json` from the virtiofs overlay, and execs the workload

### The init binary (`init/`)

The guest PID-1 is a statically-linked Rust binary (`init/src/main.rs`). It is built by `src/init_blob/build.rs` as a separate cargo invocation targeting musl. The compiled binary is embedded into the `init_blob` crate via `include_bytes!` and exposed by the passthrough fs backend as a virtual read-only file named `init.krun`.

AWS Nitro uses a separate C init (`init/aws-nitro/`) built by the Makefile when `AWS_NITRO=1`.

### Feature flags

Features are additive and controlled at the `libkrun` crate level. Each device feature (`blk`, `net`, `gpu`, `input`) enables the corresponding code in both `devices` and `vmm`. The TEE variants (`amd-sev`, `tdx`) imply `blk` + `tee` and affect the soname of the output library.

## Pull Request expectations
- New tests are added when necessary.
- Documentation is added or updated when necessary.
- Linting and formatting has been done.
- All of the tests pass.
- The commit structure follows what's described in [Commit structure](### Commit structure).

## Code Quality

### Commit structure

- Format: `<subsystem>: <title>` — e.g., `virtio/blk: add print_text() function`
- Commits must be self-contained, compile, and pass tests independently
- Sign all commits with `git commit -s` (DCO requirement)
- Agent attribution format: `Assisted-by: <Agent-tool>: <model-name>` - e.g., `Assisted-by: Claude Code: sonnet-4.6`, `Assisted-by: Cursor: codex-5.3`. Do not use `Co-authored-by`.
- Commit messages should be concise and written in the imperative mood. Small, focused commits are preferred.

### Rust coding style
- Code must be self-explanatory and the main source of reference. Do not write comments unless the code is counter-intuitive and cannot be clarified through better naming or structure. When a comment is necessary, it must explain *why*, never *what*.
- No error handling for impossible scenarios.
- Avoid checking for empty input when calling a function if the function already handles the base case well (e.g. empty input is noop).
- Use `use` imports instead of inline full paths. One level of qualitifation is fine when it clarifies what something is (e.g., `log::trace!`, `fs::read_to_string()`), but don't use longer paths like `std::process::Command::new(...)` or `crate::foo::bar::baz()` -- import with `use` instead.

## Platform support

### Host platforms (where libkrun runs as a library)

- **Linux x86_64 / aarch64**: primary targets, full feature support (KVM)
- **Linux riscv64**: experimental (KVM)
- **macOS aarch64**: supported (HVF), GPU works

### Guest platforms (what runs inside the VM)

The guest ISA always matches the host ISA — KVM and HVF use hardware virtualization, not emulation.

- **Linux** (x86_64, aarch64, riscv64): primary guest OS; the default init binary (`init/init.c`) is Linux-specific
- **FreeBSD** (same arch as host): experimental; requires building the FreeBSD init with `make BUILD_BSD_INIT=1`
