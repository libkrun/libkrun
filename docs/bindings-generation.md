# Bindings Generation (ffier)

libkrun uses [ffier](https://github.com/mtjhrc/ffier) to generate its C ABI surface and weak dynamic-linking Rust clients directly from Rust source annotations.

---

## Architecture

libkrun exposes two distinct FFI libraries:

1. **`libkrun`** (`krun`): VMM builder, device management, payload loading, execution control.
2. **`libkrun_init`** (`krun_init`): Guest init configuration builder, OCI conversion, and overlay injection.

Building with `--features ffi` generates machine-readable JSON schemas in `target/ffier-<lib>.json`. The schemas are checked in and used by `ffier-gen-c-header` to generate C headers (`include/`) and by `ffier-gen-rust-client` (invoked by dependent crate `build.rs` scripts) to generate dynamic Rust clients in Cargo's `OUT_DIR`.

### 1. The `libkrun` Bridge

- **Declaration**: `src/libkrun/src/api/mod.rs` registers exported types via `ffier::library_definition!("krun", ...)` and `src/libkrun/src/lib.rs` invokes `ffier::generate_bridge!`.
- **Schema**: `src/libkrun-via-cdylib-weak/ffier-krun.json`.
- **C Header**: `include/libkrun.h`.
- **Rust Client**: `src/libkrun-via-cdylib-weak/build.rs` reads the schema and generates a runtime dynamically-loading client into Cargo's `OUT_DIR`.

### 2. The `init-blob` Bridge

- **Declaration**: `init/init-blob/src/lib.rs` registers types via `ffier::library_definition!("krun_init", ...)` and invokes `ffier::generate_bridge!`.
- **Schema**: `init/init-blob-via-cdylib/ffier-krun_init.json`.
- **C Header**: `include/libkrun_init.h`.
- **Rust Client**: `init/init-blob-via-cdylib/build.rs` generates client code into `OUT_DIR`.

---

## Rust Integration & Linking Modes

Rust applications can consume `libkrun` and `krun-init-blob` in two ways:

1. **Direct Static Linking (In-Process Rust Crates)**:
   - Depend directly on the `krun` crate.
   - Depend on `krun-init-blob` with `features = ["direct"]` for compile-time type integration with `krun::FsOverlay` and `krun::Payload`.
   - Zero FFI overhead and full compiler type safety.

2. **Dynamic / Weak FFI Linking (Shared Library)**:
   - Generated Rust client crates (`krun-via-cdylib-weak` and `krun-init-blob-via-cdylib`) dynamically load symbols from `libkrun.so` / `libkrun_init.so` at runtime using `dlsym`.
   - Enables consuming libkrun without link-time dependencies on the library.

### The `FFI=1` Build Toggle

- `make FFI=1` builds `libkrun` with `--features ffi`, compiling the C ABI export bridge into `libkrun.so` / `libkrun.dylib`.
- Integration tests use `make test FFI=1` to build the dynamic libraries and run test suites with `features = ["dynamic-linking"]`.

---

## The `ffi` Feature Flag

Binding generation and C ABI export are gated behind the `ffi` feature:

- **`libkrun`**: Building with `--features ffi` (or `make FFI=1`) compiles the C ABI bridge symbols into `libkrun.so` / `libkrun.dylib` and generates `target/ffier-krun.json`.
- **`krun-init-blob`**: Building with `--features ffi` compiles `libkrun_init.so` and generates `target/ffier-krun_init.json`.

---

## Prerequisites

Install the `ffier-gen-c-header` binary:

```bash
cargo install --git https://github.com/mtjhrc/ffier.git --tag 0.2.0rc1 ffier-gen-c-header
```

---

## Binding Regeneration & Verification

```bash
# Regenerate all bindings
make gen-libkrun-bindings
make gen-init-blob-bindings
a
# Verify working tree has no uncommitted binding or schema diffs
git diff --exit-code
```

---

## Source of Truth

The Rust annotations and `ffier::library_definition!` calls in `src/libkrun/src/api/` and `init/init-blob/src/` are the **sole source of truth**.

Never hand-edit:
- `include/libkrun.h`
- `include/libkrun_init.h`
- `src/libkrun-via-cdylib-weak/ffier-krun.json`
- `init/init-blob-via-cdylib/ffier-krun_init.json`
- Any code generated in `OUT_DIR` by `build.rs`
