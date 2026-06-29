use std::env;
use std::path::PathBuf;
use std::process::Command;

fn musl_target_for_host() -> &'static str {
    let host = env::var("TARGET").unwrap_or_default();
    if host.starts_with("aarch64") {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    }
}

fn musl_supported(rustc: &str) -> bool {
    let musl_target = musl_target_for_host();
    let output = Command::new(rustc)
        .args(["--target", musl_target, "--print", "sysroot"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let sysroot = PathBuf::from(String::from_utf8_lossy(&o.stdout).trim());
            sysroot
                .join("lib/rustlib")
                .join(musl_target)
                .join("lib")
                .exists()
        }
        _ => false,
    }
}

/// Return a rustc binary that has the musl target's std library available.
///
/// Tries the active rustc first. If that fails, searches ~/.rustup/toolchains/
/// for a stable toolchain that does support musl — covering the common case
/// where the system package manager's rustc (e.g. Fedora's /usr/bin/rustc)
/// is used as the workspace compiler but the user also has a rustup toolchain
/// with musl support installed.
fn find_musl_rustc(default_rustc: &str) -> Option<PathBuf> {
    if musl_supported(default_rustc) {
        return Some(PathBuf::from(default_rustc));
    }

    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".rustup")))?;
    let toolchains = rustup_home.join("toolchains");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&toolchains)
        .ok()?
        .flatten()
        .map(|e| e.path().join("bin").join("rustc"))
        .filter(|p| p.exists())
        .collect();

    // Prefer stable toolchains over nightly/beta.
    candidates.sort_by_key(|p| !p.to_string_lossy().contains("stable"));

    candidates
        .into_iter()
        .find(|rustc| musl_supported(rustc.to_str().unwrap_or("")))
}

fn build_rust_init() -> PathBuf {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.join("../..");
    let init_manifest = workspace_root.join("init/Cargo.toml");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // Separate target dir avoids conflicting with the parent workspace cargo lock.
    let init_target_dir = out_dir.join("init-target");
    let init_bin = out_dir.join("init");

    let musl_target = musl_target_for_host();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "release".to_string());
    let default_cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let default_rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());

    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("init/src").display()
    );
    println!("cargo:rerun-if-changed={}", init_manifest.display());
    // Resolve which rustc (and paired cargo) to use for the init binary.
    let (rustc, cargo, use_musl) = match find_musl_rustc(&default_rustc) {
        Some(musl_rustc) => {
            // Use the cargo from the same toolchain bin/ directory so that
            // it inherits the same sysroot and target support.
            let cargo = musl_rustc
                .parent()
                .map(|bin| bin.join("cargo"))
                .filter(|p| p.exists())
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or(default_cargo);
            (musl_rustc.to_string_lossy().into_owned(), cargo, true)
        }
        None => {
            println!(
                "cargo:warning=musl target not available; krun-init will be dynamically linked. \
                 Run `rustup target add $(uname -m)-unknown-linux-musl` for a static binary."
            );
            (default_rustc, default_cargo, false)
        }
    };

    let mut cmd = Command::new(&cargo);
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(&init_manifest)
        .arg("--target-dir")
        .arg(&init_target_dir)
        .env("RUSTC", &rustc);

    if profile == "release" {
        cmd.arg("--release");
    }

    if use_musl {
        cmd.arg("--target").arg(musl_target);

        // The parent cargo sets CARGO_ENCODED_RUSTFLAGS="" for build scripts.
        // The child cargo we spawn inherits it, and since that env var has
        // higher precedence than CARGO_TARGET_*_RUSTFLAGS, the cross-linker
        // flags from the Makefile would be silently ignored. Remove it so
        // the per-target env vars take effect.
        cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
    }

    let mut features: Vec<&str> = Vec::new();
    if cfg!(feature = "amd-sev") {
        features.push("amd-sev");
    }
    if cfg!(feature = "tdx") {
        features.push("tdx");
    }
    if cfg!(feature = "timesync") {
        features.push("timesync");
    }
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }

    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to run {cargo}: {e}"));
    if !status.success() {
        panic!("failed to build krun-init");
    }

    let built = if use_musl {
        // Cross-compilation: cargo places the binary at <target-dir>/<triple>/<profile>/
        init_target_dir
            .join(musl_target)
            .join(&profile)
            .join("krun-init")
    } else {
        init_target_dir.join(&profile).join("krun-init")
    };
    std::fs::copy(&built, &init_bin).unwrap_or_else(|e| panic!("failed to copy krun-init: {e}"));

    init_bin
}

fn main() {
    let init_binary_path = env::var_os("KRUN_INIT_BINARY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(build_rust_init);
    println!(
        "cargo:rustc-env=KRUN_INIT_BINARY_PATH={}",
        init_binary_path.display()
    );
    println!("cargo:rerun-if-env-changed=KRUN_INIT_BINARY_PATH");
}
