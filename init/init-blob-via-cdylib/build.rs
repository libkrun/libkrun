use anyhow::Context;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let schema = manifest_dir.join("ffier-krun_init.json");
    println!("cargo:rerun-if-changed={}", schema.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let dest = out_dir.join("client.rs");
    let schema_str = schema.to_str().context("non-UTF-8 schema path")?;
    let src = ffier_gen_rust_client::generate_from_file(schema_str)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    fs::write(&dest, src).context("writing generated client")?;

    if pkg_config::probe_library("libkrun_init").is_err() {
        // Fallback: libkrun_init.so is being built in the same workspace,
        // so pkg-config won't find it yet. Point the linker at the workspace
        // target directory where the cdylib is produced, and emit the link
        // directive manually.
        let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
        let target_dir = manifest_dir.join("../../target").join(&profile);
        println!("cargo:rustc-link-search=native={}", target_dir.display());
        println!("cargo:rustc-link-lib=dylib=krun_init");
    }

    Ok(())
}
