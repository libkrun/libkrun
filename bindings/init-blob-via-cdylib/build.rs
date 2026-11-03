use anyhow::Context;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let schema = manifest_dir.join("ffier-krun_init.json");
    println!("cargo:rerun-if-changed={}", schema.display());
    // The link search path depends on this override, so a change has to
    // rebuild rather than reuse the cached directive.
    println!("cargo:rerun-if-env-changed=LIBKRUN_LIB_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let dest = out_dir.join("client.rs");
    let schema_str = schema.to_str().context("non-UTF-8 schema path")?;
    let src = ffier_gen_rust_client::generate_from_file(schema_str)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    fs::write(&dest, src).context("writing generated client")?;

    if env::var_os("CARGO_FEATURE_FFIER_STRONG").is_some() {
        link(&manifest_dir);
    }

    Ok(())
}

fn link(manifest_dir: &std::path::Path) {
    if let Some(dir) = env::var_os("LIBKRUN_LIB_DIR") {
        println!(
            "cargo:rustc-link-search=native={}",
            PathBuf::from(dir).display()
        );
    } else if pkg_config::probe_library("libkrun_init").is_err() {
        // A sibling workspace build has produced the cdylib but pkg-config
        // cannot see it yet.
        let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
        let target_dir = manifest_dir.join("../../target").join(&profile);
        println!("cargo:rustc-link-search=native={}", target_dir.display());
    }
    println!("cargo:rustc-link-lib=dylib=krun_init");
}
