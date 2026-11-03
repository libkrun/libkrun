use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let schema = manifest_dir.join("ffier-krun.json");
    println!("cargo:rerun-if-changed={}", schema.display());
    // The link search path depends on this override, so a change has to
    // rebuild rather than reuse the cached directive.
    println!("cargo:rerun-if-env-changed=LIBKRUN_LIB_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("client.rs");
    let src = ffier_gen_rust_client::generate_from_file(schema.to_str().unwrap())
        .unwrap_or_else(|e| panic!("failed to generate client from {}: {e}", schema.display()));
    fs::write(&dest, src).unwrap();

    if env::var_os("CARGO_FEATURE_FFIER_STRONG").is_some() {
        link(&manifest_dir);
    }
}

fn link(manifest_dir: &std::path::Path) {
    if let Some(dir) = env::var_os("LIBKRUN_LIB_DIR") {
        println!(
            "cargo:rustc-link-search=native={}",
            PathBuf::from(dir).display()
        );
    } else if pkg_config::probe_library("libkrun").is_err() {
        // A sibling workspace build has produced the cdylib but pkg-config
        // cannot see it yet.
        let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
        let target_dir = manifest_dir.join("../../target").join(&profile);
        println!("cargo:rustc-link-search=native={}", target_dir.display());
    }
    println!("cargo:rustc-link-lib=dylib=krun");
}
