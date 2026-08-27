use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let schema = manifest_dir.join("ffier-krun.json");
    println!("cargo:rerun-if-changed={}", schema.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("client.rs");
    let opts = ffier_gen_rust_client::Options { weak: true };
    let src =
        ffier_gen_rust_client::generate_from_file_with_options(schema.to_str().unwrap(), &opts)
            .unwrap_or_else(|e| panic!("failed to generate client from {}: {e}", schema.display()));
    fs::write(&dest, src).unwrap();
}
