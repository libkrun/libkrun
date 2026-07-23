use std::path::PathBuf;

fn schema_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    workspace_root.join("target/ffier-krun_init.json")
}

fn gen_c_header() {
    let path = schema_path();
    let json = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read {}: {e}\nBuild the cdylib first.",
            path.display()
        )
    });
    let lib: ffier_schema::Library = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
    let opts = ffier_gen_c_header::Options {
        fn_typedefs: true,
        ..Default::default()
    };
    print!(
        "{}",
        ffier_gen_c_header::generate(&lib, "LIBKRUN_INIT_H", &opts)
    );
}

fn gen_rust_client(weak: bool) {
    let path = schema_path();
    let opts = ffier_gen_rust_client::Options { weak };
    match ffier_gen_rust_client::generate_from_file_with_options(path.to_str().unwrap(), &opts) {
        Ok(src) => print!("{src}"),
        Err(e) => {
            eprintln!(
                "error: {e}\nBuild the cdylib first to generate {}",
                path.display()
            );
            std::process::exit(1);
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("c-header") => gen_c_header(),
        Some("rust-client") => gen_rust_client(args.next().as_deref() == Some("--weak")),
        _ => {
            eprintln!("usage: krun-init-blob-gen <c-header | rust-client [--weak]>");
            std::process::exit(1);
        }
    }
}
