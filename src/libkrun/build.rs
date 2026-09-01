use std::env;

fn main() {
    let major = env::var("CARGO_PKG_VERSION_MAJOR").unwrap();

    let variant = if env::var("CARGO_FEATURE_AWS_NITRO").is_ok() {
        "-awsnitro"
    } else if env::var("CARGO_FEATURE_AMD_SEV").is_ok() {
        "-sev"
    } else if env::var("CARGO_FEATURE_TDX").is_ok() {
        "-tdx"
    } else {
        ""
    };

    #[cfg(target_os = "linux")]
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libkrun{variant}.so.{major}");

    #[cfg(target_os = "macos")]
    {
        let minor = std::env::var("CARGO_PKG_VERSION_MINOR").unwrap();
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,-install_name,libkrun{variant}.{major}.dylib,-compatibility_version,{major}.0.0,-current_version,{major}.{minor}.0",
        );
    }
}
