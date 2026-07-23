fn main() {
    pkg_config::probe_library("libkrun").expect(
        "pkg-config could not find libkrun. \
         Install it or set PKG_CONFIG_PATH to include the directory containing libkrun.pc",
    );
}
