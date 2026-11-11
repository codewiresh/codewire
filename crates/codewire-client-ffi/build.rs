//! With `bindgen`, the unit-test binary keeps the crate's UniFFI metadata,
//! which the Swift bindings check reads from its own executable
//! (src/swift_bindings_tests.rs). The metadata are statics nothing references,
//! so the linker's garbage collection drops them by default. Of this package's
//! outputs only that binary is linked: the static library and the rlib are
//! archives, and the iOS build never enables `bindgen`.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let bindgen = std::env::var_os("CARGO_FEATURE_BINDGEN").is_some();
    let linux = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "linux");
    if bindgen && linux {
        println!("cargo::rustc-link-arg=-Wl,--no-gc-sections");
    }
}
