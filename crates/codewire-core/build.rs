//! Build script for codewire-core
//!
//! When the `uniffi` feature is enabled, this sets up UniFFI scaffolding.

fn main() {
    // UniFFI build scaffolding is only needed when generating bindings
    #[cfg(feature = "uniffi")]
    {
        println!("cargo:rerun-if-changed=src/codewire_core.udl");
    }
}
