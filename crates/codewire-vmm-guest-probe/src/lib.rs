//! Shared seed codec, canonical initramfs writer, and Linux guest helpers for
//! the Codewire-owned microVM spike.

mod newc;
mod seed;
mod setup;

#[cfg(target_os = "linux")]
pub mod guest;
#[cfg(target_os = "linux")]
mod setup_verify;

pub use newc::{
    NewcError, canonical_guest_root_newc, canonical_newc, write_canonical_guest_root_initramfs,
    write_canonical_initramfs,
};
pub use seed::{
    ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SEED_LEN, STATE_DISK_SERIAL, Seed, SeedError, SetupBinding,
};
pub use setup::{
    GUEST_ABI_VERSION, LayerEncoding, MAX_SETUP_CONFIG_BYTES, MAX_SETUP_LAYER_BYTES,
    MAX_SETUP_LAYERS, MAX_SETUP_PACK_BYTES, MAX_SETUP_PROJECT_BYTES, MAX_SETUP_TOTAL_LAYER_BYTES,
    ROOT_FORMAT_VERSION, SETUP_ALIGNMENT, SETUP_DISK_SERIAL, SETUP_HEADER_LEN, SetupArchitecture,
    SetupBlob, SetupError, SetupHeader, SetupLayer, SetupLayerBlob, SetupObject, Sha256Value,
    oci_root_generation,
};
