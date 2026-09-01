//! Shared seed codec, canonical initramfs writer, and Linux guest helpers for
//! the Codewire-owned microVM spike.

mod network;
mod newc;
mod progress;
mod seed;
mod setup;

#[cfg(target_os = "linux")]
pub mod guest;
#[cfg(target_os = "linux")]
mod setup_apply;
#[cfg(target_os = "linux")]
mod setup_archive;
#[cfg(target_os = "linux")]
mod setup_verify;
#[cfg(target_os = "linux")]
mod workspace_plan;

pub use network::{
    GUEST_NETWORK_VSOCK_PORT, NETWORK_FRAME_HEADER_LEN, NETWORK_GUEST_ACK_LEN,
    NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NETWORK_KEY_LEN, NETWORK_MAX_PACKET_BYTES,
    NetworkDirection, NetworkError, NetworkGuestAck, NetworkHostHello, NetworkHostReady,
    NetworkKey, NetworkRole, NetworkSession, encoded_network_frame_len,
};
pub use newc::{
    NewcError, canonical_guest_root_newc, canonical_newc, write_canonical_guest_root_initramfs,
    write_canonical_initramfs,
};
pub use progress::{
    GUEST_PROGRESS_VSOCK_PORT, GuestBootStage, PROGRESS_CHALLENGE_LEN, PROGRESS_FRAME_LEN,
    PROGRESS_REQUEST_LEN, ProgressError, ProgressFrame, ProgressRequest,
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
