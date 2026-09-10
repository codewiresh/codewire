//! Shared seed codec, canonical initramfs writer, and Linux guest helpers for
//! the Codewire-owned microVM spike.

mod network;

#[cfg(target_os = "linux")]
mod direct_share;

/// Codewire-owned persistent Codex home projected into the workspace.
///
/// Provider credentials are never stored here. The directory contains only
/// guest-visible configuration and Codex's own workspace-local state.
pub const CODEX_GUEST_HOME_PATH: &str = codewire_access::CODEX_NATIVE_HOME;
mod newc;
mod progress;
mod seed;
mod setup;

#[cfg(target_os = "linux")]
mod skill_snapshot;

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

#[cfg(target_os = "linux")]
pub use direct_share::{
    DIRECT_SHARE_PLAN_PATH, DIRECT_SHARE_PLAN_RELATIVE_PATH, DirectShareMount, DirectSharePlan,
    DirectSharePlanError, MAX_DIRECT_SHARE_PLAN_BYTES, MAX_DIRECT_SHARES,
};
pub use network::{
    GUEST_NETWORK_VSOCK_PORT, NETWORK_FRAME_HEADER_LEN, NETWORK_GUEST_ACK_LEN,
    NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NETWORK_HOST_READY_TIMEOUT_SECONDS,
    NETWORK_KEY_LEN, NETWORK_MAX_PACKET_BYTES, NetworkDirection, NetworkError, NetworkGuestAck,
    NetworkHostHello, NetworkHostReady, NetworkKey, NetworkRole, NetworkSession,
    encoded_network_frame_len,
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
    DOCKER_DISK_SERIAL, ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SEED_LEN, STATE_DISK_SERIAL, Seed,
    SeedError, SetupBinding,
};
pub use setup::{
    GUEST_ABI_VERSION, LayerEncoding, MAX_SETUP_CONFIG_BYTES, MAX_SETUP_LAYER_BYTES,
    MAX_SETUP_LAYERS, MAX_SETUP_PACK_BYTES, MAX_SETUP_PROJECT_BYTES, MAX_SETUP_TOTAL_LAYER_BYTES,
    ROOT_FORMAT_VERSION, SETUP_ALIGNMENT, SETUP_DISK_SERIAL, SETUP_HEADER_LEN, SetupArchitecture,
    SetupBlob, SetupError, SetupHeader, SetupLayer, SetupLayerBlob, SetupObject, Sha256Value,
    oci_root_generation,
};
#[cfg(target_os = "linux")]
pub use skill_snapshot::{
    MAX_SKILL_SNAPSHOT_PLAN_BYTES, SKILL_SNAPSHOT_CONTENT_PATH,
    SKILL_SNAPSHOT_CONTENT_RELATIVE_PATH, SKILL_SNAPSHOT_PLAN_PATH,
    SKILL_SNAPSHOT_PLAN_RELATIVE_PATH, SkillProjection, SkillProjectionRoot, SkillSnapshot,
    SkillSnapshotError, SkillSnapshotMode, SkillSnapshotPlan, SkillSnapshotSource,
};
