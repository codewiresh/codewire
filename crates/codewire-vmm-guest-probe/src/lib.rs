//! Shared seed codec, canonical initramfs writer, and Linux guest helpers for
//! the Codewire-owned microVM spike.

mod network;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod direct_share;

/// Codewire-owned persistent Codex home projected into the workspace.
///
/// Provider credentials are never stored here. The directory contains only
/// guest-visible configuration and Codex's own workspace-local state.
pub const CODEX_GUEST_HOME_PATH: &str = codewire_access::CODEX_NATIVE_HOME;
pub mod cw_runtime;
pub mod cw_runtime_live;
#[cfg(target_os = "linux")]
pub mod cw_runtime_publisher;
mod newc;
mod progress;
mod seed;
mod setup;
mod vz_inode_probe;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod skill_snapshot;

#[cfg(target_os = "linux")]
pub mod guest;
#[cfg(target_os = "linux")]
mod rtc_clock;
#[cfg(target_os = "linux")]
mod setup_apply;
#[cfg(target_os = "linux")]
mod setup_archive;
#[cfg(target_os = "linux")]
mod setup_verify;
#[cfg(target_os = "linux")]
mod workload_cgroup;
#[cfg(target_os = "linux")]
mod workspace_plan;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use direct_share::{
    DIRECT_SHARE_PLAN_PATH, DIRECT_SHARE_PLAN_RELATIVE_PATH, DirectShareMount, DirectSharePlan,
    DirectSharePlanError, MAX_DIRECT_SHARE_PLAN_BYTES, MAX_DIRECT_SHARES,
    VM_ONLY_CAPABILITY_MARKER,
};
pub use network::{
    GUEST_NETWORK_VSOCK_PORT, NETWORK_FRAME_HEADER_LEN, NETWORK_GUEST_ACK_LEN,
    NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NETWORK_HOST_READY_TIMEOUT_SECONDS,
    NETWORK_KEY_LEN, NETWORK_MAX_PACKET_BYTES, NetworkDirection, NetworkError, NetworkGuestAck,
    NetworkHostHello, NetworkHostReady, NetworkKey, NetworkRole, NetworkSession,
    encoded_network_frame_len,
};
#[cfg(target_os = "linux")]
pub use newc::write_canonical_guest_root_initramfs_with_cw;
pub use newc::{
    NewcError, canonical_guest_root_newc, canonical_guest_root_newc_with_cw, canonical_newc,
    write_canonical_guest_root_initramfs, write_canonical_initramfs,
};
pub use progress::{
    GUEST_PROGRESS_VSOCK_PORT, GuestBootStage, PROGRESS_CHALLENGE_LEN, PROGRESS_FRAME_LEN,
    PROGRESS_REQUEST_LEN, ProgressError, ProgressFrame, ProgressRequest,
};
pub use seed::{
    DOCKER_DISK_SERIAL, GUEST_RUNTIME_ABI_MARKER, ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SEED_LEN,
    STATE_DISK_SERIAL, Seed, SeedError, SetupBinding,
};
pub use setup::{
    GUEST_ABI_VERSION, LayerEncoding, MAX_SETUP_CONFIG_BYTES, MAX_SETUP_LAYER_BYTES,
    MAX_SETUP_LAYERS, MAX_SETUP_PACK_BYTES, MAX_SETUP_PROJECT_BYTES, MAX_SETUP_TOTAL_LAYER_BYTES,
    ROOT_FORMAT_VERSION, SETUP_ALIGNMENT, SETUP_DISK_SERIAL, SETUP_HEADER_LEN, SetupArchitecture,
    SetupBlob, SetupError, SetupHeader, SetupLayer, SetupLayerBlob, SetupObject, Sha256Value,
    oci_root_generation,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use skill_snapshot::{
    MAX_SKILL_SNAPSHOT_PLAN_BYTES, SKILL_SNAPSHOT_CONTENT_PATH,
    SKILL_SNAPSHOT_CONTENT_RELATIVE_PATH, SKILL_SNAPSHOT_PLAN_PATH,
    SKILL_SNAPSHOT_PLAN_RELATIVE_PATH, SkillProjection, SkillProjectionRoot, SkillSnapshot,
    SkillSnapshotError, SkillSnapshotMode, SkillSnapshotPlan, SkillSnapshotSource,
};
pub use vz_inode_probe::{
    VZ_INODE_PROBE_CHALLENGE_LEN, VZ_INODE_PROBE_FRAME_LEN, VZ_INODE_PROBE_SEED_LEN,
    VZ_INODE_PROBE_VSOCK_PORT, VzInodeProbeError, VzInodeProbeStage,
    decode_vz_inode_probe_stage_frame, encode_vz_inode_probe_frame,
    encode_vz_inode_probe_stage_frame, verify_vz_inode_probe_frame,
};
