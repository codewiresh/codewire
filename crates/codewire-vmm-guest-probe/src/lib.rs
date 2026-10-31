//! Shared seed codec, canonical initramfs writer, and Linux guest helpers for
//! the Codewire-owned microVM spike.

mod checkpoint_protocol;
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

pub use checkpoint_protocol::{
    CHECKPOINT_CHALLENGE_LEN, CHECKPOINT_HELLO_LEN, CHECKPOINT_HOST_ENTROPY_LEN,
    CHECKPOINT_REPLY_LEN, CHECKPOINT_REQUEST_LEN, CheckpointAction, CheckpointError,
    CheckpointHello, CheckpointKey, CheckpointReply, CheckpointRequest, CheckpointStatus,
    GUEST_CHECKPOINT_ABI, GUEST_CHECKPOINT_VSOCK_PORT, ResumeReport, resume_transition_allowed,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use direct_share::{
    DIRECT_SHARE_PLAN_PATH, DIRECT_SHARE_PLAN_RELATIVE_PATH, DirectShareMount, DirectSharePlan,
    DirectSharePlanError, MAX_DIRECT_SHARE_PLAN_BYTES, MAX_DIRECT_SHARES,
    VM_ONLY_CAPABILITY_MARKER,
};
/// Referenced by the guest entrypoint and read from the admitted init ELF: a
/// boot whose init lacks it has no checkpoint hook, so it is never
/// checkpointed (#3046 R4). The version is [`GUEST_CHECKPOINT_ABI`].
pub const GUEST_CHECKPOINT_ABI_MARKER: &[u8] = b"\0CWCHECKPOINTABI\0hook=1\0";
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
