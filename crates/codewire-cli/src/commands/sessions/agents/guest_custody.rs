//! Guest custody records the host reads through the guest control helper.
//!
//! The guest driver writes them; the host only decodes and compares them, so
//! a macOS host shares these exact closed types without the guest code.

/// Immutable binding of one guardian instance to its conversation, session,
/// driver process birth and boot. `peer-current.json` holds the current one.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerIdentity {
    pub(super) environment_id: String,
    pub(super) driver_id: String,
    pub(super) session_id: String,
    pub(super) instance_id: String,
    pub(super) driver_started_at: String,
    pub(super) boot_id: String,
    pub(super) driver_pid: u32,
    pub(super) driver_start_ticks: u64,
}

/// Per-instance custody state. It names processes only; provider launch
/// values never appear here.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerReceipt {
    pub(super) version: u32,
    pub(super) identity: PeerIdentity,
    pub(super) guardian_pid: Option<u32>,
    pub(super) guardian_start_ticks: Option<u64>,
    pub(super) provider_pid: Option<u32>,
    pub(super) cleanup_unknown: bool,
    pub(super) finished_at: Option<String>,
    pub(super) exit_code: Option<i32>,
    pub(super) error: Option<String>,
}

/// The operation remains durable when the requesting CLI or its input RPC is
/// cancelled. Only the driver owning this exact peer instance can accept it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ShutdownRecord {
    pub(super) version: u32,
    pub(super) operation_id: String,
    pub(super) peer: PeerIdentity,
    pub(super) requested_at: String,
    pub(super) accepted_at: Option<String>,
    pub(super) finished_at: Option<String>,
    pub(super) cleanup_unknown: bool,
    pub(super) error: Option<String>,
}
