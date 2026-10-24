//! A hosted environment's membership in one hosted Codewire Mesh network
//! (#3350).
//!
//! The creating user attaches an environment to a network at create. Once
//! its workspace Pod is bound, the daemon asks the workspace-binding listener
//! for a one-use enrollment code: 60 seconds, bound to that Pod, the
//! environment's operation generation and the attachment, stored here only
//! as its SHA-256. The daemon presents the code to Mesh once to open one Mesh
//! peer coordinate stream. Mesh redeems it here, over
//! [`EnvironmentMeshService`](codewire_proto::codewire::internal::v1::EnvironmentMeshService)
//! on the internal listener, and rechecks every member it holds within its
//! recheck interval. Nothing here is a bearer: a code opens one stream, and
//! only while its Pod is the environment's live binding.

mod service;
mod store;

pub use service::{
    ENVIRONMENT_MESH_CALLER, ENVIRONMENT_MESH_HMAC_LABEL, ENVIRONMENT_MESH_METHODS,
    environment_mesh_router, internal_service_layer,
};
pub use store::{Attachment, AttachmentReport, IssueOutcome};
pub(crate) use store::{attachment_for, insert_attachment, issue_enrollment, report_attachment};

use sha2::{Digest as _, Sha256};

/// Prefix of an environment Mesh enrollment code. Mesh routes a peer
/// credential with this prefix to orchestration rather than its own store.
pub const ENROLLMENT_CODE_PREFIX: &str = "cw_eenr_";

/// How long an issued code is accepted.
pub const ENROLLMENT_LIFETIME_SECS: i64 = 60;

/// Unexpired, unused codes one environment may hold at once. The daemon
/// needs one per stream; the bound stops a Pod filling the table.
pub const MAX_OUTSTANDING_ENROLLMENTS: i64 = 8;

/// The most members one `CheckEnvironmentMembers` call may name.
pub const MAX_CHECKED_MEMBERS: usize = 256;

/// A fresh code: the prefix and 32 random bytes as lowercase hex.
pub(crate) fn generate_enrollment_code() -> std::io::Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
    Ok(format!("{ENROLLMENT_CODE_PREFIX}{}", lower_hex(&bytes)))
}

/// The stored form of a code: lowercase hex SHA-256 of the whole code.
pub(crate) fn enrollment_code_sha256(code: &str) -> String {
    lower_hex(&Sha256::digest(code.as_bytes()))
}

/// Whether `code` has the exact shape [`generate_enrollment_code`] makes.
pub(crate) fn well_formed_enrollment_code(code: &str) -> bool {
    code.strip_prefix(ENROLLMENT_CODE_PREFIX)
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// A hosted Mesh network name, as Mesh accepts it: 1 to 128 letters, digits,
/// `-` or `_`.
pub fn valid_network_id(network_id: &str) -> bool {
    (1..=128).contains(&network_id.len())
        && network_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// A Mesh node name an environment can take: its environment name when that
/// is 1 to 63 letters, digits, `.`, `_` or `-`, starting with a letter or
/// digit. The same rule as a local VM's node name.
pub fn valid_node_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod database_tests;
