//! The names of an environment's network and egress statuses, from their
//! wire enums.

use super::*;

/// The hosted egress status's name; absent when the server sends none,
/// `unknown` for a value this CLI does not know.
pub(super) fn egress_enforcement(
    value: rpc::EnumValue<codewire_proto::codewire::v1::NetworkPolicyEnforcement>,
) -> Option<String> {
    use codewire_proto::codewire::v1::NetworkPolicyEnforcement as Enforcement;
    Some(
        match value.as_known() {
            Some(Enforcement::Unspecified) => return None,
            Some(Enforcement::NotEnforced) => "not_enforced",
            Some(Enforcement::Enforced) => "enforced",
            Some(Enforcement::Enforcing) => "enforcing",
            Some(Enforcement::FailedClosed) => "failed_closed",
            None => "unknown",
        }
        .to_owned(),
    )
}

/// The attachment state's name; absent when the environment names no
/// network, `unknown` for a value this CLI does not know.
pub(super) fn network_state(value: rpc::EnumValue<rpc::NetworkAttachmentState>) -> Option<String> {
    Some(
        match value.as_known() {
            Some(rpc::NetworkAttachmentState::Unspecified) => return None,
            Some(rpc::NetworkAttachmentState::Pending) => "pending",
            Some(rpc::NetworkAttachmentState::Attached) => "attached",
            Some(rpc::NetworkAttachmentState::Failed) => "failed",
            Some(rpc::NetworkAttachmentState::Revoked) => "revoked",
            None => "unknown",
        }
        .to_owned(),
    )
}

pub(super) fn network_failure(
    value: rpc::EnumValue<rpc::NetworkAttachmentFailure>,
) -> Option<String> {
    Some(
        match value.as_known() {
            Some(rpc::NetworkAttachmentFailure::Unspecified) => return None,
            Some(rpc::NetworkAttachmentFailure::MeshUnreachable) => "mesh_unreachable",
            Some(rpc::NetworkAttachmentFailure::NetworkNotFound) => "network_not_found",
            Some(rpc::NetworkAttachmentFailure::NotAMember) => "not_a_member",
            Some(rpc::NetworkAttachmentFailure::NodeNameTaken) => "node_name_taken",
            Some(rpc::NetworkAttachmentFailure::Refused) => "refused",
            None => "unknown",
        }
        .to_owned(),
    )
}
