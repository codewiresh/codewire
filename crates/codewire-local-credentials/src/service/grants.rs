//! The local authority's answer to which grants an environment generation
//! holds, material-free.

use codewire_access::{CapabilitySlot, EnvironmentId};
use codewire_protected_store::ProtectedStore;

use super::{auth_kind_to_proto, derived_grant_to_proto};
use crate::control::v1;
use crate::{LocalCredentialAuthority, LocalCredentialError};

/// The derived grants, and the Anthropic grant's credential kind: a launch
/// projects Claude Code's form from it, as a hosted Sandbox does from the
/// platform profile's credential. A credential's kind never changes, so the
/// separate metadata read cannot disagree with the grant.
pub(super) fn local_grants<S: ProtectedStore>(
    authority: &LocalCredentialAuthority<S>,
    environment_id: &EnvironmentId,
    environment_generation: u64,
) -> Result<v1::EvaluateEnvironmentGrantsResponse, LocalCredentialError> {
    let grants = authority.evaluate_environment_grants(environment_id, environment_generation)?;
    let anthropic_authentication_kind = match grants
        .iter()
        .find(|grant| grant.capability_slot == CapabilitySlot::anthropic())
    {
        Some(grant) => auth_kind_to_proto(
            authority
                .get_credential(&grant.credential_id)?
                .metadata
                .authentication_kind,
        )
        .into(),
        None => v1::CredentialAuthenticationKind::Unspecified.into(),
    };
    Ok(v1::EvaluateEnvironmentGrantsResponse {
        grants: grants.into_iter().map(derived_grant_to_proto).collect(),
        platform_github_connected: false,
        anthropic_authentication_kind,
    })
}
