//! A boot's credential placeholders, asked of the authority (#3999).

use codewire_access::{CapabilitySlot, CredentialPlaceholder, EnvironmentAccessBinding};
use tonic::Status;

use super::LocalCredentialControlClient;
use crate::AuthorityFeature;
use crate::control::v1;

impl LocalCredentialControlClient {
    /// The placeholders for each of `slots` that `selected` grants this
    /// environment generation, for a seed that intercepts its agent hosts.
    /// The authority refuses a binding that is no longer the environment's.
    pub async fn environment_credential_placeholders(
        &mut self,
        selected: &EnvironmentAccessBinding,
        environment_generation: u64,
        slots: &[CapabilitySlot],
    ) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, Status> {
        require_placeholders(self.info.protocol_version)?;
        let response = self
            .inner
            .get_environment_credential_placeholders(
                v1::GetEnvironmentCredentialPlaceholdersRequest {
                    environment_id: selected.environment_id.to_string(),
                    environment_generation,
                    profile_id: selected.profile_id.to_string(),
                    profile_revision: selected.profile_revision,
                    capability_slots: slots.iter().map(|slot| slot.as_str().to_owned()).collect(),
                },
            )
            .await?
            .into_inner();
        response
            .placeholders
            .into_iter()
            .map(|entry| {
                let slot = CapabilitySlot::parse(entry.capability_slot)
                    .map_err(|_| Status::internal("authority returned an invalid slot"))?;
                let placeholder = CredentialPlaceholder::parse(&entry.placeholder)
                    .map_err(|_| Status::internal("authority returned an invalid placeholder"))?;
                Ok((slot, placeholder))
            })
            .collect()
    }
}

/// An older authority's leases carry placeholders of another derivation, so
/// a seed may never mix them: it is refused before any call, and the boot
/// fails until no local VM runs and cw replaces the authority.
fn require_placeholders(authority_protocol: u32) -> Result<(), Status> {
    if AuthorityFeature::CredentialPlaceholders.served_by(authority_protocol) {
        return Ok(());
    }
    Err(Status::failed_precondition(
        "the running credential authority predates credential placeholders; stop every local VM so cw can replace it",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authority_older_than_placeholders_is_refused_before_any_call() {
        let since = AuthorityFeature::CredentialPlaceholders.since();
        let refused = require_placeholders(since - 1).unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(refused.message().contains("stop every local VM"));
        assert!(require_placeholders(since).is_ok());
    }
}
