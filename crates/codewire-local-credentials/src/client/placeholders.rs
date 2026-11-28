//! A boot's credential placeholders, asked of the authority (#3999), and
//! the bound secrets it records (#4003).

use codewire_access::{
    CapabilitySlot, CredentialPlaceholder, EnvironmentAccessBinding, EnvironmentId, FirstBindSecret,
};
use tonic::Status;

use super::LocalCredentialControlClient;
use crate::AuthorityFeature;
use crate::control::v1;

impl LocalCredentialControlClient {
    /// What a boot of `projection`'s local sources records of its bound
    /// secrets (#4003): each winner that is bound, without its value. An
    /// authority older than the question is refused, as is a selection that
    /// doesn't read; either fails the boot.
    pub async fn record_boot_bound_secrets(
        &mut self,
        projection: &crate::LocalEnvironmentProjectionBinding,
    ) -> Result<Vec<FirstBindSecret>, Status> {
        if !AuthorityFeature::BootBoundSecrets.served_by(self.info.protocol_version) {
            return Err(Status::unavailable(
                "the running local credential service predates recording bound secrets",
            ));
        }
        let response = self
            .inner
            .record_boot_bound_secrets(v1::RecordBootBoundSecretsRequest {
                projection: Some(projection.clone().into_proto()),
            })
            .await?
            .into_inner();
        Ok(response
            .secrets
            .into_iter()
            .map(crate::broker_channel::record_from_proto)
            .collect())
    }

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
        self.placeholders(v1::GetEnvironmentCredentialPlaceholdersRequest {
            environment_id: selected.environment_id.to_string(),
            environment_generation,
            profile_id: selected.profile_id.to_string(),
            profile_revision: selected.profile_revision,
            capability_slots: slot_names(slots),
            platform: None,
        })
        .await
    }

    /// The placeholders for each of `slots` that a platform boot's selection
    /// grants this environment generation (#4001), which the authority asks
    /// of the platform as the selection's creator: the ones that boot's
    /// delegation leases will carry. An authority that predates the question
    /// is refused before any call (`FailedPrecondition`); the caller falls
    /// back as for any other refusal.
    pub async fn platform_environment_credential_placeholders(
        &mut self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        platform: crate::PlatformCredentialBinding,
        slots: &[CapabilitySlot],
    ) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, Status> {
        if !AuthorityFeature::PlatformCredentialPlaceholders.served_by(self.info.protocol_version) {
            return Err(Status::failed_precondition(
                "the running credential authority predates platform credential placeholders",
            ));
        }
        self.placeholders(v1::GetEnvironmentCredentialPlaceholdersRequest {
            environment_id: environment_id.to_string(),
            environment_generation,
            capability_slots: slot_names(slots),
            platform: Some(platform.into_proto()),
            ..Default::default()
        })
        .await
    }

    async fn placeholders(
        &mut self,
        request: v1::GetEnvironmentCredentialPlaceholdersRequest,
    ) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, Status> {
        let response = self
            .inner
            .get_environment_credential_placeholders(request)
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

fn slot_names(slots: &[CapabilitySlot]) -> Vec<String> {
    slots.iter().map(|slot| slot.as_str().to_owned()).collect()
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
