//! Material-free questions about an environment generation's grants.

use std::collections::BTreeSet;

use codewire_access::{CredentialAuthKind, EnvironmentId};
use tonic::Status;

use super::{LocalCredentialControlClient, auth_kind_from_proto};
use crate::control::v1::{self, CredentialAuthenticationKind};

/// What the authority grants one environment generation now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvironmentGrants {
    /// The granted capability slots. GitHub appears only while the profile
    /// includes it and the store holds an active connection.
    pub slots: BTreeSet<String>,
    /// The Anthropic grant's credential kind, which fixes Claude Code's form.
    /// `None` without an Anthropic grant, and from an authority that predates
    /// the answer: the API-key form.
    pub anthropic_kind: Option<CredentialAuthKind>,
}

impl LocalCredentialControlClient {
    /// The grants the authority holds for this environment generation now.
    pub async fn environment_grants(
        &mut self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
    ) -> Result<EnvironmentGrants, Status> {
        let response = self
            .inner
            .evaluate_environment_grants(v1::EvaluateEnvironmentGrantsRequest {
                environment_id: environment_id.to_string(),
                environment_generation,
                platform: None,
            })
            .await?
            .into_inner();
        let anthropic_kind =
            match CredentialAuthenticationKind::try_from(response.anthropic_authentication_kind) {
                Ok(CredentialAuthenticationKind::Unspecified) => None,
                _ => Some(auth_kind_from_proto(
                    response.anthropic_authentication_kind,
                )?),
            };
        Ok(EnvironmentGrants {
            slots: response
                .grants
                .into_iter()
                .map(|grant| grant.capability_slot)
                .collect(),
            anthropic_kind,
        })
    }

    /// Whether a platform-sourced environment's creator has an active GitHub
    /// connection now, asked of the platform as that creator. Material-free:
    /// a start configures its guest for GitHub exactly when this holds.
    pub async fn platform_github_connected(
        &mut self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        platform: crate::PlatformCredentialBinding,
    ) -> Result<bool, Status> {
        Ok(self
            .inner
            .evaluate_environment_grants(v1::EvaluateEnvironmentGrantsRequest {
                environment_id: environment_id.to_string(),
                environment_generation,
                platform: Some(platform.into_proto()),
            })
            .await?
            .into_inner()
            .platform_github_connected)
    }
}
