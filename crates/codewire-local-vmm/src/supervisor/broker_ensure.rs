//! Ensuring an environment generation's credential broker with the
//! authority, carrying the boot's secrets from its runner (#3999).

use codewire_local_credentials::EnvironmentBrokerRuntime as AuthorityBrokerRuntime;
use codewire_local_credentials::{AuthorityFeature, LocalCredentialControlClient};

use super::{CredentialBrokerEnsureRequest, SupervisorError, credential_control_error};
use crate::supervisor_config::OUTDATED_CREDENTIAL_SERVICE;

/// Whether an authority at `authority_protocol` may be asked for a broker
/// under this answer (#4926). One from before the rule ignores the answer
/// and serves GitHub, which is only right when the policy allows GitHub.
fn authority_applies_network_policy(authority_protocol: u32, allows_github: bool) -> bool {
    allows_github || AuthorityFeature::NetworkPolicyGithub.served_by(authority_protocol)
}

/// What a user reads when the running credential authority cannot apply a
/// network policy to the GitHub connection (#4926).
fn authority_predates_network_policy_github() -> String {
    format!(
        "this environment's network policy does not allow GitHub, which would be used anyway: {OUTDATED_CREDENTIAL_SERVICE}, or select a network policy that allows github.com and api.github.com"
    )
}

pub(super) async fn ensure_credential_broker(
    request: CredentialBrokerEnsureRequest,
) -> Result<AuthorityBrokerRuntime, SupervisorError> {
    if !request.enabled {
        return Ok(AuthorityBrokerRuntime {
            environment_id: request.environment_id,
            environment_generation: request.environment_generation,
            running: false,
        });
    }
    let boot_secrets = super::boot_egress::broker_boot_secrets(
        &request.runner_socket,
        &request.environment_id,
        request.environment_generation,
    )
    .await?;
    let mut client = LocalCredentialControlClient::connect(&request.authority)
        .await
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)?;
    if !authority_applies_network_policy(
        client.info().protocol_version,
        request.network_policy_allows_github,
    ) {
        // An authority from before the rule would ignore the answer and
        // serve GitHub under this policy. It keeps serving the VMs that ran
        // across a cw update, so it cannot be replaced here; this
        // environment gets no credential broker from it instead.
        let _ = client
            .stop_environment_broker(&request.environment_id, None)
            .await;
        return Err(SupervisorError::NetworkPolicySelection(
            authority_predates_network_policy_github(),
        ));
    }
    client
        .ensure_environment_broker(
            &request.environment_id,
            request.environment_generation,
            &request.environment_name,
            &request.runner_socket,
            codewire_local_credentials::EnvironmentBrokerSelection {
                local_profile: request.local_profile,
                projection: request.projection,
                platform: request.platform,
                network_policy_allows_github: request.network_policy_allows_github,
                boot_secrets,
            },
        )
        .await
        .map_err(credential_control_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #4926: an authority from before the rule keeps serving across a cw
    /// update and would ignore a "no". It is asked for a broker only when the
    /// policy allows GitHub anyway.
    #[test]
    fn an_authority_from_before_the_rule_is_not_asked_to_refuse_github() {
        let since = AuthorityFeature::NetworkPolicyGithub.since();
        assert!(authority_applies_network_policy(since, false));
        assert!(authority_applies_network_policy(since, true));
        assert!(authority_applies_network_policy(since - 1, true));
        assert!(!authority_applies_network_policy(since - 1, false));
    }
}
