//! Ensuring an environment generation's credential broker with the
//! authority, carrying the boot's secrets from its runner (#3999).

use codewire_local_credentials::EnvironmentBrokerRuntime as AuthorityBrokerRuntime;
use codewire_local_credentials::LocalCredentialControlClient;

use super::{
    CredentialBrokerEnsureRequest, SupervisorError, authority_applies_network_policy,
    credential_control_error,
};

/// What a user reads when the running credential authority cannot apply a
/// network policy to the GitHub connection (#4926).
const AUTHORITY_PREDATES_NETWORK_POLICY_GITHUB: &str = "this environment's network policy does not allow GitHub, and the local credential service that is running is from an earlier cw, which would use the GitHub connection anyway; stop your local VMs so cw replaces that service, or select a network policy that allows github.com and api.github.com";

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
            AUTHORITY_PREDATES_NETWORK_POLICY_GITHUB.to_owned(),
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
