//! What one boot's egress enforces and intercepts, read once as the
//! supervisor starts it.

use std::path::Path;

use codewire_access::EnvironmentId;
use codewire_local_credentials::{AuthorityFeature, BootSecretPurpose, BrokerBootSecrets};
use uuid::Uuid;

use super::{Supervisor, SupervisorError, egress_intercept};
use crate::control::v1;
use crate::network_policy_store::SelectedPolicy;
use crate::runner_service::RunnerClient;

pub(super) struct BootEgress {
    /// The environment's selected network policy at its current revision
    /// (#2537), recorded as enforced once the boot runs.
    pub(super) network_policy: SelectedPolicy,
    /// That policy's canonical document, which the boot's egress broker
    /// enforces exactly; empty for `open`.
    pub(super) network_policy_document: Vec<u8>,
    /// Whether the boot intercepts agent hosts (#3999): the per-host switch
    /// is on and the boot has a local credential broker to pair with.
    pub(super) intercept: bool,
    /// What the boot starts with, and why not when the switch is on but it
    /// does not intercept, for its runner to report (#4912).
    pub(super) interception: v1::Interception,
}

impl Supervisor {
    /// Whether the running credential authority carries a boot's secrets to
    /// its brokers, asked only when the switch is on: an older one would drop
    /// them, and its brokers could never pair with the front door (#3999).
    async fn authority_carries_boot_secrets(&self) -> bool {
        if !egress_intercept::read_switch(&self.config.root).intercepts() {
            return false;
        }
        self.access_control_client().await.is_ok_and(|client| {
            AuthorityFeature::BootSecrets.served_by(client.info().protocol_version)
        })
    }

    pub(super) async fn boot_egress(
        &self,
        environment_id: Uuid,
        broker: &super::CredentialBrokerEnsureRequest,
    ) -> Result<BootEgress, SupervisorError> {
        let authority_carries_boot_secrets = self.authority_carries_boot_secrets().await;
        let network_policy = self
            .core()
            .network_policies
            .environment_policy(environment_id)
            .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?
            .selected;
        let network_policy_document = match &network_policy {
            SelectedPolicy::Open => Vec::new(),
            selected => selected
                .compile()
                .canonical_json()
                .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?,
        };
        let interception = egress_intercept::for_boot(
            &self.config.root,
            self.log.as_deref(),
            broker,
            authority_carries_boot_secrets,
        );
        Ok(BootEgress {
            network_policy,
            network_policy_document,
            intercept: interception.state == v1::InterceptionState::Intercepted as i32,
            interception,
        })
    }
}

/// The boot's secrets for its credential brokers (#3999), asked of its
/// runner on every ensure, so an authority restarted mid-generation gets them
/// again from the runner's memory. A boot that does not intercept has none.
/// The supervisor refuses a runner on another protocol before it gets here.
pub(super) async fn broker_boot_secrets(
    runner_socket: &Path,
    environment_id: &EnvironmentId,
    generation: u64,
) -> Result<BrokerBootSecrets, SupervisorError> {
    let environment =
        Uuid::parse_str(&environment_id.to_string()).map_err(|_| SupervisorError::InvalidState)?;
    let mut runner = RunnerClient::connect(runner_socket)
        .await
        .map_err(|_| SupervisorError::RunnerUnavailable)?;
    let secrets = match runner.boot_secrets(environment, generation).await {
        Ok(secrets) => secrets,
        Err(status) if status.code() == tonic::Code::FailedPrecondition => {
            return Ok(BrokerBootSecrets::default());
        }
        Err(_) => return Err(SupervisorError::RunnerUnavailable),
    };
    // The runner client admits only the front door's pairing purpose.
    BrokerBootSecrets::new(
        secrets
            .into_iter()
            .map(|secret| (BootSecretPurpose::FrontDoorPairing, secret.value)),
    )
    .map_err(|_| SupervisorError::InvalidRunnerResponse)
}
