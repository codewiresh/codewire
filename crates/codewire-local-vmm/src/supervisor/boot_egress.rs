//! What one boot's egress enforces and intercepts, read once as the
//! supervisor starts it.

use std::path::Path;

use codewire_access::{
    EnvironmentId, FirstBindSecret, ManagedCredentialClients, PlatformBootRecord,
};
use codewire_local_credentials::{
    AuthorityFeature, BootSecretPurpose, BrokerBootSecrets, PlatformCredentialBinding,
};
use uuid::Uuid;

use super::{Supervisor, SupervisorError, egress_intercept};

mod bound_secrets;
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
    /// How the boot's refusal log names that policy (#5058).
    pub(super) network_policy_label: v1::NetworkPolicyLabel,
    /// Whether the boot intercepts agent hosts (#3999): the per-host switch
    /// is on and the boot has a local credential broker to pair with.
    pub(super) intercept: bool,
    /// What the boot starts with, and why not when the switch is on but it
    /// does not intercept, for its runner to report (#4912).
    pub(super) interception: v1::Interception,
    /// The boot's platform selection when its credentials come from the
    /// platform (#4909), whose seed placeholders the platform gives (#4001).
    pub(super) platform: Option<PlatformCredentialBinding>,
    /// What the boot records of its local sources' bound secrets (#4003),
    /// already checked against its credentials' hosts; `None` when its
    /// authority predates the record.
    pub(super) bound_secrets: Option<Vec<FirstBindSecret>>,
    /// A platform boot's sealed record of its platform sources (#4003),
    /// whose bound hosts were checked with the local record's; `None` when
    /// the boot isn't on the platform or the platform keeps no record.
    pub(super) platform_bound_secrets: Option<PlatformBootRecord>,
}

impl BootEgress {
    /// The fields of the boot's start request this decides: the policy it
    /// enforces, what it intercepts, the seed's `credential_placeholders`,
    /// and its record of its bound secrets, whose hosts its runner binds.
    pub(super) fn start_request(
        &self,
        credential_placeholders: Vec<v1::SeedCredentialPlaceholder>,
    ) -> v1::StartVmRequest {
        v1::StartVmRequest {
            network_policy_document: self.network_policy_document.clone(),
            network_policy_label: Some(self.network_policy_label.clone()),
            intercept: self.intercept,
            interception: Some(self.interception),
            credential_placeholders,
            bound_secrets: crate::runner::records_to_proto(self.bound_secrets.clone()),
            platform_bound_secrets: crate::runner::BootRecords::platform_to_proto(
                self.platform_bound_secrets.clone(),
            ),
            ..Default::default()
        }
    }
}

impl Supervisor {
    /// What the running credential authority serves that interception
    /// needs, asked only when the switch is on: an older one would drop a
    /// boot's secrets, and its brokers could never pair with the front door
    /// (#3999), and only a newer one joins a platform delegation's front-door
    /// session (#4909).
    async fn authority_serves(&self) -> egress_intercept::AuthorityServes {
        if !egress_intercept::read_switch(&self.config.root).intercepts() {
            return Default::default();
        }
        match self.access_control_client().await {
            Ok(client) => {
                let protocol = client.info().protocol_version;
                egress_intercept::AuthorityServes {
                    reachable: true,
                    boot_secrets: AuthorityFeature::BootSecrets.served_by(protocol),
                    front_door_delegation: AuthorityFeature::FrontDoorDelegation
                        .served_by(protocol),
                }
            }
            Err(_) => Default::default(),
        }
    }

    /// What the boot that `operation_id` applies enforces and intercepts,
    /// once its VM's state disk is settled for it (#6277).
    pub(super) async fn boot_egress(
        &self,
        operation_id: Uuid,
        broker: &super::CredentialBrokerEnsureRequest,
        clients: ManagedCredentialClients,
    ) -> Result<BootEgress, SupervisorError> {
        let environment_id = Uuid::parse_str(&broker.environment_id.to_string())
            .map_err(|_| SupervisorError::InvalidState)?;
        let authority = self.authority_serves().await;
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
        let interception =
            egress_intercept::for_boot(&self.config.root, self.log.as_deref(), broker, authority)
                .map_err(|refusal| {
                refusal.record(self.log.as_deref(), broker.environment_generation);
                SupervisorError::PlatformPlaceholders(refusal)
            })?;
        let intercept = interception.state == v1::InterceptionState::Intercepted as i32;
        // The platform's record is asked beside the local one, so neither
        // waits on the other.
        let (bound_secrets, platform_bound_secrets) = tokio::try_join!(
            self.record_bound_secrets(broker),
            self.record_platform_bound_secrets(broker)
        )?;
        bound_secrets::admit_mixed(
            bound_secrets.as_deref().unwrap_or_default(),
            broker.platform.is_some(),
        )
        .map_err(SupervisorError::BoundSecrets)?;
        bound_secrets::admit(
            &crate::runner::BootRecords::union_of(
                bound_secrets.as_deref(),
                platform_bound_secrets.as_ref(),
            ),
            &interception,
            &bound_secrets::credential_intercepts(intercept, clients),
        )
        .map_err(SupervisorError::BoundSecrets)?;
        let egress = BootEgress {
            network_policy_label: crate::runner_service::policy_label(&network_policy),
            network_policy,
            network_policy_document,
            intercept,
            interception,
            platform: broker.platform.clone(),
            bound_secrets,
            platform_bound_secrets,
        };
        self.settle_state_disk_for_boot(operation_id, environment_id, &egress)
            .await?;
        Ok(egress)
    }
}

/// The boot's secrets for its credential brokers (#3999), and its records
/// of its bound secrets (#4003), local and platform, asked of its runner on
/// every ensure, so an authority restarted mid-generation gets them again
/// from the runner's memory. A boot that does not intercept has none. The
/// supervisor refuses a runner on another protocol before it gets here.
pub(super) async fn broker_boot_secrets(
    runner_socket: &Path,
    environment_id: &EnvironmentId,
    generation: u64,
) -> Result<(BrokerBootSecrets, crate::runner::BootRecords), SupervisorError> {
    let environment =
        Uuid::parse_str(&environment_id.to_string()).map_err(|_| SupervisorError::InvalidState)?;
    let mut runner = RunnerClient::connect(runner_socket)
        .await
        .map_err(|_| SupervisorError::RunnerUnavailable)?;
    let (secrets, records) = match runner.boot_secrets(environment, generation).await {
        Ok(answer) => answer,
        Err(status) if status.code() == tonic::Code::FailedPrecondition => {
            return Ok(Default::default());
        }
        Err(_) => return Err(SupervisorError::RunnerUnavailable),
    };
    // The runner client admits only the front door's pairing purpose.
    let secrets = BrokerBootSecrets::new(
        secrets
            .into_iter()
            .map(|secret| (BootSecretPurpose::FrontDoorPairing, secret.value)),
    )
    .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
    Ok((secrets, records))
}
