//! What one boot's egress enforces and intercepts, read once as the
//! supervisor starts it.

use uuid::Uuid;

use super::{Supervisor, SupervisorError, egress_intercept};
use crate::network_policy_store::SelectedPolicy;

pub(super) struct BootEgress {
    /// The environment's selected network policy at its current revision
    /// (#2537), recorded as enforced once the boot runs.
    pub(super) network_policy: SelectedPolicy,
    /// That policy's canonical document, which the boot's egress broker
    /// enforces exactly; empty for `open`.
    pub(super) network_policy_document: Vec<u8>,
    /// Whether the per-host switch has the boot intercept agent hosts (#3999).
    pub(super) intercept: bool,
}

impl Supervisor {
    pub(super) fn boot_egress(
        &self,
        environment_id: Uuid,
        generation: u64,
    ) -> Result<BootEgress, SupervisorError> {
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
        let intercept =
            egress_intercept::switch_for_boot(&self.config.root, self.log.as_deref(), generation)
                .intercepts();
        Ok(BootEgress {
            network_policy,
            network_policy_document,
            intercept,
        })
    }
}
