//! A running generation's network policy (#2537): the supervisor's request
//! to replace it, and the runner's answer once the egress broker enforces it.

use super::*;

/// How the runner's refusal log names `selected` (#5058): as `cw info`
/// does, with revision zero for a built-in.
pub(crate) fn policy_label(
    selected: &crate::network_policy_store::SelectedPolicy,
) -> v1::NetworkPolicyLabel {
    v1::NetworkPolicyLabel {
        name: selected.display_name(),
        revision: selected.revision().unwrap_or_default(),
    }
}

impl RunnerClient {
    /// Enforce `selected` on the running generation's egress broker; the
    /// digest it acknowledged.
    pub async fn replace_network_policy(
        &mut self,
        environment_id: Uuid,
        generation: u64,
        selected: &crate::network_policy_store::SelectedPolicy,
    ) -> Result<codewire_egress_policy::PolicyDigest, Status> {
        let document = selected
            .compile()
            .canonical_json()
            .map_err(|_| Status::internal("network policy has no canonical document"))?;
        let response = self
            .inner
            .replace_network_policy(v1::ReplaceNetworkPolicyRequest {
                environment_id: environment_id.to_string(),
                generation,
                network_policy_document: document,
                network_policy_label: Some(policy_label(selected)),
            })
            .await?
            .into_inner();
        let digest: [u8; 32] = response
            .enforced_digest
            .as_slice()
            .try_into()
            .map_err(|_| Status::internal("runner returned a malformed policy digest"))?;
        Ok(codewire_egress_policy::PolicyDigest::from_bytes(digest))
    }
}

impl RunnerRpc {
    pub(super) async fn replace_policy(
        &self,
        request: v1::ReplaceNetworkPolicyRequest,
    ) -> Result<v1::ReplaceNetworkPolicyResponse, Status> {
        let environment_id = parse_environment_id(&request.environment_id)?;
        if request.network_policy_document.is_empty() {
            return Err(Status::invalid_argument("network policy document is empty"));
        }
        let policy = start_network_policy(&request.network_policy_document)?;
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        state.require_adopted(environment_id)?;
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if state.generation != request.generation || state.state != v1::EnvironmentState::Running {
            return Err(Status::failed_precondition(
                "a network policy is replaced only on the running generation",
            ));
        }
        let running = state.running.as_mut().ok_or_else(|| {
            Status::failed_precondition(
                "a network policy is replaced only on the running generation",
            )
        })?;
        let enforced = running
            .replace_network_policy(policy, request.network_policy_label.as_ref())
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(v1::ReplaceNetworkPolicyResponse {
            enforced_digest: enforced.as_bytes().to_vec(),
        })
    }
}
