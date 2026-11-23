//! Whether a bound workspace Pod's bootstrap is still current (design §12).

use super::EnvironmentBinding;
use super::checks::credential_scope;
use crate::runtime::{Placement, RenderingIntent, RuntimeDriver};
use crate::sandbox::client::WorkspacePodIdentity;
use crate::worker::environment_auth::WorkspaceCredentialScope;

/// Stale-bootstrap check for the observed Pod (design §12). A bound Pod-scope
/// runtime compares the binding row's captured generation, digest and
/// clients; a legacy environment-scope Pod is never current; a Pod that is
/// not bound yet is
/// current by construction, because its binding captures the current
/// environment row under the same fence.
pub(crate) async fn workspace_bootstrap_current(
    runtime: &dyn RuntimeDriver,
    placement: &Placement,
    intent: &RenderingIntent,
    pod: &WorkspacePodIdentity,
    binding: Option<&EnvironmentBinding>,
) -> anyhow::Result<bool> {
    let live = runtime
        .observe_member(placement, &pod.name)
        .await?
        .filter(|live| live.uid.as_deref() == Some(pod.uid.as_str()))
        .ok_or_else(|| anyhow::anyhow!("workspace bootstrap Pod was replaced"))?;
    match credential_scope(&live) {
        // A Pod rendered before claim-time binding is never current: recovery
        // restarts it onto the binding rendering (no legacy compatibility).
        Some(WorkspaceCredentialScope::Environment) => Ok(false),
        Some(WorkspaceCredentialScope::Pod) => {
            let Some(binding) = binding.filter(|binding| binding.pod_uid == pod.uid) else {
                return Ok(true);
            };
            match binding_bootstrap_check(binding, &intent.identity) {
                BootstrapCheck::Current => Ok(true),
                BootstrapCheck::EarlierReservedNames => {
                    tracing::info!(
                        environment_id = %intent.identity.environment_id,
                        pod_uid = %pod.uid,
                        "workspace bootstrap keeps the reserved names it was bound with until its next start"
                    );
                    Ok(true)
                }
                BootstrapCheck::Stale(differs) => {
                    tracing::info!(
                        environment_id = %intent.identity.environment_id,
                        pod_uid = %pod.uid,
                        differs,
                        "workspace bootstrap is stale"
                    );
                    Ok(false)
                }
            }
        }
        None => anyhow::bail!("workspace credential scope is ambiguous"),
    }
}

/// How a bound Pod's captured bootstrap compares with the environment now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootstrapCheck {
    Current,
    /// Only a release's reserved names differ: the environment did not
    /// change, so the Pod keeps its bootstrap until its next start (#6005).
    EarlierReservedNames,
    /// What the environment changed: the projection selection, the managed
    /// clients or the generation.
    Stale(&'static str),
}

/// Stale-bootstrap comparison for a bound Pod-scope runtime (design §12): the
/// binding row's captured generation, projection digest and managed clients
/// against the environment's current rendering identity, with the same rule
/// as the rendered environment check: the generation only matters while a
/// projection is selected.
#[cfg(test)]
pub(crate) fn binding_bootstrap_current(
    binding: &EnvironmentBinding,
    identity: &crate::runtime::RenderingIdentity,
) -> bool {
    !matches!(
        binding_bootstrap_check(binding, identity),
        BootstrapCheck::Stale(_)
    )
}

/// [`binding_bootstrap_current`], saying what differs. A digest the same
/// selection has under an earlier shipped version of the reserved names is
/// not a change to the environment (#6005).
pub(crate) fn binding_bootstrap_check(
    binding: &EnvironmentBinding,
    identity: &crate::runtime::RenderingIdentity,
) -> BootstrapCheck {
    let hex = |digest: &[u8; 32]| {
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let digest = identity.projection_selection_sha256.as_ref().map(hex);
    let earlier = binding
        .projection_selection_sha256
        .as_ref()
        .is_some_and(|bound| {
            identity
                .earlier_projection_selection_sha256
                .iter()
                .any(|digest| hex(digest) == *bound)
        });
    if binding.projection_selection_sha256 != digest && !earlier {
        BootstrapCheck::Stale("projection selection")
    } else if binding.managed_credential_clients != identity.managed_credential_clients.encode() {
        BootstrapCheck::Stale("managed clients")
    } else if digest.is_some() && binding.operation_generation != identity.operation_generation {
        BootstrapCheck::Stale("generation")
    } else if earlier {
        BootstrapCheck::EarlierReservedNames
    } else {
        BootstrapCheck::Current
    }
}
