//! The seam between orchestration and whatever hosts an environment's runtime
//! (#3628).
//!
//! Orchestration owns the binding record, credentials, billing, the state
//! machine and metrics, and asks a [`RuntimeDriver`] for the rest by intent.
//! [`kubernetes::KubernetesDriver`] is today's only driver, and delegates to
//! [`SandboxClient`](crate::sandbox::client::SandboxClient) without changing
//! behaviour. A capability's methods arrive with the callers that move onto
//! them, so a signature is never declared before something needs it.

#[cfg(test)]
pub(crate) mod fake;
pub mod kubernetes;

use async_trait::async_trait;

pub use crate::sandbox::client::ProbeResult;

/// Where a runtime object lives. A caller names this rather than holding a
/// client per location; for Kubernetes it is the namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub namespace: String,
}

impl Placement {
    pub fn new(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }
}

/// Warm capacity held ahead of any environment.
#[async_trait]
pub trait RuntimePools: Send + Sync {
    /// Ask for the shared pools of old releases to go. `Ok(0)` means none are
    /// left; any other count means they were asked to go and may still exist.
    async fn retire_legacy_shared_pools(&self, placement: &Placement) -> anyhow::Result<usize>;
}

/// An environment's runtime over its life.
#[async_trait]
pub trait RuntimeLifecycle: Send + Sync {
    /// Observe an environment's runtime as it stands now.
    async fn probe(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ProbeResult>;
}

/// Everything orchestration needs from a runtime.
pub trait RuntimeDriver: RuntimePools + RuntimeLifecycle {}

impl<T: RuntimePools + RuntimeLifecycle> RuntimeDriver for T {}
