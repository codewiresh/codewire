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

/// Mirrors `sessions.Phase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberPhase {
    Pending,
    Running,
    Terminated,
}

/// Mirrors `sessions.Resources` — the declared (requested) compute the
/// row is billed against. Integer widths match the schema
/// (`cpu_millicores`/`memory_mib`/`disk_gib` are INT4 → i32).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resources {
    pub cpu_millicores: i32,
    pub memory_mib: i32,
    pub disk_gib: i32,
    pub runtime_class: Option<String>,
}

/// One runtime the driver holds, whether or not an environment has it yet.
#[derive(Debug, Clone)]
pub struct RuntimeMember {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    /// What the runtime itself records of its owner; each is empty when it
    /// records nothing, and is a claim to check rather than an authority.
    pub environment_id: String,
    pub organization_id: String,
    pub claim_uid: String,
    /// A snapshot's clearing runtime: it has a claim but no environment.
    pub snapshot_clearing: bool,
    /// `Pending` also covers a runtime the driver listed but couldn't read:
    /// it then has no owner and declares nothing, so a caller changes nothing
    /// for it and doesn't take it for a vanished one.
    pub phase: MemberPhase,
    /// Why it is in that phase; may be empty.
    pub phase_reason: String,
    /// Everything it declares, sidecars included.
    pub declared: Resources,
    /// The workspace's share of `declared`.
    pub workspace: Resources,
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

    /// Every runtime at a placement, as it stands now.
    async fn list_members(&self, placement: &Placement) -> anyhow::Result<Vec<RuntimeMember>>;
}

/// Everything orchestration needs from a runtime.
pub trait RuntimeDriver: RuntimePools + RuntimeLifecycle {}

impl<T: RuntimePools + RuntimeLifecycle> RuntimeDriver for T {}
