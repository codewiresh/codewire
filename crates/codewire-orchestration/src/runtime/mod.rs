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

use std::time::Duration;

use async_trait::async_trait;

pub use crate::sandbox::client::{
    ProbeResult, WorkspacePodIdentity as MemberRef, WorkspacePodReplacement as MemberReplacement,
    WorkspaceSandboxIdentity as SuspendedRuntime,
};
use crate::sandbox::host_keys::HostKeyStore;
pub use crate::sandbox::sidecar::PortForwardedStream as RuntimeStream;
use crate::sandbox::template::TemplateOpts;

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

/// The claim an environment's operation holds on its runtime. A driver acts
/// only on the claim this names, fenced by its UID and generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimRef {
    pub placement: Placement,
    pub environment_id: String,
    pub organization_id: String,
    pub operation_generation: i64,
    pub name: String,
    pub uid: String,
}

/// What to remove when an environment is destroyed, and what must be proven
/// gone before that counts as done.
pub struct RuntimeTeardown<'a> {
    pub environment_id: &'a str,
    /// The member the backend recorded, or empty.
    pub known_member: &'a str,
    pub per_environment_template: Option<&'a str>,
    pub prove_confidential_storage_absent: bool,
    pub recorded_volume_uid: Option<&'a str>,
    pub timeout: Duration,
}

/// Whether an environment's claim can take a connection yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimReadiness {
    Absent,
    /// The reason is the runtime's own, and may be empty.
    NotReady {
        reason: String,
    },
    Ready,
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

    /// The environment's current members, and the one the backend recorded if
    /// it still exists. Refuses an incomplete identity.
    async fn members(
        &self,
        placement: &Placement,
        environment_id: &str,
        known_member: &str,
    ) -> anyhow::Result<Vec<MemberRef>>;

    /// Ask for the claim's runtime to suspend. This is not evidence it has.
    async fn suspend(&self, claim: &ClaimRef) -> anyhow::Result<()>;

    /// Wait until the claim's runtime is suspended and every one of `previous`
    /// and any replacement is gone. The result is what `resume` requires.
    async fn wait_suspended(
        &self,
        claim: &ClaimRef,
        known_member: &str,
        previous: &[MemberRef],
        timeout: Duration,
    ) -> anyhow::Result<SuspendedRuntime>;

    /// Converge the runtime's identity for the claim's generation.
    async fn reconcile_identity(&self, claim: &ClaimRef) -> anyhow::Result<()>;

    /// Start the exact runtime whose suspension was observed.
    async fn resume(
        &self,
        claim: &ClaimRef,
        suspended: &SuspendedRuntime,
        support_image: &str,
    ) -> anyhow::Result<()>;

    /// Wait until the environment's runtime reports ready.
    async fn wait_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        timeout: Duration,
    ) -> anyhow::Result<()>;

    /// Whether a placement still exists at all.
    async fn placement_exists(&self, placement: &Placement) -> anyhow::Result<bool>;

    /// Remove the environment's runtime and storage, and wait until they have
    /// gone.
    async fn tear_down(
        &self,
        placement: &Placement,
        teardown: &RuntimeTeardown<'_>,
    ) -> anyhow::Result<()>;

    /// The incarnation the environment's claim currently points at, if it
    /// exists.
    async fn current_member(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<Option<MemberRef>>;

    /// The name the environment's current runtime has or will have. One read
    /// fewer than [`current_member`](Self::current_member), and it doesn't
    /// require the runtime to exist.
    async fn member_name(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<String>;

    /// Replace exactly this incarnation, re-pinned to `support_image`. It never
    /// touches a newer one.
    async fn replace_member(
        &self,
        placement: &Placement,
        environment_id: &str,
        member: &MemberRef,
        support_image: &str,
    ) -> anyhow::Result<MemberReplacement>;

    /// Wait until a ready incarnation other than `previous` has taken its name.
    async fn wait_replacement(
        &self,
        placement: &Placement,
        previous: &MemberRef,
        timeout: Duration,
    ) -> anyhow::Result<MemberRef>;
}

/// How a client reaches a running environment.
#[async_trait]
pub trait RuntimeAccess: Send + Sync {
    async fn ensure_access(
        &self,
        placement: &Placement,
        rendering: &TemplateOpts,
    ) -> anyhow::Result<()>;

    async fn delete_access(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<()>;

    /// Wait until the environment answers a connection with a host key the
    /// store accepts.
    async fn wait_access_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()>;

    async fn claim_readiness(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ClaimReadiness>;

    /// The last `tail_lines` of the workspace's output, with timestamps.
    async fn workspace_logs(
        &self,
        placement: &Placement,
        member_name: &str,
        tail_lines: i64,
    ) -> anyhow::Result<Vec<u8>>;

    /// A stream to the SSH server of the environment's current runtime, proven
    /// to be the one its bound claim controls.
    async fn ssh_stream(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<RuntimeStream>;

    /// A stream to the environment's daemon, unauthenticated: the caller
    /// brings the credential. The runtime is found by name alone, so unlike
    /// [`ssh_stream`](Self::ssh_stream) this can reach a replacement that has
    /// taken the name since the caller last looked.
    async fn daemon_stream(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<RuntimeStream>;
}

/// Everything orchestration needs from a runtime.
pub trait RuntimeDriver: RuntimePools + RuntimeLifecycle + RuntimeAccess {}

impl<T: RuntimePools + RuntimeLifecycle + RuntimeAccess> RuntimeDriver for T {}

pub(crate) async fn within_workspace_deadline<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    anyhow::ensure!(
        tokio::time::Instant::now() < deadline,
        "workspace lifecycle observation timed out"
    );
    let result = tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| anyhow::anyhow!("workspace lifecycle observation timed out"))??;
    // A future that becomes ready after monopolizing its poll cannot turn a
    // late observation into timely completion.
    anyhow::ensure!(
        tokio::time::Instant::now() < deadline,
        "workspace lifecycle observation timed out"
    );
    Ok(result)
}
