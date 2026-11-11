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

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;

use crate::sandbox::ClaimOpts;
pub use crate::sandbox::client::{
    ClearingProgress, FailedLiveResize, KeptSnapshot, PodResizeInfeasible, PoolBornClaim,
    ProbeResult, WorkspacePodIdentity as MemberRef, WorkspacePodReplacement as MemberReplacement,
    WorkspacePodResizeState as ResizeState, WorkspacePvcAnchor as VolumeRef,
    WorkspaceSandboxIdentity as SuspendedRuntime, WorkspaceStorage as VolumeIdentity,
    WorkspaceStorageResizeOutcome as VolumeGrowth,
};
pub use crate::sandbox::exec::WorkspaceExecHandle as RuntimeExec;
use crate::sandbox::host_keys::HostKeyStore;
pub use crate::sandbox::sidecar::PortForwardedStream as RuntimeStream;
pub use crate::sandbox::snapshots::{ClearingOpts, VolumeMode};
use crate::sandbox::template::TemplateOpts;
pub use crate::sandbox::warm_pool::DesiredPool;
use crate::sandbox::warm_pool::WarmPoolObjects;

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
    /// When a `Terminated` runtime records that it stopped running: it stopped
    /// reporting ready, or its deletion was requested, whichever came first.
    /// `None` in any other phase, or when it records neither.
    pub stopped_at: Option<chrono::DateTime<chrono::Utc>>,
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

/// Which of a capture's two disk snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureStage {
    /// The source's disk as it was, sign-ins included.
    Raw,
    /// A restore of the raw snapshot after clearing: what is kept.
    Kept,
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

/// Where a claim's runtime comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pick {
    /// A member of the shared pool named here, or a cold start from that
    /// pool's rendering when it has no ready member.
    Pool(String),
    /// The environment's own rendering, which
    /// [`prepare_cold_claim`](RuntimeClaims::prepare_cold_claim) made ready.
    Cold,
}

/// Whether a shared pool can take a claim now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolState {
    Claimable,
    /// It is missing, being removed, empty, or not at this rendering's
    /// revision and spec.
    NotCurrent,
    /// What runs the pool shows no claim safety on it, so a claim could adopt
    /// a member it shouldn't.
    ControllerIncapable,
    /// An unclaimed member was started from another revision.
    StaleMembers,
}

/// The warm capacity orchestration wants at a placement.
#[derive(Clone, Debug, PartialEq)]
pub struct WantedPools {
    /// In configuration order, which is the order the node cap clamps them in.
    pub pools: Vec<DesiredPool>,
    /// Validated percentage (1..=100) of the smallest runtime node that every
    /// pool together may reserve.
    pub max_node_percent: u8,
    /// `false` when nothing is cached ahead of the pools, so nothing waits for
    /// a cache.
    pub image_cache_enabled: bool,
    /// The configuration was invalid: no pool is wanted, so every existing
    /// one drains (review L7).
    pub draining: bool,
}

/// What one pass over the pools did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolPass {
    Unchanged,
    /// What runs the pools shows no claim safety, so nothing was written
    /// beyond a first empty pool.
    Held,
    Wrote,
    /// Something changed after it was read; the next pass plans again.
    Conflict,
}

/// Warm capacity held ahead of any environment.
#[async_trait]
pub trait RuntimePools: Send + Sync {
    /// One pass toward `wanted`: keep each wanted pool at this replica's
    /// rendering and within the node cap, replace stale unclaimed members,
    /// and drain and remove pools nothing wants or claims any more. Run by one
    /// replica at a time.
    async fn keep_pools(
        &self,
        placement: &Placement,
        wanted: &WantedPools,
    ) -> anyhow::Result<PoolPass>;

    /// Forget what earlier passes remembered at every placement, as a replica
    /// that stops keeping the pools must.
    fn forget_pool_memory(&self);

    /// The wanted pools a release is rotating: this replica's rendering has no
    /// pool yet while another revision's pool of the same shape is live.
    /// Empty when none is, or when nothing may write pools yet.
    async fn rotating_pools(
        &self,
        placement: &Placement,
        wanted: &WantedPools,
    ) -> anyhow::Result<Vec<DesiredPool>>;

    /// Make each of `pools` with one member, unless it exists, then wait until
    /// each has a ready member. It waits without bound: the caller bounds it.
    async fn warm_pools(&self, placement: &Placement, pools: &[DesiredPool]) -> anyhow::Result<()>;

    /// Ask for the shared pools of old releases to go. `Ok(0)` means none are
    /// left; any other count means they were asked to go and may still exist.
    async fn retire_legacy_shared_pools(&self, placement: &Placement) -> anyhow::Result<usize>;

    /// Whether the shared pool rendered as `pool` can take a claim now. Its
    /// members are read only once everything else holds.
    async fn pool_state(
        &self,
        placement: &Placement,
        pool: &WarmPoolObjects,
    ) -> anyhow::Result<PoolState>;
}

/// An environment's claim on a runtime, from a shared pool or cold.
#[async_trait]
pub trait RuntimeClaims: Send + Sync {
    /// Make the placement ready to hold claims.
    async fn ensure_placement(&self, placement: &Placement) -> anyhow::Result<()>;

    /// Make ready what a cold claim names: the environment's own rendering,
    /// then the empty pool `claim` selects it through. If the pool can't be
    /// made, the rendering is removed again. Each step's error says which.
    async fn prepare_cold_claim(
        &self,
        placement: &Placement,
        rendering: &TemplateOpts,
        claim: &ClaimOpts,
    ) -> anyhow::Result<()>;

    /// Create the environment's claim, or find it if it exists. Its identity
    /// is not converged yet: that is
    /// [`reconcile_identity`](RuntimeLifecycle::reconcile_identity).
    async fn claim(
        &self,
        placement: &Placement,
        claim: &ClaimOpts,
        pick: &Pick,
    ) -> anyhow::Result<ClaimRef>;

    /// Admit the environment's access to a member it adopted from a shared
    /// pool, before the member's new identity has converged. `runtime_uid` is
    /// the [`RuntimeMember::uid`] its binding recorded.
    async fn bridge_adopted_member(
        &self,
        placement: &Placement,
        rendering: &TemplateOpts,
        runtime_uid: &str,
    ) -> anyhow::Result<()>;

    /// The environment's claim, when it is this exact claim and selects a
    /// shared pool, with the runtime it holds.
    async fn pool_born_claim(
        &self,
        placement: &Placement,
        environment_id: &str,
        claim_uid: &str,
    ) -> anyhow::Result<Option<PoolBornClaim>>;

    /// Remove any bridge to the environment's runtime, then delete the
    /// observed pool-born claim and its runtime, each only while it is the
    /// one observed, and wait until the environment can claim again.
    async fn withdraw_pool_born_claim(
        &self,
        placement: &Placement,
        environment_id: &str,
        observed: &PoolBornClaim,
        timeout: Duration,
    ) -> anyhow::Result<()>;
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

    /// The incarnation holding this name now, if any, whoever controls it.
    async fn member_named(
        &self,
        placement: &Placement,
        member_name: &str,
    ) -> anyhow::Result<Option<MemberRef>>;

    /// Ask for the environment's runtime to suspend, for a caller that holds
    /// no claim: the runtime is the one its claim's status names now, so unlike
    /// [`suspend`](Self::suspend) this doesn't fence on the claim's identity.
    /// This is not evidence it has suspended.
    async fn suspend_current(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<()>;

    /// Ask for the environment's runtime to run again, re-pinned to
    /// `support_image`. The counterpart of
    /// [`suspend_current`](Self::suspend_current), found the same way.
    async fn resume_current(
        &self,
        placement: &Placement,
        environment_id: &str,
        support_image: &str,
    ) -> anyhow::Result<()>;

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

    /// The environment's incarnation that has ended and that a retry must
    /// replace. A healthy or still-starting one is never returned.
    async fn terminal_member(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<Option<MemberRef>>;

    /// Publish the measured confidential runtime `rendering` describes, so
    /// that the incarnation replacing `member_name` runs it. Returns what
    /// [`wait_measured_runtime`](Self::wait_measured_runtime) waits to see.
    async fn publish_measured_runtime(
        &self,
        placement: &Placement,
        environment_id: &str,
        member_name: &str,
        rendering: &TemplateOpts,
    ) -> anyhow::Result<String>;

    /// Wait until this exact incarnation shows the published measured runtime:
    /// the proof that its replacement will run it.
    async fn wait_measured_runtime(
        &self,
        placement: &Placement,
        member: &MemberRef,
        measured: &str,
        timeout: Duration,
    ) -> anyhow::Result<()>;

    /// Bring the claim's suspended runtime to `rendering` before it resumes.
    /// It never changes a running incarnation.
    async fn refresh_bootstrap(
        &self,
        claim: &ClaimRef,
        rendering: &TemplateOpts,
        suspended: &SuspendedRuntime,
    ) -> anyhow::Result<()>;
}

/// How a running environment changes size without losing its identity.
#[async_trait]
pub trait RuntimeResize: Send + Sync {
    /// What the environment's current member runs, and whether it can change
    /// CPU and memory without a restart.
    async fn resize_state(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ResizeState>;

    /// Record the size the environment's next member should have.
    async fn set_desired_size(
        &self,
        placement: &Placement,
        environment_id: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        disk_gb: i32,
    ) -> anyhow::Result<()>;

    /// Change this exact member's CPU and memory, and wait until it runs them.
    /// It never restarts or replaces the member. A size the member's host can
    /// never fit fails with [`PodResizeInfeasible`].
    async fn resize_in_place(
        &self,
        placement: &Placement,
        environment_id: &str,
        member_uid: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        timeout: Duration,
    ) -> anyhow::Result<ResizeState>;

    /// What a failed in-place resize left on this exact member, withdrawing a
    /// request still pending. Sizes are `(cpu_millicores, memory_mb)`.
    async fn settle_failed_resize(
        &self,
        placement: &Placement,
        environment_id: &str,
        member_uid: &str,
        previous: (i32, i32),
        requested: (i32, i32),
        timeout: Duration,
    ) -> FailedLiveResize;
}

/// An environment's persistent volume, found through what the backend recorded
/// and never by name alone.
#[async_trait]
pub trait RuntimeStorage: Send + Sync {
    /// The volume as it is now. Fails if the environment has none.
    async fn volume(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
    ) -> anyhow::Result<VolumeIdentity>;

    /// The volume, if it can grow to this size. Writes nothing.
    async fn check_volume_growth(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
        disk_gb: i32,
    ) -> anyhow::Result<VolumeIdentity>;

    /// Ask for the volume to grow to this size. This is not evidence it has.
    async fn grow_volume(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
        disk_gb: i32,
    ) -> anyhow::Result<()>;

    /// Wait until the volume has grown, or until only a new member can finish
    /// growing it. It never replaces the member itself.
    async fn wait_volume_growth(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
        disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<VolumeGrowth>;

    /// Wait until the volume has this capacity, for a new member that finishes
    /// growing it.
    async fn wait_volume_capacity(
        &self,
        placement: &Placement,
        volume: &VolumeRef,
        disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<()>;
}

/// A disk snapshot's capture, step by step, each keyed by the snapshot's id so
/// that a retry resumes it. A step that creates something runs under the
/// caller's lock on the capture, which is why this is not one call.
#[async_trait]
pub trait RuntimeSnapshots: Send + Sync {
    /// Take the raw snapshot of this volume, or find it. It records the volume's
    /// mode. The volume must not be mounted, and must not be one only its guest
    /// can read.
    async fn snapshot_volume(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        source: &VolumeIdentity,
        snapshot_class: &str,
    ) -> anyhow::Result<()>;

    /// Take the kept snapshot of the cleared volume, or find it. It is the one
    /// volume a snapshot keeps, so call this only after `clearing_progress`
    /// returned `Succeeded` and `stop_clearing` returned: the driver can't check
    /// either, and a snapshot of an uncleared volume would keep its sign-ins.
    async fn keep_cleared_volume(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        snapshot_class: &str,
    ) -> anyhow::Result<()>;

    /// Wait until this snapshot is ready, and return its size.
    async fn wait_snapshot(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        stage: CaptureStage,
        timeout: Duration,
    ) -> anyhow::Result<String>;

    /// The source volume's mode, as the raw snapshot recorded it.
    async fn raw_snapshot_mode(
        &self,
        placement: &Placement,
        snapshot_id: &str,
    ) -> anyhow::Result<VolumeMode>;

    /// Start clearing a restore of the raw snapshot, or find it started.
    async fn start_clearing(
        &self,
        placement: &Placement,
        opts: &ClearingOpts<'_>,
    ) -> anyhow::Result<()>;

    async fn clearing_progress(
        &self,
        placement: &Placement,
        snapshot_id: &str,
    ) -> anyhow::Result<ClearingProgress>;

    /// Stop the clearing and wait until the volume is unmounted.
    async fn stop_clearing(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        timeout: Duration,
    ) -> anyhow::Result<()>;

    /// Delete what a capture made, the kept snapshot only if asked. An error
    /// never stops the rest, because the raw snapshot holds sign-ins whole.
    async fn delete_capture(
        &self,
        placement: &Placement,
        snapshot_id: &str,
        kept: KeptSnapshot,
        timeout: Duration,
    ) -> anyhow::Result<()>;
}

/// How a client reaches a running environment.
#[async_trait]
pub trait RuntimeAccess: Send + Sync {
    /// The address of the environment's current member.
    async fn member_address(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<String>;

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

    /// [`wait_access_ready`](Self::wait_access_ready), then in the same
    /// connection a login and an SFTP exchange, retried until it all succeeds.
    /// Returns the incarnation it proved, as [`MemberRef::uid`].
    async fn prove_access(
        &self,
        placement: &Placement,
        environment_id: &str,
        timeout: Duration,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<String>;

    /// One attempt at what a client does first: connect, check the host key
    /// against the store, log in and exchange SFTP.
    async fn ssh_ready(
        &self,
        placement: &Placement,
        environment_id: &str,
        host_keys: &dyn HostKeyStore,
    ) -> anyhow::Result<()>;

    async fn claim_readiness(
        &self,
        placement: &Placement,
        environment_id: &str,
    ) -> anyhow::Result<ClaimReadiness>;

    /// Start a command in the workspace of this exact member, without waiting
    /// for it to exit. Once this returns, the command may already be running.
    async fn start_exec(
        &self,
        placement: &Placement,
        member_name: &str,
        command: &[String],
        work_dir: &str,
        env: &BTreeMap<String, String>,
    ) -> anyhow::Result<RuntimeExec>;

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
pub trait RuntimeDriver:
    RuntimePools
    + RuntimeClaims
    + RuntimeLifecycle
    + RuntimeResize
    + RuntimeStorage
    + RuntimeSnapshots
    + RuntimeAccess
{
}

impl<
    T: RuntimePools
        + RuntimeClaims
        + RuntimeLifecycle
        + RuntimeResize
        + RuntimeStorage
        + RuntimeSnapshots
        + RuntimeAccess,
> RuntimeDriver for T
{
}

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
