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

pub use crate::sandbox::client::{
    ClearingProgress, FailedLiveResize, KeptSnapshot, PodResizeInfeasible, ProbeResult,
    WorkspacePodIdentity as MemberRef, WorkspacePodReplacement as MemberReplacement,
    WorkspacePodResizeState as ResizeState, WorkspacePvcAnchor as VolumeRef,
    WorkspaceSandboxIdentity as SuspendedRuntime, WorkspaceStorage as VolumeIdentity,
    WorkspaceStorageResizeOutcome as VolumeGrowth,
};
pub use crate::sandbox::exec::WorkspaceExecHandle as RuntimeExec;
use crate::sandbox::host_keys::HostKeyStore;
pub use crate::sandbox::sidecar::PortForwardedStream as RuntimeStream;
pub use crate::sandbox::snapshots::{ClearingOpts, VolumeMode};
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
    RuntimePools + RuntimeLifecycle + RuntimeResize + RuntimeStorage + RuntimeSnapshots + RuntimeAccess
{
}

impl<
    T: RuntimePools
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
