//! kube-rs client for agent-sandbox CRDs and Codewire-owned companion runtime objects.
//!
//! Mirror of the dynamic-client paths in `internal/sandbox/client.go`:
//! SandboxClaim create (AlreadyExists → reuse), get, finalizer removal,
//! delete. It also manages the environment's access objects: the
//! workspace-daemon Service, the direct-UDP LoadBalancer and the workspace
//! NetworkPolicies.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Duration;

use crc32fast::Hasher as Crc32Hasher;
use k8s_openapi::api::core::v1::{
    ContainerStatus, Namespace, PersistentVolume, PersistentVolumeClaim, Pod, ResourceRequirements,
};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::jiff::Timestamp;
use kube::Client;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
    Preconditions,
};
use kube::core::GroupVersionKind;
use prometheus::{IntCounterVec, Opts, register_int_counter_vec};
use serde_json::Value;

use super::template::{
    CpuSharingRatio, DOCKER_DATA_INIT_CONTAINER, DOCKER_DATA_INIT_ENV,
    KATA_COCO_INIT_DATA_ANNOTATION_KEY, KATA_CONFIDENTIAL_VOLUME_ANNOTATION,
    KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY, LEGACY_DIND_BOOTSTRAP_SCRIPT,
    LEGACY_WORKSPACE_MOUNT_VOLUME, MOUNT_WORKSPACE_CONTAINER, RUNTIME_CLASS_RUNC, TemplateOpts,
    WORKSPACE_MOUNT_VOLUME, WorkspaceVolume, commodity_dind_bootstrap_script,
    dind_bootstrap_script, direct_udp_service_name, docker_data_init_container,
    docker_data_size_gib, eager_mkfs_dind_bootstrap_script, growth_in_dind_bootstrap_script,
    is_commodity_runtime_class, pre_growth_dind_bootstrap_script, render_direct_udp_service,
    render_sandbox_shadow_pool, render_sandbox_template, render_warm_member_bridge,
    render_workspace_daemon_network_policy, render_workspace_daemon_service,
    warm_member_daemon_bridge_name, workspace_daemon_network_policy_name,
    workspace_daemon_service_name,
};
use super::{
    CRD_VERSION, ClaimOpts, EXTENSIONS_GROUP, LABEL_ENV_ID, LABEL_ORG_ID, LABEL_TYPE,
    SANDBOX_GROUP, claim_name, render_sandbox_claim, runtime_identity_labels,
};

/// Mirrors `sandbox.ProbeResult`.
#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    pub claim_exists: bool,
    pub claim_ready: bool,
    pub claim_reason: String,
    pub replicas: i64,
    /// The Claim's bound Sandbox exists and its spec requests `Suspended`.
    /// Unlike `replicas == 0`, this is never inferred from an unbound Claim.
    pub sandbox_suspended: bool,
    pub pod_exists: bool,
    pub pod_phase: String,
    /// `metadata.deletionTimestamp` of the probed Pod: something asked for it
    /// to go. The time it will be force-killed, so up to its grace period ahead.
    pub pod_deleting_at: Option<Timestamp>,
    pub node_name: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub pod_ip: String,
    /// Start marks of the probed Pod, read from the same Pod object, plus
    /// the Claim's creation.
    pub pod_timeline: PodStartTimeline,
    /// The PVC the probed Pod mounts as its `workspace` volume; empty for an
    /// ephemeral workspace.
    pub workspace_pvc_name: String,
    /// The bound Sandbox's agent-sandbox launch type: `warm` for an adopted
    /// warm-pool member (Program #2238 C3).
    pub launch_type: String,
}

/// Kubernetes-reported start marks for one workspace Pod incarnation, taken
/// from the Pod's own metadata and status. Kubernetes records these times at
/// one-second resolution. A condition's mark is its latest transition to
/// `True`.
///
/// `from_pod` reads only the Pod. The Claim's and the workspace volume's
/// creation come from their own objects: the probe sets `claim_created_at`
/// from the Claim it already reads, and the Pod start record sets
/// `volume_created_at` with one PVC and one PersistentVolume read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodStartTimeline {
    /// The SandboxClaim's creation.
    pub claim_created_at: Option<Timestamp>,
    pub created_at: Option<Timestamp>,
    /// The creation of the PersistentVolume bound to the workspace PVC: the
    /// provisioner creates it once the volume exists.
    pub volume_created_at: Option<Timestamp>,
    /// `PodScheduled=True`.
    pub scheduled_at: Option<Timestamp>,
    /// `PodReadyToStartContainers=True`: the kubelet mounted the volumes and
    /// the runtime created the Pod sandbox (the Kata VM) with its network.
    pub ready_to_start_containers_at: Option<Timestamp>,
    /// `Initialized=True`: every init container completed.
    pub initialized_at: Option<Timestamp>,
    /// The `workspace` container's first `state.running.startedAt`.
    pub workspace_started_at: Option<Timestamp>,
    /// The `dind` container's first `state.running.startedAt`.
    pub dind_started_at: Option<Timestamp>,
    /// The latest `state.running.startedAt`, set only when every container is
    /// running on its first start. A restarted container's start time
    /// describes the restart rather than the Pod start, so it leaves this
    /// unset.
    pub running_at: Option<Timestamp>,
    /// `ContainersReady=True`.
    pub containers_ready_at: Option<Timestamp>,
}

impl PodStartTimeline {
    pub fn from_pod(pod: &Pod) -> Self {
        let status = pod.status.as_ref();
        let condition_true_at = |kind: &str| {
            status
                .and_then(|status| status.conditions.as_deref())
                .into_iter()
                .flatten()
                .find(|condition| condition.type_ == kind && condition.status == "True")
                .and_then(|condition| condition.last_transition_time.as_ref())
                .map(|time| time.0)
        };
        let containers = status
            .and_then(|status| status.container_statuses.as_deref())
            .unwrap_or_default();
        let running_at = containers
            .iter()
            .map(first_start_running_at)
            .collect::<Option<Vec<_>>>()
            .and_then(|started| started.into_iter().max());
        let container_started_at = |name: &str| {
            containers
                .iter()
                .find(|container| container.name == name)
                .and_then(first_start_running_at)
        };
        Self {
            created_at: pod.metadata.creation_timestamp.as_ref().map(|time| time.0),
            scheduled_at: condition_true_at("PodScheduled"),
            ready_to_start_containers_at: condition_true_at("PodReadyToStartContainers"),
            initialized_at: condition_true_at("Initialized"),
            workspace_started_at: container_started_at("workspace"),
            dind_started_at: container_started_at("dind"),
            running_at,
            containers_ready_at: condition_true_at("ContainersReady"),
            ..Self::default()
        }
    }
}

/// The PVC a Pod mounts as its `workspace` volume.
fn workspace_pvc_claim_name(pod: &Pod) -> Option<String> {
    pod.spec
        .as_ref()?
        .volumes
        .as_deref()?
        .iter()
        .find(|volume| volume.name == "workspace")?
        .persistent_volume_claim
        .as_ref()
        .map(|claim| claim.claim_name.clone())
        .filter(|name| !name.is_empty())
}

fn first_start_running_at(container: &ContainerStatus) -> Option<Timestamp> {
    if container.restart_count != 0 {
        return None;
    }
    let started_at = container
        .state
        .as_ref()?
        .running
        .as_ref()?
        .started_at
        .as_ref()?;
    Some(started_at.0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePodIdentity {
    pub name: String,
    pub uid: String,
}

/// Exact owned Sandbox whose current suspension the controller completed.
/// Constructed only by the suspension observation; callers retain it through
/// old-Pod absence, bootstrap refresh, and conditional resume.
#[derive(Debug, PartialEq, Eq)]
pub struct WorkspaceSandboxIdentity {
    name: String,
    uid: String,
}

impl WorkspaceSandboxIdentity {
    fn require_match(&self, sandbox: &DynamicObject) -> anyhow::Result<()> {
        anyhow::ensure!(
            sandbox.metadata.name.as_deref() == Some(self.name.as_str())
                && sandbox.metadata.uid.as_deref() == Some(self.uid.as_str()),
            "workspace Sandbox is not the observed suspended runtime"
        );
        Ok(())
    }
}

/// Exact controller-owned objects observed before metadata publication. This
/// contains no token and confers no credential authority.
#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeIdentityObservation {
    sandbox_uid: String,
    pod: WorkspacePodIdentity,
}

impl RuntimeIdentityObservation {
    pub fn pod(&self) -> &WorkspacePodIdentity {
        &self.pod
    }
}

struct WorkspaceBootstrapSnapshot {
    pool: DynamicObject,
    template: DynamicObject,
    sandbox: DynamicObject,
    /// The Claim selects a shared `cw-pool-` pool (Program #2238 C3): its
    /// template serves every member and is never written for one
    /// environment.
    shared: bool,
}

struct RuntimeIdentitySnapshot {
    claim: DynamicObject,
    sandbox: DynamicObject,
    pod: Pod,
    observation: RuntimeIdentityObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePodResizeState {
    pub identity: WorkspacePodIdentity,
    pub runtime_class_name: String,
    pub restart_count: i32,
    pub live_resize_compatible: bool,
    pub incompatibility_reason: Option<String>,
}

/// A `pods/resize` request the API server accepted for one exact Pod
/// incarnation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptedPodResize {
    /// The observation the request was conditioned on.
    before: WorkspacePodResizeState,
    /// What was requested.
    compute: WorkspaceCompute,
    /// `metadata.generation` of the accepted spec, when the API server
    /// reports Pod generations.
    generation: Option<i64>,
}

/// The workspace container's CPU and memory at one size. A resize keeps the
/// CPU sharing the workspace already runs at, whatever the deployment or its
/// organization would give a new one, so an existing sandbox keeps its request
/// ratio until it is replaced (#3635).
#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceCompute {
    cpu_request: String,
    cpu_limit: String,
    memory: String,
}

impl WorkspaceCompute {
    fn new(cpu_millicores: i32, memory_mb: i32, sharing: CpuSharingRatio) -> Self {
        Self {
            cpu_request: format!("{}m", sharing.request_millicores(i64::from(cpu_millicores))),
            cpu_limit: format!("{cpu_millicores}m"),
            memory: format!("{memory_mb}Mi"),
        }
    }
}

/// Bound on re-resolving the workspace Pod after the API server refuses a
/// `/resize` request because the Pod changed since it was observed.
const POD_RESIZE_SUBMIT_ATTEMPTS: usize = 5;

/// The kubelet acknowledged this resize request's generation and reported
/// it infeasible on the Pod's node; resubmitting it cannot succeed.
#[derive(Debug)]
pub struct PodResizeInfeasible(pub String);

/// How long the scheduler must keep refusing a workspace Pod for lack of
/// resources before the wait calls the cluster full (#3635). Long enough for a
/// terminating Kata Pod to give its reservation back, which the scheduler then
/// sees by itself; a worker restart only restarts this clock.
pub const NO_CAPACITY_GRACE: Duration = Duration::from_secs(60);

/// How often [`SandboxClient::refused_for_no_capacity`] reads the Pod.
const NO_CAPACITY_POLL: Duration = Duration::from_secs(5);

/// The scheduler refused the workspace Pod for lack of resources for
/// [`NO_CAPACITY_GRACE`]. There is no autoscaler to wait for, so more waiting
/// only delays the answer.
#[derive(Debug)]
pub struct NoCapacity(pub String);

impl std::fmt::Display for NoCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no capacity for the workspace Pod: {}", self.0)
    }
}

impl std::error::Error for NoCapacity {}

impl std::fmt::Display for PodResizeInfeasible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Kubernetes cannot fit the requested CPU and memory on the workspace node: {}",
            self.0
        )
    }
}

impl std::error::Error for PodResizeInfeasible {}

/// What a failed resize operation left on the workspace Pod incarnation it
/// may have asked to resize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailedLiveResize {
    /// The Pod runs, and asks for, the previous CPU and memory, and the
    /// kubelet has seen that request: nothing is pending.
    Settled,
    /// The Pod runs, and asks for, the requested CPU and memory.
    Applied,
    /// The outcome could not be established on that incarnation.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceStorage {
    pub pvc_name: String,
    /// The resolved PVC's UID. Every later write is preconditioned on it.
    pub pvc_uid: String,
    pub storage_class_name: String,
    pub requested_disk_gb: i32,
    pub applied_disk_gb: Option<i32>,
    pub filesystem_resize_pending: bool,
    pub expansion_allowed: bool,
    /// The claim is a raw `volumeMode: Block` device: a commodity workspace
    /// the guest formats (#3718), or a confidential one.
    pub raw_block: bool,
    /// The claim is confidential's ReadWriteOncePod one, whose guest-owned
    /// LUKS2/dm-integrity volume has no grow path (#860), whatever the
    /// StorageClass allows.
    pub confidential: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceStorageResizeOutcome {
    Applied,
    RequiresPodRestart,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentResidue {
    pub resources: Vec<String>,
}

impl EnvironmentResidue {
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }
}

const DELETION_PROTECTION_FINALIZER: &str = "codewire.sh/deletion-protection";
const LEGACY_SHARED_WARM_POOL_PREFIX: &str = "sandbox-warmpool-workspace";
const DEFAULT_DIRECT_UDP_LB_PORT_START: u16 = 32000;
const DEFAULT_DIRECT_UDP_LB_PORT_END: u16 = 60999;

fn legacy_shared_warm_pool_name_matches(name: &str, template_name: &str) -> bool {
    fn positive_number_with_suffix(value: &str, suffix: &str) -> bool {
        value
            .strip_suffix(suffix)
            .and_then(|number| number.parse::<u32>().ok())
            .is_some_and(|number| number > 0)
    }

    let canonical_template = template_name == "workspace"
        || template_name.strip_prefix("workspace-").is_some_and(|sku| {
            let fields = sku.split('-').collect::<Vec<_>>();
            fields.len() == 3
                && positive_number_with_suffix(fields[0], "m")
                && positive_number_with_suffix(fields[1], "mib")
                && positive_number_with_suffix(fields[2], "gib")
        });
    if !canonical_template {
        return false;
    }

    name.strip_prefix("sandbox-warmpool-")
        .and_then(|remainder| remainder.strip_prefix(template_name))
        .and_then(|remainder| remainder.strip_prefix('-'))
        .is_some_and(|revision| {
            revision.len() == 8
                && revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[path = "client/snapshots.rs"]
mod snapshots;
#[path = "client/workspace_binding.rs"]
mod workspace_binding;
pub(crate) use workspace_binding::sandbox_name_hash;

#[path = "client/warm_pool.rs"]
mod warm_pool;
pub use snapshots::{ClearingProgress, KeptSnapshot, VolumeSnapshotProgress};
pub use warm_pool::PoolBornClaim;
pub use workspace_binding::{BindableRuntime, WorkspacePvc, WorkspacePvcAnchor};

#[cfg(test)]
#[path = "client_runtime_identity_tests.rs"]
mod runtime_identity_tests;

#[cfg(test)]
#[path = "client_cleanup_tests.rs"]
mod cleanup_tests;

#[cfg(test)]
#[path = "client/workspace_bootstrap_tests.rs"]
mod workspace_bootstrap_tests;

#[cfg(test)]
#[path = "client/claim_ready_tests.rs"]
mod claim_ready_tests;

/// The workspace environment the rendering owns: the binding, the measured
/// anchors of a confidential workspace, the daemon's listener and the token
/// a pre-binding rendering carried. A Claim may never override them.
const WORKSPACE_OWNED_ENVIRONMENT: [&str; 6] = [
    codewire_daemon_proto::WORKSPACE_BINDING_URL_ENV,
    codewire_daemon_proto::WORKSPACE_POD_UID_ENV,
    codewire_daemon_proto::WORKSPACE_MEASURED_BINDING_ROOTS_ENV,
    codewire_daemon_proto::WORKSPACE_MEASURED_ENVIRONMENT_ID_ENV,
    "CODEWIRE_WORKSPACE_SHIM_ADDR",
    LEGACY_DAEMON_AUTH_TOKEN_ENV,
];

fn workspace_container(containers: &[Value]) -> anyhow::Result<(usize, &Value)> {
    let mut workspace = containers.iter().enumerate().filter(|(_, container)| {
        container.get("name").and_then(Value::as_str) == Some("workspace")
    });
    match (workspace.next(), workspace.next()) {
        (Some(container), None) => Ok(container),
        _ => anyhow::bail!("runtime object requires exactly one workspace container"),
    }
}

fn workspace_environment(container: &Value) -> anyhow::Result<&[Value]> {
    match container.get("env") {
        None => Ok(&[]),
        Some(Value::Array(env)) => Ok(env),
        _ => anyhow::bail!("workspace environment is malformed"),
    }
}

/// Volumes that held Codex's configuration before the daemon wrote the
/// user's `~/.codex`: the per-environment ConfigMap and a memory home. Nothing
/// renders them now; a start removes them from older objects.
const WORKSPACE_CLIENT_VOLUMES: [&str; 2] = ["credential-codex-config", "credential-codex-home"];

/// Whether an object still renders a Codex volume the daemon made redundant.
fn workspace_object_has_legacy_codex_home(object: &DynamicObject) -> anyhow::Result<bool> {
    let volumes = match object.data.pointer("/spec/podTemplate/spec/volumes") {
        None => return Ok(false),
        Some(Value::Array(volumes)) => volumes,
        Some(_) => anyhow::bail!("workspace volumes are malformed"),
    };
    Ok(volumes.iter().any(|volume| {
        volume
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| WORKSPACE_CLIENT_VOLUMES.contains(&name))
    }))
}

/// The repository an image reference names, without its digest or tag:
/// `registry.example.invalid/codewire/daemon` for
/// `registry.example.invalid/codewire/daemon:v1@sha256:…`. A registry port's colon
/// precedes a `/`, a tag's colon does not.
fn image_repository(reference: &str) -> &str {
    let name = reference
        .split_once('@')
        .map_or(reference, |(name, _)| name);
    match name.rfind(':') {
        Some(colon) if !name[colon..].contains('/') => &name[..colon],
        _ => name,
    }
}

/// Why a resume or Pod replacement leaves a Sandbox's daemon image as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonImageKept {
    /// The configured support image names no digest, so there is no exact
    /// image to pin (Kind's side-loaded gateway).
    UnpinnedSupportImage,
    /// The Sandbox has neither a `codewire-bin` image volume nor a
    /// `codewire-daemon-init` init container.
    NoDaemonSource,
    /// A runtime class other than none, runc or commodity. A confidential
    /// guest's Pod is measured and attested: its policy admits exactly the
    /// rendered containers, so its daemon image changes only with a new
    /// measured rendering, never with a patch to an existing Sandbox.
    ConfidentialRuntime,
    /// The daemon image comes from another repository than the configured
    /// support image's.
    UnlistedRepository,
}

impl DaemonImageKept {
    fn label(self) -> &'static str {
        match self {
            Self::UnpinnedSupportImage => "unpinned_support_image",
            Self::NoDaemonSource => "no_daemon_source",
            Self::ConfidentialRuntime => "confidential_runtime",
            Self::UnlistedRepository => "unlisted_repository",
        }
    }
}

/// The one field a re-pin rewrites: the `codewire-bin` image volume's
/// `image.reference`, or the `codewire-daemon-init` init container's `image`
/// where the daemon is copied into an emptyDir.
#[derive(Debug, PartialEq, Eq)]
struct DaemonImageEntry<'a> {
    /// The volume's or init container's JSON pointer.
    path: String,
    name: &'static str,
    /// The image field under `path`.
    field: &'static str,
    from: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
enum DaemonImagePlan<'a> {
    /// The daemon already runs from the current support image.
    Current,
    Repin(DaemonImageEntry<'a>),
    Kept(DaemonImageKept),
}

/// The named entries of one Pod spec array, failing closed on a malformed
/// array or a duplicated name.
fn daemon_named_entry<'a>(
    pod_spec: &'a Value,
    array: &str,
    name: &str,
) -> anyhow::Result<Option<(usize, &'a Value)>> {
    let entries = match pod_spec.get(array) {
        None => return Ok(None),
        Some(Value::Array(entries)) => entries,
        Some(_) => anyhow::bail!("workspace {array} are malformed"),
    };
    let mut named = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.get("name").and_then(Value::as_str) == Some(name));
    let first = named.next();
    anyhow::ensure!(
        named.next().is_none(),
        "workspace daemon {array} entry is duplicated"
    );
    Ok(first)
}

/// Owner decision 2026-10-05: on every Start or resume, and before a running
/// Sandbox's Pod is replaced, the Sandbox's daemon runs from the current
/// support image, not the one it was created with. The sandbox controller
/// builds each new Pod from the Sandbox's own `spec.podTemplate.spec` and
/// never rewrites a running Pod, so the Sandbox is what to re-pin; a claimed
/// warm-pool member is re-pinned the same way. The daemon reaches the
/// workspace by one route: the `codewire-bin` image volume, or the
/// `codewire-daemon-init` copy that commodity Sandboxes from before the image
/// volume (e374b1f11), runc and Kind use. Either is re-pinned from an image in
/// the configured support image's repository (`SANDBOX_DAEMON_IMAGE`) to that
/// digest-pinned support image, except on a confidential runtime. A Dev
/// candidate smoke that swaps `SANDBOX_DAEMON_IMAGE` within that repository
/// (`scripts/runtime/dev/smoke-dev-candidate.sh`) therefore re-pins Sandboxes
/// started while it runs, and their next Start after the restore re-pins them
/// back. A malformed or ambiguous daemon
/// source fails closed: no Pod can be built from it, and nothing here can
/// tell which entry the daemon uses.
fn plan_daemon_image<'a>(
    sandbox: &'a Value,
    support_image: &str,
) -> anyhow::Result<DaemonImagePlan<'a>> {
    let spec_path = "/spec/podTemplate/spec";
    let Some(pod_spec) = sandbox.pointer(spec_path) else {
        return Ok(DaemonImagePlan::Kept(DaemonImageKept::NoDaemonSource));
    };
    let volume = daemon_named_entry(pod_spec, "volumes", super::template::DAEMON_VOLUME)?
        .filter(|(_, volume)| volume.get("image").is_some());
    let init = daemon_named_entry(
        pod_spec,
        "initContainers",
        super::template::DAEMON_INIT_CONTAINER,
    )?;
    let entry = match (volume, init) {
        (Some(_), Some(_)) => anyhow::bail!("workspace daemon delivery is ambiguous"),
        (Some((index, volume)), None) => DaemonImageEntry {
            path: format!("{spec_path}/volumes/{index}"),
            name: super::template::DAEMON_VOLUME,
            field: "image/reference",
            from: volume
                .pointer("/image/reference")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        },
        (None, Some((index, init))) => DaemonImageEntry {
            path: format!("{spec_path}/initContainers/{index}"),
            name: super::template::DAEMON_INIT_CONTAINER,
            field: "image",
            from: init
                .get("image")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        },
        (None, None) => return Ok(DaemonImagePlan::Kept(DaemonImageKept::NoDaemonSource)),
    };
    anyhow::ensure!(
        !entry.from.is_empty(),
        "workspace daemon image is malformed"
    );
    let runtime_class = match pod_spec.get("runtimeClassName") {
        None | Some(Value::Null) => "",
        Some(class) => class
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("workspace runtime class is malformed"))?,
    };
    Ok(if entry.from == support_image {
        DaemonImagePlan::Current
    } else if !(["", RUNTIME_CLASS_RUNC].contains(&runtime_class)
        || is_commodity_runtime_class(runtime_class))
    {
        DaemonImagePlan::Kept(DaemonImageKept::ConfidentialRuntime)
    } else if !super::warm_pool::digest_pinned(support_image) {
        DaemonImagePlan::Kept(DaemonImageKept::UnpinnedSupportImage)
    } else if image_repository(entry.from) != image_repository(support_image) {
        DaemonImagePlan::Kept(DaemonImageKept::UnlistedRepository)
    } else {
        DaemonImagePlan::Repin(entry)
    })
}

/// Reads and fenced writes one Pod-replacement re-pin may make.
const DAEMON_REPIN_ATTEMPTS: usize = 3;

/// Created only for a PATCH response that guarantees no publication. A read
/// failure after a successful write must never authorize another publication.
#[derive(Debug)]
struct WorkspaceModePatchConflict(kube::Error);

impl std::fmt::Display for WorkspaceModePatchConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "workspace operating mode update was not admitted: {}",
            self.0
        )
    }
}

impl std::error::Error for WorkspaceModePatchConflict {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// How [`SandboxClient::replace_workspace_pod_if_uid`] ended. Callers treat
/// both as a replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspacePodReplacement {
    /// This call re-pinned as needed and deleted the observed incarnation.
    Replaced,
    /// The incarnation was already gone or replaced; nothing was written.
    AlreadyReplaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonImageRepinOutcome {
    /// Current or kept: nothing to write.
    Unchanged,
    Repinned,
    /// The Pod about to be replaced was gone or replaced before the write.
    PodReplaced,
}

static DAEMON_IMAGE_PLANS: OnceLock<IntCounterVec> = OnceLock::new();

/// Count one daemon-image decision by its outcome.
fn record_daemon_image_plan(outcome: &str) {
    DAEMON_IMAGE_PLANS
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "codewire_sandbox_daemon_image_plans_total",
                    "Sandbox daemon image decisions on a resume or Pod replacement: re-pinned, current, or kept for a closed reason."
                ),
                &["outcome"]
            )
            .expect("daemon image plan metric registration must be unique")
        })
        .with_label_values(&[outcome])
        .inc();
}

/// The re-pin one patch carries.
struct DaemonImageRepin {
    from: String,
    operations: [Value; 3],
}

/// The one helper behind every daemon re-pin: the resume writers and the
/// fenced re-pin before a Pod replacement ([`SandboxClient::repin_daemon_image`]).
/// JSON Patch operations, not a merge patch: a merge patch replaces the whole
/// `volumes` or `initContainers` array, while these `test` the entry's index,
/// name and old image and `replace` only that image. The surrounding patch
/// keeps its own UID (and resourceVersion) fence, and a concurrent change to
/// the entry fails the whole patch. `None` when the Sandbox is current or kept.
fn daemon_image_repin(
    sandbox: &DynamicObject,
    support_image: &str,
) -> anyhow::Result<Option<DaemonImageRepin>> {
    let name = sandbox.metadata.name.as_deref().unwrap_or_default();
    let plan = plan_daemon_image(&sandbox.data, support_image).inspect_err(|_| {
        record_daemon_image_plan("malformed");
    })?;
    let entry = match plan {
        DaemonImagePlan::Current => {
            record_daemon_image_plan("current");
            return Ok(None);
        }
        DaemonImagePlan::Repin(entry) => entry,
        DaemonImagePlan::Kept(reason) => {
            record_daemon_image_plan(reason.label());
            match reason {
                DaemonImageKept::NoDaemonSource | DaemonImageKept::UnlistedRepository => {
                    tracing::warn!(
                        sandbox = name,
                        reason = reason.label(),
                        support_image,
                        "Sandbox daemon image is not re-pinned"
                    );
                }
                DaemonImageKept::UnpinnedSupportImage | DaemonImageKept::ConfidentialRuntime => {
                    tracing::info!(
                        sandbox = name,
                        reason = reason.label(),
                        "Sandbox daemon image is not re-pinned"
                    );
                }
            }
            return Ok(None);
        }
    };
    record_daemon_image_plan("repin");
    let DaemonImageEntry {
        path,
        name: entry_name,
        field,
        from,
    } = entry;
    Ok(Some(DaemonImageRepin {
        from: from.to_owned(),
        operations: [
            serde_json::json!({"op":"test","path":format!("{path}/name"),"value":entry_name}),
            serde_json::json!({"op":"test","path":format!("{path}/{field}"),"value":from}),
            serde_json::json!({"op":"replace","path":format!("{path}/{field}"),"value":support_image}),
        ],
    }))
}

/// Log the re-pin an admitted patch carried. The write is already accepted
/// (a resume is already Running), so an unexpected reply is reported, not
/// failed: the entry's own tests made the write exact.
fn log_daemon_image_repin(
    updated: &DynamicObject,
    name: &str,
    repin: &DaemonImageRepin,
    support_image: &str,
) {
    match plan_daemon_image(&updated.data, support_image) {
        Ok(DaemonImagePlan::Current) => tracing::info!(
            name,
            from = repin.from,
            to = support_image,
            "re-pinned Sandbox daemon image"
        ),
        _ => tracing::warn!(
            name,
            from = repin.from,
            to = support_image,
            "admitted Sandbox daemon image re-pin did not return the support image"
        ),
    }
}

/// The operations that re-render a Sandbox's prior DinD bootstrap to the
/// current one: the legacy one ([`LEGACY_DIND_BOOTSTRAP_SCRIPT`]), so the
/// workspace home's `.codewire` stays 0755 and the workspace daemon opens its
/// platform session store (#2639), the eager- and lazy-`mkfs` ones that
/// never grew the Docker data image
/// ([`eager_mkfs_dind_bootstrap_script`], [`pre_growth_dind_bootstrap_script`]),
/// so a grown workspace disk grows that image too (#3554), and the one that
/// formats and grows it inside DinD ([`growth_in_dind_bootstrap_script`]),
/// whose e2fsprogs the Docker 29.9.2 DinD image no longer ships (#3208).
/// Commodity also replaces the former mount-only VFS bootstrap with cgroup
/// delegation and the containerd OverlayFS store (#3960). Its exact Docker
/// filesystem is reset once, before writing a persistent format marker; other
/// runtime profiles retain their existing store.
/// Every resume and Pod replacement that re-pins the daemon image carries
/// them, as the controller builds each new Pod from the Sandbox's own spec.
///
/// One patch brings both halves: DinD's script, tested exact and replaced,
/// and the [`DOCKER_DATA_INIT_CONTAINER`] that now prepares the image, added
/// last with the support image and DinD's own data image, size and mount
/// mode. The current DinD bootstrap only mounts an image the data init made,
/// on the DinD image the Sandbox already pins or a newer one. A Sandbox that
/// already has the data init keeps it on the current support image, re-pinned
/// as [`plan_daemon_image`] re-pins the daemon. The DinD image and the rest
/// of the environment, the workspace image, volumes and workspace contents
/// are untouched. Any other script is left alone, and so is a confidential
/// runtime, whose measured policy admits exactly the rendered containers.
/// `None` when there is nothing to re-render.
fn dind_bootstrap_refresh(
    sandbox: &DynamicObject,
    support_image: &str,
) -> anyhow::Result<Option<Vec<Value>>> {
    let spec_path = "/spec/podTemplate/spec";
    let name = sandbox.metadata.name.as_deref().unwrap_or_default();
    let Some(pod_spec) = sandbox.data.pointer(spec_path) else {
        return Ok(None);
    };
    let containers = match pod_spec.get("containers") {
        None => return Ok(None),
        Some(Value::Array(containers)) => containers,
        Some(_) => anyhow::bail!("workspace containers are malformed"),
    };
    let mut dind = containers
        .iter()
        .enumerate()
        .filter(|(_, container)| container.get("name").and_then(Value::as_str) == Some("dind"));
    let (index, container) = match (dind.next(), dind.next()) {
        (None, _) => return Ok(None),
        (Some(found), None) => found,
        (Some(_), Some(_)) => anyhow::bail!("workspace DinD container is duplicated"),
    };
    let script = container
        .get("command")
        .and_then(Value::as_array)
        .filter(|command| command.len() == 3 && command[0] == "sh" && command[1] == "-ec")
        .and_then(|command| command[2].as_str());
    // Re-rendering an eager-`mkfs` bootstrap is harmless: the data init
    // formats only a missing image, and the one it formatted is kept.
    let prior = script.filter(|script| {
        *script == LEGACY_DIND_BOOTSTRAP_SCRIPT
            || *script == eager_mkfs_dind_bootstrap_script()
            || *script == pre_growth_dind_bootstrap_script()
            || *script == growth_in_dind_bootstrap_script()
    });
    let runtime_class = match pod_spec.get("runtimeClassName") {
        None | Some(Value::Null) => "",
        Some(class) => class
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("workspace runtime class is malformed"))?,
    };
    if !(["", RUNTIME_CLASS_RUNC].contains(&runtime_class)
        || is_commodity_runtime_class(runtime_class))
    {
        return Ok(None);
    }
    let commodity = is_commodity_runtime_class(runtime_class);
    let previous_current = script.is_some_and(|script| script == dind_bootstrap_script());
    let desired = if commodity {
        commodity_dind_bootstrap_script()
    } else {
        dind_bootstrap_script()
    };
    let current = script == Some(desired.as_str());
    let prior = if commodity && previous_current {
        script
    } else {
        prior
    };
    if script.is_some() && prior.is_none() && !current {
        tracing::warn!(
            sandbox = name,
            "Sandbox DinD bootstrap is unknown; it is not re-rendered"
        );
    }
    let inits = match pod_spec.get("initContainers") {
        None | Some(Value::Null) => None,
        Some(Value::Array(inits)) => Some(inits),
        Some(_) => anyhow::bail!("workspace initContainers are malformed"),
    };
    let data_init = match inits {
        Some(inits) => daemon_named_entry(pod_spec, "initContainers", DOCKER_DATA_INIT_CONTAINER)?
            .map(|found| (inits, found)),
        None => None,
    };
    let init_path = format!("{spec_path}/initContainers");
    if current {
        return Ok(data_init.and_then(|(_, (init_index, init))| {
            docker_data_init_repin(&format!("{init_path}/{init_index}"), init, support_image)
        }));
    }
    let Some(prior) = prior else {
        return Ok(None);
    };
    if data_init.is_some() && !previous_current {
        tracing::warn!(
            sandbox = name,
            "Sandbox carries a prior DinD bootstrap beside a Docker data init; it is not re-rendered"
        );
        return Ok(None);
    }
    let dind_env = match container.get("env") {
        None => &[][..],
        Some(Value::Array(env)) => env.as_slice(),
        Some(_) => anyhow::bail!("workspace DinD environment is malformed"),
    };
    let mount_mode = dind_env
        .iter()
        .find(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("CODEWIRE_DOCKER_MOUNT_MODE")
        })
        .and_then(|entry| entry.get("value"))
        .and_then(Value::as_str);
    if mount_mode != Some("loop") {
        // Only a loop-mounted image moved to the data init; no commodity or
        // runc rendering keeps a plain directory.
        return Ok(None);
    }
    let init_env = dind_env
        .iter()
        .filter(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| DOCKER_DATA_INIT_ENV.contains(&name))
        })
        .cloned()
        .collect();
    let path = format!("{spec_path}/containers/{index}");
    let mut operations = vec![
        serde_json::json!({"op":"test","path":format!("{path}/name"),"value":"dind"}),
        serde_json::json!({"op":"test","path":format!("{path}/command/2"),"value":prior}),
        serde_json::json!({"op":"replace","path":format!("{path}/command/2"),"value":desired}),
    ];
    if let Some((_, (init_index, init))) = data_init {
        if let Some(repin) =
            docker_data_init_repin(&format!("{init_path}/{init_index}"), init, support_image)
        {
            operations.extend(repin);
        }
        return Ok(Some(operations));
    }
    // On a Block workspace `mount-workspace` prepares the data image, as a
    // fresh render has it (#3718), so only the bootstrap is re-rendered.
    let block = mounts_block_workspace(pod_spec);
    if block {
        return Ok(Some(operations));
    }
    let data_init = docker_data_init_container(support_image, init_env);
    match inits {
        // Each existing init container keeps its place by name; a daemon
        // re-pin earlier in the same patch changes only its image.
        Some(inits) => {
            for (init_index, init) in inits.iter().enumerate() {
                operations.push(serde_json::json!({
                    "op":"test","path":format!("{init_path}/{init_index}/name"),"value":init.get("name"),
                }));
            }
            operations.push(
                serde_json::json!({"op":"add","path":format!("{init_path}/-"),"value":data_init}),
            );
        }
        None => {
            operations.push(serde_json::json!({"op":"add","path":init_path,"value":[data_init]}))
        }
    }
    Ok(Some(operations))
}

/// Re-pin a Sandbox's Docker data init to the current support image, under
/// the rules [`plan_daemon_image`] keeps for the daemon: only from the
/// configured support image's repository, and only to a digest-pinned one.
/// The image cache holds the current support image, so the next Pod's init
/// starts from it.
fn docker_data_init_repin(path: &str, init: &Value, support_image: &str) -> Option<Vec<Value>> {
    let from = init.get("image").and_then(Value::as_str)?;
    if from == support_image
        || !super::warm_pool::digest_pinned(support_image)
        || image_repository(from) != image_repository(support_image)
    {
        return None;
    }
    Some(vec![
        serde_json::json!({"op":"test","path":format!("{path}/name"),"value":DOCKER_DATA_INIT_CONTAINER}),
        serde_json::json!({"op":"test","path":format!("{path}/image"),"value":from}),
        serde_json::json!({"op":"replace","path":format!("{path}/image"),"value":support_image}),
    ])
}

/// Log a DinD bootstrap refresh an admitted patch carried.
/// Whether a Pod mounts a Block workspace's filesystem: the guest-memory
/// volume `mount-workspace` mounts it into, by its name since #4026 or the
/// one Pods rendered before it still carry.
fn mounts_block_workspace(pod_spec: &Value) -> bool {
    pod_spec
        .get("volumes")
        .and_then(Value::as_array)
        .is_some_and(|volumes| {
            volumes.iter().any(|volume| {
                matches!(
                    volume.get("name").and_then(Value::as_str),
                    Some(WORKSPACE_MOUNT_VOLUME | LEGACY_WORKSPACE_MOUNT_VOLUME)
                )
            })
        })
}

/// A commodity Sandbox's Block workspace (#3718): the index of its
/// `mount-workspace` init container, or `None` with no Block workspace.
///
/// A commodity Sandbox whose workspace claim is not Block predates the Block
/// workspace and is refused: there is no second commodity storage path, and
/// such environments are deleted at cutover (design §6).
fn block_workspace(sandbox: &DynamicObject) -> anyhow::Result<Option<usize>> {
    let spec_path = "/spec/podTemplate/spec";
    let commodity = sandbox
        .data
        .pointer(&format!("{spec_path}/runtimeClassName"))
        .and_then(Value::as_str)
        .is_some_and(is_commodity_runtime_class);
    let workspace_mode = sandbox
        .data
        .pointer("/spec/volumeClaimTemplates")
        .and_then(Value::as_array)
        .and_then(|claims| {
            claims.iter().find(|claim| {
                claim.pointer("/metadata/name").and_then(Value::as_str) == Some("workspace")
            })
        })
        .map(|claim| {
            claim
                .pointer("/spec/volumeMode")
                .and_then(Value::as_str)
                .unwrap_or("Filesystem")
        });
    if !commodity || workspace_mode.is_none() {
        return Ok(None);
    }
    anyhow::ensure!(
        workspace_mode == Some("Block"),
        "this environment's workspace is a Filesystem volume from before the Block workspace (#3718); \
         it cannot start, and must be recreated"
    );
    let inits = sandbox
        .data
        .pointer(&format!("{spec_path}/initContainers"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut mounts = inits.iter().enumerate().filter(|(_, init)| {
        init.get("name").and_then(Value::as_str) == Some(MOUNT_WORKSPACE_CONTAINER)
    });
    let (Some((index, _)), None) = (mounts.next(), mounts.next()) else {
        anyhow::bail!(
            "a Block workspace Sandbox needs exactly one {MOUNT_WORKSPACE_CONTAINER} init container"
        );
    };
    Ok(Some(index))
}

/// Whether a workspace Pod's `mount-workspace` finished: terminated with
/// exit 0, so its volume carries the filesystem it mounted.
fn workspace_mounted(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|status| status.init_container_statuses.as_deref())
        .unwrap_or_default()
        .iter()
        .filter(|status| status.name == MOUNT_WORKSPACE_CONTAINER)
        .any(|status| {
            status
                .state
                .as_ref()
                .and_then(|state| state.terminated.as_ref())
                .is_some_and(|terminated| terminated.exit_code == 0)
        })
}

/// The JSON Patch operations that turn `mount-workspace`'s rendered `new`
/// into `existing`, each fenced by `test`s of the entry's index, name and
/// argument, so no later Pod of the Sandbox may format its volume. Only
/// for a Sandbox whose live Pod `mounted` its workspace (#3718): a first Pod
/// that failed before or during its format leaves `new`, so the next one can
/// still format the volume. Empty when already `existing`.
fn workspace_volume_existing(
    sandbox: &DynamicObject,
    index: usize,
    mounted: bool,
) -> anyhow::Result<Vec<Value>> {
    let entry = format!("/spec/podTemplate/spec/initContainers/{index}");
    let init = sandbox
        .data
        .pointer(&entry)
        .expect("block_workspace found this entry");
    let state = init
        .pointer("/command/4")
        .and_then(Value::as_str)
        .filter(|_| {
            init.pointer("/command/3").and_then(Value::as_str) == Some(MOUNT_WORKSPACE_CONTAINER)
        });
    match state {
        Some(state) if state == WorkspaceVolume::Existing.as_str() => Ok(Vec::new()),
        Some(state) if state == WorkspaceVolume::New.as_str() && !mounted => Ok(Vec::new()),
        Some(state) if state == WorkspaceVolume::New.as_str() => Ok(vec![
            serde_json::json!({"op":"test","path":format!("{entry}/name"),"value":MOUNT_WORKSPACE_CONTAINER}),
            serde_json::json!({"op":"test","path":format!("{entry}/command/4"),"value":state}),
            serde_json::json!({
                "op":"replace",
                "path":format!("{entry}/command/4"),
                "value":WorkspaceVolume::Existing.as_str(),
            }),
        ]),
        _ => anyhow::bail!("{MOUNT_WORKSPACE_CONTAINER} names no workspace volume state"),
    }
}

fn log_dind_bootstrap_refresh(name: &str) {
    tracing::info!(
        name,
        "refreshed the Sandbox's Docker data bootstrap; its next Pod prepares the Docker data image in its init container from the current support image"
    );
}
/// The environment token a workspace rendered before claim-time binding
/// carried. Start detects it only to replace such an object's Pod spec.
const LEGACY_DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";

/// Whether a SandboxTemplate or Sandbox renders an identity-free workspace:
/// its workspace container names the binding listener and carries no
/// environment token. Both at once is refused as ambiguous; neither is the
/// legacy shape.
fn workspace_object_identity_free(object: &DynamicObject) -> anyhow::Result<bool> {
    let containers = object
        .data
        .pointer("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("runtime object has no containers"))?;
    let (_, container) = workspace_container(containers)?;
    let env = workspace_environment(container)?;
    let named = |name: &str| {
        env.iter()
            .any(|entry| entry.get("name").and_then(Value::as_str) == Some(name))
    };
    match (
        named(codewire_daemon_proto::WORKSPACE_BINDING_URL_ENV),
        named(LEGACY_DAEMON_AUTH_TOKEN_ENV),
    ) {
        (true, false) => Ok(true),
        (false, _) => Ok(false),
        (true, true) => anyhow::bail!("workspace identity rendering is ambiguous"),
    }
}

/// The JSON Patch that replaces a legacy object's workspace Pod spec (and,
/// for the template, its egress) with the identity-free rendering, bound to
/// the validated UID and resourceVersion. `None` when already identity-free
/// and current. An identity-free object rendered before the daemon wrote
/// `~/.codex` still mounts Codex's memory home, and is not current.
fn identity_free_upgrade_patch(
    object: &DynamicObject,
    pod_spec: &Value,
    network_policy: Option<&Value>,
) -> anyhow::Result<Option<Patch<()>>> {
    if workspace_object_identity_free(object)? && !workspace_object_has_legacy_codex_home(object)? {
        return Ok(None);
    }
    let uid = object
        .metadata
        .uid
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("workspace bootstrap object has no UID"))?;
    let version = object
        .metadata
        .resource_version
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("workspace bootstrap object has no resource version"))?;
    let mut patch = vec![
        serde_json::json!({"op":"test", "path":"/metadata/uid", "value":uid}),
        serde_json::json!({"op":"test", "path":"/metadata/resourceVersion", "value":version}),
        serde_json::json!({"op":"replace", "path":"/spec/podTemplate/spec", "value":pod_spec}),
    ];
    if let Some(network_policy) = network_policy {
        patch.push(
            serde_json::json!({"op":"add", "path":"/spec/networkPolicy", "value":network_policy}),
        );
    }
    Ok(Some(Patch::Json(serde_json::from_value(Value::Array(
        patch,
    ))?)))
}

fn require_bootstrap_object(
    object: &DynamicObject,
    namespace: &str,
    name: &str,
    kind: &str,
) -> anyhow::Result<()> {
    runtime_object_uid(&object.metadata, namespace, name)?;
    anyhow::ensure!(
        object.types.as_ref().is_some_and(|types| types.api_version
            == super::EXTENSIONS_API_VERSION
            && types.kind == kind),
        "workspace bootstrap object type does not match"
    );
    Ok(())
}

fn sandbox_suspension_observed(sandbox: &DynamicObject) -> bool {
    let Some(generation) = sandbox
        .metadata
        .generation
        .filter(|generation| *generation > 0)
    else {
        return false;
    };
    let Some(conditions) = sandbox
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let mut suspended = conditions
        .iter()
        .filter(|condition| condition.get("type").and_then(Value::as_str) == Some("Suspended"));
    sandbox
        .data
        .pointer("/spec/operatingMode")
        .and_then(Value::as_str)
        == Some("Suspended")
        && matches!((suspended.next(), suspended.next()), (Some(condition), None)
            if condition.get("status").and_then(Value::as_str) == Some("True")
                && condition.get("reason").and_then(Value::as_str) == Some("PodTerminated")
                && condition.get("observedGeneration").and_then(Value::as_i64) == Some(generation))
}

/// The Sandbox a Claim's status names, if it names one.
fn claim_bound_sandbox_name(claim: &DynamicObject) -> Option<&str> {
    claim
        .data
        .pointer("/status/sandbox/name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
}

/// The Pod a Sandbox's controller published, or the Sandbox's own name.
fn sandbox_pod_name<'a>(sandbox: &'a DynamicObject, sandbox_name: &'a str) -> &'a str {
    sandbox
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get("agents.x-k8s.io/pod-name"))
        .map(String::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(sandbox_name)
}

fn runtime_object_uid<'a>(
    metadata: &'a ObjectMeta,
    namespace: &str,
    name: &str,
) -> anyhow::Result<&'a str> {
    anyhow::ensure!(
        metadata.namespace.as_deref() == Some(namespace)
            && metadata.name.as_deref() == Some(name)
            && metadata.deletion_timestamp.is_none(),
        "runtime identity object is not current"
    );
    metadata
        .uid
        .as_deref()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| anyhow::anyhow!("runtime identity object has no UID"))
}

fn require_runtime_controller(
    metadata: &ObjectMeta,
    api: &str,
    kind: &str,
    name: &str,
    uid: &str,
) -> anyhow::Result<()> {
    let owners = metadata.owner_references.as_deref().unwrap_or_default();
    let mut controllers = owners.iter().filter(|owner| owner.controller == Some(true));
    anyhow::ensure!(
        matches!((controllers.next(), controllers.next()), (Some(owner), None)
        if owner.api_version == api && owner.kind == kind && owner.name == name && owner.uid == uid),
        "runtime identity controller does not match"
    );
    Ok(())
}

fn require_runtime_claim(
    claim: &DynamicObject,
    namespace: &str,
    opts: &ClaimOpts,
    name: &str,
    uid: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !opts.environment_id.is_empty()
            && !opts.org_id.is_empty()
            && opts.operation_generation > 0
            && !uid.is_empty()
            && name == claim_name(&opts.environment_id),
        "runtime identity authority is incomplete"
    );
    anyhow::ensure!(
        claim
            .types
            .as_ref()
            .is_some_and(|types| types.api_version == super::EXTENSIONS_API_VERSION
                && types.kind == "SandboxClaim"),
        "runtime identity Claim type does not match"
    );
    anyhow::ensure!(
        runtime_object_uid(&claim.metadata, namespace, name)? == uid,
        "runtime identity Claim was replaced"
    );
    let labels = claim
        .metadata
        .labels
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("runtime identity Claim owner is missing"))?;
    for (key, value) in [
        (LABEL_ENV_ID, opts.environment_id.as_str()),
        (LABEL_ORG_ID, opts.org_id.as_str()),
        (LABEL_TYPE, "sandbox"),
    ] {
        anyhow::ensure!(
            labels.get(key).map(String::as_str) == Some(value),
            "runtime identity Claim owner does not match"
        );
    }
    if let Some(generation) = labels.get(super::LABEL_OPERATION_GENERATION) {
        let generation = generation
            .parse::<i64>()
            .map_err(|_| anyhow::anyhow!("runtime identity Claim generation is invalid"))?;
        anyhow::ensure!(
            generation > 0 && generation <= opts.operation_generation,
            "runtime identity Claim generation is newer than its authority"
        );
    }
    Ok(())
}

fn json_labels_match(value: Option<&Value>, expected: &BTreeMap<String, String>) -> bool {
    value.and_then(Value::as_object).is_some_and(|labels| {
        expected
            .iter()
            .all(|(key, value)| labels.get(key).and_then(Value::as_str) == Some(value.as_str()))
    })
}

fn runtime_claim_labels_match(claim: &DynamicObject, opts: &ClaimOpts) -> bool {
    let claim_labels = runtime_identity_labels(
        &opts.environment_id,
        &opts.org_id,
        opts.operation_generation,
        "sandbox",
    );
    let pod_labels = runtime_identity_labels(
        &opts.environment_id,
        &opts.org_id,
        opts.operation_generation,
        "workspace",
    );
    claim.metadata.labels.as_ref().is_some_and(|labels| {
        claim_labels
            .iter()
            .all(|(key, value)| labels.get(key) == Some(value))
    }) && json_labels_match(
        claim.data.pointer("/spec/additionalPodMetadata/labels"),
        &pod_labels,
    )
}

fn runtime_claim_identity_patch(
    claim: &DynamicObject,
    opts: &ClaimOpts,
) -> anyhow::Result<Option<Value>> {
    if runtime_claim_labels_match(claim, opts) {
        return Ok(None);
    }
    let uid = claim
        .metadata
        .uid
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("runtime identity Claim has no UID"))?;
    let resource_version = claim
        .metadata
        .resource_version
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("runtime identity Claim has no resource version"))?;
    Ok(Some(serde_json::json!({
        "metadata": {
            "uid": uid, "resourceVersion": resource_version,
            "labels": runtime_identity_labels(&opts.environment_id, &opts.org_id, opts.operation_generation, "sandbox"),
        },
        "spec": { "additionalPodMetadata": {
            "labels": runtime_identity_labels(&opts.environment_id, &opts.org_id, opts.operation_generation, "workspace"),
        } },
    })))
}

fn runtime_ready(object: &DynamicObject, observed_generation: Option<i64>) -> bool {
    let Some(conditions) = object
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let mut ready = conditions
        .iter()
        .filter(|condition| condition.get("type").and_then(Value::as_str) == Some("Ready"));
    matches!((ready.next(), ready.next()), (Some(condition), None)
        if condition.get("status").and_then(Value::as_str) == Some("True")
            && observed_generation.is_none_or(|generation| generation > 0
                && condition.get("observedGeneration").and_then(Value::as_i64) == Some(generation)))
}

fn runtime_identity_converged(
    claim: &DynamicObject,
    sandbox: &DynamicObject,
    pod: &Pod,
    opts: &ClaimOpts,
) -> bool {
    let labels = runtime_identity_labels(
        &opts.environment_id,
        &opts.org_id,
        opts.operation_generation,
        "workspace",
    );
    let Some(generation) = sandbox.metadata.generation else {
        return false;
    };
    let Some(status) = &pod.status else {
        return false;
    };
    let conditions = status.conditions.as_deref().unwrap_or_default();
    let mut ready = conditions
        .iter()
        .filter(|condition| condition.type_ == "Ready");
    runtime_claim_labels_match(claim, opts)
        && json_labels_match(sandbox.data.pointer("/spec/podTemplate/metadata/labels"), &labels)
        && pod.metadata.labels.as_ref().is_some_and(|current| labels.iter().all(|(key, value)| current.get(key) == Some(value)))
        && runtime_ready(claim, None) // Claim Ready forwards the Sandbox generation.
        && runtime_ready(sandbox, Some(generation))
        && status.phase.as_deref() == Some("Running")
        && matches!((ready.next(), ready.next()), (Some(condition), None) if condition.status == "True")
}

/// The Sandbox's single `Ready` condition reports the current spec: its
/// `observedGeneration` equals `metadata.generation`, whatever its status. A
/// stale status could describe a Pod rendered from an older spec, which a
/// binding check would misread as an image mismatch.
fn sandbox_status_current(sandbox: &DynamicObject) -> bool {
    let Some(generation) = sandbox
        .metadata
        .generation
        .filter(|generation| *generation > 0)
    else {
        return false;
    };
    let Some(conditions) = sandbox
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let mut ready = conditions
        .iter()
        .filter(|condition| condition.get("type").and_then(Value::as_str) == Some("Ready"));
    matches!((ready.next(), ready.next()), (Some(condition), None)
        if condition.get("observedGeneration").and_then(Value::as_i64) == Some(generation))
}

/// Every container the Pod spec declares has started from a resolved image:
/// each regular container reports `started` with a non-empty `imageID`, and
/// each init container has a non-empty `imageID` and either completed
/// successfully or, as a restartable sidecar, started. Readiness is not
/// required, so a DinD container whose Docker daemon is still starting
/// counts.
pub(crate) fn pod_containers_started(pod: &Pod) -> bool {
    let (Some(spec), Some(status)) = (pod.spec.as_ref(), pod.status.as_ref()) else {
        return false;
    };
    let statuses = status.container_statuses.as_deref().unwrap_or_default();
    let init_statuses = status
        .init_container_statuses
        .as_deref()
        .unwrap_or_default();
    let resolved = |status: &ContainerStatus| !status.image_id.trim().is_empty();
    statuses.len() == spec.containers.len()
        && spec.containers.iter().all(|container| {
            statuses.iter().any(|status| {
                status.name == container.name && status.started == Some(true) && resolved(status)
            })
        })
        && init_statuses.len() == spec.init_containers.as_deref().unwrap_or_default().len()
        && spec.init_containers.iter().flatten().all(|container| {
            init_statuses.iter().any(|status| {
                status.name == container.name
                    && resolved(status)
                    && (status.started == Some(true)
                        || status
                            .state
                            .as_ref()
                            .and_then(|state| state.terminated.as_ref())
                            .is_some_and(|terminated| terminated.exit_code == 0))
            })
        })
}

/// Design §10 (amended): the record step's trigger, checked while the caller
/// still waits for Claim Ready. Claim Ready adds no security property beyond
/// label convergence, so it is not required here; it still gates MarkRunning
/// and setup. The exact UID chain and the absence of `deletionTimestamp` are
/// checked when the chain is read; images, the PVC, the credential scope and
/// the captured values by the recorder.
pub(crate) fn runtime_bind_ready(
    claim: &DynamicObject,
    sandbox: &DynamicObject,
    pod: &Pod,
    opts: &ClaimOpts,
) -> bool {
    let labels = runtime_identity_labels(
        &opts.environment_id,
        &opts.org_id,
        opts.operation_generation,
        "workspace",
    );
    runtime_claim_labels_match(claim, opts)
        && json_labels_match(
            sandbox.data.pointer("/spec/podTemplate/metadata/labels"),
            &labels,
        )
        && pod.metadata.labels.as_ref().is_some_and(|current| {
            labels
                .iter()
                .all(|(key, value)| current.get(key) == Some(value))
        })
        && claim.metadata.deletion_timestamp.is_none()
        && sandbox.metadata.deletion_timestamp.is_none()
        && pod.metadata.deletion_timestamp.is_none()
        && sandbox_status_current(sandbox)
        && pod
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            == Some("Running")
        && pod_containers_started(pod)
}

/// Namespaced client for SandboxClaim operations.
#[derive(Clone)]
pub struct SandboxClient {
    pub(crate) client: Client,
    pub(crate) namespace: String,
    claims: Api<DynamicObject>,
}

/// The labels a shared Sandbox namespace must carry: the Sandbox admission
/// policy and the cluster-wide Sandbox network policies select on them.
const SANDBOX_NAMESPACE_LABELS: [(&str, &str); 2] = [
    ("codewire.sh/resource-type", "sandbox"),
    ("codewire.sh/runtime-scope", "shared"),
];

fn sandbox_namespace_ready(
    name: &str,
    labels: Option<&BTreeMap<String, String>>,
) -> anyhow::Result<()> {
    let missing: Vec<String> = SANDBOX_NAMESPACE_LABELS
        .iter()
        .filter(|(key, value)| {
            labels
                .and_then(|labels| labels.get(*key))
                .map(String::as_str)
                != Some(*value)
        })
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    anyhow::ensure!(
        missing.is_empty(),
        "sandbox namespace {name} lacks {}; the cluster provisions it with these labels",
        missing.join(", ")
    );
    Ok(())
}

impl SandboxClient {
    /// Builds from the ambient kube config (in-cluster or KUBECONFIG),
    /// like the Go client's rest.InClusterConfig / kubeconfig fallback.
    pub async fn from_env(namespace: &str) -> anyhow::Result<Self> {
        let client = codewire_server_core::span_free::kube_client_default().await?;
        Ok(Self::new(client, namespace))
    }

    pub fn new(client: Client, namespace: &str) -> Self {
        let gvk = GroupVersionKind::gvk(EXTENSIONS_GROUP, CRD_VERSION, "SandboxClaim");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxclaims");
        Self {
            client: client.clone(),
            namespace: namespace.to_string(),
            claims: Api::namespaced_with(client, namespace, &resource),
        }
    }

    /// Checks that the shared Sandbox namespace exists and carries the labels
    /// the cluster's Sandbox admission and network policies select on.
    /// Orchestration never creates or relabels a namespace (codewire#2282):
    /// the cluster provisions it, and a namespace patch is exactly the
    /// authority that would let a compromised orchestration switch those
    /// policies off.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn ensure_namespace(&self) -> anyhow::Result<()> {
        let namespaces: Api<Namespace> = Api::all(self.client.clone());
        let name = &self.namespace;
        let namespace = match namespaces.get(name).await {
            Ok(namespace) => namespace,
            Err(kube::Error::Api(e)) if e.code == 404 => anyhow::bail!(
                "sandbox namespace {name} does not exist; the cluster provisions it with its labels"
            ),
            Err(e) => anyhow::bail!("get namespace {name}: {e}"),
        };
        sandbox_namespace_ready(name, namespace.metadata.labels.as_ref())
    }

    /// Whether this client's namespace exists. Destroy uses it to skip a
    /// namespace an older release recorded that is gone: orchestration has no
    /// authority outside the shared Sandbox namespace, so it cannot even list
    /// a missing one (codewire#2282).
    pub async fn namespace_exists(&self) -> anyhow::Result<bool> {
        let namespaces: Api<Namespace> = Api::all(self.client.clone());
        namespaces
            .get_opt(&self.namespace)
            .await
            .map(|namespace| namespace.is_some())
            .map_err(|e| anyhow::anyhow!("get namespace {}: {e}", self.namespace))
    }

    /// The Sandbox the environment's Claim is bound to, by the Claim's
    /// `status.sandbox.name`. There is no name fallback: a Claim that names
    /// no Sandbox has no runtime, and adoption makes the Sandbox name a pool
    /// member's rather than `sandbox-<env>` (Program #2238 design §12).
    pub async fn bound_sandbox_name(&self, env_id: &str) -> anyhow::Result<String> {
        let claim = self
            .get_sandbox_claim(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("resolve sandbox name: {e}"))?;
        let Some(claim) = claim else {
            anyhow::bail!("resolve sandbox name: SandboxClaim not found for env {env_id}");
        };
        claim_bound_sandbox_name(&claim)
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("resolve sandbox name: SandboxClaim is not bound"))
    }

    /// The current workspace Pod's name: the bound Sandbox's
    /// controller-published `agents.x-k8s.io/pod-name`, else the Sandbox
    /// name, exactly as the runtime identity chain resolves it. Never the
    /// Claim's name.
    pub async fn get_pod_name(&self, env_id: &str) -> anyhow::Result<String> {
        let sandbox_name = self.bound_sandbox_name(env_id).await?;
        let sandbox = self
            .sandboxes()
            .get(&sandbox_name)
            .await
            .map_err(|e| anyhow::anyhow!("resolve workspace Pod name: get Sandbox: {e}"))?;
        Ok(sandbox_pod_name(&sandbox, &sandbox_name).to_owned())
    }

    /// Resolve the exact workspace Pod incarnation. Pod names are reused when
    /// a Sandbox is suspended and resumed, so setup fencing compares UIDs.
    pub async fn get_workspace_pod_identity(
        &self,
        env_id: &str,
    ) -> anyhow::Result<Option<WorkspacePodIdentity>> {
        let pod_name = self.get_pod_name(env_id).await?;
        self.get_workspace_pod_identity_by_name(&pod_name).await
    }

    /// The exact current workspace Pod: Claim → bound Sandbox → its Pod name
    /// → a Pod that Sandbox controls. Once the environment is bound
    /// (`bound_pod_uid`), the Pod must be that exact incarnation; a replaced
    /// Pod under the same name is refused until its own binding is recorded.
    pub async fn current_workspace_pod(
        &self,
        env_id: &str,
        bound_pod_uid: Option<&str>,
    ) -> anyhow::Result<WorkspacePodIdentity> {
        let pod = self.current_workspace_pod_object(env_id).await?;
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let pod_uid = pod.metadata.uid.clone().unwrap_or_default();
        anyhow::ensure!(
            bound_pod_uid.is_none_or(|bound| bound == pod_uid),
            "workspace Pod is not the bound incarnation"
        );
        Ok(WorkspacePodIdentity {
            name: pod_name,
            uid: pod_uid,
        })
    }

    /// The current workspace Pod object through the same exact chain as
    /// [`Self::current_workspace_pod`], for callers that inspect its spec.
    pub async fn current_workspace_pod_object(&self, env_id: &str) -> anyhow::Result<Pod> {
        let sandbox_name = self.bound_sandbox_name(env_id).await?;
        let sandbox = self
            .sandboxes()
            .get(&sandbox_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace Sandbox is unavailable"))?;
        let sandbox_uid = runtime_object_uid(&sandbox.metadata, &self.namespace, &sandbox_name)?;
        let pod_name = sandbox_pod_name(&sandbox, &sandbox_name);
        let pod = self
            .pods()
            .get(pod_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace Pod is unavailable"))?;
        runtime_object_uid(&pod.metadata, &self.namespace, pod_name)?;
        require_runtime_controller(
            &pod.metadata,
            "agents.x-k8s.io/v1beta1",
            "Sandbox",
            &sandbox_name,
            sandbox_uid,
        )?;
        Ok(pod)
    }

    pub async fn get_workspace_pod_identity_by_name(
        &self,
        pod_name: &str,
    ) -> anyhow::Result<Option<WorkspacePodIdentity>> {
        match self.pods().get(pod_name).await {
            Ok(pod) => Ok(Some(WorkspacePodIdentity {
                name: pod.metadata.name.unwrap_or_else(|| pod_name.to_string()),
                uid: pod.metadata.uid.unwrap_or_default(),
            })),
            Err(kube::Error::Api(error)) if error.code == 404 => Ok(None),
            Err(error) => Err(anyhow::anyhow!("get workspace Pod {pod_name}: {error}")),
        }
    }

    /// Read the runtime facts that determine whether CPU/memory can be
    /// changed without replacing or restarting the workspace container, from
    /// the Pod the environment's current Sandbox controls.
    pub async fn workspace_pod_resize_state(
        &self,
        env_id: &str,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        let pod = self.current_workspace_pod_object(env_id).await?;
        workspace_pod_resize_state(&pod, "")
    }

    /// Apply CPU and memory through the Kubernetes Pod `/resize` subresource
    /// and wait for the kubelet-reported resources to converge. This path
    /// never deletes the Pod and fails if its identity or restart count moves.
    pub async fn resize_workspace_pod_in_place(
        &self,
        env_id: &str,
        expected_uid: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        if expected_uid.trim().is_empty() {
            anyhow::bail!("expected workspace Pod UID is required");
        }
        if cpu_millicores <= 0 || memory_mb <= 0 {
            anyhow::bail!("workspace CPU and memory must be greater than zero");
        }
        let accepted = self
            .submit_workspace_pod_resize(env_id, expected_uid, cpu_millicores, memory_mb)
            .await?;
        self.wait_for_workspace_pod_resize(&accepted, timeout).await
    }

    /// Submit a `/resize` request bound to the exact Pod incarnation the
    /// environment's current Sandbox controls. A refusal because the Pod
    /// changed re-resolves it through the Sandbox and rechecks its identity
    /// and resize policy before submitting again.
    async fn submit_workspace_pod_resize(
        &self,
        env_id: &str,
        expected_uid: &str,
        cpu_millicores: i32,
        memory_mb: i32,
    ) -> anyhow::Result<AcceptedPodResize> {
        for _ in 0..POD_RESIZE_SUBMIT_ATTEMPTS {
            let pod = self.current_workspace_pod_object(env_id).await?;
            let compute =
                WorkspaceCompute::new(cpu_millicores, memory_mb, workspace_pod_cpu_sharing(&pod));
            if let Some(accepted) = self
                .submit_pod_resize_once(&pod, expected_uid, &compute)
                .await?
            {
                return Ok(accepted);
            }
        }
        anyhow::bail!(
            "workspace Pod changed before each of {POD_RESIZE_SUBMIT_ATTEMPTS} live resize submissions; nothing was resized"
        )
    }

    /// One `/resize` request conditioned on `pod`, the observed incarnation.
    /// The patch carries its UID and resourceVersion, which the API server
    /// enforces: a replacement under the same name, or any change since the
    /// observation, is refused without mutation (`Ok(None)`).
    async fn submit_pod_resize_once(
        &self,
        pod: &Pod,
        expected_uid: &str,
        compute: &WorkspaceCompute,
    ) -> anyhow::Result<Option<AcceptedPodResize>> {
        let before = workspace_pod_resize_state(pod, "")?;
        if before.identity.uid != expected_uid {
            anyhow::bail!(
                "workspace Pod was replaced before live resize: expected UID {expected_uid}, got {}",
                before.identity.uid
            );
        }
        if !before.live_resize_compatible {
            anyhow::bail!(
                "workspace container cannot be resized live: {}",
                before
                    .incompatibility_reason
                    .as_deref()
                    .unwrap_or("incompatible resize policy")
            );
        }
        let resource_version = pod
            .metadata
            .resource_version
            .as_deref()
            .filter(|version| !version.is_empty())
            .ok_or_else(|| anyhow::anyhow!("workspace Pod has no resourceVersion"))?;
        let patch = pod_resize_patch(expected_uid, resource_version, compute);
        match self
            .pods()
            .patch_resize(
                &before.identity.name,
                &PatchParams::default(),
                &Patch::Strategic(&patch),
            )
            .await
        {
            Ok(accepted) => Ok(Some(AcceptedPodResize {
                before,
                compute: compute.clone(),
                generation: accepted.metadata.generation.filter(|value| *value > 0),
            })),
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(None),
            Err(error) => anyhow::bail!(
                "resize workspace Pod {} through /resize: {error}",
                before.identity.name
            ),
        }
    }

    /// Wait until the kubelet reports the requested resources on the same
    /// incarnation. A failure condition counts only while the Pod still asks
    /// for this request and its generation acknowledges it; an older or
    /// unacknowledged one keeps the wait going, and is named if the wait
    /// times out.
    async fn wait_for_workspace_pod_resize(
        &self,
        accepted: &AcceptedPodResize,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        let before = &accepted.before;
        let compute = &accepted.compute;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let pod = self
                .pods()
                .get(&before.identity.name)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "observe resized workspace Pod {}: {error}",
                        before.identity.name
                    )
                })?;
            let observed = workspace_pod_resize_state(&pod, &before.identity.name)?;
            if observed.identity.uid != before.identity.uid {
                anyhow::bail!(
                    "workspace Pod was replaced during live resize: expected UID {}, got {}",
                    before.identity.uid,
                    observed.identity.uid
                );
            }
            if observed.restart_count != before.restart_count {
                anyhow::bail!(
                    "workspace container restarted during live resize: restart count changed from {} to {}",
                    before.restart_count,
                    observed.restart_count
                );
            }
            let infeasible = infeasible_pod_resize(&pod, accepted.generation);
            if let Some((message, true)) = &infeasible
                && workspace_spec_resources_match(&pod, compute)
            {
                return Err(PodResizeInfeasible(message.clone()).into());
            }
            if workspace_resources_match(&pod, compute)
                && pod_resize_acknowledged(&pod, accepted.generation)
            {
                return Ok(observed);
            }
            if tokio::time::Instant::now() >= deadline {
                let unacknowledged = infeasible
                    .map(|(message, _)| {
                        format!("; an earlier or unacknowledged request is reported infeasible: {message}")
                    })
                    .unwrap_or_default();
                anyhow::bail!(
                    "timeout waiting for workspace Pod {} live resize to converge{unacknowledged}",
                    before.identity.name
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Settle what a failed resize left on the workspace Pod incarnation it
    /// may have asked to resize. An applied request is kept. A pending one is
    /// withdrawn by a preconditioned `/resize` back to the previous CPU and
    /// memory on that same incarnation; if the Pod changes first, it is
    /// classified again, so an increase that lands meanwhile is kept rather
    /// than shrunk. Another incarnation is never mutated: a replaced,
    /// terminating or unreadable Pod is `Unknown`.
    pub async fn settle_failed_live_resize(
        &self,
        env_id: &str,
        expected_uid: &str,
        previous: (i32, i32),
        requested: (i32, i32),
        timeout: Duration,
    ) -> FailedLiveResize {
        let mut withdrawal = None;
        for _ in 0..POD_RESIZE_SUBMIT_ATTEMPTS {
            let pod = match self.observe_failed_live_resize(env_id, expected_uid).await {
                Ok(pod) => pod,
                Err(error) => return FailedLiveResize::Unknown(format!("{error:#}")),
            };
            if let Some(outcome) = failed_live_resize_outcome(&pod, previous, requested) {
                return outcome;
            }
            if let Some(error) = withdrawal {
                return FailedLiveResize::Unknown(format!(
                    "withdrawing the pending request did not settle: {error:#}"
                ));
            }
            let compute =
                WorkspaceCompute::new(previous.0, previous.1, workspace_pod_cpu_sharing(&pod));
            let accepted = match self
                .submit_pod_resize_once(&pod, expected_uid, &compute)
                .await
            {
                Ok(Some(accepted)) => accepted,
                Ok(None) => continue,
                Err(error) => {
                    withdrawal = Some(error);
                    continue;
                }
            };
            match self.wait_for_workspace_pod_resize(&accepted, timeout).await {
                Ok(_) => return FailedLiveResize::Settled,
                Err(error) => withdrawal = Some(error),
            }
        }
        FailedLiveResize::Unknown(match withdrawal {
            Some(error) => format!("withdrawing the pending request did not settle: {error:#}"),
            None => "the workspace Pod changed during every withdrawal attempt".into(),
        })
    }

    async fn observe_failed_live_resize(
        &self,
        env_id: &str,
        expected_uid: &str,
    ) -> anyhow::Result<Pod> {
        let pod = self.current_workspace_pod_object(env_id).await?;
        let uid = pod.metadata.uid.as_deref().unwrap_or_default();
        anyhow::ensure!(
            uid == expected_uid,
            "the workspace Pod was replaced (UID {uid}, expected {expected_uid}) and is not compensated"
        );
        Ok(pod)
    }

    /// Enumerate every Pod carrying the stable environment label. Recovery
    /// proves environment-wide absence because a replacement may use another
    /// Pod name.
    pub async fn list_workspace_pod_identities(
        &self,
        env_id: &str,
    ) -> anyhow::Result<Vec<WorkspacePodIdentity>> {
        let selector = workspace_pod_selector(env_id);
        let pods = self
            .pods()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| anyhow::anyhow!("list workspace Pods for {env_id}: {error}"))?;
        Ok(pods
            .items
            .into_iter()
            .map(|pod| WorkspacePodIdentity {
                name: pod.metadata.name.unwrap_or_default(),
                uid: pod.metadata.uid.unwrap_or_default(),
            })
            .collect())
    }

    /// Return the exact terminal Pod incarnation that an explicit product
    /// retry must replace. A healthy or still-progressing Pod is never a
    /// replacement candidate.
    pub async fn workspace_pod_replacement_candidate(
        &self,
        env_id: &str,
    ) -> anyhow::Result<Option<WorkspacePodIdentity>> {
        let selector = workspace_pod_selector(env_id);
        let mut pods = self
            .pods()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| anyhow::anyhow!("list workspace Pods before retry: {error}"))?
            .items;
        if pods.is_empty() {
            return Ok(None);
        }
        if pods.len() != 1 {
            anyhow::bail!(
                "refusing product retry with {} workspace Pods for environment {env_id}",
                pods.len()
            );
        }
        let pod = pods.pop().expect("one workspace Pod remains");
        if !pod_requires_product_replacement(&pod) {
            return Ok(None);
        }
        let name = pod
            .metadata
            .name
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("terminal workspace Pod has no name"))?;
        let uid = pod
            .metadata
            .uid
            .filter(|uid| !uid.is_empty())
            .ok_or_else(|| anyhow::anyhow!("terminal workspace Pod {name} has no UID"))?;
        Ok(Some(WorkspacePodIdentity { name, uid }))
    }

    /// Delete one observed workspace Pod and wait for its ready replacement.
    ///
    /// This is a long-lived orchestration operation. Callers must not wrap it
    /// in the worker's short external-mutation guard; worker paths instead
    /// guard `delete_workspace_pod_if_uid` and then observe
    /// `wait_for_replacement_workspace_pod` separately.
    pub async fn delete_and_wait_for_replacement_workspace_pod(
        &self,
        env_id: &str,
        known_pod_name: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodIdentity> {
        let pod_name = match known_pod_name.filter(|name| !name.trim().is_empty()) {
            Some(name) => name.to_string(),
            None => self.get_pod_name(env_id).await?,
        };
        let old = self
            .get_workspace_pod_identity_by_name(&pod_name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("workspace Pod {pod_name} not found"))?;

        self.delete_workspace_pod_if_uid(&pod_name, &old.uid)
            .await?;
        self.wait_for_replacement_workspace_pod(&pod_name, &old.uid, timeout)
            .await
    }

    /// Replace one running workspace Pod incarnation on the current daemon:
    /// re-pin its Sandbox's daemon image ([`Self::repin_daemon_image`]), then
    /// delete the Pod with its UID precondition, so the controller builds the
    /// replacement from the re-pinned spec. Daemon repair, restart-mode resize
    /// and terminal-Pod replacement replace Pods this way.
    ///
    /// The Pod is read again immediately before the re-pin patch. Gone, or
    /// carrying another UID, it was already replaced from the Sandbox's
    /// current spec: neither the re-pin nor the delete happens, and the
    /// caller treats [`WorkspacePodReplacement::AlreadyReplaced`] as a
    /// replacement. The next Start or repair re-pins.
    pub async fn replace_workspace_pod_if_uid(
        &self,
        env_id: &str,
        pod_name: &str,
        previous_uid: &str,
        support_image: &str,
    ) -> anyhow::Result<WorkspacePodReplacement> {
        if pod_name.trim().is_empty() {
            anyhow::bail!("workspace Pod name is required");
        }
        if previous_uid.trim().is_empty() {
            anyhow::bail!("previous workspace Pod UID is required");
        }
        if !self.workspace_pod_has_uid(pod_name, previous_uid).await? {
            return Ok(WorkspacePodReplacement::AlreadyReplaced);
        }
        let repin = self
            .repin_daemon_image_before_replacement(
                env_id,
                support_image,
                Some((pod_name, previous_uid)),
            )
            .await?;
        if repin == DaemonImageRepinOutcome::PodReplaced {
            return Ok(WorkspacePodReplacement::AlreadyReplaced);
        }
        if self
            .delete_observed_workspace_pod(pod_name, previous_uid)
            .await?
        {
            return Ok(WorkspacePodReplacement::Replaced);
        }
        if repin == DaemonImageRepinOutcome::Repinned {
            // The Pod went between the read above and the re-pin: its
            // replacement may have been built from the earlier spec. Its
            // daemon copy then differs from the Sandbox, so an unbound one
            // fails its binding check and is rebuilt once; an image-volume
            // daemon runs until the next Start or repair re-pins.
            tracing::info!(
                pod = pod_name,
                previous_uid,
                "workspace Pod was replaced while its Sandbox's daemon image was re-pinned"
            );
        }
        Ok(WorkspacePodReplacement::AlreadyReplaced)
    }

    /// Whether the workspace Pod named `pod_name` exists with `uid`.
    /// Whether this exact Sandbox's live Pod mounted its Block workspace
    /// (#3718): the Pod it published, owned by its UID, whose
    /// `mount-workspace` exited 0. No such Pod is no evidence.
    async fn sandbox_pod_mounted_workspace(
        &self,
        sandbox: &DynamicObject,
        sandbox_name: &str,
    ) -> anyhow::Result<bool> {
        let Some(uid) = sandbox.metadata.uid.as_deref() else {
            return Ok(false);
        };
        let pod = self
            .pods()
            .get_opt(sandbox_pod_name(sandbox, sandbox_name))
            .await
            .map_err(|error| anyhow::anyhow!("read workspace Pod of {sandbox_name}: {error}"))?;
        Ok(pod.as_ref().is_some_and(|pod| {
            pod.metadata
                .owner_references
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|owner| owner.uid == uid && owner.controller == Some(true))
                && workspace_mounted(pod)
        }))
    }

    /// The patch that makes a Block workspace `existing` once this Sandbox's
    /// live Pod has mounted it; empty otherwise.
    async fn workspace_volume_existing_patch(
        &self,
        sandbox: &DynamicObject,
        sandbox_name: &str,
        index: usize,
    ) -> anyhow::Result<Vec<Value>> {
        let mounted = self
            .sandbox_pod_mounted_workspace(sandbox, sandbox_name)
            .await?;
        workspace_volume_existing(sandbox, index, mounted)
    }

    async fn workspace_pod_has_uid(&self, pod_name: &str, uid: &str) -> anyhow::Result<bool> {
        Ok(self
            .get_workspace_pod_identity_by_name(pod_name)
            .await?
            .is_some_and(|pod| pod.uid == uid))
    }

    /// Re-pin the bound Sandbox's daemon image ([`plan_daemon_image`]) and
    /// re-render a legacy DinD bootstrap ([`dind_bootstrap_refresh`]) while it
    /// stays Running, before its Pod is replaced. The controller never
    /// rewrites a running Pod, so this changes only the next one. The patch
    /// carries no operating mode: it tests the Sandbox's UID and
    /// resourceVersion and each entry, then replaces only its image or script.
    /// The controller keeps updating a running Sandbox's status, so a
    /// conflicting write is read and planned again, at most
    /// [`DAEMON_REPIN_ATTEMPTS`] times, and only for the first observed UID.
    pub async fn repin_daemon_image(
        &self,
        env_id: &str,
        support_image: &str,
    ) -> anyhow::Result<()> {
        self.repin_daemon_image_before_replacement(env_id, support_image, None)
            .await
            .map(|_| ())
    }

    /// [`Self::repin_daemon_image`], and when `pod` names the incarnation
    /// about to be replaced, a read of that Pod immediately before each patch.
    async fn repin_daemon_image_before_replacement(
        &self,
        env_id: &str,
        support_image: &str,
        pod: Option<(&str, &str)>,
    ) -> anyhow::Result<DaemonImageRepinOutcome> {
        let name = self.bound_sandbox_name(env_id).await?;
        let sandboxes = self.sandboxes();
        let mut incarnation: Option<String> = None;
        let mut conflict = String::new();
        for _ in 0..DAEMON_REPIN_ATTEMPTS {
            let sandbox = sandboxes
                .get(&name)
                .await
                .map_err(|e| anyhow::anyhow!("get Sandbox {name}: {e}"))?;
            let uid = runtime_object_uid(&sandbox.metadata, &self.namespace, &name)?.to_owned();
            anyhow::ensure!(
                *incarnation.get_or_insert_with(|| uid.clone()) == uid,
                "Sandbox {name} was replaced during its daemon image re-pin"
            );
            let version = sandbox
                .metadata
                .resource_version
                .as_deref()
                .filter(|version| !version.is_empty())
                .ok_or_else(|| anyhow::anyhow!("Sandbox {name} has no resource version"))?;
            let repin = daemon_image_repin(&sandbox, support_image)?;
            let dind = dind_bootstrap_refresh(&sandbox, support_image)?;
            // Once the Pod being replaced has mounted its workspace, the next
            // one's volume is never new (#3718).
            let block = match block_workspace(&sandbox)? {
                Some(index) => {
                    self.workspace_volume_existing_patch(&sandbox, &name, index)
                        .await?
                }
                None => Vec::new(),
            };
            if repin.is_none() && dind.is_none() && block.is_empty() {
                return Ok(DaemonImageRepinOutcome::Unchanged);
            }
            if let Some((pod_name, pod_uid)) = pod
                && !self.workspace_pod_has_uid(pod_name, pod_uid).await?
            {
                return Ok(DaemonImageRepinOutcome::PodReplaced);
            }
            let mut operations = vec![
                serde_json::json!({"op":"test","path":"/metadata/uid","value":uid}),
                serde_json::json!({"op":"test","path":"/metadata/resourceVersion","value":version}),
            ];
            operations.extend(
                repin
                    .iter()
                    .flat_map(|repin| repin.operations.iter().cloned()),
            );
            operations.extend(dind.iter().flatten().cloned());
            operations.extend(block);
            let patch = Patch::Json::<()>(serde_json::from_value(Value::Array(operations))?);
            match sandboxes
                .patch(&name, &PatchParams::default(), &patch)
                .await
            {
                Ok(updated) => {
                    anyhow::ensure!(
                        runtime_object_uid(&updated.metadata, &self.namespace, &name)? == uid,
                        "Sandbox {name} was replaced during its daemon image re-pin"
                    );
                    if let Some(repin) = &repin {
                        log_daemon_image_repin(&updated, &name, repin, support_image);
                    }
                    if dind.is_some() {
                        log_dind_bootstrap_refresh(&name);
                    }
                    return Ok(DaemonImageRepinOutcome::Repinned);
                }
                // A failed `test` is 422; an apiserver conflict is 409.
                Err(kube::Error::Api(status)) if matches!(status.code, 409 | 422) => {
                    conflict = kube::Error::Api(status).to_string();
                }
                Err(error) => {
                    anyhow::bail!("re-pin Sandbox {name} daemon image: {error}")
                }
            }
        }
        anyhow::bail!("re-pin Sandbox {name} daemon image kept conflicting: {conflict}")
    }

    /// Delete the old workspace incarnation only when it still has the
    /// checkpointed UID. A retried operation must never delete the replacement.
    pub async fn delete_workspace_pod_if_uid(
        &self,
        pod_name: &str,
        previous_uid: &str,
    ) -> anyhow::Result<()> {
        if pod_name.trim().is_empty() {
            anyhow::bail!("workspace Pod name is required");
        }
        if previous_uid.trim().is_empty() {
            anyhow::bail!("previous workspace Pod UID is required");
        }
        self.delete_observed_workspace_pod(pod_name, previous_uid)
            .await
            .map(|_| ())
    }

    /// Delete the Pod only when it still has `previous_uid`. True when this
    /// call deleted that incarnation; false when it was already gone or
    /// replaced.
    async fn delete_observed_workspace_pod(
        &self,
        pod_name: &str,
        previous_uid: &str,
    ) -> anyhow::Result<bool> {
        let Some(current) = self.get_workspace_pod_identity_by_name(pod_name).await? else {
            return Ok(false);
        };
        if current.uid != previous_uid {
            return Ok(false);
        }

        let delete_params = delete_params_for_observed_uid(previous_uid);
        match self.pods().delete(&current.name, &delete_params).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(error)) if error.code == 404 => Ok(false),
            // A replacement won the race after the observation above. The
            // UID precondition prevented deleting it; the caller can now
            // observe that replacement normally.
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(false),
            Err(error) => Err(anyhow::anyhow!(
                "restart workspace Pod {}: {error}",
                current.name
            )),
        }
    }

    /// Wait until the owning Sandbox controller has produced a ready
    /// incarnation of the same stable Pod name with a different UID. Match
    /// the stable Pod name instead of relying only on an environment label.
    pub async fn wait_for_replacement_workspace_pod(
        &self,
        pod_name: &str,
        previous_uid: &str,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodIdentity> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.pods().get(pod_name).await {
                Ok(pod) => {
                    let name = pod.metadata.name.unwrap_or_default();
                    let uid = pod.metadata.uid.unwrap_or_default();
                    let ready = pod
                        .status
                        .as_ref()
                        .is_some_and(|status| status.phase.as_deref() == Some("Running"))
                        && pod
                            .status
                            .as_ref()
                            .and_then(|status| status.container_statuses.as_ref())
                            .is_some_and(|statuses| {
                                statuses
                                    .iter()
                                    .find(|status| status.name == "workspace")
                                    .is_some_and(|status| status.ready)
                            });
                    if !uid.is_empty() && uid != previous_uid && ready {
                        return Ok(WorkspacePodIdentity { name, uid });
                    }
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "get replacement workspace Pod {pod_name}: {error}"
                    ));
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("timeout waiting for replacement workspace Pod {pod_name}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Publish the measured confidential Pod template (B2c) into the private
    /// template and the allocated Sandbox before replacing a terminal Pod, and
    /// return the init-data the replacement must carry. Updating the
    /// SandboxTemplate alone is insufficient because the controller does not
    /// rewrite an already-created Sandbox.
    pub async fn reconcile_per_environment_runtime(
        &self,
        env_id: &str,
        expected_pod_name: &str,
        opts: &TemplateOpts,
    ) -> anyhow::Result<String> {
        if opts.environment_id != env_id {
            anyhow::bail!("runtime template environment does not match retry environment");
        }
        if !opts.name.ends_with(&format!("-{env_id}")) {
            anyhow::bail!("refusing to update a shared runtime template before Pod replacement");
        }

        let claim = self
            .get_sandbox_claim(env_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("SandboxClaim {} not found", claim_name(env_id)))?;
        let sandbox_name = claim
            .data
            .pointer("/status/sandbox/name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("SandboxClaim has no allocated Sandbox"))?;
        if sandbox_name != expected_pod_name {
            anyhow::bail!("workspace Pod does not match the allocated Sandbox");
        }
        let warm_pool_name = claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("SandboxClaim has no shadow-pool reference"))?;
        let warm_pool = self
            .warm_pools()
            .get(warm_pool_name)
            .await
            .map_err(|error| anyhow::anyhow!("get SandboxWarmPool {warm_pool_name}: {error}"))?;
        let template_name = warm_pool
            .data
            .pointer("/spec/sandboxTemplateRef/name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("SandboxWarmPool has no template reference"))?;
        if template_name != opts.name {
            anyhow::bail!("refusing to update a runtime template not owned by this environment");
        }

        let sandboxes = self.sandboxes();
        sandboxes
            .get(sandbox_name)
            .await
            .map_err(|error| anyhow::anyhow!("get Sandbox {sandbox_name}: {error}"))?;
        let measured = MeasuredPodTemplate::render(&self.namespace, opts)?;
        self.ensure_sandbox_template(opts).await?;
        let updated = sandboxes
            .patch(
                sandbox_name,
                &PatchParams::default(),
                &Patch::Merge(&measured.merge_patch()),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("patch Sandbox {sandbox_name} measured runtime: {error}")
            })?;
        anyhow::ensure!(
            measured.published_on(&updated),
            "the Sandbox did not take the measured runtime"
        );
        Ok(measured.init_data().to_owned())
    }

    /// Wait for agent-sandbox to propagate the desired runtime annotation to
    /// the exact terminal Pod incarnation. This is the observable barrier
    /// proving a subsequently recreated Pod will use the updated Sandbox.
    pub async fn wait_for_workspace_pod_annotation(
        &self,
        pod_name: &str,
        expected_uid: &str,
        annotation_key: &str,
        expected_value: &str,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        if pod_name.trim().is_empty() || expected_uid.trim().is_empty() {
            anyhow::bail!("workspace Pod name and UID are required");
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let pod = match self.pods().get(pod_name).await {
                Ok(pod) => pod,
                Err(kube::Error::Api(error)) if error.code == 404 => {
                    anyhow::bail!("workspace Pod disappeared before runtime metadata propagated")
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "get workspace Pod {pod_name} during runtime reconciliation: {error}"
                    ));
                }
            };
            if pod.metadata.uid.as_deref() != Some(expected_uid) {
                anyhow::bail!("workspace Pod changed before runtime metadata propagated");
            }
            if pod
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(annotation_key))
                .is_some_and(|value| value == expected_value)
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("timeout waiting for workspace Pod runtime metadata propagation");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Publish only the existing operation's association labels onto the exact
    /// DB-bound Claim. The worker holds its ActivityAuthority row fence while
    /// this short mutation runs. Controller propagation is a separate wait.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %opts.environment_id))]
    pub async fn reconcile_claim_runtime_identity(
        &self,
        opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<()> {
        let claim = self
            .claims
            .get(expected_claim_name)
            .await
            .map_err(|_| anyhow::anyhow!("runtime identity Claim is unavailable"))?;
        require_runtime_claim(
            &claim,
            &self.namespace,
            opts,
            expected_claim_name,
            expected_claim_uid,
        )?;
        let Some(patch) = runtime_claim_identity_patch(&claim, opts)? else {
            return Ok(());
        };
        // Both resourceVersion and UID are fixed from the validated read.
        // Conflicts return to the authority-owning caller; never retry a blind
        // same-name replacement or copy a newer object's resourceVersion.
        let updated = self
            .claims
            .patch(
                expected_claim_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
            .map_err(|_| anyhow::anyhow!("runtime identity Claim update was not admitted"))?;
        require_runtime_claim(
            &updated,
            &self.namespace,
            opts,
            expected_claim_name,
            expected_claim_uid,
        )?;
        anyhow::ensure!(
            runtime_claim_labels_match(&updated, opts),
            "runtime identity Claim update did not converge"
        );
        Ok(())
    }

    async fn read_owned_claim_sandbox(
        &self,
        opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<(DynamicObject, DynamicObject)> {
        let claim = self
            .claims
            .get(expected_claim_name)
            .await
            .map_err(|_| anyhow::anyhow!("runtime identity Claim is unavailable"))?;
        require_runtime_claim(
            &claim,
            &self.namespace,
            opts,
            expected_claim_name,
            expected_claim_uid,
        )?;
        let sandbox_name = claim
            .data
            .pointer("/status/sandbox/name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("runtime identity Sandbox is not bound"))?;
        let sandbox = self
            .sandboxes()
            .get(sandbox_name)
            .await
            .map_err(|_| anyhow::anyhow!("runtime identity Sandbox is unavailable"))?;
        anyhow::ensure!(
            sandbox
                .types
                .as_ref()
                .is_some_and(|types| types.api_version == "agents.x-k8s.io/v1beta1"
                    && types.kind == "Sandbox"),
            "runtime identity Sandbox type does not match"
        );
        runtime_object_uid(&sandbox.metadata, &self.namespace, sandbox_name)?;
        require_runtime_controller(
            &sandbox.metadata,
            super::EXTENSIONS_API_VERSION,
            "SandboxClaim",
            expected_claim_name,
            expected_claim_uid,
        )?;
        Ok((claim, sandbox))
    }

    /// Controller-observed suspension is independent of source metadata. The
    /// caller still waits for every previously observed Pod UID to disappear,
    /// retaining this exact Sandbox identity for refresh and resume.
    pub async fn workspace_suspension_observed(
        &self,
        opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<Option<WorkspaceSandboxIdentity>> {
        let (_, sandbox) = self
            .read_owned_claim_sandbox(opts, expected_claim_name, expected_claim_uid)
            .await?;
        Ok(
            sandbox_suspension_observed(&sandbox).then(|| WorkspaceSandboxIdentity {
                name: sandbox.metadata.name.expect("validated Sandbox name"),
                uid: sandbox.metadata.uid.expect("validated Sandbox UID"),
            }),
        )
    }

    async fn read_claim_runtime_identity(
        &self,
        opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<RuntimeIdentitySnapshot> {
        let (claim, sandbox) = self
            .read_owned_claim_sandbox(opts, expected_claim_name, expected_claim_uid)
            .await?;
        let sandbox_name = sandbox
            .metadata
            .name
            .as_deref()
            .expect("validated Sandbox name");
        let sandbox_uid = sandbox
            .metadata
            .uid
            .as_deref()
            .expect("validated Sandbox UID");
        let pod_name = sandbox
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get("agents.x-k8s.io/pod-name"))
            .map(String::as_str)
            .unwrap_or(sandbox_name);
        let pod = self
            .pods()
            .get(pod_name)
            .await
            .map_err(|_| anyhow::anyhow!("runtime identity Pod is unavailable"))?;
        let pod_uid = runtime_object_uid(&pod.metadata, &self.namespace, pod_name)?;
        require_runtime_controller(
            &pod.metadata,
            "agents.x-k8s.io/v1beta1",
            "Sandbox",
            sandbox_name,
            sandbox_uid,
        )?;
        let observation = RuntimeIdentityObservation {
            sandbox_uid: sandbox_uid.to_owned(),
            pod: WorkspacePodIdentity {
                name: pod_name.to_owned(),
                uid: pod_uid.to_owned(),
            },
        };
        Ok(RuntimeIdentitySnapshot {
            claim,
            sandbox,
            pod,
            observation,
        })
    }

    async fn read_workspace_bootstrap(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<WorkspaceBootstrapSnapshot> {
        anyhow::ensure!(
            !opts.environment_id.is_empty()
                && opts.environment_id.trim() == opts.environment_id
                && !opts.organization_id.is_empty()
                && opts.operation_generation > 0
                && opts.name.ends_with(&format!("-{}", opts.environment_id)),
            "workspace bootstrap authority is incomplete"
        );
        let claim_opts = ClaimOpts {
            environment_id: opts.environment_id.clone(),
            org_id: opts.organization_id.clone(),
            operation_generation: opts.operation_generation,
            ..Default::default()
        };
        let (claim, sandbox) = self
            .read_owned_claim_sandbox(&claim_opts, expected_claim_name, expected_claim_uid)
            .await?;
        let selected = claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if super::warm_pool::is_warm_pool_name(selected) {
            return self.read_shared_pool_bootstrap(selected, sandbox).await;
        }
        let pool_name = super::shadow_warm_pool_name(&opts.name);
        anyhow::ensure!(
            selected == pool_name,
            "workspace bootstrap Claim does not select its environment shadow"
        );
        // A later cold allocation must not overwrite the immutable bootstrap
        // with a competing claim-level environment override.
        if let Some(overrides) = claim.data.pointer("/spec/env") {
            let overrides = overrides
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("workspace Claim overrides are malformed"))?;
            anyhow::ensure!(
                !overrides.iter().any(|entry| matches!(
                    entry.get("containerName").and_then(Value::as_str),
                    None | Some("" | "workspace")
                ) && entry
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| WORKSPACE_OWNED_ENVIRONMENT.contains(&name))),
                "workspace bootstrap cannot be overridden by the Claim"
            );
        }
        let pool = self
            .warm_pools()
            .get(&pool_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace environment shadow is unavailable"))?;
        require_bootstrap_object(&pool, &self.namespace, &pool_name, "SandboxWarmPool")?;
        anyhow::ensure!(
            pool.metadata
                .labels
                .as_ref()
                .is_some_and(
                    |labels| labels.get(LABEL_ENV_ID) == Some(&opts.environment_id)
                        && labels.get(LABEL_TYPE).map(String::as_str)
                            == Some("sandbox-claim-shadow")
                )
                && pool.data.pointer("/spec/replicas").and_then(Value::as_i64) == Some(0)
                && pool
                    .data
                    .pointer("/spec/sandboxTemplateRef/name")
                    .and_then(Value::as_str)
                    == Some(opts.name.as_str()),
            "workspace shadow does not own the zero-replica environment template"
        );
        let template = self
            .templates()
            .get(&opts.name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace environment template is unavailable"))?;
        require_bootstrap_object(&template, &self.namespace, &opts.name, "SandboxTemplate")?;
        // A legacy template carries this environment's label. An
        // identity-free template carries none (design §13); its
        // environment-owned shadow pool, checked above, names it.
        let template_environment = template
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_ENV_ID));
        anyhow::ensure!(
            template_environment == Some(&opts.environment_id)
                || (template_environment.is_none() && workspace_object_identity_free(&template)?),
            "workspace template belongs to another environment"
        );
        Ok(WorkspaceBootstrapSnapshot {
            pool,
            template,
            sandbox,
            shared: false,
        })
    }

    /// A pool-born environment's bootstrap (Program #2238 C3): its Claim
    /// selects a shared warm pool, whose template is Codewire's identity-free
    /// pool template. Restart accepts it only while the owned Sandbox is
    /// identity-free too, and then never writes the shared template.
    async fn read_shared_pool_bootstrap(
        &self,
        pool_name: &str,
        sandbox: DynamicObject,
    ) -> anyhow::Result<WorkspaceBootstrapSnapshot> {
        let pool = self
            .warm_pools()
            .get(pool_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace warm pool is unavailable"))?;
        require_bootstrap_object(&pool, &self.namespace, pool_name, "SandboxWarmPool")?;
        anyhow::ensure!(
            super::warm_pool::has_pool_labels(pool.metadata.labels.as_ref())
                && pool
                    .data
                    .pointer("/spec/sandboxTemplateRef/name")
                    .and_then(Value::as_str)
                    == Some(pool_name),
            "workspace warm pool is not Codewire's shared pool of its template"
        );
        let template = self
            .templates()
            .get(pool_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace warm-pool template is unavailable"))?;
        require_bootstrap_object(&template, &self.namespace, pool_name, "SandboxTemplate")?;
        anyhow::ensure!(
            super::warm_pool::has_pool_labels(template.metadata.labels.as_ref())
                && template
                    .metadata
                    .labels
                    .as_ref()
                    .is_none_or(|labels| !labels.contains_key(LABEL_ENV_ID))
                && workspace_object_identity_free(&template)?,
            "workspace warm-pool template is not identity-free"
        );
        anyhow::ensure!(
            workspace_object_identity_free(&sandbox)?,
            "a pool-born workspace Sandbox must be identity-free"
        );
        Ok(WorkspaceBootstrapSnapshot {
            pool,
            template,
            sandbox,
            shared: true,
        })
    }

    /// Bring the suspended private template and its allocated Sandbox to the
    /// current rendering before resume. Works while suspended without a Pod.
    /// The caller holds the environment-row publication fence, and owns
    /// suspension and replacement; this never mutates a live Pod.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %opts.environment_id))]
    pub async fn reconcile_workspace_bootstrap(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
    ) -> anyhow::Result<()> {
        // A confidential workspace publishes its whole measured Pod template
        // (B2c), which also upgrades a legacy one.
        if opts.measured_workspace_environment().is_some() {
            return self
                .reconcile_measured_bootstrap(
                    opts,
                    expected_claim_name,
                    expected_claim_uid,
                    expected_sandbox,
                )
                .await;
        }
        anyhow::ensure!(
            opts.runtime_profile_spec().profile != super::template::RUNTIME_PROFILE_CONFIDENTIAL,
            "a confidential workspace starts only with its measured binding anchors"
        );
        anyhow::ensure!(
            !opts.workspace_binding_url.trim().is_empty(),
            "a workspace starts only with its binding listener"
        );
        self.reconcile_identity_free_bootstrap(
            opts,
            expected_claim_name,
            expected_claim_uid,
            expected_sandbox,
        )
        .await
    }

    /// Start of a confidential workspace (B2c): publish the measured Pod
    /// template its start just authorized onto the suspended template and
    /// Sandbox, under UID and resourceVersion tests, and check that both carry
    /// it before resume. A start after a release, a roots change or a legacy
    /// rendering therefore boots exactly what Trustee authorizes.
    async fn reconcile_measured_bootstrap(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
    ) -> anyhow::Result<()> {
        let measured = MeasuredPodTemplate::render(&self.namespace, opts)?;
        let before = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&before.sandbox)?;
        anyhow::ensure!(
            !before.shared,
            "a confidential workspace never runs from a shared template"
        );
        anyhow::ensure!(
            sandbox_suspension_observed(&before.sandbox),
            "workspace bootstrap refresh requires current controller-completed suspension"
        );
        for (object, api, egress) in [
            (&before.template, self.templates(), true),
            (&before.sandbox, self.sandboxes(), false),
        ] {
            let Some(patch) = measured.json_patch(object, egress)? else {
                continue;
            };
            let name = object
                .metadata
                .name
                .as_deref()
                .expect("validated runtime name");
            let updated = api
                .patch(name, &PatchParams::default(), &patch)
                .await
                .map_err(|_| anyhow::anyhow!("measured workspace runtime was not admitted"))?;
            anyhow::ensure!(
                runtime_object_uid(&updated.metadata, &self.namespace, name)?
                    == object
                        .metadata
                        .uid
                        .as_deref()
                        .expect("validated runtime UID")
                    && measured.published_on(&updated)
                    && (!egress || measured.egress_published_on(&updated)),
                "measured workspace runtime did not converge"
            );
        }
        let after = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&after.sandbox)?;
        anyhow::ensure!(
            after
                .sandbox
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some("Suspended")
                && before.pool.metadata.uid == after.pool.metadata.uid
                && before.template.metadata.uid == after.template.metadata.uid
                && before.sandbox.metadata.uid == after.sandbox.metadata.uid
                && measured.published_on(&after.template)
                && measured.egress_published_on(&after.template)
                && measured.published_on(&after.sandbox),
            "measured workspace runtime is no longer current"
        );
        Ok(())
    }

    /// Upgrade on start (design §12): a legacy suspended environment's
    /// template and Sandbox get the whole
    /// identity-free workspace Pod spec (containers, init containers,
    /// volumes, probes, current images) and the template its identity-free
    /// egress. `volumeClaimTemplates` and the Pod template metadata are kept.
    /// Each object is patched under UID and resourceVersion tests; an object
    /// that is already identity-free and current is left alone, so a partly
    /// upgraded environment converges on its next start. The resumed Pod then
    /// binds with `credential_scope='pod'`.
    async fn reconcile_identity_free_bootstrap(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
    ) -> anyhow::Result<()> {
        let before = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&before.sandbox)?;
        anyhow::ensure!(
            sandbox_suspension_observed(&before.sandbox),
            "workspace bootstrap refresh requires current controller-completed suspension"
        );
        let rendered = render_sandbox_template(&self.namespace, opts);
        let pod_spec = rendered
            .pointer("/spec/podTemplate/spec")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("identity-free workspace rendering has no Pod spec"))?;
        let network_policy = rendered.pointer("/spec/networkPolicy").cloned();
        // A shared pool template serves every member: only the Sandbox is
        // ever patched for one environment.
        let objects = if before.shared {
            vec![(&before.sandbox, self.sandboxes(), None)]
        } else {
            vec![
                (&before.template, self.templates(), network_policy.as_ref()),
                (&before.sandbox, self.sandboxes(), None),
            ]
        };
        for (object, api, network_policy) in objects {
            let Some(patch) = identity_free_upgrade_patch(object, &pod_spec, network_policy)?
            else {
                continue;
            };
            let name = object
                .metadata
                .name
                .as_deref()
                .expect("validated runtime name");
            let updated = api
                .patch(name, &PatchParams::default(), &patch)
                .await
                .map_err(|_| anyhow::anyhow!("workspace identity upgrade was not admitted"))?;
            anyhow::ensure!(
                runtime_object_uid(&updated.metadata, &self.namespace, name)?
                    == object
                        .metadata
                        .uid
                        .as_deref()
                        .expect("validated runtime UID")
                    && workspace_object_identity_free(&updated)?
                    && !workspace_object_has_legacy_codex_home(&updated)?,
                "workspace identity upgrade did not converge"
            );
        }
        let after = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&after.sandbox)?;
        anyhow::ensure!(
            after
                .sandbox
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some("Suspended")
                && before.pool.metadata.uid == after.pool.metadata.uid
                && before.template.metadata.uid == after.template.metadata.uid
                && before.sandbox.metadata.uid == after.sandbox.metadata.uid
                && workspace_object_identity_free(&after.template)?
                && workspace_object_identity_free(&after.sandbox)?
                // A shared pool template is the reconciler's to rotate, never
                // this environment's to upgrade.
                && (after.shared || !workspace_object_has_legacy_codex_home(&after.template)?)
                && !workspace_object_has_legacy_codex_home(&after.sandbox)?,
            "workspace identity upgrade is no longer current"
        );
        Ok(())
    }

    /// Capture the currently owned Sandbox/Pod UIDs, including the controller's
    /// explicit Pod-name annotation. This is a lifecycle observation, not
    /// authentication or a broker grant.
    pub async fn observe_claim_runtime_identity(
        &self,
        opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<RuntimeIdentityObservation> {
        Ok(self
            .read_claim_runtime_identity(opts, expected_claim_name, expected_claim_uid)
            .await?
            .observation)
    }

    /// Observe propagation through the exact Claim -> Sandbox -> Pod chain.
    /// This must run outside the SQL mutation lock. Replacing any pinned UID
    /// requires a fresh lifecycle observation, never relabeling another Pod.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %opts.environment_id))]
    pub async fn wait_for_claim_runtime_identity(
        &self,
        opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected: &RuntimeIdentityObservation,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(timeout, async {
            loop {
                let snapshot = self
                    .read_claim_runtime_identity(opts, expected_claim_name, expected_claim_uid)
                    .await?;
                anyhow::ensure!(
                    &snapshot.observation == expected,
                    "runtime identity Sandbox or Pod was replaced"
                );
                if runtime_identity_converged(
                    &snapshot.claim,
                    &snapshot.sandbox,
                    &snapshot.pod,
                    opts,
                ) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("runtime identity metadata propagation timed out"))?
    }

    /// Mirrors `createSandboxClaimDynamic`: create, or reuse on
    /// AlreadyExists. Returns (name, uid).
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %opts.environment_id))]
    pub async fn create_sandbox_claim(
        &self,
        namespace: &str,
        opts: &ClaimOpts,
    ) -> anyhow::Result<(String, String)> {
        let name = claim_name(&opts.environment_id);
        let rendered = render_sandbox_claim(namespace, opts);
        let obj: DynamicObject = serde_json::from_value(rendered)?;

        match self.claims.create(&PostParams::default(), &obj).await {
            Ok(created) => {
                let uid = created.metadata.uid.unwrap_or_default();
                tracing::info!(name, namespace, env = %opts.environment_id, "created SandboxClaim");
                Ok((name, uid))
            }
            Err(kube::Error::Api(e)) if e.code == 409 => {
                tracing::info!(name, namespace, env = %opts.environment_id, "SandboxClaim already exists, reusing");
                match self.claims.get(&name).await {
                    Ok(existing) => Ok((name, existing.metadata.uid.unwrap_or_default())),
                    Err(_) => Ok((name, String::new())),
                }
            }
            Err(e) => Err(anyhow::anyhow!("create SandboxClaim {name}: {e}")),
        }
    }

    /// Mirrors `GetSandboxClaim`: Ok(None) when absent.
    pub async fn get_sandbox_claim(&self, env_id: &str) -> anyhow::Result<Option<DynamicObject>> {
        let name = claim_name(env_id);
        match self.claims.get(&name).await {
            Ok(obj) => Ok(Some(obj)),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
            Err(e) => Err(anyhow::anyhow!("get SandboxClaim {name}: {e}")),
        }
    }

    /// Mirrors `RemoveDeletionProtectionFinalizer`: no-op when the claim
    /// or the finalizer is absent.
    pub async fn remove_deletion_protection_finalizer(&self, env_id: &str) -> anyhow::Result<()> {
        let name = claim_name(env_id);
        let obj = match self.claims.get(&name).await {
            Ok(obj) => obj,
            Err(kube::Error::Api(e)) if e.code == 404 => return Ok(()),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "get SandboxClaim {name} for finalizer removal: {e}"
                ));
            }
        };
        let finalizers = obj.metadata.finalizers.unwrap_or_default();
        let filtered: Vec<&String> = finalizers
            .iter()
            .filter(|f| f.as_str() != DELETION_PROTECTION_FINALIZER)
            .collect();
        if filtered.len() == finalizers.len() {
            return Ok(()); // finalizer not present
        }
        let patch: Value = serde_json::json!({ "metadata": { "finalizers": filtered } });
        self.claims
            .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|e| anyhow::anyhow!("remove finalizer from SandboxClaim {name}: {e}"))?;
        tracing::info!(name, "removed deletion-protection finalizer");
        Ok(())
    }

    /// Deletes the claim; NotFound is success, like the Go delete paths.
    pub async fn delete_sandbox_claim(&self, env_id: &str) -> anyhow::Result<()> {
        let name = claim_name(env_id);
        match self.claims.delete(&name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("delete SandboxClaim {name}: {e}")),
        }
    }

    fn sandboxes(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, CRD_VERSION, "Sandbox");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxes");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    /// Lists every Sandbox CR in the client's namespace.
    ///
    /// The Go billing controller drives off a shared informer over
    /// Sandboxes (`billingsessions.StartSandboxController`); the Rust
    /// orchestration substitutes a leader-gated poll for watches
    /// everywhere (see `wait_for_ready`, `sandbox_liveness_loop`), so the
    /// billing-session loop lists the same objects each tick.
    pub async fn list_sandboxes(&self) -> anyhow::Result<Vec<DynamicObject>> {
        let list = self
            .sandboxes()
            .list(&ListParams::default())
            .await
            .map_err(|e| anyhow::anyhow!("list Sandboxes: {e}"))?;
        Ok(list.items)
    }

    fn templates(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(EXTENSIONS_GROUP, CRD_VERSION, "SandboxTemplate");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxtemplates");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn warm_pools(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk(EXTENSIONS_GROUP, CRD_VERSION, "SandboxWarmPool");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxwarmpools");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn persistent_volume_claims(&self) -> Api<PersistentVolumeClaim> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn persistent_volumes(&self) -> Api<PersistentVolume> {
        Api::all(self.client.clone())
    }

    fn storage_classes(&self) -> Api<StorageClass> {
        Api::all(self.client.clone())
    }

    /// Resolve the per-environment workspace PVC and the expansion capability
    /// advertised by its StorageClass. The shared Pod-less resolver walks the
    /// recorded Claim UID to its Sandbox's `workspace` volume claim template
    /// and accepts only the recorded PVC UID (or, on first resolution, the
    /// Sandbox-controlled PVC). Codewire never trusts a computed name.
    pub async fn workspace_storage(
        &self,
        anchor: &WorkspacePvcAnchor,
    ) -> anyhow::Result<WorkspaceStorage> {
        let Some((
            pvc,
            WorkspacePvc::Claim {
                name: pvc_name,
                uid: pvc_uid,
                ..
            },
        )) = self.resolve_anchored_workspace_pvc(anchor).await?
        else {
            anyhow::bail!("environment has no persistent workspace volume");
        };
        let spec = pvc
            .spec
            .ok_or_else(|| anyhow::anyhow!("workspace PVC {pvc_name} has no spec"))?;
        let raw_block = spec.volume_mode.as_deref() == Some("Block");
        // A commodity workspace is Block too (#3718); only the confidential
        // claim is ReadWriteOncePod.
        let confidential = spec
            .access_modes
            .as_deref()
            .is_some_and(|modes| modes.iter().any(|mode| mode == "ReadWriteOncePod"));
        let storage_class_name = spec.storage_class_name.unwrap_or_default();
        if storage_class_name.trim().is_empty() {
            anyhow::bail!("workspace PVC {pvc_name} has no explicit StorageClass");
        }
        let requested = spec
            .resources
            .and_then(|resources| resources.requests)
            .and_then(|requests| requests.get("storage").cloned())
            .ok_or_else(|| anyhow::anyhow!("workspace PVC {pvc_name} has no storage request"))?;
        let requested_disk_gb = parse_gib_quantity(&requested.0)?;
        let applied_disk_gb = pvc
            .status
            .as_ref()
            .and_then(|status| status.capacity.as_ref())
            .and_then(|capacity| capacity.get("storage"))
            .map(|quantity| parse_gib_quantity(&quantity.0))
            .transpose()?;
        let filesystem_resize_pending = pvc
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_deref())
            .is_some_and(|conditions| {
                conditions.iter().any(|condition| {
                    condition.type_ == "FileSystemResizePending" && condition.status == "True"
                })
            });
        let storage_class = self
            .storage_classes()
            .get(&storage_class_name)
            .await
            .map_err(|error| {
                anyhow::anyhow!("get StorageClass {storage_class_name} for {pvc_name}: {error}")
            })?;

        Ok(WorkspaceStorage {
            pvc_name,
            pvc_uid,
            storage_class_name,
            requested_disk_gb,
            applied_disk_gb,
            filesystem_resize_pending,
            expansion_allowed: storage_class.allow_volume_expansion == Some(true),
            raw_block,
            confidential,
        })
    }

    /// Verify a requested disk size before the resize operation is admitted.
    pub async fn require_workspace_storage_resize(
        &self,
        anchor: &WorkspacePvcAnchor,
        desired_disk_gb: i32,
    ) -> anyhow::Result<WorkspaceStorage> {
        let storage = self.workspace_storage(anchor).await?;
        if desired_disk_gb < storage.requested_disk_gb {
            anyhow::bail!(
                "persistent storage cannot shrink from {} Gi to {} Gi",
                storage.requested_disk_gb,
                desired_disk_gb
            );
        }
        // The guest-encrypted confidential raw-block profile cannot expand in
        // place. Reject here so Kubernetes never persists a larger PVC request
        // before the downstream CSI/CDH refusal. A commodity Block workspace
        // grows: its next Pod's `mount-workspace` grows the filesystem online.
        if desired_disk_gb > storage.requested_disk_gb && storage.confidential {
            anyhow::bail!("confidential workspace storage expansion is not supported");
        }
        if desired_disk_gb > storage.requested_disk_gb && !storage.expansion_allowed {
            anyhow::bail!(
                "StorageClass {} does not allow volume expansion",
                storage.storage_class_name
            );
        }
        Ok(storage)
    }

    /// Persist desired compute on the current claim, its private
    /// per-environment template when present, and the already-owned Sandbox.
    /// Storage is applied to the PVC directly; the pinned Sandbox CRD makes
    /// an existing Sandbox's volumeClaimTemplates immutable.
    /// The existing agent-sandbox controller does not copy claim resource
    /// changes to an existing Sandbox, so the Sandbox patch is intentional.
    pub async fn apply_resize_desired_state(
        &self,
        env_id: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        disk_gb: i32,
    ) -> anyhow::Result<()> {
        if cpu_millicores <= 0 || memory_mb <= 0 || disk_gb <= 0 {
            anyhow::bail!("resize resources must be greater than zero");
        }
        let storage = format!("{disk_gb}Gi");

        let sandbox_name = self.bound_sandbox_name(env_id).await?;
        let sandboxes = self.sandboxes();
        let mut sandbox = sandboxes
            .get(&sandbox_name)
            .await
            .map_err(|error| anyhow::anyhow!("get Sandbox {sandbox_name}: {error}"))?;
        let compute = WorkspaceCompute::new(
            cpu_millicores,
            memory_mb,
            runtime_object_cpu_sharing(&sandbox.data),
        );

        let claim = claim_name(env_id);
        let claim_patch = serde_json::json!({
            "spec": {
                "workspaceResources": [{
                    "containerName": "workspace",
                    "resources": {
                        "requests": { "cpu": compute.cpu_request, "memory": compute.memory },
                        "limits": { "cpu": compute.cpu_limit, "memory": compute.memory },
                    },
                }],
            },
        });
        self.claims
            .patch(&claim, &PatchParams::default(), &Patch::Merge(&claim_patch))
            .await
            .map_err(|error| anyhow::anyhow!("patch SandboxClaim {claim}: {error}"))?;

        set_workspace_resources(&mut sandbox.data, &compute)?;
        set_docker_data_size(&mut sandbox.data, disk_gb)?;
        sandboxes
            .replace(&sandbox_name, &PostParams::default(), &sandbox)
            .await
            .map_err(|error| anyhow::anyhow!("update Sandbox {sandbox_name}: {error}"))?;

        // Only a private per-environment template follows the resize; a
        // shared warm-pool template (Program #2238 C3) is never written for
        // one environment.
        if let Some(template_name) = self.claim_template_name(env_id).await?
            && !super::warm_pool::is_warm_pool_name(&template_name)
            && template_name.ends_with(&format!("-{env_id}"))
        {
            let templates = self.templates();
            let mut template = templates
                .get(&template_name)
                .await
                .map_err(|error| anyhow::anyhow!("get SandboxTemplate {template_name}: {error}"))?;
            set_workspace_resources(&mut template.data, &compute)?;
            set_workspace_volume_request(&mut template.data, &storage)?;
            set_docker_data_size(&mut template.data, disk_gb)?;
            templates
                .replace(&template_name, &PostParams::default(), &template)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("update SandboxTemplate {template_name}: {error}")
                })?;
        }

        Ok(())
    }

    async fn claim_template_name(&self, env_id: &str) -> anyhow::Result<Option<String>> {
        let Some(claim) = self.get_sandbox_claim(env_id).await? else {
            anyhow::bail!("SandboxClaim {} not found", claim_name(env_id));
        };
        let Some(warm_pool_name) = claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        let warm_pool = self
            .warm_pools()
            .get(warm_pool_name)
            .await
            .map_err(|error| anyhow::anyhow!("get SandboxWarmPool {warm_pool_name}: {error}"))?;
        Ok(warm_pool
            .data
            .pointer("/spec/sandboxTemplateRef/name")
            .and_then(Value::as_str)
            .map(str::to_string))
    }

    /// Apply only the PVC request. StorageClass capability was checked before
    /// admission and is rechecked here so a changed class fails closed.
    pub async fn apply_workspace_storage_resize(
        &self,
        anchor: &WorkspacePvcAnchor,
        desired_disk_gb: i32,
    ) -> anyhow::Result<WorkspaceStorage> {
        let storage = self
            .require_workspace_storage_resize(anchor, desired_disk_gb)
            .await?;
        if desired_disk_gb == storage.requested_disk_gb {
            return Ok(storage);
        }
        // The UID in the patch is a precondition: a same-name substitute
        // created after resolution is refused, never resized.
        let patch = serde_json::json!({
            "metadata": { "uid": storage.pvc_uid },
            "spec": {
                "resources": {
                    "requests": { "storage": format!("{desired_disk_gb}Gi") },
                },
            },
        });
        self.persistent_volume_claims()
            .patch(
                &storage.pvc_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("expand workspace PVC {}: {error}", storage.pvc_name)
            })?;
        Ok(WorkspaceStorage {
            requested_disk_gb: desired_disk_gb,
            ..storage
        })
    }

    /// Observe PVC expansion before Codewire advances durable applied resources.
    /// A filesystem resize that Kubernetes explicitly defers to Pod restart is
    /// returned to the workflow; this method never replaces the Pod itself.
    pub async fn wait_for_workspace_storage_resize(
        &self,
        anchor: &WorkspacePvcAnchor,
        desired_disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<WorkspaceStorageResizeOutcome> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let storage = self.workspace_storage(anchor).await?;
            if storage
                .applied_disk_gb
                .is_some_and(|size| size >= desired_disk_gb)
            {
                // A commodity Block device grows under a running guest, but
                // its filesystem grows only in the next Pod's
                // `mount-workspace` (#3718).
                return Ok(if storage.raw_block && !storage.confidential {
                    WorkspaceStorageResizeOutcome::RequiresPodRestart
                } else {
                    WorkspaceStorageResizeOutcome::Applied
                });
            }
            if storage.filesystem_resize_pending {
                return Ok(WorkspaceStorageResizeOutcome::RequiresPodRestart);
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "workspace PVC {} did not report {} Gi capacity before timeout",
                    storage.pvc_name,
                    desired_disk_gb
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Wait for the post-restart filesystem capacity, ignoring the transient
    /// FileSystemResizePending condition which is expected to clear on mount.
    pub async fn wait_for_workspace_storage_capacity(
        &self,
        anchor: &WorkspacePvcAnchor,
        desired_disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let storage = self.workspace_storage(anchor).await?;
            if storage
                .applied_disk_gb
                .is_some_and(|size| size >= desired_disk_gb)
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "workspace PVC {} did not report {} Gi capacity after Pod restart",
                    storage.pvc_name,
                    desired_disk_gb
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    fn services(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("", "v1", "Service");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "services");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn network_policies(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("networking.k8s.io", "v1", "NetworkPolicy");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "networkpolicies");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    /// Mirrors `SetReplicas`: resolve the Sandbox name from the claim
    /// status, then update spec.operatingMode (Running/Suspended). The
    /// Running patch also re-pins the Sandbox's daemon image volume to
    /// `support_image` ([`plan_daemon_image`]) and re-renders a legacy DinD
    /// bootstrap ([`dind_bootstrap_refresh`]); a suspend does neither.
    pub async fn set_replicas(
        &self,
        env_id: &str,
        replicas: i64,
        support_image: &str,
    ) -> anyhow::Result<()> {
        let name = self
            .bound_sandbox_name(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("set replicas: {e}"))?;
        let sandboxes = self.sandboxes();
        let sandbox = sandboxes
            .get(&name)
            .await
            .map_err(|e| anyhow::anyhow!("get Sandbox {name}: {e}"))?;
        anyhow::ensure!(
            sandbox.metadata.name.as_deref() == Some(name.as_str())
                && sandbox.metadata.namespace.as_deref() == Some(self.namespace.as_str())
                && sandbox.metadata.deletion_timestamp.is_none(),
            "set operatingMode: Sandbox {name} identity is unavailable"
        );
        let uid = sandbox
            .metadata
            .uid
            .as_deref()
            .filter(|uid| !uid.is_empty())
            .ok_or_else(|| anyhow::anyhow!("set operatingMode: Sandbox {name} has no UID"))?;
        anyhow::ensure!(
            sandbox.data.get("spec").is_some_and(Value::is_object),
            "set operatingMode: Sandbox {name} has no spec"
        );
        let mode = if replicas <= 0 {
            "Suspended"
        } else {
            "Running"
        };
        let (repin, dind, block) = if replicas > 0 {
            // A start refuses a Filesystem commodity workspace (#3718).
            block_workspace(&sandbox)
                .map_err(|e| anyhow::anyhow!("set operatingMode: Sandbox {name}: {e}"))?;
            (
                daemon_image_repin(&sandbox, support_image)
                    .map_err(|e| anyhow::anyhow!("set operatingMode: Sandbox {name}: {e}"))?,
                dind_bootstrap_refresh(&sandbox, support_image)
                    .map_err(|e| anyhow::anyhow!("set operatingMode: Sandbox {name}: {e}"))?,
                Vec::new(),
            )
        } else {
            // A stop, while its Pod still runs, makes a mounted Block
            // workspace `existing`; it never refuses (#3718).
            let block = match block_workspace(&sandbox).ok().flatten() {
                Some(index) => {
                    self.workspace_volume_existing_patch(&sandbox, &name, index)
                        .await?
                }
                None => Vec::new(),
            };
            (None, None, block)
        };
        // Fence the exact incarnation without conditioning the mode change on
        // unrelated controller-owned status/annotation updates. A re-pin
        // carries its own tests of the one volume it rewrites.
        let mut operations = vec![serde_json::json!(
            {"op": "test", "path": "/metadata/uid", "value": uid}
        )];
        operations.extend(repin.iter().flat_map(|repin| repin.operations.clone()));
        operations.extend(dind.iter().flatten().cloned());
        operations.extend(block);
        operations.push(serde_json::json!(
            {"op": "add", "path": "/spec/operatingMode", "value": mode}
        ));
        let patch = Patch::Json::<()>(serde_json::from_value(Value::Array(operations))?);
        let updated = sandboxes
            .patch(&name, &PatchParams::default(), &patch)
            .await
            .map_err(|e| anyhow::anyhow!("update Sandbox {name} operatingMode: {e}"))?;
        // Deletion may start after the read; do not report a deleting response
        // as a live runtime. This is not an atomic absence-of-deletion fence.
        anyhow::ensure!(
            updated.metadata.name.as_deref() == Some(name.as_str())
                && updated.metadata.namespace.as_deref() == Some(self.namespace.as_str())
                && updated.metadata.uid.as_deref() == Some(uid)
                && updated.metadata.deletion_timestamp.is_none()
                && updated
                    .data
                    .pointer("/spec/operatingMode")
                    .and_then(Value::as_str)
                    == Some(mode),
            "update Sandbox {name} operatingMode did not return the current live target"
        );
        if let Some(repin) = &repin {
            log_daemon_image_repin(&updated, &name, repin, support_image);
        }
        if dind.is_some() {
            log_dind_bootstrap_refresh(&name);
        }
        tracing::info!(name, replicas, mode, "set Sandbox operating mode");
        Ok(())
    }

    /// Request suspension only for the current exact Claim-owned Sandbox.
    /// This does not certify controller completion or Pod absence; callers
    /// obtain that separate, opaque identity from the suspension observer.
    pub async fn suspend_workspace(
        &self,
        claim_opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<()> {
        let (claim, sandbox) = self
            .read_owned_claim_sandbox(claim_opts, expected_claim_name, expected_claim_uid)
            .await?;
        self.set_workspace_operating_mode(
            claim_opts,
            expected_claim_name,
            expected_claim_uid,
            (&claim, &sandbox),
            0,
            None,
        )
        .await
    }

    /// Change operating mode on the exact Claim-owned suspended incarnation.
    /// Unlike generic scale operations this completes a captured suspension /
    /// bootstrap sequence, so concurrent spec changes must reject publication.
    /// The caller owns the environment mutation fence and old/all-Pod absence.
    /// A resume re-pins the daemon image volume to `support_image` and
    /// re-renders a legacy DinD bootstrap in the same patch
    /// ([`plan_daemon_image`], [`dind_bootstrap_refresh`]).
    pub async fn set_replicas_for_identity(
        &self,
        claim_opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
        replicas: i64,
        support_image: &str,
    ) -> anyhow::Result<()> {
        let (claim, sandbox) = self
            .read_owned_claim_sandbox(claim_opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&sandbox)?;
        self.set_workspace_operating_mode(
            claim_opts,
            expected_claim_name,
            expected_claim_uid,
            (&claim, &sandbox),
            replicas,
            Some(support_image),
        )
        .await
    }

    /// A status/annotation update may advance resourceVersion between the owned
    /// read and conditional write. Re-read at most twice, keeping the original
    /// Claim/Sandbox and complete specs: a new mode, slot or identity is never
    /// adopted as a retry. Every attempt still tests UID, version and slots.
    async fn set_workspace_operating_mode(
        &self,
        claim_opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        owned: (&DynamicObject, &DynamicObject),
        replicas: i64,
        support_image: Option<&str>,
    ) -> anyhow::Result<()> {
        const ATTEMPTS: usize = 3;
        let (claim, sandbox) = owned;
        let name = sandbox
            .metadata
            .name
            .as_deref()
            .expect("validated Sandbox name");
        let uid = runtime_object_uid(&sandbox.metadata, &self.namespace, name)?;
        let claim_spec = claim.data.get("spec");
        let sandbox_spec = sandbox.data.get("spec");
        let observed_mode = sandbox.data.pointer("/spec/operatingMode");
        let mut observed = sandbox.clone();
        for attempt in 0..ATTEMPTS {
            let error = match self
                .publish_workspace_operating_mode(
                    claim_opts,
                    expected_claim_name,
                    expected_claim_uid,
                    &observed,
                    replicas,
                    support_image,
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            if attempt + 1 == ATTEMPTS
                || error.downcast_ref::<WorkspaceModePatchConflict>().is_none()
            {
                return Err(error);
            }
            let (fresh_claim, fresh) = self
                .read_owned_claim_sandbox(claim_opts, expected_claim_name, expected_claim_uid)
                .await?;
            anyhow::ensure!(
                fresh.metadata.name.as_deref() == Some(name)
                    && runtime_object_uid(&fresh.metadata, &self.namespace, name)? == uid,
                "workspace Sandbox changed during operating mode conflict"
            );
            anyhow::ensure!(
                fresh_claim.data.get("spec") == claim_spec
                    && fresh.data.get("spec") == sandbox_spec
                    && fresh.data.pointer("/spec/operatingMode") == observed_mode,
                "workspace Claim or Sandbox spec changed during operating mode conflict"
            );
            let version = fresh
                .metadata
                .resource_version
                .as_deref()
                .filter(|v| !v.is_empty());
            if version.is_none() || version == observed.metadata.resource_version.as_deref() {
                // A deterministic invalid patch, or another unchanged refusal,
                // has no evidence of a status conflict and must not be replayed.
                return Err(error);
            }
            observed = fresh;
        }
        unreachable!("the final attempt returns its original failure")
    }

    /// One UID/version-fenced write, including unchanged ownership/convergence
    /// checks after publication. Only an unapplied API conflict is retryable.
    async fn publish_workspace_operating_mode(
        &self,
        claim_opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        sandbox: &DynamicObject,
        replicas: i64,
        support_image: Option<&str>,
    ) -> anyhow::Result<()> {
        let name = sandbox
            .metadata
            .name
            .as_deref()
            .expect("validated Sandbox name");
        let uid = runtime_object_uid(&sandbox.metadata, &self.namespace, name)?;
        let resource_version = sandbox
            .metadata
            .resource_version
            .as_deref()
            .filter(|version| !version.is_empty())
            .ok_or_else(|| anyhow::anyhow!("workspace Sandbox has no resource version"))?;
        let mode = if replicas <= 0 {
            "Suspended"
        } else {
            "Running"
        };
        anyhow::ensure!(
            sandbox.data.get("spec").is_some_and(Value::is_object),
            "workspace Sandbox has no spec"
        );
        let mut operations = vec![
            serde_json::json!({"op":"test","path":"/metadata/uid","value":uid}),
            serde_json::json!({"op":"test","path":"/metadata/resourceVersion","value":resource_version}),
        ];
        if replicas > 0 {
            anyhow::ensure!(
                sandbox
                    .data
                    .pointer("/spec/operatingMode")
                    .and_then(Value::as_str)
                    == Some("Suspended"),
                "workspace resume requires the observed Sandbox to remain suspended"
            );
            operations.push(
                serde_json::json!({"op":"test","path":"/spec/operatingMode","value":"Suspended"}),
            );
        }
        let repin = match support_image.filter(|_| replicas > 0) {
            Some(image) => daemon_image_repin(sandbox, image)?.map(|repin| (image, repin)),
            None => None,
        };
        let dind = match support_image.filter(|_| replicas > 0) {
            Some(image) => dind_bootstrap_refresh(sandbox, image)?,
            None => None,
        };
        let block = if replicas > 0 {
            // A resume refuses a Filesystem commodity workspace (#3718).
            block_workspace(sandbox)?;
            Vec::new()
        } else {
            // A suspension, while its Pod still runs, makes a mounted Block
            // workspace `existing`; it never refuses (#3718).
            match block_workspace(sandbox).ok().flatten() {
                Some(index) => {
                    self.workspace_volume_existing_patch(sandbox, name, index)
                        .await?
                }
                None => Vec::new(),
            }
        };
        operations.extend(repin.iter().flat_map(|(_, repin)| repin.operations.clone()));
        operations.extend(dind.iter().flatten().cloned());
        operations.extend(block);
        operations.push(serde_json::json!({"op":"add","path":"/spec/operatingMode","value":mode}));
        let patch = Patch::Json::<()>(serde_json::from_value(Value::Array(operations))?);
        let updated = self
            .sandboxes()
            .patch(name, &PatchParams::default(), &patch)
            .await
            .map_err(|error| {
                if matches!(&error, kube::Error::Api(status) if matches!(status.code, 409 | 422)) {
                    anyhow::Error::new(WorkspaceModePatchConflict(error))
                } else {
                    anyhow::anyhow!("workspace operating mode update was not admitted: {error}")
                }
            })?;
        anyhow::ensure!(
            runtime_object_uid(&updated.metadata, &self.namespace, name)? == uid,
            "workspace Sandbox was replaced during operating mode publication"
        );
        if let Some((image, repin)) = &repin {
            log_daemon_image_repin(&updated, name, repin, image);
        }
        if dind.is_some() {
            log_dind_bootstrap_refresh(name);
        }
        require_runtime_controller(
            &updated.metadata,
            super::EXTENSIONS_API_VERSION,
            "SandboxClaim",
            expected_claim_name,
            expected_claim_uid,
        )?;
        anyhow::ensure!(
            updated
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some(mode),
            "workspace operating mode update did not converge"
        );
        // A Claim replacement/rebind can race the cross-object read. Never
        // acknowledge it as completing the original authority's sequence.
        let (_, after) = self
            .read_owned_claim_sandbox(claim_opts, expected_claim_name, expected_claim_uid)
            .await?;
        anyhow::ensure!(
            runtime_object_uid(&after.metadata, &self.namespace, name)? == uid,
            "workspace Sandbox ownership changed during operating mode publication"
        );
        anyhow::ensure!(
            after
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some(mode),
            "workspace operating mode is no longer current"
        );
        Ok(())
    }

    /// Mirrors `GetPodIP`.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    pub async fn get_pod_ip(&self, env_id: &str) -> anyhow::Result<String> {
        let name = self
            .get_pod_name(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("get pod IP: {e}"))?;
        let pod = self
            .pods()
            .get(&name)
            .await
            .map_err(|e| anyhow::anyhow!("get pod {name}: {e}"))?;
        let ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .unwrap_or_default();
        if ip.is_empty() {
            anyhow::bail!("pod {name} has no IP assigned");
        }
        Ok(ip)
    }

    /// Mirrors `DeleteSandboxTemplate`: NotFound is success.
    pub async fn delete_sandbox_template(&self, name: &str) -> anyhow::Result<()> {
        match self
            .templates()
            .delete(name, &DeleteParams::default())
            .await
        {
            Ok(_) => {
                tracing::info!(name, namespace = self.namespace, "deleted SandboxTemplate");
                Ok(())
            }
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("delete SandboxTemplate {name}: {e}")),
        }
    }

    /// The environment's access objects (design §5): the daemon Service the
    /// API and the credential relay dial, the direct-UDP LoadBalancer to the
    /// workspace's tailnet peer, and the workspace's NetworkPolicy. The
    /// daemon hosts SSH and the tailnet.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %opts.environment_id))]
    pub async fn ensure_access_stack(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        if opts.environment_id.trim().is_empty() {
            anyhow::bail!("ensure access stack: environment_id is required");
        }
        let opts = self.resolve_direct_udp_service_opts(opts).await?;
        self.ensure_dynamic(
            self.services(),
            &workspace_daemon_service_name(&opts.environment_id),
            render_workspace_daemon_service(&self.namespace, &opts),
        )
        .await?;
        if let Some(service) = render_direct_udp_service(&self.namespace, &opts) {
            self.ensure_dynamic(
                self.services(),
                &direct_udp_service_name(&opts.environment_id),
                service,
            )
            .await?;
        } else {
            delete_dynamic(
                &self.services(),
                &direct_udp_service_name(&opts.environment_id),
            )
            .await?;
        }
        if opts.network_policy_management.is_empty() || opts.network_policy_management == "Managed"
        {
            self.ensure_dynamic(
                self.network_policies(),
                &workspace_daemon_network_policy_name(&opts.environment_id),
                render_workspace_daemon_network_policy(&self.namespace, &opts),
            )
            .await?;
        }
        Ok(())
    }

    /// Program #2238 C6 (#2434): apply `cw-daemon-warm-<env>` for the adopted
    /// warm member whose Sandbox UID a committed warm binding recorded. The
    /// caller proves that binding inside its fence; nothing else may call
    /// this. Managed like the environment's own policies, and removed with
    /// them by [`Self::delete_access_stack`].
    pub async fn ensure_warm_member_bridge(
        &self,
        opts: &TemplateOpts,
        sandbox_uid: &str,
    ) -> anyhow::Result<()> {
        if !(opts.network_policy_management.is_empty()
            || opts.network_policy_management == "Managed")
        {
            return Ok(());
        }
        self.ensure_dynamic(
            self.network_policies(),
            &warm_member_daemon_bridge_name(&opts.environment_id),
            render_warm_member_bridge(&self.namespace, opts, sandbox_uid)?,
        )
        .await
    }

    /// Remove an environment's warm-member bridge. NotFound is success.
    pub async fn delete_warm_member_bridge(&self, env_id: &str) -> anyhow::Result<()> {
        delete_dynamic(
            &self.network_policies(),
            &warm_member_daemon_bridge_name(env_id),
        )
        .await
    }

    /// Remove the environment's access objects.
    pub async fn delete_access_stack(&self, env_id: &str) -> anyhow::Result<()> {
        let services = self.services();
        delete_dynamic(&services, &workspace_daemon_service_name(env_id)).await?;
        delete_dynamic(&services, &direct_udp_service_name(env_id)).await?;
        self.delete_warm_member_bridge(env_id).await?;
        delete_dynamic(
            &self.network_policies(),
            &workspace_daemon_network_policy_name(env_id),
        )
        .await
    }

    /// Remove every environment-owned runtime object and prove absence before
    /// returning. Repeated calls are safe: Kubernetes NotFound is success and
    /// the deterministic/labeled sweep catches residue left by a partially
    /// completed earlier attempt.
    pub async fn delete_environment_resources(
        &self,
        env_id: &str,
        known_sandbox_name: &str,
        per_environment_template: Option<&str>,
        prove_confidential_storage_absent: bool,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.delete_environment_resources_with_recorded_storage(
            env_id,
            known_sandbox_name,
            per_environment_template,
            prove_confidential_storage_absent,
            None,
            timeout,
        )
        .await
    }

    /// Destroy every environment-owned object. The storage-removal proof
    /// keeps its label and owner scan, which finds orphans, and also counts a
    /// PVC carrying the recorded workspace PVC UID, so a restore-born PVC
    /// that the fork has not adopted yet (no owner, no environment label) is
    /// deleted and proven absent too.
    pub async fn delete_environment_resources_with_recorded_storage(
        &self,
        env_id: &str,
        known_sandbox_name: &str,
        per_environment_template: Option<&str>,
        prove_confidential_storage_absent: bool,
        recorded_pvc_uid: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        // A pool-born Sandbox (Program #2238 C3) is named for its pool and
        // carries no environment label. When the backend never recorded its
        // Pod, find it through the Claim before the Claim is deleted.
        let claimed_sandbox = self
            .get_sandbox_claim(env_id)
            .await?
            .and_then(|claim| claim_bound_sandbox_name(&claim).map(str::to_owned));
        let known_sandbox_name = if known_sandbox_name.trim().is_empty() {
            claimed_sandbox.as_deref().unwrap_or_default()
        } else {
            known_sandbox_name
        };
        self.delete_access_stack(env_id).await?;
        self.remove_deletion_protection_finalizer(env_id).await?;
        self.delete_sandbox_claim(env_id).await?;

        let selector = format!("{LABEL_ENV_ID}={env_id}");
        let mut sandboxes = self
            .sandboxes()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| anyhow::anyhow!("list Sandboxes for {env_id}: {error}"))?
            .items;
        if !known_sandbox_name.trim().is_empty()
            && !sandboxes
                .iter()
                .any(|sandbox| sandbox.metadata.name.as_deref() == Some(known_sandbox_name))
        {
            match self.sandboxes().get(known_sandbox_name).await {
                Ok(sandbox) => sandboxes.push(sandbox),
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "get known Sandbox {known_sandbox_name}: {error}"
                    ));
                }
            }
        }
        let mut sandbox_names: BTreeSet<String> = sandboxes
            .into_iter()
            .filter_map(|sandbox| sandbox.metadata.name)
            .collect();
        sandbox_names.insert(claim_name(env_id));
        if !known_sandbox_name.trim().is_empty() {
            sandbox_names.insert(known_sandbox_name.to_string());
        }
        for name in &sandbox_names {
            delete_dynamic(&self.sandboxes(), name).await?;
        }

        let mut pods = self.list_workspace_pod_identities(env_id).await?;
        for name in &sandbox_names {
            if !pods.iter().any(|pod| pod.name == *name)
                && let Some(pod) = self.get_workspace_pod_identity_by_name(name).await?
            {
                pods.push(pod);
            }
        }
        for pod in pods {
            match self
                .pods()
                .delete(&pod.name, &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "delete workspace Pod {}: {error}",
                        pod.name
                    ));
                }
            }
        }

        for pvc in self
            .environment_persistent_volume_claims(env_id, &sandbox_names, recorded_pvc_uid)
            .await?
        {
            match self
                .persistent_volume_claims()
                .delete(&pvc, &DeleteParams::default())
                .await
            {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "delete PersistentVolumeClaim {pvc}: {error}"
                    ));
                }
            }
        }

        let shadow_hint = per_environment_template.map(super::shadow_warm_pool_name);
        for (kind, api, hint) in [
            ("SandboxWarmPool", self.warm_pools(), shadow_hint.as_deref()),
            (
                "SandboxTemplate",
                self.templates(),
                per_environment_template,
            ),
        ] {
            for (name, uid) in environment_owned_objects(&api, env_id, kind, hint).await? {
                match api
                    .delete(&name, &delete_params_for_observed_uid(&uid))
                    .await
                {
                    Ok(_) => {}
                    Err(kube::Error::Api(error)) if error.code == 404 => {}
                    Err(error) => {
                        return Err(anyhow::anyhow!("delete owned {kind} {name}: {error}"));
                    }
                }
            }
        }

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let residue = self
                .environment_residue_with_recorded_storage(
                    env_id,
                    known_sandbox_name,
                    per_environment_template,
                    prove_confidential_storage_absent,
                    recorded_pvc_uid,
                )
                .await?;
            if residue.is_empty() {
                return Ok(());
            }
            if tokio::time::Instant::now() + Duration::from_millis(250) >= deadline {
                anyhow::bail!(
                    "timeout waiting for environment {env_id} resources to be deleted: {}",
                    residue.resources.join(", ")
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn environment_residue(
        &self,
        env_id: &str,
        known_sandbox_name: &str,
        per_environment_template: Option<&str>,
        prove_confidential_storage_absent: bool,
    ) -> anyhow::Result<EnvironmentResidue> {
        self.environment_residue_with_recorded_storage(
            env_id,
            known_sandbox_name,
            per_environment_template,
            prove_confidential_storage_absent,
            None,
        )
        .await
    }

    pub async fn environment_residue_with_recorded_storage(
        &self,
        env_id: &str,
        known_sandbox_name: &str,
        per_environment_template: Option<&str>,
        prove_confidential_storage_absent: bool,
        recorded_pvc_uid: Option<&str>,
    ) -> anyhow::Result<EnvironmentResidue> {
        let mut resources = Vec::new();
        if self.get_sandbox_claim(env_id).await?.is_some() {
            resources.push(format!("SandboxClaim/{}", claim_name(env_id)));
        }

        let selector = format!("{LABEL_ENV_ID}={env_id}");
        let mut sandbox_names = BTreeSet::from([claim_name(env_id)]);
        for sandbox in self
            .sandboxes()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| anyhow::anyhow!("list Sandboxes for {env_id}: {error}"))?
            .items
        {
            if let Some(name) = sandbox.metadata.name {
                sandbox_names.insert(name.clone());
                resources.push(format!("Sandbox/{name}"));
            }
        }
        if !known_sandbox_name.trim().is_empty()
            && !resources
                .iter()
                .any(|resource| resource == &format!("Sandbox/{known_sandbox_name}"))
        {
            match self.sandboxes().get(known_sandbox_name).await {
                Ok(_) => {
                    sandbox_names.insert(known_sandbox_name.to_string());
                    resources.push(format!("Sandbox/{known_sandbox_name}"));
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => {
                    return Err(anyhow::anyhow!("get Sandbox {known_sandbox_name}: {error}"));
                }
            }
        }
        if !known_sandbox_name.trim().is_empty() {
            sandbox_names.insert(known_sandbox_name.to_string());
        }

        let mut pod_names: BTreeSet<String> = self
            .list_workspace_pod_identities(env_id)
            .await?
            .into_iter()
            .map(|pod| pod.name)
            .collect();
        for name in &sandbox_names {
            if self
                .get_workspace_pod_identity_by_name(name)
                .await?
                .is_some()
            {
                pod_names.insert(name.clone());
            }
        }
        for name in pod_names {
            resources.push(format!("Pod/{name}"));
        }

        for pvc in self
            .environment_persistent_volume_claims(env_id, &sandbox_names, recorded_pvc_uid)
            .await?
        {
            resources.push(format!("PersistentVolumeClaim/{pvc}"));
        }
        if prove_confidential_storage_absent {
            resources.extend(self.confidential_storage_residue(&sandbox_names).await?);
        }

        for (kind, api, name) in [
            (
                "Service",
                self.services(),
                workspace_daemon_service_name(env_id),
            ),
            ("Service", self.services(), direct_udp_service_name(env_id)),
            (
                "NetworkPolicy",
                self.network_policies(),
                workspace_daemon_network_policy_name(env_id),
            ),
            (
                "NetworkPolicy",
                self.network_policies(),
                warm_member_daemon_bridge_name(env_id),
            ),
        ] {
            if dynamic_exists(&api, &name).await? {
                resources.push(format!("{kind}/{name}"));
            }
        }

        let shadow_hint = per_environment_template.map(super::shadow_warm_pool_name);
        for (kind, api, hint) in [
            (
                "SandboxTemplate",
                self.templates(),
                per_environment_template,
            ),
            ("SandboxWarmPool", self.warm_pools(), shadow_hint.as_deref()),
        ] {
            for (name, _) in environment_owned_objects(&api, env_id, kind, hint).await? {
                resources.push(format!("{kind}/{name}"));
            }
        }

        resources.sort();
        resources.dedup();
        Ok(EnvironmentResidue { resources })
    }

    /// Prove that Kubernetes has forgotten the workspace volume before
    /// orchestration is allowed to delete either key copy: no PersistentVolume
    /// still claims the workspace PVC. With a `Delete` reclaim policy the CSI
    /// external-provisioner removes the PV only after the driver's
    /// `DeleteVolume` succeeded, and the LINSTOR driver returns success only
    /// after its server-side truncate removed the resource (#2321). This stays
    /// backend-neutral; no confidential volume is ever snapshotted, which is
    /// the one case that keeps a LINSTOR resource definition alive.
    async fn confidential_storage_residue(
        &self,
        sandbox_names: &BTreeSet<String>,
    ) -> anyhow::Result<Vec<String>> {
        let pvc_names: BTreeSet<String> = sandbox_names
            .iter()
            .map(|sandbox_name| format!("workspace-{sandbox_name}"))
            .collect();
        let mut resources = Vec::new();

        let persistent_volumes = self
            .persistent_volumes()
            .list(&ListParams::default())
            .await
            .map_err(|error| anyhow::anyhow!("list PersistentVolumes: {error}"))?;
        for volume in persistent_volumes.items {
            let Some(spec) = volume.spec.as_ref() else {
                continue;
            };
            let claim_matches = spec.claim_ref.as_ref().is_some_and(|claim| {
                claim.namespace.as_deref() == Some(self.namespace.as_str())
                    && claim
                        .name
                        .as_ref()
                        .is_some_and(|name| pvc_names.contains(name))
            });
            if !claim_matches {
                continue;
            }
            if let Some(name) = volume.metadata.name {
                resources.push(format!("PersistentVolume/{name}"));
            }
        }

        Ok(resources)
    }

    async fn environment_persistent_volume_claims(
        &self,
        env_id: &str,
        sandbox_names: &BTreeSet<String>,
        recorded_pvc_uid: Option<&str>,
    ) -> anyhow::Result<Vec<String>> {
        let pvcs = self
            .persistent_volume_claims()
            .list(&ListParams::default())
            .await
            .map_err(|error| anyhow::anyhow!("list PersistentVolumeClaims: {error}"))?;
        Ok(pvcs
            .items
            .into_iter()
            .filter(|pvc| {
                let environment_matches = pvc
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(LABEL_ENV_ID))
                    .is_some_and(|value| value == env_id);
                let owner_matches = pvc
                    .metadata
                    .owner_references
                    .as_ref()
                    .is_some_and(|owners| {
                        owners
                            .iter()
                            .any(|owner| sandbox_names.contains(&owner.name))
                    });
                let recorded_matches = recorded_pvc_uid
                    .is_some_and(|recorded| pvc.metadata.uid.as_deref() == Some(recorded));
                environment_matches || owner_matches || recorded_matches
            })
            .filter_map(|pvc| pvc.metadata.name)
            .collect())
    }

    async fn ensure_dynamic(
        &self,
        api: Api<DynamicObject>,
        name: &str,
        rendered: Value,
    ) -> anyhow::Result<()> {
        let is_service = rendered.get("kind").and_then(Value::as_str) == Some("Service");
        let mut obj: DynamicObject = serde_json::from_value(rendered)?;
        let mut existing = match api.get(name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => {
                match api.create(&PostParams::default(), &obj).await {
                    Ok(_) => return Ok(()),
                    Err(kube::Error::Api(e)) if e.code == 409 => api
                        .get(name)
                        .await
                        .map_err(|e| anyhow::anyhow!("re-get {name}: {e}"))?,
                    Err(e) => return Err(anyhow::anyhow!("create {name}: {e}")),
                }
            }
            Err(e) => return Err(anyhow::anyhow!("get {name}: {e}")),
            Ok(existing) => existing,
        };

        for _ in 0..3 {
            obj.metadata.resource_version = existing.metadata.resource_version.clone();
            if is_service {
                preserve_service_allocated_fields(&mut obj, &existing);
            }
            match api.replace(name, &PostParams::default(), &obj).await {
                Ok(_) => return Ok(()),
                Err(kube::Error::Api(e)) if e.code == 409 => {
                    existing = api
                        .get(name)
                        .await
                        .map_err(|e| anyhow::anyhow!("re-get {name}: {e}"))?;
                }
                Err(e) => return Err(anyhow::anyhow!("update {name}: {e}")),
            }
        }
        anyhow::bail!("update {name}: too many conflicts")
    }

    async fn resolve_direct_udp_service_opts(
        &self,
        opts: &TemplateOpts,
    ) -> anyhow::Result<TemplateOpts> {
        let mut opts = opts.clone();
        if !opts.direct_udp_lb_enabled {
            return Ok(opts);
        }
        if opts.direct_udp_lb_ip.trim().is_empty() {
            anyhow::bail!("direct UDP LoadBalancer is enabled but no IP is configured");
        }
        if opts.direct_udp_lb_port == 0 {
            opts.direct_udp_lb_port = i64::from(self.allocate_direct_udp_port(&opts).await?);
        } else {
            validate_direct_udp_port(opts.direct_udp_lb_port)
                .map_err(|e| anyhow::anyhow!("direct UDP LoadBalancer port: {e}"))?;
        }
        Ok(opts)
    }

    async fn allocate_direct_udp_port(&self, opts: &TemplateOpts) -> anyhow::Result<u16> {
        let services = self.services();
        let name = direct_udp_service_name(&opts.environment_id);
        match services.get(&name).await {
            Ok(existing) => {
                if let Some(port) = direct_udp_service_port(&existing) {
                    return Ok(port);
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => return Err(anyhow::anyhow!("get direct UDP Service {name}: {e}")),
        }

        let (start, end) = direct_udp_port_range(opts)?;
        let used = self.used_direct_udp_ports(opts).await?;
        let width = u32::from(end) - u32::from(start) + 1;
        let mut hasher = Crc32Hasher::new();
        hasher.update(opts.environment_id.as_bytes());
        let offset = hasher.finalize() % width;
        for step in 0..width {
            let port = u32::from(start) + ((offset + step) % width);
            let port = u16::try_from(port).expect("port range is u16");
            if !used.contains(&port) {
                return Ok(port);
            }
        }
        anyhow::bail!("no free direct UDP LoadBalancer ports in configured range {start}-{end}")
    }

    async fn used_direct_udp_ports(&self, opts: &TemplateOpts) -> anyhow::Result<BTreeSet<u16>> {
        let ip = opts.direct_udp_lb_ip.trim();
        let list = self
            .services()
            .list(&ListParams::default().labels("codewire.sh/runtime-network=direct-udp"))
            .await
            .map_err(|e| anyhow::anyhow!("list direct UDP Services: {e}"))?;
        Ok(list
            .items
            .iter()
            .filter(|service| direct_udp_service_ip_matches(service, ip))
            .filter_map(direct_udp_service_port)
            .collect())
    }

    /// Mirrors `WaitForReady`: the claim's Ready condition ends the wait; a
    /// terminal container failure on the backing pod (ImagePullBackOff & co —
    /// which the claim watcher never surfaces) fails it early with the
    /// same `pod <name>: <reason>: <message>` error the Go poller
    /// produces, so permanent-failure detection matches.
    ///
    /// Create and start block on this wait, so it wakes on the claim's next
    /// change rather than a fixed poll. Every wake re-reads the claim, and a
    /// missed or failed watch only falls back to the old 2-second re-read.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    pub async fn wait_for_ready(&self, env_id: &str, timeout: Duration) -> anyhow::Result<()> {
        tokio::select! {
            result = self.wait_for_ready_with_fallback(env_id, timeout, CLAIM_READY_FALLBACK_POLL) => result,
            refusal = Box::pin(self.refused_for_no_capacity(env_id)) => Err(refusal.into()),
        }
    }

    /// Ends once the scheduler has refused the environment's workspace Pod for
    /// lack of resources for [`NO_CAPACITY_GRACE`] without a break, and never
    /// otherwise, so each wait for a new Pod races it (#3635). An unreadable Pod
    /// breaks the run, so only an unbroken refusal counts.
    pub(super) async fn refused_for_no_capacity(&self, env_id: &str) -> NoCapacity {
        let name = claim_name(env_id);
        let mut refused_since = None;
        loop {
            let pod = self.claim_workspace_pod(&name).await;
            match pod.as_ref().and_then(capacity_refusal) {
                Some(refusal) => {
                    let since = *refused_since.get_or_insert_with(tokio::time::Instant::now);
                    if since.elapsed() >= NO_CAPACITY_GRACE {
                        return NoCapacity(refusal);
                    }
                }
                None => refused_since = None,
            }
            tokio::time::sleep(NO_CAPACITY_POLL).await;
        }
    }

    async fn wait_for_ready_with_fallback(
        &self,
        env_id: &str,
        timeout: Duration,
        fallback_poll: Duration,
    ) -> anyhow::Result<()> {
        let name = claim_name(env_id);
        let started = tokio::time::Instant::now();
        let deadline = started + timeout;
        loop {
            let claim = self
                .claims
                .get(&name)
                .await
                .map_err(|e| anyhow::anyhow!("get SandboxClaim {name}: {e}"))?;
            if let (true, _) = claim_ready_status(&claim) {
                return Ok(());
            }
            // Pod failure check after the same 10s scheduling grace
            // period Go's pollPodFailures uses.
            if started.elapsed() >= Duration::from_secs(10)
                && let Some(pod) = self.claim_workspace_pod(&name).await
                && let Some((reason, message)) = terminal_pod_failure_reason(&pod)
            {
                let err = anyhow::anyhow!("pod {name}: {reason}: {message}");
                tracing::warn!(claim = name, error = %err, "pod terminal failure detected");
                return Err(err);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("timeout waiting for SandboxClaim {name} to become Ready");
            }
            wait_for_object_change(&self.claims, &name, &claim, fallback_poll.min(remaining)).await;
        }
    }

    /// Mirrors `WaitForDeleted` with a poll loop.
    pub async fn wait_for_deleted(&self, env_id: &str, timeout: Duration) -> anyhow::Result<()> {
        let name = claim_name(env_id);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.claims.get(&name).await {
                Err(kube::Error::Api(e)) if e.code == 404 => return Ok(()),
                Err(e) => return Err(anyhow::anyhow!("get SandboxClaim {name}: {e}")),
                Ok(_) => {}
            }
            if tokio::time::Instant::now() + Duration::from_secs(2) >= deadline {
                anyhow::bail!("timeout waiting for SandboxClaim {name} to be deleted");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Mirrors `pollPodFailures`' per-tick check: resolve the pod
    /// behind the claim, then look for terminal waiting reasons.
    async fn claim_workspace_pod(&self, claim: &str) -> Option<Pod> {
        // No Claim-name fallback: an unbound Claim has no Pod to inspect yet.
        let sandbox_name = match self.claims.get(claim).await {
            Ok(c) => claim_bound_sandbox_name(&c)?.to_string(),
            Err(_) => return None,
        };
        let pod_name = match self.sandboxes().get(&sandbox_name).await {
            Ok(sandbox) => sandbox_pod_name(&sandbox, &sandbox_name).to_owned(),
            Err(_) => sandbox_name.clone(),
        };
        // No Pod yet: not scheduled either.
        self.pods().get(&pod_name).await.ok()
    }
}

/// The scheduler's message when it refused `pod` for lack of a resource, not for
/// a taint, a selector or a volume alone: those are not "full".
fn capacity_refusal(pod: &Pod) -> Option<String> {
    let condition = pod
        .status
        .as_ref()?
        .conditions
        .as_deref()?
        .iter()
        .find(|condition| condition.type_ == "PodScheduled")?;
    let message = condition.message.as_deref().unwrap_or_default();
    (condition.status == "False"
        && condition.reason.as_deref() == Some("Unschedulable")
        && (message.contains("Insufficient ") || message.contains("Too many pods")))
    .then(|| message.to_owned())
}

fn delete_params_for_observed_uid(uid: &str) -> DeleteParams {
    DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn direct_udp_port_range(opts: &TemplateOpts) -> anyhow::Result<(u16, u16)> {
    let start = if opts.direct_udp_lb_port_start == 0 {
        DEFAULT_DIRECT_UDP_LB_PORT_START
    } else {
        validate_direct_udp_port(opts.direct_udp_lb_port_start)
            .map_err(|e| anyhow::anyhow!("direct UDP LoadBalancer port start: {e}"))?
    };
    let end = if opts.direct_udp_lb_port_end == 0 {
        DEFAULT_DIRECT_UDP_LB_PORT_END
    } else {
        validate_direct_udp_port(opts.direct_udp_lb_port_end)
            .map_err(|e| anyhow::anyhow!("direct UDP LoadBalancer port end: {e}"))?
    };
    if start > end {
        anyhow::bail!("direct UDP LoadBalancer port range start {start} is greater than end {end}");
    }
    Ok((start, end))
}

fn workspace_pod_selector(env_id: &str) -> String {
    format!("{LABEL_ENV_ID}={env_id},{LABEL_TYPE}=workspace")
}

fn validate_direct_udp_port(port: i64) -> Result<u16, &'static str> {
    match u16::try_from(port) {
        Ok(port) if port > 0 => Ok(port),
        _ => Err("must be a UDP port from 1 to 65535"),
    }
}

fn direct_udp_service_port(service: &DynamicObject) -> Option<u16> {
    service
        .data
        .pointer("/spec/ports")
        .and_then(Value::as_array)?
        .iter()
        .find(|port| {
            port["protocol"].as_str() == Some("UDP")
                && port["targetPort"].as_i64()
                    == Some(i64::from(codewire_daemon_proto::WORKSPACE_TAILNET_UDP_PORT))
        })
        .and_then(|port| port["port"].as_i64())
        .and_then(|port| u16::try_from(port).ok())
}

fn direct_udp_service_ip_matches(service: &DynamicObject, ip: &str) -> bool {
    service
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get("lbipam.cilium.io/ips"))
        .is_some_and(|raw| {
            raw.split(',')
                .map(str::trim)
                .any(|candidate| candidate == ip)
        })
}

fn preserve_service_allocated_fields(obj: &mut DynamicObject, existing: &DynamicObject) {
    let Some(new_spec) = obj.data.get_mut("spec").and_then(Value::as_object_mut) else {
        return;
    };
    let Some(existing_spec) = existing.data.get("spec").and_then(Value::as_object) else {
        return;
    };
    for key in ["clusterIP", "clusterIPs"] {
        if !new_spec.contains_key(key)
            && let Some(value) = existing_spec.get(key)
        {
            new_spec.insert(key.to_string(), value.clone());
        }
    }
}

async fn delete_dynamic(api: &Api<DynamicObject>, name: &str) -> anyhow::Result<()> {
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(anyhow::anyhow!("delete {name}: {e}")),
    }
}

async fn dynamic_exists(api: &Api<DynamicObject>, name: &str) -> anyhow::Result<bool> {
    match api.get(name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(false),
        Err(error) => Err(anyhow::anyhow!("get {name}: {error}")),
    }
}

/// Whether a listed or hinted object belongs to `env_id` for cleanup. A
/// labelled object must carry this environment's label. An identity-free
/// per-environment template (B2.4) carries no environment label; its name is
/// this environment's own derived name (`<base>-<env_id>`), so an unlabelled
/// object is accepted when its name ends in `-<env_id>`. Shared objects such
/// as warm-pool templates (`cw-pool-*`) never end in an environment ID, so
/// they are never taken for one environment's.
fn owned_by_environment(metadata: &kube::api::ObjectMeta, env_id: &str) -> bool {
    match metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_ENV_ID))
    {
        Some(value) => value == env_id,
        None => {
            !env_id.trim().is_empty()
                && metadata
                    .name
                    .as_deref()
                    .is_some_and(|name| name.ends_with(&format!("-{env_id}")))
        }
    }
}

async fn environment_owned_objects(
    api: &Api<DynamicObject>,
    env_id: &str,
    kind: &str,
    name_hint: Option<&str>,
) -> anyhow::Result<BTreeMap<String, String>> {
    anyhow::ensure!(
        !env_id.trim().is_empty(),
        "environment identity is required for cleanup"
    );
    // An identity-free template carries no environment label, so templates
    // are listed whole and kept by ownership. Destroy then finds the
    // environment's template by its own name, not only through the hint
    // derived from its preset's current image: a preset whose image changed,
    // or whose configuration was removed, after the environment was created
    // names another template or none (#2831).
    let listed = if kind == "SandboxTemplate" {
        ListParams::default()
    } else {
        ListParams::default().labels(&format!("{LABEL_ENV_ID}={env_id}"))
    };
    let mut objects: Vec<DynamicObject> = api
        .list(&listed)
        .await
        .map_err(|error| anyhow::anyhow!("list owned {kind} for {env_id}: {error}"))?
        .items
        .into_iter()
        .filter(|object| owned_by_environment(&object.metadata, env_id))
        .collect();
    if let Some(name) = name_hint
        && !objects
            .iter()
            .any(|object| object.metadata.name.as_deref() == Some(name))
    {
        match api.get(name).await {
            Ok(object) => {
                anyhow::ensure!(
                    owned_by_environment(&object.metadata, env_id),
                    "hinted {kind} does not belong to the environment"
                );
                objects.push(object);
            }
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(error) => return Err(anyhow::anyhow!("get hinted {kind}: {error}")),
        }
    }
    objects
        .into_iter()
        .map(|object| {
            let name = object
                .metadata
                .name
                .filter(|name| !name.is_empty())
                .ok_or_else(|| anyhow::anyhow!("listed {kind} has no name"))?;
            let uid = object
                .metadata
                .uid
                .filter(|uid| !uid.is_empty())
                .ok_or_else(|| anyhow::anyhow!("listed {kind} has no UID"))?;
            Ok((name, uid))
        })
        .collect()
}

impl SandboxClient {
    /// Mirrors `ensureSandboxTemplateDynamic`: create when absent,
    /// otherwise update (3 retries on resource-version conflicts).
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %opts.environment_id))]
    pub async fn ensure_sandbox_template(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        opts.validate_confidential_storage_manifest()?;
        let name = &opts.name;
        let templates = self.templates();
        let rendered = render_sandbox_template(&self.namespace, opts);
        let mut template: DynamicObject = serde_json::from_value(rendered)?;

        let mut existing = match templates.get(name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => {
                match templates.create(&PostParams::default(), &template).await {
                    Ok(_) => {
                        tracing::info!(name, namespace = self.namespace, "created SandboxTemplate");
                        return Ok(());
                    }
                    Err(kube::Error::Api(e)) if e.code == 409 => templates
                        .get(name)
                        .await
                        .map_err(|e| anyhow::anyhow!("re-get SandboxTemplate {name}: {e}"))?,
                    Err(e) => return Err(anyhow::anyhow!("create SandboxTemplate {name}: {e}")),
                }
            }
            Err(e) => return Err(anyhow::anyhow!("get SandboxTemplate {name}: {e}")),
            Ok(existing) => existing,
        };

        for _ in 0..3 {
            template.metadata.resource_version = existing.metadata.resource_version.clone();
            match templates
                .replace(name, &PostParams::default(), &template)
                .await
            {
                Ok(_) => {
                    tracing::info!(name, namespace = self.namespace, "updated SandboxTemplate");
                    return Ok(());
                }
                Err(kube::Error::Api(e)) if e.code == 409 => {
                    existing = templates
                        .get(name)
                        .await
                        .map_err(|e| anyhow::anyhow!("re-get SandboxTemplate {name}: {e}"))?;
                }
                Err(e) => return Err(anyhow::anyhow!("update SandboxTemplate {name}: {e}")),
            }
        }
        anyhow::bail!("update SandboxTemplate {name}: too many conflicts")
    }

    /// Ensure the zero-replica shadow pool required by SandboxClaim.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %environment_id))]
    pub async fn ensure_shadow_pool(
        &self,
        name: &str,
        template_ref: &str,
        environment_id: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            name == super::shadow_warm_pool_name(template_ref),
            "claim shadow name does not match its environment template"
        );
        anyhow::ensure!(
            !environment_id.is_empty() && environment_id.trim() == environment_id,
            "claim shadow requires a canonical environment id"
        );
        let pools = self.warm_pools();
        let rendered =
            render_sandbox_shadow_pool(&self.namespace, name, template_ref, environment_id);
        let mut pool: DynamicObject = serde_json::from_value(rendered)?;

        let existing = match pools.get(name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => {
                pools
                    .create(&PostParams::default(), &pool)
                    .await
                    .map_err(|e| anyhow::anyhow!("create SandboxWarmPool {name}: {e}"))?;
                tracing::info!(name, "created zero-replica SandboxWarmPool");
                return Ok(());
            }
            Err(e) => return Err(anyhow::anyhow!("get SandboxWarmPool {name}: {e}")),
            Ok(existing) => existing,
        };

        pool.metadata.resource_version = existing.metadata.resource_version.clone();
        pools
            .replace(name, &PostParams::default(), &pool)
            .await
            .map_err(|e| anyhow::anyhow!("update SandboxWarmPool {name}: {e}"))?;
        tracing::info!(name, "updated zero-replica SandboxWarmPool");
        Ok(())
    }

    /// Delete an environment-scoped shadow pool. NotFound is success.
    pub async fn delete_shadow_pool(&self, name: &str) -> anyhow::Result<()> {
        match self
            .warm_pools()
            .delete(name, &DeleteParams::default())
            .await
        {
            Ok(_) => {
                tracing::info!(
                    name,
                    namespace = self.namespace,
                    "deleted environment shadow SandboxWarmPool"
                );
                Ok(())
            }
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("delete SandboxWarmPool {name}: {e}")),
        }
    }

    /// Retire shared performance warm pools from releases that predate the
    /// per-environment authenticated daemon boundary. The new create path can
    /// emit only `shadow-pool-*` objects, so every accepted candidate is
    /// historical. Observe every claim before the first delete so a retained
    /// or in-flight environment fails the whole pass closed.
    pub async fn retire_legacy_shared_warm_pools(&self) -> anyhow::Result<usize> {
        let pools = self.warm_pools();
        let listed = pools
            .list(&ListParams::default())
            .await
            .map_err(|error| anyhow::anyhow!("list legacy SandboxWarmPools: {error}"))?;
        let mut candidates = BTreeSet::new();
        for pool in listed.items {
            let name = pool.metadata.name.unwrap_or_default();
            if !name.starts_with(LEGACY_SHARED_WARM_POOL_PREFIX) {
                continue;
            }
            let template_name = pool
                .data
                .pointer("/spec/sandboxTemplateRef/name")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("legacy SandboxWarmPool {name} has no exact template reference")
                })?;
            anyhow::ensure!(
                legacy_shared_warm_pool_name_matches(&name, template_name),
                "refusing malformed legacy SandboxWarmPool {name} for template {template_name}"
            );
            candidates.insert(name);
        }
        if candidates.is_empty() {
            return Ok(0);
        }

        let claims = self
            .claims
            .list(&ListParams::default())
            .await
            .map_err(|error| {
                anyhow::anyhow!("list SandboxClaims before legacy retirement: {error}")
            })?;
        let mut referenced = BTreeSet::new();
        for claim in claims.items {
            let Some(pool_name) = claim
                .data
                .pointer("/spec/warmPoolRef/name")
                .and_then(Value::as_str)
            else {
                continue;
            };
            if candidates.contains(pool_name) {
                referenced.insert(pool_name.to_string());
            }
        }
        anyhow::ensure!(
            referenced.is_empty(),
            "legacy shared warm pools remain referenced by SandboxClaims: {}",
            referenced.into_iter().collect::<Vec<_>>().join(",")
        );

        let mut retired = 0;
        for name in candidates {
            match pools.delete(&name, &DeleteParams::default()).await {
                Ok(_) => {
                    retired += 1;
                    tracing::info!(
                        name,
                        namespace = self.namespace,
                        "retired legacy shared SandboxWarmPool"
                    );
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {
                    retired += 1;
                    tracing::info!(
                        name,
                        namespace = self.namespace,
                        "legacy shared SandboxWarmPool was already absent"
                    );
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "delete legacy SandboxWarmPool {name}: {error}"
                    ));
                }
            }
        }
        Ok(retired)
    }

    /// Mirrors `GetSandboxClaimReadyStatus`: (exists, ready, reason).
    pub async fn get_sandbox_claim_ready_status(
        &self,
        env_id: &str,
    ) -> anyhow::Result<(bool, bool, String)> {
        match self.get_sandbox_claim(env_id).await? {
            None => Ok((false, false, String::new())),
            Some(claim) => {
                let (ready, reason) = claim_ready_status(&claim);
                Ok((true, ready, reason))
            }
        }
    }

    /// The creation of the PersistentVolume bound to the workspace PVC
    /// `pvc_name`, for start timing: one PVC read and one PersistentVolume
    /// list narrowed to the bound volume's name (orchestration may list, not
    /// get, PersistentVolumes). `None` while the PVC is absent or unbound, or
    /// when the volume does not claim this exact PVC.
    pub async fn workspace_volume_created_at(
        &self,
        pvc_name: &str,
    ) -> anyhow::Result<Option<Timestamp>> {
        let Some(pvc) = self
            .persistent_volume_claims()
            .get_opt(pvc_name)
            .await
            .map_err(|error| anyhow::anyhow!("get workspace PVC {pvc_name}: {error}"))?
        else {
            return Ok(None);
        };
        let Some(volume_name) = pvc
            .spec
            .as_ref()
            .and_then(|spec| spec.volume_name.clone())
            .filter(|name| !name.is_empty())
        else {
            return Ok(None);
        };
        let volumes = self
            .persistent_volumes()
            .list(&ListParams::default().fields(&format!("metadata.name={volume_name}")))
            .await
            .map_err(|error| anyhow::anyhow!("list PersistentVolume {volume_name}: {error}"))?;
        Ok(volumes
            .items
            .into_iter()
            .find(|volume| {
                volume.metadata.name.as_deref() == Some(volume_name.as_str())
                    && volume
                        .spec
                        .as_ref()
                        .and_then(|spec| spec.claim_ref.as_ref())
                        .is_some_and(|claim| {
                            claim.namespace.as_deref() == Some(self.namespace.as_str())
                                && claim.name.as_deref() == Some(pvc_name)
                                && claim.uid.is_some()
                                && claim.uid == pvc.metadata.uid
                        })
            })
            .and_then(|volume| volume.metadata.creation_timestamp)
            .map(|time| time.0))
    }

    /// Mirrors `ClientBackend.ProbeEnvironment`.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    pub async fn probe_environment(&self, env_id: &str) -> anyhow::Result<ProbeResult> {
        let (exists, ready, reason) = self
            .get_sandbox_claim_ready_status(env_id)
            .await
            .map_err(|e| anyhow::anyhow!("probe get claim status: {e}"))?;
        if !exists {
            return Ok(ProbeResult::default());
        }

        let mut result = ProbeResult {
            claim_exists: true,
            claim_ready: ready,
            claim_reason: reason,
            ..Default::default()
        };

        let claim = claim_name(env_id);
        let mut claim_created_at = None;
        let sandbox_name = match self.claims.get(&claim).await {
            Ok(c) => {
                claim_created_at = c.metadata.creation_timestamp.as_ref().map(|time| time.0);
                claim_bound_sandbox_name(&c).unwrap_or_default().to_string()
            }
            Err(_) => String::new(),
        };
        // No Claim-name fallback: a Claim that names no Sandbox has no Pod.
        let mut pod_lookup = sandbox_name.clone();
        if !sandbox_name.is_empty()
            && let Ok(sb) = self.sandboxes().get(&sandbox_name).await
        {
            // Like getSandboxReplicas: Suspended reads 0; any other existing
            // Sandbox is treated as one running slot.
            result.sandbox_suspended = sb
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some("Suspended");
            result.replicas = if result.sandbox_suspended { 0 } else { 1 };
            result.launch_type = sb
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(super::warm_pool::LAUNCH_TYPE_LABEL))
                .cloned()
                .unwrap_or_default();
            pod_lookup = sandbox_pod_name(&sb, &sandbox_name).to_owned();
        }

        if !pod_lookup.is_empty()
            && let Ok(pod) = self.pods().get(&pod_lookup).await
        {
            result.pod_exists = true;
            result.pod_timeline = PodStartTimeline {
                claim_created_at,
                ..PodStartTimeline::from_pod(&pod)
            };
            result.workspace_pvc_name = workspace_pvc_claim_name(&pod).unwrap_or_default();
            result.pod_uid = pod.metadata.uid.clone().unwrap_or_default();
            result.pod_deleting_at = pod.metadata.deletion_timestamp.as_ref().map(|time| time.0);
            if let Some(status) = &pod.status {
                result.pod_phase = status.phase.clone().unwrap_or_default();
                result.pod_ip = status.pod_ip.clone().unwrap_or_default();
            }
            if let Some(spec) = &pod.spec {
                result.node_name = spec.node_name.clone().unwrap_or_default();
            }
            result.pod_name = pod.metadata.name.clone().unwrap_or_default();
        }

        Ok(result)
    }
}

/// Mirrors `terminalWaitingReasons`.
const TERMINAL_WAITING_REASONS: [&str; 6] = [
    "ImagePullBackOff",
    "ErrImagePull",
    "InvalidImageName",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
];

fn pod_requires_product_replacement(pod: &Pod) -> bool {
    terminal_pod_failure_reason(pod).is_some()
}

/// Classify the complete Pod start boundary. Kubernetes reports image and
/// runtime failures on both init and regular containers, while a completed
/// Pod can carry only a terminal phase. All three observations must release
/// the bounded product wait so the owning lifecycle can retry the exact Pod
/// incarnation instead of waiting for the confidential timeout.
fn terminal_pod_failure_reason(pod: &Pod) -> Option<(String, String)> {
    let status = pod.status.as_ref()?;
    if let Some(phase) = status
        .phase
        .as_deref()
        .filter(|phase| matches!(*phase, "Failed" | "Succeeded"))
    {
        let reason = status
            .reason
            .clone()
            .filter(|reason| !reason.trim().is_empty())
            .unwrap_or_else(|| format!("Pod{phase}"));
        // A Pod whose container failed carries no message of its own: name
        // each terminated container and how it ended (exit code, reason such
        // as OOMKilled, signal), so the failure is diagnosable after the Pod
        // is gone.
        let message = status
            .message
            .clone()
            .filter(|message| !message.trim().is_empty())
            .unwrap_or_else(|| terminated_containers(status));
        return Some((reason, message));
    }

    status
        .init_container_statuses
        .as_deref()
        .into_iter()
        .flatten()
        .chain(status.container_statuses.as_deref().into_iter().flatten())
        .filter_map(|container| container.state.as_ref()?.waiting.as_ref())
        .find_map(|waiting| {
            let reason = waiting.reason.as_deref().unwrap_or_default();
            TERMINAL_WAITING_REASONS.contains(&reason).then(|| {
                (
                    reason.to_string(),
                    waiting.message.clone().unwrap_or_default(),
                )
            })
        })
}

/// Each init and regular container that terminated, as
/// `name exited CODE (REASON, signal N)`, joined by `; `.
fn terminated_containers(status: &k8s_openapi::api::core::v1::PodStatus) -> String {
    status
        .init_container_statuses
        .as_deref()
        .into_iter()
        .flatten()
        .chain(status.container_statuses.as_deref().into_iter().flatten())
        .filter_map(|container| {
            let terminated = container.state.as_ref()?.terminated.as_ref()?;
            let mut detail = Vec::new();
            if let Some(reason) = terminated.reason.as_deref().filter(|r| !r.is_empty()) {
                detail.push(reason.to_string());
            }
            if let Some(signal) = terminated.signal.filter(|signal| *signal != 0) {
                detail.push(format!("signal {signal}"));
            }
            Some(if detail.is_empty() {
                format!("{} exited {}", container.name, terminated.exit_code)
            } else {
                format!(
                    "{} exited {} ({})",
                    container.name,
                    terminated.exit_code,
                    detail.join(", ")
                )
            })
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Mirrors `isClaimReady`: (ready, reason).
pub fn claim_ready_status(claim: &DynamicObject) -> (bool, String) {
    let Some(conditions) = claim
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
    else {
        return (false, "no conditions".to_string());
    };
    for cond in conditions {
        if cond.get("type").and_then(Value::as_str) != Some("Ready") {
            continue;
        }
        let status = cond
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let reason = cond
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        return (status == "True", reason);
    }
    (false, "no Ready condition".to_string())
}

/// The claim readiness wait re-reads at least this often, covering a watch
/// that cannot be opened and the Pod failure check.
const CLAIM_READY_FALLBACK_POLL: Duration = Duration::from_secs(2);

/// Returns on the first change to `name` after the observed revision, or
/// once `fallback_poll` elapses. A watch that cannot open, reports an error,
/// or ends early waits out the fallback, so a broken watch never turns into
/// a tight read loop.
async fn wait_for_object_change(
    api: &Api<DynamicObject>,
    name: &str,
    observed: &DynamicObject,
    fallback_poll: Duration,
) {
    use futures::StreamExt;
    use kube::api::{WatchEvent, WatchParams};

    let changed = async {
        let Some(version) = observed.metadata.resource_version.as_deref() else {
            return std::future::pending::<()>().await;
        };
        let params = WatchParams::default()
            .fields(&format!("metadata.name={name}"))
            .timeout(fallback_poll.as_secs().clamp(1, 290) as u32)
            .disable_bookmarks();
        let Ok(events) = api.watch(&params, version).await else {
            return std::future::pending::<()>().await;
        };
        let mut events = std::pin::pin!(events);
        while let Some(event) = events.next().await {
            if matches!(
                event,
                Ok(WatchEvent::Added(_) | WatchEvent::Modified(_) | WatchEvent::Deleted(_))
            ) {
                return;
            }
        }
        std::future::pending::<()>().await
    };
    let _ = tokio::time::timeout(fallback_poll, changed).await;
}

fn parse_gib_quantity(value: &str) -> anyhow::Result<i32> {
    let gib = value
        .strip_suffix("Gi")
        .ok_or_else(|| anyhow::anyhow!("unsupported workspace storage quantity {value:?}"))?
        .parse::<i32>()?;
    if gib <= 0 {
        anyhow::bail!("workspace storage quantity must be positive");
    }
    Ok(gib)
}

fn workspace_pod_resize_state(
    pod: &Pod,
    fallback_name: &str,
) -> anyhow::Result<WorkspacePodResizeState> {
    let spec = pod
        .spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("workspace Pod {fallback_name} has no spec"))?;
    let workspace = spec
        .containers
        .iter()
        .find(|container| container.name == "workspace")
        .ok_or_else(|| {
            anyhow::anyhow!("workspace Pod {fallback_name} has no workspace container")
        })?;
    let incompatible = workspace
        .resize_policy
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|policy| {
            matches!(policy.resource_name.as_str(), "cpu" | "memory")
                && !matches!(policy.restart_policy.as_str(), "" | "NotRequired")
        });
    let restart_count = pod
        .status
        .as_ref()
        .and_then(|status| status.container_statuses.as_deref())
        .and_then(|statuses| statuses.iter().find(|status| status.name == "workspace"))
        .map_or(0, |status| status.restart_count);
    Ok(WorkspacePodResizeState {
        identity: WorkspacePodIdentity {
            name: pod
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| fallback_name.to_string()),
            uid: pod.metadata.uid.clone().unwrap_or_default(),
        },
        runtime_class_name: spec.runtime_class_name.clone().unwrap_or_default(),
        restart_count,
        live_resize_compatible: incompatible.is_none(),
        incompatibility_reason: incompatible.map(|policy| {
            format!(
                "{} uses restartPolicy {}",
                policy.resource_name, policy.restart_policy
            )
        }),
    })
}

/// The kubelet reports `compute` as the workspace container's actual requests
/// and limits.
fn workspace_resources_match(pod: &Pod, compute: &WorkspaceCompute) -> bool {
    resources_match(
        pod.status
            .as_ref()
            .and_then(|status| status.container_statuses.as_deref())
            .and_then(|statuses| statuses.iter().find(|status| status.name == "workspace"))
            .and_then(|status| status.resources.as_ref()),
        compute,
    )
}

/// The Pod spec asks for `compute` as the workspace container's requests and
/// limits.
fn workspace_spec_resources_match(pod: &Pod, compute: &WorkspaceCompute) -> bool {
    resources_match(
        pod.spec
            .as_ref()
            .and_then(|spec| {
                spec.containers
                    .iter()
                    .find(|container| container.name == "workspace")
            })
            .and_then(|container| container.resources.as_ref()),
        compute,
    )
}

fn resources_match(resources: Option<&ResourceRequirements>, compute: &WorkspaceCompute) -> bool {
    let Some(resources) = resources else {
        return false;
    };
    [
        (resources.requests.as_ref(), &compute.cpu_request),
        (resources.limits.as_ref(), &compute.cpu_limit),
    ]
    .into_iter()
    .all(|(class, cpu)| {
        class.is_some_and(|values| {
            values
                .get("cpu")
                .is_some_and(|value| quantities_equal(&value.0, cpu))
                && values
                    .get("memory")
                    .is_some_and(|value| quantities_equal(&value.0, &compute.memory))
        })
    })
}

/// The CPU sharing a workspace Pod runs at, from its spec.
fn workspace_pod_cpu_sharing(pod: &Pod) -> CpuSharingRatio {
    let resources = pod
        .spec
        .as_ref()
        .and_then(|spec| {
            spec.containers
                .iter()
                .find(|container| container.name == "workspace")
        })
        .and_then(|container| container.resources.as_ref());
    let request = resources
        .and_then(|resources| resources.requests.as_ref())
        .and_then(|requests| requests.get("cpu"));
    let limit = resources
        .and_then(|resources| resources.limits.as_ref())
        .and_then(|limits| limits.get("cpu"));
    observed_cpu_sharing(
        request.map(|quantity| quantity.0.as_str()),
        limit.map(|quantity| quantity.0.as_str()),
    )
}

/// The CPU sharing a Sandbox or SandboxTemplate renders its workspace at.
fn runtime_object_cpu_sharing(data: &Value) -> CpuSharingRatio {
    let workspace = data
        .pointer("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array)
        .and_then(|containers| {
            containers.iter().find(|container| {
                container.get("name").and_then(Value::as_str) == Some("workspace")
            })
        });
    let cpu = |path| {
        workspace
            .and_then(|workspace| workspace.pointer(path))
            .and_then(Value::as_str)
    };
    observed_cpu_sharing(cpu("/resources/requests/cpu"), cpu("/resources/limits/cpu"))
}

fn observed_cpu_sharing(request: Option<&str>, limit: Option<&str>) -> CpuSharingRatio {
    let millicores = |quantity: Option<&str>| {
        parse_quantity_ratio(quantity?)
            .and_then(|(numerator, denominator)| i64::try_from(numerator * 1000 / denominator).ok())
    };
    match (millicores(request), millicores(limit)) {
        (Some(request), Some(limit)) => CpuSharingRatio::observed(request, limit),
        _ => CpuSharingRatio::NONE,
    }
}

/// Compare Kubernetes quantities by value rather than serialized form.
///
/// The kubelet canonicalizes equivalent requests (for example `3000m` to `3`
/// and `5120Mi` to `5Gi`). Resource convergence must accept that formatting
/// change without accepting a different value or a malformed observation.
pub(crate) fn quantities_equal(left: &str, right: &str) -> bool {
    let Some((left_numerator, left_denominator)) = parse_quantity_ratio(left) else {
        return false;
    };
    let Some((right_numerator, right_denominator)) = parse_quantity_ratio(right) else {
        return false;
    };
    match (
        left_numerator.checked_mul(right_denominator),
        right_numerator.checked_mul(left_denominator),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

pub(crate) fn parse_quantity_ratio(quantity: &str) -> Option<(i128, i128)> {
    let quantity = quantity.trim();
    if quantity.is_empty() {
        return None;
    }

    let (number, numerator_scale, denominator_scale) =
        if let Some(number) = quantity.strip_suffix("Ei") {
            (number, 1_i128.checked_shl(60)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Pi") {
            (number, 1_i128.checked_shl(50)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Ti") {
            (number, 1_i128.checked_shl(40)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Gi") {
            (number, 1_i128.checked_shl(30)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Mi") {
            (number, 1_i128.checked_shl(20)?, 1)
        } else if let Some(number) = quantity.strip_suffix("Ki") {
            (number, 1_i128.checked_shl(10)?, 1)
        } else if let Some((number, exponent)) = split_decimal_exponent(quantity) {
            if exponent >= 0 {
                (number, 10_i128.checked_pow(exponent.unsigned_abs())?, 1)
            } else {
                (number, 1, 10_i128.checked_pow(exponent.unsigned_abs())?)
            }
        } else if let Some(number) = quantity.strip_suffix('E') {
            (number, 10_i128.checked_pow(18)?, 1)
        } else if let Some(number) = quantity.strip_suffix('P') {
            (number, 10_i128.checked_pow(15)?, 1)
        } else if let Some(number) = quantity.strip_suffix('T') {
            (number, 10_i128.checked_pow(12)?, 1)
        } else if let Some(number) = quantity.strip_suffix('G') {
            (number, 10_i128.checked_pow(9)?, 1)
        } else if let Some(number) = quantity.strip_suffix('M') {
            (number, 10_i128.checked_pow(6)?, 1)
        } else if let Some(number) = quantity
            .strip_suffix('k')
            .or_else(|| quantity.strip_suffix('K'))
        {
            (number, 10_i128.checked_pow(3)?, 1)
        } else if let Some(number) = quantity.strip_suffix('m') {
            (number, 1, 10_i128.checked_pow(3)?)
        } else if let Some(number) = quantity.strip_suffix('u') {
            (number, 1, 10_i128.checked_pow(6)?)
        } else if let Some(number) = quantity.strip_suffix('n') {
            (number, 1, 10_i128.checked_pow(9)?)
        } else {
            (quantity, 1, 1)
        };

    let (numerator, denominator) = parse_decimal_ratio(number)?;
    let numerator = numerator.checked_mul(numerator_scale)?;
    let denominator = denominator.checked_mul(denominator_scale)?;
    if numerator <= 0 || denominator <= 0 {
        return None;
    }
    Some((numerator, denominator))
}

fn split_decimal_exponent(quantity: &str) -> Option<(&str, i32)> {
    let index = quantity.rfind(['e', 'E'])?;
    let (number, exponent) = quantity.split_at(index);
    let exponent = exponent.get(1..)?.parse::<i32>().ok()?;
    (!number.is_empty()).then_some((number, exponent))
}

fn parse_decimal_ratio(number: &str) -> Option<(i128, i128)> {
    let number = number.trim();
    if number.is_empty() || number.starts_with('-') {
        return None;
    }
    let number = number.strip_prefix('+').unwrap_or(number);
    let mut parts = number.split('.');
    let whole = parts.next()?;
    let fractional = parts.next().unwrap_or("");
    if parts.next().is_some()
        || (whole.is_empty() && fractional.is_empty())
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let denominator = 10_i128.checked_pow(u32::try_from(fractional.len()).ok()?)?;
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<i128>().ok()?
    };
    let fractional = if fractional.is_empty() {
        0
    } else {
        fractional.parse::<i128>().ok()?
    };
    Some((
        whole.checked_mul(denominator)?.checked_add(fractional)?,
        denominator,
    ))
}

/// The workspace container's `/resize` request: CPU and memory only, bound
/// to the observed incarnation. The API server refuses the patch when the Pod
/// no longer has this UID (the field is immutable) or this resourceVersion
/// (optimistic concurrency), so it can never apply to a replacement.
fn pod_resize_patch(uid: &str, resource_version: &str, compute: &WorkspaceCompute) -> Value {
    serde_json::json!({
        "metadata": { "uid": uid, "resourceVersion": resource_version },
        "spec": {
            "containers": [{
                "name": "workspace",
                "resources": {
                    "requests": { "cpu": compute.cpu_request, "memory": compute.memory },
                    "limits": { "cpu": compute.cpu_limit, "memory": compute.memory },
                },
            }],
        },
    })
}

/// A `PodResizePending=True reason=Infeasible` condition, and whether its
/// `observedGeneration` acknowledges the request accepted at `generation`.
/// Without both generations the condition cannot be attributed to this
/// request; the caller keeps waiting rather than fail a feasible one on a
/// stale condition.
fn infeasible_pod_resize(pod: &Pod, generation: Option<i64>) -> Option<(String, bool)> {
    let condition = pod
        .status
        .as_ref()?
        .conditions
        .as_deref()?
        .iter()
        .find(|condition| {
            condition.type_ == "PodResizePending"
                && condition.status == "True"
                && condition.reason.as_deref() == Some("Infeasible")
        })?;
    let message = condition
        .message
        .clone()
        .filter(|message| !message.trim().is_empty())
        .unwrap_or_else(|| "Kubernetes reported the requested resources as infeasible".into());
    let acknowledged = matches!(
        (generation, condition.observed_generation),
        (Some(requested), Some(observed)) if observed >= requested
    );
    Some((message, acknowledged))
}

/// The kubelet has seen the Pod spec at `generation`. Where the kubelet or
/// the API server reports no generation, resources alone decide.
fn pod_resize_acknowledged(pod: &Pod, generation: Option<i64>) -> bool {
    match (
        generation,
        pod.status
            .as_ref()
            .and_then(|status| status.observed_generation),
    ) {
        (Some(requested), Some(observed)) => observed >= requested,
        _ => true,
    }
}

/// `Applied` or `Settled` when the Pod's spec and kubelet-reported resources
/// agree on one side of a failed resize; `None` while anything is pending.
fn failed_live_resize_outcome(
    pod: &Pod,
    previous: (i32, i32),
    requested: (i32, i32),
) -> Option<FailedLiveResize> {
    let sharing = workspace_pod_cpu_sharing(pod);
    let runs = |(cpu, memory): (i32, i32)| {
        let compute = WorkspaceCompute::new(cpu, memory, sharing);
        workspace_spec_resources_match(pod, &compute) && workspace_resources_match(pod, &compute)
    };
    if runs(requested) {
        Some(FailedLiveResize::Applied)
    } else if runs(previous) && pod_resize_acknowledged(pod, pod.metadata.generation) {
        Some(FailedLiveResize::Settled)
    } else {
        None
    }
}

fn set_workspace_resources(data: &mut Value, compute: &WorkspaceCompute) -> anyhow::Result<()> {
    let containers = data
        .pointer_mut("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("runtime object has no PodTemplate containers"))?;
    let workspace = containers
        .iter_mut()
        .find(|container| container.get("name").and_then(Value::as_str) == Some("workspace"))
        .ok_or_else(|| anyhow::anyhow!("runtime object has no workspace container"))?;
    for (class, cpu) in [
        ("requests", &compute.cpu_request),
        ("limits", &compute.cpu_limit),
    ] {
        let resources = workspace
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("workspace container is not an object"))?
            .entry("resources")
            .or_insert_with(|| serde_json::json!({}));
        let class_values = resources
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("workspace resources are not an object"))?
            .entry(class)
            .or_insert_with(|| serde_json::json!({}));
        let class_values = class_values
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("workspace resource {class} are not an object"))?;
        class_values.insert("cpu".to_string(), Value::String(cpu.clone()));
        class_values.insert("memory".to_string(), Value::String(compute.memory.clone()));
    }
    Ok(())
}

/// Size a loop-mounted DinD data image for `disk_gb`, so the next Pod's
/// Docker data init (on a Block workspace, `mount-workspace`; or, in a
/// Sandbox not yet re-rendered, its DinD bootstrap) grows the image with the
/// workspace disk (#3554, #3208, #3718). DinD and the container that prepares
/// the image carry the same size, and each only ever grows: a smaller
/// rendering than one already carries is left alone, and so is a runtime
/// without a loop-mounted image (no DinD, or the confidential profile, whose
/// measured policy admits exactly what it was rendered with and whose volume
/// never expands).
fn set_docker_data_size(data: &mut Value, disk_gb: i32) -> anyhow::Result<()> {
    let desired = docker_data_size_gib(i64::from(disk_gb));
    for (array, name) in [
        ("containers", "dind"),
        ("initContainers", DOCKER_DATA_INIT_CONTAINER),
        ("initContainers", MOUNT_WORKSPACE_CONTAINER),
    ] {
        let Some(containers) = data
            .pointer_mut(&format!("/spec/podTemplate/spec/{array}"))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        let Some(container) = containers
            .iter_mut()
            .find(|container| container.get("name").and_then(Value::as_str) == Some(name))
        else {
            continue;
        };
        let Some(env) = container.get_mut("env").and_then(Value::as_array_mut) else {
            continue;
        };
        grow_docker_data_size(env, desired)?;
    }
    Ok(())
}

/// Raise one container's `CODEWIRE_DOCKER_DATA_SIZE` to `desired` GiB when it
/// loop-mounts the image and carries less.
fn grow_docker_data_size(env: &mut Vec<Value>, desired: i64) -> anyhow::Result<()> {
    let value_of = |env: &[Value], name: &str| {
        env.iter()
            .find(|entry| entry.get("name").and_then(Value::as_str) == Some(name))
            .and_then(|entry| entry.get("value"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    if value_of(env, "CODEWIRE_DOCKER_MOUNT_MODE").as_deref() != Some("loop") {
        return Ok(());
    }
    let current = value_of(env, "CODEWIRE_DOCKER_DATA_SIZE")
        .and_then(|size| size.strip_suffix('G')?.parse::<i64>().ok());
    if current.is_some_and(|current| current >= desired) {
        return Ok(());
    }
    let size = Value::String(format!("{desired}G"));
    match env.iter_mut().find(|entry| {
        entry.get("name").and_then(Value::as_str) == Some("CODEWIRE_DOCKER_DATA_SIZE")
    }) {
        Some(entry) => {
            entry
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("Docker data environment entry is not an object"))?
                .insert("value".into(), size);
        }
        None => env.push(serde_json::json!({ "name": "CODEWIRE_DOCKER_DATA_SIZE", "value": size })),
    }
    Ok(())
}

fn set_workspace_volume_request(data: &mut Value, storage: &str) -> anyhow::Result<()> {
    let templates = data
        .pointer_mut("/spec/volumeClaimTemplates")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("runtime object has no volumeClaimTemplates"))?;
    let workspace = templates
        .iter_mut()
        .find(|template| {
            template.pointer("/metadata/name").and_then(Value::as_str) == Some("workspace")
        })
        .ok_or_else(|| anyhow::anyhow!("runtime object has no workspace volumeClaimTemplate"))?;
    let requests = workspace
        .pointer_mut("/spec/resources/requests")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("workspace volume has no resource requests"))?;
    requests.insert("storage".to_string(), Value::String(storage.to_string()));
    Ok(())
}

/// The Pod-template annotations a confidential workspace's measured runtime
/// owns: its init-data, its kernel parameters and its confidential volume.
const MEASURED_POD_ANNOTATIONS: [&str; 3] = [
    KATA_COCO_INIT_DATA_ANNOTATION_KEY,
    KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY,
    KATA_CONFIDENTIAL_VOLUME_ANNOTATION,
];

/// A confidential workspace's rendered Pod template as its measured
/// init-data authorizes it (Program #2238 B2c): the whole Pod spec and the
/// measured annotations. Start and terminal replacement publish exactly this
/// beside the authorization, so what boots is what Trustee authorizes.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MeasuredPodTemplate {
    spec: Value,
    /// The rendered egress, which the private template carries for the
    /// environment's Pods; the Sandbox has none.
    network_policy: Option<Value>,
    /// Every measured key, `None` where this rendering carries none.
    annotations: Vec<(&'static str, Option<String>)>,
}

impl MeasuredPodTemplate {
    pub(crate) fn render(namespace: &str, opts: &TemplateOpts) -> anyhow::Result<Self> {
        anyhow::ensure!(
            opts.measured_workspace_environment().is_some(),
            "a measured Pod template needs a confidential identity-free rendering"
        );
        opts.validate_confidential_storage_manifest()?;
        let rendered = render_sandbox_template(namespace, opts);
        let spec = rendered
            .pointer("/spec/podTemplate/spec")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("confidential rendering has no Pod spec"))?;
        let rendered_annotations = rendered
            .pointer("/spec/podTemplate/metadata/annotations")
            .and_then(Value::as_object);
        let annotations = MEASURED_POD_ANNOTATIONS
            .into_iter()
            .map(|key| {
                let value = rendered_annotations
                    .and_then(|annotations| annotations.get(key))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                (key, value)
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            annotations
                .iter()
                .any(|(key, value)| *key == KATA_COCO_INIT_DATA_ANNOTATION_KEY && value.is_some()),
            "confidential rendering has no measured init-data"
        );
        let network_policy = rendered.pointer("/spec/networkPolicy").cloned();
        Ok(Self {
            spec,
            network_policy,
            annotations,
        })
    }

    /// The init-data annotation the next Pod must carry.
    pub(crate) fn init_data(&self) -> &str {
        self.annotations
            .iter()
            .find(|(key, _)| *key == KATA_COCO_INIT_DATA_ANNOTATION_KEY)
            .and_then(|(_, value)| value.as_deref())
            .expect("a measured Pod template has init-data")
    }

    /// Whether `object` (a template or Sandbox) already carries this
    /// measurement. The init-data commits to every measured Pod-spec field,
    /// so equal measured annotations mean an equal measured Pod.
    fn published_on(&self, object: &DynamicObject) -> bool {
        let annotations = object
            .data
            .pointer("/spec/podTemplate/metadata/annotations")
            .and_then(Value::as_object);
        self.annotations.iter().all(|(key, value)| {
            annotations
                .and_then(|annotations| annotations.get(*key))
                .and_then(Value::as_str)
                == value.as_deref()
        })
    }

    /// Whether the private template carries the rendered egress. A template
    /// rendered before B2c lacks the binding listener's egress, so its daemon
    /// could never bind.
    fn egress_published_on(&self, template: &DynamicObject) -> bool {
        template.data.pointer("/spec/networkPolicy") == self.network_policy.as_ref()
    }

    /// The JSON Patch publishing it onto one suspended template or Sandbox,
    /// bound to its validated UID and resourceVersion; with `egress`, the
    /// template's rendered egress too. `None` when already published.
    fn json_patch(
        &self,
        object: &DynamicObject,
        egress: bool,
    ) -> anyhow::Result<Option<Patch<()>>> {
        let egress_current = !egress || self.egress_published_on(object);
        if self.published_on(object) && egress_current {
            return Ok(None);
        }
        let uid = object
            .metadata
            .uid
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("measured runtime object has no UID"))?;
        let version = object
            .metadata
            .resource_version
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("measured runtime object has no resource version"))?;
        let mut patch = vec![
            serde_json::json!({"op":"test", "path":"/metadata/uid", "value":uid}),
            serde_json::json!({"op":"test", "path":"/metadata/resourceVersion", "value":version}),
            serde_json::json!({"op":"replace", "path":"/spec/podTemplate/spec", "value":self.spec}),
        ];
        let existing = object
            .data
            .pointer("/spec/podTemplate/metadata/annotations")
            .and_then(Value::as_object);
        if object.data.pointer("/spec/podTemplate/metadata").is_none() {
            patch.push(
                serde_json::json!({"op":"add", "path":"/spec/podTemplate/metadata", "value":{}}),
            );
        }
        if existing.is_none() {
            patch.push(serde_json::json!(
                {"op":"add", "path":"/spec/podTemplate/metadata/annotations", "value":{}}
            ));
        }
        if !egress_current {
            patch.push(match &self.network_policy {
                Some(policy) => {
                    serde_json::json!({"op":"add", "path":"/spec/networkPolicy", "value":policy})
                }
                None => serde_json::json!({"op":"remove", "path":"/spec/networkPolicy"}),
            });
        }
        for (key, value) in &self.annotations {
            let path = format!(
                "/spec/podTemplate/metadata/annotations/{}",
                key.replace('~', "~0").replace('/', "~1")
            );
            match value {
                Some(value) => {
                    patch.push(serde_json::json!({"op":"add", "path":path, "value":value}));
                }
                None if existing.is_some_and(|annotations| annotations.contains_key(*key)) => {
                    patch.push(serde_json::json!({"op":"remove", "path":path}));
                }
                None => {}
            }
        }
        Ok(Some(Patch::Json(serde_json::from_value(Value::Array(
            patch,
        ))?)))
    }

    /// The merge patch publishing it onto an allocated Sandbox whose Pod is
    /// being replaced: arrays such as containers and volumes are replaced
    /// whole, and an absent measured annotation is removed.
    fn merge_patch(&self) -> Value {
        let annotations = self
            .annotations
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_owned(),
                    value.clone().map(Value::String).unwrap_or(Value::Null),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        serde_json::json!({
            "spec": {
                "podTemplate": {
                    "metadata": { "annotations": annotations },
                    "spec": self.spec,
                },
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_namespace_must_carry_the_policy_labels() {
        let labels = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect()
        };
        let ready = labels(&[
            ("codewire.sh/resource-type", "sandbox"),
            ("codewire.sh/runtime-scope", "shared"),
            ("app.kubernetes.io/managed-by", "flux"),
        ]);
        assert!(super::sandbox_namespace_ready("prod-sandboxes", Some(&ready)).is_ok());
        let unscoped = labels(&[("codewire.sh/resource-type", "sandbox")]);
        let error = super::sandbox_namespace_ready("dev-sandboxes", Some(&unscoped))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("codewire.sh/runtime-scope=shared"),
            "{error}"
        );
        assert!(!error.contains("resource-type"), "{error}");
        let wrong = labels(&[
            ("codewire.sh/resource-type", "sandbox"),
            ("codewire.sh/runtime-scope", "dedicated"),
        ]);
        assert!(super::sandbox_namespace_ready("dev-sandboxes", Some(&wrong)).is_err());
        assert!(super::sandbox_namespace_ready("dev-sandboxes", None).is_err());
    }
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, Response, StatusCode, header};
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const SUPPORT_IMAGE: &str = crate::sandbox::template::TEST_SUPPORT_IMAGE;
    const MODE_CLAIM_PATH: &str = "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxclaims/sandbox-env-test";
    const MODE_SANDBOX_PATH: &str =
        "/apis/agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxes/workspace-env-test";

    #[derive(Clone, Copy)]
    enum ModeInterleave {
        ControllerUpdate,
        ReplaceUid,
        Delete,
        Reject(StatusCode),
        InvalidReply(u8),
    }

    struct ModeFixture {
        object: Value,
        writes: Vec<(Method, Value)>,
    }

    fn mode_sandbox() -> Value {
        json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "metadata": {
                "name": "workspace-env-test", "namespace": "dev-sandboxes",
                "uid": "sandbox-incarnation", "resourceVersion": "10",
                "annotations": {"agents.x-k8s.io/pod-name": "old-pod"}
            },
            "spec": {"operatingMode": "Suspended", "podTemplate": {"fixture": "preserve"}},
            "status": {"fixture": "before-controller-update"}
        })
    }

    fn mode_client(
        object: Value,
        interleave: ModeInterleave,
    ) -> (SandboxClient, Arc<Mutex<ModeFixture>>) {
        let state = Arc::new(Mutex::new(ModeFixture {
            object,
            writes: Vec::new(),
        }));
        let shared = Arc::clone(&state);
        let service = Router::new().fallback(move |request: Request<Body>| {
            let shared = Arc::clone(&shared);
            async move {
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let content_type = request.headers().get(header::CONTENT_TYPE).cloned();
                let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024).await.unwrap();
                let mut state = shared.lock().unwrap();
                let (status, body) = if method == Method::GET && path == MODE_CLAIM_PATH {
                    (StatusCode::OK, json!({
                        "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                        "metadata": {"name": "sandbox-env-test", "namespace": "dev-sandboxes"},
                        "status": {"sandbox": {"name": "workspace-env-test"}}
                    }))
                } else if method == Method::GET && path == MODE_SANDBOX_PATH {
                    let observed = state.object.clone();
                    // The response carries RV10, but the controller has already
                    // changed unrelated fields by the time the caller writes.
                    state.object["metadata"]["resourceVersion"] = json!("11");
                    state.object["metadata"]["annotations"].as_object_mut().unwrap()
                        .remove("agents.x-k8s.io/pod-name");
                    state.object["status"]["fixture"] = json!("controller-update-survives");
                    if matches!(interleave, ModeInterleave::ReplaceUid) {
                        state.object["metadata"]["uid"] = json!("replacement-incarnation");
                    }
                    (StatusCode::OK, observed)
                } else {
                    assert_eq!(path, MODE_SANDBOX_PATH, "mutation must use the resolved Sandbox, never the Claim or Pod");
                    let body: Value = serde_json::from_slice(&bytes).unwrap();
                    state.writes.push((method.clone(), body.clone()));
                    match interleave {
                        ModeInterleave::Delete => (StatusCode::NOT_FOUND, kubernetes_status("NotFound", 404)),
                        ModeInterleave::Reject(status) => (status, kubernetes_status("Rejected", status.as_u16())),
                        _ if method == Method::PUT => {
                            // Enforce real optimistic concurrency, not a fixed
                            // old-implementation rejection: stale PUTs conflict.
                            if body.pointer("/metadata/uid") != state.object.pointer("/metadata/uid")
                                || body.pointer("/metadata/resourceVersion") != state.object.pointer("/metadata/resourceVersion")
                            {
                                (StatusCode::CONFLICT, kubernetes_status("Conflict", 409))
                            } else {
                                state.object = body;
                                (StatusCode::OK, state.object.clone())
                            }
                        }
                        _ => {
                            assert_eq!(method, Method::PATCH);
                            assert_eq!(content_type.as_ref().map(|value| value.to_str().unwrap()), Some("application/json-patch+json"));
                            let operations = body.as_array().expect("JSON patch operations");
                            assert_eq!(operations.len(), 2, "only UID fence and mode mutation");
                            assert_eq!(operations[0]["op"], "test");
                            assert_eq!(operations[0]["path"], "/metadata/uid");
                            assert_eq!(operations[1]["op"], "add");
                            assert_eq!(operations[1]["path"], "/spec/operatingMode");
                            if operations[0].get("value") != state.object.pointer("/metadata/uid") {
                                (StatusCode::UNPROCESSABLE_ENTITY, kubernetes_status("Invalid", 422))
                            } else {
                                state.object["spec"]["operatingMode"] = operations[1]["value"].clone();
                                let mut response = state.object.clone();
                                if let ModeInterleave::InvalidReply(invalid) = interleave {
                                    match invalid {
                                        0 => response["metadata"]["uid"] = json!("replacement-incarnation"),
                                        1 => response["metadata"]["deletionTimestamp"] = json!("2026-09-07T00:00:00Z"),
                                        2 => response["metadata"]["name"] = json!("wrong-name"),
                                        3 => response["metadata"]["namespace"] = json!("wrong-namespace"),
                                        4 => response["spec"]["operatingMode"] = json!("Suspended"),
                                        _ => unreachable!(),
                                    }
                                }
                                (StatusCode::OK, response)
                            }
                        }
                    }
                };
                Response::builder().status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string())).unwrap()
            }
        });
        (
            SandboxClient::new(Client::new(service, "default"), "dev-sandboxes"),
            state,
        )
    }

    fn probe_client(claim: Value, sandbox: Option<Value>) -> SandboxClient {
        let service = Router::new().fallback(move |request: Request<Body>| {
            let (claim, sandbox) = (claim.clone(), sandbox.clone());
            async move {
                assert_eq!(request.method(), Method::GET, "a probe never mutates");
                let path = request.uri().path().to_string();
                let (status, body) = match (path.as_str(), sandbox) {
                    (MODE_CLAIM_PATH, _) => (StatusCode::OK, claim),
                    (MODE_SANDBOX_PATH, Some(sandbox)) => (StatusCode::OK, sandbox),
                    _ => (StatusCode::NOT_FOUND, kubernetes_status("NotFound", 404)),
                };
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        SandboxClient::new(Client::new(service, "default"), "dev-sandboxes")
    }

    #[tokio::test]
    async fn probe_reports_a_pod_being_deleted_and_not_one_that_finished() {
        let probed = |deleting: Option<&'static str>| async move {
            let service = Router::new().fallback(move |request: Request<Body>| async move {
                let path = request.uri().path().to_string();
                let body = if path == MODE_CLAIM_PATH {
                    json!({
                        "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                        "metadata": {"name": "sandbox-env-test", "namespace": "dev-sandboxes"},
                        "status": {"sandbox": {"name": "workspace-env-test"}},
                    })
                } else if path == MODE_SANDBOX_PATH {
                    mode_sandbox()
                } else {
                    let mut pod = json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": "workspace-env-test", "namespace": "dev-sandboxes", "uid": "pod-uid"},
                        "status": {"phase": "Succeeded"},
                    });
                    if let Some(at) = deleting {
                        pod["metadata"]["deletionTimestamp"] = json!(at);
                    }
                    pod
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            });
            SandboxClient::new(Client::new(service, "default"), "dev-sandboxes")
                .probe_environment("env-test")
                .await
                .unwrap()
        };

        let finished = probed(None).await;
        assert_eq!(finished.pod_phase, "Succeeded");
        assert_eq!(finished.pod_deleting_at, None);

        let deleting = probed(Some("2026-11-03T19:26:48Z")).await;
        assert_eq!(deleting.pod_phase, "Succeeded");
        assert_eq!(
            deleting.pod_deleting_at,
            Some("2026-11-03T19:26:48Z".parse().unwrap())
        );
    }

    /// #2328: create recovery resumes only an observed suspended Sandbox. An
    /// unbound Claim also reads zero replicas and must not look suspended.
    #[tokio::test]
    async fn probe_reports_suspension_only_for_the_bound_sandbox() {
        let claim = |bound: bool| {
            let mut claim = json!({
                "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                "metadata": {"name": "sandbox-env-test", "namespace": "dev-sandboxes"},
                "status": {"conditions": [{"type": "Ready", "status": "False", "reason": "SandboxSuspended"}]}
            });
            if bound {
                claim["status"]["sandbox"] = json!({"name": "workspace-env-test"});
            }
            claim
        };
        let sandbox = |mode: &str| {
            let mut sandbox = mode_sandbox();
            sandbox["spec"]["operatingMode"] = json!(mode);
            sandbox
        };
        for (label, client, suspended, replicas) in [
            (
                "suspended",
                probe_client(claim(true), Some(sandbox("Suspended"))),
                true,
                0,
            ),
            (
                "running",
                probe_client(claim(true), Some(sandbox("Running"))),
                false,
                1,
            ),
            ("unbound", probe_client(claim(false), None), false, 0),
            (
                "bound but absent",
                probe_client(claim(true), None),
                false,
                0,
            ),
        ] {
            let probe =
                tokio::time::timeout(Duration::from_secs(2), client.probe_environment("env-test"))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(probe.claim_exists && !probe.claim_ready, "{label}");
            assert_eq!(probe.sandbox_suspended, suspended, "{label}");
            assert_eq!(probe.replicas, replicas, "{label}");
            assert!(!probe.pod_exists, "{label}");
        }
    }

    #[tokio::test]
    async fn operating_mode_preserves_interleaved_controller_updates_for_start_and_stop() {
        for (replicas, expected) in [(1, "Running"), (0, "Suspended")] {
            let (client, state) = mode_client(mode_sandbox(), ModeInterleave::ControllerUpdate);
            tokio::time::timeout(
                Duration::from_secs(2),
                client.set_replicas("env-test", replicas, SUPPORT_IMAGE),
            )
            .await
            .unwrap()
            .expect("controller metadata changes must not fail an operating-mode update");
            let state = state.lock().unwrap();
            assert_eq!(state.writes.len(), 1);
            assert_eq!(state.object["spec"]["operatingMode"], expected);
            assert_eq!(
                state.object["spec"]["podTemplate"],
                json!({"fixture": "preserve"})
            );
            assert_eq!(state.object["metadata"]["resourceVersion"], "11");
            assert_eq!(state.object["metadata"]["uid"], "sandbox-incarnation");
            assert!(
                state.object["metadata"]["annotations"]
                    .get("agents.x-k8s.io/pod-name")
                    .is_none()
            );
            assert_eq!(
                state.object["status"]["fixture"],
                "controller-update-survives"
            );
        }
    }

    #[tokio::test]
    async fn operating_mode_rejects_replacement_deletion_and_api_errors_without_retry() {
        for interleave in [
            ModeInterleave::ReplaceUid,
            ModeInterleave::Delete,
            ModeInterleave::Reject(StatusCode::FORBIDDEN),
            ModeInterleave::Reject(StatusCode::CONFLICT),
            ModeInterleave::Reject(StatusCode::UNPROCESSABLE_ENTITY),
            ModeInterleave::Reject(StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let (client, state) = mode_client(mode_sandbox(), interleave);
            assert!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    client.set_replicas("env-test", 1, SUPPORT_IMAGE)
                )
                .await
                .unwrap()
                .is_err()
            );
            let state = state.lock().unwrap();
            assert_eq!(
                state.writes.len(),
                1,
                "no blind retry after uncertain or rejected mutation"
            );
            assert_eq!(state.object["spec"]["operatingMode"], "Suspended");
        }
    }

    #[tokio::test]
    async fn operating_mode_rejects_incomplete_or_deleting_observations_without_mutation() {
        for invalid in 0..7 {
            let mut sandbox = mode_sandbox();
            match invalid {
                0 => {
                    sandbox.as_object_mut().unwrap().remove("spec");
                }
                1 => sandbox["spec"] = Value::Null,
                2 => {
                    sandbox["metadata"].as_object_mut().unwrap().remove("uid");
                }
                3 => sandbox["metadata"]["uid"] = json!(""),
                4 => sandbox["metadata"]["deletionTimestamp"] = json!("2026-09-07T00:00:00Z"),
                5 => sandbox["metadata"]["name"] = json!("wrong-name"),
                6 => sandbox["metadata"]["namespace"] = json!("wrong-namespace"),
                _ => unreachable!(),
            }
            let (client, state) = mode_client(sandbox, ModeInterleave::ControllerUpdate);
            assert!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    client.set_replicas("env-test", 1, SUPPORT_IMAGE)
                )
                .await
                .unwrap()
                .is_err(),
                "case {invalid}"
            );
            assert!(
                state.lock().unwrap().writes.is_empty(),
                "case {invalid} mutated an invalid target"
            );
        }
    }

    #[tokio::test]
    async fn operating_mode_rejects_invalid_success_replies_without_replaying_the_write() {
        for invalid in 0..5 {
            let (client, state) =
                mode_client(mode_sandbox(), ModeInterleave::InvalidReply(invalid));
            assert!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    client.set_replicas("env-test", 1, SUPPORT_IMAGE)
                )
                .await
                .unwrap()
                .is_err(),
                "case {invalid} must not report a current live target"
            );
            let state = state.lock().unwrap();
            assert_eq!(state.writes.len(), 1);
            // A rejected response is not proof of rollback: the mutation may
            // already have happened, and must not be blindly replayed.
            assert_eq!(state.object["spec"]["operatingMode"], "Running");
        }
    }

    #[tokio::test]
    async fn operating_mode_adds_a_missing_mode_without_creating_or_replacing_the_spec() {
        let mut sandbox = mode_sandbox();
        sandbox["spec"]
            .as_object_mut()
            .unwrap()
            .remove("operatingMode");
        let (client, state) = mode_client(sandbox, ModeInterleave::ControllerUpdate);
        tokio::time::timeout(
            Duration::from_secs(2),
            client.set_replicas("env-test", 1, SUPPORT_IMAGE),
        )
        .await
        .unwrap()
        .unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.writes.len(), 1);
        assert_eq!(state.object["spec"]["operatingMode"], "Running");
        assert_eq!(
            state.object["spec"]["podTemplate"],
            json!({"fixture": "preserve"})
        );
    }

    #[test]
    fn recovery_selector_excludes_gateway_and_companion_pods() {
        assert_eq!(
            workspace_pod_selector("env-test"),
            "codewire.sh/environment-id=env-test,codewire.sh/type=workspace"
        );
    }

    #[test]
    fn product_retry_replaces_only_terminal_workspace_pods() {
        let cases = [
            ("Running", None, false),
            ("Pending", Some("ContainerCreating"), false),
            ("Pending", Some("CreateContainerError"), true),
            ("Pending", Some("RunContainerError"), true),
            ("Failed", None, true),
            ("Succeeded", None, true),
        ];

        for (phase, waiting_reason, expected) in cases {
            let mut status = json!({"phase": phase});
            if let Some(reason) = waiting_reason {
                status["containerStatuses"] = json!([{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "",
                    "ready": false,
                    "restartCount": 0,
                    "state": {"waiting": {"reason": reason}}
                }]);
            }
            let pod: Pod = serde_json::from_value(json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "workspace", "uid": "uid-1"},
                "spec": {"containers": [{"name": "workspace", "image": "workspace:test"}]},
                "status": status
            }))
            .unwrap();

            assert_eq!(
                pod_requires_product_replacement(&pod),
                expected,
                "phase={phase} waiting_reason={waiting_reason:?}"
            );
        }
    }

    #[test]
    fn terminal_wait_observes_init_containers_and_terminal_phase() {
        let init_failure: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {
                "initContainers": [{"name": "init", "image": "init:test"}],
                "containers": [{"name": "workspace", "image": "workspace:test"}]
            },
            "status": {
                "phase": "Pending",
                "initContainerStatuses": [{
                    "name": "init",
                    "image": "init:test",
                    "imageID": "",
                    "ready": false,
                    "restartCount": 0,
                    "state": {"waiting": {
                        "reason": "RunContainerError",
                        "message": "runtime rejected init container"
                    }}
                }]
            }
        }))
        .unwrap();
        assert_eq!(
            terminal_pod_failure_reason(&init_failure),
            Some((
                "RunContainerError".into(),
                "runtime rejected init container".into()
            ))
        );
        assert!(pod_requires_product_replacement(&init_failure));

        let progressing_init: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-2"},
            "spec": {
                "initContainers": [{"name": "init", "image": "init:test"}],
                "containers": [{"name": "workspace", "image": "workspace:test"}]
            },
            "status": {
                "phase": "Pending",
                "initContainerStatuses": [{
                    "name": "init",
                    "image": "init:test",
                    "imageID": "",
                    "ready": false,
                    "restartCount": 0,
                    "state": {"waiting": {"reason": "PodInitializing"}}
                }]
            }
        }))
        .unwrap();
        assert_eq!(terminal_pod_failure_reason(&progressing_init), None);
        assert!(!pod_requires_product_replacement(&progressing_init));

        let failed_phase: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-3"},
            "spec": {"containers": [{"name": "workspace", "image": "workspace:test"}]},
            "status": {"phase": "Failed", "reason": "StartError", "message": "start failed"}
        }))
        .unwrap();
        assert_eq!(
            terminal_pod_failure_reason(&failed_phase),
            Some(("StartError".into(), "start failed".into()))
        );
        assert!(pod_requires_product_replacement(&failed_phase));

        // A Pod failed by its init container has no message of its own; the
        // terminated containers name the cause.
        let failed_init: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-4"},
            "spec": {
                "initContainers": [{"name": "codewire-daemon-init", "image": "init:test"}],
                "containers": [{"name": "workspace", "image": "workspace:test"}]
            },
            "status": {
                "phase": "Failed",
                "initContainerStatuses": [{
                    "name": "codewire-daemon-init",
                    "image": "init:test",
                    "imageID": "",
                    "ready": false,
                    "restartCount": 0,
                    "state": {"terminated": {"exitCode": 137, "reason": "OOMKilled"}}
                }],
                "containerStatuses": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "",
                    "ready": false,
                    "restartCount": 0,
                    "state": {"waiting": {"reason": "PodInitializing"}}
                }]
            }
        }))
        .unwrap();
        assert_eq!(
            terminal_pod_failure_reason(&failed_init),
            Some((
                "PodFailed".into(),
                "codewire-daemon-init exited 137 (OOMKilled)".into()
            ))
        );
    }

    fn timeline_pod(workspace_restarts: i32, dind_state: Value) -> Pod {
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "workspace",
                "uid": "uid-1",
                "creationTimestamp": "2026-09-29T10:00:00Z"
            },
            "spec": {"containers": [
                {"name": "workspace", "image": "workspace:test"},
                {"name": "dind", "image": "dind:test"}
            ]},
            "status": {
                "phase": "Running",
                "startTime": "2026-09-29T10:00:03Z",
                "conditions": [
                    {"type": "PodReadyToStartContainers", "status": "True",
                     "lastTransitionTime": "2026-09-29T10:00:14Z"},
                    {"type": "Initialized", "status": "True",
                     "lastTransitionTime": "2026-09-29T10:00:36Z"},
                    {"type": "Ready", "status": "True",
                     "lastTransitionTime": "2026-09-29T10:00:40Z"},
                    {"type": "ContainersReady", "status": "True",
                     "lastTransitionTime": "2026-09-29T10:00:40Z"},
                    {"type": "PodScheduled", "status": "True",
                     "lastTransitionTime": "2026-09-29T10:00:03Z"}
                ],
                "containerStatuses": [
                    {"name": "workspace", "image": "workspace:test", "imageID": "",
                     "ready": true, "restartCount": workspace_restarts,
                     "state": {"running": {"startedAt": "2026-09-29T10:00:37Z"}}},
                    {"name": "dind", "image": "dind:test", "imageID": "",
                     "ready": true, "restartCount": 0, "state": dind_state}
                ]
            }
        }))
        .unwrap()
    }

    #[test]
    fn pod_start_timeline_reads_conditions_and_first_container_starts() {
        let at = |value: &str| Some(value.parse::<Timestamp>().unwrap());
        let started = json!({"running": {"startedAt": "2026-09-29T10:00:38Z"}});
        assert_eq!(
            PodStartTimeline::from_pod(&timeline_pod(0, started.clone())),
            PodStartTimeline {
                created_at: at("2026-09-29T10:00:00Z"),
                scheduled_at: at("2026-09-29T10:00:03Z"),
                ready_to_start_containers_at: at("2026-09-29T10:00:14Z"),
                initialized_at: at("2026-09-29T10:00:36Z"),
                workspace_started_at: at("2026-09-29T10:00:37Z"),
                dind_started_at: at("2026-09-29T10:00:38Z"),
                // The last container to start marks the Pod fully running.
                running_at: at("2026-09-29T10:00:38Z"),
                containers_ready_at: at("2026-09-29T10:00:40Z"),
                // The Claim and the volume are read from their own objects.
                claim_created_at: None,
                volume_created_at: None,
            }
        );

        // A restart or a container not yet running leaves the mark unknown
        // rather than reporting a restart time as the Pod start.
        let restarted = PodStartTimeline::from_pod(&timeline_pod(1, started));
        assert_eq!(restarted.running_at, None);
        assert_eq!(restarted.workspace_started_at, None);
        assert_eq!(restarted.dind_started_at, at("2026-09-29T10:00:38Z"));
        assert_eq!(restarted.initialized_at, at("2026-09-29T10:00:36Z"));
        let waiting = PodStartTimeline::from_pod(&timeline_pod(
            0,
            json!({"waiting": {"reason": "ContainerCreating"}}),
        ));
        assert_eq!(waiting.running_at, None);
        assert_eq!(waiting.dind_started_at, None);
        assert_eq!(waiting.workspace_started_at, at("2026-09-29T10:00:37Z"));

        let mut unscheduled = timeline_pod(0, json!({}));
        let status = unscheduled.status.as_mut().unwrap();
        status
            .conditions
            .as_mut()
            .unwrap()
            .retain(|condition| condition.type_ != "PodScheduled");
        status.conditions.as_mut().unwrap().push(
            serde_json::from_value(json!({"type": "PodScheduled", "status": "False",
                "lastTransitionTime": "2026-09-29T10:00:01Z"}))
            .unwrap(),
        );
        assert_eq!(PodStartTimeline::from_pod(&unscheduled).scheduled_at, None);
    }

    #[test]
    fn the_workspace_pvc_is_the_one_the_pod_mounts_as_its_workspace_volume() {
        let mut pod = timeline_pod(0, json!({}));
        assert_eq!(workspace_pvc_claim_name(&pod), None);
        pod.spec.as_mut().unwrap().volumes = Some(
            serde_json::from_value(json!([
                {"name": "codewire-run", "emptyDir": {}},
                {"name": "workspace", "persistentVolumeClaim": {"claimName": "workspace-sb-1"}}
            ]))
            .unwrap(),
        );
        assert_eq!(
            workspace_pvc_claim_name(&pod).as_deref(),
            Some("workspace-sb-1")
        );
        // An ephemeral workspace has no claim to time.
        pod.spec.as_mut().unwrap().volumes =
            Some(serde_json::from_value(json!([{"name": "workspace", "emptyDir": {}}])).unwrap());
        assert_eq!(workspace_pvc_claim_name(&pod), None);
    }

    fn workspace_pvc(volume_name: Option<&str>) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "workspace-sb-1", "namespace": "dev-sandboxes", "uid": STORAGE_PVC_UID},
            "spec": {"volumeName": volume_name},
        })
    }

    fn persistent_volume_list(claim_uid: &str) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeList",
            "metadata": {"resourceVersion": "1"},
            "items": [{
                "metadata": {"name": "pvc-1", "creationTimestamp": "2026-09-29T10:00:02Z"},
                "spec": {"claimRef": {
                    "namespace": "dev-sandboxes", "name": "workspace-sb-1", "uid": claim_uid,
                }},
            }],
        })
    }

    #[tokio::test]
    async fn workspace_volume_creation_comes_from_the_volume_bound_to_this_pvc() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (StatusCode::OK, workspace_pvc(Some("pvc-1"))),
            (StatusCode::OK, persistent_volume_list(STORAGE_PVC_UID)),
        ]);
        assert_eq!(
            client
                .workspace_volume_created_at("workspace-sb-1")
                .await
                .unwrap(),
            Some("2026-09-29T10:00:02Z".parse::<Timestamp>().unwrap())
        );
        assert_eq!(
            *requests.lock().unwrap(),
            [
                (
                    Method::GET,
                    "/api/v1/namespaces/dev-sandboxes/persistentvolumeclaims/workspace-sb-1".into()
                ),
                (Method::GET, "/api/v1/persistentvolumes".into()),
            ]
        );

        // A volume that claims another PVC incarnation is not this one's.
        let (client, _) = sandbox_client_with_secret_responses(vec![
            (StatusCode::OK, workspace_pvc(Some("pvc-1"))),
            (StatusCode::OK, persistent_volume_list("another-uid")),
        ]);
        assert_eq!(
            client
                .workspace_volume_created_at("workspace-sb-1")
                .await
                .unwrap(),
            None
        );

        // An unbound PVC is read once; there is no volume to list.
        let (client, requests) =
            sandbox_client_with_secret_responses(vec![(StatusCode::OK, workspace_pvc(None))]);
        assert_eq!(
            client
                .workspace_volume_created_at("workspace-sb-1")
                .await
                .unwrap(),
            None
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn live_resize_observation_locks_uid_restart_count_and_terminal_failure() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {
                "runtimeClassName": "commodity",
                "containers": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "resizePolicy": [
                        {"resourceName": "cpu", "restartPolicy": "NotRequired"},
                        {"resourceName": "memory", "restartPolicy": "NotRequired"}
                    ]
                }]
            },
            "status": {
                "containerStatuses": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "workspace:test",
                    "ready": true,
                    "restartCount": 3,
                    "started": true,
                    "state": {"running": {"startedAt": "2026-08-02T00:00:00Z"}},
                    "resources": {
                        "requests": {"cpu": "500m", "memory": "512Mi"},
                        "limits": {"cpu": "500m", "memory": "512Mi"}
                    }
                }],
                "conditions": [{
                    "type": "PodResizePending",
                    "status": "True",
                    "reason": "Infeasible",
                    "message": "node has insufficient memory",
                    "lastTransitionTime": "2026-08-02T00:00:00Z"
                }]
            }
        }))
        .unwrap();
        let observed = workspace_pod_resize_state(&pod, "fallback").unwrap();
        assert_eq!(observed.identity.uid, "uid-1");
        assert_eq!(observed.restart_count, 3);
        assert!(observed.live_resize_compatible);
        assert!(workspace_resources_match(
            &pod,
            &WorkspaceCompute::new(500, 512, CpuSharingRatio::NONE)
        ));
        // No observedGeneration: the condition cannot be attributed to a
        // request, whatever generation that request was accepted at.
        for generation in [None, Some(1), Some(7)] {
            assert_eq!(
                infeasible_pod_resize(&pod, generation),
                Some(("node has insufficient memory".to_string(), false))
            );
        }
    }

    #[test]
    fn live_resize_observation_accepts_semantically_equal_quantities() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {"containers": [{"name": "workspace"}]},
            "status": {
                "containerStatuses": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "workspace:test",
                    "ready": true,
                    "restartCount": 0,
                    "resources": {
                        "requests": {"cpu": "3", "memory": "5Gi"},
                        "limits": {"cpu": "3e0", "memory": "5242880Ki"}
                    },
                    "state": {"running": {"startedAt": "2026-08-04T00:00:00Z"}}
                }]
            }
        }))
        .unwrap();

        let matches = |cpu, memory| {
            workspace_resources_match(
                &pod,
                &WorkspaceCompute::new(cpu, memory, CpuSharingRatio::NONE),
            )
        };
        assert!(matches(3000, 5120));
        assert!(!matches(2999, 5120));
        assert!(!matches(3000, 5119));
        assert!(quantities_equal("1500000u", "1500m"));
        assert!(quantities_equal("1.5Gi", "1536Mi"));
        assert!(!quantities_equal("invalid", "3000m"));
        assert!(!quantities_equal("0", "0"));
    }

    #[test]
    fn live_resize_observation_fails_closed_without_reported_resources() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {"containers": [{"name": "workspace"}]},
            "status": {
                "containerStatuses": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "imageID": "workspace:test",
                    "ready": true,
                    "restartCount": 0,
                    "state": {"running": {"startedAt": "2026-08-04T00:00:00Z"}}
                }]
            }
        }))
        .unwrap();

        assert!(!workspace_resources_match(
            &pod,
            &WorkspaceCompute::new(3000, 5120, CpuSharingRatio::NONE)
        ));
    }

    #[test]
    fn live_resize_rejects_container_restart_policy() {
        let pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "workspace", "uid": "uid-1"},
            "spec": {
                "containers": [{
                    "name": "workspace",
                    "image": "workspace:test",
                    "resizePolicy": [{"resourceName": "memory", "restartPolicy": "RestartContainer"}]
                }]
            }
        }))
        .unwrap();
        let observed = workspace_pod_resize_state(&pod, "fallback").unwrap();
        assert!(!observed.live_resize_compatible);
        assert_eq!(
            observed.incompatibility_reason.as_deref(),
            Some("memory uses restartPolicy RestartContainer")
        );
    }

    #[test]
    fn a_grown_disk_sizes_only_a_loop_mounted_docker_data_image_and_never_down() {
        let dind = |mode: &str, size: &str| {
            json!({"spec": {"podTemplate": {"spec": {"containers": [
                {"name": "workspace", "env": [{"name": "HOME", "value": "/workspace"}]},
                {"name": "dind", "env": [
                    {"name": "DOCKER_TLS_CERTDIR", "value": ""},
                    {"name": "CODEWIRE_DOCKER_DATA_SIZE", "value": size},
                    {"name": "CODEWIRE_DOCKER_MOUNT_MODE", "value": mode}
                ]}
            ]}}}})
        };
        let size = |runtime: &Value| {
            runtime
                .pointer("/spec/podTemplate/spec/containers/1/env/1/value")
                .cloned()
        };

        let mut grown = dind("loop", "78G");
        set_docker_data_size(&mut grown, 120).unwrap();
        assert_eq!(size(&grown), Some(json!("118G")));
        let mut expected = dind("loop", "118G");
        assert_eq!(grown, expected);
        // Never smaller than the image already is.
        set_docker_data_size(&mut expected, 80).unwrap();
        assert_eq!(size(&expected), Some(json!("118G")));
        // The confidential profile's root is not a loop-mounted image.
        let mut confidential = dind("none", "48G");
        set_docker_data_size(&mut confidential, 120).unwrap();
        assert_eq!(confidential, dind("none", "48G"));
        // No DinD container: nothing to size.
        let mut no_docker = json!({"spec": {"podTemplate": {"spec": {"containers": [
            {"name": "workspace"}
        ]}}}});
        let before = no_docker.clone();
        set_docker_data_size(&mut no_docker, 120).unwrap();
        assert_eq!(no_docker, before);

        // The Docker data init carries DinD's size, and grows with it, never
        // down; a Sandbox not yet re-rendered has only DinD's.
        let with_init = |dind_size: &str, init_size: &str| {
            let mut runtime = dind("loop", dind_size);
            runtime["spec"]["podTemplate"]["spec"]["initContainers"] = json!([
                {"name": "codewire-daemon-init", "env": []},
                {"name": DOCKER_DATA_INIT_CONTAINER, "env": [
                    {"name": "CODEWIRE_DOCKER_DATA_IMAGE", "value": "/workspace/.codewire/docker-data.ext4"},
                    {"name": "CODEWIRE_DOCKER_DATA_SIZE", "value": init_size},
                    {"name": "CODEWIRE_DOCKER_MOUNT_MODE", "value": "loop"}
                ]}
            ]);
            runtime
        };
        let mut grown = with_init("78G", "78G");
        set_docker_data_size(&mut grown, 120).unwrap();
        assert_eq!(grown, with_init("118G", "118G"));
        let mut kept = with_init("118G", "118G");
        set_docker_data_size(&mut kept, 80).unwrap();
        assert_eq!(kept, with_init("118G", "118G"));
        // Each is raised to the rendering on its own, never down.
        let mut behind = with_init("118G", "78G");
        set_docker_data_size(&mut behind, 100).unwrap();
        assert_eq!(behind, with_init("118G", "98G"));
    }

    #[test]
    fn a_resize_of_a_shared_runtime_object_keeps_its_ratio() {
        let workspace = |request: &str, limit: &str| {
            json!({"spec": {"podTemplate": {"spec": {"containers": [
                {"name": "dind", "resources": {"requests": {"cpu": "500m"}, "limits": {"cpu": "2"}}},
                {"name": "workspace", "resources": {
                    "requests": {"cpu": request, "memory": "8Gi"},
                    "limits": {"cpu": limit, "memory": "8Gi"}
                }}
            ]}}}})
        };
        // The controller may store a quantity canonicalized.
        let sharing = |request, limit| runtime_object_cpu_sharing(&workspace(request, limit));
        assert_eq!(sharing("2000m", "2000m"), CpuSharingRatio::NONE);
        assert_eq!(sharing("2", "2000m"), CpuSharingRatio::NONE);
        assert_eq!(
            sharing("1", "2"),
            CpuSharingRatio::observed(1000, 2000),
            "1 CPU reserved for 2 vCPUs"
        );
        assert_eq!(
            runtime_object_cpu_sharing(&json!({"spec": {}})),
            CpuSharingRatio::NONE
        );

        let mut runtime = workspace("1", "2");
        let compute = WorkspaceCompute::new(4000, 16384, runtime_object_cpu_sharing(&runtime));
        set_workspace_resources(&mut runtime, &compute).unwrap();
        let resources = runtime
            .pointer("/spec/podTemplate/spec/containers/1/resources")
            .unwrap();
        assert_eq!(resources["requests"]["cpu"], "2000m");
        assert_eq!(resources["limits"]["cpu"], "4000m");
        assert_eq!(resources["requests"]["memory"], "16384Mi");
        assert_eq!(resources["limits"]["memory"], "16384Mi");
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/containers/0/resources/limits/cpu"),
            Some(&json!("2")),
            "DinD keeps its own"
        );
    }

    #[test]
    fn only_a_resource_refusal_counts_as_no_capacity() {
        let pending = |status: &str, reason: &str, message: &str| -> Pod {
            serde_json::from_value(json!({
                "metadata": {"name": "workspace"},
                "status": {"conditions": [{
                    "type": "PodScheduled", "status": status, "reason": reason, "message": message
                }]}
            }))
            .unwrap()
        };
        let full = "0/4 nodes are available: 1 Insufficient cpu, 1 node(s) had untolerated taint(s), 2 node(s) didn't match Pod's node affinity/selector.";
        assert_eq!(
            capacity_refusal(&pending("False", "Unschedulable", full)).as_deref(),
            Some(full)
        );
        for message in [
            "0/1 nodes are available: 1 Insufficient memory.",
            "0/1 nodes are available: 1 Too many pods.",
        ] {
            assert_eq!(
                capacity_refusal(&pending("False", "Unschedulable", message)).as_deref(),
                Some(message)
            );
        }
        // A volume on another node or a taint alone is not "full".
        for message in [
            "0/4 nodes are available: 1 node(s) had volume node affinity conflict, 3 node(s) didn't match Pod's node affinity/selector.",
            "0/1 nodes are available: 1 node(s) had untolerated taint(s).",
        ] {
            assert_eq!(
                capacity_refusal(&pending("False", "Unschedulable", message)),
                None
            );
        }
        // Scheduled, or not refused by the scheduler, is not "full" either.
        assert_eq!(capacity_refusal(&pending("True", "", full)), None);
        assert_eq!(
            capacity_refusal(&pending("False", "SchedulingGated", full)),
            None
        );
        let no_status: Pod = serde_json::from_value(json!({"metadata": {"name": "p"}})).unwrap();
        assert_eq!(capacity_refusal(&no_status), None);
    }

    #[test]
    fn resize_mutates_only_workspace_resources_and_preserves_runtime_identity() {
        let mut runtime = json!({
            "metadata": {"labels": {"codewire.sh/isolation-tier": "future-tier"}},
            "spec": {
                "podTemplate": {"spec": {
                    "runtimeClassName": "kata-future",
                    "initContainers": [{"name": "daemon-inject", "image": "daemon:init"}],
                    "containers": [
                        {"name": "workspace", "image": "custom.example/workspace@sha256:abc", "ports": [{"containerPort": 8080}], "resources": {
                            "requests": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "5Gi"},
                            "limits": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "5Gi"}
                        }},
                        {"name": "codewire-gateway", "image": "gateway:stable", "resources": {"requests": {"cpu": "250m"}}}
                    ]
                }},
                "volumeClaimTemplates": [{"metadata": {"name": "workspace"}, "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": "expandable",
                    "resources": {"requests": {"storage": "10Gi"}}
                }}]
            }
        });
        set_workspace_resources(
            &mut runtime,
            &WorkspaceCompute::new(1500, 2048, CpuSharingRatio::NONE),
        )
        .unwrap();
        set_workspace_volume_request(&mut runtime, "20Gi").unwrap();
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/containers/0/image"),
            Some(&json!("custom.example/workspace@sha256:abc"))
        );
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/containers/0/resources/requests/cpu"),
            Some(&json!("1500m"))
        );
        assert_eq!(
            runtime.pointer(
                "/spec/podTemplate/spec/containers/0/resources/requests/ephemeral-storage"
            ),
            Some(&json!("5Gi"))
        );
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/containers/1/image"),
            Some(&json!("gateway:stable"))
        );
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/runtimeClassName"),
            Some(&json!("kata-future"))
        );
        assert_eq!(
            runtime.pointer("/spec/podTemplate/spec/initContainers/0/image"),
            Some(&json!("daemon:init"))
        );
        assert_eq!(
            runtime.pointer("/spec/volumeClaimTemplates/0/spec/resources/requests/storage"),
            Some(&json!("20Gi"))
        );
        assert_eq!(
            runtime.pointer("/spec/volumeClaimTemplates/0/spec/storageClassName"),
            Some(&json!("expandable"))
        );
    }

    #[tokio::test]
    async fn workspace_storage_growth_requires_storage_class_expansion_and_never_shrinks() {
        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses(true));
        let supported = client
            .require_workspace_storage_resize(&storage_anchor(Some(STORAGE_PVC_UID)), 20)
            .await
            .unwrap();
        assert_eq!(supported.requested_disk_gb, 10);
        assert_eq!(supported.applied_disk_gb, Some(10));
        assert!(!supported.filesystem_resize_pending);
        assert!(supported.expansion_allowed);

        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses(false));
        assert!(
            client
                .require_workspace_storage_resize(&storage_anchor(Some(STORAGE_PVC_UID)), 20)
                .await
                .unwrap_err()
                .to_string()
                .contains("does not allow volume expansion")
        );

        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses(true));
        assert!(
            client
                .require_workspace_storage_resize(&storage_anchor(None), 5)
                .await
                .unwrap_err()
                .to_string()
                .contains("cannot shrink")
        );
    }

    /// Resize resolves the PVC through the recorded Claim and PVC UIDs, never
    /// a computed name: a same-name substitute with another UID is refused
    /// before any write.
    #[tokio::test]
    async fn workspace_storage_refuses_a_same_name_pvc_with_another_uid() {
        let (client, requests) =
            sandbox_client_with_secret_responses(storage_lookup_responses(true));
        let error = client
            .require_workspace_storage_resize(
                &storage_anchor(Some("a1560db3-8899-40c9-b521-500f223b04fb")),
                20,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("recorded UID"), "{error:#}");
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|(method, _)| *method == Method::GET)
        );
        // A replaced Claim under the same name never resolves either.
        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses(true));
        let mut replaced = storage_anchor(Some(STORAGE_PVC_UID));
        replaced.claim_uid = "a1560db3-8899-40c9-b521-500f223b04fb".into();
        assert!(
            client
                .require_workspace_storage_resize(&replaced, 20)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn confidential_workspace_storage_growth_is_rejected_before_mutation() {
        // The StorageClass allows expansion: the raw Block claim alone refuses
        // growth, whatever the class is called.
        let block =
            || storage_lookup_responses_for_claim("linstor-confidential", true, Some("Block"));
        let (client, _) = sandbox_client_with_secret_responses(block());
        let unchanged = client
            .require_workspace_storage_resize(&storage_anchor(Some(STORAGE_PVC_UID)), 10)
            .await
            .unwrap();
        assert!(unchanged.raw_block);
        assert_eq!(unchanged.storage_class_name, "linstor-confidential");

        let (client, requests) = sandbox_client_with_secret_responses(block());

        let error = client
            .require_workspace_storage_resize(&storage_anchor(Some(STORAGE_PVC_UID)), 20)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("confidential workspace storage expansion is not supported")
        );
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|(method, _)| *method == Method::GET),
            "confidential resize admission must not mutate Kubernetes objects"
        );
    }

    #[tokio::test]
    async fn filesystem_workspace_storage_is_not_raw_block() {
        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses(true));
        let storage = client
            .require_workspace_storage_resize(&storage_anchor(Some(STORAGE_PVC_UID)), 20)
            .await
            .unwrap();
        assert!(!storage.raw_block);
    }

    /// #3718: a commodity Block workspace is raw-block but not confidential:
    /// it grows like any other claim, and only its next Pod's
    /// `mount-workspace` grows the filesystem, so a running one restarts.
    #[tokio::test]
    async fn a_commodity_block_workspace_grows_and_finishes_in_its_next_pod() {
        let commodity_block = || {
            let mut responses =
                storage_lookup_responses_for_claim("linstor-local", true, Some("Block"));
            for (_, body) in &mut responses {
                if body["kind"] == "PersistentVolumeClaim" {
                    body["spec"]["accessModes"] = json!(["ReadWriteOnce"]);
                }
            }
            responses
        };
        let (client, _) = sandbox_client_with_secret_responses(commodity_block());
        let storage = client
            .require_workspace_storage_resize(&storage_anchor(Some(STORAGE_PVC_UID)), 20)
            .await
            .unwrap();
        assert!(storage.raw_block && !storage.confidential);
        let (client, _) = sandbox_client_with_secret_responses(commodity_block());
        assert_eq!(
            client
                .wait_for_workspace_storage_resize(
                    &storage_anchor(Some(STORAGE_PVC_UID)),
                    10,
                    Duration::from_secs(1),
                )
                .await
                .unwrap(),
            WorkspaceStorageResizeOutcome::RequiresPodRestart
        );
    }

    #[tokio::test]
    async fn workspace_daemon_repair_replaces_only_the_workspace_pod() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-old",
                    },
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-old",
                    },
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Success",
                    "code": 200,
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-new",
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [{
                            "image": "workspace:test",
                            "imageID": "workspace@test",
                            "name": "workspace",
                            "ready": true,
                            "restartCount": 0,
                            "started": true,
                            "state": {
                                "running": {
                                    "startedAt": "2026-07-25T00:00:00Z"
                                }
                            }
                        }]
                    }
                }),
            ),
        ]);

        let replacement = client
            .delete_and_wait_for_replacement_workspace_pod(
                "env-test",
                Some("workspace-old"),
                Duration::from_secs(1),
            )
            .await
            .unwrap();

        assert_eq!(
            replacement,
            WorkspacePodIdentity {
                name: "workspace-old".into(),
                uid: "uid-new".into(),
            }
        );
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[
                (
                    Method::GET,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
                (
                    Method::GET,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
                (
                    Method::DELETE,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
                (
                    Method::GET,
                    "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn retried_resize_never_deletes_the_replacement_workspace_pod() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::OK,
            json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "workspace-old",
                    "namespace": "dev-sandboxes",
                    "uid": "uid-new",
                },
            }),
        )]);

        client
            .delete_workspace_pod_if_uid("workspace-old", "uid-old")
            .await
            .unwrap();

        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[(
                Method::GET,
                "/api/v1/namespaces/dev-sandboxes/pods/workspace-old".to_string(),
            )]
        );
    }

    #[test]
    fn terminal_recovery_delete_is_bound_to_the_observed_pod_uid() {
        let delete = serde_json::to_value(delete_params_for_observed_uid("uid-old")).unwrap();
        assert_eq!(
            delete.pointer("/preconditions/uid"),
            Some(&json!("uid-old"))
        );
    }

    fn confidential_runtime_opts() -> TemplateOpts {
        TemplateOpts {
            name: "workspace-env-test".into(),
            environment_id: "env-test".into(),
            runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_CONFIDENTIAL.into(),
            workspace_binding_url:
                "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087".into(),
            measured_binding_roots:
                "-----BEGIN CERTIFICATE-----\nMIIBsynthetic\n-----END CERTIFICATE-----\n".into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url: "https://kbs.example.test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn measured_runtime_merge_patch_carries_the_whole_measured_template() {
        let opts = confidential_runtime_opts();
        let measured = MeasuredPodTemplate::render("dev-sandboxes", &opts).unwrap();
        let rendered = render_sandbox_template("dev-sandboxes", &opts);
        let patch = measured.merge_patch();
        // The whole Pod spec: containers, volumes and init containers are
        // arrays, which a merge patch replaces whole.
        assert_eq!(
            patch.pointer("/spec/podTemplate/spec"),
            rendered.pointer("/spec/podTemplate/spec")
        );
        let annotations = patch
            .pointer("/spec/podTemplate/metadata/annotations")
            .and_then(Value::as_object)
            .unwrap();
        // Only the measured keys, so unrelated annotations are kept.
        assert_eq!(annotations.len(), MEASURED_POD_ANNOTATIONS.len());
        assert_eq!(
            annotations[KATA_COCO_INIT_DATA_ANNOTATION_KEY],
            json!(measured.init_data())
        );
        assert!(
            annotations[KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY]
                .as_str()
                .unwrap()
                .contains("agent.log_vport=1025")
        );
        // Without storage there is no confidential volume to declare.
        assert_eq!(
            annotations[KATA_CONFIDENTIAL_VOLUME_ANNOTATION],
            Value::Null
        );
        // Commodity, or a confidential rendering without measured anchors,
        // has no measured runtime.
        for unmeasured in [
            TemplateOpts {
                runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_COMMODITY.into(),
                ..opts.clone()
            },
            TemplateOpts {
                measured_binding_roots: String::new(),
                ..opts.clone()
            },
        ] {
            assert!(MeasuredPodTemplate::render("dev-sandboxes", &unmeasured).is_err());
        }
    }

    #[tokio::test]
    async fn terminal_recovery_refreshes_the_adopted_sandbox_before_uid_delete() {
        let opts = confidential_runtime_opts();
        let measured = MeasuredPodTemplate::render("dev-sandboxes", &opts).unwrap();
        let measured_annotations =
            measured.merge_patch()["spec"]["podTemplate"]["metadata"]["annotations"]
                .as_object()
                .unwrap()
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<serde_json::Map<_, _>>();
        let expected_init_data = measured.init_data().to_owned();

        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-test", "namespace": "dev-sandboxes"},
                    "spec": {"warmPoolRef": {"name": "shadow-pool-workspace-env-test"}},
                    "status": {"sandbox": {"name": "workspace-old"}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxWarmPool",
                    "metadata": {"name": "shadow-pool-workspace-env-test", "namespace": "dev-sandboxes"},
                    "spec": {"sandboxTemplateRef": {"name": "workspace-env-test"}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "agents.x-k8s.io/v1beta1",
                    "kind": "Sandbox",
                    "metadata": {"name": "workspace-old", "namespace": "dev-sandboxes"},
                    "spec": {"podTemplate": {"metadata": {"annotations": {}}}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxTemplate",
                    "metadata": {
                        "name": "workspace-env-test",
                        "namespace": "dev-sandboxes",
                        "resourceVersion": "1"
                    },
                    "spec": {}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxTemplate",
                    "metadata": {"name": "workspace-env-test", "namespace": "dev-sandboxes"},
                    "spec": {}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "agents.x-k8s.io/v1beta1",
                    "kind": "Sandbox",
                    "metadata": {"name": "workspace-old", "namespace": "dev-sandboxes"},
                    "spec": {"podTemplate": {"metadata": {"annotations": measured_annotations}}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-old",
                        "annotations": {
                            KATA_COCO_INIT_DATA_ANNOTATION_KEY: expected_init_data,
                        }
                    }
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-old"
                    }
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Success",
                    "code": 200
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "workspace-old",
                        "namespace": "dev-sandboxes",
                        "uid": "uid-new"
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [{
                            "image": "workspace:test",
                            "imageID": "workspace@test",
                            "name": "workspace",
                            "ready": true,
                            "restartCount": 0,
                            "started": true,
                            "state": {"running": {"startedAt": "2026-07-25T00:00:00Z"}}
                        }]
                    }
                }),
            ),
        ]);

        let init_data = client
            .reconcile_per_environment_runtime("env-test", "workspace-old", &opts)
            .await
            .unwrap();
        assert_eq!(init_data, expected_init_data);
        client
            .wait_for_workspace_pod_annotation(
                "workspace-old",
                "uid-old",
                KATA_COCO_INIT_DATA_ANNOTATION_KEY,
                &init_data,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        client
            .delete_workspace_pod_if_uid("workspace-old", "uid-old")
            .await
            .unwrap();
        client
            .wait_for_replacement_workspace_pod("workspace-old", "uid-old", Duration::from_secs(1))
            .await
            .unwrap();

        let requests = requests.lock().unwrap();
        let patch_index = requests
            .iter()
            .position(|(method, path)| {
                *method == Method::PATCH && path.ends_with("/sandboxes/workspace-old")
            })
            .unwrap();
        let delete_index = requests
            .iter()
            .position(|(method, path)| {
                *method == Method::DELETE && path.ends_with("/pods/workspace-old")
            })
            .unwrap();
        assert!(patch_index < delete_index);
        assert_eq!(requests[patch_index + 1].0, Method::GET);
        assert!(requests[patch_index + 1].1.ends_with("/pods/workspace-old"));
    }

    #[tokio::test]
    async fn terminal_recovery_refuses_a_shared_template_without_mutation() {
        let opts = confidential_runtime_opts();
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-test", "namespace": "dev-sandboxes"},
                    "spec": {"warmPoolRef": {"name": "shared-pool"}},
                    "status": {"sandbox": {"name": "workspace-old"}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxWarmPool",
                    "metadata": {"name": "shared-pool", "namespace": "dev-sandboxes"},
                    "spec": {"sandboxTemplateRef": {"name": "workspace-shared"}}
                }),
            ),
        ]);

        let error = client
            .reconcile_per_environment_runtime("env-test", "workspace-old", &opts)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not owned by this environment"));
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|(method, _)| *method == Method::GET)
        );
    }

    #[tokio::test]
    async fn runtime_metadata_barrier_refuses_a_changed_pod_uid() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::OK,
            json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "workspace-old",
                    "namespace": "dev-sandboxes",
                    "uid": "uid-new",
                    "annotations": {
                        KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY: "agent.log_vport=1025"
                    }
                }
            }),
        )]);

        let error = client
            .wait_for_workspace_pod_annotation(
                "workspace-old",
                "uid-old",
                KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY,
                "agent.log_vport=1025",
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("workspace Pod changed"));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    fn kubernetes_status(reason: &str, code: u16) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "message": format!("mock Kubernetes API response: {reason}"),
            "reason": reason,
            "code": code,
        })
    }

    type RecordedRequests = Arc<Mutex<Vec<(Method, String)>>>;

    fn storage_lookup_responses_for_class(
        storage_class_name: &str,
        expansion_allowed: bool,
    ) -> Vec<(StatusCode, Value)> {
        storage_lookup_responses_for_claim(storage_class_name, expansion_allowed, None)
    }

    fn storage_lookup_responses_for_claim(
        storage_class_name: &str,
        expansion_allowed: bool,
        volume_mode: Option<&str>,
    ) -> Vec<(StatusCode, Value)> {
        let mut claim_spec = json!({
            "storageClassName": storage_class_name,
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "10Gi"}}
        });
        if let Some(volume_mode) = volume_mode {
            claim_spec["volumeMode"] = volume_mode.into();
            claim_spec["accessModes"] = json!(["ReadWriteOncePod"]);
        }
        vec![
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-test", "namespace": "dev-sandboxes",
                        "uid": STORAGE_CLAIM_UID},
                    "status": {"sandbox": {"name": "workspace-env-test"}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "agents.x-k8s.io/v1beta1",
                    "kind": "Sandbox",
                    "metadata": {"name": "workspace-env-test", "namespace": "dev-sandboxes",
                        "uid": STORAGE_SANDBOX_UID,
                        "ownerReferences": [{"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                            "kind": "SandboxClaim", "name": "sandbox-env-test",
                            "uid": STORAGE_CLAIM_UID, "controller": true}]},
                    "spec": {"volumeClaimTemplates": [{"metadata": {"name": "workspace"}}]}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "metadata": {"name": "workspace-workspace-env-test", "namespace": "dev-sandboxes",
                        "uid": STORAGE_PVC_UID,
                        "ownerReferences": [{"apiVersion": "agents.x-k8s.io/v1beta1",
                            "kind": "Sandbox", "name": "workspace-env-test",
                            "uid": STORAGE_SANDBOX_UID, "controller": true}]},
                    "spec": claim_spec,
                    "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}}
                }),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "storage.k8s.io/v1",
                    "kind": "StorageClass",
                    "metadata": {"name": storage_class_name},
                    "provisioner": "example.test/provisioner",
                    "allowVolumeExpansion": expansion_allowed
                }),
            ),
        ]
    }

    fn storage_lookup_responses(expansion_allowed: bool) -> Vec<(StatusCode, Value)> {
        storage_lookup_responses_for_class("expandable", expansion_allowed)
    }

    const STORAGE_CLAIM_UID: &str = "c0ffee00-1d2e-4f3a-8b4c-5d6e7f8a9b0c";
    const STORAGE_SANDBOX_UID: &str = "5a4db0c5-6d1e-4b0f-9b3c-2f0e7c1d9a11";
    const STORAGE_PVC_UID: &str = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";

    fn storage_anchor(recorded: Option<&str>) -> WorkspacePvcAnchor {
        WorkspacePvcAnchor {
            claim_name: "sandbox-env-test".into(),
            claim_uid: STORAGE_CLAIM_UID.into(),
            recorded_pvc_uid: recorded.map(str::to_owned),
        }
    }

    fn sandbox_client_with_secret_responses(
        responses: Vec<(StatusCode, Value)>,
    ) -> (SandboxClient, RecordedRequests) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let queued = responses.clone();
        let service = Router::new().fallback(move |request: Request<Body>| {
            let recorded = recorded.clone();
            let queued = queued.clone();
            async move {
                recorded
                    .lock()
                    .unwrap()
                    .push((request.method().clone(), request.uri().path().to_string()));
                let (status, body) = queued
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected Kubernetes API request");
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            }
        });
        let client = Client::new(service, "default");
        (SandboxClient::new(client, "dev-sandboxes"), requests)
    }

    fn object_meta(name: &str, env_label: Option<&str>) -> kube::api::ObjectMeta {
        kube::api::ObjectMeta {
            name: Some(name.to_string()),
            labels: env_label.map(|value| {
                [(LABEL_ENV_ID.to_string(), value.to_string())]
                    .into_iter()
                    .collect()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn cleanup_ownership_takes_identity_free_templates_by_their_derived_name() {
        let env = "4f6c0a52-91d4-4c56-9e1f-3a2b7c1d0e9f";
        let derived = format!("codewire-workspace-{env}");
        // Labelled objects keep the label rule.
        assert!(owned_by_environment(&object_meta(&derived, Some(env)), env));
        assert!(!owned_by_environment(
            &object_meta(&derived, Some("other-environment")),
            env,
        ));
        // An identity-free per-environment template has no label; its own
        // derived name proves ownership, whichever base named it.
        assert!(owned_by_environment(&object_meta(&derived, None), env));
        assert!(owned_by_environment(
            &object_meta(&format!("workspace-{env}"), None),
            env
        ));
        // Shared templates and other environments' templates are never taken.
        assert!(!owned_by_environment(
            &object_meta("cw-pool-1000m-4096mi-10gi-0a1b2c3d", None),
            env,
        ));
        let other = "codewire-workspace-6d1e2f3a-0b4c-4d5e-8f9a-1b2c3d4e5f60";
        assert!(!owned_by_environment(&object_meta(other, None), env));
        assert!(!owned_by_environment(&object_meta(env, None), env));
        assert!(!owned_by_environment(&object_meta(&derived, None), ""));
    }

    fn warm_pool_list(items: Vec<Value>) -> Value {
        json!({
            "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
            "kind": "SandboxWarmPoolList",
            "metadata": {"resourceVersion": "1"},
            "items": items,
        })
    }

    fn warm_pool(name: &str, template_name: &str) -> Value {
        json!({
            "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
            "kind": "SandboxWarmPool",
            "metadata": {"name": name, "namespace": "dev-sandboxes"},
            "spec": {
                "replicas": 2,
                "sandboxTemplateRef": {"name": template_name},
            },
        })
    }

    fn claim_list(items: Vec<Value>) -> Value {
        json!({
            "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
            "kind": "SandboxClaimList",
            "metadata": {"resourceVersion": "1"},
            "items": items,
        })
    }

    #[test]
    fn legacy_shared_warm_pool_selector_excludes_environment_shadows() {
        assert!(legacy_shared_warm_pool_name_matches(
            "sandbox-warmpool-workspace-5513aec3",
            "workspace"
        ));
        assert!(legacy_shared_warm_pool_name_matches(
            "sandbox-warmpool-workspace-2000m-4096mib-10gib-e1354543",
            "workspace-2000m-4096mib-10gib"
        ));
        assert!(!legacy_shared_warm_pool_name_matches(
            "shadow-pool-workspace-env-test",
            "workspace-env-test"
        ));
        assert!(!legacy_shared_warm_pool_name_matches(
            "sandbox-warmpool-workspace-env-test-deadbeef",
            "workspace-env-test"
        ));
        assert!(!legacy_shared_warm_pool_name_matches(
            "sandbox-warmpool-workspace-5513AEC3",
            "workspace"
        ));
        // Program #2238 C1 warm pools are never legacy candidates, and the
        // retirement pass skips them before its fail-closed name check.
        for pool_name in c1_warm_pool_names() {
            assert!(!pool_name.starts_with(LEGACY_SHARED_WARM_POOL_PREFIX));
            for template_name in [
                pool_name.as_str(),
                "workspace",
                "workspace-1000m-4096mib-10gib",
            ] {
                assert!(!legacy_shared_warm_pool_name_matches(
                    &pool_name,
                    template_name
                ));
            }
        }
    }

    fn c1_warm_pool_names() -> Vec<String> {
        [(1000, 4096, 10), (2000, 8192, 10)]
            .into_iter()
            .map(|(cpu_millicores, memory_mib, disk_gib)| {
                super::super::warm_pool::WarmPoolKey::new(
                    super::super::warm_pool::WorkspaceShape {
                        cpu_millicores,
                        memory_mib,
                        disk_gib,
                    },
                    "linstor-local",
                    "dev-sandboxes",
                    "dev",
                )
                .unwrap()
                .name("revision")
            })
            .collect()
    }

    #[tokio::test]
    async fn legacy_shared_warm_pool_retirement_preserves_c1_warm_pools() {
        let legacy_pool = "sandbox-warmpool-workspace-5513aec3";
        let pools = c1_warm_pool_names();
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                warm_pool_list(vec![
                    warm_pool(&pools[0], &pools[0]),
                    warm_pool(legacy_pool, "workspace"),
                    warm_pool(&pools[1], &pools[1]),
                ]),
            ),
            // A claimed C1 member does not hold back the legacy retirement.
            (
                StatusCode::OK,
                claim_list(vec![json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-live", "namespace": "dev-sandboxes"},
                    "spec": {"warmPoolRef": {"name": pools[0]}},
                })]),
            ),
            (StatusCode::OK, kubernetes_status("Success", 200)),
            // Only C1 pools remain: nothing to retire, no claim read.
            (
                StatusCode::OK,
                warm_pool_list(vec![
                    warm_pool(&pools[0], &pools[0]),
                    warm_pool(&pools[1], &pools[1]),
                ]),
            ),
        ]);

        assert_eq!(client.retire_legacy_shared_warm_pools().await.unwrap(), 1);
        assert_eq!(client.retire_legacy_shared_warm_pools().await.unwrap(), 0);
        let pools_path =
            "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxwarmpools";
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[
                (Method::GET, pools_path.into()),
                (
                    Method::GET,
                    "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxclaims".into(),
                ),
                (Method::DELETE, format!("{pools_path}/{legacy_pool}")),
                (Method::GET, pools_path.into()),
            ]
        );
    }

    #[tokio::test]
    async fn legacy_shared_warm_pool_retirement_preserves_shadows() {
        let default_pool = "sandbox-warmpool-workspace-5513aec3";
        let legacy_pool = "sandbox-warmpool-workspace-2000m-4096mib-10gib-e1354543";
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                warm_pool_list(vec![
                    warm_pool(default_pool, "workspace"),
                    warm_pool(legacy_pool, "workspace-2000m-4096mib-10gib"),
                    warm_pool("shadow-pool-workspace-env-test", "workspace-env-test"),
                ]),
            ),
            (StatusCode::OK, claim_list(Vec::new())),
            (StatusCode::OK, kubernetes_status("Success", 200)),
            (StatusCode::OK, kubernetes_status("Success", 200)),
        ]);

        assert_eq!(client.retire_legacy_shared_warm_pools().await.unwrap(), 2);
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[
                (
                    Method::GET,
                    "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxwarmpools".into(),
                ),
                (
                    Method::GET,
                    "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxclaims".into(),
                ),
                (
                    Method::DELETE,
                    format!(
                        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxwarmpools/{legacy_pool}"
                    ),
                ),
                (
                    Method::DELETE,
                    format!(
                        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxwarmpools/{default_pool}"
                    ),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn legacy_shared_warm_pool_retirement_denies_referenced_pool() {
        let pool_name = "sandbox-warmpool-workspace-5513aec3";
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                warm_pool_list(vec![warm_pool(pool_name, "workspace")]),
            ),
            (
                StatusCode::OK,
                claim_list(vec![json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxClaim",
                    "metadata": {"name": "sandbox-env-live", "namespace": "dev-sandboxes"},
                    "spec": {"warmPoolRef": {"name": pool_name}},
                })]),
            ),
        ]);

        let error = client.retire_legacy_shared_warm_pools().await.unwrap_err();
        assert!(error.to_string().contains(pool_name));
        assert_eq!(requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn legacy_shared_warm_pool_retirement_retries_partial_deletion() {
        let default_pool = "sandbox-warmpool-workspace-5513aec3";
        let legacy_pool = "sandbox-warmpool-workspace-2000m-4096mib-10gib-e1354543";
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                warm_pool_list(vec![
                    warm_pool(default_pool, "workspace"),
                    warm_pool(legacy_pool, "workspace-2000m-4096mib-10gib"),
                ]),
            ),
            (StatusCode::OK, claim_list(Vec::new())),
            (StatusCode::OK, kubernetes_status("Success", 200)),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                kubernetes_status("InternalError", 500),
            ),
            (
                StatusCode::OK,
                warm_pool_list(vec![warm_pool(default_pool, "workspace")]),
            ),
            (StatusCode::OK, claim_list(Vec::new())),
            (StatusCode::OK, kubernetes_status("Success", 200)),
        ]);

        assert!(client.retire_legacy_shared_warm_pools().await.is_err());
        assert_eq!(client.retire_legacy_shared_warm_pools().await.unwrap(), 1);
        let deletes = requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _)| *method == Method::DELETE)
            .count();
        assert_eq!(deletes, 3);
    }

    #[tokio::test]
    async fn post_bookkeeping_retry_reuses_the_existing_claim_without_teardown() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::CONFLICT,
                kubernetes_status("AlreadyExists", 409),
            ),
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxClaim",
                    "metadata": {
                        "name": "sandbox-env-test",
                        "namespace": "dev-sandboxes",
                        "uid": "claim-uid"
                    },
                    "spec": {
                        "warmPoolRef": {"name": "shadow-pool-workspace-env-test"}
                    }
                }),
            ),
        ]);
        let opts = ClaimOpts {
            environment_id: "env-test".into(),
            org_id: "org-test".into(),
            template_ref: "workspace-env-test".into(),
            warm_pool_ref: "shadow-pool-workspace-env-test".into(),
            ..Default::default()
        };

        let claim = client
            .create_sandbox_claim("dev-sandboxes", &opts)
            .await
            .unwrap();

        assert_eq!(claim, ("sandbox-env-test".into(), "claim-uid".into()));
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[
                (
                    Method::POST,
                    "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxclaims"
                        .into(),
                ),
                (
                    Method::GET,
                    "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxclaims/sandbox-env-test"
                        .into(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn retained_claim_shadow_converges_across_retry_and_destroy() {
        let pool_name = "shadow-pool-workspace-env-test";
        let pool = json!({
            "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
            "kind": "SandboxWarmPool",
            "metadata": {
                "name": pool_name,
                "namespace": "dev-sandboxes",
                "resourceVersion": "1"
            },
            "spec": {
                "replicas": 0,
                "sandboxTemplateRef": {"name": "workspace-env-test"}
            }
        });
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (StatusCode::NOT_FOUND, kubernetes_status("NotFound", 404)),
            (StatusCode::CREATED, pool.clone()),
            (StatusCode::OK, pool.clone()),
            (StatusCode::OK, pool),
            (StatusCode::OK, kubernetes_status("Success", 200)),
            (StatusCode::NOT_FOUND, kubernetes_status("NotFound", 404)),
        ]);

        client
            .ensure_shadow_pool(pool_name, "workspace-env-test", "env-test")
            .await
            .unwrap();
        client
            .ensure_shadow_pool(pool_name, "workspace-env-test", "env-test")
            .await
            .unwrap();
        client.delete_shadow_pool(pool_name).await.unwrap();
        client.delete_shadow_pool(pool_name).await.unwrap();

        let methods = requests
            .lock()
            .unwrap()
            .iter()
            .map(|(method, _)| method.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            vec![
                Method::GET,
                Method::POST,
                Method::GET,
                Method::PUT,
                Method::DELETE,
                Method::DELETE,
            ]
        );
    }

    #[tokio::test]
    async fn retained_environment_template_converges_across_retry_and_destroy() {
        let template_name = "workspace-env-test";
        let template = json!({
            "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
            "kind": "SandboxTemplate",
            "metadata": {
                "name": template_name,
                "namespace": "dev-sandboxes",
                "resourceVersion": "1"
            },
            "spec": {}
        });
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (StatusCode::NOT_FOUND, kubernetes_status("NotFound", 404)),
            (StatusCode::CREATED, template.clone()),
            (StatusCode::OK, template.clone()),
            (StatusCode::OK, template),
            (StatusCode::OK, kubernetes_status("Success", 200)),
            (StatusCode::NOT_FOUND, kubernetes_status("NotFound", 404)),
        ]);
        let opts = TemplateOpts {
            name: template_name.into(),
            image: "workspace:test".into(),
            environment_id: "env-test".into(),
            cpu_millicores: 1_000,
            memory_mib: 1_024,
            disk_gib: 10,
            ..Default::default()
        };

        client.ensure_sandbox_template(&opts).await.unwrap();
        client.ensure_sandbox_template(&opts).await.unwrap();
        client.delete_sandbox_template(template_name).await.unwrap();
        client.delete_sandbox_template(template_name).await.unwrap();

        let methods = requests
            .lock()
            .unwrap()
            .iter()
            .map(|(method, _)| method.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            vec![
                Method::GET,
                Method::POST,
                Method::GET,
                Method::PUT,
                Method::DELETE,
                Method::DELETE,
            ]
        );
    }

    #[test]
    fn direct_udp_service_helpers_read_cilium_lb_ipam_shape() {
        let service: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "cw-tailnet-udp-env-test",
                "annotations": {
                    "lbipam.cilium.io/ips": "203.0.113.36",
                },
            },
            "spec": {
                "ports": [
                    { "name": "tailnet-udp", "protocol": "UDP", "port": 33123, "targetPort": 31000 },
                ],
            },
        }))
        .unwrap();

        assert!(direct_udp_service_ip_matches(&service, "203.0.113.36"));
        assert_eq!(direct_udp_service_port(&service), Some(33123));
    }

    #[test]
    fn direct_udp_port_range_defaults_and_validates() {
        let opts = TemplateOpts::default();
        assert_eq!(
            direct_udp_port_range(&opts).unwrap(),
            (
                DEFAULT_DIRECT_UDP_LB_PORT_START,
                DEFAULT_DIRECT_UDP_LB_PORT_END
            )
        );

        let opts = TemplateOpts {
            direct_udp_lb_port_start: 33000,
            direct_udp_lb_port_end: 33010,
            ..Default::default()
        };
        assert_eq!(direct_udp_port_range(&opts).unwrap(), (33000, 33010));

        let opts = TemplateOpts {
            direct_udp_lb_port_start: 40000,
            direct_udp_lb_port_end: 33000,
            ..Default::default()
        };
        assert!(direct_udp_port_range(&opts).is_err());
    }

    #[test]
    fn service_replace_preserves_allocated_cluster_ips() {
        let mut rendered: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "cw-daemon-env-test" },
            "spec": {
                "type": "ClusterIP",
                "ports": [
                    { "name": "ssh", "protocol": "TCP", "port": 2222, "targetPort": 2222 },
                ],
            },
        }))
        .unwrap();
        let existing: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "cw-daemon-env-test" },
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "10.43.12.34",
                "clusterIPs": ["10.43.12.34"],
                "ports": [
                    { "name": "ssh", "protocol": "TCP", "port": 2222, "targetPort": 2222 },
                ],
            },
        }))
        .unwrap();

        preserve_service_allocated_fields(&mut rendered, &existing);

        assert_eq!(
            rendered
                .data
                .pointer("/spec/clusterIP")
                .and_then(Value::as_str),
            Some("10.43.12.34")
        );
        assert_eq!(
            rendered
                .data
                .pointer("/spec/clusterIPs/0")
                .and_then(Value::as_str),
            Some("10.43.12.34")
        );
    }

    /// Live Pod resize (#2473, #2474, #2475) against a fake API server that
    /// enforces Kubernetes' UID and resourceVersion preconditions on
    /// `pods/resize`, and a scripted kubelet.
    mod live_resize {
        use super::*;

        const ENV: &str = "env-test";
        const SANDBOX_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxes/workspace-env-test";
        const POD_PATH: &str = "/api/v1/namespaces/dev-sandboxes/pods/workspace-pod";
        const RESIZE_PATH: &str = "/api/v1/namespaces/dev-sandboxes/pods/workspace-pod/resize";
        const UID: &str = "uid-1";
        const PREVIOUS: (i32, i32) = (500, 1024);
        const REQUESTED: (i32, i32) = (1000, 2048);
        const WAIT: Duration = Duration::from_millis(800);

        /// How the kubelet answers a Pod spec it has not applied, once it syncs.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Kubelet {
            Applies,
            Defers,
            Infeasible,
            Stalls,
        }

        /// A change another writer makes right after the first Pod read.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Race {
            None,
            ReplacePod,
            StatusUpdate,
            RestartPolicy,
            KubeletApplies,
        }

        struct Fake {
            pod: Value,
            kubelet: Kubelet,
            race: Race,
            /// Pod reads after an accepted change that still see the old status.
            lag: usize,
            unsynced: Option<usize>,
            /// Pod reads after an accepted change that fail.
            failing_reads: usize,
            failing: usize,
            generations: bool,
            reads: usize,
            accepted: Vec<Value>,
            refused: Vec<u16>,
        }

        impl Fake {
            fn new(pod: Value, kubelet: Kubelet, race: Race) -> Self {
                Self {
                    pod,
                    kubelet,
                    race,
                    lag: 0,
                    unsynced: None,
                    failing_reads: 0,
                    failing: 0,
                    generations: true,
                    reads: 0,
                    accepted: Vec::new(),
                    refused: Vec::new(),
                }
            }

            fn bump(&mut self) {
                let version: u64 = self.pod["metadata"]["resourceVersion"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                self.pod["metadata"]["resourceVersion"] = json!((version + 1).to_string());
            }

            fn sync(&mut self) {
                if self.kubelet == Kubelet::Stalls {
                    return;
                }
                let spec = self.pod["spec"]["containers"][0]["resources"].clone();
                let generation = self.pod["metadata"]["generation"].clone();
                let status = &mut self.pod["status"];
                let reason = if status["containerStatuses"][0]["resources"] == spec {
                    None
                } else {
                    match self.kubelet {
                        Kubelet::Applies => {
                            status["containerStatuses"][0]["resources"] = spec;
                            None
                        }
                        Kubelet::Defers => Some("Deferred"),
                        Kubelet::Infeasible => Some("Infeasible"),
                        Kubelet::Stalls => unreachable!(),
                    }
                };
                status["conditions"] = match reason {
                    None => json!([]),
                    Some(reason) => json!([{
                        "type": "PodResizePending", "status": "True", "reason": reason,
                        "message": format!("{reason} on node"), "observedGeneration": generation
                    }]),
                };
                if self.generations {
                    status["observedGeneration"] = generation;
                }
                self.bump();
            }

            fn race(&mut self) {
                match self.race {
                    Race::None => return,
                    Race::ReplacePod => {
                        self.pod["metadata"]["uid"] = json!("uid-replacement");
                        self.pod["status"]["conditions"] = json!([]);
                    }
                    Race::StatusUpdate => self.pod["status"]["podIP"] = json!("10.0.0.9"),
                    Race::RestartPolicy => {
                        self.pod["spec"]["containers"][0]["resizePolicy"][1]["restartPolicy"] =
                            json!("RestartContainer");
                    }
                    Race::KubeletApplies => {
                        self.pod["status"]["containerStatuses"][0]["resources"] =
                            self.pod["spec"]["containers"][0]["resources"].clone();
                        self.pod["status"]["conditions"] = json!([]);
                        self.pod["status"]["observedGeneration"] =
                            self.pod["metadata"]["generation"].clone();
                    }
                }
                self.bump();
            }

            fn read(&mut self) -> (StatusCode, Value) {
                self.reads += 1;
                match self.unsynced {
                    Some(0) => {
                        self.unsynced = None;
                        self.sync();
                    }
                    Some(reads) => self.unsynced = Some(reads - 1),
                    None => {}
                }
                if self.failing > 0 {
                    self.failing -= 1;
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        kubernetes_status("InternalError", 500),
                    );
                }
                let observed = self.pod.clone();
                if self.reads == 1 {
                    self.race();
                }
                (StatusCode::OK, observed)
            }

            /// Kubernetes' order: optimistic concurrency, then UID immutability.
            /// A patch without either field is unconditional, as in Kubernetes.
            fn resize(&mut self, body: Value) -> (StatusCode, Value) {
                let differs = |field: &str| {
                    body.pointer(field)
                        .is_some_and(|value| Some(value) != self.pod.pointer(field))
                };
                if differs("/metadata/resourceVersion") {
                    self.refused.push(409);
                    return (StatusCode::CONFLICT, kubernetes_status("Conflict", 409));
                }
                if differs("/metadata/uid") {
                    self.refused.push(422);
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        kubernetes_status("Invalid", 422),
                    );
                }
                assert_eq!(body["spec"]["containers"][0]["name"], "workspace");
                let requested = body["spec"]["containers"][0]["resources"].clone();
                self.accepted.push(body);
                if self.pod["spec"]["containers"][0]["resources"] != requested {
                    self.pod["spec"]["containers"][0]["resources"] = requested;
                    if self.generations {
                        let generation = self.pod["metadata"]["generation"].as_i64().unwrap();
                        self.pod["metadata"]["generation"] = json!(generation + 1);
                    }
                    self.bump();
                    self.unsynced = Some(self.lag);
                    self.failing = self.failing_reads;
                }
                (StatusCode::OK, self.pod.clone())
            }
        }

        fn api(fake: Fake) -> (SandboxClient, Arc<Mutex<Fake>>) {
            let state = Arc::new(Mutex::new(fake));
            let shared = Arc::clone(&state);
            let service = Router::new().fallback(move |request: Request<Body>| {
                let shared = Arc::clone(&shared);
                async move {
                    let method = request.method().clone();
                    let path = request.uri().path().to_string();
                    let content_type = request
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .map(|value| value.to_str().unwrap().to_string());
                    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
                        .await
                        .unwrap();
                    let mut fake = shared.lock().unwrap();
                    let (status, body) = if method == Method::GET && path == MODE_CLAIM_PATH {
                        (
                            StatusCode::OK,
                            json!({
                                "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                                "kind": "SandboxClaim",
                                "metadata": {"name": "sandbox-env-test", "namespace": "dev-sandboxes"},
                                "status": {"sandbox": {"name": "workspace-env-test"}}
                            }),
                        )
                    } else if method == Method::GET && path == SANDBOX_PATH {
                        (
                            StatusCode::OK,
                            json!({
                                "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                                "metadata": {
                                    "name": "workspace-env-test", "namespace": "dev-sandboxes",
                                    "uid": "sandbox-incarnation",
                                    "annotations": {"agents.x-k8s.io/pod-name": "workspace-pod"}
                                }
                            }),
                        )
                    } else if method == Method::GET && path == POD_PATH {
                        fake.read()
                    } else if method == Method::PATCH && path == RESIZE_PATH {
                        assert_eq!(
                            content_type.as_deref(),
                            Some("application/strategic-merge-patch+json")
                        );
                        fake.resize(serde_json::from_slice(&bytes).unwrap())
                    } else {
                        panic!("unexpected Kubernetes request {method} {path}");
                    };
                    Response::builder()
                        .status(status)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap()
                }
            });
            (
                SandboxClient::new(Client::new(service, "default"), "dev-sandboxes"),
                state,
            )
        }

        fn quantities((cpu, memory): (i32, i32)) -> Value {
            let (cpu, memory) = (format!("{cpu}m"), format!("{memory}Mi"));
            json!({
                "requests": {"cpu": cpu, "memory": memory},
                "limits": {"cpu": cpu, "memory": memory}
            })
        }

        fn pod(uid: &str, spec: (i32, i32), actual: (i32, i32)) -> Value {
            json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {
                    "name": "workspace-pod", "namespace": "dev-sandboxes", "uid": uid,
                    "resourceVersion": "100", "generation": 1,
                    "ownerReferences": [{
                        "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                        "name": "workspace-env-test", "uid": "sandbox-incarnation",
                        "controller": true
                    }]
                },
                "spec": {"containers": [{
                    "name": "workspace", "image": "workspace:test",
                    "resizePolicy": [
                        {"resourceName": "cpu", "restartPolicy": "NotRequired"},
                        {"resourceName": "memory", "restartPolicy": "NotRequired"}
                    ],
                    "resources": quantities(spec)
                }]},
                "status": {
                    "observedGeneration": 1,
                    "containerStatuses": [{
                        "name": "workspace", "image": "workspace:test",
                        "imageID": "workspace:test", "ready": true, "restartCount": 2,
                        "started": true,
                        "state": {"running": {"startedAt": "2026-10-07T00:00:00Z"}},
                        "resources": quantities(actual)
                    }]
                }
            })
        }

        /// A Pod whose request at generation 2 the kubelet reported as `reason`.
        fn pending(uid: &str, spec: (i32, i32), actual: (i32, i32), reason: &str) -> Value {
            let mut pod = pod(uid, spec, actual);
            pod["metadata"]["generation"] = json!(2);
            pod["status"]["observedGeneration"] = json!(2);
            pod["status"]["conditions"] = json!([{
                "type": "PodResizePending", "status": "True", "reason": reason,
                "message": format!("{reason} on node"), "observedGeneration": 2
            }]);
            pod
        }

        fn spec_of(fake: &Fake) -> &Value {
            &fake.pod["spec"]["containers"][0]["resources"]
        }

        fn actual_of(fake: &Fake) -> &Value {
            &fake.pod["status"]["containerStatuses"][0]["resources"]
        }

        async fn resize(client: &SandboxClient) -> anyhow::Result<WorkspacePodResizeState> {
            client
                .resize_workspace_pod_in_place(ENV, UID, REQUESTED.0, REQUESTED.1, WAIT)
                .await
        }

        async fn settle(client: &SandboxClient) -> FailedLiveResize {
            client
                .settle_failed_live_resize(ENV, UID, PREVIOUS, REQUESTED, WAIT)
                .await
        }

        /// #2473: the replacement under the same name receives no mutation.
        #[tokio::test]
        async fn resize_never_mutates_a_pod_replaced_between_observation_and_patch() {
            let (client, fake) = api(Fake::new(
                pod(UID, PREVIOUS, PREVIOUS),
                Kubelet::Applies,
                Race::ReplacePod,
            ));
            let error = resize(&client).await.unwrap_err();
            assert!(
                format!("{error:#}").contains("replaced before live resize"),
                "{error:#}"
            );
            let fake = fake.lock().unwrap();
            assert!(fake.accepted.is_empty());
            assert_eq!(fake.refused, [409]);
            assert_eq!(fake.pod["metadata"]["uid"], "uid-replacement");
            assert_eq!(spec_of(&fake), &quantities(PREVIOUS));
        }

        /// #2473: a concurrent change is revalidated, never overwritten blind.
        #[tokio::test]
        async fn resize_revalidates_identity_and_policy_after_a_concurrent_change() {
            let (client, fake) = api(Fake::new(
                pod(UID, PREVIOUS, PREVIOUS),
                Kubelet::Applies,
                Race::StatusUpdate,
            ));
            let resized = resize(&client).await.unwrap();
            assert_eq!(resized.identity.uid, UID);
            {
                let observed = fake.lock().unwrap();
                assert_eq!(observed.refused, [409]);
                assert_eq!(observed.accepted.len(), 1);
                assert_eq!(
                    observed.accepted[0]["metadata"],
                    json!({"uid": UID, "resourceVersion": "101"})
                );
                assert_eq!(actual_of(&observed), &quantities(REQUESTED));
            }

            let (client, fake) = api(Fake::new(
                pod(UID, PREVIOUS, PREVIOUS),
                Kubelet::Applies,
                Race::RestartPolicy,
            ));
            let error = resize(&client).await.unwrap_err();
            assert!(
                format!("{error:#}").contains("cannot be resized live"),
                "{error:#}"
            );
            let fake = fake.lock().unwrap();
            assert!(fake.accepted.is_empty());
            assert_eq!(fake.refused, [409]);
            assert_eq!(spec_of(&fake), &quantities(PREVIOUS));
        }

        /// #2473: a normal resize goes through `pods/resize`, bound to the
        /// observed incarnation, and keeps its UID and restart count.
        #[tokio::test]
        async fn normal_resize_uses_the_resize_subresource_bound_to_the_observed_pod() {
            let (client, fake) = api(Fake::new(
                pod(UID, PREVIOUS, PREVIOUS),
                Kubelet::Applies,
                Race::None,
            ));
            let resized = resize(&client).await.unwrap();
            assert_eq!(resized.identity.uid, UID);
            assert_eq!(resized.restart_count, 2);
            let fake = fake.lock().unwrap();
            assert!(fake.refused.is_empty());
            assert_eq!(fake.accepted.len(), 1);
            assert_eq!(
                fake.accepted[0],
                json!({
                    "metadata": {"uid": UID, "resourceVersion": "100"},
                    "spec": {"containers": [{"name": "workspace", "resources": quantities(REQUESTED)}]}
                })
            );
            assert_eq!(actual_of(&fake), &quantities(REQUESTED));
        }

        /// A Pod running at 2:1: half its CPU reserved, all of its memory.
        fn shared_quantities((cpu, memory): (i32, i32)) -> Value {
            json!({
                "requests": {"cpu": format!("{}m", cpu / 2), "memory": format!("{memory}Mi")},
                "limits": {"cpu": format!("{cpu}m"), "memory": format!("{memory}Mi")}
            })
        }

        fn shared_pod(uid: &str, spec: (i32, i32), actual: (i32, i32)) -> Value {
            let mut pod = pod(uid, spec, actual);
            pod["spec"]["containers"][0]["resources"] = shared_quantities(spec);
            pod["status"]["containerStatuses"][0]["resources"] = shared_quantities(actual);
            pod
        }

        /// #3635: a resize keeps the ratio the Pod runs at, and converges on it.
        #[tokio::test]
        async fn a_resize_keeps_the_cpu_sharing_the_pod_runs_at() {
            let (client, fake) = api(Fake::new(
                shared_pod(UID, PREVIOUS, PREVIOUS),
                Kubelet::Applies,
                Race::None,
            ));
            resize(&client).await.unwrap();
            let fake = fake.lock().unwrap();
            assert_eq!(fake.accepted.len(), 1);
            assert_eq!(
                fake.accepted[0]["spec"]["containers"][0]["resources"],
                shared_quantities(REQUESTED)
            );
            assert_eq!(actual_of(&fake), &shared_quantities(REQUESTED));
        }

        /// #3635: a failed resize of a shared Pod is recognized as applied, and
        /// never rewritten at 1:1.
        #[tokio::test]
        async fn a_failed_resize_of_a_shared_pod_settles_at_its_ratio() {
            let mut fake = Fake::new(
                shared_pod(UID, PREVIOUS, PREVIOUS),
                Kubelet::Applies,
                Race::None,
            );
            fake.failing_reads = 1;
            let (client, fake) = api(fake);
            resize(&client).await.unwrap_err();
            assert_eq!(settle(&client).await, FailedLiveResize::Applied);
            let fake = fake.lock().unwrap();
            assert_eq!(fake.accepted.len(), 1, "no withdrawal");
            assert_eq!(actual_of(&fake), &shared_quantities(REQUESTED));
        }

        /// #3635: a withdrawal goes back to the previous size at the Pod's ratio.
        #[tokio::test]
        async fn a_withdrawn_resize_of_a_shared_pod_returns_to_its_ratio() {
            let mut pending = pending(UID, REQUESTED, PREVIOUS, "Deferred");
            pending["spec"]["containers"][0]["resources"] = shared_quantities(REQUESTED);
            pending["status"]["containerStatuses"][0]["resources"] = shared_quantities(PREVIOUS);
            let (client, fake) = api(Fake::new(pending, Kubelet::Applies, Race::None));
            assert_eq!(settle(&client).await, FailedLiveResize::Settled);
            let fake = fake.lock().unwrap();
            assert_eq!(spec_of(&fake), &shared_quantities(PREVIOUS));
            assert_eq!(actual_of(&fake), &shared_quantities(PREVIOUS));
        }

        /// #2475: an Infeasible condition from an earlier generation does not
        /// fail a new feasible request before the kubelet acknowledges it.
        #[tokio::test]
        async fn stale_infeasible_condition_does_not_fail_a_new_feasible_request() {
            let mut fake = Fake::new(
                pending(UID, (64_000, 1024), PREVIOUS, "Infeasible"),
                Kubelet::Applies,
                Race::None,
            );
            fake.lag = 1;
            let (client, fake) = api(fake);
            resize(&client).await.unwrap();
            let fake = fake.lock().unwrap();
            // Submission read, the stale read, then the synced read.
            assert!(fake.reads >= 3, "{}", fake.reads);
            assert_eq!(fake.pod["metadata"]["generation"], 3);
            assert_eq!(actual_of(&fake), &quantities(REQUESTED));
        }

        /// #2475: an Infeasible condition acknowledging this request's
        /// generation is an actionable, terminal failure.
        #[tokio::test]
        async fn current_generation_infeasible_request_fails_actionably() {
            let (client, _) = api(Fake::new(
                pod(UID, PREVIOUS, PREVIOUS),
                Kubelet::Infeasible,
                Race::None,
            ));
            let error = resize(&client).await.unwrap_err();
            let infeasible = error
                .downcast_ref::<PodResizeInfeasible>()
                .expect("acknowledged infeasible request");
            assert_eq!(infeasible.0, "Infeasible on node");
        }

        /// #2474, #2475: Deferred keeps waiting within the deadline and then
        /// fails retryably, never as infeasible.
        #[tokio::test]
        async fn deferred_request_keeps_waiting_until_the_operation_deadline() {
            let (client, fake) = api(Fake::new(
                pod(UID, PREVIOUS, PREVIOUS),
                Kubelet::Defers,
                Race::None,
            ));
            let error = resize(&client).await.unwrap_err();
            assert!(error.downcast_ref::<PodResizeInfeasible>().is_none());
            assert!(
                format!("{error:#}").contains("timeout waiting"),
                "{error:#}"
            );
            assert!(fake.lock().unwrap().reads > 2);
        }

        /// #2475: without generation fields an Infeasible condition cannot be
        /// attributed, so the request waits for its deadline and names it.
        #[tokio::test]
        async fn infeasible_without_generation_fields_waits_instead_of_failing() {
            let mut pod = pod(UID, PREVIOUS, PREVIOUS);
            pod["metadata"]
                .as_object_mut()
                .unwrap()
                .remove("generation");
            pod["status"]
                .as_object_mut()
                .unwrap()
                .remove("observedGeneration");
            let mut fake = Fake::new(pod, Kubelet::Infeasible, Race::None);
            fake.generations = false;
            let (client, _) = api(fake);
            let error = resize(&client).await.unwrap_err();
            assert!(error.downcast_ref::<PodResizeInfeasible>().is_none());
            assert!(
                format!("{error:#}")
                    .contains("unacknowledged request is reported infeasible: Infeasible on node"),
                "{error:#}"
            );
        }

        /// #2475: a worker retry resubmits the same spec, which keeps its
        /// generation, so that generation's Infeasible condition is its own.
        #[tokio::test]
        async fn retried_request_owns_the_infeasible_condition_of_its_generation() {
            let (client, fake) = api(Fake::new(
                pending(UID, REQUESTED, PREVIOUS, "Infeasible"),
                Kubelet::Infeasible,
                Race::None,
            ));
            let error = resize(&client).await.unwrap_err();
            assert!(error.downcast_ref::<PodResizeInfeasible>().is_some());
            let fake = fake.lock().unwrap();
            assert_eq!(fake.accepted.len(), 1);
            assert_eq!(fake.pod["metadata"]["generation"], 2);
        }

        #[test]
        fn generation_evidence_attributes_only_acknowledged_conditions() {
            let with = |metadata: Option<i64>, condition: Option<i64>, kubelet: Option<i64>| {
                let mut pod = pending(UID, REQUESTED, PREVIOUS, "Infeasible");
                pod["status"]["conditions"][0]["observedGeneration"] = json!(condition);
                pod["status"]["observedGeneration"] = json!(kubelet);
                pod["metadata"]["generation"] = json!(metadata);
                serde_json::from_value::<Pod>(pod).unwrap()
            };
            for (requested, observed, acknowledged) in [
                (Some(3), Some(2), false),
                (Some(3), Some(3), true),
                (Some(3), Some(4), true),
                (None, Some(3), false),
                (Some(3), None, false),
            ] {
                let pod = with(requested, observed, observed);
                assert_eq!(
                    infeasible_pod_resize(&pod, requested),
                    Some(("Infeasible on node".to_string(), acknowledged)),
                    "{requested:?} {observed:?}"
                );
                // Resources alone decide where either generation is absent.
                assert_eq!(
                    pod_resize_acknowledged(&pod, requested),
                    acknowledged || requested.is_none() || observed.is_none(),
                    "{requested:?} {observed:?}"
                );
            }
        }

        /// #2474: a request still Deferred when the operation fails is
        /// withdrawn on the same Pod, so nothing applies later.
        #[tokio::test]
        async fn failed_resize_withdraws_a_deferred_request_on_the_same_pod() {
            let (client, fake) = api(Fake::new(
                pending(UID, REQUESTED, PREVIOUS, "Deferred"),
                Kubelet::Defers,
                Race::None,
            ));
            assert_eq!(settle(&client).await, FailedLiveResize::Settled);
            let fake = fake.lock().unwrap();
            assert_eq!(fake.accepted.len(), 1);
            assert_eq!(
                fake.accepted[0]["metadata"],
                json!({"uid": UID, "resourceVersion": "100"})
            );
            assert_eq!(spec_of(&fake), &quantities(PREVIOUS));
            assert_eq!(actual_of(&fake), &quantities(PREVIOUS));
            assert_eq!(fake.pod["status"]["conditions"], json!([]));
            assert_eq!(fake.pod["status"]["observedGeneration"], 3);
        }

        /// #2474: an increase applied before observation failed is kept and
        /// reported, never withdrawn.
        #[tokio::test]
        async fn failed_resize_keeps_a_request_the_pod_already_applied() {
            let mut fake = Fake::new(pod(UID, PREVIOUS, PREVIOUS), Kubelet::Applies, Race::None);
            fake.failing_reads = 1;
            let (client, fake) = api(fake);
            let error = resize(&client).await.unwrap_err();
            assert!(
                format!("{error:#}").contains("observe resized workspace Pod"),
                "{error:#}"
            );
            assert_eq!(settle(&client).await, FailedLiveResize::Applied);
            let fake = fake.lock().unwrap();
            assert_eq!(fake.accepted.len(), 1, "no withdrawal");
            assert_eq!(actual_of(&fake), &quantities(REQUESTED));
        }

        /// #2474: an increase landing during withdrawal changes the Pod, so the
        /// withdrawal is refused and the applied increase is kept.
        #[tokio::test]
        async fn failed_resize_keeps_an_increase_that_lands_during_withdrawal() {
            let (client, fake) = api(Fake::new(
                pending(UID, REQUESTED, PREVIOUS, "Deferred"),
                Kubelet::Defers,
                Race::KubeletApplies,
            ));
            assert_eq!(settle(&client).await, FailedLiveResize::Applied);
            let fake = fake.lock().unwrap();
            assert!(fake.accepted.is_empty());
            assert_eq!(fake.refused, [409]);
            assert_eq!(spec_of(&fake), &quantities(REQUESTED));
        }

        /// #2474: compensation never reaches another Pod incarnation.
        #[tokio::test]
        async fn failed_resize_never_compensates_a_replacement_pod() {
            let (client, fake) = api(Fake::new(
                pending("uid-replacement", REQUESTED, PREVIOUS, "Deferred"),
                Kubelet::Defers,
                Race::None,
            ));
            let FailedLiveResize::Unknown(reason) = settle(&client).await else {
                panic!("a replacement Pod must not be settled");
            };
            assert!(reason.contains("replaced"), "{reason}");
            let fake = fake.lock().unwrap();
            assert!(fake.accepted.is_empty() && fake.refused.is_empty());
        }

        /// #2474: a withdrawal that does not settle leaves the outcome unknown.
        #[tokio::test]
        async fn failed_resize_is_unknown_when_withdrawal_does_not_settle() {
            let (client, fake) = api(Fake::new(
                pod(UID, REQUESTED, (1000, 1024)),
                Kubelet::Stalls,
                Race::None,
            ));
            let FailedLiveResize::Unknown(reason) = settle(&client).await else {
                panic!("an unsettled withdrawal must stay unknown");
            };
            assert!(reason.contains("did not settle"), "{reason}");
            assert_eq!(fake.lock().unwrap().accepted.len(), 1);
        }
    }
}
