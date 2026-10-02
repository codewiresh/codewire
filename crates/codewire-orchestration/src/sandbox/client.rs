//! kube-rs client for agent-sandbox CRDs and Codewire-owned companion runtime objects.
//!
//! Mirror of the dynamic-client paths in `internal/sandbox/client.go`:
//! SandboxClaim create (AlreadyExists → reuse), get, finalizer removal,
//! delete. Rust now owns the live gateway/workspace split, so this client
//! also manages the gateway Deployment, gateway Service, workspace-daemon
//! Service, and their NetworkPolicies.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crc32fast::Hasher as Crc32Hasher;
use k8s_openapi::api::core::v1::{
    ContainerStatus, Namespace, PersistentVolume, PersistentVolumeClaim, Pod,
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
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use serde_json::Value;

use super::template::{
    CONFIDENTIAL_WORKSPACE_STORAGE_CLASS, KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY,
    TemplateOpts, gateway_direct_udp_service_name, gateway_host_key_secret_name,
    gateway_network_policy_name, gateway_workload_name, render_gateway_deployment,
    render_gateway_direct_udp_service, render_gateway_host_key_secret,
    render_gateway_network_policy, render_gateway_service, render_sandbox_shadow_pool,
    render_sandbox_template, render_workspace_daemon_network_policy,
    render_workspace_daemon_service, workspace_daemon_network_policy_name,
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
    pub node_name: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub pod_ip: String,
    /// Start marks of the probed Pod, read from the same Pod object.
    pub pod_timeline: PodStartTimeline,
}

/// Kubernetes-reported start marks for one workspace Pod incarnation, taken
/// from the Pod's own metadata and status. Kubernetes records these times at
/// one-second resolution. A condition's mark is its latest transition to
/// `True`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodStartTimeline {
    pub created_at: Option<Timestamp>,
    /// `PodScheduled=True`.
    pub scheduled_at: Option<Timestamp>,
    /// `Initialized=True`: every init container completed.
    pub initialized_at: Option<Timestamp>,
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
        Self {
            created_at: pod.metadata.creation_timestamp.as_ref().map(|time| time.0),
            scheduled_at: condition_true_at("PodScheduled"),
            initialized_at: condition_true_at("Initialized"),
            running_at,
            containers_ready_at: condition_true_at("ContainersReady"),
        }
    }
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
const LONGHORN_NAMESPACE: &str = "longhorn-system";
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

#[path = "client_credentials.rs"]
mod credentials;

#[path = "client/workspace_binding.rs"]
mod workspace_binding;
#[cfg(test)]
pub(crate) use workspace_binding::sandbox_name_hash;
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

const WORKSPACE_BOOTSTRAP_KEYS: [&str; 4] = [
    "CODEWIRE_ENVIRONMENT_ID",
    "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",
    "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256",
    super::template::MANAGED_CREDENTIAL_CLIENTS_ENV,
];

fn workspace_owned_environment_keys() -> BTreeSet<String> {
    let mut keys: BTreeSet<_> = WORKSPACE_BOOTSTRAP_KEYS
        .into_iter()
        .map(str::to_owned)
        .collect();
    keys.extend(
        codewire_access::ManagedCredentialClients::from_profile_slots([
            "codex",
            "openai",
            "anthropic",
            "ssh",
        ])
        .expect("closed slots")
        .for_placement(codewire_access::ManagedCredentialClientPlacement::Platform)
        .environment
        .into_keys(),
    );
    // Public roots previously rendered by this same owned workspace bootstrap.
    // They must not persist when the stock client uses the loopback route.
    keys.insert("CODEX_CA_CERTIFICATE".into());
    keys
}

fn workspace_bootstrap_values(opts: &TemplateOpts) -> anyhow::Result<BTreeMap<String, String>> {
    anyhow::ensure!(
        !opts.environment_id.is_empty()
            && opts.environment_id.trim() == opts.environment_id
            && !opts.organization_id.is_empty()
            && opts.operation_generation > 0
            && opts.name.ends_with(&format!("-{}", opts.environment_id)),
        "workspace bootstrap authority is incomplete"
    );
    let Some(digest) = opts.projection_selection_sha256 else {
        anyhow::ensure!(
            opts.managed_credential_clients == Default::default(),
            "managed credential clients have no selected bootstrap"
        );
        return Ok(BTreeMap::new());
    };
    anyhow::ensure!(
        digest != [0; 32] && opts.credential_runtime.is_some(),
        "workspace bootstrap selection has no runtime trust"
    );
    let mut expected = BTreeMap::from([
        (
            WORKSPACE_BOOTSTRAP_KEYS[0].to_owned(),
            opts.environment_id.clone(),
        ),
        (
            WORKSPACE_BOOTSTRAP_KEYS[1].to_owned(),
            opts.operation_generation.to_string(),
        ),
        (
            WORKSPACE_BOOTSTRAP_KEYS[2].to_owned(),
            digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        ),
        (
            WORKSPACE_BOOTSTRAP_KEYS[3].to_owned(),
            opts.managed_credential_clients.encode().to_owned(),
        ),
    ]);
    expected.extend(
        opts.managed_credential_clients
            .for_placement(codewire_access::ManagedCredentialClientPlacement::Platform)
            .environment,
    );
    Ok(expected)
}

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

fn bootstrap_environment_matches(env: &[Value], expected: &BTreeMap<String, String>) -> bool {
    let mut seen = BTreeSet::new();
    let owned = workspace_owned_environment_keys();
    for entry in env {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            return false;
        };
        if owned.contains(name)
            && (!seen.insert(name)
                || !entry.get("valueFrom").is_none_or(Value::is_null)
                || environment_value(entry) != expected.get(name).map(String::as_str)
                || !expected.contains_key(name))
        {
            return false;
        }
    }
    seen.len() == expected.len()
}

/// The Pod API omits an empty `value`, so a stored Pod never repeats the
/// blank placeholders a selected client renders (for example
/// `ANTHROPIC_API_KEY`). An absent value is the empty string.
fn environment_value(entry: &Value) -> Option<&str> {
    match entry.get("value") {
        None | Some(Value::Null) => Some(""),
        Some(value) => value.as_str(),
    }
}

fn bootstrap_template_matches(
    object: &DynamicObject,
    expected: &BTreeMap<String, String>,
) -> anyhow::Result<bool> {
    let containers = object
        .data
        .pointer("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("runtime object has no containers"))?;
    let (_, container) = workspace_container(containers)?;
    Ok(bootstrap_environment_matches(
        workspace_environment(container)?,
        expected,
    ))
}

/// JSON Patch modifies only the owned entries, not the surrounding env array.
/// UID/RV tests bind the validated incarnation and every array index. No retry
/// substitutes another object's version after a conflict.
fn workspace_bootstrap_patch(
    object: &DynamicObject,
    expected: &BTreeMap<String, String>,
    recovery: Option<&Value>,
    clients: &Value,
) -> anyhow::Result<Option<Patch<()>>> {
    let env_matches = bootstrap_template_matches(object, expected)?;
    let mut changes = workspace_client_changes(&object.data, clients, "/spec/podTemplate/spec")?;
    if let Some(recovery) = recovery {
        let kernel = recovery
            .pointer("/spec/podTemplate/metadata/annotations")
            .and_then(|annotations| annotations.get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY))
            .ok_or_else(|| anyhow::anyhow!("confidential recovery annotation is unavailable"))?;
        let annotations = "/spec/podTemplate/metadata/annotations";
        if object
            .data
            .pointer(annotations)
            .and_then(|values| values.get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY))
            != Some(kernel)
        {
            anyhow::ensure!(
                object
                    .data
                    .pointer("/spec/podTemplate/metadata")
                    .is_some_and(Value::is_object),
                "workspace metadata is unavailable"
            );
            if let Some(current) = object.data.pointer(annotations) {
                anyhow::ensure!(current.is_object(), "workspace annotations are malformed");
                let key = KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY
                    .replace('~', "~0")
                    .replace('/', "~1");
                changes.push(serde_json::json!({"op":"add", "path":format!("{annotations}/{key}"), "value":kernel}));
            } else {
                changes.push(serde_json::json!({"op":"add", "path":annotations, "value":{KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY:kernel}}));
            }
        }
        let policy = "/spec/podTemplate/spec/securityContext/fsGroupChangePolicy";
        let expected_policy = recovery
            .pointer(policy)
            .ok_or_else(|| anyhow::anyhow!("confidential recovery policy is unavailable"))?;
        if object.data.pointer(policy) != Some(expected_policy) {
            anyhow::ensure!(
                object
                    .data
                    .pointer("/spec/podTemplate/spec/securityContext")
                    .is_some_and(Value::is_object),
                "workspace security context is unavailable"
            );
            changes.push(serde_json::json!({"op":"add", "path":policy, "value":expected_policy}));
        }
    }
    if env_matches && changes.is_empty() {
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
    let containers = object
        .data
        .pointer("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("runtime object has no containers"))?;
    let (index, container) = workspace_container(containers)?;
    let env = workspace_environment(container)?;
    anyhow::ensure!(
        env.iter()
            .all(|entry| entry.get("name").and_then(Value::as_str).is_some()),
        "workspace environment is malformed"
    );
    let path = format!("/spec/podTemplate/spec/containers/{index}/env");
    let mut patch = vec![
        serde_json::json!({"op":"test", "path":"/metadata/uid", "value":uid}),
        serde_json::json!({"op":"test", "path":"/metadata/resourceVersion", "value":version}),
    ];
    if !env_matches && container.get("env").is_none() {
        patch.push(serde_json::json!({"op":"add", "path":path, "value":[]}));
    }
    for (index, entry) in env.iter().enumerate().rev().filter(|_| !env_matches) {
        if entry
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| workspace_owned_environment_keys().contains(name))
        {
            patch.push(serde_json::json!({"op":"remove", "path":format!("{path}/{index}")}));
        }
    }
    for (name, value) in expected.iter().filter(|_| !env_matches) {
        patch.push(serde_json::json!({"op":"add", "path":format!("{path}/-"), "value":{"name":name,"value":value}}));
    }
    patch.extend(changes);
    Ok(Some(Patch::Json(serde_json::from_value(Value::Array(
        patch,
    ))?)))
}

const WORKSPACE_CLIENT_VOLUMES: [&str; 2] = ["credential-codex-config", "credential-codex-home"];

/// Reconcile named machine-owned entries without replacing their surrounding
/// arrays. Array indices are protected by the outer object's UID/RV tests.
fn workspace_client_named_changes(
    data: &Value,
    path: &str,
    expected: &[Value],
    changes: &mut Vec<Value>,
) -> anyhow::Result<()> {
    let current = match data.pointer(path) {
        None => &[][..],
        Some(Value::Array(values)) => values.as_slice(),
        _ => anyhow::bail!("workspace client bootstrap array is malformed"),
    };
    anyhow::ensure!(
        current
            .iter()
            .all(|entry| entry.get("name").and_then(Value::as_str).is_some()),
        "workspace client bootstrap entry is malformed"
    );
    let owned = |entry: &&Value| {
        entry
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| WORKSPACE_CLIENT_VOLUMES.contains(&name))
    };
    let current_owned: Vec<_> = current.iter().filter(owned).collect();
    let desired: Vec<_> = expected.iter().filter(owned).collect();
    if current_owned.len() == desired.len()
        && current_owned
            .iter()
            .map(|entry| entry["name"].as_str().expect("validated entry name"))
            .collect::<BTreeSet<_>>()
            .len()
            == current_owned.len()
        && current_owned.iter().all(|entry| desired.contains(entry))
    {
        return Ok(());
    }
    if data.pointer(path).is_none() {
        changes.push(serde_json::json!({"op":"add","path":path,"value":[]}));
    }
    for (index, entry) in current.iter().enumerate().rev() {
        if owned(&entry) {
            changes.push(serde_json::json!({"op":"remove","path":format!("{path}/{index}")}));
        }
    }
    for entry in desired {
        changes.push(serde_json::json!({"op":"add","path":format!("{path}/-"),"value":entry}));
    }
    Ok(())
}

fn workspace_client_changes(
    data: &Value,
    clients: &Value,
    spec_path: &str,
) -> anyhow::Result<Vec<Value>> {
    let spec = data
        .pointer(spec_path)
        .ok_or_else(|| anyhow::anyhow!("workspace spec is unavailable"))?;
    let containers = spec
        .get("containers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("workspace containers are unavailable"))?;
    let (workspace_index, _) = workspace_container(containers)?;
    let init_containers = match spec.get("initContainers") {
        None => &[][..],
        Some(Value::Array(values)) => values.as_slice(),
        _ => anyhow::bail!("workspace bootstrap init is malformed"),
    };
    let named_init = |name: &str| -> anyhow::Result<Option<(usize, &Value)>> {
        let mut found = init_containers
            .iter()
            .enumerate()
            .filter(|(_, container)| container["name"] == name);
        let first = found.next();
        anyhow::ensure!(
            found.next().is_none(),
            "workspace bootstrap init is duplicated"
        );
        Ok(first)
    };
    let daemon_init = named_init(super::template::DAEMON_INIT_CONTAINER)?;
    let client_init = named_init(super::template::CLIENT_BOOTSTRAP_CONTAINER)?;
    // The daemon reaches `/codewire/bin` by exactly one route, fixed when the
    // object was created: copied by its init container into an emptyDir, or
    // mounted from the support image. Older objects keep the copy.
    let daemon_image = match (daemon_init, workspace_daemon_image(spec)?) {
        (Some(_), None) if client_init.is_none() => None,
        (None, Some(image)) => Some(image),
        (None, None) => anyhow::bail!("workspace bootstrap init is unavailable"),
        _ => anyhow::bail!("workspace daemon delivery is ambiguous"),
    };
    let mut changes = Vec::new();
    for (path, expected) in [
        (format!("{spec_path}/volumes"), &clients["volumes"]),
        (
            format!("{spec_path}/containers/{workspace_index}/volumeMounts"),
            &clients["volumeMounts"],
        ),
    ] {
        workspace_client_named_changes(
            data,
            &path,
            expected.as_array().expect("rendered client array"),
            &mut changes,
        )?;
    }
    let (current, expected) = match daemon_image {
        None => (daemon_init, &clients["init"]),
        Some(image) => {
            let expected = &clients["clientInit"];
            match (client_init, expected.is_null()) {
                (None, true) => return Ok(changes),
                (Some((index, _)), true) => {
                    changes.push(serde_json::json!({"op":"remove","path":format!("{spec_path}/initContainers/{index}")}));
                    return Ok(changes);
                }
                (None, false) => {
                    let mut init = expected.clone();
                    init["image"] = image.into();
                    changes.push(if spec.get("initContainers").is_none() {
                        serde_json::json!({"op":"add","path":format!("{spec_path}/initContainers"),"value":[init]})
                    } else {
                        serde_json::json!({"op":"add","path":format!("{spec_path}/initContainers/-"),"value":init})
                    });
                    return Ok(changes);
                }
                (Some(_), false) => (client_init, expected),
            }
        }
    };
    let (init_index, current_init) = current.expect("selected bootstrap init");
    workspace_client_named_changes(
        data,
        &format!("{spec_path}/initContainers/{init_index}/volumeMounts"),
        expected["volumeMounts"]
            .as_array()
            .expect("rendered client array"),
        &mut changes,
    )?;
    if current_init.get("command") != Some(&expected["command"]) {
        changes.push(serde_json::json!({"op":"add","path":format!("{spec_path}/initContainers/{init_index}/command"),"value":expected["command"]}));
    }
    Ok(changes)
}

/// The support image a Pod mounts its daemon from, or `None` when its
/// `codewire-bin` is an emptyDir filled by the daemon init container.
fn workspace_daemon_image(spec: &Value) -> anyhow::Result<Option<&str>> {
    let volumes = spec
        .get("volumes")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut daemon = volumes
        .iter()
        .filter(|volume| volume["name"] == super::template::DAEMON_VOLUME);
    let volume = daemon.next();
    anyhow::ensure!(
        daemon.next().is_none(),
        "workspace daemon volume is duplicated"
    );
    let Some(image) = volume.and_then(|volume| volume.get("image")) else {
        return Ok(None);
    };
    image
        .get("reference")
        .and_then(Value::as_str)
        .filter(|reference| !reference.is_empty())
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("workspace daemon image is malformed"))
}

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
        named(codewire_gateway_proto::WORKSPACE_BINDING_URL_ENV),
        named(super::template::DAEMON_AUTH_TOKEN_ENV),
    ) {
        (true, false) => Ok(true),
        (false, _) => Ok(false),
        (true, true) => anyhow::bail!("workspace identity rendering is ambiguous"),
    }
}

/// The JSON Patch that replaces a legacy object's workspace Pod spec (and,
/// for the template, its egress) with the identity-free rendering, bound to
/// the validated UID and resourceVersion. `None` when already identity-free.
fn identity_free_upgrade_patch(
    object: &DynamicObject,
    pod_spec: &Value,
    network_policy: Option<&Value>,
) -> anyhow::Result<Option<Patch<()>>> {
    if workspace_object_identity_free(object)? {
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

/// Namespaced client for SandboxClaim operations.
#[derive(Clone)]
pub struct SandboxClient {
    pub(crate) client: Client,
    pub(crate) namespace: String,
    claims: Api<DynamicObject>,
}

impl SandboxClient {
    /// Builds from the ambient kube config (in-cluster or KUBECONFIG),
    /// like the Go client's rest.InClusterConfig / kubeconfig fallback.
    pub async fn from_env(namespace: &str) -> anyhow::Result<Self> {
        let client = Client::try_default().await?;
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

    /// Ensures the shared sandbox namespace exists with the current Codewire labels.
    pub async fn ensure_namespace(&self) -> anyhow::Result<()> {
        let namespaces: Api<Namespace> = Api::all(self.client.clone());
        let name = &self.namespace;
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "codewire".to_string(),
        );
        labels.insert(
            "codewire.sh/resource-type".to_string(),
            "sandbox".to_string(),
        );
        labels.insert(
            "codewire.sh/runtime-scope".to_string(),
            "shared".to_string(),
        );

        match namespaces.get(name).await {
            Err(kube::Error::Api(e)) if e.code == 404 => {
                let namespace = Namespace {
                    metadata: ObjectMeta {
                        name: Some(name.clone()),
                        labels: Some(labels),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                namespaces
                    .create(&PostParams::default(), &namespace)
                    .await
                    .map_err(|e| anyhow::anyhow!("create namespace {name}: {e}"))?;
                tracing::info!(namespace = name, "created sandbox namespace");
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("get namespace {name}: {e}")),
            Ok(_) => {
                let patch: Value = serde_json::json!({
                    "metadata": {
                        "labels": {
                            "app.kubernetes.io/managed-by": "codewire",
                            "codewire.sh/resource-type": "sandbox",
                            "codewire.sh/runtime-scope": "shared",
                        },
                    },
                });
                namespaces
                    .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                    .await
                    .map_err(|e| anyhow::anyhow!("patch namespace {name}: {e}"))?;
                tracing::info!(namespace = name, "normalized sandbox namespace");
                Ok(())
            }
        }
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
        let pod_uid = runtime_object_uid(&pod.metadata, &self.namespace, pod_name)?;
        require_runtime_controller(
            &pod.metadata,
            "agents.x-k8s.io/v1beta1",
            "Sandbox",
            &sandbox_name,
            sandbox_uid,
        )?;
        anyhow::ensure!(
            bound_pod_uid.is_none_or(|bound| bound == pod_uid),
            "workspace Pod is not the bound incarnation"
        );
        Ok(WorkspacePodIdentity {
            name: pod_name.to_owned(),
            uid: pod_uid.to_owned(),
        })
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
    /// changed without replacing or restarting the workspace container.
    pub async fn workspace_pod_resize_state(
        &self,
        env_id: &str,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        let pod_name = self.get_pod_name(env_id).await?;
        let pod = self
            .pods()
            .get(&pod_name)
            .await
            .map_err(|error| anyhow::anyhow!("get workspace Pod {pod_name}: {error}"))?;
        workspace_pod_resize_state(&pod, &pod_name)
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

        let before = self.workspace_pod_resize_state(env_id).await?;
        if before.identity.uid != expected_uid {
            anyhow::bail!(
                "workspace Pod identity changed before live resize: expected UID {expected_uid}, got {}",
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

        let cpu = format!("{cpu_millicores}m");
        let memory = format!("{memory_mb}Mi");
        let patch = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "workspace",
                    "resources": {
                        "requests": { "cpu": cpu, "memory": memory },
                        "limits": { "cpu": cpu, "memory": memory },
                    },
                }],
            },
        });
        self.pods()
            .patch_resize(
                &before.identity.name,
                &PatchParams::default(),
                &Patch::Strategic(&patch),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "resize workspace Pod {} through /resize: {error}",
                    before.identity.name
                )
            })?;

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
            if observed.identity.uid != expected_uid {
                anyhow::bail!(
                    "workspace Pod was replaced during live resize: expected UID {expected_uid}, got {}",
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
            if let Some(failure) = terminal_pod_resize_failure(&pod) {
                anyhow::bail!("workspace Pod live resize failed: {failure}");
            }
            if workspace_resources_match(&pod, &cpu, &memory) {
                return Ok(observed);
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "timeout waiting for workspace Pod {} live resize to converge",
                    before.identity.name
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
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
        let Some(current) = self.get_workspace_pod_identity_by_name(pod_name).await? else {
            return Ok(());
        };
        if current.uid != previous_uid {
            return Ok(());
        }

        let delete_params = delete_params_for_observed_uid(previous_uid);
        match self.pods().delete(&current.name, &delete_params).await {
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            // A replacement won the race after the observation above. The
            // UID precondition prevented deleting it; the caller can now
            // observe that replacement normally.
            Err(kube::Error::Api(error)) if error.code == 409 => {}
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "restart workspace Pod {}: {error}",
                    current.name
                ));
            }
        }
        Ok(())
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

    /// Reconcile the current confidential runtime fields into the private
    /// template and the allocated Sandbox before replacing a terminal Pod.
    /// Updating the SandboxTemplate alone is insufficient because the
    /// controller does not rewrite an already-created Sandbox.
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
        let (kernel_params, runtime_patch) =
            rendered_runtime_recovery_patch(&self.namespace, opts)?;
        self.ensure_sandbox_template(opts).await?;
        sandboxes
            .patch(
                sandbox_name,
                &PatchParams::default(),
                &Patch::Merge(&runtime_patch),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("patch Sandbox {sandbox_name} runtime parameters: {error}")
            })?;
        Ok(kernel_params)
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
        workspace_bootstrap_values(opts)?;
        let claim_opts = ClaimOpts {
            environment_id: opts.environment_id.clone(),
            org_id: opts.organization_id.clone(),
            operation_generation: opts.operation_generation,
            ..Default::default()
        };
        let (claim, sandbox) = self
            .read_owned_claim_sandbox(&claim_opts, expected_claim_name, expected_claim_uid)
            .await?;
        let pool_name = super::shadow_warm_pool_name(&opts.name);
        anyhow::ensure!(
            claim
                .data
                .pointer("/spec/warmPoolRef/name")
                .and_then(Value::as_str)
                == Some(pool_name.as_str()),
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
                    .is_some_and(|name| workspace_owned_environment_keys().contains(name))),
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
        })
    }

    /// Refresh only environment-owned bootstrap fields in the private template
    /// and its allocated Sandbox. Works while suspended without a Pod. The
    /// caller holds the existing environment-row publication fence, and owns
    /// suspension/replacement; this never mutates a live Pod's environment.
    pub async fn reconcile_workspace_bootstrap(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
    ) -> anyhow::Result<()> {
        if opts.identity_free() {
            return self
                .reconcile_identity_free_bootstrap(
                    opts,
                    expected_claim_name,
                    expected_claim_uid,
                    expected_sandbox,
                )
                .await;
        }
        let expected = workspace_bootstrap_values(opts)?;
        let before = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&before.sandbox)?;
        anyhow::ensure!(
            sandbox_suspension_observed(&before.sandbox),
            "workspace bootstrap refresh requires current controller-completed suspension"
        );
        // Rollback (`environment-token`) renders legacy Pods for new
        // environments but leaves an identity-free one as it is: it keeps
        // binding, and environment values patched into it would make its
        // binding-mode daemon refuse to start.
        if workspace_object_identity_free(&before.template)?
            || workspace_object_identity_free(&before.sandbox)?
        {
            return Ok(());
        }
        let recovery = if opts.runtime_profile_spec().profile
            == super::template::RUNTIME_PROFILE_CONFIDENTIAL
        {
            Some(rendered_runtime_recovery_patch(&self.namespace, opts)?.1)
        } else {
            None
        };
        let clients = super::template::render_workspace_client_bootstrap(opts);
        let patches = [
            (
                &before.template,
                self.templates(),
                workspace_bootstrap_patch(
                    &before.template,
                    &expected,
                    recovery.as_ref(),
                    &clients,
                )?,
            ),
            (
                &before.sandbox,
                self.sandboxes(),
                workspace_bootstrap_patch(&before.sandbox, &expected, recovery.as_ref(), &clients)?,
            ),
        ];
        if opts
            .managed_credential_clients
            .contains(codewire_access::ManagedCredentialClient::Codex)
        {
            // A newly selected Codex init mount must exist before resume; waiting
            // for gateway/Pod readiness first would deadlock on its ConfigMap.
            self.ensure_credential_bootstrap(opts).await?;
        }
        for (object, api, patch) in patches {
            let Some(patch) = patch else {
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
                .map_err(|_| anyhow::anyhow!("workspace bootstrap update was not admitted"))?;
            anyhow::ensure!(
                runtime_object_uid(&updated.metadata, &self.namespace, name)?
                    == object
                        .metadata
                        .uid
                        .as_deref()
                        .expect("validated runtime UID"),
                "workspace bootstrap object was replaced during publication"
            );
            anyhow::ensure!(
                workspace_bootstrap_patch(&updated, &expected, recovery.as_ref(), &clients)?
                    .is_none(),
                "workspace bootstrap update did not converge"
            );
        }
        let after = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&after.sandbox)?;
        // Refresh itself can advance metadata.generation. The prior completed
        // suspension is retained by exact identity and unchanged mode, not by
        // pretending its condition acknowledges this new template generation.
        anyhow::ensure!(
            after
                .sandbox
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some("Suspended"),
            "workspace Sandbox resumed during bootstrap publication"
        );
        anyhow::ensure!(
            before.pool.metadata.uid == after.pool.metadata.uid
                && before.template.metadata.uid == after.template.metadata.uid
                && before.sandbox.metadata.uid == after.sandbox.metadata.uid,
            "workspace bootstrap ownership changed during publication"
        );
        for object in [&after.template, &after.sandbox] {
            anyhow::ensure!(
                workspace_bootstrap_patch(object, &expected, recovery.as_ref(), &clients)?
                    .is_none(),
                "workspace bootstrap publication is no longer current"
            );
        }
        Ok(())
    }

    /// Upgrade on start (design §12): with the identity mode at `binding`, the
    /// suspended environment's template and Sandbox get the whole
    /// identity-free workspace Pod spec (containers, init containers,
    /// volumes, probes, current images) and the template its identity-free
    /// egress. `volumeClaimTemplates` and the Pod template metadata are kept.
    /// Each object is patched under UID and resourceVersion tests; an object
    /// that is already identity-free is left alone, so a partly upgraded
    /// environment converges on its next start. The resumed Pod then binds
    /// with `credential_scope='pod'`.
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
        for (object, api, network_policy) in [
            (&before.template, self.templates(), network_policy.as_ref()),
            (&before.sandbox, self.sandboxes(), None),
        ] {
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
                    && workspace_object_identity_free(&updated)?,
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
                && workspace_object_identity_free(&after.sandbox)?,
            "workspace identity upgrade is no longer current"
        );
        Ok(())
    }

    /// Read the actual Pod's immutable tuple, not mutable association labels or
    /// template intent. A different Pod/owner is an identity error; stale or
    /// duplicate bootstrap entries return false for lifecycle-owned recovery.
    pub async fn workspace_bootstrap_matches(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_pod: &WorkspacePodIdentity,
    ) -> anyhow::Result<bool> {
        let expected = workspace_bootstrap_values(opts)?;
        let before = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        let sandbox_name = before
            .sandbox
            .metadata
            .name
            .as_deref()
            .expect("validated Sandbox name");
        let pod_name = before
            .sandbox
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get("agents.x-k8s.io/pod-name"))
            .map(String::as_str)
            .unwrap_or(sandbox_name);
        anyhow::ensure!(
            expected_pod.name == pod_name && !expected_pod.uid.is_empty(),
            "workspace bootstrap Pod is not the observed runtime"
        );
        let pod = self
            .pods()
            .get(pod_name)
            .await
            .map_err(|_| anyhow::anyhow!("workspace bootstrap Pod is unavailable"))?;
        anyhow::ensure!(
            runtime_object_uid(&pod.metadata, &self.namespace, pod_name)? == expected_pod.uid,
            "workspace bootstrap Pod was replaced"
        );
        require_runtime_controller(
            &pod.metadata,
            "agents.x-k8s.io/v1beta1",
            "Sandbox",
            sandbox_name,
            before
                .sandbox
                .metadata
                .uid
                .as_deref()
                .expect("validated Sandbox UID"),
        )?;
        let spec = pod
            .spec
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("workspace Pod has no spec"))?;
        let containers = serde_json::to_value(&spec.containers)?;
        let (_, container) =
            workspace_container(containers.as_array().expect("serialized containers array"))?;
        let clients = super::template::render_workspace_client_bootstrap(opts);
        let pod_data = serde_json::json!({"spec":spec});
        let matches = bootstrap_environment_matches(workspace_environment(container)?, &expected)
            && workspace_client_changes(&pod_data, &clients, "/spec")?.is_empty();
        let after = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        anyhow::ensure!(
            before.pool.metadata.uid == after.pool.metadata.uid
                && before.template.metadata.uid == after.template.metadata.uid
                && before.sandbox.metadata.uid == after.sandbox.metadata.uid,
            "workspace bootstrap ownership changed during observation"
        );
        let current_pod_name = after
            .sandbox
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get("agents.x-k8s.io/pod-name"))
            .map(String::as_str)
            .unwrap_or(
                after
                    .sandbox
                    .metadata
                    .name
                    .as_deref()
                    .expect("validated Sandbox name"),
            );
        anyhow::ensure!(
            current_pod_name == expected_pod.name,
            "workspace bootstrap Pod association changed during observation"
        );
        Ok(matches)
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

    fn longhorn_volumes(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("longhorn.io", "v1beta2", "Volume");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "volumes");
        Api::namespaced_with(self.client.clone(), LONGHORN_NAMESPACE, &resource)
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
        // before the downstream CSI/CDH refusal.
        if desired_disk_gb > storage.requested_disk_gb
            && storage.storage_class_name == CONFIDENTIAL_WORKSPACE_STORAGE_CLASS
        {
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
        let cpu = format!("{cpu_millicores}m");
        let memory = format!("{memory_mb}Mi");
        let storage = format!("{disk_gb}Gi");

        let claim = claim_name(env_id);
        let claim_patch = serde_json::json!({
            "spec": {
                "workspaceResources": [{
                    "containerName": "workspace",
                    "resources": {
                        "requests": { "cpu": cpu, "memory": memory },
                        "limits": { "cpu": cpu, "memory": memory },
                    },
                }],
            },
        });
        self.claims
            .patch(&claim, &PatchParams::default(), &Patch::Merge(&claim_patch))
            .await
            .map_err(|error| anyhow::anyhow!("patch SandboxClaim {claim}: {error}"))?;

        let sandbox_name = self.bound_sandbox_name(env_id).await?;
        let sandboxes = self.sandboxes();
        let mut sandbox = sandboxes
            .get(&sandbox_name)
            .await
            .map_err(|error| anyhow::anyhow!("get Sandbox {sandbox_name}: {error}"))?;
        set_workspace_resources(&mut sandbox.data, &cpu, &memory)?;
        sandboxes
            .replace(&sandbox_name, &PostParams::default(), &sandbox)
            .await
            .map_err(|error| anyhow::anyhow!("update Sandbox {sandbox_name}: {error}"))?;

        if let Some(template_name) = self.claim_template_name(env_id).await?
            && template_name.ends_with(&format!("-{env_id}"))
        {
            let templates = self.templates();
            let mut template = templates
                .get(&template_name)
                .await
                .map_err(|error| anyhow::anyhow!("get SandboxTemplate {template_name}: {error}"))?;
            set_workspace_resources(&mut template.data, &cpu, &memory)?;
            set_workspace_volume_request(&mut template.data, &storage)?;
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
                return Ok(WorkspaceStorageResizeOutcome::Applied);
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

    fn deployments(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("apps", "v1", "Deployment");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "deployments");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn services(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("", "v1", "Service");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "services");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn secrets(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("", "v1", "Secret");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "secrets");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    fn network_policies(&self) -> Api<DynamicObject> {
        let gvk = GroupVersionKind::gvk("networking.k8s.io", "v1", "NetworkPolicy");
        let resource = ApiResource::from_gvk_with_plural(&gvk, "networkpolicies");
        Api::namespaced_with(self.client.clone(), &self.namespace, &resource)
    }

    /// Mirrors `SetReplicas`: resolve the Sandbox name from the claim
    /// status, then update spec.operatingMode (Running/Suspended).
    pub async fn set_replicas(&self, env_id: &str, replicas: i64) -> anyhow::Result<()> {
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
        // Fence the exact incarnation without conditioning this one-field
        // change on unrelated controller-owned status/annotation updates.
        let patch = Patch::Json::<()>(serde_json::from_value(serde_json::json!([
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "add", "path": "/spec/operatingMode", "value": mode}
        ]))?);
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
        let (_, sandbox) = self
            .read_owned_claim_sandbox(claim_opts, expected_claim_name, expected_claim_uid)
            .await?;
        self.set_workspace_operating_mode(
            claim_opts,
            expected_claim_name,
            expected_claim_uid,
            &sandbox,
            0,
        )
        .await
    }

    /// Change operating mode on the exact Claim-owned suspended incarnation.
    /// Unlike generic scale operations this completes a captured suspension /
    /// bootstrap sequence, so concurrent spec changes must reject publication.
    /// The caller owns the environment mutation fence and old/all-Pod absence.
    pub async fn set_replicas_for_identity(
        &self,
        claim_opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
        replicas: i64,
    ) -> anyhow::Result<()> {
        let (_, sandbox) = self
            .read_owned_claim_sandbox(claim_opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&sandbox)?;
        self.set_workspace_operating_mode(
            claim_opts,
            expected_claim_name,
            expected_claim_uid,
            &sandbox,
            replicas,
        )
        .await
    }

    /// The object is supplied only by the exact owned-chain readers above.
    /// Keep one UID/version-fenced writer for initial suspend and pinned resume.
    async fn set_workspace_operating_mode(
        &self,
        claim_opts: &ClaimOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        sandbox: &DynamicObject,
        replicas: i64,
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
        operations.push(serde_json::json!({"op":"add","path":"/spec/operatingMode","value":mode}));
        let patch = Patch::Json::<()>(serde_json::from_value(Value::Array(operations))?);
        let updated = self
            .sandboxes()
            .patch(name, &PatchParams::default(), &patch)
            .await
            .map_err(|_| anyhow::anyhow!("workspace operating mode update was not admitted"))?;
        anyhow::ensure!(
            runtime_object_uid(&updated.metadata, &self.namespace, name)? == uid,
            "workspace Sandbox was replaced during operating mode publication"
        );
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

    pub async fn ensure_gateway_stack(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        if opts.environment_id.trim().is_empty() {
            anyhow::bail!("ensure gateway stack: environment_id is required");
        }
        let opts = self.resolve_gateway_direct_udp_service_opts(opts).await?;
        self.ensure_credential_bootstrap(&opts).await?;
        self.ensure_gateway_host_key_secret(&opts).await?;
        self.ensure_dynamic(
            self.services(),
            &workspace_daemon_service_name(&opts.environment_id),
            render_workspace_daemon_service(&self.namespace, &opts),
        )
        .await?;
        self.ensure_dynamic(
            self.services(),
            &super::template::gateway_service_name(&opts.environment_id),
            render_gateway_service(&self.namespace, &opts),
        )
        .await?;
        if let Some(service) = render_gateway_direct_udp_service(&self.namespace, &opts) {
            self.ensure_dynamic(
                self.services(),
                &gateway_direct_udp_service_name(&opts.environment_id),
                service,
            )
            .await?;
        } else {
            delete_dynamic(
                &self.services(),
                &gateway_direct_udp_service_name(&opts.environment_id),
            )
            .await?;
        }
        self.ensure_dynamic(
            self.deployments(),
            &gateway_workload_name(&opts.environment_id),
            render_gateway_deployment(&self.namespace, &opts),
        )
        .await?;
        if opts.network_policy_management.is_empty() || opts.network_policy_management == "Managed"
        {
            self.ensure_dynamic(
                self.network_policies(),
                &workspace_daemon_network_policy_name(&opts.environment_id),
                render_workspace_daemon_network_policy(&self.namespace, &opts),
            )
            .await?;
            self.ensure_dynamic(
                self.network_policies(),
                &gateway_network_policy_name(&opts.environment_id),
                render_gateway_network_policy(&self.namespace, &opts),
            )
            .await?;
        }
        Ok(())
    }

    pub async fn ensure_gateway_host_key_secret(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        if opts.environment_id.trim().is_empty() {
            anyhow::bail!("ensure gateway host key secret: environment_id is required");
        }
        let name = gateway_host_key_secret_name(&opts.environment_id);
        let secrets = self.secrets();
        let host_key = generate_gateway_host_key_openssh()?;
        let obj: DynamicObject = serde_json::from_value(render_gateway_host_key_secret(
            &self.namespace,
            opts,
            &host_key,
        ))?;
        match secrets.create(&PostParams::default(), &obj).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 409 => Ok(()),
            Err(e) => Err(anyhow::anyhow!(
                "create gateway host key Secret {name}: {e}"
            )),
        }
    }

    pub async fn delete_gateway_stack(&self, env_id: &str) -> anyhow::Result<()> {
        let services = self.services();
        delete_dynamic(&services, &workspace_daemon_service_name(env_id)).await?;
        delete_dynamic(&services, &super::template::gateway_service_name(env_id)).await?;
        delete_dynamic(&services, &gateway_direct_udp_service_name(env_id)).await?;
        delete_dynamic(&self.deployments(), &gateway_workload_name(env_id)).await?;
        delete_dynamic(
            &self.network_policies(),
            &workspace_daemon_network_policy_name(env_id),
        )
        .await?;
        delete_dynamic(
            &self.network_policies(),
            &gateway_network_policy_name(env_id),
        )
        .await?;
        Ok(())
    }

    pub async fn delete_gateway_host_key_secret(&self, env_id: &str) -> anyhow::Result<()> {
        delete_dynamic(&self.secrets(), &gateway_host_key_secret_name(env_id)).await
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
        self.delete_gateway_stack(env_id).await?;
        self.delete_credential_bootstrap(env_id, timeout).await?;
        delete_dynamic_until_absent(
            &self.secrets(),
            &gateway_host_key_secret_name(env_id),
            timeout,
        )
        .await?;
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
                "Certificate",
                self.credential_certificates(),
                super::template::credential_gateway_certificate_name(env_id),
            ),
            (
                "ConfigMap",
                self.credential_config_maps(),
                super::template::credential_codex_config_name(env_id),
            ),
            (
                "Deployment",
                self.deployments(),
                gateway_workload_name(env_id),
            ),
            (
                "Service",
                self.services(),
                workspace_daemon_service_name(env_id),
            ),
            (
                "Service",
                self.services(),
                super::template::gateway_service_name(env_id),
            ),
            (
                "Service",
                self.services(),
                gateway_direct_udp_service_name(env_id),
            ),
            (
                "NetworkPolicy",
                self.network_policies(),
                workspace_daemon_network_policy_name(env_id),
            ),
            (
                "NetworkPolicy",
                self.network_policies(),
                gateway_network_policy_name(env_id),
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

    /// Prove that Kubernetes and Longhorn have both forgotten the workspace
    /// volume before orchestration is allowed to delete either key copy. The
    /// Longhorn KubernetesStatus fields retain the PVC identity while volume
    /// deletion is in progress, including after the PVC itself disappears.
    async fn confidential_storage_residue(
        &self,
        sandbox_names: &BTreeSet<String>,
    ) -> anyhow::Result<Vec<String>> {
        let pvc_names: BTreeSet<String> = sandbox_names
            .iter()
            .map(|sandbox_name| format!("workspace-{sandbox_name}"))
            .collect();
        let mut resources = Vec::new();
        let mut volume_handles = BTreeSet::new();

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
            if let Some(handle) = spec
                .csi
                .as_ref()
                .map(|source| source.volume_handle.as_str())
            {
                volume_handles.insert(handle.to_string());
            }
            if let Some(name) = volume.metadata.name {
                resources.push(format!("PersistentVolume/{name}"));
            }
        }

        let longhorn_volumes = self
            .longhorn_volumes()
            .list(&ListParams::default())
            .await
            .map_err(|error| anyhow::anyhow!("list Longhorn volumes: {error}"))?;
        for volume in longhorn_volumes.items {
            let name = volume.metadata.name.unwrap_or_default();
            let kubernetes_status = volume.data.pointer("/status/kubernetesStatus");
            let pvc_matches = kubernetes_status.is_some_and(|status| {
                status.get("namespace").and_then(Value::as_str) == Some(self.namespace.as_str())
                    && status
                        .get("pvcName")
                        .and_then(Value::as_str)
                        .is_some_and(|pvc_name| pvc_names.contains(pvc_name))
            });
            if pvc_matches || volume_handles.contains(&name) {
                resources.push(format!("LonghornVolume/{name}"));
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

    async fn resolve_gateway_direct_udp_service_opts(
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
            opts.direct_udp_lb_port =
                i64::from(self.allocate_gateway_direct_udp_port(&opts).await?);
        } else {
            validate_gateway_direct_udp_port(opts.direct_udp_lb_port)
                .map_err(|e| anyhow::anyhow!("direct UDP LoadBalancer port: {e}"))?;
        }
        Ok(opts)
    }

    async fn allocate_gateway_direct_udp_port(&self, opts: &TemplateOpts) -> anyhow::Result<u16> {
        let services = self.services();
        let name = gateway_direct_udp_service_name(&opts.environment_id);
        match services.get(&name).await {
            Ok(existing) => {
                if let Some(port) = gateway_direct_udp_service_port(&existing) {
                    return Ok(port);
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => return Err(anyhow::anyhow!("get direct UDP Service {name}: {e}")),
        }

        let (start, end) = gateway_direct_udp_port_range(opts)?;
        let used = self.used_gateway_direct_udp_ports(opts).await?;
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

    async fn used_gateway_direct_udp_ports(
        &self,
        opts: &TemplateOpts,
    ) -> anyhow::Result<BTreeSet<u16>> {
        let ip = opts.direct_udp_lb_ip.trim();
        let list = self
            .services()
            .list(&ListParams::default().labels("codewire.sh/runtime-network=direct-udp"))
            .await
            .map_err(|e| anyhow::anyhow!("list direct UDP Services: {e}"))?;
        Ok(list
            .items
            .iter()
            .filter(|service| gateway_direct_udp_service_ip_matches(service, ip))
            .filter_map(gateway_direct_udp_service_port)
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
    pub async fn wait_for_ready(&self, env_id: &str, timeout: Duration) -> anyhow::Result<()> {
        self.wait_for_ready_with_fallback(env_id, timeout, CLAIM_READY_FALLBACK_POLL)
            .await
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
                && let Some(err) = self.pod_terminal_failure(&name).await
            {
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
    async fn pod_terminal_failure(&self, claim: &str) -> Option<anyhow::Error> {
        // No Claim-name fallback: an unbound Claim has no Pod to inspect yet.
        let sandbox_name = match self.claims.get(claim).await {
            Ok(c) => claim_bound_sandbox_name(&c)?.to_string(),
            Err(_) => return None,
        };
        let pod_name = match self.sandboxes().get(&sandbox_name).await {
            Ok(sandbox) => sandbox_pod_name(&sandbox, &sandbox_name).to_owned(),
            Err(_) => sandbox_name.clone(),
        };
        let pod = match self.pods().get(&pod_name).await {
            Ok(p) => p,
            Err(_) => return None, // pod not scheduled yet
        };
        let (reason, message) = terminal_pod_failure_reason(&pod)?;
        Some(anyhow::anyhow!(
            "pod {}: {reason}: {message}",
            pod.metadata.name.as_deref().unwrap_or(&pod_name)
        ))
    }
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

fn generate_gateway_host_key_openssh() -> anyhow::Result<String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("generate gateway host key: {e}"))?;
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
        .to_openssh(LineEnding::LF)
        .map(|key| key.to_string())
        .map_err(|e| anyhow::anyhow!("encode gateway host key: {e}"))
}

fn gateway_direct_udp_port_range(opts: &TemplateOpts) -> anyhow::Result<(u16, u16)> {
    let start = if opts.direct_udp_lb_port_start == 0 {
        DEFAULT_DIRECT_UDP_LB_PORT_START
    } else {
        validate_gateway_direct_udp_port(opts.direct_udp_lb_port_start)
            .map_err(|e| anyhow::anyhow!("direct UDP LoadBalancer port start: {e}"))?
    };
    let end = if opts.direct_udp_lb_port_end == 0 {
        DEFAULT_DIRECT_UDP_LB_PORT_END
    } else {
        validate_gateway_direct_udp_port(opts.direct_udp_lb_port_end)
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

fn validate_gateway_direct_udp_port(port: i64) -> Result<u16, &'static str> {
    match u16::try_from(port) {
        Ok(port) if port > 0 => Ok(port),
        _ => Err("must be a UDP port from 1 to 65535"),
    }
}

fn gateway_direct_udp_service_port(service: &DynamicObject) -> Option<u16> {
    service
        .data
        .pointer("/spec/ports")
        .and_then(Value::as_array)?
        .iter()
        .find(|port| {
            port["protocol"].as_str() == Some("UDP")
                && port["targetPort"].as_i64() == Some(super::template::GATEWAY_TAILNET_UDP_PORT)
        })
        .and_then(|port| port["port"].as_i64())
        .and_then(|port| u16::try_from(port).ok())
}

fn gateway_direct_udp_service_ip_matches(service: &DynamicObject, ip: &str) -> bool {
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

async fn delete_dynamic_until_absent(
    api: &Api<DynamicObject>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match api.delete(name, &DeleteParams::default()).await {
            Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
            Ok(_) => {}
            Err(error) => return Err(anyhow::anyhow!("delete {name}: {error}")),
        }
        if tokio::time::Instant::now() + Duration::from_millis(250) >= deadline {
            anyhow::bail!("timeout waiting for {name} to be deleted");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn dynamic_exists(api: &Api<DynamicObject>, name: &str) -> anyhow::Result<bool> {
    match api.get(name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(false),
        Err(error) => Err(anyhow::anyhow!("get {name}: {error}")),
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
    let mut objects = api
        .list(&ListParams::default().labels(&format!("{LABEL_ENV_ID}={env_id}")))
        .await
        .map_err(|error| anyhow::anyhow!("list owned {kind} for {env_id}: {error}"))?
        .items;
    if let Some(name) = name_hint
        && !objects
            .iter()
            .any(|object| object.metadata.name.as_deref() == Some(name))
    {
        match api.get(name).await {
            Ok(object) => objects.push(object),
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(error) => return Err(anyhow::anyhow!("get hinted {kind}: {error}")),
        }
    }
    objects
        .into_iter()
        .map(|object| {
            anyhow::ensure!(
                object
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(LABEL_ENV_ID))
                    .is_some_and(|value| value == env_id),
                "listed {kind} does not belong to the environment"
            );
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
    pub async fn ensure_sandbox_template(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        opts.validate_confidential_storage_manifest()?;
        self.ensure_credential_bootstrap(opts).await?;
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

    /// Mirrors `ClientBackend.ProbeEnvironment`.
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
        let sandbox_name = match self.claims.get(&claim).await {
            Ok(c) => claim_bound_sandbox_name(&c).unwrap_or_default().to_string(),
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
            pod_lookup = sandbox_pod_name(&sb, &sandbox_name).to_owned();
        }

        if !pod_lookup.is_empty()
            && let Ok(pod) = self.pods().get(&pod_lookup).await
        {
            result.pod_exists = true;
            result.pod_timeline = PodStartTimeline::from_pod(&pod);
            result.pod_uid = pod.metadata.uid.clone().unwrap_or_default();
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
        let message = status.message.clone().unwrap_or_default();
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

fn workspace_resources_match(pod: &Pod, cpu: &str, memory: &str) -> bool {
    let Some(resources) = pod
        .status
        .as_ref()
        .and_then(|status| status.container_statuses.as_deref())
        .and_then(|statuses| statuses.iter().find(|status| status.name == "workspace"))
        .and_then(|status| status.resources.as_ref())
    else {
        return false;
    };
    [resources.requests.as_ref(), resources.limits.as_ref()]
        .into_iter()
        .all(|class| {
            class.is_some_and(|values| {
                values
                    .get("cpu")
                    .is_some_and(|value| quantities_equal(&value.0, cpu))
                    && values
                        .get("memory")
                        .is_some_and(|value| quantities_equal(&value.0, memory))
            })
        })
}

/// Compare Kubernetes quantities by value rather than serialized form.
///
/// The kubelet canonicalizes equivalent requests (for example `3000m` to `3`
/// and `5120Mi` to `5Gi`). Resource convergence must accept that formatting
/// change without accepting a different value or a malformed observation.
fn quantities_equal(left: &str, right: &str) -> bool {
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

fn parse_quantity_ratio(quantity: &str) -> Option<(i128, i128)> {
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

fn terminal_pod_resize_failure(pod: &Pod) -> Option<String> {
    pod.status
        .as_ref()?
        .conditions
        .as_deref()?
        .iter()
        .find(|condition| {
            condition.type_ == "PodResizePending"
                && condition.status == "True"
                && condition.reason.as_deref() == Some("Infeasible")
        })
        .map(|condition| {
            condition
                .message
                .clone()
                .filter(|message| !message.trim().is_empty())
                .unwrap_or_else(|| {
                    "Kubernetes reported the requested resources as infeasible".into()
                })
        })
}

fn set_workspace_resources(data: &mut Value, cpu: &str, memory: &str) -> anyhow::Result<()> {
    let containers = data
        .pointer_mut("/spec/podTemplate/spec/containers")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("runtime object has no PodTemplate containers"))?;
    let workspace = containers
        .iter_mut()
        .find(|container| container.get("name").and_then(Value::as_str) == Some("workspace"))
        .ok_or_else(|| anyhow::anyhow!("runtime object has no workspace container"))?;
    for class in ["requests", "limits"] {
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
        class_values.insert("cpu".to_string(), Value::String(cpu.to_string()));
        class_values.insert("memory".to_string(), Value::String(memory.to_string()));
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

fn rendered_runtime_recovery_patch(
    namespace: &str,
    opts: &TemplateOpts,
) -> anyhow::Result<(String, Value)> {
    opts.validate_confidential_storage_manifest()?;
    let rendered = render_sandbox_template(namespace, opts);
    let kernel_params = rendered
        .pointer("/spec/podTemplate/metadata/annotations")
        .and_then(Value::as_object)
        .and_then(|annotations| annotations.get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("rendered runtime has no confidential kernel parameters"))?;
    let fs_group_change_policy = rendered
        .pointer("/spec/podTemplate/spec/securityContext/fsGroupChangePolicy")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("rendered runtime has no fsGroup change policy"))?;

    let mut annotations = serde_json::Map::new();
    annotations.insert(
        KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY.to_string(),
        Value::String(kernel_params.clone()),
    );
    let patch = serde_json::json!({
        "spec": {
            "podTemplate": {
                "metadata": {
                    "annotations": annotations,
                },
                "spec": {
                    "securityContext": {
                        "fsGroupChangePolicy": fs_group_change_policy,
                    },
                },
            },
        },
    });
    Ok((kernel_params, patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, Response, StatusCode, header};
    use russh::keys::ssh_key::Algorithm;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

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
                client.set_replicas("env-test", replicas),
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
                tokio::time::timeout(Duration::from_secs(2), client.set_replicas("env-test", 1))
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
                tokio::time::timeout(Duration::from_secs(2), client.set_replicas("env-test", 1))
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
                tokio::time::timeout(Duration::from_secs(2), client.set_replicas("env-test", 1))
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
        tokio::time::timeout(Duration::from_secs(2), client.set_replicas("env-test", 1))
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
                initialized_at: at("2026-09-29T10:00:36Z"),
                // The last container to start marks the Pod fully running.
                running_at: at("2026-09-29T10:00:38Z"),
                containers_ready_at: at("2026-09-29T10:00:40Z"),
            }
        );

        // A restart or a container not yet running leaves the mark unknown
        // rather than reporting a restart time as the Pod start.
        let restarted = PodStartTimeline::from_pod(&timeline_pod(1, started));
        assert_eq!(restarted.running_at, None);
        assert_eq!(restarted.initialized_at, at("2026-09-29T10:00:36Z"));
        let waiting = PodStartTimeline::from_pod(&timeline_pod(
            0,
            json!({"waiting": {"reason": "ContainerCreating"}}),
        ));
        assert_eq!(waiting.running_at, None);

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
        assert!(workspace_resources_match(&pod, "500m", "512Mi"));
        assert_eq!(
            terminal_pod_resize_failure(&pod).as_deref(),
            Some("node has insufficient memory")
        );
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

        assert!(workspace_resources_match(&pod, "3000m", "5120Mi"));
        assert!(!workspace_resources_match(&pod, "2999m", "5120Mi"));
        assert!(!workspace_resources_match(&pod, "3000m", "5119Mi"));
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

        assert!(!workspace_resources_match(&pod, "3000m", "5120Mi"));
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
        set_workspace_resources(&mut runtime, "1500m", "2048Mi").unwrap();
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
        let (client, _) = sandbox_client_with_secret_responses(storage_lookup_responses_for_class(
            CONFIDENTIAL_WORKSPACE_STORAGE_CLASS,
            true,
        ));
        let unchanged = client
            .require_workspace_storage_resize(&storage_anchor(Some(STORAGE_PVC_UID)), 10)
            .await
            .unwrap();
        assert_eq!(
            unchanged.storage_class_name,
            CONFIDENTIAL_WORKSPACE_STORAGE_CLASS
        );

        let (client, requests) = sandbox_client_with_secret_responses(
            storage_lookup_responses_for_class(CONFIDENTIAL_WORKSPACE_STORAGE_CLASS, true),
        );

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

    #[test]
    fn generated_gateway_host_key_is_openssh_ed25519() {
        let key = generate_gateway_host_key_openssh().unwrap();
        assert!(key.contains("BEGIN OPENSSH PRIVATE KEY"));
        let parsed = PrivateKey::from_openssh(&key).unwrap();
        assert_eq!(parsed.algorithm(), Algorithm::Ed25519);
    }

    #[tokio::test]
    async fn gateway_host_key_secret_fresh_create_is_one_post() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::CREATED,
            json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "cw-gateway-host-key-env-test",
                    "namespace": "dev-sandboxes",
                },
            }),
        )]);

        client
            .ensure_gateway_host_key_secret(&gateway_host_key_opts())
            .await
            .unwrap();

        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[(
                Method::POST,
                "/api/v1/namespaces/dev-sandboxes/secrets".to_string(),
            )]
        );
    }

    #[tokio::test]
    async fn gateway_host_key_secret_conflict_is_success_without_read() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::CONFLICT,
            kubernetes_status("AlreadyExists", 409),
        )]);

        client
            .ensure_gateway_host_key_secret(&gateway_host_key_opts())
            .await
            .unwrap();

        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[(
                Method::POST,
                "/api/v1/namespaces/dev-sandboxes/secrets".to_string(),
            )]
        );
    }

    #[tokio::test]
    async fn gateway_host_key_secret_non_conflict_failure_is_error_without_read() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::FORBIDDEN,
            kubernetes_status("Forbidden", 403),
        )]);

        let error = client
            .ensure_gateway_host_key_secret(&gateway_host_key_opts())
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("create gateway host key Secret cw-gateway-host-key-env-test")
        );
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[(
                Method::POST,
                "/api/v1/namespaces/dev-sandboxes/secrets".to_string(),
            )]
        );
    }

    #[tokio::test]
    async fn gateway_host_key_delete_retries_until_not_found_without_read() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![
            (
                StatusCode::OK,
                json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Success",
                    "code": 200,
                }),
            ),
            (StatusCode::NOT_FOUND, kubernetes_status("NotFound", 404)),
        ]);

        delete_dynamic_until_absent(
            &client.secrets(),
            "cw-gateway-host-key-env-test",
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[
                (
                    Method::DELETE,
                    "/api/v1/namespaces/dev-sandboxes/secrets/cw-gateway-host-key-env-test"
                        .to_string(),
                ),
                (
                    Method::DELETE,
                    "/api/v1/namespaces/dev-sandboxes/secrets/cw-gateway-host-key-env-test"
                        .to_string(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn gateway_host_key_delete_failure_is_retryable_without_false_absence() {
        let (client, requests) = sandbox_client_with_secret_responses(vec![(
            StatusCode::FORBIDDEN,
            kubernetes_status("Forbidden", 403),
        )]);

        let error = delete_dynamic_until_absent(
            &client.secrets(),
            "cw-gateway-host-key-env-test",
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("delete cw-gateway-host-key-env-test")
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
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
            gateway_token: "confidential-recovery-coordinate-token".into(),
            daemon_auth_token: "confidential-recovery-daemon-token".into(),
            runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_CONFIDENTIAL.into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url: "https://kbs.example.test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn sandbox_runtime_patch_changes_only_recovery_fields() {
        let (kernel_params, patch) =
            rendered_runtime_recovery_patch("dev-sandboxes", &confidential_runtime_opts()).unwrap();
        assert_eq!(
            patch
                .pointer("/spec/podTemplate/metadata/annotations")
                .and_then(Value::as_object)
                .and_then(|annotations| {
                    annotations.get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY)
                }),
            Some(&json!(kernel_params))
        );
        assert_eq!(
            patch
                .pointer("/spec/podTemplate/metadata/annotations")
                .and_then(Value::as_object)
                .map(serde_json::Map::len),
            Some(1)
        );
        assert_eq!(
            patch.pointer("/spec/podTemplate/spec/securityContext/fsGroupChangePolicy"),
            Some(&json!("OnRootMismatch"))
        );
        assert_eq!(
            patch
                .pointer("/spec/podTemplate/spec/securityContext")
                .and_then(Value::as_object)
                .map(serde_json::Map::len),
            Some(1)
        );
    }

    #[tokio::test]
    async fn terminal_recovery_refreshes_the_adopted_sandbox_before_uid_delete() {
        let opts = confidential_runtime_opts();
        let (expected_kernel_params, _) =
            rendered_runtime_recovery_patch("dev-sandboxes", &opts).unwrap();
        assert!(expected_kernel_params.contains("agent.log_vport=1025"));

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
                    "spec": {"podTemplate": {"metadata": {"annotations": {}}}}
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
                            KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY: expected_kernel_params,
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

        let kernel_params = client
            .reconcile_per_environment_runtime("env-test", "workspace-old", &opts)
            .await
            .unwrap();
        client
            .wait_for_workspace_pod_annotation(
                "workspace-old",
                "uid-old",
                KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY,
                &kernel_params,
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

    fn gateway_host_key_opts() -> TemplateOpts {
        TemplateOpts {
            environment_id: "env-test".into(),
            ..Default::default()
        }
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
                    "spec": {
                        "storageClassName": storage_class_name,
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "10Gi"}}
                    },
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
            gateway_token: "synthetic-coordinate-token".into(),
            daemon_auth_token: "synthetic-daemon-token".into(),
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
                "name": "cw-gateway-udp-env-test",
                "annotations": {
                    "lbipam.cilium.io/ips": "192.0.2.36",
                },
            },
            "spec": {
                "ports": [
                    { "name": "tailnet-udp", "protocol": "UDP", "port": 33123, "targetPort": 31000 },
                ],
            },
        }))
        .unwrap();

        assert!(gateway_direct_udp_service_ip_matches(
            &service,
            "192.0.2.36"
        ));
        assert_eq!(gateway_direct_udp_service_port(&service), Some(33123));
    }

    #[test]
    fn direct_udp_port_range_defaults_and_validates() {
        let opts = TemplateOpts::default();
        assert_eq!(
            gateway_direct_udp_port_range(&opts).unwrap(),
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
        assert_eq!(
            gateway_direct_udp_port_range(&opts).unwrap(),
            (33000, 33010)
        );

        let opts = TemplateOpts {
            direct_udp_lb_port_start: 40000,
            direct_udp_lb_port_end: 33000,
            ..Default::default()
        };
        assert!(gateway_direct_udp_port_range(&opts).is_err());
    }

    #[test]
    fn service_replace_preserves_allocated_cluster_ips() {
        let mut rendered: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "cw-gateway-svc-env-test" },
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
            "metadata": { "name": "cw-gateway-svc-env-test" },
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
}
