//! Warm-pool shape keys and identity-free pool templates (Program #2238 C1).
//!
//! A warm pool is one shared SandboxTemplate and one SandboxWarmPool per exact
//! workspace shape. Kata VMs are sized at boot (A6), so a member serves only a
//! claim of exactly its CPU, memory and disk. Each pool renders from its shape
//! and this process's cluster configuration alone, through the B2
//! identity-free renderer: no environment row, identity, credential or secret
//! reaches it (design invariant 1, §13). Its template spec equals the
//! per-environment identity-free rendering of the same shape, so a cold start
//! is a pool miss (invariant 10).
//!
//! Names are `cw-pool-<cpu>m-<mem>mi-<disk>gi-<h8>`. `h8` hashes the storage
//! class and both namespaces (the sandbox namespace that holds the pool and the
//! orchestration namespace its members bind through), so a different placement
//! is a different pool. The prefix is disjoint from the per-environment
//! `shadow-pool-` objects and from the `sandbox-warmpool-` objects that
//! `retire_legacy_shared_warm_pools` deletes.
//!
//! `codewire.sh/pool-revision` is the SHA-256 of the rendered template spec.
//! The spec names every image a member runs (workspace, DinD, and the support
//! image behind `codewire-bin`), and outside diagnostic runtimes each must be
//! digest-pinned, so a new digest is a new revision. Replicas are not part of
//! the revision: resizing a pool never rotates its members.
//!
//! Which shapes are kept warm, and how many unclaimed members each holds, is
//! `SANDBOX_WARM_POOL_SHAPES` ([`parse_warm_pool_shapes`]). Empty or unset
//! configures no pool, and then nothing in Codewire creates, routes to or
//! reconciles one: the leader reconciler (C2, `worker::warm_pool`) returns
//! before it builds a Kubernetes client. Confidential environments are never
//! pooled.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::template::{RUNTIME_PROFILE_CONFIDENTIAL, TemplateOpts, render_sandbox_template};
use super::{EXTENSIONS_API_VERSION, LABEL_TYPE};

/// Every warm pool and its template carry this prefix, and nothing else does.
pub const WARM_POOL_NAME_PREFIX: &str = "cw-pool-";
/// The SHA-256 of the pool template's rendered spec, on both objects.
pub const POOL_REVISION_ANNOTATION: &str = "codewire.sh/pool-revision";
/// `codewire.sh/type` of a warm pool and its template.
pub const WARM_POOL_TYPE: &str = "workspace-pool";
const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
/// Domain separation for the placement hash; bump it only with a migration of
/// existing pool names.
const PLACEMENT_HASH_DOMAIN: &str = "codewire.sh/warm-pool/placement/v1";
const PLACEMENT_HASH_HEX: usize = 8;
/// The agent-sandbox fork labels each member Sandbox, and its Pod, with the
/// FNV-1a name hash of the pool that created it. Adoption removes it.
pub const MEMBER_POOL_LABEL: &str = "agents.x-k8s.io/warm-pool-sandbox";
/// The fork's launch-type label: `warm` once a claim adopted a pool member.
pub const LAUNCH_TYPE_LABEL: &str = "agents.x-k8s.io/launch-type";
pub const LAUNCH_TYPE_WARM: &str = "warm";
/// The fork's template-reference label: the FNV-1a hash of the template a
/// Sandbox was built from. It survives adoption.
pub const TEMPLATE_REF_HASH_LABEL: &str = "agents.x-k8s.io/sandbox-template-ref-hash";
/// The warm-pool configuration key.
pub const WARM_POOL_SHAPES_ENV: &str = "SANDBOX_WARM_POOL_SHAPES";
/// The most unclaimed members one shape may hold, whatever the node cap
/// allows. The admission policy pins the same bound.
pub const MAX_POOL_MEMBERS: i32 = 16;

/// One configured pool: an exact shape and its unclaimed member count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfiguredShape {
    pub shape: WorkspaceShape,
    pub members: i32,
}

/// Parse `SANDBOX_WARM_POOL_SHAPES`: comma-separated
/// `<cpu>m/<memory>Mi/<disk>Gi=<members>` entries, for example
/// `1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=2`. Dimensions are positive
/// decimal integers without leading zeros, exactly the units a workspace is
/// sized in; members are 0 to [`MAX_POOL_MEMBERS`]. A shape may appear once.
/// Empty or whitespace configures no pool.
pub fn parse_warm_pool_shapes(value: &str) -> anyhow::Result<Vec<ConfiguredShape>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut configured: Vec<ConfiguredShape> = Vec::new();
    for (index, entry) in value.split(',').enumerate() {
        let entry = entry.trim();
        let parsed = parse_shape_entry(entry).ok_or_else(|| {
            anyhow::anyhow!(
                "{WARM_POOL_SHAPES_ENV} entry {} must be <cpu>m/<memory>Mi/<disk>Gi=<members> \
                 with members 0..={MAX_POOL_MEMBERS}",
                index + 1
            )
        })?;
        anyhow::ensure!(
            !configured.iter().any(|seen| seen.shape == parsed.shape),
            "{WARM_POOL_SHAPES_ENV} entry {} repeats an earlier shape",
            index + 1
        );
        configured.push(parsed);
    }
    Ok(configured)
}

fn parse_shape_entry(entry: &str) -> Option<ConfiguredShape> {
    let (shape, members) = entry.split_once('=')?;
    let mut dimensions = shape.split('/');
    let cpu = positive_decimal(dimensions.next()?.strip_suffix('m')?)?;
    let memory = positive_decimal(dimensions.next()?.strip_suffix("Mi")?)?;
    let disk = positive_decimal(dimensions.next()?.strip_suffix("Gi")?)?;
    if dimensions.next().is_some() {
        return None;
    }
    let members = match members {
        "0" => 0,
        other => i32::try_from(positive_decimal(other)?).ok()?,
    };
    (members <= MAX_POOL_MEMBERS).then_some(ConfiguredShape {
        shape: WorkspaceShape {
            cpu_millicores: cpu,
            memory_mib: memory,
            disk_gib: disk,
        },
        members,
    })
}

fn positive_decimal(text: &str) -> Option<i64> {
    (!text.is_empty() && !text.starts_with('0') && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse::<i64>().ok())
        .flatten()
        .filter(|value| *value <= i64::from(i32::MAX))
}

/// The bounded metric label of a shape: `<cpu>m-<mem>mi-<disk>gi`. It names
/// configuration, never an environment.
pub fn shape_label(shape: WorkspaceShape) -> String {
    let WorkspaceShape {
        cpu_millicores,
        memory_mib,
        disk_gib,
    } = shape;
    format!("{cpu_millicores}m-{memory_mib}mi-{disk_gib}gi")
}

/// The shape a warm pool name encodes, when `name` is one.
pub fn warm_pool_name_shape(name: &str) -> Option<WorkspaceShape> {
    if !is_warm_pool_name(name) {
        return None;
    }
    let mut fields = name.strip_prefix(WARM_POOL_NAME_PREFIX)?.split('-');
    let cpu = fields.next()?.strip_suffix('m')?.parse().ok()?;
    let memory = fields.next()?.strip_suffix("mi")?.parse().ok()?;
    let disk = fields.next()?.strip_suffix("gi")?.parse().ok()?;
    Some(WorkspaceShape {
        cpu_millicores: cpu,
        memory_mib: memory,
        disk_gib: disk,
    })
}

/// The exact resources a workspace renders with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceShape {
    pub cpu_millicores: i64,
    pub memory_mib: i64,
    pub disk_gib: i64,
}

impl WorkspaceShape {
    /// The shape a template rendering uses.
    pub fn of(opts: &TemplateOpts) -> Self {
        Self {
            cpu_millicores: opts.cpu_millicores,
            memory_mib: opts.memory_mib,
            disk_gib: opts.disk_gib,
        }
    }
}

/// One pool's identity: its exact shape and its placement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarmPoolKey {
    shape: WorkspaceShape,
    storage_class: String,
    sandbox_namespace: String,
    server_namespace: String,
}

impl WarmPoolKey {
    /// A pool member pre-provisions its volume, so every dimension, the disk
    /// included, is a positive environment-sized value.
    pub fn new(
        shape: WorkspaceShape,
        storage_class: &str,
        sandbox_namespace: &str,
        server_namespace: &str,
    ) -> anyhow::Result<Self> {
        for (dimension, value) in [
            ("CPU millicores", shape.cpu_millicores),
            ("memory MiB", shape.memory_mib),
            ("disk GiB", shape.disk_gib),
        ] {
            anyhow::ensure!(
                (1..=i64::from(i32::MAX)).contains(&value),
                "warm pool {dimension} must be positive, got {value}"
            );
        }
        for (field, value) in [
            ("storage class", storage_class),
            ("sandbox namespace", sandbox_namespace),
            ("orchestration namespace", server_namespace),
        ] {
            anyhow::ensure!(
                kubernetes_name(value),
                "warm pool {field} must be a Kubernetes name"
            );
        }
        Ok(Self {
            shape,
            storage_class: storage_class.to_owned(),
            sandbox_namespace: sandbox_namespace.to_owned(),
            server_namespace: server_namespace.to_owned(),
        })
    }

    pub fn shape(&self) -> WorkspaceShape {
        self.shape
    }

    /// `cw-pool-<cpu>m-<mem>mi-<disk>gi-<h8>`, at most 54 characters.
    pub fn name(&self) -> String {
        let WorkspaceShape {
            cpu_millicores,
            memory_mib,
            disk_gib,
        } = self.shape;
        format!(
            "{WARM_POOL_NAME_PREFIX}{cpu_millicores}m-{memory_mib}mi-{disk_gib}gi-{}",
            self.placement_hash()
        )
    }

    fn placement_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [
            PLACEMENT_HASH_DOMAIN,
            self.storage_class.as_str(),
            self.sandbox_namespace.as_str(),
            self.server_namespace.as_str(),
        ] {
            hasher.update(part.as_bytes());
            hasher.update([0]);
        }
        hex(&hasher.finalize())[..PLACEMENT_HASH_HEX].to_owned()
    }
}

/// Whether `name` is exactly a warm pool name: the prefix, three positive
/// decimal dimensions without leading zeros, and an eight-digit lowercase hex
/// placement hash.
pub fn is_warm_pool_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(WARM_POOL_NAME_PREFIX) else {
        return false;
    };
    let fields: Vec<&str> = rest.split('-').collect();
    let [cpu, memory, disk, hash] = fields.as_slice() else {
        return false;
    };
    let dimension = |field: &str, unit: &str| {
        field.strip_suffix(unit).is_some_and(|number| {
            !number.is_empty()
                && !number.starts_with('0')
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && number
                    .parse::<i64>()
                    .is_ok_and(|value| value <= i64::from(i32::MAX))
        })
    };
    dimension(cpu, "m")
        && dimension(memory, "mi")
        && dimension(disk, "gi")
        && hash.len() == PLACEMENT_HASH_HEX
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The pool revision of a rendered SandboxTemplate spec: the SHA-256 of its
/// serialization without the revision marker ([`POOL_REVISION_ENV`]), so a
/// marked pool spec and the unmarked per-environment rendering of the same
/// shape share one revision. serde_json maps are sorted, so equal specs hash
/// equally.
pub fn pool_revision(template_spec: &Value) -> String {
    hex(&Sha256::digest(
        serde_json::to_vec(&without_revision_marker(template_spec))
            .expect("rendered template spec serializes"),
    ))
}

/// Program #2238 C3 review M1: every pool member's workspace container
/// carries its pool revision in its environment. A Pod's spec is immutable,
/// so the bind reads the revision the Pod booted with from the Pod itself;
/// adoption rewrites only the Sandbox's Pod-template metadata.
pub const POOL_REVISION_ENV: &str = "CODEWIRE_WORKSPACE_POOL_REVISION";

/// `spec` (a SandboxTemplate or Sandbox spec) without the revision marker.
pub fn without_revision_marker(spec: &Value) -> Value {
    let mut spec = spec.clone();
    if let Some(containers) = spec
        .pointer_mut("/podTemplate/spec/containers")
        .and_then(Value::as_array_mut)
    {
        for container in containers {
            if let Some(env) = container.get_mut("env").and_then(Value::as_array_mut) {
                env.retain(|entry| entry["name"] != POOL_REVISION_ENV);
            }
        }
    }
    spec
}

/// The pool revision a Pod spec's workspace container booted with, when it
/// carries exactly one literal marker.
pub fn pod_spec_pool_revision(pod_spec: &Value) -> Option<&str> {
    let workspace = pod_spec["containers"]
        .as_array()?
        .iter()
        .find(|container| container["name"] == "workspace")?;
    let mut markers = workspace["env"]
        .as_array()?
        .iter()
        .filter(|entry| entry["name"] == POOL_REVISION_ENV);
    match (markers.next(), markers.next()) {
        (Some(marker), None) if marker.get("valueFrom").is_none() => marker["value"].as_str(),
        _ => None,
    }
}

/// One rendered pool: the shared SandboxTemplate and its SandboxWarmPool.
#[derive(Clone, Debug, PartialEq)]
pub struct WarmPoolObjects {
    pub key: WarmPoolKey,
    pub name: String,
    pub revision: String,
    pub template: Value,
    pub pool: Value,
}

/// Render one pool from identity-free shape inputs.
///
/// `opts` must carry no environment identity: no name, environment or
/// organization, operation generation, token, projection digest, managed
/// client selection or confidential storage manifest. They must select the
/// identity-free (binding) workspace and a non-confidential runtime. Unless
/// `allow_unpinned_images` (diagnostic runtimes only), every image the Pod
/// names must be digest-pinned, so the revision covers each digest.
pub fn render_warm_pool(
    namespace: &str,
    opts: &TemplateOpts,
    replicas: i32,
    allow_unpinned_images: bool,
) -> anyhow::Result<WarmPoolObjects> {
    validate_pool_template_opts(opts)?;
    anyhow::ensure!(replicas >= 0, "warm pool replicas must not be negative");
    let key = WarmPoolKey::new(
        WorkspaceShape::of(opts),
        opts.effective_workspace_storage_class(),
        namespace,
        &opts.server_namespace,
    )?;
    let name = key.name();
    let named = TemplateOpts {
        name: name.clone(),
        ..opts.clone()
    };
    let mut template = render_sandbox_template(namespace, &named);
    if !allow_unpinned_images {
        for image in pod_template_images(&template["spec"]["podTemplate"]["spec"]) {
            anyhow::ensure!(
                digest_pinned(image),
                "warm pool image {image:?} is not digest-pinned"
            );
        }
    }
    let revision = pool_revision(&template["spec"]);
    let workspace = template["spec"]["podTemplate"]["spec"]["containers"]
        .as_array_mut()
        .and_then(|containers| {
            containers
                .iter_mut()
                .find(|container| container["name"] == "workspace")
        })
        .ok_or_else(|| anyhow::anyhow!("warm pool rendering has no workspace container"))?;
    match workspace.get_mut("env").and_then(Value::as_array_mut) {
        Some(env) => env.push(json!({ "name": POOL_REVISION_ENV, "value": revision })),
        None => workspace["env"] = json!([{ "name": POOL_REVISION_ENV, "value": revision }]),
    }
    let metadata = &mut template["metadata"];
    metadata["labels"] = pool_labels();
    metadata["annotations"] = json!({ POOL_REVISION_ANNOTATION: revision });
    let pool = json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxWarmPool",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": pool_labels(),
            "annotations": { POOL_REVISION_ANNOTATION: revision },
        },
        "spec": {
            "replicas": replicas,
            "sandboxTemplateRef": { "name": name },
            // A changed template replaces every unclaimed member at once, so
            // the reconciler (C2) may change it only once the image cache is
            // warm.
            "updateStrategy": { "type": "Recreate" },
        },
    });
    Ok(WarmPoolObjects {
        key,
        name,
        revision,
        template,
        pool,
    })
}

/// Whether `live` is the stored form of `expected`, a rendered Pod spec
/// fragment. The API server and the agent-sandbox controller store a spec
/// differently from its rendering without changing it: the controller copies
/// a template through typed Go structs, which canonicalize quantities
/// (`1000m` as `1`, `4096Mi` as `4Gi`) and drop empty `omitempty` fields (an
/// empty env value), and the CRD may add its scalar defaults (an empty name,
/// `false`, protocol `TCP`). Anything else that is extra, missing or
/// different refuses with its JSON path.
pub fn spec_equivalent(expected: &Value, live: &Value, path: &str) -> Result<(), String> {
    match (expected, live) {
        (Value::Object(expected), Value::Object(live)) => {
            for (key, value) in expected {
                let at = format!("{path}/{key}");
                match live.get(key) {
                    Some(live) => spec_equivalent(value, live, &at)?,
                    None if omitted_when_empty(value) => {}
                    None => return Err(at),
                }
            }
            for (key, value) in live {
                if !expected.contains_key(key) && !crd_default(key, value) {
                    return Err(format!("{path}/{key}"));
                }
            }
            Ok(())
        }
        (Value::Array(expected), Value::Array(live)) if expected.len() == live.len() => expected
            .iter()
            .zip(live)
            .enumerate()
            .try_for_each(|(index, (expected, live))| {
                spec_equivalent(expected, live, &format!("{path}/{index}"))
            }),
        (Value::String(expected), Value::String(live))
            if quantity_path(path) && super::client::quantities_equal(expected, live) =>
        {
            Ok(())
        }
        (expected, live) if expected == live => Ok(()),
        _ => Err(path.to_owned()),
    }
}

/// A rendered value a Go `omitempty` field drops. A rendered `false` is never
/// one: Kubernetes keeps security-relevant booleans such as
/// `automountServiceAccountToken` as pointers, so absent means the API
/// default, which may be `true` (review L1).
fn omitted_when_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

/// A value the API server may add with its CRD default.
fn crd_default(key: &str, value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty() || (key == "protocol" && text == "TCP"),
        Value::Bool(flag) => !flag,
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
        Value::Number(_) => false,
    }
}

/// Resource quantities, which the controller may store canonicalized.
fn quantity_path(path: &str) -> bool {
    path.contains("/resources/requests/")
        || path.contains("/resources/limits/")
        || path.ends_with("/sizeLimit")
}

/// Refuse shape inputs that carry any environment state, a legacy identity,
/// or the confidential runtime.
pub fn validate_pool_template_opts(opts: &TemplateOpts) -> anyhow::Result<()> {
    anyhow::ensure!(
        opts.runtime_profile_spec().profile != RUNTIME_PROFILE_CONFIDENTIAL,
        "confidential workspaces are never pooled"
    );
    anyhow::ensure!(
        opts.identity_free(),
        "warm pools render only identity-free workspaces"
    );
    let environment_state = [
        ("name", !opts.name.is_empty()),
        ("environment ID", !opts.environment_id.is_empty()),
        ("organization ID", !opts.organization_id.is_empty()),
        ("operation generation", opts.operation_generation != 0),
        ("gateway token", !opts.gateway_token.is_empty()),
        ("daemon token", !opts.daemon_auth_token.is_empty()),
        (
            "projection digest",
            opts.projection_selection_sha256.is_some(),
        ),
        (
            "managed credential clients",
            opts.managed_credential_clients != Default::default(),
        ),
        (
            "confidential storage manifest",
            !opts.confidential_storage_manifest_uri.is_empty(),
        ),
    ];
    for (field, present) in environment_state {
        anyhow::ensure!(!present, "warm pool inputs carry an environment {field}");
    }
    Ok(())
}

fn pool_labels() -> Value {
    json!({
        MANAGED_BY_LABEL: "codewire",
        LABEL_TYPE: WARM_POOL_TYPE,
    })
}

/// Selects every warm pool and pool template Codewire owns.
pub fn pool_label_selector() -> String {
    format!("{MANAGED_BY_LABEL}=codewire,{LABEL_TYPE}={WARM_POOL_TYPE}")
}

/// Whether a live object carries the pool labels (other labels, such as the
/// fork's template-reference hash, may be added beside them).
pub fn has_pool_labels(labels: Option<&std::collections::BTreeMap<String, String>>) -> bool {
    labels.is_some_and(|labels| {
        labels.get(MANAGED_BY_LABEL).map(String::as_str) == Some("codewire")
            && labels.get(LABEL_TYPE).map(String::as_str) == Some(WARM_POOL_TYPE)
    })
}

/// Every image a Pod spec runs or mounts: containers, init containers and
/// image volumes.
pub fn pod_template_images(pod_spec: &Value) -> Vec<&str> {
    let containers = ["containers", "initContainers"]
        .into_iter()
        .filter_map(|field| pod_spec[field].as_array())
        .flatten()
        .filter_map(|container| container["image"].as_str());
    let volumes = pod_spec["volumes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|volume| volume["image"]["reference"].as_str());
    containers.chain(volumes).collect()
}

fn digest_pinned(image: &str) -> bool {
    image.split_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty()
            && !name.contains(char::is_whitespace)
            && digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn kubernetes_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && value.starts_with(|ch: char| ch.is_ascii_alphanumeric())
        && value.ends_with(|ch: char| ch.is_ascii_alphanumeric())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "warm_pool_tests.rs"]
pub(crate) mod tests;
