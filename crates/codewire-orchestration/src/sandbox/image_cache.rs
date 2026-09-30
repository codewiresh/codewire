//! Orchestration-owned node image cache (Program #2238 A2b, slice 1).
//!
//! A new release changes the gateway image (which the workspace Pod's
//! daemon-init also copies the daemon from) and sometimes the workspace and
//! DinD images. Without a cache, the first sandbox on a runtime node after a
//! release waits for those pulls. Orchestration renders those exact digests,
//! so it also keeps them warm: one `cw-image-cache` DaemonSet holds one idle
//! container per image on every runtime node.
//!
//! The DaemonSet carries two image sets, newest first. Each orchestration Pod
//! adds its own set when it is missing, and the oldest set is dropped once a
//! third arrives, so a rolling deploy keeps the running release's images
//! while the next release's images pull (`maxSurge: 1`,
//! `maxUnavailable: 0`). The merge is monotonic: a dropped set is remembered
//! and never re-added, so Pods of an older release cannot evict newer images.
//!
//! Only digest-pinned images from approved registries are cached. Tag
//! references, and anything else the admission policy would refuse, are
//! skipped and counted. Per-organization preset images are not cached: they
//! are user-chosen, unbounded, and may name any registry.
//!
//! Every cache container runs the same idle process, whatever its image
//! contains. An init container copies BusyBox and the musl dynamic loader out
//! of the pinned DinD image into an `emptyDir`; each cache container then
//! runs `sleep` through that loader. This works in images without a shell or
//! libc, and needs no image beyond the ones already cached. The loader path
//! is x86-64 only, like every current runtime node.
//!
//! This slice does not gate orchestration readiness on the cache. A new
//! orchestration Pod adds its set and continues; the warm gauge reports
//! whether its images are Ready on every eligible node. Holding readiness and
//! Temporal polling until warm is slice 2.
//!
//! This module is pure: rendering, merge and rollout decisions only. The
//! Kubernetes reconcile loop lives in `worker::image_cache`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::CANONICAL_WORKSPACE_RUNTIME_IMAGE;
use super::template::DEFAULT_DIND_IMAGE;

/// The one DaemonSet orchestration may manage (the admission policy binds
/// this exact name).
pub const IMAGE_CACHE_NAME: &str = "cw-image-cache";
/// Dedicated identity with no token and no RBAC. Never `codewire-sandbox`.
pub const IMAGE_CACHE_SERVICE_ACCOUNT: &str = "cw-image-cache";
pub const IMAGE_CACHE_PULL_SECRET: &str = "harbor-registry";
/// JSON [`CacheState`] recorded on the DaemonSet.
pub const IMAGE_CACHE_STATE_ANNOTATION: &str = "codewire.sh/image-cache-state";
pub const IMAGE_CACHE_ENV: &str = "SANDBOX_IMAGE_CACHE";
pub const IMAGE_CACHE_NODE_SELECTOR_ENV: &str = "SANDBOX_IMAGE_CACHE_NODE_SELECTOR";
/// The commodity RuntimeClass's scheduling selector: every node that can run
/// a sandbox.
pub const DEFAULT_IMAGE_CACHE_NODE_SELECTOR: &str =
    "katacontainers.io/kata-runtime=true,node.codewire.sh/runtime-candidate=true";
pub const RUNTIME_CANDIDATE_TAINT_KEY: &str = "node.codewire.sh/runtime-candidate";
/// Bumped whenever the rendered Pod shape changes for the same image sets.
/// A Pod never rewrites a DaemonSet rendered by a newer renderer.
pub const IMAGE_CACHE_RENDER_VERSION: u32 = 1;
/// Registries the admission policy accepts. Kept in the same order and
/// spelling as `deployments/k8s/orchestration/image-cache-authz.yaml`.
pub const APPROVED_IMAGE_REGISTRIES: [&str; 2] = ["registry.example.invalid/", "docker.io/library/"];

const MAX_SETS: usize = 2;
const MAX_RETIRED: usize = 16;
const TOOL_VOLUME: &str = "cw-image-cache-tool";
const TOOL_DIR: &str = "/cw-image-cache";
const TOOL_CONTAINER: &str = "tool";
const BUSYBOX: &str = "busybox";
const MUSL_LOADER: &str = "ld-musl-x86_64.so.1";
const CACHE_UID: i64 = 65532;
/// About 68 years; BusyBox `sleep` takes seconds.
const IDLE_SECONDS: &str = "2147483647";

/// One orchestration release's images. `tool` is the DinD image the idle
/// process is copied from; it is always also one of `images`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSet {
    pub generation: u64,
    pub tool: String,
    pub images: Vec<String>,
}

impl ImageSet {
    /// Order-independent identity of the images a set holds.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.tool, &self.images)
    }
}

fn fingerprint(tool: &str, images: &[String]) -> String {
    let sorted: BTreeSet<&str> = images.iter().map(String::as_str).collect();
    let mut hasher = Sha256::new();
    hasher.update(tool.as_bytes());
    for image in sorted {
        hasher.update([0]);
        hasher.update(image.as_bytes());
    }
    hex_prefix(&hasher.finalize(), 16)
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes.iter().take(len).map(|b| format!("{b:02x}")).collect()
}

/// What the DaemonSet currently holds, recorded in its annotation so every
/// orchestration Pod merges against the same history.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheState {
    /// Render version that produced the live spec.
    pub version: u32,
    /// Last generation assigned to a set.
    pub generation: u64,
    /// Newest first, at most two.
    pub sets: Vec<ImageSet>,
    /// Fingerprints of dropped sets, newest first, bounded. A retired set is
    /// never added back.
    pub retired: Vec<String>,
    /// SHA-256 of the rendered `spec`, to detect a changed render input.
    pub spec_sha256: String,
}

impl CacheState {
    pub fn parse(annotation: &str) -> anyhow::Result<Self> {
        let state: Self = serde_json::from_str(annotation)?;
        anyhow::ensure!(
            state.sets.len() <= MAX_SETS && state.retired.len() <= MAX_RETIRED,
            "image cache state exceeds its bounds"
        );
        for set in &state.sets {
            anyhow::ensure!(
                set.images.contains(&set.tool)
                    && set.images.iter().all(|image| is_approved_image(image)),
                "image cache state names an unapproved image"
            );
        }
        Ok(state)
    }

    pub fn contains(&self, desired: &DesiredSet) -> bool {
        let fp = desired.fingerprint();
        self.sets.iter().any(|set| set.fingerprint() == fp)
    }

    /// Index of `desired` among the held sets: 0 current, 1 previous.
    pub fn position(&self, desired: &DesiredSet) -> Option<usize> {
        let fp = desired.fingerprint();
        self.sets.iter().position(|set| set.fingerprint() == fp)
    }
}

/// The images this orchestration Pod renders, filtered to what the cache may
/// hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesiredSet {
    pub tool: String,
    pub images: Vec<String>,
    /// Rendered references that are not approved, digest-pinned images.
    pub skipped: usize,
}

impl DesiredSet {
    /// Workspace default, gateway (also the daemon-init source) and DinD, in
    /// that order. An empty `dind_image` means the template default.
    pub fn from_rendered(gateway_image: &str, dind_image: &str) -> Self {
        let dind = match dind_image.trim() {
            "" => DEFAULT_DIND_IMAGE,
            image => image,
        };
        let tool = if is_approved_image(dind) {
            dind
        } else {
            DEFAULT_DIND_IMAGE
        };
        let mut images = Vec::new();
        let mut skipped = 0;
        for image in [
            CANONICAL_WORKSPACE_RUNTIME_IMAGE,
            gateway_image.trim(),
            dind,
        ] {
            if !is_approved_image(image) {
                skipped += 1;
            } else if !images.iter().any(|held| held == image) {
                images.push(image.to_owned());
            }
        }
        if !images.iter().any(|held| held == tool) {
            images.push(tool.to_owned());
        }
        Self {
            tool: tool.to_owned(),
            images,
            skipped,
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.tool, &self.images)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// The set is already held (current or previous).
    Present,
    /// The set was added as the newest; the oldest may have been retired.
    Added,
    /// A newer release already retired this set; it is not added back.
    Superseded,
}

/// Add `desired` as the newest set unless it is held or retired. Keeps the
/// two newest sets.
pub fn merge(state: &mut CacheState, desired: &DesiredSet) -> MergeOutcome {
    if state.contains(desired) {
        return MergeOutcome::Present;
    }
    let fp = desired.fingerprint();
    if state.retired.contains(&fp) {
        return MergeOutcome::Superseded;
    }
    let generation = state
        .sets
        .iter()
        .map(|set| set.generation)
        .fold(state.generation, u64::max)
        + 1;
    state.generation = generation;
    state.sets.insert(
        0,
        ImageSet {
            generation,
            tool: desired.tool.clone(),
            images: desired.images.clone(),
        },
    );
    while state.sets.len() > MAX_SETS {
        let dropped = state.sets.pop().expect("more than MAX_SETS sets");
        let dropped = dropped.fingerprint();
        state.retired.retain(|held| held != &dropped);
        state.retired.insert(0, dropped);
    }
    state.retired.truncate(MAX_RETIRED);
    MergeOutcome::Added
}

/// The admission policy's image expression, which [`is_approved_image`]
/// implements. A test binds this text to the policy file.
pub const APPROVED_IMAGE_PATTERN: &str = "^(registry[.]example[.]invalid|docker[.]io/library)/[a-z0-9]+([._/-][a-z0-9]+)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$";

/// `registry.example.invalid/…` or `docker.io/library/…`, with an optional tag and a
/// mandatory `@sha256:` digest ([`APPROVED_IMAGE_PATTERN`]).
pub fn is_approved_image(image: &str) -> bool {
    let Some(rest) = APPROVED_IMAGE_REGISTRIES
        .iter()
        .find_map(|registry| image.strip_prefix(registry))
    else {
        return false;
    };
    let Some((name, digest)) = rest.split_once("@sha256:") else {
        return false;
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    let (path, tag) = match name.split_once(':') {
        Some((path, tag)) => (path, Some(tag)),
        None => (name, None),
    };
    valid_repository_path(path) && tag.is_none_or(valid_tag)
}

fn valid_repository_path(path: &str) -> bool {
    let mut previous_separator = true;
    for b in path.bytes() {
        let separator = matches!(b, b'.' | b'_' | b'/' | b'-');
        if separator {
            if previous_separator {
                return false;
            }
        } else if !(b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return false;
        }
        previous_separator = separator;
    }
    !path.is_empty() && !previous_separator
}

fn valid_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Parse `key=value,key=value`. The selector must be non-empty: an empty one
/// would place the cache on every untainted node.
pub fn parse_node_selector(value: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let mut selector = BTreeMap::new();
    for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (key, label) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("node selector entry {entry:?} is not key=value"))?;
        anyhow::ensure!(
            valid_label_key(key) && valid_label_value(label),
            "node selector entry {entry:?} is not a valid label"
        );
        anyhow::ensure!(
            selector.insert(key.to_owned(), label.to_owned()).is_none(),
            "node selector repeats {key:?}"
        );
    }
    anyhow::ensure!(!selector.is_empty(), "node selector must not be empty");
    Ok(selector)
}

fn valid_label_key(key: &str) -> bool {
    let (prefix, name) = match key.rsplit_once('/') {
        Some((prefix, name)) => (Some(prefix), name),
        None => (None, key),
    };
    prefix.is_none_or(|prefix| {
        !prefix.is_empty()
            && prefix.len() <= 253
            && prefix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
    }) && valid_label_value(name)
        && !name.is_empty()
}

fn valid_label_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() <= 63
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && bytes.first().is_none_or(u8::is_ascii_alphanumeric)
        && bytes.last().is_none_or(u8::is_ascii_alphanumeric)
}

/// Render inputs that are not image sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderConfig {
    pub namespace: String,
    pub node_selector: BTreeMap<String, String>,
}

fn labels() -> Value {
    json!({
        "app.kubernetes.io/name": IMAGE_CACHE_NAME,
        "app.kubernetes.io/component": "image-cache",
        "app.kubernetes.io/part-of": "codewire",
        "app.kubernetes.io/managed-by": "codewire",
    })
}

fn container_security_context() -> Value {
    json!({
        "allowPrivilegeEscalation": false,
        "readOnlyRootFilesystem": true,
        "capabilities": { "drop": ["ALL"] },
    })
}

fn container_resources() -> Value {
    json!({
        "requests": { "cpu": "1m", "memory": "4Mi" },
        "limits": { "cpu": "10m", "memory": "16Mi" },
    })
}

/// Unique images across the held sets, newest set first.
pub fn cached_images(sets: &[ImageSet]) -> Vec<String> {
    let mut images: Vec<String> = Vec::new();
    for image in sets.iter().flat_map(|set| &set.images) {
        if !images.contains(image) {
            images.push(image.clone());
        }
    }
    images
}

/// The DaemonSet `spec` for `sets` (newest first; must not be empty).
pub fn render_spec(cfg: &RenderConfig, sets: &[ImageSet]) -> Value {
    let tool = &sets.first().expect("image cache has a set").tool;
    let containers: Vec<Value> = cached_images(sets)
        .into_iter()
        .enumerate()
        .map(|(index, image)| {
            json!({
                "name": format!("image-{index}"),
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": [
                    format!("{TOOL_DIR}/{MUSL_LOADER}"),
                    format!("{TOOL_DIR}/{BUSYBOX}"),
                    "sleep",
                    IDLE_SECONDS,
                ],
                "securityContext": container_security_context(),
                "resources": container_resources(),
                "volumeMounts": [
                    { "name": TOOL_VOLUME, "mountPath": TOOL_DIR, "readOnly": true },
                ],
            })
        })
        .collect();
    json!({
        "selector": { "matchLabels": { "app.kubernetes.io/name": IMAGE_CACHE_NAME } },
        "updateStrategy": {
            "type": "RollingUpdate",
            "rollingUpdate": { "maxUnavailable": 0, "maxSurge": 1 },
        },
        "template": {
            "metadata": { "labels": labels() },
            "spec": {
                "serviceAccountName": IMAGE_CACHE_SERVICE_ACCOUNT,
                "automountServiceAccountToken": false,
                "enableServiceLinks": false,
                "imagePullSecrets": [ { "name": IMAGE_CACHE_PULL_SECRET } ],
                "nodeSelector": cfg.node_selector,
                "tolerations": [
                    {
                        "key": RUNTIME_CANDIDATE_TAINT_KEY,
                        "operator": "Equal",
                        "value": "true",
                        "effect": "NoSchedule",
                    },
                ],
                "terminationGracePeriodSeconds": 1,
                "securityContext": {
                    "runAsNonRoot": true,
                    "runAsUser": CACHE_UID,
                    "runAsGroup": CACHE_UID,
                    "seccompProfile": { "type": "RuntimeDefault" },
                },
                "initContainers": [
                    {
                        "name": TOOL_CONTAINER,
                        "image": tool,
                        "imagePullPolicy": "IfNotPresent",
                        "command": [
                            format!("/bin/{BUSYBOX}"),
                            "cp",
                            format!("/bin/{BUSYBOX}"),
                            format!("/lib/{MUSL_LOADER}"),
                            format!("{TOOL_DIR}/"),
                        ],
                        "securityContext": container_security_context(),
                        "resources": container_resources(),
                        "volumeMounts": [ { "name": TOOL_VOLUME, "mountPath": TOOL_DIR } ],
                    },
                ],
                "containers": containers,
                "volumes": [
                    { "name": TOOL_VOLUME, "emptyDir": { "sizeLimit": "8Mi" } },
                ],
            },
        },
    })
}

pub fn spec_sha256(spec: &Value) -> String {
    let bytes = serde_json::to_vec(spec).expect("rendered spec serializes");
    hex_prefix(&Sha256::digest(bytes), 32)
}

/// The whole DaemonSet for `state`, recording `state` (with the render
/// version and spec hash filled in) in its annotation.
pub fn render_daemon_set(cfg: &RenderConfig, state: &CacheState) -> (Value, CacheState) {
    let spec = render_spec(cfg, &state.sets);
    let mut recorded = state.clone();
    recorded.version = IMAGE_CACHE_RENDER_VERSION;
    recorded.spec_sha256 = spec_sha256(&spec);
    let annotation = serde_json::to_string(&recorded).expect("image cache state serializes");
    let daemon_set = json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {
            "name": IMAGE_CACHE_NAME,
            "namespace": cfg.namespace,
            "labels": labels(),
            "annotations": { IMAGE_CACHE_STATE_ANNOTATION: annotation },
        },
        "spec": spec,
    });
    (daemon_set, recorded)
}

/// What one reconcile pass should do.
#[derive(Debug, PartialEq)]
pub enum Plan {
    Create {
        daemon_set: Value,
        state: CacheState,
    },
    Replace {
        daemon_set: Value,
        state: CacheState,
    },
    /// Nothing to write. `state` is the live state (for metrics).
    Keep { state: CacheState },
    /// A newer release owns the cache; this Pod's set is not held.
    Superseded { state: CacheState },
}

/// Decide the write for this Pod's `desired` set against the live DaemonSet
/// (`None` when absent).
pub fn plan(cfg: &RenderConfig, live: Option<&Value>, desired: &DesiredSet) -> Plan {
    let Some(live) = live else {
        let mut state = CacheState::default();
        merge(&mut state, desired);
        let (daemon_set, state) = render_daemon_set(cfg, &state);
        return Plan::Create { daemon_set, state };
    };
    let annotation = live
        .pointer("/metadata/annotations")
        .and_then(|annotations| annotations.get(IMAGE_CACHE_STATE_ANNOTATION))
        .and_then(Value::as_str);
    // A newer renderer's record is never rewritten, even when this Pod
    // cannot read it.
    let recorded_version = annotation
        .and_then(|annotation| serde_json::from_str::<Value>(annotation).ok())
        .and_then(|record| record["version"].as_u64())
        .unwrap_or(0);
    if recorded_version > u64::from(IMAGE_CACHE_RENDER_VERSION) {
        let state = annotation
            .and_then(|annotation| CacheState::parse(annotation).ok())
            .unwrap_or_default();
        return if state.contains(desired) {
            Plan::Keep { state }
        } else {
            Plan::Superseded { state }
        };
    }
    // A missing or unreadable record means someone else wrote the object;
    // start again from this Pod's set rather than trust it.
    let mut state = annotation
        .and_then(|annotation| CacheState::parse(annotation).ok())
        .unwrap_or_default();
    match merge(&mut state, desired) {
        MergeOutcome::Superseded => Plan::Superseded { state },
        MergeOutcome::Added => {
            let (daemon_set, state) = render_daemon_set(cfg, &state);
            Plan::Replace { daemon_set, state }
        }
        MergeOutcome::Present => {
            let (daemon_set, rendered) = render_daemon_set(cfg, &state);
            if state.version == IMAGE_CACHE_RENDER_VERSION
                && state.spec_sha256 == rendered.spec_sha256
                && live_images(live) == live_images(&daemon_set)
            {
                Plan::Keep { state }
            } else {
                Plan::Replace {
                    daemon_set,
                    state: rendered,
                }
            }
        }
    }
}

/// Init and cache container images, in order; detects edits the annotation
/// does not record.
fn live_images(daemon_set: &Value) -> Vec<String> {
    let spec = daemon_set.pointer("/spec/template/spec");
    ["initContainers", "containers"]
        .iter()
        .flat_map(|field| {
            spec.and_then(|spec| spec.get(field))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .map(|container| container["image"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// DaemonSet rollout status, from `status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rollout {
    pub desired: i64,
    pub updated: i64,
    pub available: i64,
    pub ready: i64,
    /// The controller has observed the current spec and every eligible node
    /// runs an available Pod of it.
    pub complete: bool,
}

pub fn rollout(daemon_set: &Value) -> Rollout {
    let status = &daemon_set["status"];
    let count = |field: &str| status[field].as_i64().unwrap_or(0);
    let desired = count("desiredNumberScheduled");
    let updated = count("updatedNumberScheduled");
    let available = count("numberAvailable");
    let observed = status["observedGeneration"].as_i64().unwrap_or(-1);
    let generation = daemon_set["metadata"]["generation"].as_i64().unwrap_or(0);
    Rollout {
        desired,
        updated,
        available,
        ready: count("numberReady"),
        complete: observed >= generation
            && updated == desired
            && available == desired
            && count("numberUnavailable") == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKSPACE: &str = CANONICAL_WORKSPACE_RUNTIME_IMAGE;
    const GATEWAY_A: &str = "registry.example.invalid/codewire/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const GATEWAY_B: &str = "registry.example.invalid/codewire/gateway@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GATEWAY_C: &str = "registry.example.invalid/codewire/gateway@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn cfg() -> RenderConfig {
        RenderConfig {
            namespace: "dev-sandboxes".into(),
            node_selector: parse_node_selector(DEFAULT_IMAGE_CACHE_NODE_SELECTOR).unwrap(),
        }
    }

    fn release(gateway: &str) -> DesiredSet {
        DesiredSet::from_rendered(gateway, "")
    }

    fn load_golden(name: &str) -> Value {
        let path = format!(
            "{}/tests/fixtures/sandbox/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("golden file missing")).unwrap()
    }

    fn state_of(daemon_set: &Value) -> CacheState {
        CacheState::parse(
            daemon_set["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    fn apply(live: Option<Value>, desired: &DesiredSet) -> (Option<Value>, &'static str) {
        match plan(&cfg(), live.as_ref(), desired) {
            Plan::Create { daemon_set, .. } => (Some(daemon_set), "create"),
            Plan::Replace { daemon_set, .. } => (Some(daemon_set), "replace"),
            Plan::Keep { .. } => (live, "keep"),
            Plan::Superseded { .. } => (live, "superseded"),
        }
    }

    #[test]
    fn rendered_daemon_set_matches_golden_file() {
        let (live, _) = apply(None, &release(GATEWAY_A));
        let (live, _) = apply(live, &release(GATEWAY_B));
        assert_eq!(
            live.unwrap(),
            load_golden("image-cache-daemonset.golden.json"),
            "image cache DaemonSet render drifted from its golden file"
        );
    }

    #[test]
    fn desired_set_is_workspace_gateway_and_dind_with_dind_as_tool() {
        let set = release(GATEWAY_A);
        assert_eq!(set.images, [WORKSPACE, GATEWAY_A, DEFAULT_DIND_IMAGE]);
        assert_eq!(set.tool, DEFAULT_DIND_IMAGE);
        assert_eq!(set.skipped, 0);
    }

    #[test]
    fn unpinned_or_unapproved_references_are_skipped_and_the_tool_falls_back() {
        // Kind renders a side-loaded gateway tag and a local DinD alias.
        let set = DesiredSet::from_rendered(
            "codewire-gateway:e2e",
            "localhost/codewire-ci/docker-dind:verified-66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e",
        );
        assert_eq!(set.images, [WORKSPACE, DEFAULT_DIND_IMAGE]);
        assert_eq!(set.tool, DEFAULT_DIND_IMAGE);
        assert_eq!(set.skipped, 2);
    }

    #[test]
    fn a_configured_pinned_dind_is_the_tool() {
        let dind = "registry.example.invalid/oci-approved/docker/dind@sha256:66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e";
        let set = DesiredSet::from_rendered(GATEWAY_A, dind);
        assert_eq!(set.images, [WORKSPACE, GATEWAY_A, dind]);
        assert_eq!(set.tool, dind);
    }

    #[test]
    fn approved_images_match_the_admission_expression() {
        for image in [
            WORKSPACE,
            DEFAULT_DIND_IMAGE,
            GATEWAY_A,
            "docker.io/library/busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(is_approved_image(image), "{image}");
        }
        for image in [
            "codewire-gateway:e2e",
            "registry.example.invalid/codewire/gateway:main",
            "docker.io/library/docker:29-dind",
            "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff",
            "docker.io/evil/docker@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid.evil/x@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid/codewire/gateway@sha256:E8FAAD5A8DC5279DFF929AFC5449F2791736912FFF9F99351D742DB2FAD01B4C",
            "registry.example.invalid/codewire/gateway@sha256:e8faad",
            "registry.example.invalid//gateway@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid/Codewire/gateway@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid/codewire/gateway:@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid/codewire/gateway:-x@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
        ] {
            assert!(!is_approved_image(image), "{image}");
        }
    }

    #[test]
    fn first_reconcile_creates_one_set_and_repeats_keep_it() {
        let (live, action) = apply(None, &release(GATEWAY_A));
        assert_eq!(action, "create");
        let state = state_of(live.as_ref().unwrap());
        assert_eq!(state.generation, 1);
        assert_eq!(state.sets.len(), 1);
        assert_eq!(state.version, IMAGE_CACHE_RENDER_VERSION);
        let (_, action) = apply(live, &release(GATEWAY_A));
        assert_eq!(action, "keep");
    }

    #[test]
    fn rolling_deploy_keeps_current_and_previous_and_never_downgrades() {
        let (live, _) = apply(None, &release(GATEWAY_A));
        // Release B rolls out: its Pods add B; A's Pods keep running on A.
        let (live, action) = apply(live, &release(GATEWAY_B));
        assert_eq!(action, "replace");
        let state = state_of(live.as_ref().unwrap());
        assert_eq!(
            state.sets.iter().map(|s| s.generation).collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(apply(live.clone(), &release(GATEWAY_A)).1, "keep");
        assert_eq!(apply(live.clone(), &release(GATEWAY_B)).1, "keep");
        // Both releases' gateways stay cached.
        let images = cached_images(&state.sets);
        assert!(images.contains(&GATEWAY_A.to_owned()));
        assert!(images.contains(&GATEWAY_B.to_owned()));

        // Release C retires A.
        let (live, action) = apply(live, &release(GATEWAY_C));
        assert_eq!(action, "replace");
        let state = state_of(live.as_ref().unwrap());
        assert_eq!(
            state.sets.iter().map(|s| s.generation).collect::<Vec<_>>(),
            [3, 2]
        );
        assert_eq!(state.retired, [release(GATEWAY_A).fingerprint()]);
        assert!(!cached_images(&state.sets).contains(&GATEWAY_A.to_owned()));

        // A lingering Pod of A never evicts the newer sets.
        let (after, action) = apply(live.clone(), &release(GATEWAY_A));
        assert_eq!(action, "superseded");
        assert_eq!(after, live);
        // Rolling back to B (still held) changes nothing.
        assert_eq!(apply(live, &release(GATEWAY_B)).1, "keep");
    }

    #[test]
    fn retired_history_is_bounded_and_deduplicated() {
        let mut state = CacheState::default();
        for index in 0..40u32 {
            let gateway = format!("registry.example.invalid/codewire/gateway@sha256:{index:064x}");
            assert_eq!(merge(&mut state, &release(&gateway)), MergeOutcome::Added);
        }
        assert_eq!(state.sets.len(), MAX_SETS);
        assert_eq!(state.retired.len(), MAX_RETIRED);
        assert_eq!(state.generation, 40);
        let unique: BTreeSet<_> = state.retired.iter().collect();
        assert_eq!(unique.len(), MAX_RETIRED);
    }

    #[test]
    fn shared_images_across_sets_are_cached_once() {
        let mut state = CacheState::default();
        merge(&mut state, &release(GATEWAY_A));
        merge(&mut state, &release(GATEWAY_B));
        assert_eq!(
            cached_images(&state.sets),
            [WORKSPACE, GATEWAY_B, DEFAULT_DIND_IMAGE, GATEWAY_A]
        );
    }

    #[test]
    fn a_newer_renderer_is_never_overwritten() {
        let (live, _) = apply(None, &release(GATEWAY_A));
        let mut live = live.unwrap();
        let mut state = state_of(&live);
        state.version = IMAGE_CACHE_RENDER_VERSION + 1;
        live["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION] =
            serde_json::to_string(&state).unwrap().into();
        assert_eq!(apply(Some(live.clone()), &release(GATEWAY_A)).1, "keep");
        assert_eq!(
            apply(Some(live.clone()), &release(GATEWAY_B)).1,
            "superseded"
        );
        // Even a newer record this renderer cannot parse is left alone.
        let newer = json!({ "version": IMAGE_CACHE_RENDER_VERSION + 1, "sets": "reshaped" });
        live["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION] = newer.to_string().into();
        assert_eq!(apply(Some(live), &release(GATEWAY_A)).1, "superseded");
    }

    #[test]
    fn render_input_changes_and_live_edits_are_repaired() {
        let (live, _) = apply(None, &release(GATEWAY_A));
        let live = live.unwrap();

        let mut other = cfg();
        other.node_selector = BTreeMap::from([("kubernetes.io/os".to_owned(), "linux".to_owned())]);
        assert!(matches!(
            plan(&other, Some(&live), &release(GATEWAY_A)),
            Plan::Replace { .. }
        ));

        let mut edited = live.clone();
        edited["spec"]["template"]["spec"]["containers"][0]["image"] =
            "docker.io/library/busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        assert!(matches!(
            plan(&cfg(), Some(&edited), &release(GATEWAY_A)),
            Plan::Replace { .. }
        ));

        let mut foreign = live;
        foreign["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION] = "{".into();
        let Plan::Replace { state, .. } = plan(&cfg(), Some(&foreign), &release(GATEWAY_A)) else {
            panic!("an unreadable record is rewritten");
        };
        assert_eq!(state.sets.len(), 1);
    }

    #[test]
    fn state_parse_rejects_unapproved_or_oversized_records() {
        let mut state = CacheState::default();
        merge(&mut state, &release(GATEWAY_A));
        let mut bad = state.clone();
        bad.sets[0].images.push("docker.io/evil/x:latest".into());
        assert!(CacheState::parse(&serde_json::to_string(&bad).unwrap()).is_err());
        let mut bad = state.clone();
        bad.sets[0].tool = GATEWAY_C.into();
        assert!(CacheState::parse(&serde_json::to_string(&bad).unwrap()).is_err());
        let mut bad = state;
        bad.sets = vec![bad.sets[0].clone(); 3];
        assert!(CacheState::parse(&serde_json::to_string(&bad).unwrap()).is_err());
    }

    #[test]
    fn pod_shape_is_runc_tokenless_unprivileged_and_scoped_to_runtime_nodes() {
        let (live, _) = apply(None, &release(GATEWAY_A));
        let live = live.unwrap();
        let pod = &live["spec"]["template"]["spec"];
        assert!(pod.get("runtimeClassName").is_none());
        assert_eq!(pod["serviceAccountName"], IMAGE_CACHE_SERVICE_ACCOUNT);
        assert_ne!(
            pod["serviceAccountName"],
            crate::sandbox::template::SANDBOX_SERVICE_ACCOUNT
        );
        assert_eq!(pod["automountServiceAccountToken"], false);
        for field in ["hostNetwork", "hostPID", "hostIPC", "priorityClassName"] {
            assert!(pod.get(field).is_none(), "{field}");
        }
        assert!(
            pod["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v.get("emptyDir").is_some())
        );
        assert_eq!(
            pod["nodeSelector"],
            json!({
                "katacontainers.io/kata-runtime": "true",
                "node.codewire.sh/runtime-candidate": "true",
            })
        );
        let containers = pod["containers"]
            .as_array()
            .unwrap()
            .iter()
            .chain(pod["initContainers"].as_array().unwrap());
        for container in containers {
            assert!(is_approved_image(container["image"].as_str().unwrap()));
            assert_eq!(container["securityContext"], container_security_context());
            assert!(container.get("env").is_none() && container.get("ports").is_none());
        }
        assert_eq!(
            live["spec"]["updateStrategy"]["rollingUpdate"],
            json!({ "maxUnavailable": 0, "maxSurge": 1 })
        );
    }

    #[test]
    fn admission_policy_pins_the_rendered_commands_identity_and_image_rule() {
        let policy = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deployments/k8s/orchestration/image-cache-authz.yaml"
        ))
        .expect("image cache admission policy");
        let (live, _) = apply(None, &release(GATEWAY_A));
        let pod = &live.unwrap()["spec"]["template"]["spec"];
        let cel_list = |command: &Value| {
            let items: Vec<String> = command
                .as_array()
                .unwrap()
                .iter()
                .map(|item| format!("'{}'", item.as_str().unwrap()))
                .collect();
            format!("[{}]", items.join(", "))
        };
        for command in [
            &pod["containers"][0]["command"],
            &pod["initContainers"][0]["command"],
        ] {
            let command = cel_list(command);
            assert!(policy.contains(&command), "policy does not pin {command}");
        }
        assert!(policy.contains(&format!("c.image.matches('{APPROVED_IMAGE_PATTERN}')")));
        for fragment in [
            format!("request.name == '{IMAGE_CACHE_NAME}'"),
            format!("variables.pod.serviceAccountName == '{IMAGE_CACHE_SERVICE_ACCOUNT}'"),
            format!("s.name == '{IMAGE_CACHE_PULL_SECRET}'"),
            format!("t.key == '{RUNTIME_CANDIDATE_TAINT_KEY}'"),
        ] {
            assert!(
                policy.contains(&fragment),
                "policy does not contain {fragment}"
            );
        }
    }

    #[test]
    fn node_selector_parses_and_rejects_bad_labels() {
        assert_eq!(
            parse_node_selector(" kubernetes.io/os=linux ").unwrap(),
            BTreeMap::from([("kubernetes.io/os".to_owned(), "linux".to_owned())])
        );
        for bad in [
            "",
            ",",
            "novalue",
            "a=b,a=c",
            "bad key=x",
            "k=-x",
            "Upper.Case/x=y",
        ] {
            assert!(parse_node_selector(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rollout_is_complete_only_when_every_node_runs_the_observed_spec() {
        let daemon_set = |observed: i64, desired: i64, updated: i64, available: i64| {
            json!({
                "metadata": { "generation": 3 },
                "status": {
                    "observedGeneration": observed,
                    "desiredNumberScheduled": desired,
                    "updatedNumberScheduled": updated,
                    "numberAvailable": available,
                    "numberReady": available,
                },
            })
        };
        assert!(rollout(&daemon_set(3, 2, 2, 2)).complete);
        assert!(rollout(&daemon_set(3, 0, 0, 0)).complete);
        assert!(!rollout(&daemon_set(2, 2, 2, 2)).complete);
        assert!(!rollout(&daemon_set(3, 2, 1, 2)).complete);
        assert!(!rollout(&daemon_set(3, 2, 2, 1)).complete);
        assert!(!rollout(&json!({ "metadata": { "generation": 1 } })).complete);
    }
}
