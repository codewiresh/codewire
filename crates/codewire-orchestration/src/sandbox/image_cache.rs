//! Orchestration-owned node image cache (Program #2238 A2b, slice 1).
//!
//! A new release changes the daemon support image (which the workspace Pod
//! mounts or copies the daemon from) and sometimes the workspace and
//! DinD images. Without a cache, the first sandbox on a runtime node after a
//! release waits for those pulls. Orchestration renders those exact digests,
//! so it also keeps them warm: one `cw-image-cache` DaemonSet on every
//! `katacontainers.io/kata-runtime` node mounts each image as a read-only OCI
//! image volume, which makes the kubelet pull it and keeps it in use.
//!
//! The DaemonSet carries two image sets, ordered by release: the orchestration
//! Deployment revision of the Pod that rendered them. Each orchestration Pod
//! adds its own set when it is missing, and the oldest release's set is
//! dropped once a third arrives, so a rolling deploy keeps the running
//! release's images while the next release's images pull (`maxSurge: 1`,
//! `maxUnavailable: 0`). The merge is monotonic: a set older than every held
//! set is never added, and a dropped set is remembered and never re-added, so
//! a leftover Pod of an older release cannot evict newer images. A rollback
//! gets a new revision, so the rolled-back release becomes current again.
//!
//! Only digest-pinned images from approved registries are cached. Tag
//! references, and anything else the admission policy would refuse, are
//! skipped and counted. Per-organization preset images are not cached: they
//! are user-chosen, unbounded, and may name any registry.
//!
//! Nothing from a cached image ever runs. The Pod has one container, running
//! BusyBox `sleep` from the pinned DinD image's own root filesystem
//! ([`IMAGE_CACHE_IDLE_IMAGE`]); every other image is an image volume
//! (`volumes[].image`, GA and locked on in Kubernetes 1.36) mounted read-only
//! into it. The kubelet pulls image volumes with the Pod's pull secrets and
//! its image garbage collector counts an image mounted by a container as in
//! use. Executing from an `emptyDir` is not an option on Talos: the kubelet's
//! state tree is `kubelet_state_t`, which pods may read and write but not use
//! as a container entrypoint.
//!
//! This slice does not gate orchestration readiness on the cache. A new
//! orchestration Pod adds its set and continues; the warm gauge reports
//! whether its images are Ready on every eligible node. Holding readiness and
//! Temporal polling until warm is slice 2.
//!
//! `SANDBOX_IMAGE_CACHE=disabled` stops reconciling but leaves the DaemonSet:
//! orchestration has no delete grant. To remove it, an operator deletes
//! `daemonset/cw-image-cache` in the sandbox namespace after the setting has
//! rolled out.
//!
//! This module is pure: rendering, merge and rollout decisions only. The
//! Kubernetes reconcile loop lives in `worker::image_cache`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::canonical_workspace_runtime_image;
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
/// The commodity RuntimeClass's scheduling selector: every node that can run
/// a sandbox. The admission policy requires exactly this selector.
pub const IMAGE_CACHE_NODE_SELECTOR: [(&str, &str); 2] = [
    ("katacontainers.io/kata-runtime", "true"),
    ("node.codewire.sh/runtime-candidate", "true"),
];
pub const RUNTIME_CANDIDATE_TAINT_KEY: &str = "node.codewire.sh/runtime-candidate";
/// The only image the idle container may run: the DinD image the sandbox
/// runtime policy already pins. The admission policy pins the same string.
/// It is cached by running it, so it is never also an image volume.
pub const IMAGE_CACHE_IDLE_IMAGE: &str = DEFAULT_DIND_IMAGE;
/// Bumped whenever the rendered Pod shape changes for the same image sets.
/// A Pod never rewrites a DaemonSet rendered by a newer renderer. A test
/// fails until a render change bumps it.
pub const IMAGE_CACHE_RENDER_VERSION: u32 = 3;
/// What follows an approved registry prefix
/// ([`super::runtime_images::APPROVED_IMAGE_REGISTRIES_ENV`]): a repository
/// path, an optional tag and a mandatory digest. The admission policy matches
/// the rest of a reference after a prefix it approves against this text, and
/// [`is_approved_image`] implements it. A test binds both to the policy file.
pub const APPROVED_IMAGE_NAME_PATTERN: &str =
    "^[a-z0-9]+([._/-][a-z0-9]+)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$";

const MAX_SETS: usize = 2;
/// Workspace, daemon and DinD per set.
const MAX_SET_IMAGES: usize = 3;
/// The admission policy's image volume bound.
pub const MAX_CACHED_IMAGES: usize = MAX_SETS * MAX_SET_IMAGES;
const MAX_RETIRED: usize = 16;
const IDLE_CONTAINER: &str = "idle";
/// Image volumes mount at `<root>/<volume name>`.
pub const IMAGE_VOLUME_ROOT: &str = "/cw-image-cache";
const CACHE_UID: i64 = 65532;
/// About 68 years; BusyBox `sleep` takes seconds.
const IDLE_SECONDS: &str = "2147483647";

/// One orchestration release's images.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSet {
    /// Deployment revision of the release that rendered the set.
    #[serde(default)]
    pub release: u64,
    /// Arrival order, the tie-break between equal releases.
    pub generation: u64,
    pub images: Vec<String>,
}

impl ImageSet {
    /// Order-independent identity of the images a set holds.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.images)
    }
}

fn fingerprint(images: &[String]) -> String {
    let sorted: BTreeSet<&str> = images.iter().map(String::as_str).collect();
    let mut hasher = Sha256::new();
    for image in sorted {
        hasher.update(image.as_bytes());
        hasher.update([0]);
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
    /// Newest release first, at most two.
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
                !set.images.is_empty()
                    && set.images.len() <= MAX_SET_IMAGES
                    && set.images.iter().all(|image| is_approved_image(image)),
                "image cache state names an unapproved or oversized set"
            );
        }
        Ok(state)
    }

    /// Index of `desired` among the held sets: 0 current, 1 previous.
    pub fn position(&self, desired: &DesiredSet) -> Option<usize> {
        let fp = desired.fingerprint();
        self.sets.iter().position(|set| set.fingerprint() == fp)
    }

    fn sort(&mut self) {
        self.sets.sort_by(|a, b| {
            b.release
                .cmp(&a.release)
                .then(b.generation.cmp(&a.generation))
        });
    }
}

/// The images this orchestration Pod renders, filtered to what the cache may
/// hold, and the release that renders them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesiredSet {
    pub images: Vec<String>,
    /// Rendered references that are not approved, digest-pinned images.
    pub skipped: usize,
    /// This Pod's Deployment revision; 0 when unknown.
    pub release: u64,
}

impl DesiredSet {
    /// Workspace default, daemon (also the daemon-init source) and DinD, in
    /// that order. An empty `dind_image` means the template default.
    pub fn from_rendered(daemon_image: &str, dind_image: &str) -> Self {
        let dind = match dind_image.trim() {
            "" => DEFAULT_DIND_IMAGE,
            image => image,
        };
        let mut images = Vec::new();
        let mut skipped = 0;
        for image in [
            canonical_workspace_runtime_image(),
            daemon_image.trim(),
            dind,
        ] {
            if !is_approved_image(image) {
                skipped += 1;
            } else if !images.iter().any(|held| held == image) {
                images.push(image.to_owned());
            }
        }
        Self {
            images,
            skipped,
            release: 0,
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.images)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// The set is already held (current or previous) at this release.
    Present,
    /// The held set was re-recorded at this Pod's newer release (a rollback
    /// or a revision this Pod had not reported yet).
    Promoted,
    /// The set was added; the oldest release's set may have been retired.
    Added,
    /// Older than every held set, or retired by a newer release: not added.
    Superseded,
}

/// Merge this Pod's set by release. Keeps the two newest releases' sets.
pub fn merge(state: &mut CacheState, desired: &DesiredSet) -> MergeOutcome {
    if let Some(index) = state.position(desired) {
        if desired.release > state.sets[index].release {
            state.sets[index].release = desired.release;
            state.sort();
            return MergeOutcome::Promoted;
        }
        return MergeOutcome::Present;
    }
    let fp = desired.fingerprint();
    if state.retired.contains(&fp)
        || (state.sets.len() >= MAX_SETS
            && state.sets.iter().all(|set| desired.release < set.release))
    {
        return MergeOutcome::Superseded;
    }
    let generation = state
        .sets
        .iter()
        .map(|set| set.generation)
        .fold(state.generation, u64::max)
        + 1;
    state.generation = generation;
    state.sets.push(ImageSet {
        release: desired.release,
        generation,
        images: desired.images.clone(),
    });
    state.sort();
    while state.sets.len() > MAX_SETS {
        let dropped = state.sets.pop().expect("more than MAX_SETS sets");
        let dropped = dropped.fingerprint();
        state.retired.retain(|held| held != &dropped);
        state.retired.insert(0, dropped);
    }
    state.retired.truncate(MAX_RETIRED);
    MergeOutcome::Added
}

/// An image from a registry this deployment approves, with an optional tag
/// and a mandatory `@sha256:` digest ([`APPROVED_IMAGE_NAME_PATTERN`]).
pub fn is_approved_image(image: &str) -> bool {
    approved_by(
        super::runtime_images::configured().approved_registries(),
        image,
    )
}

/// Whether any of `registries` prefixes `image` and the rest is an approved
/// name, as the admission policy's `exists` evaluates it.
fn approved_by(registries: &[String], image: &str) -> bool {
    registries.iter().any(|registry| {
        image
            .strip_prefix(registry.as_str())
            .is_some_and(approved_name)
    })
}

fn approved_name(rest: &str) -> bool {
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

/// Render inputs that are not image sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderConfig {
    pub namespace: String,
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

/// The idle container's command, from the pinned DinD image's own BusyBox.
pub fn idle_command() -> Vec<String> {
    vec!["/bin/busybox".into(), "sleep".into(), IDLE_SECONDS.into()]
}

/// Unique images across the held sets, newest release first.
pub fn cached_images(sets: &[ImageSet]) -> Vec<String> {
    let mut images: Vec<String> = Vec::new();
    for image in sets.iter().flat_map(|set| &set.images) {
        if !images.contains(image) {
            images.push(image.clone());
        }
    }
    images
}

/// The cached images held as image volumes: every cached image except the
/// idle image, which the container itself keeps in use.
pub fn volume_images(sets: &[ImageSet]) -> Vec<String> {
    cached_images(sets)
        .into_iter()
        .filter(|image| image != IMAGE_CACHE_IDLE_IMAGE)
        .take(MAX_CACHED_IMAGES)
        .collect()
}

/// The DaemonSet `spec` for `sets` (newest release first).
pub fn render_spec(sets: &[ImageSet]) -> Value {
    let images = volume_images(sets);
    let name = |index: usize| format!("image-{index}");
    let volumes: Vec<Value> = images
        .iter()
        .enumerate()
        .map(|(index, image)| {
            json!({
                "name": name(index),
                "image": { "reference": image, "pullPolicy": "IfNotPresent" },
            })
        })
        .collect();
    let mounts: Vec<Value> = (0..images.len())
        .map(|index| {
            json!({
                "name": name(index),
                "mountPath": format!("{IMAGE_VOLUME_ROOT}/{}", name(index)),
                "readOnly": true,
            })
        })
        .collect();
    let node_selector: serde_json::Map<String, Value> = IMAGE_CACHE_NODE_SELECTOR
        .iter()
        .map(|(key, value)| ((*key).to_owned(), Value::from(*value)))
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
                "hostUsers": false,
                "imagePullSecrets": [ { "name": IMAGE_CACHE_PULL_SECRET } ],
                "nodeSelector": node_selector,
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
                "containers": [
                    {
                        "name": IDLE_CONTAINER,
                        "image": IMAGE_CACHE_IDLE_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": idle_command(),
                        "securityContext": container_security_context(),
                        "resources": container_resources(),
                        "volumeMounts": mounts,
                    },
                ],
                "volumes": volumes,
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
    let spec = render_spec(&state.sets);
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
///
/// Any Pod may add or promote its own set. Only the Pod whose set is current
/// (`sets[0]`) repairs render-only drift, so two releases never fight over
/// the Pod shape.
pub fn plan(cfg: &RenderConfig, live: Option<&Value>, desired: &DesiredSet) -> Plan {
    let annotation = live
        .and_then(|live| live.pointer("/metadata/annotations"))
        .and_then(|annotations| annotations.get(IMAGE_CACHE_STATE_ANNOTATION))
        .and_then(Value::as_str);
    let parsed = annotation
        .and_then(|annotation| CacheState::parse(annotation).ok())
        .unwrap_or_default();
    if desired.images.is_empty() {
        return Plan::Keep { state: parsed };
    }
    let Some(live) = live else {
        let mut state = CacheState::default();
        merge(&mut state, desired);
        let (daemon_set, state) = render_daemon_set(cfg, &state);
        return Plan::Create { daemon_set, state };
    };
    // A newer renderer's record is never rewritten, even when this Pod
    // cannot read it.
    let recorded_version = annotation
        .and_then(|annotation| serde_json::from_str::<Value>(annotation).ok())
        .and_then(|record| record["version"].as_u64())
        .unwrap_or(0);
    if recorded_version > u64::from(IMAGE_CACHE_RENDER_VERSION) {
        return if parsed.position(desired).is_some() {
            Plan::Keep { state: parsed }
        } else {
            Plan::Superseded { state: parsed }
        };
    }
    // A missing or unreadable record means someone else wrote the object;
    // start again from this Pod's set rather than trust it.
    let mut state = parsed;
    match merge(&mut state, desired) {
        MergeOutcome::Superseded => Plan::Superseded { state },
        MergeOutcome::Added | MergeOutcome::Promoted => {
            let (daemon_set, state) = render_daemon_set(cfg, &state);
            Plan::Replace { daemon_set, state }
        }
        MergeOutcome::Present => {
            let (daemon_set, rendered) = render_daemon_set(cfg, &state);
            let drifted = state.version != IMAGE_CACHE_RENDER_VERSION
                || state.spec_sha256 != rendered.spec_sha256
                || live_images(live) != live_images(&daemon_set);
            if drifted && state.position(desired) == Some(0) {
                Plan::Replace {
                    daemon_set,
                    state: rendered,
                }
            } else {
                Plan::Keep { state }
            }
        }
    }
}

/// Container images and image volume references, in order; detects edits
/// the annotation does not record.
fn live_images(daemon_set: &Value) -> Vec<String> {
    let spec = daemon_set.pointer("/spec/template/spec");
    let list = |field: &str| {
        spec.and_then(|spec| spec.get(field))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let mut images = Vec::new();
    for container in list("initContainers").iter().chain(&list("containers")) {
        images.push(container["image"].as_str().unwrap_or_default().to_owned());
    }
    for volume in list("volumes") {
        images.push(
            volume
                .pointer("/image/reference")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        );
    }
    images
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

    const WORKSPACE: &str = "registry.example.invalid/codewire/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const DIND: &str = DEFAULT_DIND_IMAGE;
    // The support image's repository before its rename to `codewire/daemon`:
    // the render history hashes below are computed over these references.
    const GATEWAY_A: &str = "registry.example.invalid/codewire/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const GATEWAY_B: &str = "registry.example.invalid/codewire/gateway@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GATEWAY_C: &str = "registry.example.invalid/codewire/gateway@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    /// Every render version with the spec hash of the canonical render
    /// ([`canonical_state`]). A render change alters the hash; append the new
    /// hash under a bumped `IMAGE_CACHE_RENDER_VERSION`.
    const RENDER_HISTORY: &[(u32, &str)] = &[
        // One idle container per image, BusyBox copied into an emptyDir.
        (
            1,
            "d1f20498b4b3d5d2dd156333b012a6dd89ee6cbab09a7e00c1ff435db341cf8e",
        ),
        // One idle DinD container; cached images as image volumes. Hashed
        // again when the fixture images moved to registry.example.invalid.
        (
            2,
            "24964f5c4e40dcb0442b5ae3ea94479d6ad0086e3e59f487e0034e88f175e401",
        ),
        // The idle container's DinD image moved from Docker 29.7.1 to 29.9.2
        // (CVE-2026-92543, #3208); the admission policy names only the new
        // one, so an older renderer must not rewrite it back.
        (
            3,
            "7d637330553048a399b72c9a1c38ace76f8c0c3eae91c9145291a5daae5c425f",
        ),
    ];

    fn cfg() -> RenderConfig {
        RenderConfig {
            namespace: "dev-sandboxes".into(),
        }
    }

    /// A release's set, independent of the runtime image constants except
    /// the DinD idle image, which is part of the render.
    fn release(gateway: &str, revision: u64) -> DesiredSet {
        DesiredSet {
            images: vec![WORKSPACE.into(), gateway.into(), DIND.into()],
            skipped: 0,
            release: revision,
        }
    }

    fn canonical_state() -> CacheState {
        let mut state = CacheState::default();
        merge(&mut state, &release(GATEWAY_A, 1));
        merge(&mut state, &release(GATEWAY_B, 2));
        state
    }

    fn state_of(daemon_set: &Value) -> CacheState {
        CacheState::parse(
            daemon_set["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    fn gateways(daemon_set: &Option<Value>) -> Vec<Vec<String>> {
        state_of(daemon_set.as_ref().unwrap())
            .sets
            .iter()
            .map(|set| {
                set.images
                    .iter()
                    .filter(|image| image.contains("/gateway@"))
                    .cloned()
                    .collect()
            })
            .collect()
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
        let (live, _) = apply(None, &release(GATEWAY_A, 1));
        let (live, _) = apply(live, &release(GATEWAY_B, 2));
        crate::test_golden::assert_golden("image-cache-daemonset.golden.json", &live.unwrap());
    }

    #[test]
    fn render_changes_bump_the_render_version() {
        let (version, hash) = RENDER_HISTORY.last().unwrap();
        assert_eq!(
            *version, IMAGE_CACHE_RENDER_VERSION,
            "RENDER_HISTORY must end at IMAGE_CACHE_RENDER_VERSION"
        );
        assert_eq!(
            spec_sha256(&render_spec(&canonical_state().sets)),
            *hash,
            "the rendered Pod shape changed: bump IMAGE_CACHE_RENDER_VERSION and append \
             its new hash to RENDER_HISTORY, so older renderers stop rewriting it"
        );
        for pair in RENDER_HISTORY.windows(2) {
            assert!(pair[0].0 < pair[1].0 && pair[0].1 != pair[1].1);
        }
    }

    #[test]
    fn desired_set_is_workspace_daemon_and_dind() {
        let daemon = crate::sandbox::template::TEST_SUPPORT_IMAGE;
        let set = DesiredSet::from_rendered(daemon, "");
        assert_eq!(
            set.images,
            [
                canonical_workspace_runtime_image(),
                daemon,
                DEFAULT_DIND_IMAGE
            ]
        );
        assert_eq!(set.skipped, 0);
        assert!(set.images.len() <= MAX_SET_IMAGES);
    }

    #[test]
    fn unpinned_or_unapproved_references_are_skipped() {
        // Kind renders a side-loaded daemon tag and a local DinD alias.
        let set = DesiredSet::from_rendered(
            "codewire-daemon:e2e",
            "localhost/codewire-ci/docker-dind:verified-66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e",
        );
        assert_eq!(set.images, [canonical_workspace_runtime_image()]);
        assert_eq!(set.skipped, 2);
    }

    #[test]
    fn approved_images_match_the_admission_expression() {
        for image in [
            canonical_workspace_runtime_image(),
            DEFAULT_DIND_IMAGE,
            GATEWAY_A,
            "docker.io/library/busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(is_approved_image(image), "{image}");
        }
        for image in [
            "codewire-daemon:e2e",
            "registry.example.invalid/codewire/daemon:main",
            "docker.io/library/docker:29-dind",
            crate::sandbox::PUBLIC_CANONICAL_WORKSPACE_RUNTIME_IMAGE,
            "docker.io/evil/docker@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid.evil/x@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid/codewire/daemon@sha256:E8FAAD5A8DC5279DFF929AFC5449F2791736912FFF9F99351D742DB2FAD01B4C",
            "registry.example.invalid/codewire/daemon@sha256:e8faad",
            "registry.example.invalid//daemon@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid/Codewire/daemon@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid/codewire/daemon:@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
            "registry.example.invalid/codewire/daemon:-x@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",
        ] {
            assert!(!is_approved_image(image), "{image}");
        }
        // Like the policy's `exists`, any approved prefix may admit an image,
        // not only the first that matches it.
        let nested = [
            "registry.example.invalid/".to_owned(),
            "registry.example.invalid/team/".to_owned(),
        ];
        let image = "registry.example.invalid/team/x@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c";
        assert!(approved_by(&nested, image));
        assert!(approved_by(&[nested[1].clone(), nested[0].clone()], image));
        assert!(!approved_by(&[], image));
    }

    #[test]
    fn first_reconcile_creates_one_set_and_repeats_keep_it() {
        let (live, action) = apply(None, &release(GATEWAY_A, 1));
        assert_eq!(action, "create");
        let state = state_of(live.as_ref().unwrap());
        assert_eq!(state.generation, 1);
        assert_eq!(state.sets.len(), 1);
        assert_eq!(state.version, IMAGE_CACHE_RENDER_VERSION);
        let (_, action) = apply(live, &release(GATEWAY_A, 1));
        assert_eq!(action, "keep");
    }

    #[test]
    fn rolling_deploy_keeps_current_and_previous_and_never_downgrades() {
        let (live, _) = apply(None, &release(GATEWAY_A, 1));
        // Release B rolls out: its Pods add B; A's Pods keep running on A.
        let (live, action) = apply(live, &release(GATEWAY_B, 2));
        assert_eq!(action, "replace");
        assert_eq!(gateways(&live), [[GATEWAY_B], [GATEWAY_A]]);
        assert_eq!(apply(live.clone(), &release(GATEWAY_A, 1)).1, "keep");
        assert_eq!(apply(live.clone(), &release(GATEWAY_B, 2)).1, "keep");

        // Release C retires A.
        let (live, action) = apply(live, &release(GATEWAY_C, 3));
        assert_eq!(action, "replace");
        assert_eq!(gateways(&live), [[GATEWAY_C], [GATEWAY_B]]);
        let state = state_of(live.as_ref().unwrap());
        assert_eq!(state.retired, [release(GATEWAY_A, 1).fingerprint()]);
        assert!(!cached_images(&state.sets).contains(&GATEWAY_A.to_owned()));

        // A lingering Pod of A never evicts the newer sets.
        let (after, action) = apply(live.clone(), &release(GATEWAY_A, 1));
        assert_eq!(action, "superseded");
        assert_eq!(after, live);
        assert_eq!(apply(live, &release(GATEWAY_B, 2)).1, "keep");
    }

    #[test]
    fn a_late_old_release_cannot_evict_the_previous_set() {
        // B's Pod was slow and first reconciles after C and D: B was never
        // held, so only its older release keeps it out.
        let (live, _) = apply(None, &release(GATEWAY_C, 3));
        let d = "registry.example.invalid/codewire/gateway@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let (live, _) = apply(live, &release(d, 5));
        let (after, action) = apply(live.clone(), &release(GATEWAY_B, 2));
        assert_eq!(action, "superseded");
        assert_eq!(after, live);
        assert_eq!(gateways(&live), [[d], [GATEWAY_C]]);
        // A release between the held ones replaces only the older one.
        let (live, action) = apply(live, &release(GATEWAY_A, 4));
        assert_eq!(action, "replace");
        assert_eq!(gateways(&live), [[d], [GATEWAY_A]]);
    }

    #[test]
    fn a_rollback_promotes_the_held_previous_set() {
        let (live, _) = apply(None, &release(GATEWAY_B, 2));
        let (live, _) = apply(live, &release(GATEWAY_C, 3));
        // Rolling back to B gives its ReplicaSet revision 4.
        let (live, action) = apply(live, &release(GATEWAY_B, 4));
        assert_eq!(action, "replace");
        assert_eq!(gateways(&live), [[GATEWAY_B], [GATEWAY_C]]);
        assert_eq!(state_of(live.as_ref().unwrap()).sets[0].release, 4);
        assert_eq!(apply(live, &release(GATEWAY_C, 3)).1, "keep");
    }

    #[test]
    fn only_the_current_release_repairs_render_drift() {
        let (live, _) = apply(None, &release(GATEWAY_A, 1));
        let (live, _) = apply(live, &release(GATEWAY_B, 2));
        let mut edited = live.unwrap();
        edited["spec"]["template"]["spec"]["volumes"][0]["image"]["reference"] =
            "docker.io/library/busybox@sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        assert!(matches!(
            plan(&cfg(), Some(&edited), &release(GATEWAY_A, 1)),
            Plan::Keep { .. }
        ));
        assert!(matches!(
            plan(&cfg(), Some(&edited), &release(GATEWAY_B, 2)),
            Plan::Replace { .. }
        ));

        let mut stale = edited.clone();
        let mut state = state_of(&stale);
        state.spec_sha256 = "stale".into();
        stale["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION] =
            serde_json::to_string(&state).unwrap().into();
        assert!(matches!(
            plan(&cfg(), Some(&stale), &release(GATEWAY_A, 1)),
            Plan::Keep { .. }
        ));
    }

    #[test]
    fn retired_history_is_bounded_and_deduplicated() {
        let mut state = CacheState::default();
        for index in 0..40u64 {
            let daemon = format!("registry.example.invalid/codewire/daemon@sha256:{index:064x}");
            assert_eq!(
                merge(&mut state, &release(&daemon, index + 1)),
                MergeOutcome::Added
            );
        }
        assert_eq!(state.sets.len(), MAX_SETS);
        assert_eq!(state.retired.len(), MAX_RETIRED);
        assert_eq!(state.generation, 40);
        let unique: BTreeSet<_> = state.retired.iter().collect();
        assert_eq!(unique.len(), MAX_RETIRED);
    }

    #[test]
    fn unknown_releases_fall_back_to_arrival_order() {
        let mut state = CacheState::default();
        merge(&mut state, &release(GATEWAY_A, 0));
        merge(&mut state, &release(GATEWAY_B, 0));
        assert_eq!(state.sets[0].images[1], GATEWAY_B);
        assert_eq!(
            merge(&mut state, &release(GATEWAY_C, 0)),
            MergeOutcome::Added
        );
        assert_eq!(state.sets[0].images[1], GATEWAY_C);
        assert_eq!(
            merge(&mut state, &release(GATEWAY_A, 0)),
            MergeOutcome::Superseded
        );
    }

    #[test]
    fn shared_images_across_sets_are_cached_once_and_bounded() {
        let state = canonical_state();
        assert_eq!(
            cached_images(&state.sets),
            [WORKSPACE, GATEWAY_B, DIND, GATEWAY_A]
        );
        let mut disjoint = CacheState::default();
        for (index, digit) in ["1", "2"].iter().enumerate() {
            let image = |name: &str| {
                format!(
                    "registry.example.invalid/codewire/{name}@sha256:{}",
                    digit.repeat(64)
                )
            };
            merge(
                &mut disjoint,
                &DesiredSet {
                    images: vec![image("workspace"), image("daemon"), image("dind")],
                    skipped: 0,
                    release: index as u64 + 1,
                },
            );
        }
        let spec = render_spec(&disjoint.sets);
        let pod = &spec["template"]["spec"];
        assert_eq!(pod["volumes"].as_array().unwrap().len(), MAX_CACHED_IMAGES);
        assert_eq!(
            pod["containers"][0]["volumeMounts"]
                .as_array()
                .unwrap()
                .len(),
            MAX_CACHED_IMAGES
        );
        // The idle image is the container's, never also a volume.
        assert_eq!(
            volume_images(&state.sets),
            [WORKSPACE, GATEWAY_B, GATEWAY_A]
        );
    }

    #[test]
    fn a_newer_renderer_is_never_overwritten() {
        let (live, _) = apply(None, &release(GATEWAY_A, 1));
        let mut live = live.unwrap();
        let mut state = state_of(&live);
        state.version = IMAGE_CACHE_RENDER_VERSION + 1;
        live["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION] =
            serde_json::to_string(&state).unwrap().into();
        assert_eq!(apply(Some(live.clone()), &release(GATEWAY_A, 1)).1, "keep");
        assert_eq!(
            apply(Some(live.clone()), &release(GATEWAY_B, 2)).1,
            "superseded"
        );
        // Even a newer record this renderer cannot parse is left alone.
        let newer = json!({ "version": IMAGE_CACHE_RENDER_VERSION + 1, "sets": "reshaped" });
        live["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION] = newer.to_string().into();
        assert_eq!(apply(Some(live), &release(GATEWAY_A, 1)).1, "superseded");
    }

    #[test]
    fn an_unreadable_record_is_rewritten_from_this_set() {
        let (live, _) = apply(None, &release(GATEWAY_A, 1));
        let mut foreign = live.unwrap();
        foreign["metadata"]["annotations"][IMAGE_CACHE_STATE_ANNOTATION] = "{".into();
        let Plan::Replace { state, .. } = plan(&cfg(), Some(&foreign), &release(GATEWAY_A, 1))
        else {
            panic!("an unreadable record is rewritten");
        };
        assert_eq!(state.sets.len(), 1);
    }

    #[test]
    fn state_parse_rejects_unapproved_or_oversized_records() {
        let state = canonical_state();
        let mut bad = state.clone();
        bad.sets[0].images.push("docker.io/evil/x:latest".into());
        assert!(CacheState::parse(&serde_json::to_string(&bad).unwrap()).is_err());
        let mut bad = state.clone();
        bad.sets[0].images.push(GATEWAY_C.into());
        assert!(CacheState::parse(&serde_json::to_string(&bad).unwrap()).is_err());
        let mut bad = state;
        bad.sets = vec![bad.sets[0].clone(); 3];
        assert!(CacheState::parse(&serde_json::to_string(&bad).unwrap()).is_err());
    }

    #[test]
    fn pod_shape_is_runc_tokenless_unprivileged_and_scoped_to_runtime_nodes() {
        let spec = render_spec(&canonical_state().sets);
        let pod = &spec["template"]["spec"];
        assert!(pod.get("runtimeClassName").is_none());
        assert_eq!(pod["serviceAccountName"], IMAGE_CACHE_SERVICE_ACCOUNT);
        assert_ne!(
            pod["serviceAccountName"],
            crate::sandbox::template::SANDBOX_SERVICE_ACCOUNT
        );
        assert_eq!(pod["automountServiceAccountToken"], false);
        assert_eq!(pod["hostUsers"], false);
        for field in ["hostNetwork", "hostPID", "hostIPC", "priorityClassName"] {
            assert!(pod.get(field).is_none(), "{field}");
        }
        assert_eq!(
            pod["nodeSelector"],
            json!({
                "katacontainers.io/kata-runtime": "true",
                "node.codewire.sh/runtime-candidate": "true",
            })
        );
        assert!(pod.get("initContainers").is_none());
        let containers = pod["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1);
        let idle = &containers[0];
        assert_eq!(idle["image"], IMAGE_CACHE_IDLE_IMAGE);
        assert_eq!(idle["command"], json!(idle_command()));
        assert_eq!(idle["securityContext"], container_security_context());
        assert_eq!(idle["resources"], container_resources());
        assert!(idle.get("env").is_none() && idle.get("ports").is_none());
        let volumes = pod["volumes"].as_array().unwrap();
        let mounts = idle["volumeMounts"].as_array().unwrap();
        assert_eq!(volumes.len(), mounts.len());
        for (volume, mount) in volumes.iter().zip(mounts) {
            // Every image volume is mounted, so the kubelet counts it in use.
            assert_eq!(volume["name"], mount["name"]);
            assert!(is_approved_image(
                volume["image"]["reference"].as_str().unwrap()
            ));
            assert_eq!(volume["image"]["pullPolicy"], "IfNotPresent");
            assert_eq!(mount["readOnly"], true);
            assert_eq!(
                mount["mountPath"],
                format!("{IMAGE_VOLUME_ROOT}/{}", volume["name"].as_str().unwrap())
            );
            assert_eq!(volume.as_object().unwrap().len(), 2, "image volumes only");
        }
        assert_eq!(
            spec["updateStrategy"]["rollingUpdate"],
            json!({ "maxUnavailable": 0, "maxSurge": 1 })
        );
    }

    /// The policy approves exactly what [`is_approved_image`] does: it reads
    /// `CODEWIRE_APPROVED_IMAGE_REGISTRIES` from the ConfigMap orchestration
    /// reads it from, keeps the entries [`APPROVED_REGISTRY_PATTERN`]
    /// accepts, and matches the rest of a reference after any of them against
    /// [`APPROVED_IMAGE_NAME_PATTERN`].
    #[test]
    fn admission_policy_reads_the_registries_orchestration_reads() {
        use crate::sandbox::runtime_images::{
            APPROVED_IMAGE_REGISTRIES_ENV, APPROVED_REGISTRY_PATTERN,
        };
        let read = |path: &str| {
            std::fs::read_to_string(format!(
                "{}/../../deployments/k8s/orchestration/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect(path)
        };
        let config_map = "codewire-image-registries";
        let policy = read("image-cache-authz.yaml");
        for fragment in [
            "paramKind:\n    apiVersion: v1\n    kind: ConfigMap\n".to_owned(),
            format!(
                "paramRef:\n    name: {config_map}\n    namespace: prod\n    parameterNotFoundAction: Deny\n"
            ),
            format!(
                "has(params.data) && '{APPROVED_IMAGE_REGISTRIES_ENV}' in params.data ?\n        \
                 params.data['{APPROVED_IMAGE_REGISTRIES_ENV}'].split(',')\
                 .filter(r, r.matches('{APPROVED_REGISTRY_PATTERN}')) : []"
            ),
            "variables.registries.exists(r, v.image.reference.startsWith(r) &&\n        \
             v.image.reference.substring(size(r))"
                .to_owned(),
            format!(
                "v.image.reference.substring(size(r)).matches('{APPROVED_IMAGE_NAME_PATTERN}')"
            ),
        ] {
            assert!(policy.contains(&fragment), "policy does not pin {fragment}");
        }
        let registries = read("image-registries.yaml");
        assert!(registries.contains(&format!(
            "kind: ConfigMap\nmetadata:\n  name: {config_map}\n"
        )));
        assert!(registries.contains(&format!("\n  {APPROVED_IMAGE_REGISTRIES_ENV}: \"\"\n")));
        let deployment = read("deployment.yaml");
        assert!(deployment.contains(&format!(
            "- name: {APPROVED_IMAGE_REGISTRIES_ENV}\n              valueFrom:\n                \
             configMapKeyRef:\n                  name: {config_map}\n                  \
             key: {APPROVED_IMAGE_REGISTRIES_ENV}\n"
        )));
        // The pattern is the one valid_registry_prefix implements.
        for prefix in crate::sandbox::runtime_images::RuntimeImages::example().approved_registries()
        {
            assert!(crate::sandbox::runtime_images::valid_registry_prefix(
                prefix
            ));
        }
    }

    #[test]
    fn admission_policy_pins_the_rendered_shape() {
        let policy = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deployments/k8s/orchestration/image-cache-authz.yaml"
        ))
        .expect("image cache admission policy");
        let cel_list = |items: &[String]| {
            let quoted: Vec<String> = items.iter().map(|item| format!("'{item}'")).collect();
            format!("[{}]", quoted.join(", "))
        };
        let node_selector: Vec<String> = IMAGE_CACHE_NODE_SELECTOR
            .iter()
            .map(|(key, value)| format!("'{key}': '{value}'"))
            .collect();
        for fragment in [
            cel_list(&idle_command()),
            format!("c.image == '{IMAGE_CACHE_IDLE_IMAGE}'"),
            format!("size(variables.volumes) <= {MAX_CACHED_IMAGES}"),
            format!("m.mountPath == '{IMAGE_VOLUME_ROOT}/' + m.name"),
            format!("variables.pod.nodeSelector == {{{}}}", node_selector.join(", ")),
            format!("request.name == '{IMAGE_CACHE_NAME}'"),
            format!("variables.pod.serviceAccountName == '{IMAGE_CACHE_SERVICE_ACCOUNT}'"),
            format!("s.name == '{IMAGE_CACHE_PULL_SECRET}'"),
            format!("t.key == '{RUNTIME_CANDIDATE_TAINT_KEY}'"),
            "c.resources == {'requests': {'cpu': '1m', 'memory': '4Mi'}, 'limits': {'cpu': '10m', 'memory': '16Mi'}}".to_owned(),
        ] {
            assert!(policy.contains(&fragment), "policy does not pin {fragment}");
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
