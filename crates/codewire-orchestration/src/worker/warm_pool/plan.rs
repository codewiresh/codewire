//! Pure decisions of the warm-pool reconciler (Program #2238 C2): the node
//! cap, the image-cache gate, which pool objects to write and which unclaimed
//! members to delete. Nothing here reads or writes Kubernetes; the loop in
//! `super` observes, calls [`plan`] and executes the result.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use k8s_openapi::api::core::v1::{Node, Taint, Toleration};
use k8s_openapi::jiff::Timestamp;
use kube::api::DynamicObject;
use serde_json::Value;

use crate::sandbox::client::{parse_quantity_ratio, sandbox_name_hash};
use crate::sandbox::image_cache::{CacheState, cached_images, is_approved_image, rollout};
use crate::sandbox::warm_pool::{
    ConfiguredShape, MEMBER_POOL_LABEL, POOL_REVISION_ANNOTATION, TEMPLATE_REF_HASH_LABEL,
    WarmPoolObjects, has_pool_labels, is_warm_pool_name, shape_label, spec_equivalent,
    warm_pool_name_shape,
};
use crate::sandbox::{EXTENSIONS_API_VERSION, image_cache::IMAGE_CACHE_STATE_ANNOTATION};

/// An unclaimed member older than this is replaced, so a member never holds
/// a day-old image or node state when a claim adopts it.
pub const MEMBER_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Member deletions per pass. The controller refills at its own bounded rate;
/// this bounds how fast the reconciler can churn volumes.
pub const MAX_MEMBER_DELETES_PER_PASS: usize = 4;
/// Owner decision (2026-10-02): pools reserve at most a quarter of a runtime
/// node.
pub const NODE_RESERVATION_PERCENT: i128 = 25;
/// How long a template change counts as an in-progress rotation while its
/// pool refills. A rotation that has not settled by then stops blocking the
/// next shape, so one stuck shape cannot freeze every other pool.
pub const ROTATION_SETTLE: Duration = Duration::from_secs(10 * 60);
/// A pool of a configured shape at another revision that is newer than this
/// leader's own pool is the next release's, warming while this replica still
/// serves (#3572), and is left alone; once it is this old it is drained like
/// an older one, so a rolled-back release never leaves it running. A rollout
/// replaces this replica within the readiness bound of its warm-up.
pub const SUPERSEDED_GRACE: Duration = Duration::from_secs(15 * 60);
/// The fork removes this from an adopted Sandbox; it never marks staleness.
const SAFE_TO_EVICT_ANNOTATION: &str = "cluster-autoscaler.kubernetes.io/safe-to-evict";

/// One configured pool, rendered by this replica from its own configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct DesiredPool {
    pub configured: ConfiguredShape,
    pub objects: WarmPoolObjects,
}

impl DesiredPool {
    pub fn label(&self) -> String {
        shape_label(self.configured.shape)
    }
}

/// What one member reserves on its node: its effective Pod requests plus the
/// RuntimeClass overhead, as the scheduler counts them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reservation {
    pub cpu_millis: i128,
    pub memory_bytes: i128,
}

/// What all pools together may reserve.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    pub cpu_millis: i128,
    pub memory_bytes: i128,
}

/// A quantity in thousandths of its unit (CPU millicores), rounded up.
pub fn quantity_millis(quantity: &str) -> Option<i128> {
    let (numerator, denominator) = parse_quantity_ratio(quantity)?;
    let scaled = numerator.checked_mul(1000)?;
    Some((scaled + denominator - 1) / denominator)
}

/// A quantity in whole units (memory bytes), rounded up.
pub fn quantity_units(quantity: &str) -> Option<i128> {
    let (numerator, denominator) = parse_quantity_ratio(quantity)?;
    Some((numerator + denominator - 1) / denominator)
}

/// Requests of one container; an absent request is zero. `None` when a
/// present request cannot be parsed, which refuses the pool rather than
/// under-counting it.
fn container_requests(container: &Value) -> Option<Reservation> {
    let requests = container.pointer("/resources/requests");
    let read = |name: &str, parse: fn(&str) -> Option<i128>| -> Option<i128> {
        match requests.and_then(|requests| requests.get(name)) {
            None => Some(0),
            Some(value) => parse(value.as_str()?),
        }
    };
    Some(Reservation {
        cpu_millis: read("cpu", quantity_millis)?,
        memory_bytes: read("memory", quantity_units)?,
    })
}

/// Each RuntimeClass's fixed Pod overhead, by class name.
pub type ClassOverheads = BTreeMap<String, BTreeMap<String, String>>;

/// The fixed overhead the scheduler adds to a Pod of `pod_spec`: its
/// RuntimeClass's, and none without one. `None` when the class was not read.
pub fn pod_overhead<'a>(
    pod_spec: &Value,
    overheads: &'a ClassOverheads,
) -> Option<&'a BTreeMap<String, String>> {
    static NONE: BTreeMap<String, String> = BTreeMap::new();
    match pod_spec["runtimeClassName"].as_str() {
        Some(class) if !class.is_empty() => overheads.get(class),
        _ => Some(&NONE),
    }
}

/// The effective requests of a Pod spec (Kubernetes' rule: the larger of
/// the regular containers plus restartable sidecars, and each init container
/// plus the sidecars started before it), plus the RuntimeClass overhead.
pub fn member_reservation(
    pod_spec: &Value,
    overhead: &BTreeMap<String, String>,
) -> Option<Reservation> {
    let list = |field: &str| pod_spec[field].as_array().cloned().unwrap_or_default();
    let mut running = Reservation::default();
    for container in list("containers") {
        let requests = container_requests(&container)?;
        running.cpu_millis += requests.cpu_millis;
        running.memory_bytes += requests.memory_bytes;
    }
    let mut sidecars = Reservation::default();
    let mut init_peak = Reservation::default();
    for container in list("initContainers") {
        let requests = container_requests(&container)?;
        if container["restartPolicy"].as_str() == Some("Always") {
            sidecars.cpu_millis += requests.cpu_millis;
            sidecars.memory_bytes += requests.memory_bytes;
        } else {
            init_peak.cpu_millis = init_peak
                .cpu_millis
                .max(requests.cpu_millis + sidecars.cpu_millis);
            init_peak.memory_bytes = init_peak
                .memory_bytes
                .max(requests.memory_bytes + sidecars.memory_bytes);
        }
    }
    let overhead_cpu = match overhead.get("cpu") {
        Some(value) => quantity_millis(value)?,
        None => 0,
    };
    let overhead_memory = match overhead.get("memory") {
        Some(value) => quantity_units(value)?,
        None => 0,
    };
    Some(Reservation {
        cpu_millis: (running.cpu_millis + sidecars.cpu_millis).max(init_peak.cpu_millis)
            + overhead_cpu,
        memory_bytes: (running.memory_bytes + sidecars.memory_bytes).max(init_peak.memory_bytes)
            + overhead_memory,
    })
}

/// Whether a node can take a new member: Ready and not cordoned.
pub fn node_schedulable(node: &Node) -> bool {
    let cordoned = node
        .spec
        .as_ref()
        .and_then(|spec| spec.unschedulable)
        .unwrap_or(false);
    let ready = node
        .status
        .as_ref()
        .and_then(|status| status.conditions.as_deref())
        .unwrap_or_default()
        .iter()
        .any(|condition| condition.type_ == "Ready" && condition.status == "True");
    !cordoned && ready
}

/// Whether `toleration` tolerates `taint` (the scheduler's rule).
fn tolerates(toleration: &Toleration, taint: &Taint) -> bool {
    let effect_matches = toleration
        .effect
        .as_deref()
        .is_none_or(|effect| effect.is_empty() || effect == taint.effect);
    let key = toleration.key.as_deref().unwrap_or_default();
    let key_matches = match toleration.operator.as_deref() {
        Some("Exists") => key.is_empty() || key == taint.key,
        _ => {
            key == taint.key
                && toleration.value.as_deref().unwrap_or_default()
                    == taint.value.as_deref().unwrap_or_default()
        }
    };
    effect_matches && key_matches
}

/// Review M3: an unclaimed member's node can no longer hold it. The node is
/// gone, not Ready, cordoned, or carries a NoSchedule or NoExecute taint the
/// member's Pod does not tolerate. A claim adopting such a member would
/// stall, so it is replaced instead.
pub fn node_unfit(node: Option<&Node>, tolerations: &[Toleration]) -> bool {
    let Some(node) = node else {
        return true;
    };
    !node_schedulable(node)
        || node
            .spec
            .as_ref()
            .and_then(|spec| spec.taints.as_deref())
            .unwrap_or_default()
            .iter()
            .any(|taint| {
                matches!(taint.effect.as_str(), "NoSchedule" | "NoExecute")
                    && !tolerations
                        .iter()
                        .any(|toleration| tolerates(toleration, taint))
            })
}

/// Review L6: a lower budget applies only after it held for this many
/// passes, so one node flapping NotReady does not shrink every pool.
pub const BUDGET_DECREASE_PASSES: u8 = 3;

/// The budget to apply: a higher one at once, a lower one once it has been
/// observed for [`BUDGET_DECREASE_PASSES`] consecutive passes. Returns the
/// applied budget and the count of consecutive lower observations.
pub fn settle_budget(previous: Option<(Budget, u8)>, observed: Budget) -> (Budget, u8) {
    match previous {
        Some((applied, lower))
            if observed.cpu_millis < applied.cpu_millis
                || observed.memory_bytes < applied.memory_bytes =>
        {
            if lower + 1 >= BUDGET_DECREASE_PASSES {
                (observed, 0)
            } else {
                (applied, lower + 1)
            }
        }
        _ => (observed, 0),
    }
}

/// Review H1: whether the running agent-sandbox controller guards warm-pool
/// member deletes, adopts only current-revision members and marks a claim
/// Ready only after its Pod labels land (C0). The fork pin that carries C0
/// (`aacf9ba`) also carries upstream #1328 (`fa7f00f`), which records
/// `status.observedGeneration` on every SandboxWarmPool it reconciles; the
/// earlier `4c528d3` controller and its CRD have no such field, and the API
/// server would prune it. Any pool, an environment's zero-replica shadow
/// included, whose status observed its current generation is the evidence.
/// Without it, pools are held: nothing is replaced, scaled or deleted, and
/// only [`bootstrap_writes`] may create an empty pool.
pub fn controller_capable(pools: &[DynamicObject]) -> bool {
    pools.iter().any(pool_observed_by_capable_controller)
}

/// The held reconciler's only writes, on a cluster with no SandboxWarmPool at
/// all: there the controller has no pool to show its claim safety on, so the
/// hold would never end. Create the first configured pool's template, behind
/// the image-cache gate, and once it exists the pool itself with zero
/// members. An empty pool holds nothing an unguarded controller could delete
/// or adopt, and creates route cold until a capable controller observes it;
/// a capable one does, which ends the hold.
pub fn bootstrap_writes(
    desired: &[DesiredPool],
    templates: &BTreeMap<String, DynamicObject>,
    cache_warm: bool,
) -> Vec<Write> {
    let Some(first) = desired.first() else {
        return Vec::new();
    };
    let name = first.objects.name.clone();
    match templates.get(&name) {
        Some(template) if deleting(template) => Vec::new(),
        Some(_) => {
            let mut body = first.objects.pool.clone();
            body["spec"]["replicas"] = Value::from(0);
            vec![Write::CreatePool { name, body }]
        }
        None if cache_warm => vec![Write::CreateTemplate {
            name,
            body: first.objects.template.clone(),
        }],
        None => Vec::new(),
    }
}

/// One pool's status was written by a capable controller at its current
/// generation.
pub fn pool_observed_by_capable_controller(pool: &DynamicObject) -> bool {
    pool.data
        .pointer("/status/observedGeneration")
        .and_then(Value::as_i64)
        .is_some_and(|observed| observed >= 1 && Some(observed) == pool.metadata.generation)
}

/// Review L5: the live template is this replica's rendering, not only
/// labelled with its revision: its Pod template, volume claim templates and
/// network policy are [`spec_equivalent`] to the rendering's.
pub fn template_spec_current(live: &DynamicObject, rendered: &Value) -> bool {
    [
        "/spec/podTemplate",
        "/spec/volumeClaimTemplates",
        "/spec/networkPolicy",
    ]
    .into_iter()
    .all(|path| {
        spec_equivalent(
            rendered.pointer(path).unwrap_or(&Value::Null),
            live.data.pointer(path).unwrap_or(&Value::Null),
            path,
        )
        .is_ok()
    })
}

/// The owner's cap: [`NODE_RESERVATION_PERCENT`] of the smallest
/// schedulable runtime node, per resource. Members may all land on one node,
/// so the cap bounds the total against a single node. No schedulable node,
/// or an unreadable allocatable, is a zero budget.
pub fn node_budget(runtime_nodes: &[Node]) -> Budget {
    let mut smallest: Option<(i128, i128)> = None;
    for node in runtime_nodes.iter().filter(|node| node_schedulable(node)) {
        let allocatable = node
            .status
            .as_ref()
            .and_then(|status| status.allocatable.as_ref());
        let cpu = allocatable
            .and_then(|allocatable| allocatable.get("cpu"))
            .and_then(|quantity| quantity_millis(&quantity.0));
        let memory = allocatable
            .and_then(|allocatable| allocatable.get("memory"))
            .and_then(|quantity| quantity_units(&quantity.0));
        let (Some(cpu), Some(memory)) = (cpu, memory) else {
            return Budget::default();
        };
        smallest = Some(match smallest {
            None => (cpu, memory),
            Some((low_cpu, low_memory)) => (low_cpu.min(cpu), low_memory.min(memory)),
        });
    }
    let (cpu, memory) = smallest.unwrap_or_default();
    Budget {
        cpu_millis: cpu * NODE_RESERVATION_PERCENT / 100,
        memory_bytes: memory * NODE_RESERVATION_PERCENT / 100,
    }
}

/// Members each pool may hold under `budget`, in configuration order: each
/// pool gets its configured count, or as many as still fit. A pool whose
/// reservation could not be computed gets none.
pub fn clamp_members(
    pools: &[DesiredPool],
    reservations: &[Option<Reservation>],
    budget: Budget,
) -> Vec<i32> {
    let mut remaining = budget;
    pools
        .iter()
        .zip(reservations)
        .map(|(pool, reservation)| {
            let Some(reservation) = reservation
                .filter(|reservation| reservation.cpu_millis > 0 && reservation.memory_bytes > 0)
            else {
                return 0;
            };
            let fit = (remaining.cpu_millis / reservation.cpu_millis)
                .min(remaining.memory_bytes / reservation.memory_bytes)
                .max(0);
            let allowed = i128::from(pool.configured.members).min(fit);
            remaining.cpu_millis -= allowed * reservation.cpu_millis;
            remaining.memory_bytes -= allowed * reservation.memory_bytes;
            i32::try_from(allowed).unwrap_or(0)
        })
        .collect()
}

/// #3572: what the pools of configured shapes at other revisions still hold,
/// so the node cap counts them. While two revisions of a shape are live, the
/// outgoing leader shrinks its own pools for the incoming replica's warm-up
/// member, and the incoming leader grows its pool only as the old one drains.
/// A rotation therefore never reserves more than the cap, which keeps the room
/// customer creates need on a busy node. Members of the same shape reserve
/// what this replica's member of that shape does. A pool holds the larger of
/// its desired and its observed replicas, since a draining pool's members
/// remain until deleted.
pub fn superseded_reservation(
    desired: &[DesiredPool],
    reservations: &[Option<Reservation>],
    pools: &BTreeMap<String, DynamicObject>,
) -> Reservation {
    let mut held = Reservation::default();
    for (name, pool) in pools {
        if !has_pool_labels(pool.metadata.labels.as_ref())
            || desired.iter().any(|desired| desired.objects.name == *name)
        {
            continue;
        }
        let Some(shape) = warm_pool_name_shape(name) else {
            continue;
        };
        let Some(Some(reservation)) = desired
            .iter()
            .zip(reservations)
            .find(|(desired, _)| desired.configured.shape == shape)
            .map(|(_, reservation)| *reservation)
        else {
            continue;
        };
        let replicas = |pointer: &str| {
            pool.data
                .pointer(pointer)
                .and_then(Value::as_i64)
                .unwrap_or(0)
        };
        let members = i128::from(
            replicas("/spec/replicas")
                .max(replicas("/status/replicas"))
                .max(0),
        );
        held.cpu_millis += members * reservation.cpu_millis;
        held.memory_bytes += members * reservation.memory_bytes;
    }
    held
}

/// The node cap left after `held`, never below zero.
pub fn budget_after(budget: Budget, held: Reservation) -> Budget {
    Budget {
        cpu_millis: (budget.cpu_millis - held.cpu_millis).max(0),
        memory_bytes: (budget.memory_bytes - held.memory_bytes).max(0),
    }
}

/// The image-cache gate (A2b): every image the pools run that the cache can
/// hold is held in its current or previous set, and the DaemonSet rollout of
/// that spec is complete on every eligible node. Images the cache never
/// holds (not digest-pinned, or outside the approved registries) do not
/// block. A missing DaemonSet or an unreadable record is cold.
pub fn image_cache_warm(daemon_set: Option<&Value>, images: &[&str]) -> bool {
    let Some(daemon_set) = daemon_set else {
        return false;
    };
    let Some(state) = daemon_set
        .pointer("/metadata/annotations")
        .and_then(|annotations| annotations.get(IMAGE_CACHE_STATE_ANNOTATION))
        .and_then(Value::as_str)
        .and_then(|annotation| CacheState::parse(annotation).ok())
    else {
        return false;
    };
    let held = cached_images(&state.sets);
    images
        .iter()
        .filter(|image| is_approved_image(image))
        .all(|image| held.iter().any(|held| held == image))
        && rollout(daemon_set).complete
}

/// Why an unclaimed member is deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeleteReason {
    /// Its Pod's node is gone, not Ready, cordoned or tainted against it.
    NodeUnfit,
    /// Its pool is no longer configured.
    Unconfigured,
    /// It was built from an older template revision.
    Stale,
    /// It is older than [`MEMBER_MAX_AGE`].
    OverAge,
}

impl DeleteReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeUnfit => "node_unfit",
            Self::Unconfigured => "unconfigured",
            Self::Stale => "stale",
            Self::OverAge => "over_age",
        }
    }
}

/// One write. Every replace and delete carries the observed UID and
/// resourceVersion, so a concurrent change refuses it instead of losing it.
#[derive(Clone, Debug, PartialEq)]
pub enum Write {
    CreateTemplate {
        name: String,
        body: Value,
    },
    ReplaceTemplate {
        name: String,
        body: Value,
    },
    CreatePool {
        name: String,
        body: Value,
    },
    ReplacePool {
        name: String,
        body: Value,
    },
    DeleteMember {
        pool: String,
        name: String,
        uid: String,
        resource_version: String,
        reason: DeleteReason,
    },
    DeletePool {
        name: String,
        uid: String,
        resource_version: String,
    },
    DeleteTemplate {
        name: String,
        uid: String,
        resource_version: String,
    },
}

/// Everything one pass decides from.
pub struct Observed<'a> {
    pub desired: &'a [DesiredPool],
    /// Members each desired pool may hold after the node cap, aligned with
    /// `desired`.
    pub allowed_members: &'a [i32],
    pub templates: &'a BTreeMap<String, DynamicObject>,
    pub pools: &'a BTreeMap<String, DynamicObject>,
    /// Sandboxes labelled as some pool's member.
    pub members: &'a [DynamicObject],
    /// Member Pod name → where it runs.
    pub member_pods: &'a BTreeMap<String, Placement>,
    /// Runtime nodes by name.
    pub nodes: &'a BTreeMap<String, Node>,
    /// Pools a SandboxClaim names, when claims were read.
    pub referenced_pools: Option<&'a BTreeSet<String>>,
    /// Template-reference hashes live Sandboxes carry, when read. A template
    /// in use owns the NetworkPolicy its Pods run under.
    pub template_users: Option<&'a BTreeSet<String>>,
    pub cache_warm: bool,
    /// The pool whose template this leader last changed, and how long ago.
    pub rotation: Option<(&'a str, Duration)>,
    pub now: Timestamp,
}

/// Where a member Pod runs, and what it tolerates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Placement {
    pub node: String,
    pub tolerations: Vec<Toleration>,
}

/// Per-pool facts for metrics and logs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolReport {
    pub template_current: bool,
    pub blocked_by_cache: bool,
    pub blocked_by_rotation: bool,
    /// Unclaimed members the pool owns.
    pub members: i64,
    pub ready: i64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    pub writes: Vec<Write>,
    /// The configured pool whose template this plan creates or replaces.
    pub started_rotation: Option<String>,
    /// The remembered rotation has settled (or its pool is gone).
    pub rotation_settled: bool,
    pub reports: BTreeMap<String, PoolReport>,
    /// Unconfigured pools still present.
    pub unconfigured: BTreeSet<String>,
    /// Pools of a configured shape at another revision that this pass keeps
    /// (#3572): this leader's own pool is not ready yet, or they are a newer
    /// release's.
    pub superseded_kept: BTreeSet<String>,
}

fn revision(object: &DynamicObject) -> Option<&str> {
    object
        .metadata
        .annotations
        .as_ref()?
        .get(POOL_REVISION_ANNOTATION)
        .map(String::as_str)
}

fn deleting(object: &DynamicObject) -> bool {
    object.metadata.deletion_timestamp.is_some()
}

fn uid_and_version(object: &DynamicObject) -> Option<(String, String)> {
    Some((
        object.metadata.uid.clone().filter(|uid| !uid.is_empty())?,
        object
            .metadata
            .resource_version
            .clone()
            .filter(|version| !version.is_empty())?,
    ))
}

/// The unclaimed members a pool owns: labelled for it, controlled by its UID
/// and not terminating. An adopted member has lost both.
fn owned_members<'a>(
    pool_name: &str,
    pool: &DynamicObject,
    members: &'a [DynamicObject],
) -> Vec<&'a DynamicObject> {
    let hash = sandbox_name_hash(pool_name);
    let Some(pool_uid) = pool.metadata.uid.as_deref() else {
        return Vec::new();
    };
    members
        .iter()
        .filter(|member| {
            !deleting(member)
                && member
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(MEMBER_POOL_LABEL))
                    == Some(&hash)
                && member
                    .metadata
                    .owner_references
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .filter(|owner| owner.controller == Some(true))
                    .map(|owner| {
                        (
                            owner.api_version.as_str(),
                            owner.kind.as_str(),
                            owner.uid.as_str(),
                        )
                    })
                    .eq([(EXTENSIONS_API_VERSION, "SandboxWarmPool", pool_uid)])
        })
        .collect()
}

fn pod_annotations(object: &Value) -> BTreeMap<String, Value> {
    object
        .pointer("/spec/podTemplate/metadata/annotations")
        .and_then(Value::as_object)
        .map(|annotations| {
            annotations
                .iter()
                .filter(|(key, _)| key.as_str() != SAFE_TO_EVICT_ANNOTATION)
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// A member is stale when its Pod spec, Pod annotations or volume claim
/// templates differ from the live pool template's: the controller copied
/// them from an older revision. The controller stores its copy through typed
/// structs, so the comparison is [`spec_equivalent`], not byte equality.
pub fn member_stale(member: &DynamicObject, template: &DynamicObject) -> bool {
    let (member, template) = (&member.data, &template.data);
    let part = |object: &Value, path: &str| object.pointer(path).cloned().unwrap_or(Value::Null);
    ["/spec/podTemplate/spec", "/spec/volumeClaimTemplates"]
        .into_iter()
        .any(|path| spec_equivalent(&part(template, path), &part(member, path), path).is_err())
        || spec_equivalent(
            &Value::Object(pod_annotations(template).into_iter().collect()),
            &Value::Object(pod_annotations(member).into_iter().collect()),
            "/spec/podTemplate/metadata/annotations",
        )
        .is_err()
}

fn member_pod_name(member: &DynamicObject) -> Option<&str> {
    member
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get("agents.x-k8s.io/pod-name"))
        .map(String::as_str)
        .filter(|name| !name.is_empty())
        .or(member.metadata.name.as_deref())
}

fn over_age(member: &DynamicObject, now: Timestamp) -> bool {
    member
        .metadata
        .creation_timestamp
        .as_ref()
        .is_some_and(|created| {
            now.as_second().saturating_sub(created.0.as_second())
                >= i64::try_from(MEMBER_MAX_AGE.as_secs()).unwrap_or(i64::MAX)
        })
}

fn member_delete(pool: &str, member: &DynamicObject, reason: DeleteReason) -> Option<Write> {
    let (uid, resource_version) = uid_and_version(member)?;
    Some(Write::DeleteMember {
        pool: pool.to_owned(),
        name: member.metadata.name.clone()?,
        uid,
        resource_version,
        reason,
    })
}

/// The live pool with its replica count changed and nothing else.
fn with_replicas(pool: &DynamicObject, replicas: i32) -> Option<Value> {
    let mut body = serde_json::to_value(pool).ok()?;
    body.as_object_mut()?.remove("status");
    body["spec"]["replicas"] = Value::from(replicas);
    Some(body)
}

fn pool_matches(live: &DynamicObject, desired: &Value) -> bool {
    let fields = [
        "/spec/replicas",
        "/spec/sandboxTemplateRef/name",
        "/spec/updateStrategy/type",
    ];
    fields
        .iter()
        .all(|field| live.data.pointer(field) == desired.pointer(field))
        && revision(live)
            == desired
                .pointer("/metadata/annotations")
                .and_then(|annotations| {
                    annotations
                        .get(POOL_REVISION_ANNOTATION)
                        .and_then(Value::as_str)
                })
        && has_pool_labels(live.metadata.labels.as_ref())
}

fn created_at(object: &DynamicObject) -> Option<Timestamp> {
    object
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|created| created.0)
}

/// #3572: whether `pool`, a configured shape's pool at another revision than
/// this leader's `own`, may drain. Only once `own` has a ready member, and only
/// when `pool` is older than `own` or older than [`SUPERSEDED_GRACE`].
///
/// #3824: a shape this leader is configured to keep at zero (`wants_none`) has
/// no ready member to wait for, so `pool` drains by the same age rules; with no
/// own pool yet, only once it is older than the grace. The node cap's zero is
/// not this: the operator still wants members, and the old pool keeps serving.
fn superseded_drains(
    pool: &DynamicObject,
    own: Option<&DynamicObject>,
    wants_none: bool,
    now: Timestamp,
) -> bool {
    let Some(created) = created_at(pool) else {
        return false;
    };
    let past_grace =
        now.as_second().saturating_sub(created.as_second()) >= SUPERSEDED_GRACE.as_secs() as i64;
    match own.filter(|own| !deleting(own)) {
        Some(own) if wants_none || ready_replicas(own) >= 1 => {
            created_at(own).is_some_and(|own_created| created < own_created || past_grace)
        }
        None if wants_none => past_grace,
        _ => false,
    }
}

fn ready_replicas(pool: &DynamicObject) -> i64 {
    pool.data
        .pointer("/status/readyReplicas")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

/// Decide one pass.
///
/// - A configured pool's template is created or replaced only while the
///   image cache is warm for its images and no other pool is rotating, and at
///   most one template changes per pass: pools rotate one shape at a time.
/// - A pool is written only once its template is at this replica's revision;
///   before that, only a lower member count may be applied to it.
/// - Unclaimed members on cordoned nodes, of unconfigured pools, built from
///   an older template, or older than a day are deleted, a few per pass.
/// - An unconfigured pool is drained to zero members and removed, with its
///   template, only when no SandboxClaim names it.
pub fn plan(observed: &Observed<'_>) -> Plan {
    let mut plan = Plan::default();
    let mut deletes: Vec<Write> = Vec::new();
    let desired_names: BTreeSet<&str> = observed
        .desired
        .iter()
        .map(|pool| pool.objects.name.as_str())
        .collect();

    // Which pools are still rotating: stale members remain on a current
    // template, or this leader changed the template recently and the pool
    // has not refilled.
    let stale_members = |name: &str| -> bool {
        let (Some(pool), Some(template)) = (observed.pools.get(name), observed.templates.get(name))
        else {
            return false;
        };
        owned_members(name, pool, observed.members)
            .into_iter()
            .any(|member| member_stale(member, template))
    };
    // A pool not created yet has not refilled either.
    let remembered = observed.rotation.filter(|(name, elapsed)| {
        *elapsed < ROTATION_SETTLE
            && observed.pools.get(*name).is_none_or(|pool| {
                ready_replicas(pool)
                    < pool
                        .data
                        .pointer("/spec/replicas")
                        .and_then(Value::as_i64)
                        .unwrap_or(0)
            })
    });
    plan.rotation_settled = observed.rotation.is_some()
        && remembered.is_none()
        && observed
            .rotation
            .is_none_or(|(name, _)| !stale_members(name));
    let rotating: BTreeSet<&str> = observed
        .desired
        .iter()
        .map(|pool| pool.objects.name.as_str())
        .filter(|name| {
            remembered.is_some_and(|(remembered, _)| remembered == *name) || stale_members(name)
        })
        .collect();

    for (desired, allowed) in observed.desired.iter().zip(observed.allowed_members) {
        let name = desired.objects.name.as_str();
        let live_template = observed.templates.get(name);
        let live_pool = observed.pools.get(name);
        let mut report = PoolReport::default();
        if live_template.is_some_and(deleting) || live_pool.is_some_and(deleting) {
            plan.reports.insert(desired.label(), report);
            continue;
        }
        let template_current = live_template.is_some_and(|template| {
            revision(template) == Some(&desired.objects.revision)
                && template_spec_current(template, &desired.objects.template)
        });
        report.template_current = template_current;

        if !template_current {
            let others_rotating = rotating.iter().any(|other| *other != name);
            if !observed.cache_warm {
                report.blocked_by_cache = true;
            } else if others_rotating || plan.started_rotation.is_some() {
                report.blocked_by_rotation = true;
            } else {
                let mut body = desired.objects.template.clone();
                match live_template {
                    None => plan.writes.push(Write::CreateTemplate {
                        name: name.to_owned(),
                        body,
                    }),
                    Some(live) => {
                        body["metadata"]["resourceVersion"] =
                            Value::from(live.metadata.resource_version.clone().unwrap_or_default());
                        if let Some(hash) = live
                            .metadata
                            .labels
                            .as_ref()
                            .and_then(|labels| labels.get(TEMPLATE_REF_HASH_LABEL))
                        {
                            body["metadata"]["labels"][TEMPLATE_REF_HASH_LABEL] =
                                Value::from(hash.clone());
                        }
                        plan.writes.push(Write::ReplaceTemplate {
                            name: name.to_owned(),
                            body,
                        });
                    }
                }
                plan.started_rotation = Some(name.to_owned());
            }
            // A stale pool may only shrink until its template rotates.
            if let Some(pool) = live_pool {
                let live_replicas = pool
                    .data
                    .pointer("/spec/replicas")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                if i64::from(*allowed) < live_replicas
                    && let Some(body) = with_replicas(pool, *allowed)
                {
                    plan.writes.push(Write::ReplacePool {
                        name: name.to_owned(),
                        body,
                    });
                }
            }
        } else {
            let mut body = desired.objects.pool.clone();
            body["spec"]["replicas"] = Value::from(*allowed);
            match live_pool {
                None => plan.writes.push(Write::CreatePool {
                    name: name.to_owned(),
                    body,
                }),
                Some(live) if !pool_matches(live, &body) => {
                    body["metadata"]["resourceVersion"] =
                        Value::from(live.metadata.resource_version.clone().unwrap_or_default());
                    plan.writes.push(Write::ReplacePool {
                        name: name.to_owned(),
                        body,
                    });
                }
                Some(_) => {}
            }
        }

        if let Some(pool) = live_pool {
            let owned = owned_members(name, pool, observed.members);
            report.members = owned.len() as i64;
            report.ready = ready_replicas(pool);
            for member in owned {
                let on_unfit_node = member_pod_name(member)
                    .and_then(|pod| observed.member_pods.get(pod))
                    .is_some_and(|placement| {
                        node_unfit(observed.nodes.get(&placement.node), &placement.tolerations)
                    });
                let reason = if on_unfit_node {
                    Some(DeleteReason::NodeUnfit)
                } else if template_current
                    && live_template.is_some_and(|template| member_stale(member, template))
                {
                    Some(DeleteReason::Stale)
                } else if over_age(member, observed.now) {
                    Some(DeleteReason::OverAge)
                } else {
                    None
                };
                if let Some(write) = reason.and_then(|reason| member_delete(name, member, reason)) {
                    deletes.push(write);
                }
            }
        }
        plan.reports.insert(desired.label(), report);
    }

    // Unconfigured pools: drain, then remove once no claim names them.
    let mut removed_pools: BTreeSet<&str> = BTreeSet::new();
    for (name, pool) in observed.pools {
        if desired_names.contains(name.as_str())
            || !is_warm_pool_name(name)
            || !has_pool_labels(pool.metadata.labels.as_ref())
        {
            continue;
        }
        // #3572: a configured shape's pool at another revision keeps serving
        // the replicas that rendered it until this leader's own pool of that
        // shape is ready, or this leader is configured to keep none of it
        // (#3824), and a newer one is the next release's.
        let own = warm_pool_name_shape(name).and_then(|shape| {
            observed
                .desired
                .iter()
                .find(|desired| desired.configured.shape == shape)
        });
        if let Some(own) = own
            && !superseded_drains(
                pool,
                observed.pools.get(&own.objects.name),
                own.configured.members == 0,
                observed.now,
            )
        {
            plan.superseded_kept.insert(name.clone());
            continue;
        }
        plan.unconfigured.insert(name.clone());
        let owned = owned_members(name, pool, observed.members);
        if own.is_none()
            && let Some(shape) = warm_pool_name_shape(name)
        {
            plan.reports.insert(
                shape_label(shape),
                PoolReport {
                    members: owned.len() as i64,
                    ready: ready_replicas(pool),
                    ..PoolReport::default()
                },
            );
        }
        if deleting(pool) {
            continue;
        }
        let live_replicas = pool
            .data
            .pointer("/spec/replicas")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if live_replicas != 0 {
            // Stop the controller refilling before deleting members.
            if let Some(body) = with_replicas(pool, 0) {
                plan.writes.push(Write::ReplacePool {
                    name: name.clone(),
                    body,
                });
            }
            continue;
        }
        if !owned.is_empty() {
            deletes.extend(
                owned
                    .into_iter()
                    .filter_map(|member| member_delete(name, member, DeleteReason::Unconfigured)),
            );
            continue;
        }
        // Claims that were not read count as naming every pool.
        let referenced = observed
            .referenced_pools
            .is_none_or(|referenced| referenced.contains(name));
        if !referenced && let Some((uid, resource_version)) = uid_and_version(pool) {
            plan.writes.push(Write::DeletePool {
                name: name.clone(),
                uid,
                resource_version,
            });
            removed_pools.insert(name.as_str());
        }
    }
    for (name, template) in observed.templates {
        if desired_names.contains(name.as_str())
            || !is_warm_pool_name(name)
            || !has_pool_labels(template.metadata.labels.as_ref())
            || deleting(template)
        {
            continue;
        }
        let still_named = observed.pools.iter().any(|(pool_name, pool)| {
            !removed_pools.contains(pool_name.as_str())
                && (pool_name == name
                    || pool
                        .data
                        .pointer("/spec/sandboxTemplateRef/name")
                        .and_then(Value::as_str)
                        == Some(name.as_str()))
        });
        // Review L4: no claim may still name the pool of this template, and
        // no live Sandbox may still run under the NetworkPolicy the template
        // owns. Unread claims or users keep it.
        let claimed = observed
            .referenced_pools
            .is_none_or(|referenced| referenced.contains(name));
        let in_use = observed
            .template_users
            .is_none_or(|users| users.contains(&sandbox_name_hash(name)));
        if !still_named
            && !claimed
            && !in_use
            && let Some((uid, resource_version)) = uid_and_version(template)
        {
            plan.writes.push(Write::DeleteTemplate {
                name: name.clone(),
                uid,
                resource_version,
            });
        }
    }

    deletes.sort_by_key(|write| match write {
        Write::DeleteMember { reason, .. } => *reason,
        _ => DeleteReason::OverAge,
    });
    deletes.truncate(MAX_MEMBER_DELETES_PER_PASS);
    // Members go before their pool and template are removed.
    let removals: Vec<Write> = plan
        .writes
        .iter()
        .filter(|write| {
            matches!(
                write,
                Write::DeletePool { .. } | Write::DeleteTemplate { .. }
            )
        })
        .cloned()
        .collect();
    plan.writes.retain(|write| {
        !matches!(
            write,
            Write::DeletePool { .. } | Write::DeleteTemplate { .. }
        )
    });
    plan.writes.extend(deletes);
    plan.writes.extend(removals);
    plan
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
