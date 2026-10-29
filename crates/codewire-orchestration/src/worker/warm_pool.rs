//! The leader `warm-pool` reconciler (Program #2238 C2).
//!
//! For every shape in `SANDBOX_WARM_POOL_SHAPES` it keeps one shared,
//! identity-free SandboxTemplate and one SandboxWarmPool (`cw-pool-…`,
//! rendered by C1's `render_configured_warm_pool`) at this replica's
//! revision, with as many unclaimed members as the configuration and the
//! node cap allow. The agent-sandbox controller creates, refills and adopts
//! members; this loop decides what it may hold:
//!
//! - **Image-cache gate.** A template is created or changed only while A2b's
//!   `cw-image-cache` holds every cacheable pool image and its rollout is
//!   complete, so a rotation never pulls on the claim path. With
//!   `SANDBOX_IMAGE_CACHE=disabled` (Kind) the gate is open.
//! - **One shape at a time.** At most one template changes per pass, and not
//!   while another pool still holds stale members or has not refilled after
//!   its own change (bounded by `plan::ROTATION_SETTLE`).
//! - **Node cap.** All pools together reserve at most 25% of the smallest
//!   schedulable runtime node (owner decision, 2026-10-02): requests plus the
//!   RuntimeClass overhead, on nodes the RuntimeClass schedules to. Pools are
//!   clamped in configuration order, and each clamp is logged.
//! - **Member hygiene.** Unclaimed members on cordoned nodes, of unconfigured
//!   pools, built from an older template, or older than 24 hours are deleted
//!   with UID and resourceVersion preconditions, a few per pass. An adoption
//!   rewrites a member's owner and labels, so a racing delete is refused
//!   rather than garbage-collecting a claimed environment's volume.
//! - **Removal.** A pool that is no longer configured is drained to zero
//!   members and removed, with its template, only when no SandboxClaim names
//!   it (pool-born environments keep naming theirs).
//!
//! Inert by default: with `SANDBOX_WARM_POOL_SHAPES` empty or unset the loop
//! logs once and returns before it builds a Kubernetes API, so it reads and
//! writes nothing. An invalid value is logged and also reconciles nothing.
//!
//! The pinned agent-sandbox controller still lacks guarded member deletes,
//! current-revision adoption and Ready-after-labels (C0); configuration (C4)
//! follows the pin bump. Until a pool shows the controller's claim safety,
//! nothing is replaced, scaled or deleted; on a cluster with no
//! SandboxWarmPool at all, where no pool could show it, the first configured
//! pool is created empty ([`bootstrap_writes`]). The unbound members'
//! ingress is the template-owned NetworkPolicy the controller manages from
//! the template's `networkPolicy`: orchestration's identity alone on the
//! daemon and SSH ports, where nothing listens before the bind
//! (codewire#3626).
//!
//! Metrics carry the shape (`<cpu>m-<mem>mi-<disk>gi`), never an environment.

mod plan;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::{Node, Pod};
use k8s_openapi::api::node::v1::RuntimeClass;
use k8s_openapi::jiff::Timestamp;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, ListParams, PostParams, Preconditions,
};
use kube::core::GroupVersionKind;
use prometheus::{IntCounterVec, IntGauge, IntGaugeVec, Opts};
use prometheus::{register_int_counter_vec, register_int_gauge, register_int_gauge_vec};
use serde_json::Value;

use super::WorkerContext;
use super::create::{SandboxWorkerCfg, render_configured_warm_pool};
use super::image_cache::ImageCacheConfig;
use crate::sandbox::client::sandbox_name_hash;
use crate::sandbox::image_cache::IMAGE_CACHE_NAME;
use crate::sandbox::warm_pool::{
    LAUNCH_TYPE_LABEL, LAUNCH_TYPE_WARM, MEMBER_POOL_LABEL, TEMPLATE_REF_HASH_LABEL,
    has_pool_labels, is_warm_pool_name, parse_warm_pool_shapes, pod_template_images,
    pool_label_selector, shape_label, warm_pool_name_shape,
};
use crate::sandbox::{CRD_VERSION, EXTENSIONS_GROUP, SANDBOX_GROUP};
pub use plan::{
    Budget, DeleteReason, DesiredPool, Observed, Placement, Plan, Reservation, Write,
    bootstrap_writes, clamp_members, controller_capable, image_cache_warm, member_reservation,
    node_budget, node_unfit, pool_observed_by_capable_controller, settle_budget,
    template_spec_current,
};

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// What this replica reconciles toward.
#[derive(Clone, Debug, PartialEq)]
pub struct WarmPoolConfig {
    pub namespace: String,
    pub pools: Vec<DesiredPool>,
    /// `false` with `SANDBOX_IMAGE_CACHE=disabled`: nothing is cached, so the
    /// gate is open.
    pub image_cache_enabled: bool,
    /// The configuration was invalid: no pool is desired, so every existing
    /// pool drains (review L7).
    pub draining: bool,
}

/// What the loop does at startup.
#[derive(Debug, PartialEq)]
pub enum Startup {
    /// No shape configured: no Kubernetes access at all.
    Inert,
    Reconcile(WarmPoolConfig),
}

/// Decide startup. No shape configured is inert. A configured value that is
/// invalid, or that any renderer refusal rejects, never leaves existing pools
/// unmanaged: the reconciler runs with no desired pool, so each existing one
/// is drained and removed once unreferenced (review L7), still only on a
/// capable controller.
pub fn startup(cfg: &SandboxWorkerCfg, image_cache_enabled: anyhow::Result<bool>) -> Startup {
    if cfg.warm_pool_shapes.trim().is_empty() {
        return Startup::Inert;
    }
    match image_cache_enabled.and_then(|enabled| WarmPoolConfig::from_cfg(cfg, enabled)) {
        Ok(Some(config)) => Startup::Reconcile(config),
        Ok(None) => Startup::Inert,
        Err(error) => {
            config_valid_metric().set(0);
            tracing::error!(error = %format!("{error:#}"), "warm pools: invalid configuration; draining every existing pool");
            let namespace = cfg.sandbox_namespace.trim();
            if namespace.is_empty() {
                return Startup::Inert;
            }
            Startup::Reconcile(WarmPoolConfig {
                namespace: namespace.to_owned(),
                pools: Vec::new(),
                image_cache_enabled: false,
                draining: true,
            })
        }
    }
}

impl WarmPoolConfig {
    /// `Ok(None)` when no shape is configured. Every configured shape renders
    /// through C1's identity-free renderer, so a missing binding listener, a
    /// confidential or unmanaged runtime, or an unpinned image outside a
    /// diagnostic cluster refuses the whole configuration.
    pub fn from_cfg(
        cfg: &SandboxWorkerCfg,
        image_cache_enabled: bool,
    ) -> anyhow::Result<Option<Self>> {
        let configured = parse_warm_pool_shapes(&cfg.warm_pool_shapes)?;
        if configured.is_empty() {
            return Ok(None);
        }
        let namespace = cfg.sandbox_namespace.trim();
        anyhow::ensure!(!namespace.is_empty(), "sandbox namespace is not configured");
        let pools = configured
            .into_iter()
            .map(|configured| {
                Ok(DesiredPool {
                    objects: render_configured_warm_pool(
                        cfg,
                        configured.shape,
                        configured.members,
                    )?,
                    configured,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Some(Self {
            namespace: namespace.to_owned(),
            pools,
            image_cache_enabled,
            draining: false,
        }))
    }

    /// Every image the pools run or mount.
    pub fn images(&self) -> Vec<&str> {
        let mut images: Vec<&str> = Vec::new();
        for pool in &self.pools {
            for image in pod_template_images(&pool.objects.template["spec"]["podTemplate"]["spec"])
            {
                if !images.contains(&image) {
                    images.push(image);
                }
            }
        }
        images
    }

    /// The RuntimeClass every pool renders (they share this replica's
    /// runtime profile).
    pub fn runtime_class(&self) -> Option<&str> {
        self.pools
            .first()?
            .objects
            .template
            .pointer("/spec/podTemplate/spec/runtimeClassName")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
    }
}

/// Leader-gated; runs until the process exits. Inert without configuration.
pub async fn warm_pool_loop(ctx: Arc<WorkerContext>, is_leader: Arc<AtomicBool>) {
    let image_cache_enabled =
        ImageCacheConfig::from_env(&ctx.sandbox_cfg).map(|config| config.is_some());
    let config = match startup(&ctx.sandbox_cfg, image_cache_enabled) {
        Startup::Reconcile(config) => config,
        Startup::Inert => {
            tracing::info!("warm pools: no shapes configured; the reconciler is inert");
            return;
        }
    };
    if config.draining {
        record_result(PassResult::InvalidConfig);
    } else {
        config_valid_metric().set(1);
    }
    let Some(client) = ctx.kube.clone() else {
        tracing::warn!("warm pools: Kubernetes access unavailable; not reconciling");
        return;
    };
    tracing::info!(
        namespace = %config.namespace,
        pools = config.pools.len(),
        image_cache = config.image_cache_enabled,
        draining = config.draining,
        "warm pools: reconciling configured shapes"
    );
    let mut state = LoopState::default();
    let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
    loop {
        ticker.tick().await;
        if !is_leader.load(Ordering::SeqCst) {
            state = LoopState::default();
            continue;
        }
        match reconcile_once(&client, &config, &mut state).await {
            Ok(result) => record_result(result),
            Err(error) => {
                record_result(PassResult::Error);
                tracing::warn!(error = %format!("{error:#}"), "warm pools: reconcile failed; retrying");
            }
        }
    }
}

/// Leader memory across passes; reset whenever leadership is lost.
#[derive(Default)]
struct LoopState {
    rotation: Option<(String, Instant)>,
    /// The last controller capability observed, for logging transitions.
    capable: Option<bool>,
    /// The applied node budget and its consecutive lower observations.
    budget: Option<(Budget, u8)>,
    /// Owned member UIDs per pool at the previous pass; `None` before the
    /// first pass, which only records a baseline.
    members: Option<BTreeMap<String, BTreeSet<String>>>,
    adopted: Option<BTreeSet<String>>,
    clamped: BTreeMap<String, i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PassResult {
    Unchanged,
    /// The controller lacks C0's claim safety: nothing was written.
    Held,
    Wrote,
    Conflict,
    Error,
    InvalidConfig,
}

impl PassResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Held => "held",
            Self::Wrote => "wrote",
            Self::Conflict => "conflict",
            Self::Error => "error",
            Self::InvalidConfig => "invalid_config",
        }
    }
}

fn dynamic(
    client: &kube::Client,
    namespace: &str,
    group: &str,
    kind: &str,
    plural: &str,
) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk(group, CRD_VERSION, kind);
    Api::namespaced_with(
        client.clone(),
        namespace,
        &ApiResource::from_gvk_with_plural(&gvk, plural),
    )
}

fn by_name(objects: Vec<DynamicObject>) -> BTreeMap<String, DynamicObject> {
    objects
        .into_iter()
        .filter_map(|object| {
            let name = object.metadata.name.clone()?;
            is_warm_pool_name(&name).then_some((name, object))
        })
        .collect()
}

fn selector_of(labels: &BTreeMap<String, String>) -> String {
    labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

async fn reconcile_once(
    client: &kube::Client,
    config: &WarmPoolConfig,
    state: &mut LoopState,
) -> anyhow::Result<PassResult> {
    let namespace = config.namespace.as_str();
    let templates_api = dynamic(
        client,
        namespace,
        EXTENSIONS_GROUP,
        "SandboxTemplate",
        "sandboxtemplates",
    );
    let pools_api = dynamic(
        client,
        namespace,
        EXTENSIONS_GROUP,
        "SandboxWarmPool",
        "sandboxwarmpools",
    );
    let sandboxes_api = dynamic(client, namespace, SANDBOX_GROUP, "Sandbox", "sandboxes");
    let pool_selector = ListParams::default().labels(&pool_label_selector());
    // Every pool, environment shadows included: the controller's capability
    // shows on whichever it reconciled (review H1).
    let all_pools = pools_api.list(&ListParams::default()).await?.items;
    let capable = controller_capable(&all_pools);
    controller_ready_metric().set(i64::from(capable));
    if state.capable != Some(capable) {
        if capable {
            tracing::info!(
                "warm pools: the agent-sandbox controller guards member deletes; reconciling"
            );
        } else {
            tracing::warn!(
                "warm pools: the agent-sandbox controller shows no claim-safe pool support \
                 (no SandboxWarmPool status.observedGeneration); holding every pool"
            );
        }
        state.capable = Some(capable);
    }
    if !capable {
        // Review H1 holds every pool, but a capable controller shows itself
        // only on a pool it reconciled. With none at all (a fresh cluster, or
        // every environment destroyed) bootstrap one empty pool.
        if all_pools.is_empty() {
            let templates = by_name(templates_api.list(&pool_selector).await?.items);
            let cache_warm = image_cache_gate(client, namespace, config).await?;
            for write in bootstrap_writes(&config.pools, &templates, cache_warm) {
                match execute(&templates_api, &pools_api, &sandboxes_api, &write).await {
                    Ok(()) => log_write(&write),
                    Err(WriteError::Conflict) => break,
                    Err(WriteError::Other(error)) => {
                        return Err(error.context(format!(
                            "warm pools: bootstrap {} {}",
                            write_kind(&write),
                            write_name(&write)
                        )));
                    }
                }
            }
        }
        return Ok(PassResult::Held);
    }
    let templates = by_name(templates_api.list(&pool_selector).await?.items);
    let pools = by_name(
        all_pools
            .into_iter()
            .filter(|pool| has_pool_labels(pool.metadata.labels.as_ref()))
            .collect(),
    );
    let members = sandboxes_api
        .list(&ListParams::default().labels(MEMBER_POOL_LABEL))
        .await?
        .items;
    let adopted = sandboxes_api
        .list(&ListParams::default().labels(&format!("{LAUNCH_TYPE_LABEL}={LAUNCH_TYPE_WARM}")))
        .await?
        .items;
    let member_pods: BTreeMap<String, Placement> =
        Api::<Pod>::namespaced(client.clone(), namespace)
            .list(&ListParams::default().labels(MEMBER_POOL_LABEL))
            .await?
            .items
            .into_iter()
            .filter_map(|pod| {
                let spec = pod.spec?;
                Some((
                    pod.metadata.name?,
                    Placement {
                        node: spec.node_name?,
                        tolerations: spec.tolerations.unwrap_or_default(),
                    },
                ))
            })
            .collect();

    let cache_warm = image_cache_gate(client, namespace, config).await?;

    // The node cap, from the RuntimeClass the pools render.
    let (overhead, node_selector) = match config.runtime_class() {
        Some(name) => {
            let class = Api::<RuntimeClass>::all(client.clone()).get(name).await?;
            let overhead: BTreeMap<String, String> = class
                .overhead
                .and_then(|overhead| overhead.pod_fixed)
                .unwrap_or_default()
                .into_iter()
                .map(|(resource, quantity)| (resource, quantity.0))
                .collect();
            let selector = class
                .scheduling
                .and_then(|scheduling| scheduling.node_selector)
                .unwrap_or_default();
            (overhead, selector)
        }
        None => (BTreeMap::new(), BTreeMap::new()),
    };
    let nodes = Api::<Node>::all(client.clone())
        .list(&ListParams::default().labels(&selector_of(&node_selector)))
        .await?
        .items;
    let (budget, lower) = settle_budget(state.budget, node_budget(&nodes));
    state.budget = Some((budget, lower));
    let nodes: BTreeMap<String, Node> = nodes
        .into_iter()
        .filter_map(|node| Some((node.metadata.name.clone()?, node)))
        .collect();
    let reservations: Vec<Option<Reservation>> = config
        .pools
        .iter()
        .map(|pool| {
            member_reservation(
                &pool.objects.template["spec"]["podTemplate"]["spec"],
                &overhead,
            )
        })
        .collect();
    let allowed = clamp_members(&config.pools, &reservations, budget);
    for ((pool, reservation), allowed) in config.pools.iter().zip(&reservations).zip(&allowed) {
        let label = pool.label();
        if *allowed < pool.configured.members
            && state.clamped.insert(label.clone(), *allowed) != Some(*allowed)
        {
            tracing::warn!(
                shape = %label,
                configured = pool.configured.members,
                allowed,
                member_cpu_millis = reservation.map(|r| r.cpu_millis as i64),
                member_memory_bytes = reservation.map(|r| r.memory_bytes as i64),
                budget_cpu_millis = budget.cpu_millis as i64,
                budget_memory_bytes = budget.memory_bytes as i64,
                "warm pools: members clamped to 25% of the smallest runtime node"
            );
        } else if *allowed >= pool.configured.members && state.clamped.remove(&label).is_some() {
            tracing::info!(shape = %label, allowed, "warm pools: node cap no longer clamps this shape");
        }
    }

    let desired_names: BTreeSet<&str> = config
        .pools
        .iter()
        .map(|pool| pool.objects.name.as_str())
        .collect();
    // Claims and template users are read only when a pool or template might
    // be removed.
    let removal_candidates = pools
        .keys()
        .chain(templates.keys())
        .any(|name| !desired_names.contains(name.as_str()));
    let template_users = if removal_candidates {
        Some(
            sandboxes_api
                .list(&ListParams::default().labels(TEMPLATE_REF_HASH_LABEL))
                .await?
                .items
                .into_iter()
                .filter_map(|sandbox| {
                    sandbox
                        .metadata
                        .labels?
                        .get(TEMPLATE_REF_HASH_LABEL)
                        .cloned()
                })
                .collect::<BTreeSet<String>>(),
        )
    } else {
        None
    };
    let referenced = if removal_candidates {
        Some(
            dynamic(
                client,
                namespace,
                EXTENSIONS_GROUP,
                "SandboxClaim",
                "sandboxclaims",
            )
            .list(&ListParams::default())
            .await?
            .items
            .into_iter()
            .filter_map(|claim| {
                claim
                    .data
                    .pointer("/spec/warmPoolRef/name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<BTreeSet<String>>(),
        )
    } else {
        None
    };

    let rotation = state
        .rotation
        .as_ref()
        .map(|(name, started)| (name.as_str(), started.elapsed()));
    let decided = plan::plan(&Observed {
        desired: &config.pools,
        allowed_members: &allowed,
        templates: &templates,
        pools: &pools,
        members: &members,
        member_pods: &member_pods,
        nodes: &nodes,
        referenced_pools: referenced.as_ref(),
        template_users: template_users.as_ref(),
        cache_warm,
        rotation,
        now: Timestamp::now(),
    });
    if let Some(name) = &decided.started_rotation {
        state.rotation = Some((name.clone(), Instant::now()));
    } else if decided.rotation_settled {
        state.rotation = None;
    }

    record_observation(
        config, &allowed, &decided, cache_warm, &pools, &members, &adopted, state,
    );

    let mut result = PassResult::Unchanged;
    for write in decided.writes {
        match execute(&templates_api, &pools_api, &sandboxes_api, &write).await {
            Ok(()) => {
                result = PassResult::Wrote;
                log_write(&write);
            }
            Err(WriteError::Conflict) => {
                tracing::info!(
                    write = write_kind(&write),
                    name = write_name(&write),
                    "warm pools: an object changed after it was observed; re-planning next pass"
                );
                return Ok(PassResult::Conflict);
            }
            Err(WriteError::Other(error)) => {
                return Err(error.context(format!(
                    "warm pools: {} {}",
                    write_kind(&write),
                    write_name(&write)
                )));
            }
        }
    }
    Ok(result)
}

/// A2b's gate: whether every cacheable pool image is held and rolled out.
/// With the cache disabled (Kind) it is open without a read.
async fn image_cache_gate(
    client: &kube::Client,
    namespace: &str,
    config: &WarmPoolConfig,
) -> anyhow::Result<bool> {
    if !config.image_cache_enabled {
        return Ok(true);
    }
    let daemon_set = dynamic_daemon_sets(client, namespace)
        .get_opt(IMAGE_CACHE_NAME)
        .await?
        .map(serde_json::to_value)
        .transpose()?;
    Ok(image_cache_warm(daemon_set.as_ref(), &config.images()))
}

fn dynamic_daemon_sets(client: &kube::Client, namespace: &str) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk("apps", "v1", "DaemonSet");
    Api::namespaced_with(
        client.clone(),
        namespace,
        &ApiResource::from_gvk_with_plural(&gvk, "daemonsets"),
    )
}

enum WriteError {
    Conflict,
    Other(anyhow::Error),
}

impl From<kube::Error> for WriteError {
    fn from(error: kube::Error) -> Self {
        match error {
            kube::Error::Api(status) if status.code == 409 => Self::Conflict,
            other => Self::Other(other.into()),
        }
    }
}

fn guarded(uid: &str, resource_version: &str) -> DeleteParams {
    DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid.to_owned()),
            resource_version: Some(resource_version.to_owned()),
        }),
        ..DeleteParams::default()
    }
}

/// A guarded delete that finds the object already gone succeeded.
fn absent_ok<T>(result: Result<T, kube::Error>) -> Result<(), WriteError> {
    match result {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(status)) if status.code == 404 => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn execute(
    templates: &Api<DynamicObject>,
    pools: &Api<DynamicObject>,
    sandboxes: &Api<DynamicObject>,
    write: &Write,
) -> Result<(), WriteError> {
    let object = |body: &Value| -> Result<DynamicObject, WriteError> {
        serde_json::from_value(body.clone()).map_err(|error| WriteError::Other(error.into()))
    };
    match write {
        Write::CreateTemplate { body, .. } => {
            templates
                .create(&PostParams::default(), &object(body)?)
                .await?;
        }
        Write::ReplaceTemplate { name, body } => {
            templates
                .replace(name, &PostParams::default(), &object(body)?)
                .await?;
        }
        Write::CreatePool { body, .. } => {
            pools.create(&PostParams::default(), &object(body)?).await?;
        }
        Write::ReplacePool { name, body } => {
            pools
                .replace(name, &PostParams::default(), &object(body)?)
                .await?;
        }
        Write::DeleteMember {
            name,
            uid,
            resource_version,
            ..
        } => absent_ok(
            sandboxes
                .delete(name, &guarded(uid, resource_version))
                .await,
        )?,
        Write::DeletePool {
            name,
            uid,
            resource_version,
        } => absent_ok(pools.delete(name, &guarded(uid, resource_version)).await)?,
        Write::DeleteTemplate {
            name,
            uid,
            resource_version,
        } => absent_ok(
            templates
                .delete(name, &guarded(uid, resource_version))
                .await,
        )?,
    }
    Ok(())
}

const fn write_kind(write: &Write) -> &'static str {
    match write {
        Write::CreateTemplate { .. } => "create template",
        Write::ReplaceTemplate { .. } => "replace template",
        Write::CreatePool { .. } => "create pool",
        Write::ReplacePool { .. } => "replace pool",
        Write::DeleteMember { .. } => "delete member",
        Write::DeletePool { .. } => "delete pool",
        Write::DeleteTemplate { .. } => "delete template",
    }
}

fn write_name(write: &Write) -> &str {
    match write {
        Write::CreateTemplate { name, .. }
        | Write::ReplaceTemplate { name, .. }
        | Write::CreatePool { name, .. }
        | Write::ReplacePool { name, .. }
        | Write::DeleteMember { name, .. }
        | Write::DeletePool { name, .. }
        | Write::DeleteTemplate { name, .. } => name,
    }
}

fn log_write(write: &Write) {
    match write {
        Write::DeleteMember { pool, reason, .. } => {
            member_deletions_metric()
                .with_label_values(&[pool_shape_label(pool).as_str(), reason.as_str()])
                .inc();
            tracing::info!(
                pool = %pool,
                member = write_name(write),
                reason = reason.as_str(),
                "warm pools: deleted an unclaimed member"
            );
        }
        Write::CreatePool { body, .. } | Write::ReplacePool { body, .. } => {
            let replicas = body.pointer("/spec/replicas").and_then(Value::as_i64);
            tracing::info!(
                write = write_kind(write),
                pool = write_name(write),
                replicas,
                "warm pools: pool written"
            );
        }
        _ => tracing::info!(
            write = write_kind(write),
            name = write_name(write),
            "warm pools: written"
        ),
    }
}

fn pool_shape_label(pool: &str) -> String {
    warm_pool_name_shape(pool).map_or_else(|| "unknown".to_owned(), shape_label)
}

/// Gauges for this pass, and refill and adoption counts since the previous
/// one (the first pass after winning leadership records a baseline only).
#[allow(clippy::too_many_arguments)]
fn record_observation(
    config: &WarmPoolConfig,
    allowed: &[i32],
    decided: &Plan,
    cache_warm: bool,
    pools: &BTreeMap<String, DynamicObject>,
    members: &[DynamicObject],
    adopted: &[DynamicObject],
    state: &mut LoopState,
) {
    cache_warm_metric().set(i64::from(cache_warm));
    let gauges = members_metric();
    for (pool, allowed) in config.pools.iter().zip(allowed) {
        let label = pool.label();
        gauges
            .with_label_values(&[label.as_str(), "configured"])
            .set(i64::from(pool.configured.members));
        gauges
            .with_label_values(&[label.as_str(), "allowed"])
            .set(i64::from(*allowed));
    }
    for (label, report) in &decided.reports {
        gauges
            .with_label_values(&[label.as_str(), "unclaimed"])
            .set(report.members);
        gauges
            .with_label_values(&[label.as_str(), "ready"])
            .set(report.ready);
        template_current_metric()
            .with_label_values(&[label])
            .set(i64::from(report.template_current));
    }

    // Refills: member UIDs a pool owns now that it did not own last pass.
    let mut current: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, pool) in pools {
        let hash = sandbox_name_hash(name);
        let uid = pool.metadata.uid.as_deref().unwrap_or_default();
        let owned = members
            .iter()
            .filter(|member| {
                member
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
                        .any(|owner| owner.controller == Some(true) && owner.uid == uid)
            })
            .filter_map(|member| member.metadata.uid.clone())
            .collect();
        current.insert(name.clone(), owned);
    }
    if let Some(previous) = &state.members {
        for (name, owned) in &current {
            let fresh = owned
                .iter()
                .filter(|uid| !previous.get(name).is_some_and(|seen| seen.contains(*uid)))
                .count();
            if fresh > 0 {
                refills_metric()
                    .with_label_values(&[&pool_shape_label(name)])
                    .inc_by(fresh as u64);
            }
        }
    }
    state.members = Some(current);

    // Adoptions: warm-launched Sandboxes a claim controls, by the pool
    // template they were built from.
    let pool_by_hash: BTreeMap<String, &str> = pools
        .keys()
        .map(String::as_str)
        .chain(config.pools.iter().map(|pool| pool.objects.name.as_str()))
        .map(|name| (sandbox_name_hash(name), name))
        .collect();
    let mut adopted_now = BTreeSet::new();
    for sandbox in adopted {
        let claimed = sandbox
            .metadata
            .owner_references
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|owner| owner.controller == Some(true) && owner.kind == "SandboxClaim");
        let Some(pool) = sandbox
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(TEMPLATE_REF_HASH_LABEL))
            .and_then(|hash| pool_by_hash.get(hash))
        else {
            continue;
        };
        let Some(uid) = sandbox.metadata.uid.clone().filter(|_| claimed) else {
            continue;
        };
        if state
            .adopted
            .as_ref()
            .is_some_and(|seen| !seen.contains(&uid))
        {
            adoptions_metric()
                .with_label_values(&[&pool_shape_label(pool)])
                .inc();
        }
        adopted_now.insert(uid);
    }
    state.adopted = Some(adopted_now);
}

static RECONCILES: OnceLock<IntCounterVec> = OnceLock::new();
static MEMBERS: OnceLock<IntGaugeVec> = OnceLock::new();
static TEMPLATE_CURRENT: OnceLock<IntGaugeVec> = OnceLock::new();
static CACHE_WARM: OnceLock<IntGauge> = OnceLock::new();
static CONTROLLER_READY: OnceLock<IntGauge> = OnceLock::new();
static CONFIG_VALID: OnceLock<IntGauge> = OnceLock::new();

fn controller_ready_metric() -> &'static IntGauge {
    CONTROLLER_READY.get_or_init(|| {
        register_int_gauge!(
            "codewire_warm_pool_controller_ready",
            "1 when the agent-sandbox controller shows claim-safe pool support (C0); 0 holds every pool."
        )
        .expect("warm pool controller metric registration must be unique")
    })
}

fn config_valid_metric() -> &'static IntGauge {
    CONFIG_VALID.get_or_init(|| {
        register_int_gauge!(
            "codewire_warm_pool_config_valid",
            "0 when SANDBOX_WARM_POOL_SHAPES is invalid and every existing pool drains."
        )
        .expect("warm pool config metric registration must be unique")
    })
}
static REFILLS: OnceLock<IntCounterVec> = OnceLock::new();
static ADOPTIONS: OnceLock<IntCounterVec> = OnceLock::new();
static MEMBER_DELETIONS: OnceLock<IntCounterVec> = OnceLock::new();

fn record_result(result: PassResult) {
    RECONCILES
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "codewire_warm_pool_reconciles_total",
                    "Warm-pool reconcile passes by closed result."
                ),
                &["result"]
            )
            .expect("warm pool reconcile metric registration must be unique")
        })
        .with_label_values(&[result.as_str()])
        .inc();
}

fn members_metric() -> &'static IntGaugeVec {
    MEMBERS.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "codewire_warm_pool_members",
                "Warm-pool members by shape: configured, allowed by the node cap, unclaimed and ready."
            ),
            &["shape", "state"]
        )
        .expect("warm pool members metric registration must be unique")
    })
}

fn template_current_metric() -> &'static IntGaugeVec {
    TEMPLATE_CURRENT.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "codewire_warm_pool_template_current",
                "1 when the shape's pool template is at this replica's revision."
            ),
            &["shape"]
        )
        .expect("warm pool template metric registration must be unique")
    })
}

fn cache_warm_metric() -> &'static IntGauge {
    CACHE_WARM.get_or_init(|| {
        register_int_gauge!(
            "codewire_warm_pool_image_cache_warm",
            "1 when the image cache holds every cacheable pool image on every eligible node."
        )
        .expect("warm pool cache metric registration must be unique")
    })
}

fn refills_metric() -> &'static IntCounterVec {
    REFILLS.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_warm_pool_refills_total",
                "Unclaimed members a pool gained, by shape."
            ),
            &["shape"]
        )
        .expect("warm pool refill metric registration must be unique")
    })
}

fn adoptions_metric() -> &'static IntCounterVec {
    ADOPTIONS.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_warm_pool_adoptions_total",
                "Pool members adopted by a claim, by shape."
            ),
            &["shape"]
        )
        .expect("warm pool adoption metric registration must be unique")
    })
}

fn member_deletions_metric() -> &'static IntCounterVec {
    MEMBER_DELETIONS.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_warm_pool_member_deletions_total",
                "Unclaimed members the reconciler deleted, by shape and closed reason."
            ),
            &["shape", "reason"]
        )
        .expect("warm pool deletion metric registration must be unique")
    })
}

#[cfg(test)]
#[path = "warm_pool/tests.rs"]
mod tests;
