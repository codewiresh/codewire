//! Reconcile loop and telemetry for the `cw-image-cache` DaemonSet.
//!
//! Runs on every orchestration Pod, not only the leader: each Pod adds the
//! image set it renders (see `sandbox::image_cache` for the monotonic,
//! release-ordered merge). Writes are optimistic: a replace carries the
//! observed `resourceVersion`, and a conflict re-reads and re-plans.
//!
//! A Pod's release is its ReplicaSet's `deployment.kubernetes.io/revision`,
//! read each pass (a rollback renumbers the reused ReplicaSet). Orchestration
//! may already read Pods; reading its own namespace's ReplicaSets is a
//! separate read-only Role. Without it the release is 0 and sets fall back
//! to arrival order.
//!
//! Orchestration's DaemonSet grant is a Role in the sandbox namespace that
//! can create DaemonSets and get, update or patch only `cw-image-cache`; the
//! `codewire-orchestration-image-cache` admission policy bounds the shape.
//!
//! Slice 1 does not hold this Pod's readiness on the cache;
//! `codewire_image_cache_warm` reports whether it would.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use k8s_openapi::api::apps::v1::ReplicaSet;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ApiResource, DynamicObject, PostParams};
use kube::core::GroupVersionKind;
use prometheus::{IntCounterVec, IntGauge, IntGaugeVec, Opts};
use prometheus::{register_int_counter_vec, register_int_gauge, register_int_gauge_vec};
use serde_json::Value;

use super::WorkerContext;
use super::create::SandboxWorkerCfg;
use crate::sandbox::image_cache::{
    CacheState, DesiredSet, IMAGE_CACHE_ENV, IMAGE_CACHE_NAME, Plan, RenderConfig, plan, rollout,
};

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const CONFLICT_ATTEMPTS: usize = 3;
const REVISION_ANNOTATION: &str = "deployment.kubernetes.io/revision";

/// Everything one Pod reconciles toward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageCacheConfig {
    pub render: RenderConfig,
    pub desired: DesiredSet,
}

impl ImageCacheConfig {
    /// `Ok(None)` when `SANDBOX_IMAGE_CACHE=disabled`. Disabling stops
    /// reconciling; an operator deletes the DaemonSet.
    pub fn from_env(sandbox: &SandboxWorkerCfg) -> anyhow::Result<Option<Self>> {
        Self::from_values(std::env::var(IMAGE_CACHE_ENV).ok().as_deref(), sandbox)
    }

    fn from_values(mode: Option<&str>, sandbox: &SandboxWorkerCfg) -> anyhow::Result<Option<Self>> {
        match mode.map(str::trim).unwrap_or_default() {
            "" | "enabled" => {}
            "disabled" => return Ok(None),
            other => anyhow::bail!("{IMAGE_CACHE_ENV}={other:?} must be enabled or disabled"),
        }
        let namespace = sandbox.sandbox_namespace.trim();
        anyhow::ensure!(!namespace.is_empty(), "sandbox namespace is not configured");
        Ok(Some(Self {
            render: RenderConfig {
                namespace: namespace.to_owned(),
            },
            desired: DesiredSet::from_rendered(&sandbox.daemon_image, &sandbox.dind_image),
        }))
    }
}

/// This Pod's identity, for its release lookup.
#[derive(Clone, Debug)]
struct Own {
    namespace: String,
    name: String,
    uid: String,
}

impl Own {
    fn from_env() -> Option<Self> {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        Some(Self {
            namespace: var("POD_NAMESPACE")?,
            name: var("POD_NAME")?,
            uid: var("POD_UID")?,
        })
    }
}

/// The revision of the ReplicaSet that controls this Pod.
async fn own_release(client: &kube::Client, own: &Own) -> anyhow::Result<u64> {
    let pod = Api::<Pod>::namespaced(client.clone(), &own.namespace)
        .get(&own.name)
        .await?;
    anyhow::ensure!(
        pod.metadata.uid.as_deref() == Some(own.uid.as_str()),
        "Pod {} is not this process's Pod",
        own.name
    );
    let owner = pod
        .metadata
        .owner_references
        .unwrap_or_default()
        .into_iter()
        .find(|owner| owner.kind == "ReplicaSet" && owner.controller == Some(true))
        .ok_or_else(|| anyhow::anyhow!("Pod {} has no controlling ReplicaSet", own.name))?;
    let replica_set = Api::<ReplicaSet>::namespaced(client.clone(), &own.namespace)
        .get(&owner.name)
        .await?;
    anyhow::ensure!(
        replica_set.metadata.uid.as_deref() == Some(owner.uid.as_str()),
        "ReplicaSet {} was replaced",
        owner.name
    );
    replica_set
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(REVISION_ANNOTATION))
        .and_then(|revision| revision.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("ReplicaSet {} has no revision", owner.name))
}

/// Runs until the process exits. Never gates readiness (slice 1).
pub async fn image_cache_loop(ctx: Arc<WorkerContext>) {
    let mut config = match ImageCacheConfig::from_env(&ctx.sandbox_cfg) {
        Ok(Some(config)) => config,
        Ok(None) => {
            tracing::info!("image cache: disabled");
            return;
        }
        Err(error) => {
            record_result(ReconcileResult::InvalidConfig);
            tracing::error!(%error, "image cache: invalid configuration; not reconciling");
            return;
        }
    };
    let Some(client) = ctx.kube.clone() else {
        tracing::warn!("image cache: Kubernetes access unavailable; not reconciling");
        return;
    };
    let own = Own::from_env();
    tracing::info!(
        namespace = %config.render.namespace,
        images = config.desired.images.len(),
        skipped = config.desired.skipped,
        "image cache: reconciling this release's image set"
    );
    let api = daemon_sets(client.clone(), &config.render.namespace);
    let mut release_known = true;
    loop {
        let release = match &own {
            Some(own) => own_release(&client, own).await,
            None => Err(anyhow::anyhow!(
                "POD_NAMESPACE, POD_NAME or POD_UID is unset"
            )),
        };
        config.desired.release = match release {
            Ok(release) => {
                release_known = true;
                release
            }
            Err(error) => {
                if release_known {
                    tracing::warn!(%error, "image cache: release unknown; ordering by arrival");
                }
                release_known = false;
                0
            }
        };
        match reconcile_once(&api, &config).await {
            Ok(observation) => observation.record(&config.desired),
            Err(error) => {
                record_result(ReconcileResult::Error);
                warm_metric().set(0);
                tracing::warn!(%error, "image cache: reconcile failed; retrying");
            }
        }
        tokio::time::sleep(RECONCILE_INTERVAL).await;
    }
}

fn daemon_sets(client: kube::Client, namespace: &str) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk("apps", "v1", "DaemonSet");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "daemonsets");
    Api::namespaced_with(client, namespace, &resource)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReconcileResult {
    Created,
    Updated,
    Unchanged,
    Superseded,
    Conflict,
    Error,
    InvalidConfig,
}

impl ReconcileResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
            Self::Superseded => "superseded",
            Self::Conflict => "conflict",
            Self::Error => "error",
            Self::InvalidConfig => "invalid_config",
        }
    }
}

struct Observation {
    result: ReconcileResult,
    state: CacheState,
    live: Option<Value>,
}

impl Observation {
    fn record(&self, desired: &DesiredSet) {
        record_result(self.result);
        let images = images_metric();
        let held = |index: usize| {
            self.state
                .sets
                .get(index)
                .map_or(0, |set| set.images.len() as i64)
        };
        images.with_label_values(&["current"]).set(held(0));
        images.with_label_values(&["previous"]).set(held(1));
        images
            .with_label_values(&["skipped"])
            .set(desired.skipped as i64);

        let rollout = self.live.as_ref().map(rollout).unwrap_or_default();
        let nodes = nodes_metric();
        nodes.with_label_values(&["desired"]).set(rollout.desired);
        nodes.with_label_values(&["updated"]).set(rollout.updated);
        nodes
            .with_label_values(&["available"])
            .set(rollout.available);
        nodes.with_label_values(&["ready"]).set(rollout.ready);

        let position = self.state.position(desired);
        own_set_metric().set(position.map_or(-1, |index| index as i64));
        let wrote = matches!(
            self.result,
            ReconcileResult::Created | ReconcileResult::Updated
        );
        // A write changes the spec; its rollout is judged on the next pass.
        let warm = position.is_some() && !wrote && rollout.complete;
        warm_metric().set(i64::from(warm));
    }
}

async fn reconcile_once(
    api: &Api<DynamicObject>,
    config: &ImageCacheConfig,
) -> anyhow::Result<Observation> {
    for _ in 0..CONFLICT_ATTEMPTS {
        let live = api
            .get_opt(IMAGE_CACHE_NAME)
            .await?
            .map(serde_json::to_value)
            .transpose()?;
        match plan(&config.render, live.as_ref(), &config.desired) {
            Plan::Create { daemon_set, state } => {
                let object: DynamicObject = serde_json::from_value(daemon_set)?;
                match api.create(&PostParams::default(), &object).await {
                    Ok(created) => {
                        log_write("created", &state);
                        return Ok(Observation {
                            result: ReconcileResult::Created,
                            state,
                            live: Some(serde_json::to_value(created)?),
                        });
                    }
                    Err(kube::Error::Api(error)) if error.code == 409 => {
                        record_result(ReconcileResult::Conflict);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Plan::Replace { daemon_set, state } => {
                let mut object: DynamicObject = serde_json::from_value(daemon_set)?;
                object.metadata.resource_version = live
                    .as_ref()
                    .and_then(|live| live.pointer("/metadata/resourceVersion"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                match api
                    .replace(IMAGE_CACHE_NAME, &PostParams::default(), &object)
                    .await
                {
                    Ok(updated) => {
                        log_write("updated", &state);
                        return Ok(Observation {
                            result: ReconcileResult::Updated,
                            state,
                            live: Some(serde_json::to_value(updated)?),
                        });
                    }
                    Err(kube::Error::Api(error)) if error.code == 409 => {
                        record_result(ReconcileResult::Conflict);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Plan::Keep { state } => {
                return Ok(Observation {
                    result: ReconcileResult::Unchanged,
                    state,
                    live,
                });
            }
            Plan::Superseded { state } => {
                tracing::warn!(
                    release = config.desired.release,
                    "image cache: a newer release holds the cache; this release's set is not cached"
                );
                return Ok(Observation {
                    result: ReconcileResult::Superseded,
                    state,
                    live,
                });
            }
        }
    }
    anyhow::bail!("{IMAGE_CACHE_NAME} kept changing; {CONFLICT_ATTEMPTS} conflicting writes")
}

fn log_write(action: &str, state: &CacheState) {
    tracing::info!(
        action,
        generation = state.generation,
        releases = ?state.sets.iter().map(|set| set.release).collect::<Vec<_>>(),
        images = crate::sandbox::image_cache::cached_images(&state.sets).len(),
        "image cache: DaemonSet written"
    );
}

static RECONCILES: OnceLock<IntCounterVec> = OnceLock::new();
static IMAGES: OnceLock<IntGaugeVec> = OnceLock::new();
static NODES: OnceLock<IntGaugeVec> = OnceLock::new();
static OWN_SET: OnceLock<IntGauge> = OnceLock::new();
static WARM: OnceLock<IntGauge> = OnceLock::new();

fn record_result(result: ReconcileResult) {
    RECONCILES
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "codewire_image_cache_reconciles_total",
                    "Image cache reconcile passes by closed result."
                ),
                &["result"]
            )
            .expect("image cache reconcile metric registration must be unique")
        })
        .with_label_values(&[result.as_str()])
        .inc();
}

fn images_metric() -> &'static IntGaugeVec {
    IMAGES.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "codewire_image_cache_images",
                "Images in the cache's current and previous sets, and rendered images skipped as unpinned or unapproved."
            ),
            &["state"]
        )
        .expect("image cache images metric registration must be unique")
    })
}

fn nodes_metric() -> &'static IntGaugeVec {
    NODES.get_or_init(|| {
        register_int_gauge_vec!(
            Opts::new(
                "codewire_image_cache_nodes",
                "Image cache DaemonSet nodes by rollout state."
            ),
            &["state"]
        )
        .expect("image cache nodes metric registration must be unique")
    })
}

fn own_set_metric() -> &'static IntGauge {
    OWN_SET.get_or_init(|| {
        register_int_gauge!(
            "codewire_image_cache_own_set_index",
            "This Pod's image set in the cache: 0 current, 1 previous, -1 not held."
        )
        .expect("image cache own-set metric registration must be unique")
    })
}

fn warm_metric() -> &'static IntGauge {
    WARM.get_or_init(|| {
        register_int_gauge!(
            "codewire_image_cache_warm",
            "1 when this Pod's image set is held and Ready on every eligible node."
        )
        .expect("image cache warm metric registration must be unique")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox_cfg() -> SandboxWorkerCfg {
        let mut cfg = SandboxWorkerCfg {
            sandbox_namespace: "dev-sandboxes".into(),
            ..Default::default()
        };
        cfg.daemon_image = crate::sandbox::template::TEST_SUPPORT_IMAGE.into();
        cfg
    }

    #[test]
    fn config_defaults_to_enabled_in_the_sandbox_namespace() {
        let config = ImageCacheConfig::from_values(None, &sandbox_cfg())
            .unwrap()
            .unwrap();
        assert_eq!(config.render.namespace, "dev-sandboxes");
        assert_eq!(config.desired.images.len(), 3);
        assert_eq!(config.desired.release, 0);
    }

    #[test]
    fn config_can_be_disabled_and_rejects_typos() {
        assert!(
            ImageCacheConfig::from_values(Some("disabled"), &sandbox_cfg())
                .unwrap()
                .is_none()
        );
        assert!(
            ImageCacheConfig::from_values(Some("enabled"), &sandbox_cfg())
                .unwrap()
                .is_some()
        );
        assert!(ImageCacheConfig::from_values(Some("on"), &sandbox_cfg()).is_err());
        let mut no_namespace = sandbox_cfg();
        no_namespace.sandbox_namespace.clear();
        assert!(ImageCacheConfig::from_values(None, &no_namespace).is_err());
    }
}
