//! Routing a create to a shared warm pool (Program #2238 C3).
//!
//! A create claims from a pool only when every condition holds: the standard
//! tier, exactly the canonical workspace image, identity mode `binding`, an
//! exact configured shape with members, an own identity-free rendering equal
//! to the pool's (design invariant 10, which covers CPU, memory, disk,
//! storage class, runtime and images), a controller that shows C0's claim
//! safety, a live pool and template at this replica's own revision and spec,
//! and no unclaimed member of another revision. Anything else goes cold,
//! unchanged. With no shape configured the decision is made before any
//! Kubernetes read.
//!
//! A pool Claim carries only `warmPoolRef` and the identity labels, so the
//! agent-sandbox controller may adopt a member. The bind then requires the
//! adopted Sandbox to be exactly this environment's rendering; a definitive
//! failure re-claims cold ([`super::reclaim_cold`]).

use std::sync::OnceLock;

use kube::api::DynamicObject;
use prometheus::{IntCounterVec, Opts, register_int_counter_vec};
use serde_json::Value;

use super::{SandboxWorkerCfg, WorkspaceIdentityMode, render_configured_warm_pool};
use crate::sandbox::CANONICAL_WORKSPACE_RUNTIME_IMAGE;
use crate::sandbox::client::SandboxClient;
use crate::sandbox::template::{TemplateOpts, render_sandbox_template};
use crate::sandbox::warm_pool::{
    POOL_REVISION_ANNOTATION, WarmPoolObjects, WorkspaceShape, has_pool_labels,
    parse_warm_pool_shapes, pod_spec_pool_revision, pool_revision,
};
use crate::worker::env_data::EnvironmentRow;
use crate::worker::warm_pool::{pool_observed_by_capable_controller, template_spec_current};

/// Where one create claims from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// The shared pool named here.
    Pool {
        name: String,
    },
    Cold(ColdReason),
}

/// Why a create went cold. Closed metric labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColdReason {
    /// No shape is configured (or the configuration is invalid).
    Unconfigured,
    /// Not the standard tier: confidential is never pooled.
    Tier,
    /// Not exactly the canonical workspace image.
    Image,
    /// Not identity mode `binding`, or a legacy rendering.
    Identity,
    /// No configured shape with members equals this environment's shape.
    Shape,
    /// The environment's own rendering differs from the pool's.
    Rendering,
    /// The live pool or template is missing, empty, terminating or at another
    /// revision or spec (a rotation, or another release's replica).
    Revision,
    /// The agent-sandbox controller shows no C0 claim safety on the pool: no
    /// `status.observedGeneration` at its generation (review H1).
    Controller,
    /// An unclaimed member still carries another revision in its Pod spec;
    /// the reconciler replaces it first (review M1).
    StaleMembers,
    /// The live pool could not be read.
    Unavailable,
    /// A pool-born Claim failed its first bind and was re-claimed.
    Reclaimed,
}

impl ColdReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unconfigured => "cold_unconfigured",
            Self::Tier => "cold_tier",
            Self::Image => "cold_image",
            Self::Identity => "cold_identity",
            Self::Shape => "cold_shape",
            Self::Rendering => "cold_rendering",
            Self::Revision => "cold_revision",
            Self::Controller => "cold_controller",
            Self::StaleMembers => "cold_stale_members",
            Self::Unavailable => "cold_unavailable",
            Self::Reclaimed => "cold_reclaimed",
        }
    }
}

/// The configuration half: the pool this environment may claim from, when
/// every static condition holds.
pub(crate) fn pool_candidate(
    cfg: &SandboxWorkerCfg,
    env: &EnvironmentRow,
    image_ref: &str,
    opts: &TemplateOpts,
    namespace: &str,
) -> Result<WarmPoolObjects, ColdReason> {
    let configured = match parse_warm_pool_shapes(&cfg.warm_pool_shapes) {
        Ok(configured) if !configured.is_empty() => configured,
        _ => return Err(ColdReason::Unconfigured),
    };
    if env.isolation_tier != "standard" {
        return Err(ColdReason::Tier);
    }
    if image_ref.trim() != CANONICAL_WORKSPACE_RUNTIME_IMAGE {
        return Err(ColdReason::Image);
    }
    if cfg.workspace_identity_mode != WorkspaceIdentityMode::Binding || !opts.identity_free() {
        return Err(ColdReason::Identity);
    }
    let shape = WorkspaceShape::of(opts);
    let Some(entry) = configured
        .iter()
        .find(|entry| entry.shape == shape && entry.members > 0)
    else {
        return Err(ColdReason::Shape);
    };
    let objects =
        render_configured_warm_pool(cfg, shape, entry.members).map_err(|_| ColdReason::Shape)?;
    if pool_revision(&render_sandbox_template(namespace, opts)["spec"]) != objects.revision {
        return Err(ColdReason::Rendering);
    }
    Ok(objects)
}

/// The live half: the pool and its template are Codewire's, not
/// terminating, at this replica's revision, the template's spec is this
/// replica's rendering (review L5), and the pool holds members.
pub(crate) fn live_pool_current(
    pool: Option<&DynamicObject>,
    template: Option<&DynamicObject>,
    objects: &WarmPoolObjects,
) -> bool {
    let at_revision = |object: &DynamicObject| {
        object.metadata.deletion_timestamp.is_none()
            && has_pool_labels(object.metadata.labels.as_ref())
            && object
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(POOL_REVISION_ANNOTATION))
                == Some(&objects.revision)
    };
    let (Some(pool), Some(template)) = (pool, template) else {
        return false;
    };
    at_revision(pool)
        && at_revision(template)
        && template_spec_current(template, &objects.template)
        && pool
            .data
            .pointer("/spec/sandboxTemplateRef/name")
            .and_then(Value::as_str)
            == Some(objects.name.as_str())
        && pool
            .data
            .pointer("/spec/replicas")
            .and_then(Value::as_i64)
            .is_some_and(|replicas| replicas > 0)
}

/// Every unclaimed, non-terminating member booted from `revision`: its Pod
/// spec carries exactly that marker (review M1). The controller could adopt
/// any of them.
pub(crate) fn members_current(members: &[DynamicObject], revision: &str) -> bool {
    members
        .iter()
        .filter(|member| member.metadata.deletion_timestamp.is_none())
        .all(|member| {
            member
                .data
                .pointer("/spec/podTemplate/spec")
                .and_then(pod_spec_pool_revision)
                == Some(revision)
        })
}

/// The live pool's route: claim only on a capable controller, a current
/// pool and template, and current members. Members are read only once the
/// rest holds.
async fn live_route(client: &SandboxClient, objects: &WarmPoolObjects) -> anyhow::Result<Route> {
    let (pool, template) = client.warm_pool_objects(&objects.name).await?;
    let Some(pool) = pool else {
        return Ok(Route::Cold(ColdReason::Revision));
    };
    if !pool_observed_by_capable_controller(&pool) {
        return Ok(Route::Cold(ColdReason::Controller));
    }
    if !live_pool_current(Some(&pool), template.as_ref(), objects) {
        return Ok(Route::Cold(ColdReason::Revision));
    }
    let members = client.warm_pool_members(&objects.name).await?;
    if !members_current(&members, &objects.revision) {
        return Ok(Route::Cold(ColdReason::StaleMembers));
    }
    Ok(Route::Pool {
        name: objects.name.clone(),
    })
}

/// Decide one create's route, and count it.
pub(crate) async fn route(
    cfg: &SandboxWorkerCfg,
    env: &EnvironmentRow,
    image_ref: &str,
    opts: &TemplateOpts,
    client: &SandboxClient,
    reclaimed: bool,
) -> Route {
    let route = if reclaimed {
        Route::Cold(ColdReason::Reclaimed)
    } else {
        match pool_candidate(cfg, env, image_ref, opts, &client.namespace) {
            Err(reason) => Route::Cold(reason),
            Ok(objects) => match live_route(client, &objects).await {
                Ok(route) => route,
                Err(error) => {
                    tracing::warn!(env = %env.id, error = %format!("{error:#}"), "warm pool unavailable; creating cold");
                    Route::Cold(ColdReason::Unavailable)
                }
            },
        }
    };
    routes_metric()
        .with_label_values(&[match &route {
            Route::Pool { .. } => "pool",
            Route::Cold(reason) => reason.as_str(),
        }])
        .inc();
    route
}

static ROUTES: OnceLock<IntCounterVec> = OnceLock::new();
static RECLAIMS: OnceLock<IntCounterVec> = OnceLock::new();

fn routes_metric() -> &'static IntCounterVec {
    ROUTES.get_or_init(|| {
        register_int_counter_vec!(
            Opts::new(
                "codewire_warm_pool_routes_total",
                "Environment creates by route: a shared warm pool, or cold with a closed reason."
            ),
            &["route"]
        )
        .expect("warm pool route metric registration must be unique")
    })
}

/// Count one cold re-claim of a pool-born Claim by its result.
pub(crate) fn record_reclaim(result: &str) {
    RECLAIMS
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "codewire_warm_pool_reclaims_total",
                    "Pool-born Claims deleted and re-claimed cold after a definitive bind-check failure."
                ),
                &["result"]
            )
            .expect("warm pool reclaim metric registration must be unique")
        })
        .with_label_values(&[result])
        .inc();
}

#[cfg(test)]
#[path = "pool_route_tests.rs"]
mod tests;
