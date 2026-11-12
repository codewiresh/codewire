//! Routing a create to a shared warm pool (Program #2238 C3).
//!
//! A create claims from a pool only when every condition holds: the standard
//! tier, exactly the canonical workspace image, no dedicated CPU the pools do
//! not give (#3635), a binding listener, an
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

use prometheus::{IntCounterVec, Opts, register_int_counter_vec};

use super::{SandboxWorkerCfg, warm_pool_template_opts};
use crate::runtime::{Placement, PoolState, RuntimeDriver, WantedPool};
use crate::sandbox::canonical_workspace_runtime_image;
use crate::sandbox::template::{CpuSharingRatio, TemplateOpts};
use crate::sandbox::warm_pool::{WorkspaceShape, parse_warm_pool_shapes};
use crate::worker::env_data::EnvironmentRow;

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
    /// The organization has dedicated CPU and the pools share (#3635).
    DedicatedCpu,
    /// No binding listener to render the workspace against.
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
    /// It starts from a hosted snapshot, and a pool member already has a disk.
    SourceSnapshot,
}

impl ColdReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unconfigured => "cold_unconfigured",
            Self::Tier => "cold_tier",
            Self::Image => "cold_image",
            Self::DedicatedCpu => "cold_dedicated_cpu",
            Self::Identity => "cold_identity",
            Self::Shape => "cold_shape",
            Self::Rendering => "cold_rendering",
            Self::Revision => "cold_revision",
            Self::Controller => "cold_controller",
            Self::StaleMembers => "cold_stale_members",
            Self::Unavailable => "cold_unavailable",
            Self::Reclaimed => "cold_reclaimed",
            Self::SourceSnapshot => "cold_source_snapshot",
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
) -> Result<WantedPool, ColdReason> {
    let configured = match parse_warm_pool_shapes(&cfg.warm_pool_shapes) {
        Ok(configured) if !configured.is_empty() => configured,
        _ => return Err(ColdReason::Unconfigured),
    };
    if env.isolation_tier != "standard" {
        return Err(ColdReason::Tier);
    }
    if env.source_snapshot_id.is_some() {
        return Err(ColdReason::SourceSnapshot);
    }
    if image_ref.trim() != canonical_workspace_runtime_image() {
        return Err(ColdReason::Image);
    }
    if env.dedicated_cpu && cfg.cpu_sharing_ratio != CpuSharingRatio::NONE {
        return Err(ColdReason::DedicatedCpu);
    }
    if opts.workspace_binding_url.trim().is_empty() {
        return Err(ColdReason::Identity);
    }
    let shape = WorkspaceShape::of(opts);
    let Some(entry) = configured
        .iter()
        .find(|entry| entry.shape == shape && entry.members > 0)
    else {
        return Err(ColdReason::Shape);
    };
    // The driver renders the pool, and answers whether it renders at all
    // (`cold_shape`) and whether this environment's rendering is the pool's
    // (`cold_rendering`).
    Ok(WantedPool {
        configured: *entry,
        rendering: warm_pool_template_opts(cfg, shape).map_err(|_| ColdReason::Shape)?,
        allow_unpinned_images: cfg.allow_diagnostic_runtime,
    })
}

/// The live half: what the driver says of the pool, as a route.
async fn live_route(
    runtime: &dyn RuntimeDriver,
    placement: &Placement,
    pool: &WantedPool,
    opts: &TemplateOpts,
) -> anyhow::Result<Route> {
    Ok(match runtime.pool_state(placement, pool, opts).await? {
        PoolState::Claimable { pool } => Route::Pool { name: pool },
        PoolState::NoPools => Route::Cold(ColdReason::Unconfigured),
        PoolState::Unrenderable => Route::Cold(ColdReason::Shape),
        PoolState::RenderingDiffers => Route::Cold(ColdReason::Rendering),
        PoolState::NotCurrent => Route::Cold(ColdReason::Revision),
        PoolState::ControllerIncapable => Route::Cold(ColdReason::Controller),
        PoolState::StaleMembers => Route::Cold(ColdReason::StaleMembers),
    })
}

/// Decide one create's route, and count it.
pub(crate) async fn route(
    cfg: &SandboxWorkerCfg,
    env: &EnvironmentRow,
    image_ref: &str,
    opts: &TemplateOpts,
    runtime: &dyn RuntimeDriver,
    placement: &Placement,
    reclaimed: bool,
) -> Route {
    let route = if reclaimed {
        Route::Cold(ColdReason::Reclaimed)
    } else {
        match pool_candidate(cfg, env, image_ref, opts) {
            Err(reason) => Route::Cold(reason),
            Ok(pool) => match live_route(runtime, placement, &pool, opts).await {
                Ok(route) => route,
                Err(error) => {
                    tracing::warn!(env = %env.id, error = %format!("{error:#}"), "warm pool unavailable; creating cold");
                    Route::Cold(ColdReason::Unavailable)
                }
            },
        }
    };
    // The counter resets with the replica; the log keeps why a create of a
    // pooled deployment went cold (#3852). No pool configured is not news.
    if let Route::Cold(reason) = &route
        && !matches!(reason, ColdReason::Unconfigured)
    {
        tracing::info!(env = %env.id, route = reason.as_str(), "environment creating cold");
    }
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
