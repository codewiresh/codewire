//! The leader `warm-pool` loop (Program #2238 C2): which warm pools this
//! replica wants, and when the runtime driver keeps them.
//!
//! `SANDBOX_WARM_POOL_SHAPES` names the shapes, each rendered by C1's
//! identity-free renderer (`render_configured_warm_pool`), and
//! `SANDBOX_WARM_POOL_MAX_NODE_PERCENT` the share of the smallest runtime node
//! they may reserve together: 25% unless a deployment sets its own budget
//! (owner, 2026-11-08, #2238). Every 30 s the leader asks the driver for one
//! pass toward them ([`RuntimePools::keep_pools`]); on every tick it is not the
//! leader, it has the driver forget what earlier passes remembered.
//!
//! A starting replica warms its own pool of each shape a release is rotating
//! before it reports ready ([`warm_own_pools`], #3572), while the outgoing
//! replicas keep claiming from theirs.
//!
//! Inert by default: with `SANDBOX_WARM_POOL_SHAPES` empty or unset the loop
//! logs once and returns before it asks the driver for anything. An invalid
//! value is logged and wants no pool, so every existing one drains.
//!
//! [`RuntimePools::keep_pools`]: crate::runtime::RuntimePools::keep_pools

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prometheus::{IntCounterVec, IntGauge, Opts};
use prometheus::{register_int_counter_vec, register_int_gauge};
use tokio::sync::watch;

use super::WorkerContext;
use super::create::{SandboxWorkerCfg, render_configured_warm_pool};
use super::image_cache::ImageCacheConfig;
use crate::runtime::{DesiredPool, Placement, PoolPass, RuntimeDriver, WantedPools};
use crate::sandbox::warm_pool::parse_warm_pool_shapes;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
pub const MAX_NODE_PERCENT_ENV: &str = "SANDBOX_WARM_POOL_MAX_NODE_PERCENT";
const DEFAULT_MAX_NODE_PERCENT: u8 = 25;
/// How long a starting replica waits for its own revision's pools before it
/// reports ready anyway, so a release never stalls on a pool (#3572).
pub const WARM_UP_BOUND: Duration = Duration::from_secs(3 * 60);
/// How long a starting replica may take to tell whether a release is rotating
/// its pools. Past it, the start is treated as not rotating, so a slow API
/// never holds a start that has nothing to warm.
const ROTATION_CHECK_BOUND: Duration = Duration::from_secs(15);

fn parse_max_node_percent(value: &str) -> anyhow::Result<u8> {
    if value.is_empty() {
        return Ok(DEFAULT_MAX_NODE_PERCENT);
    }
    let percent = value.parse::<u8>().ok();
    anyhow::ensure!(
        value.bytes().all(|byte| byte.is_ascii_digit())
            && percent.is_some_and(|percent| (1..=100).contains(&percent)),
        "{MAX_NODE_PERCENT_ENV} must be a whole number from 1 to 100"
    );
    Ok(percent.expect("the percentage was validated"))
}

/// What this replica reconciles toward, and where.
#[derive(Clone, Debug, PartialEq)]
pub struct WarmPoolConfig {
    pub placement: Placement,
    pub wanted: WantedPools,
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
                placement: Placement::new(namespace),
                wanted: WantedPools {
                    pools: Vec::new(),
                    max_node_percent: DEFAULT_MAX_NODE_PERCENT,
                    image_cache_enabled: false,
                    draining: true,
                },
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
        let max_node_percent = parse_max_node_percent(&cfg.warm_pool_max_node_percent)?;
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
            placement: Placement::new(namespace),
            wanted: WantedPools {
                pools,
                max_node_percent,
                image_cache_enabled,
                draining: false,
            },
        }))
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
    if config.wanted.draining {
        record_result(PassResult::InvalidConfig);
    } else {
        config_valid_metric().set(1);
    }
    let Some(runtime) = ctx.runtime.clone() else {
        tracing::warn!("warm pools: Kubernetes access unavailable; not reconciling");
        return;
    };
    tracing::info!(
        namespace = %config.placement.namespace,
        pools = config.wanted.pools.len(),
        max_node_percent = config.wanted.max_node_percent,
        image_cache = config.wanted.image_cache_enabled,
        draining = config.wanted.draining,
        "warm pools: reconciling configured shapes"
    );
    let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
    loop {
        ticker.tick().await;
        if let Some(result) =
            tick(runtime.as_ref(), &config, is_leader.load(Ordering::SeqCst)).await
        {
            record_result(result);
        }
    }
}

/// One tick of the loop: the leader has the driver keep the pools; any other
/// replica has it forget what earlier passes remembered, so a leader elected
/// later starts afresh. `None` when no pass ran.
async fn tick(
    runtime: &dyn RuntimeDriver,
    config: &WarmPoolConfig,
    leader: bool,
) -> Option<PassResult> {
    if !leader {
        runtime.forget_pool_memory();
        return None;
    }
    Some(
        match runtime.keep_pools(&config.placement, &config.wanted).await {
            Ok(pass) => PassResult::from(pass),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "warm pools: reconcile failed; retrying");
                PassResult::Error
            }
        },
    )
}

/// #3572: during a release, this replica reports ready only once its own
/// revision's pool of each rotating shape has a ready member, so the outgoing
/// replicas keep serving from their full pools meanwhile and no create misses.
/// A shape rotates when this revision's pool is missing and a pool of the
/// shape at another revision exists: only then does this create the missing
/// template and pool, with one member, and wait. The leader then sizes it to
/// the node cap and drains the older revision (`plan`). Not leader-gated.
///
/// `ready` gates both of orchestration's ways in: `/readyz`, which holds its
/// HTTP traffic, and the start of its Temporal worker ([`pools_warmed`]), which
/// would otherwise run workflow and activity tasks, a create among them, from
/// the still-empty pool (#3572: one create missed so on Dev, 2026-10-30).
/// Anything else is ready at once and left to the leader: a restart beside its
/// own pools, even empty ones, a scale-up, a release that changes no template,
/// a fresh cluster and a newly configured shape. So stops, starts and deletes
/// wait only when a release rotates a pool, and then for at most
/// [`WARM_UP_BOUND`]. `ready` is also set on any error, and when telling
/// whether this start rotates takes longer than [`ROTATION_CHECK_BOUND`].
pub async fn warm_own_pools(ctx: Arc<WorkerContext>, ready: watch::Sender<bool>) {
    hold_until_warm(
        &ready,
        rotation(&ctx),
        |rotation| warm(&ctx, rotation),
        ROTATION_CHECK_BOUND,
        WARM_UP_BOUND,
    )
    .await;
}

/// Waits until `ready` holds, or its sender is gone: the start of a replica's
/// Temporal worker during a release ([`warm_own_pools`]).
pub async fn pools_warmed(ready: &mut watch::Receiver<bool>) {
    let _ = ready.wait_for(|warm| *warm).await;
}

/// [`warm_own_pools`]'s gate: `decide` tells whether this start rotates, and
/// only a rotating start waits for `warm`, each within its bound.
async fn hold_until_warm<R, D, W, F>(
    ready: &watch::Sender<bool>,
    decide: D,
    warm: W,
    decide_bound: Duration,
    warm_bound: Duration,
) where
    D: std::future::Future<Output = anyhow::Result<Option<R>>>,
    W: FnOnce(R) -> F,
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    match tokio::time::timeout(decide_bound, decide).await {
        Ok(Ok(Some(rotation))) => match tokio::time::timeout(warm_bound, warm(rotation)).await {
            Ok(Ok(())) => tracing::info!("warm pools: this revision's pools have ready members"),
            Ok(Err(error)) => tracing::warn!(
                error = %format!("{error:#}"),
                "warm pools: warm-up failed; ready, and starting the Temporal worker, without it"
            ),
            Err(_) => tracing::warn!(
                bound_seconds = warm_bound.as_secs(),
                "warm pools: this revision's pools have no ready member within the bound; \
                 ready, and starting the Temporal worker, without them"
            ),
        },
        Ok(Ok(None)) => {}
        Ok(Err(error)) => tracing::warn!(
            error = %format!("{error:#}"),
            "warm pools: could not tell whether this start rotates its pools; ready at once"
        ),
        Err(_) => tracing::warn!(
            bound_seconds = decide_bound.as_secs(),
            "warm pools: could not tell in time whether this start rotates its pools; ready at once"
        ),
    }
    ready.send_replace(true);
}

/// The pools a release is rotating, and where.
struct Rotation {
    placement: Placement,
    rotating: Vec<DesiredPool>,
}

/// `None` when there is nothing to warm.
async fn rotation(ctx: &WorkerContext) -> anyhow::Result<Option<Rotation>> {
    let image_cache_enabled =
        ImageCacheConfig::from_env(&ctx.sandbox_cfg).map(|config| config.is_some());
    let Startup::Reconcile(config) = startup(&ctx.sandbox_cfg, image_cache_enabled) else {
        return Ok(None);
    };
    let Some(runtime) = ctx.runtime.as_deref() else {
        return Ok(None);
    };
    let rotating = runtime
        .rotating_pools(&config.placement, &config.wanted)
        .await?;
    if rotating.is_empty() {
        return Ok(None);
    }
    Ok(Some(Rotation {
        placement: config.placement,
        rotating,
    }))
}

/// Create each rotating shape's template and one-member pool, then wait until
/// every one has a ready member.
async fn warm(ctx: &WorkerContext, rotation: Rotation) -> anyhow::Result<()> {
    ctx.runtime
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("sandbox backend is not configured"))?
        .warm_pools(&rotation.placement, &rotation.rotating)
        .await
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

impl From<PoolPass> for PassResult {
    fn from(pass: PoolPass) -> Self {
        match pass {
            PoolPass::Unchanged => Self::Unchanged,
            PoolPass::Held => Self::Held,
            PoolPass::Wrote => Self::Wrote,
            PoolPass::Conflict => Self::Conflict,
        }
    }
}

static RECONCILES: OnceLock<IntCounterVec> = OnceLock::new();
static CONFIG_VALID: OnceLock<IntGauge> = OnceLock::new();

fn config_valid_metric() -> &'static IntGauge {
    CONFIG_VALID.get_or_init(|| {
        register_int_gauge!(
            "codewire_warm_pool_config_valid",
            "0 when warm-pool configuration is invalid and every existing pool drains."
        )
        .expect("warm pool config metric registration must be unique")
    })
}

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

#[cfg(test)]
#[path = "warm_pool/tests.rs"]
mod tests;
