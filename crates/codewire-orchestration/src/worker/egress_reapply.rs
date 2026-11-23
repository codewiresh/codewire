//! The startup re-apply of every bound broker Sandbox's environment policy
//! (#6070, `egress::reapply`): before the egress service decides any
//! lockdown, each bound environment's `cw-daemon-net-<env>` is applied again
//! as the access stack now renders it, in its Sandbox's own egress mode. It
//! is bounded by `egress::reapply::SWEEP_BOUND`; past it the service decides
//! anyway, and a Sandbox whose policy still differs is refused.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::WorkerContext;
use super::env_data::load_environment;
use crate::egress::reapply::{PoliciesReapplied, PolicyReapply, SWEEP_BOUND, count_reapply};
use crate::runtime::{Placement, RenderingIntent, RuntimeDriver};

/// Start the sweep where this process has a cluster and the broker settings,
/// and return what the egress service waits on; elsewhere there is nothing to
/// wait for.
pub fn start(ctx: &Arc<WorkerContext>) -> Arc<PoliciesReapplied> {
    if ctx.runtime.is_none() || ctx.sandbox_cfg.hosted_egress.broker.is_none() {
        return PoliciesReapplied::finished();
    }
    let reapplied = PoliciesReapplied::pending();
    tokio::spawn(run(ctx.clone(), reapplied.clone()));
    reapplied
}

/// Run the sweep on this process, then let its egress service decide.
pub async fn run(ctx: Arc<WorkerContext>, reapplied: Arc<PoliciesReapplied>) {
    let sweep = async {
        let Ok(runtime) = ctx.require_runtime() else {
            return;
        };
        let targets = match bound_environments(&ctx).await {
            Ok(targets) => targets,
            Err(error) => {
                tracing::warn!(%error, "egress policy re-apply: read the bound environments");
                return;
            }
        };
        reapply_each(runtime, &targets).await;
    };
    finish_within(SWEEP_BOUND, &reapplied, sweep).await;
}

/// Every environment with a live binding, with the intent its access stack
/// renders from. One that can't be read is logged and left out.
async fn bound_environments(
    ctx: &WorkerContext,
) -> anyhow::Result<Vec<(Placement, RenderingIntent)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT environment_id, namespace FROM sandbox_workspace_bindings
          WHERE released_at IS NULL",
    )
    .fetch_all(&ctx.pool)
    .await?;
    let mut targets = Vec::with_capacity(rows.len());
    for (environment_id, namespace) in rows {
        let intent = async {
            let env = load_environment(&ctx.pool, &environment_id).await?;
            super::create::load_environment_rendering_intent(ctx, &env, env.operation_generation)
                .await
        };
        match intent.await {
            Ok(intent) => targets.push((Placement::new(&namespace), intent)),
            Err(error) => tracing::warn!(
                environment_id,
                error = format!("{error:#}"),
                "egress policy re-apply: render the environment"
            ),
        }
    }
    Ok(targets)
}

/// Apply each target's policy again, in turn; a failure is logged for its
/// environment and the sweep goes on. Returns how many it replaced. A
/// replaced policy differed from the rendering, which a release explains but
/// a change between restarts would too, so each is a warning.
pub(crate) async fn reapply_each(
    runtime: &dyn RuntimeDriver,
    targets: &[(Placement, RenderingIntent)],
) -> usize {
    let mut applied = 0usize;
    for (placement, intent) in targets {
        let environment_id = intent.identity.environment_id.as_str();
        match runtime.reapply_broker_policy(placement, intent).await {
            Ok(outcome) => {
                count_reapply(outcome);
                if outcome == PolicyReapply::Applied {
                    applied += 1;
                    tracing::warn!(
                        environment_id,
                        "egress policy re-apply replaced a policy that differed from its rendering"
                    );
                } else {
                    tracing::debug!(
                        environment_id,
                        outcome = outcome.label(),
                        "egress policy re-apply"
                    );
                }
            }
            Err(error) => tracing::warn!(
                environment_id,
                error = format!("{error:#}"),
                "egress policy re-apply failed; the Sandbox is refused until its policy is applied"
            ),
        }
    }
    tracing::info!(
        environments = targets.len(),
        applied,
        "egress policies applied again"
    );
    applied
}

/// Run `sweep`, at most for `bound`, then mark the sweep finished either way.
/// The sweep is marked finished however it ends, a panic included: a guard
/// does it on drop, so the egress service never stays UNAVAILABLE.
pub(crate) async fn finish_within<T>(
    bound: Duration,
    reapplied: &PoliciesReapplied,
    sweep: impl Future<Output = T>,
) {
    struct Finish<'a>(&'a PoliciesReapplied);
    impl Drop for Finish<'_> {
        fn drop(&mut self) {
            self.0.finish();
        }
    }
    let _finish = Finish(reapplied);
    if tokio::time::timeout(bound, sweep).await.is_err() {
        tracing::warn!(
            bound_seconds = bound.as_secs(),
            "egress policy re-apply did not finish within its bound; deciding anyway, and a policy that differs is refused"
        );
    }
}

#[cfg(test)]
mod tests;
