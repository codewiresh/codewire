//! Environments on a host in the lifecycle activities (#3609). Each activity
//! asks here first: a host environment's step runs on its host, through
//! [`host_lifecycle`], and the cluster's code never sees it.

use super::*;
use crate::worker::host_lifecycle::{self, OperationScope};

/// A lifecycle activity, as a host environment takes it.
#[derive(Clone, Copy, Debug)]
pub(super) enum Step {
    Create,
    Change(Change),
    /// Setup, sources and reconcile: a host environment starts with an empty
    /// workspace, has no sources yet, and is driven by its host's own reports.
    Nothing,
    /// Not available on a host yet: the environment ends in error saying so.
    Unsupported(&'static str),
}

/// Runs `step` when `authority`'s environment is on a host. `false` when it
/// is not, and the activity goes on to the cluster.
pub(super) async fn ran(
    wctx: &WorkerContext,
    ctx: &ActivityContext,
    authority: &ActivityAuthority,
    step: Step,
) -> Result<bool, ActivityError> {
    let pool = &wctx.pool;
    if !host_lifecycle::is_host(pool, authority.environment_id()).await? {
        return Ok(false);
    }
    match step {
        Step::Nothing => {}
        Step::Create => {
            let scope = scope(ctx)?;
            let created = host_lifecycle::create(pool, authority, &scope);
            run_environment_activity(ctx.clone(), created).await?
        }
        Step::Change(change) => {
            let scope = scope(ctx)?;
            let changed = host_lifecycle::change(pool, authority, &scope, change);
            run_environment_activity(ctx.clone(), changed).await?
        }
        Step::Unsupported(what) => {
            let refused = host_lifecycle::unsupported(pool, authority, what);
            run_environment_activity(ctx.clone(), refused).await?
        }
    }
    Ok(true)
}

/// What names this activity's operation on the host: the same across its
/// retries, as its claim uses.
fn scope(ctx: &ActivityContext) -> anyhow::Result<OperationScope> {
    let (workflow_run_id, scheduled_at_unix_nanos) = claim_authority_metadata(ctx)?;
    Ok(OperationScope {
        workflow_run_id,
        scheduled_at_unix_nanos,
    })
}
