//! How a create's or a start's readiness wait ended, when it failed: the
//! marks and reads of its error, and the line its user reads (#3635, #4431).

use super::*;

/// A create's readiness wait expired or failed before its Sandbox bound
/// (review M3). It reads exactly as the wait's own error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct ReadinessWaitFailed(pub(super) anyhow::Error);

/// Mark a readiness wait's failure, so a never-bound pool-born Claim that
/// never became Ready can be re-claimed cold. Authority loss is checked
/// outside this wait and is never marked.
pub(super) async fn readiness_wait<T>(
    wait: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    wait.await.map_err(|error| {
        if crate::worker::activity_authority::is_authority_lost(&error) {
            error
        } else {
            ReadinessWaitFailed(error).into()
        }
    })
}

/// The scheduler's refusal, when the readiness wait ended for lack of room.
pub(in crate::worker) fn no_capacity_refusal(error: &anyhow::Error) -> Option<&NoCapacity> {
    error.downcast_ref::<NoCapacity>().or_else(|| {
        error
            .downcast_ref::<ReadinessWaitFailed>()
            .and_then(|failed| failed.0.downcast_ref::<NoCapacity>())
    })
}

/// The container that could not start, when a readiness wait ended for that.
pub(in crate::worker) fn container_start_failure(
    error: &anyhow::Error,
) -> Option<&ContainerStartFailed> {
    error.downcast_ref::<ContainerStartFailed>().or_else(|| {
        error
            .downcast_ref::<ReadinessWaitFailed>()
            .and_then(|failed| failed.0.downcast_ref::<ContainerStartFailed>())
    })
}

/// End a create whose workspace container cannot start, in place of an error
/// that would retry into the same failed Pod: this activity finishes, and the
/// reconcile it queues does the normal destroy, which releases the claim and
/// the slot (#4431).
pub(in crate::worker) async fn fail_create_for_container_start(
    ctx: &WorkerContext,
    svc: &Service<PgLifecycleStore>,
    authority: &ActivityAuthority,
    env_id: &str,
    failure: &ContainerStartFailed,
) -> anyhow::Result<()> {
    authority.ensure().await?;
    let message = start_failure_text::summary(failure);
    start_failure_text::log(env_id, failure);
    if !svc
        .fail_create_for_container_start(env_id, &message, CREATE_MUTATION_STATES)
        .await?
    {
        return Ok(());
    }
    tracing::warn!(
        environment_id = env_id,
        container = %failure.container,
        reason = %failure.reason,
        "create ended: a workspace container could not start"
    );
    ctx.temporal_trigger
        .trigger_environment(env_id, "reconcile")
        .await
}

/// End a create that never ran, when its readiness wait ended for a cause
/// that retrying can't fix: a container that can't start, or a front door
/// that can't serve its selection. `Ok(true)` when it ended it.
pub(in crate::worker) async fn end_failed_create(
    ctx: &WorkerContext,
    svc: &Service<PgLifecycleStore>,
    authority: &ActivityAuthority,
    env_id: &str,
    error: &anyhow::Error,
) -> anyhow::Result<bool> {
    if let Some(failure) = container_start_failure(error) {
        fail_create_for_container_start(ctx, svc, authority, env_id, failure).await?;
    } else if let Some(refusal) = front_door_hosts::front_door_hosts_unserved(error) {
        front_door_hosts::fail_create_for_front_door_hosts(ctx, svc, authority, env_id, refusal)
            .await?;
    } else {
        return Ok(false);
    }
    Ok(true)
}

/// A failed wait's line in the environment's log, which its user reads. The
/// scheduler's words describe the cluster's nodes, so a refusal says what the
/// user can do; [`refuse_for_no_capacity`] keeps them in the worker's log.
pub(in crate::worker) fn wait_failure_log(
    error: &anyhow::Error,
    outcome: crate::lifecycle::NoCapacityRefusal,
) -> String {
    if no_capacity_refusal(error).is_some() {
        return outcome.message.to_owned();
    }
    match container_start_failure(error) {
        Some(failure) => start_failure_text::summary(failure),
        None => format!("{error:#}"),
    }
}
