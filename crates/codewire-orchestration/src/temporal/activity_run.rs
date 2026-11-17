//! How a lifecycle activity runs: the authority it must hold, its heartbeat
//! while the work is in flight, and what its context says about the command.

use super::*;

pub(super) async fn required_authority(
    wctx: &WorkerContext,
    cmd: &EnvironmentActivityCommand,
    desired_state: &str,
) -> Result<Option<ActivityAuthority>, ActivityError> {
    match ActivityAuthority::capture_required(
        &wctx.pool,
        &cmd.environment_id,
        desired_state,
        cmd.operation_generation,
    )
    .await
    {
        Ok(authority) => Ok(Some(authority)),
        Err(error) if is_authority_lost(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Records an empty heartbeat. The SDK encodes it before handing it to the
/// worker, which throttles and sends it; encoding `()` cannot fail, and a
/// heartbeat that cannot be sent is never a reason to fail the activity.
pub(super) async fn record_heartbeat(ctx: &ActivityContext) {
    if let Err(error) = ctx.record_heartbeat(()).await {
        tracing::warn!(%error, "activity heartbeat could not be encoded");
    }
}

pub(super) async fn run_environment_activity<T, F>(
    ctx: ActivityContext,
    future: F,
) -> Result<T, ActivityError>
where
    T: Default,
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    let cancel_ctx = ctx.clone();
    let heartbeat_ctx = ctx;
    record_heartbeat(&heartbeat_ctx).await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = cancel_ctx.cancelled() => return Err(ActivityError::cancelled()),
            _ = heartbeat.tick() => record_heartbeat(&heartbeat_ctx).await,
            result = &mut future => {
                return match result {
                    Ok(value) => Ok(value),
                    Err(error) if is_authority_lost(&error) => Ok(T::default()),
                    Err(error) => Err(error.into()),
                };
            }
        }
    }
}

pub(super) async fn run_claim_activity<F>(
    ctx: ActivityContext,
    future: F,
) -> Result<i64, ActivityError>
where
    F: std::future::Future<Output = anyhow::Result<i64>>,
{
    record_heartbeat(&ctx).await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = ctx.cancelled() => return Err(ActivityError::cancelled()),
            _ = heartbeat.tick() => record_heartbeat(&ctx).await,
            result = &mut future => return result.map_err(Into::into),
        }
    }
}

/// Setup cancellation must be acknowledged by the setup handler only after it
/// has fenced any ambiguously attached workspace process by observing the Pod
/// absent. Keep heartbeating while that cleanup runs; unlike the ordinary
/// activity wrapper, do not drop the handler future when cancellation arrives.
pub(super) async fn run_cleanup_aware_environment_activity<T, F>(
    ctx: ActivityContext,
    future: F,
) -> Result<T, ActivityError>
where
    T: Default,
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    record_heartbeat(&ctx).await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // On the heap: an activity's state machine is large, and this one is
    // otherwise held inside the activity future that the SDK moves.
    let mut future = Box::pin(future);

    loop {
        tokio::select! {
            _ = heartbeat.tick() => record_heartbeat(&ctx).await,
            result = &mut future => {
                return match result {
                    Ok(value) => Ok(value),
                    Err(error) if setup::is_setup_activity_cancelled(&error) => {
                        Err(ActivityError::cancelled())
                    }
                    Err(error) if setup::is_setup_recovery_failed(&error) => {
                        Err(error.into())
                    }
                    Err(error) if is_authority_lost(&error) => Ok(T::default()),
                    Err(error) => Err(error.into()),
                };
            }
        }
    }
}

pub(super) fn claim_authority_metadata(ctx: &ActivityContext) -> anyhow::Result<(String, i64)> {
    let info = ctx.info();
    let workflow_run_id = info
        .workflow_run_id
        .as_deref()
        .map(str::trim)
        .filter(|run_id| !run_id.is_empty())
        .ok_or(AuthorityLost)?
        .to_string();
    let scheduled_at_unix_nanos = info
        .scheduled_time
        .ok_or(AuthorityLost)?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AuthorityLost)?
        .as_nanos()
        .try_into()
        .map_err(|_| AuthorityLost)?;
    Ok((workflow_run_id, scheduled_at_unix_nanos))
}

pub(super) fn setup_activity_identity(
    ctx: &ActivityContext,
    cmd: &EnvironmentActivityCommand,
) -> anyhow::Result<SetupActivityIdentity> {
    let info = ctx.info();
    SetupActivityIdentity::new(
        cmd.operation_generation,
        info.activity_id.clone(),
        info.attempt,
    )
}
