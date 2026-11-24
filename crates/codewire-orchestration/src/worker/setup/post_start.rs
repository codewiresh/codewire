//! The post-start mutation a stop and start runs: Git author and startup
//! script under the setup lease.

use super::*;

/// Reapply Git author metadata and run the current startup script after a
/// stop→start Pod replacement under the same durable process lease used by setup.
pub async fn handle_post_start_configuration(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
    setup_identity: SetupActivityIdentity,
    activity_ctx: ActivityContext,
) -> anyhow::Result<()> {
    let env = load_environment(&ctx.pool, &payload.environment_id).await?;
    let backend = load_backend_row(&ctx.pool, &payload.environment_id).await?;
    let input = to_setup_inputs(&env, &backend);
    let phase = input.setup_phase;
    let phase_authority = SetupPhaseAuthority::new(authority.clone(), setup_identity)?;
    let mut ops = WorkerSetupOps {
        ctx,
        env,
        authority,
        phase_authority: phase_authority.clone(),
        activity_ctx,
        active_phase: phase,
        recovery_lock: std::sync::Arc::new(tokio::sync::Mutex::new(false)),
        launch_group_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        launch_group_reaping: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        health_proven: false,
        defaults_written: false,
    };
    match phase_authority.prepare_post_start_mutation(phase).await? {
        PhasePreparation::Ready(PhaseAcquire::Acquired) => {}
        PhasePreparation::Ready(PhaseAcquire::AlreadyComplete(_)) => {
            return Err(crate::worker::activity_authority::AuthorityLost.into());
        }
        PhasePreparation::Recover(owner) => ops
            .recover_setup_phase(&input, &owner)
            .await
            .map_err(classify_setup_recovery_error)?,
    }

    under_post_start_lease(&phase_authority, phase, async {
        ops.configure_git_identity(&input.namespace).await?;
        run_post_start_script(&mut ops, &input).await?;
        ops.ensure_can_commit().await
    })
    .await
}

/// Finishes the post-start `steps`, run under this activity's lease. On
/// success `complete_post_start_mutation` releases the lease. On any error,
/// including one from `complete_post_start_mutation`, the activity releases
/// its own lease if it is still `claimed` and returns the error unchanged
/// (#6258). A failed release is
/// logged and never replaces the error.
async fn under_post_start_lease(
    phase_authority: &SetupPhaseAuthority,
    phase: i32,
    steps: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let outcome = match steps.await {
        Ok(()) => phase_authority.complete_post_start_mutation(phase).await,
        Err(error) => Err(error),
    };
    if let Err(error) = &outcome {
        release_own_claim_after(phase_authority, phase, error).await;
    }
    outcome
}

async fn release_own_claim_after(
    phase_authority: &SetupPhaseAuthority,
    phase: i32,
    error: &anyhow::Error,
) {
    let identity = phase_authority.identity();
    let environment_id = phase_authority.environment_id();
    match phase_authority.release_own_claimed_owner(phase).await {
        Ok(None) => {}
        Ok(Some(_)) => tracing::info!(
            environment_id,
            activity_generation = identity.generation,
            activity_id = identity.activity_id,
            activity_attempt = identity.attempt,
            phase,
            error = %format_args!("{error:#}"),
            "post-start: released its own claimed setup lease after an error"
        ),
        // Another run or a lifecycle change holds the Sandbox now; this
        // activity may write nothing, so it releases nothing.
        Err(release_error) if is_authority_lost(&release_error) => tracing::info!(
            environment_id,
            activity_generation = identity.generation,
            activity_id = identity.activity_id,
            activity_attempt = identity.attempt,
            phase,
            error = %format_args!("{error:#}"),
            "post-start: authority lost, so its setup lease was not released"
        ),
        Err(release_error) => tracing::warn!(
            environment_id,
            activity_generation = identity.generation,
            activity_id = identity.activity_id,
            activity_attempt = identity.attempt,
            phase,
            error = %format_args!("{error:#}"),
            release_error = %format_args!("{release_error:#}"),
            "post-start: releasing its own claimed setup lease failed"
        ),
    }
}

/// Startup runs on every start, independently of completed install/clone phases.
/// The caller owns the post-start lease and completes it only after this succeeds.
pub(super) async fn run_post_start_script(
    ops: &mut impl SetupOps,
    input: &Inputs,
) -> anyhow::Result<()> {
    if input.startup_script.is_empty() {
        return Ok(());
    }
    ops.emit_log(
        &input.environment_id,
        input.setup_phase,
        "startup_script",
        "started",
        "",
        None,
    )
    .await?;
    let (status, message) = match ops
        .run_startup_script(input, &input.working_directory)
        .await
    {
        Ok(()) => ("completed", String::new()),
        Err(error) if is_setup_control_flow(&error) => return Err(error),
        Err(error) => ("warning", format!("{error:#}")),
    };
    ops.ensure_can_commit().await?;
    ops.emit_log(
        &input.environment_id,
        input.setup_phase,
        "startup_script",
        status,
        &message,
        None,
    )
    .await
}

#[cfg(test)]
#[path = "post_start_tests.rs"]
mod tests;
