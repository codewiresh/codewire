//! Durable environment resize activity body.

use std::time::Duration;

use super::WorkerContext;
use super::activity_authority::ActivityAuthority;
use super::env_data::{load_backend_row, load_environment, workspace_pvc_anchor};
use crate::api::environment_daemon::{
    list_environment_daemon_sessions_for_worker, stop_environment_daemon_session_for_worker,
};
use crate::api::environment_resize::{
    EnvironmentResizeDisruptionPolicy, EnvironmentResizeExecutionMode, EnvironmentResizeOperation,
    EnvironmentResources, classify_execution_mode, scan_operation,
};
use crate::resize_metrics;
use crate::runtime::{
    FailedLiveResize, MemberRef, Placement, PodResizeInfeasible, RuntimeDriver, VolumeGrowth,
};
use codewire_daemon_proto::daemon::v1::SessionLifecycleState;

const RESIZE_MUTATION_STATES: &[&str] = &["resizing"];
const RESTART_TIMEOUT: Duration = Duration::from_secs(600);
const IN_PLACE_RESIZE_TIMEOUT: Duration = Duration::from_secs(600);
const STORAGE_RESIZE_TIMEOUT: Duration = Duration::from_secs(600);
/// Withdrawing a pending live request needs no new capacity, so a settled
/// Pod shows it within seconds.
const LIVE_RESIZE_WITHDRAW_TIMEOUT: Duration = Duration::from_secs(120);
/// A running environment's runtime is already bound and access-ready, so the
/// identity reconcile before its resize takes seconds. One that has not
/// converged by then is not resized: the operation fails with that reason
/// instead of waiting out the cold-start access budget.
const RUNNING_RUNTIME_RECONCILE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct TerminalResizeFailure {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for TerminalResizeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TerminalResizeFailure {}

pub fn terminal_failure(error: &anyhow::Error) -> Option<&TerminalResizeFailure> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<TerminalResizeFailure>())
}

/// A request the kubelet acknowledged as infeasible fails the operation
/// without the retries that cannot change the answer.
fn infeasible_is_terminal(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<PodResizeInfeasible>() {
        Some(infeasible) => TerminalResizeFailure {
            code: "runtime_apply_failed",
            message: format!("{infeasible}; request a smaller size"),
        }
        .into(),
        None => error,
    }
}

fn active_session(state: i32) -> bool {
    matches!(
        SessionLifecycleState::try_from(state).unwrap_or(SessionLifecycleState::Unspecified),
        SessionLifecycleState::Starting | SessionLifecycleState::Running
    )
}

fn require_runtime(ctx: &WorkerContext) -> anyhow::Result<&dyn RuntimeDriver> {
    ctx.runtime
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("sandbox runtime is unavailable"))
}

async fn active_operation(
    ctx: &WorkerContext,
    environment_id: &str,
) -> anyhow::Result<Option<EnvironmentResizeOperation>> {
    let row = sqlx::query(
        "SELECT * FROM environment_resize_operations
          WHERE environment_id = $1
            AND state IN ('pending', 'applying', 'restarting')
          ORDER BY created_at DESC
          LIMIT 1",
    )
    .bind(environment_id)
    .fetch_optional(&ctx.pool)
    .await?;
    row.as_ref()
        .map(scan_operation)
        .transpose()
        .map_err(Into::into)
}

async fn set_operation_state(
    authority: &ActivityAuthority,
    operation_id: &str,
    state: &str,
) -> anyhow::Result<()> {
    let result = authority
        .execute_for_states(
            RESIZE_MUTATION_STATES,
            sqlx::query(
                "UPDATE environment_resize_operations
                    SET state = $1, updated_at = NOW()
                  WHERE id = $2
                    AND state IN ('pending', 'applying', 'restarting')",
            )
            .bind(state)
            .bind(operation_id),
        )
        .await?;
    if result.rows_affected() == 1 {
        resize_metrics::refresh_active_best_effort(authority.pool()).await;
    }
    Ok(())
}

async fn checkpoint_previous_pod_uid(
    authority: &ActivityAuthority,
    operation: &EnvironmentResizeOperation,
    runtime: &dyn RuntimeDriver,
    placement: &Placement,
) -> anyhow::Result<String> {
    if let Some(uid) = operation
        .previous_pod_uid
        .as_deref()
        .filter(|uid| !uid.trim().is_empty())
    {
        return Ok(uid.to_string());
    }
    let pod = runtime
        .current_member(placement, &operation.environment_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("workspace Pod is unavailable for running environment"))?;
    authority
        .execute_for_states(
            RESIZE_MUTATION_STATES,
            sqlx::query(
                "UPDATE environment_resize_operations
                    SET previous_pod_uid = COALESCE(previous_pod_uid, $1), updated_at = NOW()
                  WHERE id = $2",
            )
            .bind(&pod.uid)
            .bind(&operation.id),
        )
        .await?;
    Ok(pod.uid)
}

async fn enforce_session_policy(
    ctx: &WorkerContext,
    authority: &ActivityAuthority,
    operation: &EnvironmentResizeOperation,
    namespace: &str,
    execution_mode: EnvironmentResizeExecutionMode,
) -> anyhow::Result<()> {
    if operation.previous_state != "running"
        || execution_mode != EnvironmentResizeExecutionMode::Restart
    {
        return Ok(());
    }
    let sessions = list_environment_daemon_sessions_for_worker(
        &ctx.pool,
        ctx.runtime.as_deref(),
        &ctx.sandbox_cfg.session_secret,
        namespace,
        &operation.environment_id,
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let active = sessions
        .into_iter()
        .filter(|session| active_session(session.state))
        .collect::<Vec<_>>();
    if !active.is_empty() && !operation.force {
        return Err(TerminalResizeFailure {
            code: "active_sessions",
            message: format!(
                "environment has {} active session(s); retry resize with force=true",
                active.len()
            ),
        }
        .into());
    }
    for session in active {
        authority
            .run_external_mutation(RESIZE_MUTATION_STATES, async {
                stop_environment_daemon_session_for_worker(
                    &ctx.pool,
                    ctx.runtime.as_deref(),
                    &ctx.sandbox_cfg.session_secret,
                    namespace,
                    &operation.environment_id,
                    &session.session_id,
                )
                .await
                .map(|_| ())
                .map_err(|error| anyhow::anyhow!(error.to_string()))
            })
            .await?;
    }
    Ok(())
}

async fn checkpoint_storage_applied(
    authority: &ActivityAuthority,
    operation: &EnvironmentResizeOperation,
) -> anyhow::Result<()> {
    let mut tx = authority.pool().begin().await?;
    authority
        .lock_transaction_for_states(&mut tx, RESIZE_MUTATION_STATES)
        .await?;
    sqlx::query(
        "UPDATE environment_resize_operations
            SET last_applied_disk_gb = desired_disk_gb, updated_at = NOW()
          WHERE id = $1",
    )
    .bind(&operation.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE environments SET disk_gb = $1 WHERE id = $2")
        .bind(operation.desired_resources.disk_gb)
        .bind(&operation.environment_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn complete_resize(
    authority: &ActivityAuthority,
    operation: &EnvironmentResizeOperation,
    pod_name: Option<&str>,
    pod_ip: Option<&str>,
    applied_mode: EnvironmentResizeExecutionMode,
    pod_replaced: bool,
) -> anyhow::Result<()> {
    let mut tx = authority.pool().begin().await?;
    authority
        .lock_transaction_for_states(&mut tx, RESIZE_MUTATION_STATES)
        .await?;
    sqlx::query(
        "UPDATE environments
            SET cpu_millicores = $1, memory_mb = $2, disk_gb = $3,
                state = $4, desired_state = $5, state_changed_at = NOW(),
                error_reason = NULL
          WHERE id = $6",
    )
    .bind(operation.desired_resources.cpu_millicores)
    .bind(operation.desired_resources.memory_mb)
    .bind(operation.desired_resources.disk_gb)
    .bind(&operation.previous_state)
    .bind(&operation.previous_desired_state)
    .bind(&operation.environment_id)
    .execute(&mut *tx)
    .await?;
    if let (Some(pod_name), Some(pod_ip)) = (pod_name, pod_ip) {
        sqlx::query(
            "UPDATE sandbox_environment_backend
                SET pod_name = $1, pod_ip = $2
              WHERE environment_id = $3",
        )
        .bind(pod_name)
        .bind(pod_ip)
        .bind(&operation.environment_id)
        .execute(&mut *tx)
        .await?;
    }
    let terminal: Option<(chrono::NaiveDateTime, chrono::NaiveDateTime)> = sqlx::query_as(
        "UPDATE environment_resize_operations
            SET last_applied_cpu_millicores = desired_cpu_millicores,
                last_applied_memory_mb = desired_memory_mb,
                last_applied_disk_gb = desired_disk_gb,
                state = 'completed', failure_code = NULL, failure_message = NULL,
                applied_mode = $2, pod_replaced = $3,
                updated_at = NOW(), completed_at = NOW()
          WHERE id = $1
            AND state IN ('pending', 'applying', 'restarting')
          RETURNING created_at, completed_at",
    )
    .bind(&operation.id)
    .bind(applied_mode.as_str())
    .bind(pod_replaced)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    if terminal.is_some() {
        resize_metrics::record_terminal_after_commit("completed", applied_mode, terminal);
        resize_metrics::refresh_active_best_effort(authority.pool()).await;
    }
    Ok(())
}

pub async fn handle_environment_resize(
    ctx: &WorkerContext,
    environment_id: &str,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    authority.ensure_for_states(RESIZE_MUTATION_STATES).await?;
    let Some(operation) = active_operation(ctx, environment_id).await? else {
        return Ok(());
    };
    let backend = load_backend_row(&ctx.pool, environment_id).await?;
    let runtime = require_runtime(ctx)?;
    let placement = Placement::new(&backend.namespace);

    if operation.previous_state == "running" {
        let env = load_environment(&ctx.pool, environment_id).await?;
        tokio::time::timeout(
            RUNNING_RUNTIME_RECONCILE_TIMEOUT,
            super::create::reconcile_runtime_identity(
                ctx,
                &env,
                &backend,
                authority,
                RESIZE_MUTATION_STATES,
            ),
        )
        .await
        .map_err(|_| TerminalResizeFailure {
            code: "runtime_not_ready",
            message: format!(
                "the running workspace did not become access-ready within {} seconds; the resize was not applied",
                RUNNING_RUNTIME_RECONCILE_TIMEOUT.as_secs()
            ),
        })??;
    }

    let pod_state = if operation.previous_state == "running" {
        Some(runtime.resize_state(&placement, environment_id).await?)
    } else {
        None
    };
    let (mut execution_mode, reason) = classify_execution_mode(
        &operation.previous_state,
        operation.last_applied_resources,
        operation.desired_resources,
        pod_state.as_ref(),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if execution_mode == EnvironmentResizeExecutionMode::Restart
        && operation.disruption_policy != EnvironmentResizeDisruptionPolicy::AllowRestart
    {
        return Err(TerminalResizeFailure {
            code: "restart_consent_required",
            message: format!(
                "resize now requires workspace Pod replacement: {reason}; submit a new request with allow-restart consent"
            ),
        }
        .into());
    }
    let mut sessions_enforced = false;
    if execution_mode == EnvironmentResizeExecutionMode::Restart {
        enforce_session_policy(
            ctx,
            authority,
            &operation,
            &backend.namespace,
            execution_mode,
        )
        .await?;
        sessions_enforced = true;
    }
    let previous_pod_uid = if operation.previous_state == "running" {
        Some(checkpoint_previous_pod_uid(authority, &operation, runtime, &placement).await?)
    } else {
        None
    };
    set_operation_state(authority, &operation.id, "applying").await?;

    authority
        .run_external_mutation(
            RESIZE_MUTATION_STATES,
            runtime.set_desired_size(
                &placement,
                environment_id,
                operation.desired_resources.cpu_millicores,
                operation.desired_resources.memory_mb,
                operation.desired_resources.disk_gb,
            ),
        )
        .await?;

    let mut storage_needs_post_restart_wait = false;
    if operation.desired_resources.disk_gb != operation.last_applied_resources.disk_gb {
        authority
            .run_external_mutation(
                RESIZE_MUTATION_STATES,
                runtime.grow_volume(
                    &placement,
                    &workspace_pvc_anchor(&backend),
                    operation.desired_resources.disk_gb,
                ),
            )
            .await?;
        if operation.previous_state == "running" {
            match authority
                .run_while_authoritative_for_states(
                    RESIZE_MUTATION_STATES,
                    runtime.wait_volume_growth(
                        &placement,
                        &workspace_pvc_anchor(&backend),
                        operation.desired_resources.disk_gb,
                        STORAGE_RESIZE_TIMEOUT,
                    ),
                )
                .await?
            {
                VolumeGrowth::Applied => {
                    checkpoint_storage_applied(authority, &operation).await?;
                }
                VolumeGrowth::RequiresPodRestart => {
                    execution_mode = EnvironmentResizeExecutionMode::Restart;
                    storage_needs_post_restart_wait = true;
                    if operation.disruption_policy
                        != EnvironmentResizeDisruptionPolicy::AllowRestart
                    {
                        return Err(TerminalResizeFailure {
                            code: "restart_consent_required",
                            message: "Kubernetes requires workspace Pod replacement to finish filesystem expansion; the volume has grown and its filesystem grows when the workspace Pod is next replaced: stop and start the environment to finish it".into(),
                        }
                        .into());
                    }
                }
            }
        }
    }

    if execution_mode == EnvironmentResizeExecutionMode::Restart && !sessions_enforced {
        enforce_session_policy(
            ctx,
            authority,
            &operation,
            &backend.namespace,
            execution_mode,
        )
        .await?;
    }

    let Some(previous_pod_uid) = previous_pod_uid else {
        return complete_resize(authority, &operation, None, None, execution_mode, false).await;
    };

    if execution_mode == EnvironmentResizeExecutionMode::InPlace {
        if operation.desired_resources.cpu_millicores
            != operation.last_applied_resources.cpu_millicores
            || operation.desired_resources.memory_mb != operation.last_applied_resources.memory_mb
        {
            authority
                .run_while_authoritative_for_states(
                    RESIZE_MUTATION_STATES,
                    runtime.resize_in_place(
                        &placement,
                        environment_id,
                        &previous_pod_uid,
                        operation.desired_resources.cpu_millicores,
                        operation.desired_resources.memory_mb,
                        IN_PLACE_RESIZE_TIMEOUT,
                    ),
                )
                .await
                .map_err(infeasible_is_terminal)?;
        }
        return complete_resize(
            authority,
            &operation,
            None,
            None,
            EnvironmentResizeExecutionMode::InPlace,
            false,
        )
        .await;
    }

    set_operation_state(authority, &operation.id, "restarting").await?;
    authority
        .run_external_mutation(
            RESIZE_MUTATION_STATES,
            runtime.replace_member(
                &placement,
                environment_id,
                &MemberRef {
                    name: backend.pod_name.clone(),
                    uid: previous_pod_uid.clone(),
                },
                ctx.sandbox_cfg.support_image(),
            ),
        )
        .await?;
    let replacement = authority
        .run_while_authoritative_for_states(
            RESIZE_MUTATION_STATES,
            runtime.wait_replacement(
                &placement,
                &MemberRef {
                    name: backend.pod_name.clone(),
                    uid: previous_pod_uid.clone(),
                },
                RESTART_TIMEOUT,
            ),
        )
        .await?;
    if storage_needs_post_restart_wait {
        authority
            .run_while_authoritative_for_states(
                RESIZE_MUTATION_STATES,
                runtime.wait_volume_capacity(
                    &placement,
                    &workspace_pvc_anchor(&backend),
                    operation.desired_resources.disk_gb,
                    STORAGE_RESIZE_TIMEOUT,
                ),
            )
            .await?;
        checkpoint_storage_applied(authority, &operation).await?;
    }
    let pod_ip = runtime.member_address(&placement, environment_id).await?;
    let env = load_environment(&ctx.pool, environment_id).await?;
    super::create::reconcile_runtime_identity(
        ctx,
        &env,
        &backend,
        authority,
        RESIZE_MUTATION_STATES,
    )
    .await?;
    complete_resize(
        authority,
        &operation,
        Some(&replacement.name),
        Some(&pod_ip),
        EnvironmentResizeExecutionMode::Restart,
        true,
    )
    .await
}

/// Run the environment's active resize. A terminal failure, or any failure
/// on the final attempt, ends the operation through
/// [`mark_environment_resize_failed`]; any other failure returns for a retry,
/// which resumes from the durable operation and the observed runtime.
pub async fn run_environment_resize(
    ctx: &WorkerContext,
    environment_id: &str,
    authority: &ActivityAuthority,
    final_attempt: bool,
) -> anyhow::Result<()> {
    let Err(error) = handle_environment_resize(ctx, environment_id, authority).await else {
        return Ok(());
    };
    if let Some(failure) = terminal_failure(&error) {
        let message = failure.message.clone();
        return mark_environment_resize_failed(
            ctx,
            environment_id,
            authority,
            failure.code,
            &message,
        )
        .await;
    }
    if final_attempt {
        return mark_environment_resize_failed(
            ctx,
            environment_id,
            authority,
            "runtime_apply_failed",
            &format!("environment resize did not converge: {error:#}"),
        )
        .await;
    }
    Err(error)
}

/// The workspace Pod incarnation that may hold this operation's live CPU or
/// memory request: recorded before any runtime mutation of a running
/// environment, and only relevant when compute changes.
fn live_compute_pod_uid(operation: &EnvironmentResizeOperation) -> Option<&str> {
    let previous = operation.last_applied_resources;
    let requested = operation.desired_resources;
    let compute_changed = previous.cpu_millicores != requested.cpu_millicores
        || previous.memory_mb != requested.memory_mb;
    operation
        .previous_pod_uid
        .as_deref()
        .filter(|uid| compute_changed && !uid.trim().is_empty())
}

/// The resources a failed operation records and accounts for. CPU and memory
/// follow what its workspace Pod runs or may still apply. Storage never
/// shrinks: it keeps the last applied size, or the requested size once the
/// PVC request was raised, because PVC expansion cannot be undone.
pub(crate) fn failed_resources(
    operation: &EnvironmentResizeOperation,
    live: Option<&FailedLiveResize>,
    storage_requested: bool,
) -> EnvironmentResources {
    let previous = operation.last_applied_resources;
    let requested = operation.desired_resources;
    let (cpu_millicores, memory_mb) = match live {
        None | Some(FailedLiveResize::Settled) => (previous.cpu_millicores, previous.memory_mb),
        Some(FailedLiveResize::Applied) => (requested.cpu_millicores, requested.memory_mb),
        Some(FailedLiveResize::Unknown(_)) => (
            previous.cpu_millicores.max(requested.cpu_millicores),
            previous.memory_mb.max(requested.memory_mb),
        ),
    };
    let disk_gb = if storage_requested {
        previous.disk_gb.max(requested.disk_gb)
    } else {
        previous.disk_gb
    };
    EnvironmentResources {
        cpu_millicores,
        memory_mb,
        disk_gb,
    }
}

fn failed_live_resize_note(live: Option<&FailedLiveResize>) -> String {
    match live {
        Some(FailedLiveResize::Applied) => {
            "; the workspace Pod already runs the requested CPU and memory, which are kept".into()
        }
        Some(FailedLiveResize::Unknown(reason)) => format!(
            "; the workspace Pod's CPU and memory could not be confirmed ({reason}), so the larger \
             of the previous and requested values is recorded and kept for the workspace; submit \
             a new resize to choose another size"
        ),
        None | Some(FailedLiveResize::Settled) => String::new(),
    }
}

/// End an operation that cannot complete. A live CPU/memory request it may
/// have left on its workspace Pod is settled first, on that same incarnation
/// only, so the recorded and accounted resources are what the Pod runs or may
/// still apply: an applied request is kept, and completes the operation when
/// storage is also done; a pending one is withdrawn; one that cannot be
/// confirmed records the larger of the previous and requested values. A raised
/// PVC request is recorded because it cannot be undone. No workspace is
/// restarted here, and storage is never shrunk.
pub async fn mark_environment_resize_failed(
    ctx: &WorkerContext,
    environment_id: &str,
    authority: &ActivityAuthority,
    code: &str,
    message: &str,
) -> anyhow::Result<()> {
    let Some(operation) = active_operation(ctx, environment_id).await? else {
        return Ok(());
    };
    let backend = load_backend_row(&ctx.pool, environment_id).await.ok();
    let target = backend.as_ref().and_then(|backend| {
        let runtime = require_runtime(ctx).ok()?;
        Some((runtime, Placement::new(&backend.namespace)))
    });
    let live = match (live_compute_pod_uid(&operation), &target) {
        (None, _) => None,
        (Some(_), None) => Some(FailedLiveResize::Unknown(
            "the sandbox runtime is unavailable".into(),
        )),
        (Some(pod_uid), Some((runtime, placement))) => Some(
            authority
                .run_while_authoritative_for_states(RESIZE_MUTATION_STATES, async {
                    Ok(runtime
                        .settle_failed_resize(
                            placement,
                            environment_id,
                            pod_uid,
                            (
                                operation.last_applied_resources.cpu_millicores,
                                operation.last_applied_resources.memory_mb,
                            ),
                            (
                                operation.desired_resources.cpu_millicores,
                                operation.desired_resources.memory_mb,
                            ),
                            LIVE_RESIZE_WITHDRAW_TIMEOUT,
                        )
                        .await)
                })
                .await?,
        ),
    };
    let storage_requested = operation.desired_resources.disk_gb
        > operation.last_applied_resources.disk_gb
        && match (&target, &backend) {
            (Some((runtime, placement)), Some(backend)) => runtime
                .volume(placement, &workspace_pvc_anchor(backend))
                .await
                .map_or(true, |storage| {
                    storage.requested_disk_gb >= operation.desired_resources.disk_gb
                }),
            _ => true,
        };
    let recorded = failed_resources(&operation, live.as_ref(), storage_requested);
    if live == Some(FailedLiveResize::Applied)
        && operation.last_applied_resources.disk_gb == operation.desired_resources.disk_gb
    {
        return complete_resize(
            authority,
            &operation,
            None,
            None,
            EnvironmentResizeExecutionMode::InPlace,
            false,
        )
        .await;
    }

    let mut failure_message = format!("{message}{}", failed_live_resize_note(live.as_ref()));
    if let Some((runtime, placement)) = &target
        && let Err(error) = authority
            .run_external_mutation(
                RESIZE_MUTATION_STATES,
                runtime.set_desired_size(
                    placement,
                    environment_id,
                    recorded.cpu_millicores,
                    recorded.memory_mb,
                    recorded.disk_gb.max(operation.desired_resources.disk_gb),
                ),
            )
            .await
    {
        failure_message.push_str(&format!(
            "; runtime desired-state rollback failed: {error:#}"
        ));
    }

    record_failed_resize(authority, &operation, recorded, code, &failure_message).await
}

/// Durably end `operation` as failed, recording `recorded` as the
/// environment's resources and the operation's last applied resources, which
/// quota and billing then account for.
pub(crate) async fn record_failed_resize(
    authority: &ActivityAuthority,
    operation: &EnvironmentResizeOperation,
    recorded: EnvironmentResources,
    code: &str,
    failure_message: &str,
) -> anyhow::Result<()> {
    let mut tx = authority.pool().begin().await?;
    authority
        .lock_transaction_for_states(&mut tx, RESIZE_MUTATION_STATES)
        .await?;
    sqlx::query(
        "UPDATE environments
            SET cpu_millicores = $1, memory_mb = $2, disk_gb = $3,
                state = $4, desired_state = $5, state_changed_at = NOW(),
                error_reason = $6
          WHERE id = $7",
    )
    .bind(recorded.cpu_millicores)
    .bind(recorded.memory_mb)
    .bind(recorded.disk_gb)
    .bind(&operation.previous_state)
    .bind(&operation.previous_desired_state)
    .bind(failure_message)
    .bind(&operation.environment_id)
    .execute(&mut *tx)
    .await?;
    let terminal: Option<(chrono::NaiveDateTime, chrono::NaiveDateTime)> = sqlx::query_as(
        "UPDATE environment_resize_operations
            SET state = 'failed', failure_code = $1, failure_message = $2,
                last_applied_cpu_millicores = $4, last_applied_memory_mb = $5,
                last_applied_disk_gb = $6, updated_at = NOW(), completed_at = NOW()
          WHERE id = $3
            AND state IN ('pending', 'applying', 'restarting')
          RETURNING created_at, completed_at",
    )
    .bind(code)
    .bind(failure_message)
    .bind(&operation.id)
    .bind(recorded.cpu_millicores)
    .bind(recorded.memory_mb)
    .bind(recorded.disk_gb)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    if terminal.is_some() {
        resize_metrics::record_terminal_after_commit("failed", operation.planned_mode, terminal);
        resize_metrics::record_failure(code);
        resize_metrics::refresh_active_best_effort(authority.pool()).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_session_states_are_narrow() {
        assert!(active_session(SessionLifecycleState::Starting as i32));
        assert!(active_session(SessionLifecycleState::Running as i32));
        assert!(!active_session(SessionLifecycleState::Stopped as i32));
        assert!(!active_session(SessionLifecycleState::Exited as i32));
    }

    fn operation(
        previous: (i32, i32, i32),
        desired: (i32, i32, i32),
        pod_uid: Option<&str>,
    ) -> EnvironmentResizeOperation {
        let resources = |(cpu_millicores, memory_mb, disk_gb)| EnvironmentResources {
            cpu_millicores,
            memory_mb,
            disk_gb,
        };
        EnvironmentResizeOperation {
            id: "operation".into(),
            org_id: "org".into(),
            environment_id: "env".into(),
            request_id: "request".into(),
            previous_resources: resources(previous),
            desired_resources: resources(desired),
            last_applied_resources: resources(previous),
            previous_state: "running".into(),
            previous_desired_state: "started".into(),
            state: "applying".into(),
            force: false,
            disruption_policy: EnvironmentResizeDisruptionPolicy::LiveOnly,
            planned_mode: EnvironmentResizeExecutionMode::InPlace,
            applied_mode: None,
            pod_replaced: false,
            reserved_cpu_millicores: 0,
            reserved_memory_mb: 0,
            failure: None,
            previous_pod_uid: pod_uid.map(str::to_owned),
            created_at: chrono::NaiveDateTime::default(),
            updated_at: chrono::NaiveDateTime::default(),
            completed_at: None,
        }
    }

    /// #2474: a failed operation records what its Pod runs or may still
    /// apply, so quota and billing never miss a pending or applied increase.
    #[test]
    fn failed_operation_records_what_the_pod_runs_or_may_still_apply() {
        let increase = operation((1_000, 1_024, 10), (2_000, 4_096, 20), Some("uid"));
        let recorded = |live: Option<FailedLiveResize>| {
            let resources = failed_resources(&increase, live.as_ref(), false);
            (
                resources.cpu_millicores,
                resources.memory_mb,
                resources.disk_gb,
            )
        };
        assert_eq!(recorded(None), (1_000, 1_024, 10));
        assert_eq!(
            recorded(Some(FailedLiveResize::Settled)),
            (1_000, 1_024, 10)
        );
        assert_eq!(
            recorded(Some(FailedLiveResize::Applied)),
            (2_000, 4_096, 10)
        );
        assert_eq!(
            recorded(Some(FailedLiveResize::Unknown("unreadable".into()))),
            (2_000, 4_096, 10)
        );

        // A live CPU decrease that cannot be confirmed keeps the larger value.
        let decrease = operation((2_000, 4_096, 10), (1_000, 4_096, 10), Some("uid"));
        let unknown = failed_resources(
            &decrease,
            Some(&FailedLiveResize::Unknown("x".into())),
            false,
        );
        assert_eq!((unknown.cpu_millicores, unknown.memory_mb), (2_000, 4_096));

        // Completed PVC expansion stays recorded, and a raised PVC request is
        // recorded because it cannot be undone; compute recovery never
        // shrinks storage.
        let mut expanded = increase.clone();
        expanded.last_applied_resources.disk_gb = 20;
        for live in [
            FailedLiveResize::Settled,
            FailedLiveResize::Applied,
            FailedLiveResize::Unknown("x".into()),
        ] {
            assert_eq!(failed_resources(&expanded, Some(&live), false).disk_gb, 20);
            assert_eq!(failed_resources(&increase, Some(&live), true).disk_gb, 20);
            assert_eq!(failed_resources(&increase, Some(&live), false).disk_gb, 10);
        }
    }

    #[test]
    fn only_a_recorded_pod_with_a_compute_change_is_settled() {
        let pod = Some("uid");
        assert_eq!(
            live_compute_pod_uid(&operation((1, 1, 1), (2, 1, 1), pod)),
            pod
        );
        assert_eq!(
            live_compute_pod_uid(&operation((1, 1, 1), (1, 2, 1), pod)),
            pod
        );
        // Storage-only, before the Pod was recorded, or a blank record.
        assert_eq!(
            live_compute_pod_uid(&operation((1, 1, 1), (1, 1, 2), pod)),
            None
        );
        assert_eq!(
            live_compute_pod_uid(&operation((1, 1, 1), (2, 1, 1), None)),
            None
        );
        assert_eq!(
            live_compute_pod_uid(&operation((1, 1, 1), (2, 1, 1), Some(" "))),
            None
        );
    }

    /// #2475: an acknowledged infeasible request fails without retries and
    /// says what to do; any other error stays retryable.
    #[test]
    fn acknowledged_infeasible_request_is_a_terminal_actionable_failure() {
        let error = infeasible_is_terminal(
            PodResizeInfeasible("Node didn't have enough capacity".into()).into(),
        );
        let failure = terminal_failure(&error).expect("terminal");
        assert_eq!(failure.code, "runtime_apply_failed");
        assert!(failure.message.contains("Node didn't have enough capacity"));
        assert!(failure.message.ends_with("request a smaller size"));
        let error = infeasible_is_terminal(anyhow::anyhow!("timeout waiting"));
        assert!(terminal_failure(&error).is_none());
    }

    #[test]
    fn failure_note_names_kept_or_unconfirmed_resources() {
        assert_eq!(failed_live_resize_note(None), "");
        assert_eq!(
            failed_live_resize_note(Some(&FailedLiveResize::Settled)),
            ""
        );
        assert!(
            failed_live_resize_note(Some(&FailedLiveResize::Applied)).contains("which are kept")
        );
        let note = failed_live_resize_note(Some(&FailedLiveResize::Unknown("Pod replaced".into())));
        assert!(note.contains("(Pod replaced)") && note.contains("larger of the previous"));
    }

    #[test]
    fn terminal_failures_retain_actionable_codes() {
        let error: anyhow::Error = TerminalResizeFailure {
            code: "active_sessions",
            message: "stop sessions".into(),
        }
        .into();
        let failure = terminal_failure(&error).unwrap();
        assert_eq!(failure.code, "active_sessions");
        assert_eq!(failure.message, "stop sessions");
    }
}
