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
    classify_execution_mode, scan_operation,
};
use crate::resize_metrics;
use crate::sandbox::client::{SandboxClient, WorkspaceStorageResizeOutcome};
use codewire_daemon_proto::daemon::v1::SessionLifecycleState;

const RESIZE_MUTATION_STATES: &[&str] = &["resizing"];
const RESTART_TIMEOUT: Duration = Duration::from_secs(600);
const IN_PLACE_RESIZE_TIMEOUT: Duration = Duration::from_secs(600);
const STORAGE_RESIZE_TIMEOUT: Duration = Duration::from_secs(600);
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

fn active_session(state: i32) -> bool {
    matches!(
        SessionLifecycleState::try_from(state).unwrap_or(SessionLifecycleState::Unspecified),
        SessionLifecycleState::Starting | SessionLifecycleState::Running
    )
}

fn sandbox_client(ctx: &WorkerContext, namespace: &str) -> anyhow::Result<SandboxClient> {
    let kube = ctx
        .kube
        .clone()
        .ok_or_else(|| anyhow::anyhow!("sandbox runtime is unavailable"))?;
    Ok(SandboxClient::new(kube, namespace))
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
    client: &SandboxClient,
) -> anyhow::Result<String> {
    if let Some(uid) = operation
        .previous_pod_uid
        .as_deref()
        .filter(|uid| !uid.trim().is_empty())
    {
        return Ok(uid.to_string());
    }
    let pod = client
        .get_workspace_pod_identity(&operation.environment_id)
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
        ctx.kube.as_ref(),
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
                    ctx.kube.as_ref(),
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
    let client = sandbox_client(ctx, &backend.namespace)?;

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
        Some(client.workspace_pod_resize_state(environment_id).await?)
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
        Some(checkpoint_previous_pod_uid(authority, &operation, &client).await?)
    } else {
        None
    };
    set_operation_state(authority, &operation.id, "applying").await?;

    authority
        .run_external_mutation(
            RESIZE_MUTATION_STATES,
            client.apply_resize_desired_state(
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
                client.apply_workspace_storage_resize(
                    &workspace_pvc_anchor(&backend),
                    operation.desired_resources.disk_gb,
                ),
            )
            .await?;
        if operation.previous_state == "running" {
            match authority
                .run_while_authoritative_for_states(
                    RESIZE_MUTATION_STATES,
                    client.wait_for_workspace_storage_resize(
                        &workspace_pvc_anchor(&backend),
                        operation.desired_resources.disk_gb,
                        STORAGE_RESIZE_TIMEOUT,
                    ),
                )
                .await?
            {
                WorkspaceStorageResizeOutcome::Applied => {
                    checkpoint_storage_applied(authority, &operation).await?;
                }
                WorkspaceStorageResizeOutcome::RequiresPodRestart => {
                    execution_mode = EnvironmentResizeExecutionMode::Restart;
                    storage_needs_post_restart_wait = true;
                    if operation.disruption_policy
                        != EnvironmentResizeDisruptionPolicy::AllowRestart
                    {
                        return Err(TerminalResizeFailure {
                            code: "restart_consent_required",
                            message: "Kubernetes requires workspace Pod replacement to finish filesystem expansion; retry with allow-restart consent".into(),
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
                    client.resize_workspace_pod_in_place(
                        environment_id,
                        &previous_pod_uid,
                        operation.desired_resources.cpu_millicores,
                        operation.desired_resources.memory_mb,
                        IN_PLACE_RESIZE_TIMEOUT,
                    ),
                )
                .await?;
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
            client.replace_workspace_pod_if_uid(
                environment_id,
                &backend.pod_name,
                &previous_pod_uid,
                ctx.sandbox_cfg.support_image(),
            ),
        )
        .await?;
    let replacement = authority
        .run_while_authoritative_for_states(
            RESIZE_MUTATION_STATES,
            client.wait_for_replacement_workspace_pod(
                &backend.pod_name,
                &previous_pod_uid,
                RESTART_TIMEOUT,
            ),
        )
        .await?;
    if storage_needs_post_restart_wait {
        authority
            .run_while_authoritative_for_states(
                RESIZE_MUTATION_STATES,
                client.wait_for_workspace_storage_capacity(
                    &workspace_pvc_anchor(&backend),
                    operation.desired_resources.disk_gb,
                    STORAGE_RESIZE_TIMEOUT,
                ),
            )
            .await?;
        checkpoint_storage_applied(authority, &operation).await?;
    }
    let pod_ip = client.get_pod_ip(environment_id).await?;
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
    let mut failure_message = message.to_string();
    if let Ok(backend) = load_backend_row(&ctx.pool, environment_id).await
        && let Ok(client) = sandbox_client(ctx, &backend.namespace)
        && let Err(error) = authority
            .run_external_mutation(
                RESIZE_MUTATION_STATES,
                client.apply_resize_desired_state(
                    environment_id,
                    operation.last_applied_resources.cpu_millicores,
                    operation.last_applied_resources.memory_mb,
                    operation
                        .last_applied_resources
                        .disk_gb
                        .max(operation.desired_resources.disk_gb),
                ),
            )
            .await
    {
        failure_message.push_str(&format!(
            "; runtime desired-state rollback failed: {error:#}"
        ));
    }

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
    .bind(operation.last_applied_resources.cpu_millicores)
    .bind(operation.last_applied_resources.memory_mb)
    .bind(operation.last_applied_resources.disk_gb)
    .bind(&operation.previous_state)
    .bind(&operation.previous_desired_state)
    .bind(&failure_message)
    .bind(environment_id)
    .execute(&mut *tx)
    .await?;
    let terminal: Option<(chrono::NaiveDateTime, chrono::NaiveDateTime)> = sqlx::query_as(
        "UPDATE environment_resize_operations
            SET state = 'failed', failure_code = $1, failure_message = $2,
                updated_at = NOW(), completed_at = NOW()
          WHERE id = $3
            AND state IN ('pending', 'applying', 'restarting')
          RETURNING created_at, completed_at",
    )
    .bind(code)
    .bind(&failure_message)
    .bind(&operation.id)
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
