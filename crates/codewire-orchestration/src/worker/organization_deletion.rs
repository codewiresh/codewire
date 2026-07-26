//! Dark durable organization-deletion activities.
//!
//! Customer DELETE still uses the inherited synchronous bridge until WI-7.
//! These generation-bound activities are reached only by the recoverable
//! WI-5 Temporal workflow and its outbox reconciler.

use std::time::{Duration, Instant};

use chrono::Utc;
use codewire_server_core::AppError;
use codewire_server_core::org_deletion::{
    OrganizationDeletionPhase, advance_organization_deletion_phase,
    finalize_organization_deletion_database, mark_organization_deletion_failed,
    mark_organization_deletion_started, mark_organization_mutation_resolution_required,
    organization_deletion_operation, resolve_organization_mutation_lease,
    unresolved_organization_mutation_leases,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::WorkerContext;
use super::tenant_secret_teardown::{
    OrganizationTenantSecretTeardownInput, teardown_organization_tenant_secrets,
};

const RUNTIME_DEADLINE_CODE: &str = "environment_runtime_dispatch_deadline_elapsed";
const DATABASE_DEADLINE_CODE: &str = "control_plane_database_deadline_elapsed";
const ENVIRONMENT_WAIT_LIMIT: Duration = Duration::from_secs(5 * 60);
const ENVIRONMENT_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDeletionWorkflowInput {
    pub operation_id: String,
    pub organization_id: String,
    pub generation: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDeletionActivityResult {
    pub state: String,
    pub resource_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDeletionFailureInput {
    pub operation: OrganizationDeletionWorkflowInput,
    pub failure_code: String,
}

#[derive(sqlx::FromRow)]
struct EnvironmentState {
    id: String,
    state: String,
    desired_state: String,
    external_cleanup_completed: bool,
}

pub async fn destroy_organization_environments(
    ctx: &WorkerContext,
    input: &OrganizationDeletionWorkflowInput,
) -> Result<OrganizationDeletionActivityResult, AppError> {
    // Activity execution is itself authoritative proof that Temporal accepted
    // the deterministic workflow start. It may race the outbox reconciler's
    // post-start acknowledgement, so make that transition idempotently here
    // before requiring the started phase.
    mark_organization_deletion_started(&ctx.pool, &input.operation_id, input.generation).await?;
    if require_started_phase_or_replay(
        ctx.pool.clone(),
        input,
        OrganizationDeletionPhase::WriteFenced,
        OrganizationDeletionPhase::EnvironmentsDestroyed,
    )
    .await?
    {
        return Ok(OrganizationDeletionActivityResult {
            state: "completed".into(),
            resource_count: 0,
        });
    }
    wait_for_active_deadlines(&ctx.pool, &input.organization_id).await?;

    let runtime_leases = unresolved_organization_mutation_leases(&ctx.pool, &input.organization_id)
        .await?
        .into_iter()
        .filter(|lease| lease.mutation_class == "environment_runtime_dispatch")
        .collect::<Vec<_>>();
    for lease in &runtime_leases {
        if lease.state == "active" {
            mark_organization_mutation_resolution_required(
                &ctx.pool,
                &lease.id,
                RUNTIME_DEADLINE_CODE,
            )
            .await?;
        }
    }

    let environments = load_environments(&ctx.pool, &input.organization_id).await?;
    for environment in &environments {
        sqlx::query(
            r#"UPDATE environments
               SET desired_state = 'destroyed',
                   deletion_requested_at = COALESCE(deletion_requested_at, NOW()),
                   deletion_grace_until = NULL
               WHERE id = $1 AND org_id = $2"#,
        )
        .bind(&environment.id)
        .bind(&input.organization_id)
        .execute(&ctx.pool)
        .await
        .map_err(AppError::from)?;

        let action = if environment.state == "destroyed" {
            "reconcile"
        } else {
            "destroy"
        };
        ctx.temporal_trigger
            .trigger_environment(&environment.id, action)
            .await
            .map_err(|error| {
                tracing::warn!(
                    environment_id = environment.id,
                    action,
                    error = %error,
                    "organization deletion could not trigger environment cleanup"
                );
                AppError::ServiceUnavailable(
                    "organization environment cleanup could not be started".into(),
                )
            })?;
    }

    let deadline = Instant::now() + ENVIRONMENT_WAIT_LIMIT;
    loop {
        let current = load_environments(&ctx.pool, &input.organization_id).await?;
        if current.iter().all(|environment| {
            environment.state == "destroyed"
                && environment.desired_state == "destroyed"
                && environment.external_cleanup_completed
        }) {
            break;
        }
        if Instant::now() >= deadline {
            return Err(AppError::ServiceUnavailable(
                "organization environment cleanup is not complete".into(),
            ));
        }
        tokio::time::sleep(ENVIRONMENT_POLL_INTERVAL).await;
    }

    // The second complete enumeration is the post-drain boundary. Only now
    // can ambiguous pre-fence runtime admissions be resolved.
    let verified = load_environments(&ctx.pool, &input.organization_id).await?;
    if verified.iter().any(|environment| {
        environment.state != "destroyed"
            || environment.desired_state != "destroyed"
            || !environment.external_cleanup_completed
    }) {
        return Err(AppError::ServiceUnavailable(
            "organization environment cleanup changed during re-enumeration".into(),
        ));
    }
    for lease in &runtime_leases {
        resolve_organization_mutation_lease(&ctx.pool, &lease.id).await?;
    }
    require_class_drained(
        &ctx.pool,
        &input.organization_id,
        "environment_runtime_dispatch",
    )
    .await?;
    advance_organization_deletion_phase(
        &ctx.pool,
        &input.operation_id,
        input.generation,
        OrganizationDeletionPhase::EnvironmentsDestroyed,
    )
    .await?;

    Ok(OrganizationDeletionActivityResult {
        state: "completed".into(),
        resource_count: verified.len().try_into().unwrap_or(u32::MAX),
    })
}

pub async fn record_billing_finalized(
    pool: &PgPool,
    input: &OrganizationDeletionWorkflowInput,
) -> Result<OrganizationDeletionActivityResult, AppError> {
    require_class_drained(pool, &input.organization_id, "billing_provider").await?;
    advance_organization_deletion_phase(
        pool,
        &input.operation_id,
        input.generation,
        OrganizationDeletionPhase::BillingFinalized,
    )
    .await?;
    Ok(OrganizationDeletionActivityResult {
        state: "completed".into(),
        resource_count: 0,
    })
}

pub async fn teardown_tenant_secrets(
    ctx: &WorkerContext,
    input: &OrganizationDeletionWorkflowInput,
) -> Result<OrganizationDeletionActivityResult, AppError> {
    if require_started_phase_or_replay(
        ctx.pool.clone(),
        input,
        OrganizationDeletionPhase::BillingFinalized,
        OrganizationDeletionPhase::TenantSecretsRemoved,
    )
    .await?
    {
        return Ok(OrganizationDeletionActivityResult {
            state: "completed".into(),
            resource_count: 0,
        });
    }
    let result = teardown_organization_tenant_secrets(
        &ctx.pool,
        &ctx.secrets,
        &OrganizationTenantSecretTeardownInput {
            operation_id: input.operation_id.clone(),
            organization_id: input.organization_id.clone(),
            generation: input.generation,
        },
    )
    .await?;
    require_class_drained(&ctx.pool, &input.organization_id, "tenant_secret_provider").await?;
    advance_organization_deletion_phase(
        &ctx.pool,
        &input.operation_id,
        input.generation,
        OrganizationDeletionPhase::TenantSecretsRemoved,
    )
    .await?;
    Ok(OrganizationDeletionActivityResult {
        state: "completed".into(),
        resource_count: result.project_path_count,
    })
}

pub async fn reconcile_control_plane_mutations(
    pool: &PgPool,
    input: &OrganizationDeletionWorkflowInput,
) -> Result<OrganizationDeletionActivityResult, AppError> {
    if require_started_phase_or_replay(
        pool.clone(),
        input,
        OrganizationDeletionPhase::TenantSecretsRemoved,
        OrganizationDeletionPhase::ControlPlaneReconciled,
    )
    .await?
    {
        return Ok(OrganizationDeletionActivityResult {
            state: "completed".into(),
            resource_count: 0,
        });
    }
    wait_for_active_deadlines(pool, &input.organization_id).await?;

    let leases = unresolved_organization_mutation_leases(pool, &input.organization_id)
        .await?
        .into_iter()
        .filter(|lease| lease.mutation_class == "control_plane_database")
        .collect::<Vec<_>>();
    for lease in &leases {
        if lease.state == "active" {
            mark_organization_mutation_resolution_required(pool, &lease.id, DATABASE_DEADLINE_CODE)
                .await?;
        }
    }

    // Re-enumerate the entire declared database namespace after every
    // pre-fence database mutation has crossed its enforced deadline. Rows are
    // retained for the following atomic finalizer; only value-blind counts
    // are observed here.
    let dependency_count: i64 = sqlx::query_scalar(
        r#"SELECT
              (SELECT COUNT(*) FROM repo_configs WHERE org_id = $1)
            + (SELECT COUNT(*) FROM environments WHERE org_id = $1)
            + (SELECT COUNT(*) FROM environment_presets WHERE org_id = $1)
            + (SELECT COUNT(*) FROM api_keys WHERE org_id = $1)
            + (SELECT COUNT(*) FROM environment_quotas WHERE org_id = $1)
            + (SELECT COUNT(*) FROM environment_usage_billing WHERE org_id = $1)
            + (SELECT COUNT(*) FROM secret_projects WHERE org_id = $1)
            + (SELECT COUNT(*) FROM org_invitations WHERE org_id = $1)
            + (SELECT COUNT(*) FROM org_members WHERE org_id = $1)"#,
    )
    .bind(&input.organization_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)?;

    for lease in &leases {
        resolve_organization_mutation_lease(pool, &lease.id).await?;
    }
    require_class_drained(pool, &input.organization_id, "control_plane_database").await?;
    advance_organization_deletion_phase(
        pool,
        &input.operation_id,
        input.generation,
        OrganizationDeletionPhase::ControlPlaneReconciled,
    )
    .await?;
    Ok(OrganizationDeletionActivityResult {
        state: "completed".into(),
        resource_count: dependency_count.try_into().unwrap_or(u32::MAX),
    })
}

pub async fn finalize_database(
    pool: &PgPool,
    input: &OrganizationDeletionWorkflowInput,
) -> Result<OrganizationDeletionActivityResult, AppError> {
    let operation = finalize_organization_deletion_database(
        pool,
        &input.operation_id,
        &input.organization_id,
        input.generation,
    )
    .await?;
    Ok(OrganizationDeletionActivityResult {
        state: operation.state,
        resource_count: 0,
    })
}

pub async fn record_failure(
    pool: &PgPool,
    input: &OrganizationDeletionFailureInput,
) -> Result<OrganizationDeletionActivityResult, AppError> {
    let current = organization_deletion_operation(pool, &input.operation.operation_id).await?;
    if current.organization_id != input.operation.organization_id
        || current.generation != input.operation.generation
    {
        return Err(AppError::Conflict(
            "organization deletion generation is no longer current".into(),
        ));
    }
    // A finalizer may have committed while its activity result was lost.
    // Durable completion wins over the workflow's stale failure branch.
    if current.state == "completed" {
        return Ok(OrganizationDeletionActivityResult {
            state: current.state,
            resource_count: 0,
        });
    }
    let operation = mark_organization_deletion_failed(
        pool,
        &input.operation.operation_id,
        input.operation.generation,
        &input.failure_code,
    )
    .await?;
    Ok(OrganizationDeletionActivityResult {
        state: operation.state,
        resource_count: 0,
    })
}

/// Validate one activity's exact input phase, while treating the phase that
/// this same activity commits as a successful lost-result replay.
async fn require_started_phase_or_replay(
    pool: PgPool,
    input: &OrganizationDeletionWorkflowInput,
    input_phase: OrganizationDeletionPhase,
    committed_phase: OrganizationDeletionPhase,
) -> Result<bool, AppError> {
    let operation = organization_deletion_operation(&pool, &input.operation_id).await?;
    if operation.organization_id != input.organization_id
        || operation.generation != input.generation
        || operation.state != "started"
    {
        return Err(AppError::Conflict(
            "organization deletion generation is no longer current".into(),
        ));
    }
    classify_activity_phase(&operation.phase, input_phase, committed_phase)
}

fn classify_activity_phase(
    current_phase: &str,
    input_phase: OrganizationDeletionPhase,
    committed_phase: OrganizationDeletionPhase,
) -> Result<bool, AppError> {
    if current_phase == committed_phase.as_str() {
        return Ok(true);
    }
    if current_phase != input_phase.as_str() {
        return Err(AppError::Conflict(
            "organization deletion phase is no longer current".into(),
        ));
    }
    Ok(false)
}

async fn wait_for_active_deadlines(pool: &PgPool, organization_id: &str) -> Result<(), AppError> {
    loop {
        let active = unresolved_organization_mutation_leases(pool, organization_id)
            .await?
            .into_iter()
            .filter(|lease| lease.state == "active")
            .collect::<Vec<_>>();
        if active.is_empty() {
            return Ok(());
        }
        let now = Utc::now().naive_utc();
        let remaining = active
            .iter()
            .filter_map(|lease| (lease.deadline_at > now).then_some(lease.deadline_at - now))
            .max();
        let Some(remaining) = remaining else {
            return Ok(());
        };
        let sleep = remaining
            .to_std()
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_secs(2));
        tokio::time::sleep(sleep.max(Duration::from_millis(50))).await;
    }
}

async fn require_class_drained(
    pool: &PgPool,
    organization_id: &str,
    mutation_class: &str,
) -> Result<(), AppError> {
    if unresolved_organization_mutation_leases(pool, organization_id)
        .await?
        .iter()
        .any(|lease| lease.mutation_class == mutation_class)
    {
        return Err(AppError::Conflict(
            "organization mutation class still requires recovery".into(),
        ));
    }
    Ok(())
}

async fn load_environments(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Vec<EnvironmentState>, AppError> {
    sqlx::query_as::<_, EnvironmentState>(
        r#"SELECT id, state, desired_state,
                  external_cleanup_completed_at IS NOT NULL
                      AS external_cleanup_completed
           FROM environments WHERE org_id = $1 ORDER BY id"#,
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::{OrganizationDeletionPhase, classify_activity_phase};
    use codewire_server_core::AppError;

    #[test]
    fn activity_phase_accepts_only_input_or_its_own_committed_replay() {
        assert!(
            !classify_activity_phase(
                "write_fenced",
                OrganizationDeletionPhase::WriteFenced,
                OrganizationDeletionPhase::EnvironmentsDestroyed,
            )
            .unwrap()
        );
        assert!(
            classify_activity_phase(
                "environments_destroyed",
                OrganizationDeletionPhase::WriteFenced,
                OrganizationDeletionPhase::EnvironmentsDestroyed,
            )
            .unwrap()
        );
        assert!(matches!(
            classify_activity_phase(
                "billing_finalized",
                OrganizationDeletionPhase::WriteFenced,
                OrganizationDeletionPhase::EnvironmentsDestroyed,
            ),
            Err(AppError::Conflict(_))
        ));
    }
}
