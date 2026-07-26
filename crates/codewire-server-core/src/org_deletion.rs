//! Durable organization-deletion bridge primitives.
//!
//! WI-1 deliberately does not route customer DELETE traffic here. It lays
//! down the durable cross-replica mutation barrier, transactional write fence,
//! and recoverable Temporal-start record used by the later dark workflow and
//! entrypoint flip.

use std::future::Future;
use std::time::Duration;

use axum::http::StatusCode;
use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::AppError;

const DELETION_REQUESTED_ACTION: &str = "org.deletion_requested";
const DELETION_RETRY_REQUESTED_ACTION: &str = "org.deletion_retry_requested";
const INITIAL_PHASE: &str = "write_fenced";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationDeletionPhase {
    WriteFenced,
    EnvironmentsDestroyed,
    BillingFinalized,
    TenantSecretsRemoved,
    ControlPlaneReconciled,
    Completed,
}

impl OrganizationDeletionPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WriteFenced => "write_fenced",
            Self::EnvironmentsDestroyed => "environments_destroyed",
            Self::BillingFinalized => "billing_finalized",
            Self::TenantSecretsRemoved => "tenant_secrets_removed",
            Self::ControlPlaneReconciled => "control_plane_reconciled",
            Self::Completed => "completed",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::WriteFenced => 0,
            Self::EnvironmentsDestroyed => 1,
            Self::BillingFinalized => 2,
            Self::TenantSecretsRemoved => 3,
            Self::ControlPlaneReconciled => 4,
            Self::Completed => 5,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "write_fenced" => Some(Self::WriteFenced),
            "environments_destroyed" => Some(Self::EnvironmentsDestroyed),
            "billing_finalized" => Some(Self::BillingFinalized),
            "tenant_secrets_removed" => Some(Self::TenantSecretsRemoved),
            "control_plane_reconciled" => Some(Self::ControlPlaneReconciled),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }
}

/// Bounded classes give later reconciliation work one closed set of recovery
/// contracts. Callers cannot supply arbitrary class names or deadlines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationMutationClass {
    ControlPlaneDatabase,
    EnvironmentRuntimeDispatch,
    TenantSecretProvider,
    BillingProvider,
}

impl OrganizationMutationClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlaneDatabase => "control_plane_database",
            Self::EnvironmentRuntimeDispatch => "environment_runtime_dispatch",
            Self::TenantSecretProvider => "tenant_secret_provider",
            Self::BillingProvider => "billing_provider",
        }
    }

    fn deadline_seconds(self) -> i64 {
        match self {
            Self::ControlPlaneDatabase => 30,
            Self::EnvironmentRuntimeDispatch => 60,
            Self::TenantSecretProvider | Self::BillingProvider => 30,
        }
    }
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub struct OrganizationMutationLease {
    pub id: String,
    pub organization_id: String,
    pub mutation_class: String,
    pub state: String,
    pub admitted_at: NaiveDateTime,
    pub deadline_at: NaiveDateTime,
    pub released_at: Option<NaiveDateTime>,
    pub resolution_required_at: Option<NaiveDateTime>,
    pub resolved_at: Option<NaiveDateTime>,
    pub recovery_code: Option<String>,
    pub updated_at: NaiveDateTime,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub struct OrganizationDeletionOperation {
    pub id: String,
    pub organization_id: String,
    pub generation: i64,
    pub requested_by: String,
    pub workflow_id: String,
    pub state: String,
    pub phase: String,
    pub failure_code: Option<String>,
    pub start_attempts: i32,
    pub last_start_attempt_at: Option<NaiveDateTime>,
    pub started_at: Option<NaiveDateTime>,
    pub completed_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, FromRow)]
struct LockedOrganization {
    deletion_state: String,
    deletion_generation: i64,
    deletion_operation_id: Option<String>,
    role: Option<String>,
}

#[derive(Serialize)]
struct DeletionAuditMetadata<'a> {
    organization_id: &'a str,
    operation_id: &'a str,
    generation: i64,
    state: &'static str,
}

/// Admit one mutation before the deletion fence in a short transaction.
///
/// Both admission and deletion lock the same organization row, so their
/// commits have one cross-replica order. This function commits before it
/// returns: provider work and ordinary queries never retain a pooled
/// connection or database lock.
pub async fn acquire_organization_mutation_lease(
    pool: &PgPool,
    organization_id: &str,
    mutation_class: OrganizationMutationClass,
) -> Result<OrganizationMutationLease, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let deletion_state: Option<String> =
        sqlx::query_scalar(r#"SELECT deletion_state FROM organizations WHERE id = $1 FOR UPDATE"#)
            .bind(organization_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::from)?;

    match deletion_state.as_deref() {
        Some("active") => {}
        Some("deleting" | "delete_failed") => {
            return Err(state_conflict("organization deletion is in progress"));
        }
        Some(_) => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "organization {organization_id} has an unknown deletion state"
            )));
        }
        None => return Err(AppError::NotFound("organization not found".into())),
    }

    let lease_id = format!("organization-mutation/{}", Uuid::new_v4());
    let lease = sqlx::query_as::<_, OrganizationMutationLease>(
        r#"
        INSERT INTO organization_mutation_leases
            (id, organization_id, mutation_class, deadline_at)
        VALUES ($1, $2, $3, NOW() + ($4 * INTERVAL '1 second'))
        RETURNING *
        "#,
    )
    .bind(&lease_id)
    .bind(organization_id)
    .bind(mutation_class.as_str())
    .bind(mutation_class.deadline_seconds())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::from)?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(lease)
}

/// Record a known mutation outcome. Rows are retained as value-blind
/// evidence; release changes state instead of deleting the lease.
pub async fn release_organization_mutation_lease(
    pool: &PgPool,
    lease_id: &str,
) -> Result<OrganizationMutationLease, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let lease = lock_mutation_lease(&mut tx, lease_id).await?;
    if lease.state == "active" {
        sqlx::query(
            r#"
            UPDATE organization_mutation_leases
            SET state = 'released', released_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND state = 'active'
            "#,
        )
        .bind(lease_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
    } else if lease.state != "released" {
        return Err(mutation_lease_conflict(
            "organization mutation lease requires reconciliation",
        ));
    }
    let lease = load_mutation_lease(&mut tx, lease_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(lease)
}

/// Preserve an ambiguous timeout/crash boundary for class-specific recovery.
/// A deadline alone never resolves or releases the lease.
pub async fn mark_organization_mutation_resolution_required(
    pool: &PgPool,
    lease_id: &str,
    recovery_code: &str,
) -> Result<OrganizationMutationLease, AppError> {
    if !valid_safe_code(recovery_code) {
        return Err(AppError::BadRequest(
            "invalid mutation recovery code".into(),
        ));
    }

    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let lease = lock_mutation_lease(&mut tx, lease_id).await?;
    if lease.state == "active" {
        sqlx::query(
            r#"
            UPDATE organization_mutation_leases
            SET state = 'resolution_required',
                resolution_required_at = NOW(),
                recovery_code = $2,
                updated_at = NOW()
            WHERE id = $1 AND state = 'active'
            "#,
        )
        .bind(lease_id)
        .bind(recovery_code)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
    } else if lease.state != "resolution_required"
        || lease.recovery_code.as_deref() != Some(recovery_code)
    {
        return Err(mutation_lease_conflict(
            "organization mutation lease recovery evidence is immutable",
        ));
    }
    let lease = load_mutation_lease(&mut tx, lease_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(lease)
}

/// Resolve ambiguity only after the mutation class's later WI proves a
/// provider-specific outcome or conservative quiescence boundary.
pub async fn resolve_organization_mutation_lease(
    pool: &PgPool,
    lease_id: &str,
) -> Result<OrganizationMutationLease, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let lease = lock_mutation_lease(&mut tx, lease_id).await?;
    if lease.state == "resolution_required" {
        sqlx::query(
            r#"
            UPDATE organization_mutation_leases
            SET state = 'resolved', resolved_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND state = 'resolution_required'
            "#,
        )
        .bind(lease_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
    } else if lease.state != "resolved" {
        return Err(mutation_lease_conflict(
            "organization mutation lease has no resolved ambiguity evidence",
        ));
    }
    let lease = load_mutation_lease(&mut tx, lease_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(lease)
}

pub async fn unresolved_organization_mutation_leases(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Vec<OrganizationMutationLease>, AppError> {
    sqlx::query_as::<_, OrganizationMutationLease>(
        r#"
        SELECT * FROM organization_mutation_leases
        WHERE organization_id = $1
          AND state IN ('active', 'resolution_required')
        ORDER BY admitted_at, id
        "#,
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// Finalizers call this before removing the organization boundary. The later
/// workflow WI performs class-specific reconciliation; this guard never
/// treats an expired deadline as proof that a mutation is absent.
pub async fn require_organization_mutation_barrier_drained(
    pool: &PgPool,
    organization_id: &str,
) -> Result<(), AppError> {
    let unresolved: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM organization_mutation_leases
            WHERE organization_id = $1
              AND state IN ('active', 'resolution_required')
        )
        "#,
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)?;
    if unresolved {
        return Err(AppError::Coded {
            status: StatusCode::CONFLICT,
            code: "organization_mutation_barrier_not_drained",
            detail: "organization mutations still require recovery".into(),
        });
    }
    Ok(())
}

/// Run a bounded mutation whose returned error is a known outcome. Request
/// cancellation drops this future before release and deliberately leaves the
/// lease for conservative recovery.
pub async fn run_organization_database_mutation<T, F>(
    pool: &PgPool,
    organization_id: &str,
    operation: F,
) -> Result<T, AppError>
where
    F: Future<Output = Result<T, AppError>>,
{
    let lease = acquire_organization_mutation_lease(
        pool,
        organization_id,
        OrganizationMutationClass::ControlPlaneDatabase,
    )
    .await?;
    match tokio::time::timeout(Duration::from_secs(30), operation).await {
        Ok(result) => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            result
        }
        Err(_) => {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                "control_plane_database_timeout",
            )
            .await?;
            Err(AppError::InternalMsg(
                "organization database mutation timed out".into(),
            ))
        }
    }
}

/// Runtime admission distinguishes a known request result from an ambiguous
/// Temporal/provider dispatch boundary. Request cancellation drops the future
/// before either terminal update and intentionally leaves the lease active for
/// conservative reconciliation.
pub enum OrganizationRuntimeMutationError {
    Known(AppError),
    Ambiguous(AppError),
}

/// A billing-provider mutation distinguishes a request that is known not to
/// have changed Stripe from a transport boundary whose remote outcome is
/// unknown. The latter must retain durable recovery evidence until the
/// deletion billing phase re-enumerates the provider namespace.
pub enum OrganizationBillingMutationError {
    Known(AppError),
    Ambiguous(AppError),
}

/// A tenant-secret provider mutation distinguishes a rejection whose outcome
/// is known from a transport boundary that may have committed remotely. The
/// latter remains durable evidence until the deletion secret phase
/// re-enumerates the complete organization namespace.
pub enum OrganizationTenantSecretMutationError {
    Known(AppError),
    Ambiguous(AppError),
}

impl OrganizationTenantSecretMutationError {
    pub fn known(error: AppError) -> Self {
        Self::Known(error)
    }

    pub fn ambiguous(error: AppError) -> Self {
        Self::Ambiguous(error)
    }
}

impl OrganizationBillingMutationError {
    pub fn known(error: AppError) -> Self {
        Self::Known(error)
    }

    pub fn ambiguous(error: AppError) -> Self {
        Self::Ambiguous(error)
    }
}

/// Run one Stripe mutation behind the cross-replica organization fence.
///
/// The lease transaction commits before the provider call begins and the
/// provider future is bounded by the same server-selected class deadline as
/// its durable evidence. Dropping this future leaves the lease active;
/// transport errors and elapsed deadlines move it to `resolution_required`.
pub async fn run_organization_billing_mutation<T, F>(
    pool: &PgPool,
    organization_id: &str,
    operation: F,
) -> Result<T, AppError>
where
    F: Future<Output = Result<T, OrganizationBillingMutationError>>,
{
    let lease = acquire_organization_mutation_lease(
        pool,
        organization_id,
        OrganizationMutationClass::BillingProvider,
    )
    .await?;

    match tokio::time::timeout(Duration::from_secs(30), operation).await {
        Ok(Ok(value)) => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            Ok(value)
        }
        Ok(Err(OrganizationBillingMutationError::Known(error))) => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            Err(error)
        }
        Ok(Err(OrganizationBillingMutationError::Ambiguous(error))) => {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                "billing_provider_ambiguous",
            )
            .await?;
            Err(error)
        }
        Err(_) => {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                "billing_provider_timeout",
            )
            .await?;
            Err(AppError::InternalMsg(
                "billing provider request timed out".into(),
            ))
        }
    }
}

/// Run one tenant-secret mutation behind the cross-replica organization
/// fence and the server-selected provider deadline.
///
/// Request cancellation leaves an active lease. Transport ambiguity and an
/// elapsed deadline retain `resolution_required` evidence until the dark
/// tenant-secret teardown re-enumerates every organization-owned path.
pub async fn run_organization_tenant_secret_mutation<T, F>(
    pool: &PgPool,
    organization_id: &str,
    operation: F,
) -> Result<T, AppError>
where
    F: Future<Output = Result<T, OrganizationTenantSecretMutationError>>,
{
    let lease = acquire_organization_mutation_lease(
        pool,
        organization_id,
        OrganizationMutationClass::TenantSecretProvider,
    )
    .await?;

    match tokio::time::timeout(Duration::from_secs(30), operation).await {
        Ok(Ok(value)) => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            Ok(value)
        }
        Ok(Err(OrganizationTenantSecretMutationError::Known(error))) => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            Err(error)
        }
        Ok(Err(OrganizationTenantSecretMutationError::Ambiguous(error))) => {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                "tenant_secret_provider_ambiguous",
            )
            .await?;
            Err(error)
        }
        Err(_) => {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                "tenant_secret_provider_timeout",
            )
            .await?;
            Err(AppError::InternalMsg(
                "tenant secret provider request timed out".into(),
            ))
        }
    }
}

impl OrganizationRuntimeMutationError {
    pub fn ambiguous(error: AppError) -> Self {
        Self::Ambiguous(error)
    }
}

impl From<AppError> for OrganizationRuntimeMutationError {
    fn from(error: AppError) -> Self {
        Self::Known(error)
    }
}

pub async fn run_organization_runtime_mutation<T, F>(
    pool: &PgPool,
    organization_id: &str,
    operation: F,
) -> Result<T, AppError>
where
    F: Future<Output = Result<T, OrganizationRuntimeMutationError>>,
{
    let lease = acquire_organization_mutation_lease(
        pool,
        organization_id,
        OrganizationMutationClass::EnvironmentRuntimeDispatch,
    )
    .await?;
    finish_organization_runtime_mutation(pool, lease, operation).await
}

/// Admit an environment-scoped runtime mutation in the same organization-row
/// order as external cleanup completion. If cleanup won that order, the
/// post-admission state read rejects the stale request; if admission won, the
/// durable lease keeps the cleanup marker blocked until the outcome is known.
pub async fn run_environment_runtime_mutation<T, F>(
    pool: &PgPool,
    organization_id: &str,
    environment_id: &str,
    operation: F,
) -> Result<T, AppError>
where
    F: Future<Output = Result<T, OrganizationRuntimeMutationError>>,
{
    let lease =
        acquire_environment_runtime_mutation_lease(pool, organization_id, environment_id).await?;
    finish_organization_runtime_mutation(pool, lease, operation).await
}

pub async fn acquire_environment_runtime_mutation_lease(
    pool: &PgPool,
    organization_id: &str,
    environment_id: &str,
) -> Result<OrganizationMutationLease, AppError> {
    let lease = acquire_organization_mutation_lease(
        pool,
        organization_id,
        OrganizationMutationClass::EnvironmentRuntimeDispatch,
    )
    .await?;
    let mutable: Option<bool> = sqlx::query_scalar(
        r#"SELECT state NOT IN ('destroying', 'destroyed')
                  AND desired_state <> 'destroyed'
                  AND external_cleanup_completed_at IS NULL
           FROM environments
           WHERE id = $1 AND org_id = $2"#,
    )
    .bind(environment_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?;
    match mutable {
        Some(true) => {}
        Some(false) => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            return Err(AppError::Conflict(
                "environment destruction is in progress".into(),
            ));
        }
        None => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            return Err(AppError::NotFound("environment not found".into()));
        }
    }
    Ok(lease)
}

async fn finish_organization_runtime_mutation<T, F>(
    pool: &PgPool,
    lease: OrganizationMutationLease,
    operation: F,
) -> Result<T, AppError>
where
    F: Future<Output = Result<T, OrganizationRuntimeMutationError>>,
{
    match tokio::time::timeout(Duration::from_secs(60), operation).await {
        Ok(Ok(value)) => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            Ok(value)
        }
        Ok(Err(OrganizationRuntimeMutationError::Known(error))) => {
            release_organization_mutation_lease(pool, &lease.id).await?;
            Err(error)
        }
        Ok(Err(OrganizationRuntimeMutationError::Ambiguous(error))) => {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                "environment_runtime_dispatch_ambiguous",
            )
            .await?;
            Err(error)
        }
        Err(_) => {
            mark_organization_mutation_resolution_required(
                pool,
                &lease.id,
                "environment_runtime_dispatch_timeout",
            )
            .await?;
            Err(AppError::InternalMsg(
                "environment runtime dispatch timed out".into(),
            ))
        }
    }
}

/// Atomically fence an organization, revoke its machine credentials, and
/// persist the recoverable workflow-start intent.
///
/// Repeating the call while the current generation is deleting returns the
/// existing operation. Retrying a retained `delete_failed` organization
/// advances the generation and creates a new deterministic operation.
pub async fn begin_organization_deletion(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> Result<OrganizationDeletionOperation, AppError> {
    let initial_phase = require_safe_deletion_phase(INITIAL_PHASE)?;
    if !user.permits_organization(org_id) {
        return Err(AppError::NotFound("organization not found".into()));
    }

    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let locked = sqlx::query_as::<_, LockedOrganization>(
        r#"
        SELECT o.deletion_state,
               o.deletion_generation,
               o.deletion_operation_id,
               m.role
        FROM organizations o
        LEFT JOIN org_members m
          ON m.org_id = o.id AND m.user_id = $2
        WHERE o.id = $1
        FOR UPDATE OF o
        "#,
    )
    .bind(org_id)
    .bind(&user.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::NotFound("organization not found".into()))?;

    let role = locked
        .role
        .as_deref()
        .ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    if role != "owner" {
        return Err(AppError::Forbidden);
    }

    if locked.deletion_state == "deleting" {
        let operation_id = locked.deletion_operation_id.ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "deleting organization {org_id} has no operation id"
            ))
        })?;
        let operation = load_operation(&mut tx, &operation_id).await?;
        tx.commit().await.map_err(AppError::from)?;
        return Ok(operation);
    }

    if !matches!(locked.deletion_state.as_str(), "active" | "delete_failed") {
        return Err(AppError::Internal(anyhow::anyhow!(
            "organization {org_id} has unknown deletion state {}",
            locked.deletion_state
        )));
    }

    let generation = locked.deletion_generation + 1;
    let operation_id = format!("organization-deletion/{org_id}/{generation}");
    let workflow_id = operation_id.clone();
    let audit_action = if locked.deletion_state == "delete_failed" {
        DELETION_RETRY_REQUESTED_ACTION
    } else {
        DELETION_REQUESTED_ACTION
    };

    sqlx::query(
        r#"
        INSERT INTO organization_deletion_operations
            (id, organization_id, generation, requested_by, workflow_id,
             state, phase)
        VALUES ($1, $2, $3, $4, $5, 'pending_start', $6)
        "#,
    )
    .bind(&operation_id)
    .bind(org_id)
    .bind(generation)
    .bind(&user.user_id)
    .bind(&workflow_id)
    .bind(initial_phase)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    sqlx::query(
        r#"
        UPDATE organizations
        SET deletion_state = 'deleting',
            deletion_generation = $2,
            deletion_requested_by = $3,
            deletion_requested_at = NOW(),
            deletion_operation_id = $4,
            deletion_workflow_id = $5,
            deletion_phase = $6,
            deletion_failure_code = NULL,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(org_id)
    .bind(generation)
    .bind(&user.user_id)
    .bind(&operation_id)
    .bind(&workflow_id)
    .bind(initial_phase)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    sqlx::query(
        r#"UPDATE api_keys SET disabled_at = COALESCE(disabled_at, NOW()) WHERE org_id = $1"#,
    )
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    let metadata = serde_json::to_value(DeletionAuditMetadata {
        organization_id: org_id,
        operation_id: &operation_id,
        generation,
        state: "deleting",
    })
    .map_err(|error| AppError::Internal(error.into()))?;
    sqlx::query(
        r#"
        INSERT INTO audit_logs
            (id, timestamp, action, user_id, metadata, severity)
        VALUES ($1, NOW(), $2, $3, $4, 'info')
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(audit_action)
    .bind(&user.user_id)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    let operation = load_operation(&mut tx, &operation_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(operation)
}

/// Recover committed operations whose deterministic Temporal workflow has
/// not yet been durably acknowledged as started.
pub async fn pending_organization_deletion_operations(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<OrganizationDeletionOperation>, AppError> {
    if !(1..=1_000).contains(&limit) {
        return Err(AppError::BadRequest(
            "limit must be between 1 and 1000".into(),
        ));
    }

    sqlx::query_as::<_, OrganizationDeletionOperation>(
        r#"
        SELECT op.*
        FROM organization_deletion_operations op
        JOIN organizations org
          ON org.id = op.organization_id
         AND org.deletion_state = 'deleting'
         AND org.deletion_generation = op.generation
         AND org.deletion_operation_id = op.id
        WHERE op.state = 'pending_start'
        ORDER BY op.created_at, op.id
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// Record a deterministic workflow-start attempt before contacting Temporal.
/// A crash after this commit leaves the operation pending and discoverable.
pub async fn record_organization_deletion_start_attempt(
    pool: &PgPool,
    operation_id: &str,
    generation: i64,
) -> Result<OrganizationDeletionOperation, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    lock_current_operation(&mut tx, operation_id, generation, &["deleting"]).await?;
    sqlx::query(
        r#"
        UPDATE organization_deletion_operations
        SET start_attempts = start_attempts + 1,
            last_start_attempt_at = NOW(),
            updated_at = NOW()
        WHERE id = $1 AND generation = $2 AND state = 'pending_start'
        "#,
    )
    .bind(operation_id)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    let operation = load_operation(&mut tx, operation_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(operation)
}

/// Mark the current generation's deterministic workflow as started.
/// Duplicate acknowledgements are idempotent.
pub async fn mark_organization_deletion_started(
    pool: &PgPool,
    operation_id: &str,
    generation: i64,
) -> Result<OrganizationDeletionOperation, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    lock_current_operation(&mut tx, operation_id, generation, &["deleting"]).await?;
    sqlx::query(
        r#"
        UPDATE organization_deletion_operations
        SET state = 'started',
            started_at = COALESCE(started_at, NOW()),
            updated_at = NOW()
        WHERE id = $1 AND generation = $2 AND state = 'pending_start'
        "#,
    )
    .bind(operation_id)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    let operation = load_operation(&mut tx, operation_id).await?;
    if operation.state != "started" {
        return Err(state_conflict(
            "organization deletion workflow cannot be started",
        ));
    }
    tx.commit().await.map_err(AppError::from)?;
    Ok(operation)
}

/// Retain a terminal forward-only failure for the current generation.
pub async fn mark_organization_deletion_failed(
    pool: &PgPool,
    operation_id: &str,
    generation: i64,
    failure_code: &str,
) -> Result<OrganizationDeletionOperation, AppError> {
    if !valid_failure_code(failure_code) {
        return Err(AppError::BadRequest("invalid deletion failure code".into()));
    }

    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let organization_id = lock_current_operation(
        &mut tx,
        operation_id,
        generation,
        &["deleting", "delete_failed"],
    )
    .await?;
    let existing = load_operation(&mut tx, operation_id).await?;
    if existing.state == "failed" {
        tx.commit().await.map_err(AppError::from)?;
        return Ok(existing);
    }
    if !matches!(existing.state.as_str(), "pending_start" | "started") {
        return Err(stale_generation_conflict(
            "organization deletion operation is already terminal",
        ));
    }
    let operation_transition = sqlx::query(
        r#"
        UPDATE organization_deletion_operations
        SET state = 'failed', failure_code = $3, updated_at = NOW()
        WHERE id = $1 AND generation = $2 AND state IN ('pending_start', 'started')
        "#,
    )
    .bind(operation_id)
    .bind(generation)
    .bind(failure_code)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if operation_transition.rows_affected() != 1 {
        return Err(stale_generation_conflict(
            "organization deletion operation could not transition to failed",
        ));
    }
    let organization_transition = sqlx::query(
        r#"
        UPDATE organizations
        SET deletion_state = 'delete_failed',
            deletion_failure_code = $3,
            updated_at = NOW()
        WHERE id = $1 AND deletion_generation = $2 AND deletion_state = 'deleting'
        "#,
    )
    .bind(&organization_id)
    .bind(generation)
    .bind(failure_code)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if organization_transition.rows_affected() != 1 {
        return Err(stale_generation_conflict(
            "organization deletion operation is no longer current",
        ));
    }
    let operation = load_operation(&mut tx, operation_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(operation)
}

pub async fn organization_deletion_operation(
    pool: &PgPool,
    operation_id: &str,
) -> Result<OrganizationDeletionOperation, AppError> {
    sqlx::query_as::<_, OrganizationDeletionOperation>(
        "SELECT * FROM organization_deletion_operations WHERE id = $1",
    )
    .bind(operation_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::NotFound("organization deletion operation not found".into()))
}

/// Advance one current generation through the closed, deterministic phase
/// sequence. Replaying the same transition is idempotent; skipping or
/// rewinding a phase is rejected.
pub async fn advance_organization_deletion_phase(
    pool: &PgPool,
    operation_id: &str,
    generation: i64,
    next: OrganizationDeletionPhase,
) -> Result<OrganizationDeletionOperation, AppError> {
    if next == OrganizationDeletionPhase::Completed {
        return Err(AppError::BadRequest(
            "the database finalizer owns the completed phase".into(),
        ));
    }

    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let organization_id =
        lock_current_operation(&mut tx, operation_id, generation, &["deleting"]).await?;
    let operation = load_operation(&mut tx, operation_id).await?;
    if operation.state != "started" {
        return Err(stale_generation_conflict(
            "organization deletion workflow is not started",
        ));
    }
    let current = OrganizationDeletionPhase::parse(&operation.phase).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "organization deletion operation has an unknown phase"
        ))
    })?;
    if current == next {
        tx.commit().await.map_err(AppError::from)?;
        return Ok(operation);
    }
    if next.rank() != current.rank() + 1 {
        return Err(stale_generation_conflict(
            "organization deletion phase transition is out of order",
        ));
    }
    if next == OrganizationDeletionPhase::BillingFinalized {
        let billing_completed: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                   SELECT 1 FROM organization_deletion_billing_phases
                   WHERE operation_id = $1 AND organization_id = $2
                     AND generation = $3 AND state = 'completed'
               )"#,
        )
        .bind(operation_id)
        .bind(&organization_id)
        .bind(generation)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::from)?;
        if !billing_completed {
            return Err(AppError::Conflict(
                "organization billing cleanup is not complete".into(),
            ));
        }
    }

    let operation_transition = sqlx::query(
        r#"UPDATE organization_deletion_operations
           SET phase = $3, updated_at = NOW()
           WHERE id = $1 AND generation = $2 AND state = 'started'"#,
    )
    .bind(operation_id)
    .bind(generation)
    .bind(next.as_str())
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if operation_transition.rows_affected() != 1 {
        return Err(stale_generation_conflict(
            "organization deletion operation could not advance",
        ));
    }
    let changed = sqlx::query(
        r#"UPDATE organizations
           SET deletion_phase = $3, updated_at = NOW()
           WHERE id = $1 AND deletion_generation = $2
             AND deletion_state = 'deleting'"#,
    )
    .bind(&organization_id)
    .bind(generation)
    .bind(next.as_str())
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if changed.rows_affected() != 1 {
        return Err(stale_generation_conflict(
            "organization deletion operation is no longer current",
        ));
    }

    let operation = load_operation(&mut tx, operation_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(operation)
}

/// Atomically remove the complete database ownership boundary for one
/// externally-verified generation. The operation and audit evidence survive
/// the organization row. A retry after a lost commit response returns the
/// already-completed operation without recreating anything.
pub async fn finalize_organization_deletion_database(
    pool: &PgPool,
    operation_id: &str,
    organization_id: &str,
    generation: i64,
) -> Result<OrganizationDeletionOperation, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let operation = sqlx::query_as::<_, OrganizationDeletionOperation>(
        "SELECT * FROM organization_deletion_operations WHERE id = $1 FOR UPDATE",
    )
    .bind(operation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::NotFound("organization deletion operation not found".into()))?;

    if operation.organization_id != organization_id || operation.generation != generation {
        return Err(stale_generation_conflict(
            "organization deletion generation is no longer current",
        ));
    }
    if operation.state == "completed" {
        let organization_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)")
                .bind(organization_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::from)?;
        if organization_exists {
            return Err(AppError::Internal(anyhow::anyhow!(
                "completed organization deletion retained its organization"
            )));
        }
        tx.commit().await.map_err(AppError::from)?;
        return Ok(operation);
    }
    if operation.state != "started"
        || operation.phase != OrganizationDeletionPhase::ControlPlaneReconciled.as_str()
    {
        return Err(stale_generation_conflict(
            "organization deletion is not ready for database finalization",
        ));
    }

    let current: Option<(String, i64, String, String)> = sqlx::query_as(
        r#"SELECT deletion_operation_id, deletion_generation,
                  deletion_state, deletion_phase
           FROM organizations WHERE id = $1 FOR UPDATE"#,
    )
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?;
    let Some((current_operation, current_generation, state, phase)) = current else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "started organization deletion lost its organization"
        )));
    };
    if current_operation != operation_id
        || current_generation != generation
        || state != "deleting"
        || phase != OrganizationDeletionPhase::ControlPlaneReconciled.as_str()
    {
        return Err(stale_generation_conflict(
            "organization deletion generation is no longer current",
        ));
    }

    let unresolved: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM organization_mutation_leases
               WHERE organization_id = $1
                 AND state IN ('active', 'resolution_required')
           )"#,
    )
    .bind(organization_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if unresolved {
        return Err(AppError::Coded {
            status: StatusCode::CONFLICT,
            code: "organization_mutation_barrier_not_drained",
            detail: "organization mutations still require recovery".into(),
        });
    }

    let unverified_environment: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM environments
               WHERE org_id = $1
                 AND (state <> 'destroyed'
                      OR desired_state <> 'destroyed'
                      OR external_cleanup_completed_at IS NULL)
           )"#,
    )
    .bind(organization_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if unverified_environment {
        return Err(AppError::Conflict(
            "organization environment cleanup is not complete".into(),
        ));
    }

    let billing_completed: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM organization_deletion_billing_phases
               WHERE operation_id = $1 AND organization_id = $2
                 AND generation = $3 AND state = 'completed'
           )"#,
    )
    .bind(operation_id)
    .bind(organization_id)
    .bind(generation)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if !billing_completed {
        return Err(AppError::Conflict(
            "organization billing cleanup is not complete".into(),
        ));
    }

    let project_parent = format!("/projects/{organization_id}");
    sqlx::query(
        r#"DELETE FROM local_secrets
           WHERE path = $1
              OR left(path, char_length($2) + 1) = $2 || '/'"#,
    )
    .bind(format!("/org-secrets/{organization_id}"))
    .bind(&project_parent)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    for statement in [
        "DELETE FROM repo_configs WHERE org_id = $1",
        "DELETE FROM environments WHERE org_id = $1",
        "DELETE FROM environment_presets WHERE org_id = $1",
        "DELETE FROM api_keys WHERE org_id = $1",
        "DELETE FROM environment_quotas WHERE org_id = $1",
        "DELETE FROM environment_usage_billing WHERE org_id = $1",
        "DELETE FROM secret_projects WHERE org_id = $1",
        "DELETE FROM org_invitations WHERE org_id = $1",
        "DELETE FROM org_members WHERE org_id = $1",
    ] {
        sqlx::query(statement)
            .bind(organization_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::from)?;
    }

    let removed = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
    if removed.rows_affected() != 1 {
        return Err(stale_generation_conflict(
            "organization deletion generation is no longer current",
        ));
    }

    let operation_transition = sqlx::query(
        r#"UPDATE organization_deletion_operations
           SET state = 'completed', phase = 'completed', completed_at = NOW(),
               updated_at = NOW()
           WHERE id = $1 AND generation = $2 AND state = 'started'
             AND phase = 'control_plane_reconciled'"#,
    )
    .bind(operation_id)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;
    if operation_transition.rows_affected() != 1 {
        return Err(stale_generation_conflict(
            "organization deletion operation could not be finalized",
        ));
    }

    let requester_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(&operation.requested_by)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::from)?;
    let metadata = serde_json::to_value(DeletionAuditMetadata {
        organization_id,
        operation_id,
        generation,
        state: "completed",
    })
    .map_err(|error| AppError::Internal(error.into()))?;
    sqlx::query(
        r#"INSERT INTO audit_logs
               (id, timestamp, action, user_id, metadata, severity)
           VALUES ($1, NOW(), 'org.deleted', $2, $3, 'warn')"#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(requester_exists.then_some(operation.requested_by.as_str()))
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    let operation = load_operation(&mut tx, operation_id).await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(operation)
}

async fn load_operation(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: &str,
) -> Result<OrganizationDeletionOperation, AppError> {
    sqlx::query_as::<_, OrganizationDeletionOperation>(
        r#"SELECT * FROM organization_deletion_operations WHERE id = $1"#,
    )
    .bind(operation_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)
}

async fn lock_current_operation(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    generation: i64,
    allowed_organization_states: &[&str],
) -> Result<String, AppError> {
    let current: Option<(String, i64, String, String)> = sqlx::query_as(
        r#"
        SELECT op.organization_id, org.deletion_generation,
               org.deletion_operation_id, org.deletion_state
        FROM organization_deletion_operations op
        JOIN organizations org ON org.id = op.organization_id
        WHERE op.id = $1
        FOR UPDATE OF op, org
        "#,
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)?;

    let Some((organization_id, current_generation, current_operation_id, state)) = current else {
        return Err(AppError::NotFound(
            "organization deletion operation not found".into(),
        ));
    };
    if current_generation != generation
        || current_operation_id != operation_id
        || !allowed_organization_states.contains(&state.as_str())
    {
        return Err(AppError::Coded {
            status: StatusCode::CONFLICT,
            code: "organization_deletion_stale_generation",
            detail: "organization deletion generation is no longer current".into(),
        });
    }
    Ok(organization_id)
}

async fn load_mutation_lease(
    tx: &mut Transaction<'_, Postgres>,
    lease_id: &str,
) -> Result<OrganizationMutationLease, AppError> {
    sqlx::query_as::<_, OrganizationMutationLease>(
        r#"SELECT * FROM organization_mutation_leases WHERE id = $1"#,
    )
    .bind(lease_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)
}

async fn lock_mutation_lease(
    tx: &mut Transaction<'_, Postgres>,
    lease_id: &str,
) -> Result<OrganizationMutationLease, AppError> {
    sqlx::query_as::<_, OrganizationMutationLease>(
        r#"SELECT * FROM organization_mutation_leases WHERE id = $1 FOR UPDATE"#,
    )
    .bind(lease_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::NotFound("organization mutation lease not found".into()))
}

fn state_conflict(detail: &'static str) -> AppError {
    AppError::Coded {
        status: StatusCode::CONFLICT,
        code: "organization_write_blocked",
        detail: detail.into(),
    }
}

fn stale_generation_conflict(detail: &'static str) -> AppError {
    AppError::Coded {
        status: StatusCode::CONFLICT,
        code: "organization_deletion_stale_generation",
        detail: detail.into(),
    }
}

fn mutation_lease_conflict(detail: &'static str) -> AppError {
    AppError::Coded {
        status: StatusCode::CONFLICT,
        code: "organization_mutation_lease_conflict",
        detail: detail.into(),
    }
}

fn valid_failure_code(value: &str) -> bool {
    valid_safe_code(value)
}

fn require_safe_deletion_phase(value: &'static str) -> Result<&'static str, AppError> {
    if valid_safe_code(value) {
        Ok(value)
    } else {
        Err(AppError::Internal(anyhow::anyhow!(
            "organization deletion phase is not a safe identifier"
        )))
    }
}

fn valid_safe_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::{require_safe_deletion_phase, valid_failure_code};

    #[test]
    fn failure_codes_are_safe_value_blind_identifiers() {
        assert!(valid_failure_code("temporal_start_failed"));
        assert!(valid_failure_code("provider_503"));
        assert!(!valid_failure_code(""));
        assert!(!valid_failure_code("Stripe response: secret"));
        assert!(!valid_failure_code(&"a".repeat(129)));
    }

    #[test]
    fn deletion_phases_are_safe_value_blind_identifiers() {
        assert_eq!(
            require_safe_deletion_phase("write_fenced").unwrap(),
            "write_fenced"
        );
        assert!(require_safe_deletion_phase("provider body: credential=secret").is_err());
    }
}
