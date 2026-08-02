//! Billing-catalog admin write handlers + subscription migrations.
//!
//! The shared operations write `billing_catalog_plans` and
//! `billing_catalog_subscription_migrations`; BillingCatalogService owns the
//! public protobuf mapping and authorization.
//!
//! `#181` removed the legacy max-instance catalog column; it is deliberately
//! not present here.

use std::borrow::Cow;

use codewire_server_core::{AppError, AppResult, ValidationIssue};
use sqlx::PgPool;

use crate::routes::BillingState;
use crate::subscription_migration::{self, MigrationCandidate};

// ── Plan create / update / archive ──────────────────────────────────

/// Connect plan input with database-native numeric widths.
#[derive(Debug)]
pub struct PlanWriteBody {
    pub display_name: String,
    pub price_cents: i32,
    pub included_devs: i32,
    pub max_concurrent_ws: i32,
    pub max_team_members: i32,
    pub storage_gb: i32,
    pub is_contact_us: bool,
    pub is_admin_only: bool,
    pub included_cpu_hours: i32,
    pub included_mem_gb_hours: i32,
    pub included_disk_gb_hours: i32,
    pub cpu_overage_cents: f64,
    pub mem_overage_cents: f64,
    pub disk_overage_cents: f64,
}
/// Shared catalog-plan create operation used by BillingCatalogService.
pub async fn create_plan_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    plan: &PlanWriteBody,
) -> AppResult<()> {
    let p = plan;
    sqlx::query(
        r#"INSERT INTO billing_catalog_plans
           (resource_type, plan_key, display_name, price_cents,
            included_devs, max_concurrent_ws, max_team_members,
            storage_gb, is_contact_us, is_admin_only,
            included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours,
            cpu_overage_cents, mem_overage_cents, disk_overage_cents,
            created_at, updated_at, archived_at)
           VALUES ($1, $2, $3, $4,
                   $5, $6, $7,
                   $8, $9, $10,
                   $11, $12, $13,
                   $14, $15, $16,
                   NOW(), NOW(), NULL)"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(&p.display_name)
    .bind(p.price_cents)
    .bind(p.included_devs)
    .bind(p.max_concurrent_ws)
    .bind(p.max_team_members)
    .bind(p.storage_gb)
    .bind(p.is_contact_us)
    .bind(p.is_admin_only)
    .bind(p.included_cpu_hours)
    .bind(p.included_mem_gb_hours)
    .bind(p.included_disk_gb_hours)
    .bind(p.cpu_overage_cents)
    .bind(p.mem_overage_cents)
    .bind(p.disk_overage_cents)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to create billing catalog plan".into()))?;
    Ok(())
}

/// Shared catalog-plan update operation used by BillingCatalogService.
pub async fn update_plan_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    p: &PlanWriteBody,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_plans
           SET display_name = $3,
               price_cents = $4,
               included_devs = $5,
               max_concurrent_ws = $6,
               max_team_members = $7,
               storage_gb = $8,
               is_contact_us = $9,
               is_admin_only = $10,
               included_cpu_hours = $11,
               included_mem_gb_hours = $12,
               included_disk_gb_hours = $13,
               cpu_overage_cents = $14,
               mem_overage_cents = $15,
               disk_overage_cents = $16,
               updated_at = NOW()
           WHERE resource_type = $1 AND plan_key = $2"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(&p.display_name)
    .bind(p.price_cents)
    .bind(p.included_devs)
    .bind(p.max_concurrent_ws)
    .bind(p.max_team_members)
    .bind(p.storage_gb)
    .bind(p.is_contact_us)
    .bind(p.is_admin_only)
    .bind(p.included_cpu_hours)
    .bind(p.included_mem_gb_hours)
    .bind(p.included_disk_gb_hours)
    .bind(p.cpu_overage_cents)
    .bind(p.mem_overage_cents)
    .bind(p.disk_overage_cents)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to update billing catalog plan".into()))?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("billing catalog plan not found".into()));
    }
    Ok(())
}

/// Shared catalog-plan archive operation used by BillingCatalogService.
pub async fn set_plan_archived_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    archived: bool,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_plans
           SET archived_at = CASE WHEN $3 THEN NOW() ELSE NULL END,
               updated_at = NOW()
           WHERE resource_type = $1 AND plan_key = $2"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(archived)
    .execute(pool)
    .await
    .map_err(|_| {
        AppError::InternalMsg("failed to update billing catalog plan archive state".into())
    })?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("billing catalog plan not found".into()));
    }
    Ok(())
}

// ── Price create / update / archive + settings ─────────────────────

/// Shared catalog-price create operation used by BillingCatalogService.
pub async fn create_price_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    stripe_mode: &str,
    price_kind: &str,
    stripe_price_id: &str,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO billing_catalog_prices
           (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id,
            created_at, updated_at, archived_at)
           VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), NULL)"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(stripe_mode)
    .bind(price_kind)
    .bind(stripe_price_id)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to create billing catalog price".into()))?;
    Ok(())
}

/// Shared catalog-price update operation used by BillingCatalogService.
pub async fn update_price_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    stripe_mode: &str,
    price_kind: &str,
    stripe_price_id: &str,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_prices
           SET stripe_price_id = $5, updated_at = NOW()
           WHERE resource_type = $1 AND plan_key = $2 AND stripe_mode = $3 AND price_kind = $4"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(stripe_mode)
    .bind(price_kind)
    .bind(stripe_price_id)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to update billing catalog price".into()))?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("billing catalog price not found".into()));
    }
    Ok(())
}

/// Shared catalog-price archive operation used by BillingCatalogService.
pub async fn set_price_archived_core(
    pool: &PgPool,
    resource_type: &str,
    plan_key: &str,
    stripe_mode: &str,
    price_kind: &str,
    archived: bool,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_prices
           SET archived_at = CASE WHEN $5 THEN NOW() ELSE NULL END,
               updated_at = NOW()
           WHERE resource_type = $1 AND plan_key = $2 AND stripe_mode = $3 AND price_kind = $4"#,
    )
    .bind(resource_type)
    .bind(plan_key)
    .bind(stripe_mode)
    .bind(price_kind)
    .bind(archived)
    .execute(pool)
    .await
    .map_err(|_| {
        AppError::InternalMsg("failed to update billing catalog price archive state".into())
    })?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("billing catalog price not found".into()));
    }
    Ok(())
}

/// Shared catalog-setting update operation used by BillingCatalogService.
pub async fn update_setting_core(
    pool: &PgPool,
    setting_key: &str,
    int_value: i32,
) -> AppResult<()> {
    let result = sqlx::query(
        r#"UPDATE billing_catalog_settings
           SET int_value = $2, updated_at = NOW()
           WHERE setting_key = $1"#,
    )
    .bind(setting_key)
    .bind(int_value)
    .execute(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to update billing catalog setting".into()))?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "billing catalog setting not found".into(),
        ));
    }
    Ok(())
}

// ── Subscription migrations ─────────────────────────────────────────

/// Migration sample mapped into the Connect response.
#[derive(Debug)]
pub struct MigrationSample {
    pub scope: String,
    pub org_id: String,
    pub org_slug: String,
    pub stripe_subscription_id: String,
    pub status: String,
    pub current_plan_key: String,
    pub current_stripe_price_id: String,
}

impl From<MigrationCandidate> for MigrationSample {
    fn from(c: MigrationCandidate) -> Self {
        MigrationSample {
            scope: c.scope,
            org_id: c.org_id,
            org_slug: c.org_slug,
            stripe_subscription_id: c.stripe_subscription_id,
            status: c.status,
            current_plan_key: c.current_plan_key,
            current_stripe_price_id: c.current_stripe_price_id,
        }
    }
}

/// Migration preview mapped into the Connect response.
#[derive(Debug)]
pub struct MigrationPreviewResponse {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub target_stripe_price_id: String,
    pub matching_count: i32,
    pub candidate_count: i32,
    pub already_on_target: i32,
    pub samples: Vec<MigrationSample>,
}

/// Migration run mapped into the Connect response.
#[derive(Debug)]
pub struct MigrationRunResponse {
    pub id: String,
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub target_stripe_price_id: String,
    pub proration_behavior: String,
    pub migrated_count: i32,
    pub skipped_count: i32,
    pub failed_count: i32,
    pub created_by: String,
    pub created_at: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct PreviewMigrationBody {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub sample_limit: i32,
}

#[derive(Debug)]
pub struct RunMigrationBody {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    pub proration_behavior: String,
}

/// Validates the Connect field limit with a protobuf field path.
pub fn validate_connect_migration_limit(limit: i64) -> AppResult<i64> {
    validate_migration_limit_at(limit, "/limit")
}

fn validate_migration_limit_at(limit: i64, path: &'static str) -> AppResult<i64> {
    if limit > 100 {
        return Err(AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed(path),
                message: Cow::Borrowed("expected number <= 100"),
            }],
        });
    }
    Ok(limit)
}

/// Shared subscription-migration preview used by BillingCatalogService.
///
/// The caller supplies the required configured Stripe handle. No missing-Stripe
/// response is part of either product contract.
pub async fn preview_migration_core(
    state: &BillingState,
    body: &PreviewMigrationBody,
) -> AppResult<MigrationPreviewResponse> {
    let preview = subscription_migration::preview(
        &state.pool,
        &state.stripe,
        &body.resource_type,
        &body.source_plan_key,
        &body.target_plan_key,
        body.sample_limit,
    )
    .await?;

    Ok(MigrationPreviewResponse {
        resource_type: preview.resource_type,
        source_plan_key: preview.source_plan_key,
        target_plan_key: preview.target_plan_key,
        target_stripe_price_id: preview.target_stripe_price_id,
        matching_count: preview.matching_count,
        candidate_count: preview.candidate_count,
        already_on_target: preview.already_on_target,
        samples: preview
            .samples
            .into_iter()
            .map(MigrationSample::from)
            .collect(),
    })
}

/// Shared subscription-migration command used by BillingCatalogService.
pub async fn run_migration_core(
    state: &BillingState,
    body: &RunMigrationBody,
    user_id: &str,
) -> AppResult<MigrationRunResponse> {
    let proration_behavior = if body.proration_behavior.is_empty() {
        subscription_migration::PRORATION_NONE.to_string()
    } else {
        body.proration_behavior.clone()
    };

    let result = subscription_migration::run(
        &state.pool,
        &state.stripe,
        &body.resource_type,
        &body.source_plan_key,
        &body.target_plan_key,
        &proration_behavior,
        user_id,
    )
    .await?;

    // created_by on the response is the actor's email (Go uses
    // user.Email); audit log uses user.ID. Look the email up — empty if
    // the row is gone, matching the omitempty behavior.
    let email: String =
        sqlx::query_scalar(r#"SELECT COALESCE(email, '') FROM users WHERE id = $1"#)
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_default();

    let ip = String::new();
    let ua = String::new();
    log_audit_event(
        &state.pool,
        "admin.billing.catalog.subscription_migration",
        user_id,
        &ip,
        &ua,
        serde_json::json!({
            "resource_type": result.resource_type,
            "source_plan_key": result.source_plan_key,
            "target_plan_key": result.target_plan_key,
            "target_stripe_price_id": result.target_stripe_price_id,
            "proration_behavior": result.proration_behavior,
            "migrated_count": result.migrated_count,
            "skipped_count": result.skipped_count,
            "failed_count": result.failed_count,
            "migration_id": result.id,
            "failures": result.failures,
        }),
        "warn",
    )
    .await;

    Ok(MigrationRunResponse {
        id: result.id,
        resource_type: result.resource_type,
        source_plan_key: result.source_plan_key,
        target_plan_key: result.target_plan_key,
        target_stripe_price_id: result.target_stripe_price_id,
        proration_behavior: result.proration_behavior,
        migrated_count: result.migrated_count,
        skipped_count: result.skipped_count,
        failed_count: result.failed_count,
        created_by: email,
        created_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        metadata: Some(serde_json::json!({ "failures": result.failures })),
    })
}

/// Shared subscription-migration listing used by BillingCatalogService.
pub async fn list_migrations_core(
    pool: &PgPool,
    limit: i64,
) -> AppResult<Vec<MigrationRunResponse>> {
    let rows: Vec<MigrationRunRow> = sqlx::query_as(
        r#"SELECT m.id, m.resource_type, m.source_plan_key, m.target_plan_key,
                  m.target_stripe_price_id, m.proration_behavior,
                  m.migrated_count, m.skipped_count, m.failed_count,
                  COALESCE(u.email, '') AS created_by,
                  COALESCE(m.metadata, '{}'::jsonb) AS metadata,
                  m.created_at
             FROM billing_catalog_subscription_migrations m
             LEFT JOIN users u ON u.id = m.created_by
            ORDER BY m.created_at DESC
            LIMIT $1"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|_| AppError::InternalMsg("failed to query billing subscription migrations".into()))?;

    let runs: Vec<MigrationRunResponse> = rows
        .into_iter()
        .map(|r| MigrationRunResponse {
            id: r.id,
            resource_type: r.resource_type,
            source_plan_key: r.source_plan_key,
            target_plan_key: r.target_plan_key,
            target_stripe_price_id: r.target_stripe_price_id,
            proration_behavior: r.proration_behavior,
            migrated_count: r.migrated_count,
            skipped_count: r.skipped_count,
            failed_count: r.failed_count,
            created_by: r.created_by,
            created_at: r.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            // Go: only set when the row's metadata is valid JSON; the
            // COALESCE guarantees a value, and '{}' parses fine, so this
            // is always Some — matching Go's `omitempty`-but-present
            // behavior for the persisted `{"failures": …}` blob.
            metadata: Some(r.metadata),
        })
        .collect();

    Ok(runs)
}

#[derive(Debug, sqlx::FromRow)]
struct MigrationRunRow {
    id: String,
    resource_type: String,
    source_plan_key: String,
    target_plan_key: String,
    target_stripe_price_id: String,
    proration_behavior: String,
    migrated_count: i32,
    skipped_count: i32,
    failed_count: i32,
    created_by: String,
    metadata: serde_json::Value,
    // `timestamp without time zone`, stored UTC; formatted with a literal
    // Z to match Go's `createdAt.UTC().Format(time.RFC3339)`.
    created_at: chrono::NaiveDateTime,
}

/// Mirrors `auth.LogAuditEvent`: best-effort insert, errors logged not
/// surfaced. Severity is written verbatim (the run handler passes
/// `"warn"`).
async fn log_audit_event(
    pool: &PgPool,
    action: &str,
    user_id: &str,
    ip_address: &str,
    user_agent: &str,
    metadata: serde_json::Value,
    severity: &str,
) {
    // ID generation mirrors the schema default (gen_random_uuid()::text)
    // — the billing crate keeps no uuid dependency, generating IDs in SQL
    // like the webhook handler does.
    if let Err(e) = sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), $1, $2, $3, $4, $5, $6)"#,
    )
    .bind(action)
    .bind(user_id)
    .bind(ip_address)
    .bind(user_agent)
    .bind(&metadata)
    .bind(severity)
    .execute(pool)
    .await
    {
        tracing::error!(action, error = %e, "failed to log audit event");
    }
}
