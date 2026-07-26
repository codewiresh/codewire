//! Billing-catalog admin write handlers + subscription migrations.
//!
//! The handlers write `billing_catalog_plans` and
//! `billing_catalog_subscription_migrations`, returning either
//! `{"success":true}` (the SuccessResponse shape) or the migration
//! preview/run/list bodies. Auth (require_auth + require_admin) is
//! applied in `routes.rs`.
//!
//! Wire-parity notes (the billing contract suite is the gate):
//!
//! - Success bodies are `{"success":true}` exactly (huma's
//!   SuccessResponse). The Go side also injected a `$schema` link the
//!   Rust side intentionally omits.
//! - Field order on the migration preview/run/list bodies follows the
//!   Go struct declaration order (encoding/json preserves it); serde
//!   preserves struct field order too, so the field order below is
//!   load-bearing.
//! - `omitempty` fields (`current_stripe_price_id` on samples;
//!   `created_by`, `metadata` on runs) are reproduced with
//!   `skip_serializing_if`.
//! - Error details match the Go `huma.Error400BadRequest(err.Error())`
//!   / `Error404NotFound` / `Error500InternalServerError` strings.
//!
//! `#181` removed the legacy max-instance catalog column; it is deliberately
//! not present here.

use std::borrow::Cow;

use axum::Json;
use axum::extract::{Path, Query, State};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult, ValidatedJson, ValidationIssue};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::routes::BillingState;
use crate::subscription_migration::{self, MigrationCandidate};

// ── Shared success body (huma SuccessResponse) ──────────────────────

#[derive(Debug, Serialize, JsonSchema)]
pub struct SuccessResponse {
    pub success: bool,
}

fn ok_success() -> Json<SuccessResponse> {
    Json(SuccessResponse { success: true })
}

// ── Plan create / update / archive ──────────────────────────────────

/// Body for create + update. Numeric widths match the schema
/// (`integer` → `i32`, `double precision` → `f64`); the Go input uses
/// `int`/`float64`. All catalog plan fields are required by the generated
/// Rust schema and enforced by `ValidatedJson`.
#[derive(Debug, Deserialize, JsonSchema)]
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

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreatePlanBody {
    pub resource_type: String,
    pub plan_key: String,
    #[serde(flatten)]
    pub plan: PlanWriteBody,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ArchivePlanBody {
    pub archived: bool,
}

/// Shared catalog-plan create operation used by REST and BillingCatalogService.
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

/// `POST /api/v1/admin/billing/catalog/plans` — mirrors
/// `createAdminBillingCatalogPlan`.
pub async fn create_plan(
    State(pool): State<PgPool>,
    ValidatedJson(body): ValidatedJson<CreatePlanBody>,
) -> AppResult<Json<SuccessResponse>> {
    create_plan_core(&pool, &body.resource_type, &body.plan_key, &body.plan).await?;
    Ok(ok_success())
}

/// Shared catalog-plan update operation used by REST and BillingCatalogService.
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

/// `PUT /api/v1/admin/billing/catalog/plans/{resourceType}/{planKey}` —
/// mirrors `updateAdminBillingCatalogPlan`.
pub async fn update_plan(
    State(pool): State<PgPool>,
    Path((resource_type, plan_key)): Path<(String, String)>,
    ValidatedJson(p): ValidatedJson<PlanWriteBody>,
) -> AppResult<Json<SuccessResponse>> {
    update_plan_core(&pool, &resource_type, &plan_key, &p).await?;
    Ok(ok_success())
}

/// Shared catalog-plan archive operation used by REST and BillingCatalogService.
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

/// `PUT /api/v1/admin/billing/catalog/plans/{resourceType}/{planKey}/archive`
/// — mirrors `setAdminBillingCatalogPlanArchive`.
pub async fn set_plan_archive(
    State(pool): State<PgPool>,
    Path((resource_type, plan_key)): Path<(String, String)>,
    ValidatedJson(body): ValidatedJson<ArchivePlanBody>,
) -> AppResult<Json<SuccessResponse>> {
    set_plan_archived_core(&pool, &resource_type, &plan_key, body.archived).await?;
    Ok(ok_success())
}

// ── Price create / update / archive + settings ─────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreatePriceBody {
    pub resource_type: String,
    pub plan_key: String,
    pub stripe_mode: String,
    pub price_kind: String,
    pub stripe_price_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdatePriceBody {
    pub stripe_price_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ArchivePriceBody {
    pub archived: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateSettingBody {
    pub int_value: i32,
}

/// Shared catalog-price create operation used by REST and BillingCatalogService.
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

/// `POST /api/v1/admin/billing/catalog/prices` — mirrors
/// `createAdminBillingCatalogPrice`. Pure catalog DB write (no Stripe).
pub async fn create_price(
    State(pool): State<PgPool>,
    ValidatedJson(body): ValidatedJson<CreatePriceBody>,
) -> AppResult<Json<SuccessResponse>> {
    create_price_core(
        &pool,
        &body.resource_type,
        &body.plan_key,
        &body.stripe_mode,
        &body.price_kind,
        &body.stripe_price_id,
    )
    .await?;
    Ok(ok_success())
}

/// Shared catalog-price update operation used by REST and BillingCatalogService.
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

/// `PUT /api/v1/admin/billing/catalog/prices/{resourceType}/{planKey}/{stripeMode}/{priceKind}`
/// — mirrors `updateAdminBillingCatalogPrice`.
pub async fn update_price(
    State(pool): State<PgPool>,
    Path((resource_type, plan_key, stripe_mode, price_kind)): Path<(
        String,
        String,
        String,
        String,
    )>,
    ValidatedJson(body): ValidatedJson<UpdatePriceBody>,
) -> AppResult<Json<SuccessResponse>> {
    update_price_core(
        &pool,
        &resource_type,
        &plan_key,
        &stripe_mode,
        &price_kind,
        &body.stripe_price_id,
    )
    .await?;
    Ok(ok_success())
}

/// Shared catalog-price archive operation used by REST and BillingCatalogService.
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

/// `PUT /api/v1/admin/billing/catalog/prices/{resourceType}/{planKey}/{stripeMode}/{priceKind}/archive`
/// — mirrors `setAdminBillingCatalogPriceArchive`.
pub async fn set_price_archive(
    State(pool): State<PgPool>,
    Path((resource_type, plan_key, stripe_mode, price_kind)): Path<(
        String,
        String,
        String,
        String,
    )>,
    ValidatedJson(body): ValidatedJson<ArchivePriceBody>,
) -> AppResult<Json<SuccessResponse>> {
    set_price_archived_core(
        &pool,
        &resource_type,
        &plan_key,
        &stripe_mode,
        &price_kind,
        body.archived,
    )
    .await?;
    Ok(ok_success())
}

/// Shared catalog-setting update operation used by REST and BillingCatalogService.
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

/// `PUT /api/v1/admin/billing/catalog/settings/{settingKey}` — mirrors
/// `updateAdminBillingCatalogSetting`. Pure DB write of a single int.
pub async fn update_setting(
    State(pool): State<PgPool>,
    Path(setting_key): Path<String>,
    ValidatedJson(body): ValidatedJson<UpdateSettingBody>,
) -> AppResult<Json<SuccessResponse>> {
    update_setting_core(&pool, &setting_key, body.int_value).await?;
    Ok(ok_success())
}

// ── Subscription migrations ─────────────────────────────────────────

/// JSON shape of a migration sample (Go `AdminBillingCatalogMigrationSample`,
/// field order preserved). `current_stripe_price_id` is `omitempty` in Go.
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(rename = "AdminBillingCatalogMigrationSample")]
pub struct MigrationSample {
    pub scope: String,
    pub org_id: String,
    pub org_slug: String,
    pub stripe_subscription_id: String,
    pub status: String,
    pub current_plan_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
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

/// Go `AdminBillingCatalogMigrationPreview` (field order preserved).
#[derive(Debug, Serialize, JsonSchema)]
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

/// Go `AdminBillingCatalogMigrationRun` (field order preserved).
/// `created_by` and `metadata` are `omitempty` in Go.
#[derive(Debug, Serialize, JsonSchema)]
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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_by: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PreviewMigrationBody {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    #[serde(default)]
    pub sample_limit: i32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunMigrationBody {
    pub resource_type: String,
    pub source_plan_key: String,
    pub target_plan_key: String,
    #[serde(default)]
    pub proration_behavior: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMigrationsQuery {
    /// huma default 25, max 100.
    #[serde(default = "default_migration_limit")]
    pub limit: i64,
}

fn default_migration_limit() -> i64 {
    25
}

/// Validates the REST query limit while preserving its existing error path.
pub fn validate_migration_limit(limit: i64) -> AppResult<i64> {
    validate_migration_limit_at(limit, "query.limit")
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

/// Shared subscription-migration preview used by REST and BillingCatalogService.
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

/// `POST /api/v1/admin/billing/catalog/subscription-migrations/preview`
/// — mirrors `previewAdminBillingCatalogMigration`.
pub async fn preview_migration(
    State(state): State<BillingState>,
    ValidatedJson(body): ValidatedJson<PreviewMigrationBody>,
) -> AppResult<Json<MigrationPreviewResponse>> {
    // Transitional REST behavior remains unchanged. The Connect contract does
    // not add this deployment-misconfiguration branch or assert it.
    if !state.stripe.is_configured() {
        return Err(AppError::BadRequest("billing is disabled".into()));
    }
    Ok(Json(preview_migration_core(&state, &body).await?))
}

/// Shared subscription-migration command used by REST and BillingCatalogService.
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

/// `POST /api/v1/admin/billing/catalog/subscription-migrations` —
/// mirrors `runAdminBillingCatalogMigration`.
pub async fn run_migration(
    State(state): State<BillingState>,
    user: AuthUser,
    ValidatedJson(body): ValidatedJson<RunMigrationBody>,
) -> AppResult<Json<MigrationRunResponse>> {
    // Transitional REST behavior remains unchanged. The Connect contract does
    // not add this deployment-misconfiguration branch or assert it.
    if !state.stripe.is_configured() {
        return Err(AppError::BadRequest("billing is disabled".into()));
    }
    Ok(Json(
        run_migration_core(&state, &body, &user.user_id).await?,
    ))
}

/// Shared subscription-migration listing used by REST and BillingCatalogService.
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

/// `GET /api/v1/admin/billing/catalog/subscription-migrations` —
/// mirrors `listAdminBillingCatalogMigrations`.
pub async fn list_migrations(
    State(pool): State<PgPool>,
    Query(query): Query<ListMigrationsQuery>,
) -> AppResult<Json<Vec<MigrationRunResponse>>> {
    // Negative values still reach Postgres and produce the handler's
    // generic 500, preserving the historical handler behavior for now.
    let limit = validate_migration_limit(query.limit)?;
    Ok(Json(list_migrations_core(&pool, limit).await?))
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

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn success_body_is_exactly_success_true() {
        let s = serde_json::to_string(&SuccessResponse { success: true }).unwrap();
        assert_eq!(s, r#"{"success":true}"#);
    }

    #[test]
    fn sample_omits_empty_price_like_go() {
        let sample = MigrationSample {
            scope: "environment".into(),
            org_id: "org_1".into(),
            org_slug: "acme".into(),
            stripe_subscription_id: "sub_1".into(),
            status: "active".into(),
            current_plan_key: "starter".into(),
            current_stripe_price_id: String::new(),
        };
        let v = serde_json::to_value(&sample).unwrap();
        // omitempty fields are absent (not "" / null), matching Go.
        assert!(v.get("current_stripe_price_id").is_none());
        // Non-omitempty fields stay present.
        assert_eq!(v["scope"], "environment");
        assert_eq!(v["status"], "active");
    }

    #[test]
    fn run_response_field_order_matches_go_struct() {
        // encoding/json preserves struct field order; serde preserves
        // declaration order — pin the run body order byte for byte.
        let run = MigrationRunResponse {
            id: "mig_1".into(),
            resource_type: "org".into(),
            source_plan_key: "starter".into(),
            target_plan_key: "pro".into(),
            target_stripe_price_id: "price_1".into(),
            proration_behavior: "none".into(),
            migrated_count: 1,
            skipped_count: 0,
            failed_count: 0,
            created_by: "admin@codewire.test".into(),
            created_at: "2026-06-18T00:00:00Z".into(),
            metadata: Some(serde_json::json!({"failures": []})),
        };
        let s = serde_json::to_string(&run).unwrap();
        let want = concat!(
            r#"{"id":"mig_1","resource_type":"org","source_plan_key":"starter","#,
            r#""target_plan_key":"pro","target_stripe_price_id":"price_1","#,
            r#""proration_behavior":"none","migrated_count":1,"skipped_count":0,"#,
            r#""failed_count":0,"created_by":"admin@codewire.test","#,
            r#""created_at":"2026-06-18T00:00:00Z","metadata":{"failures":[]}}"#,
        );
        assert_eq!(s, want);
    }

    #[test]
    fn run_response_omits_empty_created_by_and_absent_metadata() {
        let run = MigrationRunResponse {
            id: "mig_1".into(),
            resource_type: "org".into(),
            source_plan_key: "starter".into(),
            target_plan_key: "pro".into(),
            target_stripe_price_id: "price_1".into(),
            proration_behavior: "none".into(),
            migrated_count: 0,
            skipped_count: 0,
            failed_count: 0,
            created_by: String::new(),
            created_at: "2026-06-18T00:00:00Z".into(),
            metadata: None,
        };
        let v = serde_json::to_value(&run).unwrap();
        assert!(v.get("created_by").is_none());
        assert!(v.get("metadata").is_none());
    }

    // ── Rust-native validation ─────────────────────────────────────

    #[test]
    fn plan_write_schema_requires_all_catalog_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(PlanWriteBody)).unwrap();
        assert_eq!(
            schema["required"],
            serde_json::json!([
                "display_name",
                "price_cents",
                "included_devs",
                "max_concurrent_ws",
                "max_team_members",
                "storage_gb",
                "is_contact_us",
                "is_admin_only",
                "included_cpu_hours",
                "included_mem_gb_hours",
                "included_disk_gb_hours",
                "cpu_overage_cents",
                "mem_overage_cents",
                "disk_overage_cents"
            ])
        );
    }

    #[test]
    fn plan_write_validation_accepts_full_body() {
        let full = serde_json::json!({
            "display_name": "x", "price_cents": 0, "included_devs": 0,
            "max_concurrent_ws": 0, "max_team_members": 0, "storage_gb": 0,
            "is_contact_us": false, "is_admin_only": false,
            "included_cpu_hours": 0, "included_mem_gb_hours": 0,
            "included_disk_gb_hours": 0, "cpu_overage_cents": 0,
            "mem_overage_cents": 0, "disk_overage_cents": 0
        });

        let parsed = validate_value::<PlanWriteBody>(full).expect("full plan body is valid");
        assert_eq!(parsed.display_name, "x");
        assert_eq!(parsed.price_cents, 0);
    }

    #[test]
    fn plan_write_validation_rejects_partial_body() {
        let err = validate_value::<PlanWriteBody>(serde_json::json!({
            "display_name": "x",
            "price_cents": 0
        }))
        .expect_err("partial plan body should be rejected before DB lookup");
        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert!(
            errors.iter().any(|e| e.message.contains("included_devs")),
            "errors should mention a missing required field: {errors:?}"
        );
    }

    #[test]
    fn create_plan_validation_requires_body_ids() {
        let err = validate_value::<CreatePlanBody>(serde_json::json!({
            "display_name": "x",
            "price_cents": 0,
            "included_devs": 0,
            "max_concurrent_ws": 0,
            "max_team_members": 0,
            "storage_gb": 0,
            "is_contact_us": false,
            "is_admin_only": false,
            "included_cpu_hours": 0,
            "included_mem_gb_hours": 0,
            "included_disk_gb_hours": 0,
            "cpu_overage_cents": 0,
            "mem_overage_cents": 0,
            "disk_overage_cents": 0
        }))
        .expect_err("create plan requires resource_type and plan_key");
        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert!(
            errors.iter().any(|e| e.message.contains("resource_type"))
                && errors.iter().any(|e| e.message.contains("plan_key")),
            "errors should mention missing resource_type and plan_key: {errors:?}"
        );
    }

    #[test]
    fn price_and_setting_validation_requires_fields() {
        let price_schema = serde_json::to_value(schemars::schema_for!(CreatePriceBody)).unwrap();
        assert_eq!(
            price_schema["required"],
            serde_json::json!([
                "resource_type",
                "plan_key",
                "stripe_mode",
                "price_kind",
                "stripe_price_id"
            ])
        );

        let err = validate_value::<UpdatePriceBody>(serde_json::json!({}))
            .expect_err("missing stripe_price_id should be rejected");
        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert!(errors[0].message.contains("stripe_price_id"));

        let err = validate_value::<UpdateSettingBody>(serde_json::json!({}))
            .expect_err("missing int_value should be rejected");
        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert!(errors[0].message.contains("int_value"));
    }

    #[test]
    fn archive_body_validation_requires_archived_flag() {
        let plan_schema = serde_json::to_value(schemars::schema_for!(ArchivePlanBody)).unwrap();
        assert_eq!(plan_schema["required"], serde_json::json!(["archived"]));

        let price_schema = serde_json::to_value(schemars::schema_for!(ArchivePriceBody)).unwrap();
        assert_eq!(price_schema["required"], serde_json::json!(["archived"]));

        let missing = validate_value::<ArchivePlanBody>(serde_json::json!({}))
            .expect_err("missing archived should be rejected");
        let AppError::Validation { errors } = missing else {
            panic!("expected validation error");
        };
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("archived"));

        let typed = validate_value::<ArchivePriceBody>(serde_json::json!({
            "archived": "yes"
        }))
        .expect_err("type-invalid archived should be rejected");
        let AppError::Validation { errors } = typed else {
            panic!("expected validation error");
        };
        assert_eq!(errors[0].path, "/archived");
    }

    #[test]
    fn migration_body_validation_requires_plan_keys() {
        let preview_schema =
            serde_json::to_value(schemars::schema_for!(PreviewMigrationBody)).unwrap();
        assert_eq!(
            preview_schema["required"],
            serde_json::json!(["resource_type", "source_plan_key", "target_plan_key"])
        );

        let err = validate_value::<PreviewMigrationBody>(serde_json::json!({
            "resource_type": "org",
            "source_plan_key": "starter"
        }))
        .expect_err("missing target_plan_key should be rejected");
        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("target_plan_key"));
    }

    #[test]
    fn run_migration_validation_preserves_proration_default() {
        let parsed = validate_value::<RunMigrationBody>(serde_json::json!({
            "resource_type": "org",
            "source_plan_key": "starter",
            "target_plan_key": "pro"
        }))
        .expect("proration behavior defaults after validation");

        assert_eq!(parsed.proration_behavior, "");
    }

    #[test]
    fn migration_limit_over_max_uses_rust_validation() {
        let err = validate_migration_limit(500).expect_err("must reject over maximum");
        let AppError::Validation { errors } = err else {
            panic!("expected validation error");
        };
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "query.limit");
        assert_eq!(errors[0].message, "expected number <= 100");
    }

    #[test]
    fn migration_limit_negative_is_not_clamped() {
        assert_eq!(validate_migration_limit(-5).unwrap(), -5);
    }
}
