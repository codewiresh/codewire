//! Billing catalog read handlers.
//!
//! The catalog model (plans + prices + settings) is the source of truth
//! for what each resource type costs. Admin handlers write the same tables;
//! this handler only reads.
//!
//! The response shape is the published dashboard/client contract.

use axum::Json;
use axum::extract::State;
use codewire_server_core::AppResult;
use schemars::JsonSchema;
use serde::Serialize;
use sqlx::PgPool;

// Numeric field widths match the schema exactly (`integer` → `i32`,
// `double precision` → `f64`): sqlx rejects integer-width coercions at
// row-decode time, so an `i64` here would 500 on the first real row.
#[derive(Debug, Serialize, JsonSchema, sqlx::FromRow)]
pub struct CatalogPlan {
    pub resource_type: String,
    pub plan_key: String,
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
    // Go's encoding/json prints integral floats without a decimal point.
    #[serde(serialize_with = "crate::plans::go_float")]
    pub cpu_overage_cents: f64,
    #[serde(serialize_with = "crate::plans::go_float")]
    pub mem_overage_cents: f64,
    #[serde(serialize_with = "crate::plans::go_float")]
    pub disk_overage_cents: f64,
    pub archived: bool,
}

#[derive(Debug, Serialize, JsonSchema, sqlx::FromRow)]
pub struct CatalogPrice {
    pub resource_type: String,
    pub plan_key: String,
    pub stripe_mode: String,
    pub price_kind: String,
    pub stripe_price_id: String,
    pub archived: bool,
}

#[derive(Debug, Serialize, JsonSchema, sqlx::FromRow)]
pub struct CatalogSetting {
    pub setting_key: String,
    pub int_value: i32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CatalogResponse {
    pub plans: Vec<CatalogPlan>,
    pub prices: Vec<CatalogPrice>,
    pub settings: Vec<CatalogSetting>,
}

/// Shared catalog read used by REST and BillingCatalogService.
pub async fn get_catalog_core(pool: &PgPool) -> AppResult<CatalogResponse> {
    let plans = sqlx::query_as::<_, CatalogPlan>(
        r#"
        SELECT
            resource_type,
            plan_key,
            display_name,
            price_cents,
            included_devs,
            max_concurrent_ws,
            max_team_members,
            storage_gb,
            is_contact_us,
            is_admin_only,
            included_cpu_hours,
            included_mem_gb_hours,
            included_disk_gb_hours,
            cpu_overage_cents,
            mem_overage_cents,
            disk_overage_cents,
            archived_at IS NOT NULL AS archived
        FROM billing_catalog_plans
        ORDER BY resource_type, plan_key
        "#,
    )
    .fetch_all(pool)
    .await?;

    let prices = sqlx::query_as::<_, CatalogPrice>(
        r#"
        SELECT
            resource_type,
            plan_key,
            stripe_mode,
            price_kind,
            stripe_price_id,
            archived_at IS NOT NULL AS archived
        FROM billing_catalog_prices
        ORDER BY resource_type, plan_key, stripe_mode, price_kind
        "#,
    )
    .fetch_all(pool)
    .await?;

    let settings = sqlx::query_as::<_, CatalogSetting>(
        r#"
        SELECT setting_key, int_value
        FROM billing_catalog_settings
        ORDER BY setting_key
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(CatalogResponse {
        plans,
        prices,
        settings,
    })
}

/// `GET /api/v1/admin/billing/catalog`.
///
/// Auth (require_auth + require_admin) is applied in `routes.rs`,
/// matching the Go `registerAdminRoutes` middleware chain.
pub async fn get_catalog(State(pool): State<PgPool>) -> AppResult<Json<CatalogResponse>> {
    Ok(Json(get_catalog_core(&pool).await?))
}
