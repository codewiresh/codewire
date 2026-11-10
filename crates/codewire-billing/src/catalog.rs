//! Billing catalog queries for BillingCatalogService.
//!
//! The catalog model (plans + prices + settings) is the source of truth
//! for what each resource type costs. Admin handlers write the same tables;
//! this handler only reads.
//!
//! BillingCatalogService maps these rows into the published proto contract.

use codewire_server_core::AppResult;
use sqlx::PgPool;

// Numeric field widths match the schema exactly (`integer` → `i32`,
// `double precision` → `f64`): sqlx rejects integer-width coercions at
// row-decode time, so an `i64` here would 500 on the first real row.
#[derive(Debug, sqlx::FromRow)]
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
    pub cpu_overage_cents: f64,
    pub mem_overage_cents: f64,
    pub disk_overage_cents: f64,
    pub archived: bool,
}

#[derive(Debug, sqlx::FromRow)]
pub struct CatalogPrice {
    pub resource_type: String,
    pub plan_key: String,
    pub stripe_mode: String,
    pub price_kind: String,
    pub stripe_price_id: String,
    pub archived: bool,
}

#[derive(Debug, sqlx::FromRow)]
pub struct CatalogSetting {
    pub setting_key: String,
    pub int_value: i32,
}

#[derive(Debug)]
pub struct CatalogResponse {
    pub plans: Vec<CatalogPlan>,
    pub prices: Vec<CatalogPrice>,
    pub settings: Vec<CatalogSetting>,
}

/// Shared catalog read used by BillingCatalogService.
/// The credit a new organization is granted now, in nano-euros: the
/// `signup_credit_cents` setting a platform admin sets (#3381). 0 is none.
pub async fn signup_credit_nano_eur(pool: &PgPool) -> AppResult<i64> {
    let cents: Option<i32> = sqlx::query_scalar(
        "SELECT int_value FROM billing_catalog_settings WHERE setting_key = 'signup_credit_cents'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(i64::from(cents.unwrap_or(0).max(0)) * 10_000_000)
}

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
