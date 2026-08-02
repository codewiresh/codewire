//! Billing plan queries for the Connect service.
//!
//! Two response shapes are selected by resource type:
//!
//! - `org` → map keyed by `plan_key` of [`OrgPlan`] (org-scoped, no
//!   compute fields).
//! - everything else → map keyed by `plan_key` of [`ResourcePlan`]
//!   (compute allowances + overage rates).
//!
//! `billing_catalog_plans` is the single source of truth (#69): the
//! default plan set is seeded by the canonical schema baseline, so this
//! query is a pure DB read. Archived plans are dropped and
//! `is_admin_only` plans are masked for non-admin callers.

use std::collections::BTreeMap;

use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OrgPlan {
    pub display_name: String,
    pub price_cents: i32,
    pub included_devs: i32,
    pub max_concurrent_ws: i32,
    pub max_team_members: i32,
    pub storage_gb: i32,
    pub is_contact_us: bool,
    pub archived: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourcePlan {
    pub display_name: String,
    pub price_cents: i32,
    pub included_devs: i32,
    pub max_concurrent_ws: i32,
    pub max_team_members: i32,
    pub storage_gb: i32,
    pub is_contact_us: bool,
    pub is_admin_only: bool,
    pub archived: bool,
    pub included_cpu_hours: i32,
    pub included_mem_gb_hours: i32,
    pub included_disk_gb_hours: i32,
    pub cpu_overage_cents: f64,
    pub mem_overage_cents: f64,
    pub disk_overage_cents: f64,
}

#[derive(Debug, sqlx::FromRow)]
struct OrgPlanRow {
    plan_key: String,
    #[sqlx(flatten)]
    plan: OrgPlan,
}

#[derive(Debug, sqlx::FromRow)]
struct ResourcePlanRow {
    plan_key: String,
    #[sqlx(flatten)]
    plan: ResourcePlan,
}

/// Shared organization-plan query used by the Connect adapter.
pub async fn list_org_plans(pool: &PgPool) -> AppResult<BTreeMap<String, OrgPlan>> {
    // The org shape has no admin-only flag in Go (`billing.OrgPlans`
    // only filters archived).
    let rows = sqlx::query_as::<_, OrgPlanRow>(
        r#"
        SELECT
            plan_key,
            display_name,
            price_cents,
            included_devs,
            max_concurrent_ws,
            max_team_members,
            storage_gb,
            is_contact_us,
            archived_at IS NOT NULL AS archived
        FROM billing_catalog_plans
        WHERE resource_type = 'org' AND archived_at IS NULL
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| (r.plan_key, r.plan)).collect())
}

/// Shared resource-plan query used by the Connect adapter.
pub async fn list_resource_plans(
    pool: &PgPool,
    user: &AuthUser,
    resource_type: &str,
) -> AppResult<BTreeMap<String, ResourcePlan>> {
    let rows = sqlx::query_as::<_, ResourcePlanRow>(
        r#"
        SELECT
            plan_key,
            display_name,
            price_cents,
            included_devs,
            max_concurrent_ws,
            max_team_members,
            storage_gb,
            is_contact_us,
            is_admin_only,
            archived_at IS NOT NULL AS archived,
            included_cpu_hours,
            included_mem_gb_hours,
            included_disk_gb_hours,
            cpu_overage_cents,
            mem_overage_cents,
            disk_overage_cents
        FROM billing_catalog_plans
        WHERE resource_type = $1
          AND archived_at IS NULL
          AND ($2 OR NOT is_admin_only)
        "#,
    )
    .bind(resource_type)
    .bind(user.is_admin)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| (r.plan_key, r.plan)).collect())
}
