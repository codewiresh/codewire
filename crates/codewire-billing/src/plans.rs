//! `GET /api/v1/billing/plans/{resource_type}`.
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
//! handler is a pure DB read. Archived plans are dropped and
//! `is_admin_only` plans are masked for non-admin callers.
//!
//! Serialization contract notes:
//!
//! - `archived` and `is_admin_only` are absent when false; since archived plans are filtered out
//!   of every listing, `archived` never appears at all. The
//!   `skip_serializing_if` attributes below reproduce that byte for byte.
//! - Overage rates preserve the published integral JSON form (`0`, not
//!   `0.0`) through [`go_float`].
//! - The catalog columns are Postgres `integer`/`double precision`; the
//!   Rust field types must be `i32`/`f64` because sqlx refuses lossy
//!   integer-width coercions at decode time (an `i64` field against an
//!   INT4 column fails the row decode as soon as a row exists).

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use codewire_server_core::AppResult;
use codewire_server_core::auth::AuthUser;
use schemars::JsonSchema;
use serde::{Serialize, Serializer};
use sqlx::PgPool;

fn is_false(b: &bool) -> bool {
    !*b
}

/// Serialize an `f64` the way Go's encoding/json does: integral values
/// print without a fractional part (`5`, not `5.0`).
pub(crate) fn go_float<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 9.007_199_254_740_992e15 {
        s.serialize_i64(*v as i64)
    } else {
        s.serialize_f64(*v)
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema, sqlx::FromRow)]
pub struct OrgPlan {
    pub display_name: String,
    pub price_cents: i32,
    pub included_devs: i32,
    pub max_concurrent_ws: i32,
    pub max_team_members: i32,
    pub storage_gb: i32,
    pub is_contact_us: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub archived: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema, sqlx::FromRow)]
pub struct ResourcePlan {
    pub display_name: String,
    pub price_cents: i32,
    pub included_devs: i32,
    pub max_concurrent_ws: i32,
    pub max_team_members: i32,
    pub storage_gb: i32,
    pub is_contact_us: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub is_admin_only: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub archived: bool,
    pub included_cpu_hours: i32,
    pub included_mem_gb_hours: i32,
    pub included_disk_gb_hours: i32,
    #[serde(serialize_with = "go_float")]
    pub cpu_overage_cents: f64,
    #[serde(serialize_with = "go_float")]
    pub mem_overage_cents: f64,
    #[serde(serialize_with = "go_float")]
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

pub async fn get_plans(
    State(pool): State<PgPool>,
    user: AuthUser,
    Path(resource_type): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    if resource_type == "org" {
        return Ok(Json(serde_json::to_value(list_org_plans(&pool).await?)?));
    }

    Ok(Json(serde_json::to_value(
        list_resource_plans(&pool, &user, &resource_type).await?,
    )?))
}

/// Shared organization-plan query used by REST and Connect.
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

/// Shared resource-plan query used by REST and Connect.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn false_flags_are_omitted_like_go_omitempty() {
        let plan = ResourcePlan {
            display_name: "Standard".into(),
            price_cents: 900,
            included_devs: 1,
            max_concurrent_ws: 5,
            max_team_members: 5,
            storage_gb: 20,
            is_contact_us: false,
            is_admin_only: false,
            archived: false,
            included_cpu_hours: 100,
            included_mem_gb_hours: 200,
            included_disk_gb_hours: 300,
            cpu_overage_cents: 0.5,
            mem_overage_cents: 0.25,
            disk_overage_cents: 0.125,
        };
        let v = serde_json::to_value(&plan).unwrap();
        // Go tags these omitempty; absent (not false, not null) is the
        // contract.
        assert!(v.get("is_admin_only").is_none());
        assert!(v.get("archived").is_none());
        // Plain bools without omitempty stay present even when false.
        assert_eq!(v["is_contact_us"], false);
    }

    #[test]
    fn true_flags_serialize_when_set() {
        let plan = OrgPlan {
            display_name: "Legacy".into(),
            price_cents: 0,
            included_devs: 0,
            max_concurrent_ws: 0,
            max_team_members: 0,
            storage_gb: 0,
            is_contact_us: true,
            archived: true,
        };
        let v = serde_json::to_value(&plan).unwrap();
        assert_eq!(v["archived"], true);
        assert_eq!(v["is_contact_us"], true);
    }

    #[test]
    fn floats_serialize_like_go_encoding_json() {
        // Go prints float64(0) as "0" and 5.04 as "5.04"; serde's default
        // would print "0.0".
        let mut plan = ResourcePlan {
            display_name: "Enterprise".into(),
            price_cents: -1,
            included_devs: 0,
            max_concurrent_ws: -1,
            max_team_members: -1,
            storage_gb: 0,
            is_contact_us: true,
            is_admin_only: false,
            archived: false,
            included_cpu_hours: 0,
            included_mem_gb_hours: 0,
            included_disk_gb_hours: 0,
            cpu_overage_cents: 0.0,
            mem_overage_cents: 0.0,
            disk_overage_cents: 0.0,
        };
        let s = serde_json::to_string(&plan).unwrap();
        assert!(s.contains("\"cpu_overage_cents\":0"), "{s}");
        assert!(!s.contains("0.0"), "{s}");

        plan.cpu_overage_cents = 5.04;
        plan.disk_overage_cents = 0.01;
        let s = serde_json::to_string(&plan).unwrap();
        assert!(s.contains("\"cpu_overage_cents\":5.04"), "{s}");
        assert!(s.contains("\"disk_overage_cents\":0.01"), "{s}");
    }
}
