//! Environments read surface (#38 slice 1).
//!
//! Wire parity notes:
//! - Timestamps are Go `formatTime`: RFC3339 UTC, seconds precision.
//! - The list endpoint returns a JSON array (huma adds no `$schema`);
//!   the get endpoint's `$schema` is the documented accepted drift.
//! - Error envelopes are huma `CodedError` shapes via
//!   `AppError::Coded` (org_not_found / env_not_found / access_denied
//!   / internal_error with their CLI hints).

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_environment_runtime_mutation,
    run_organization_database_mutation,
};
use codewire_server_core::{AppError, AppResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use super::ApiState;
use crate::confidential_storage::require_interactive_access;

/// Mirrors `api.Environment` field-for-field (JSON tags included).
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Environment {
    pub id: String,
    pub org_id: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String")]
    pub preset_id: Option<String>,
    #[serde(rename = "type")]
    pub env_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: String,
    pub desired_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub recoverable: bool,
    pub state_changed_at: String,
    pub retry_count: i32,
    pub setup_phase: i32,
    pub setup_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shutdown_at: Option<String>,
    pub cpu_millicores: i32,
    pub memory_mb: i32,
    pub disk_gb: i32,
    pub isolation_tier: String,
    pub total_running_seconds: i32,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroyed_at: Option<String>,
    pub protected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_requested_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_grace_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ports: Vec<EnvironmentPort>,
}

/// Mirrors `api.EnvironmentPort`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct EnvironmentPort {
    pub id: String,
    pub environment_id: String,
    pub port: i32,
    pub label: String,
    pub access: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub preview_url: String,
    pub created_at: String,
}

pub(crate) fn coded(status: StatusCode, code: &'static str, detail: &'static str) -> AppError {
    AppError::Coded {
        status,
        code,
        detail: Cow::Borrowed(detail),
    }
}

/// Mirrors `formatTime`: RFC3339 UTC at seconds precision.
pub(crate) fn format_time(t: chrono::NaiveDateTime) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn format_time_opt(t: Option<chrono::NaiveDateTime>) -> Option<String> {
    t.map(format_time)
}

/// Mirrors `computePreviewURL`.
pub(crate) fn compute_preview_url(
    label: &str,
    env_id: &str,
    org_slug: &str,
    base_domain: &str,
) -> String {
    if base_domain.is_empty() || org_slug.is_empty() {
        return String::new();
    }
    let prefix = if env_id.len() > 5 {
        &env_id[..5]
    } else {
        env_id
    };
    format!("https://{label}-{prefix}-{org_slug}.{base_domain}")
}

/// Mirrors `envSelectCols` (environment_db.go) — columns only, so the
/// create handler's `WITH ins AS (...)` CTE can reuse them.
pub(crate) const ENV_SELECT_COLS: &str = r#"e.id, e.org_id, e.created_by, e.preset_id, e.type, e.name,
    e.state, e.desired_state, e.error_reason, e.recoverable, e.state_changed_at, e.retry_count,
    COALESCE(b.setup_phase, 0) AS setup_phase, COALESCE(b.setup_complete, false) AS setup_complete,
    COALESCE(b.setup_error, '') AS setup_error,
    e.ttl_seconds, e.shutdown_at,
    e.cpu_millicores, e.memory_mb, e.disk_gb, e.isolation_tier,
    e.total_running_seconds,
    e.created_at, e.started_at, e.stopped_at, e.destroyed_at,
    e.protected, e.deletion_requested_at, e.deletion_grace_until,
    t.name AS preset_name"#;

pub(crate) const ENV_SELECT_JOINS: &str = r#"LEFT JOIN environment_presets t ON e.preset_id = t.id
    LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id"#;

pub(crate) fn scan_environment(row: &PgRow) -> Result<Environment, sqlx::Error> {
    let setup_error: String = row.try_get("setup_error")?;
    Ok(Environment {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        created_by: row.try_get("created_by")?,
        preset_id: row.try_get("preset_id")?,
        env_type: row.try_get("type")?,
        name: row.try_get("name")?,
        state: row.try_get("state")?,
        desired_state: row.try_get("desired_state")?,
        error_reason: row.try_get("error_reason")?,
        recoverable: row.try_get("recoverable")?,
        state_changed_at: format_time(row.try_get("state_changed_at")?),
        retry_count: row.try_get("retry_count")?,
        setup_phase: row.try_get("setup_phase")?,
        setup_complete: row.try_get("setup_complete")?,
        setup_error: if setup_error.trim().is_empty() {
            None
        } else {
            Some(setup_error)
        },
        ttl_seconds: row.try_get("ttl_seconds")?,
        shutdown_at: format_time_opt(row.try_get("shutdown_at")?),
        cpu_millicores: row.try_get("cpu_millicores")?,
        memory_mb: row.try_get("memory_mb")?,
        disk_gb: row.try_get("disk_gb")?,
        isolation_tier: row.try_get("isolation_tier")?,
        total_running_seconds: row.try_get("total_running_seconds")?,
        created_at: format_time(row.try_get("created_at")?),
        started_at: format_time_opt(row.try_get("started_at")?),
        stopped_at: format_time_opt(row.try_get("stopped_at")?),
        destroyed_at: format_time_opt(row.try_get("destroyed_at")?),
        protected: row.try_get("protected")?,
        deletion_requested_at: format_time_opt(row.try_get("deletion_requested_at")?),
        deletion_grace_until: format_time_opt(row.try_get("deletion_grace_until")?),
        preset_name: row.try_get("preset_name")?,
        // Runtime network enrollment needs a dedicated credential-free
        // contract; workload environment values are never control input.
        network: None,
        ports: Vec::new(),
    })
}

/// Mirrors `requireEnvironmentAccess` (permission hierarchy
/// viewer < operator < owner; creator and org owner/admin bypass;
/// denials audit-logged with severity warning). `denied` is the
/// handler-specific 403 detail — Go handlers wrap the access error
/// with their own message.
pub(crate) async fn require_environment_access(
    pool: &PgPool,
    user: &AuthUser,
    env_id: &str,
    org_id: &str,
    min_permission: &str,
    denied: &'static str,
) -> Result<(), AppError> {
    // The creator shortcut below is user-based, but an API key delegates
    // authority for exactly one organization. Reject a mismatched key before
    // any user-level shortcut can widen that delegated authority.
    if !user.permits_organization(org_id) {
        return Err(coded(StatusCode::FORBIDDEN, "access_denied", denied));
    }

    let environment: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT org_id, created_by FROM environments WHERE id = $1")
            .bind(env_id)
            .fetch_optional(pool)
            .await?;
    let Some((environment_org_id, created_by)) = environment else {
        return Err(coded(StatusCode::FORBIDDEN, "access_denied", denied));
    };
    // Every shortcut below is scoped to the environment's actual tenant.
    // Without this comparison, a caller can put an organization they own in
    // the path and authorize access to an environment from another tenant.
    if environment_org_id != org_id {
        return Err(coded(StatusCode::FORBIDDEN, "access_denied", denied));
    }
    if created_by.as_deref() == Some(user.user_id.as_str()) {
        return Ok(());
    }

    if let Some(role) = user_org_role(pool, user, org_id).await?
        && (role == "owner" || role == "admin")
    {
        return Ok(());
    }

    let level = |p: &str| match p {
        "viewer" => 1,
        "operator" => 2,
        "owner" => 3,
        _ => 0,
    };
    let grant: Option<(String,)> = sqlx::query_as(
        "SELECT permission FROM environment_access WHERE environment_id = $1 AND user_id = $2",
    )
    .bind(env_id)
    .bind(&user.user_id)
    .fetch_optional(pool)
    .await?;

    match grant {
        None => {
            log_audit_event(
                pool,
                "environment.access.denied",
                &user.user_id,
                serde_json::json!({
                    "environment_id": env_id, "org_id": org_id,
                    "required": min_permission, "reason": "no grant",
                }),
            )
            .await;
            Err(coded(StatusCode::FORBIDDEN, "access_denied", denied))
        }
        Some((permission,)) if level(&permission) < level(min_permission) => {
            log_audit_event(
                pool,
                "environment.access.denied",
                &user.user_id,
                serde_json::json!({
                    "environment_id": env_id, "org_id": org_id,
                    "required": min_permission, "actual": permission,
                }),
            )
            .await;
            Err(coded(StatusCode::FORBIDDEN, "access_denied", denied))
        }
        Some(_) => Ok(()),
    }
}

/// Mirrors `auth.LogAuditEvent` (warn-only, severity "warning").
async fn log_audit_event(pool: &PgPool, action: &str, user_id: &str, metadata: serde_json::Value) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    if let Err(e) = sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity)
           VALUES ($1, NOW(), $2, $3, '', '', $4, 'warning')"#,
    )
    .bind(&id)
    .bind(action)
    .bind(user_id)
    .bind(&metadata)
    .execute(pool)
    .await
    {
        tracing::error!(action, error = %e, "failed to log audit event");
    }
}

#[derive(Debug, Deserialize)]
pub struct ListEnvironmentsQuery {
    #[serde(default, rename = "type")]
    pub env_type: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub include_destroyed: bool,
}

pub(crate) async fn list_environments_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    q: ListEnvironmentsQuery,
) -> AppResult<Vec<Environment>> {
    if user_org_role(&state.pool, user, org_id).await?.is_none() {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        ));
    }

    // Mirrors listEnvironments' dynamic filters (strPtrOrNil: empty
    // query values mean "no filter").
    let mut sql = format!(
        "SELECT {ENV_SELECT_COLS} FROM environments e {ENV_SELECT_JOINS} WHERE e.org_id = $1"
    );
    let env_type = (!q.env_type.is_empty()).then_some(q.env_type.as_str());
    let st = (!q.state.is_empty()).then_some(q.state.as_str());
    let mut idx = 2;
    if env_type.is_some() {
        sql.push_str(&format!(" AND e.type = ${idx}"));
        idx += 1;
    }
    if st.is_some() {
        sql.push_str(&format!(" AND e.state = ${idx}"));
    }
    if !q.include_destroyed && st.is_none() {
        sql.push_str(" AND e.state NOT IN ('destroyed', 'destroying')");
    }
    sql.push_str(" ORDER BY e.created_at DESC");

    let mut query = sqlx::query(&sql).bind(org_id);
    if let Some(t) = env_type {
        query = query.bind(t.to_string());
    }
    if let Some(s) = st {
        query = query.bind(s.to_string());
    }

    let rows = query.fetch_all(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "list environments query failed");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list environments",
        )
    })?;
    let envs = rows
        .iter()
        .map(scan_environment)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            tracing::error!(error = %e, "scan environment failed");
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to list environments",
            )
        })?;
    Ok(envs)
}

pub(crate) async fn get_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<Environment> {
    if user_org_role(&state.pool, user, org_id).await?.is_none() {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        ));
    }

    require_environment_access(&state.pool, user, env_id, org_id, "viewer", "access denied")
        .await?;

    let sql = format!(
        "SELECT {ENV_SELECT_COLS} FROM environments e {ENV_SELECT_JOINS} WHERE e.id = $1 AND e.org_id = $2"
    );
    let row = sqlx::query(&sql)
        .bind(env_id)
        .bind(org_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| {
            coded(
                StatusCode::NOT_FOUND,
                "env_not_found",
                "environment not found",
            )
        })?;
    let mut env = scan_environment(&row).map_err(|_| {
        coded(
            StatusCode::NOT_FOUND,
            "env_not_found",
            "environment not found",
        )
    })?;

    // Mirrors the get handler: ports with computed preview URLs.
    let port_rows = sqlx::query(
        r#"SELECT id, environment_id, port, label, access, created_at
           FROM environment_ports
           WHERE environment_id = $1 AND deletion_requested_at IS NULL
           ORDER BY created_at"#,
    )
    .bind(&env.id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    if !port_rows.is_empty() {
        let org_slug: String = sqlx::query_scalar("SELECT slug FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        env.ports = port_rows
            .iter()
            .map(|r| -> Result<EnvironmentPort, sqlx::Error> {
                Ok(EnvironmentPort {
                    id: r.try_get("id")?,
                    environment_id: r.try_get("environment_id")?,
                    port: r.try_get("port")?,
                    label: r.try_get::<String, _>("label")?,
                    access: r.try_get("access")?,
                    preview_url: String::new(),
                    created_at: format_time(r.try_get("created_at")?),
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default();
        for p in &mut env.ports {
            p.preview_url =
                compute_preview_url(&p.label, &env.id, &org_slug, &state.preview_base_domain);
        }
    }

    Ok(env)
}

// ── Lifecycle intent endpoints (#38 slice 2) ───────────────────────────
//
// Port of the delete/stop/start/protect/unprotect/cancel-deletion/
// extend-ttl handlers in environment_routes.go. All writes go through
// the shared lifecycle service (same environment_logs + journal
// entries as Go), and lifecycle triggers go through the Temporal
// SignalWithStart path — the same `environment/{id}` workflow the Go
// API signals in temporal-primary mode.
//
// The protect/unprotect/cancel-deletion/extend-ttl "events" are NOT
// ported as triggers: Go routes them through events.EmitEnvironment,
// where environmentActionToJobType returns "" for these actions, so
// they have always been warn-level no-ops on the wire.

/// Mirrors `api.StatusResponse`.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartOutcomeCore {
    Started,
    Retried,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StartEnvironmentResult {
    pub(crate) status: &'static str,
    pub(crate) outcome: StartOutcomeCore,
}

pub(crate) fn coded_owned(status: StatusCode, code: &'static str, detail: String) -> AppError {
    AppError::Coded {
        status,
        code,
        detail: Cow::Owned(detail),
    }
}

/// Lifecycle trigger via Temporal SignalWithStart of the
/// `environment/{id}` workflow. Temporal is the only orchestrator.
pub(crate) async fn trigger_environment(
    state: &ApiState,
    env_id: &str,
    action: &str,
) -> anyhow::Result<()> {
    state
        .temporal_trigger
        .trigger_environment(env_id, action)
        .await
}

/// The slice of `getEnvironment` the write handlers consume.
pub(crate) struct EnvSummary {
    pub(crate) id: String,
    pub(crate) state: String,
    pub(crate) protected: bool,
    pub(crate) env_type: String,
    pub(crate) cpu_millicores: i32,
    pub(crate) memory_mb: i32,
    pub(crate) isolation_tier: String,
}

pub(crate) async fn fetch_env_summary(
    pool: &PgPool,
    org_id: &str,
    env_id: &str,
) -> Result<EnvSummary, AppError> {
    let row = sqlx::query(
        r#"SELECT id, state, protected, type, cpu_millicores, memory_mb, isolation_tier
           FROM environments WHERE id = $1 AND org_id = $2"#,
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .ok_or_else(|| {
        coded(
            StatusCode::NOT_FOUND,
            "env_not_found",
            "environment not found",
        )
    })?;
    Ok(EnvSummary {
        id: row.try_get("id")?,
        state: row.try_get("state")?,
        protected: row.try_get("protected")?,
        env_type: row.try_get("type")?,
        cpu_millicores: row.try_get("cpu_millicores")?,
        memory_mb: row.try_get("memory_mb")?,
        isolation_tier: row.try_get("isolation_tier")?,
    })
}

pub(crate) async fn require_org_member(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> Result<(), AppError> {
    if user_org_role(pool, user, org_id).await?.is_none() {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        ));
    }
    Ok(())
}

// ── Quota (port of the environment_db.go quota helpers) ────────────────

/// Mirrors `api.OrgEnvironmentUsage`. COUNT/SUM come back as int8.
#[derive(Debug, Default, Clone, Copy)]
struct OrgEnvironmentUsage {
    active_total: i64,
    active_sandbox: i64,
    total_cpu: i64,
    total_memory_mb: i64,
}

/// Mirrors `api.OrgQuota`.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct OrgQuota {
    pub(crate) max_concurrent_environments: i32,
    pub(crate) max_concurrent_sandbox: i32,
    pub(crate) max_cpu_millicores: i32,
    pub(crate) max_memory_mb: i32,
}

/// Mirrors `countActiveEnvironments` (active = consuming compute).
async fn count_active_environments(
    pool: &PgPool,
    org_id: &str,
) -> Result<OrgEnvironmentUsage, sqlx::Error> {
    let (active_total, active_sandbox, total_cpu, total_memory_mb): (i64, i64, i64, i64) =
        sqlx::query_as(
            r#"SELECT
                COUNT(*),
                COUNT(*) FILTER (WHERE type = 'sandbox'),
                COALESCE(SUM(cpu_millicores), 0),
                COALESCE(SUM(memory_mb), 0)
             FROM environments
             WHERE org_id = $1
               AND state NOT IN ('destroyed', 'destroying', 'error', 'stopped', 'archived')"#,
        )
        .bind(org_id)
        .fetch_one(pool)
        .await?;
    Ok(OrgEnvironmentUsage {
        active_total,
        active_sandbox,
        total_cpu,
        total_memory_mb,
    })
}

/// Mirrors `resolveQuotaFromPlan`: defaults applied for unresolved
/// fields. `plan_max_ws` is the sandbox plan's max_concurrent_ws (0
/// when the plan is unknown).
fn resolve_quota_from_plan(plan_max_ws: i32) -> OrgQuota {
    let mut q = OrgQuota {
        max_concurrent_sandbox: plan_max_ws,
        ..Default::default()
    };
    if q.max_concurrent_sandbox == -1 {
        q.max_concurrent_environments = -1;
    } else if q.max_concurrent_sandbox > 0 {
        q.max_concurrent_environments = q.max_concurrent_sandbox;
    }
    if q.max_concurrent_environments == 0 {
        q.max_concurrent_environments = 10;
    }
    if q.max_concurrent_sandbox == 0 {
        q.max_concurrent_sandbox = 50;
    }
    if q.max_cpu_millicores == 0 {
        q.max_cpu_millicores = 32000;
    }
    if q.max_memory_mb == 0 {
        q.max_memory_mb = 65536;
    }
    q
}

/// Mirrors `getOrgQuota`: explicit environment_quotas row →
/// plan-derived → hardcoded defaults.
pub(crate) async fn get_org_quota(pool: &PgPool, org_id: &str) -> OrgQuota {
    if let Ok(Some((envs, sandbox, cpu, mem))) = sqlx::query_as::<_, (i32, i32, i32, i32)>(
        r#"SELECT max_concurrent_environments, max_concurrent_sandbox,
                  max_cpu_millicores, max_memory_mb
           FROM environment_quotas WHERE org_id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    {
        return OrgQuota {
            max_concurrent_environments: envs,
            max_concurrent_sandbox: sandbox,
            max_cpu_millicores: cpu,
            max_memory_mb: mem,
        };
    }

    // Plan fallback. The effective-plan resolution mirrors
    // billing.ResolveEffectiveOrgEnvironmentPlan (env subscription →
    // org subscription → organizations.billing_plan), and the plan
    // lookup reads the billing_catalog_plans table that backs Go's
    // in-memory catalog (archived plans included, as in
    // GetResourcePlan).
    let plan = resolve_effective_plan(pool, org_id).await;
    let plan_max_ws: i32 = if plan.is_empty() {
        0
    } else {
        sqlx::query_scalar(
            r#"SELECT max_concurrent_ws FROM billing_catalog_plans
               WHERE resource_type = 'sandbox' AND plan_key = $1"#,
        )
        .bind(&plan)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(0)
    };
    resolve_quota_from_plan(plan_max_ws)
}

/// Mirrors `billing.ResolveEffectiveOrgEnvironmentPlan` (the plan-name
/// slice; the Stripe subscription id is irrelevant for quotas).
async fn resolve_effective_plan(pool: &PgPool, org_id: &str) -> String {
    if let Ok(Some((plan,))) = sqlx::query_as::<_, (String,)>(
        r#"SELECT plan FROM environment_subscriptions
           WHERE org_id = $1 AND status IN ('active', 'trialing', 'past_due')
           ORDER BY updated_at DESC LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
        && !plan.is_empty()
    {
        return plan;
    }
    if let Ok(Some((plan,))) = sqlx::query_as::<_, (String,)>(
        r#"SELECT os.plan FROM org_subscriptions os
           WHERE os.org_id = $1 AND os.status IN ('active', 'trialing', 'past_due')
           ORDER BY os.updated_at DESC LIMIT 1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
        && !plan.is_empty()
    {
        return plan;
    }
    if let Ok(Some((plan,))) = sqlx::query_as::<_, (String,)>(
        r#"SELECT billing_plan FROM organizations
           WHERE id = $1 AND billing_plan NOT IN ('', 'none')
             AND billing_status IN ('active', 'trialing', 'past_due')"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    {
        return plan;
    }
    String::new()
}

/// Mirrors `evaluateQuota` — pure comparison, no DB.
fn evaluate_quota(
    quota: OrgQuota,
    usage: OrgEnvironmentUsage,
    env_type: &str,
    cpu: i32,
    mem: i32,
) -> Result<(), AppError> {
    if env_type == "sandbox"
        && quota.max_concurrent_sandbox != -1
        && usage.active_sandbox >= i64::from(quota.max_concurrent_sandbox)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "quota_exceeded",
            format!(
                "sandbox environment limit reached ({}/{})",
                usage.active_sandbox, quota.max_concurrent_sandbox
            ),
        ));
    }
    if quota.max_concurrent_environments != -1
        && usage.active_total >= i64::from(quota.max_concurrent_environments)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "quota_exceeded",
            format!(
                "environment limit reached ({}/{})",
                usage.active_total, quota.max_concurrent_environments
            ),
        ));
    }
    if quota.max_cpu_millicores != -1
        && usage.total_cpu + i64::from(cpu) > i64::from(quota.max_cpu_millicores)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "resource_limit_exceeded",
            format!(
                "CPU limit would be exceeded ({}+{} > {} millicores)",
                usage.total_cpu, cpu, quota.max_cpu_millicores
            ),
        ));
    }
    if quota.max_memory_mb != -1
        && usage.total_memory_mb + i64::from(mem) > i64::from(quota.max_memory_mb)
    {
        return Err(coded_owned(
            StatusCode::FORBIDDEN,
            "resource_limit_exceeded",
            format!(
                "memory limit would be exceeded ({}+{} > {} MB)",
                usage.total_memory_mb, mem, quota.max_memory_mb
            ),
        ));
    }
    Ok(())
}

/// Mirrors `checkQuota` — fails open on DB errors.
pub(crate) async fn check_quota(
    pool: &PgPool,
    org_id: &str,
    env_type: &str,
    cpu: i32,
    mem: i32,
) -> Result<(), AppError> {
    let usage = match count_active_environments(pool, org_id).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(org_id, error = %e, "quota check: failed to count active environments");
            return Ok(());
        }
    };
    let quota = get_org_quota(pool, org_id).await;
    evaluate_quota(quota, usage, env_type, cpu, mem)
}

/// Mirrors `auth.checkRateLimit` over the shared rate_limit table
/// (count within a sliding window keyed by `key`; any read error means
/// "no record yet" and resets the window, exactly like Go).
pub(crate) async fn check_rate_limit(
    pool: &PgPool,
    key: &str,
    window_secs: i64,
    max: i32,
) -> Result<bool, sqlx::Error> {
    let now = chrono::Utc::now().timestamp_millis();
    let window_start = now - window_secs * 1000;

    let existing: Option<(i32, i64)> =
        sqlx::query_as("SELECT count, last_request FROM rate_limit WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    let Some((count, last_request)) = existing else {
        let id = uuid::Uuid::new_v4().simple().to_string();
        sqlx::query(
            r#"INSERT INTO rate_limit (id, key, count, last_request)
               VALUES ($1, $2, 1, $3)
               ON CONFLICT (key) DO UPDATE SET count = 1, last_request = $3"#,
        )
        .bind(&id)
        .bind(key)
        .bind(now)
        .execute(pool)
        .await?;
        return Ok(true);
    };

    if last_request < window_start {
        sqlx::query("UPDATE rate_limit SET count = 1, last_request = $1 WHERE key = $2")
            .bind(now)
            .bind(key)
            .execute(pool)
            .await?;
        return Ok(true);
    }

    if count >= max {
        return Ok(false);
    }

    sqlx::query("UPDATE rate_limit SET count = count + 1, last_request = $1 WHERE key = $2")
        .bind(now)
        .bind(key)
        .execute(pool)
        .await?;
    Ok(true)
}

pub(crate) async fn delete_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<()> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can delete environments",
    )
    .await?;
    let env = fetch_env_summary(&state.pool, org_id, env_id).await?;

    let dispatch_ambiguous = AtomicBool::new(false);
    run_environment_runtime_mutation(&state.pool, org_id, env_id, async {
        let result: AppResult<()> = async {
            if env.state == "destroyed" || env.state == "destroying" {
                return Err(coded(
                    StatusCode::BAD_REQUEST,
                    "invalid_state",
                    "environment is already destroyed or destroying",
                ));
            }
            if env.protected {
                return Err(coded(
                    StatusCode::BAD_REQUEST,
                    "environment_protected",
                    "environment is protected from deletion",
                ));
            }

            // Explicit user deletes are immediate: clear pending grace-period
            // metadata, transition to destroying, then the worker tears down
            // asynchronously.
            let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
            if lifecycle.clear_deletion_grace(&env.id).await.is_err() {
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to clear pending deletion metadata",
                ));
            }
            let snap = crate::lifecycle::Snapshot {
                id: env.id.clone(),
                state: env.state.clone(),
                ..Default::default()
            };
            if lifecycle.prepare_destroy(&snap).await.is_err() {
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to mark environment for deletion",
                ));
            }
            if lifecycle
                .set_desired_state(&env.id, "destroyed")
                .await
                .is_err()
            {
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to destroy environment",
                ));
            }
            if trigger_environment(state, &env.id, "destroy")
                .await
                .is_err()
            {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to request environment destroy",
                ));
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

pub(crate) async fn stop_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can stop environments",
    )
    .await?;
    let env = fetch_env_summary(&state.pool, org_id, env_id).await?;

    let dispatch_ambiguous = AtomicBool::new(false);
    run_environment_runtime_mutation(&state.pool, org_id, env_id, async {
        let result: AppResult<StatusResponse> = async {
            if env.state != "running" {
                return Err(coded(
                    StatusCode::BAD_REQUEST,
                    "invalid_state",
                    "environment must be running to stop",
                ));
            }

            let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
            if lifecycle
                .set_desired_state(&env.id, "stopped")
                .await
                .is_err()
            {
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to stop environment",
                ));
            }
            if trigger_environment(state, &env.id, "stop").await.is_err() {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to request environment stop",
                ));
            }
            Ok(StatusResponse {
                status: "stop requested",
            })
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

pub(crate) async fn start_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StartEnvironmentResult> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "operator",
        "access denied",
    )
    .await?;
    let env = fetch_env_summary(&state.pool, org_id, env_id).await?;
    require_interactive_access(state.confidential_storage_flags, user, &env.isolation_tier)?;

    let dispatch_ambiguous = AtomicBool::new(false);
    run_environment_runtime_mutation(&state.pool, org_id, env_id, async {
        let result: AppResult<StartEnvironmentResult> = async {
            let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
            match env.state.as_str() {
                "stopped" => {} // normal start flow below
                "error" | "pending" => {
                    // Reset for immediate re-creation.
                    let retry = if env.state == "error" && env.isolation_tier == "confidential" {
                        lifecycle.retry_confidential_start(&env.id, org_id).await
                    } else {
                        lifecycle.reset_for_retry(&env.id).await
                    };
                    if let Err(error) = retry {
                        if error.to_string().contains("CONFIDENTIAL_CAPACITY_UNAVAILABLE") {
                            return Err(coded(
                                StatusCode::CONFLICT,
                                "CONFIDENTIAL_CAPACITY_UNAVAILABLE",
                                "confidential environment capacity is currently unavailable",
                            ));
                        }
                        return Err(coded(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "failed to reset environment",
                        ));
                    }
                    if trigger_environment(state, &env.id, "create").await.is_err() {
                        dispatch_ambiguous.store(true, Ordering::Release);
                        return Err(coded(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "failed to retry environment create",
                        ));
                    }
                    return Ok(StartEnvironmentResult {
                        status: "retry requested",
                        outcome: StartOutcomeCore::Retried,
                    });
                }
                _ => {
                    return Err(coded(
                        StatusCode::BAD_REQUEST,
                        "invalid_state",
                        "environment must be stopped, pending, or errored to start",
                    ));
                }
            }

            // Rate limit (fail open on errors, like Go).
            match check_rate_limit(&state.pool, &format!("env_start:{}", user.user_id), 60, 10)
                .await
            {
                Err(e) => tracing::warn!(error = %e, "env rate limit check failed, allowing"),
                Ok(false) => {
                    return Err(coded(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate_limited",
                        "too many environment start requests",
                    ));
                }
                Ok(true) => {}
            }

            // Check quota — starting resumes compute allocation.
            check_quota(
                &state.pool,
                org_id,
                &env.env_type,
                env.cpu_millicores,
                env.memory_mb,
            )
            .await?;

            if let Err(error) = lifecycle
                .admit_confidential_start(&env.id, org_id, &env.isolation_tier)
                .await
            {
                if error.to_string().contains("CONFIDENTIAL_CAPACITY_UNAVAILABLE") {
                    return Err(coded(
                        StatusCode::CONFLICT,
                        "CONFIDENTIAL_CAPACITY_UNAVAILABLE",
                        "confidential environment capacity is currently unavailable",
                    ));
                }
                tracing::error!(%error, environment_id = env.id, "start environment admission failed");
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to start environment",
                ));
            }
            if trigger_environment(state, &env.id, "start").await.is_err() {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to request environment start",
                ));
            }
            Ok(StartEnvironmentResult {
                status: "start requested",
                outcome: StartOutcomeCore::Started,
            })
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

pub(crate) async fn protect_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can protect environments",
    )
    .await?;

    run_organization_database_mutation(&state.pool, org_id, async {
        let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
        if lifecycle.protect(env_id).await.is_err() {
            return Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to protect environment",
            ));
        }
        Ok(StatusResponse {
            status: "protected",
        })
    })
    .await
}

pub(crate) async fn unprotect_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can unprotect environments",
    )
    .await?;

    run_organization_database_mutation(&state.pool, org_id, async {
        let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
        if lifecycle.unprotect(env_id).await.is_err() {
            return Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to unprotect environment",
            ));
        }
        Ok(StatusResponse {
            status: "unprotected",
        })
    })
    .await
}

pub(crate) async fn cancel_environment_deletion_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(&state.pool, user, env_id, org_id, "owner", "access denied").await?;
    let env = fetch_env_summary(&state.pool, org_id, env_id).await?;
    require_interactive_access(state.confidential_storage_flags, user, &env.isolation_tier)?;

    run_organization_database_mutation(&state.pool, org_id, async {
        let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
        match lifecycle.cancel_deletion(env_id).await {
            Err(_) => Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to cancel deletion",
            )),
            Ok(false) => Err(coded(
                StatusCode::BAD_REQUEST,
                "invalid_state",
                "no pending deletion to cancel",
            )),
            Ok(true) => Ok(StatusResponse {
                status: "deletion_cancelled",
            }),
        }
    })
    .await
}

/// Body of `POST .../extend-ttl`. (Go's huma schema also 422s when the
/// field is absent; the CLI always sends it, so only the in-range
/// check below is on the parity surface.)
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtendTtlBody {
    pub additional_seconds: i32,
}

pub(crate) async fn extend_environment_ttl_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    additional_seconds: i32,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(&state.pool, user, env_id, org_id, "owner", "access denied").await?;

    let secs = additional_seconds;
    if !(60..=86400).contains(&secs) {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "additional_seconds must be between 60 and 86400",
        ));
    }

    run_organization_database_mutation(&state.pool, org_id, async {
        let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
        match lifecycle.extend_ttl(env_id, secs).await {
            Err(_) => Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to extend TTL",
            )),
            Ok(false) => Err(coded(
                StatusCode::BAD_REQUEST,
                "invalid_state",
                "environment is already destroyed or not found",
            )),
            Ok(true) => Ok(StatusResponse {
                status: "ttl_extended",
            }),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn preview_url_mirrors_go() {
        assert_eq!(
            compute_preview_url("web", "env_12345678", "acme", "preview.dev"),
            "https://web-env_1-acme.preview.dev"
        );
        assert_eq!(
            compute_preview_url("web", "abc", "acme", "preview.dev"),
            "https://web-abc-acme.preview.dev"
        );
        assert_eq!(compute_preview_url("web", "abc", "", "preview.dev"), "");
        assert_eq!(compute_preview_url("web", "abc", "acme", ""), "");
    }

    #[test]
    fn quota_evaluation_mirrors_go() {
        let usage = |total, sandbox, cpu, mem| OrgEnvironmentUsage {
            active_total: total,
            active_sandbox: sandbox,
            total_cpu: cpu,
            total_memory_mb: mem,
        };
        let quota = OrgQuota {
            max_concurrent_environments: 10,
            max_concurrent_sandbox: 5,
            max_cpu_millicores: 32000,
            max_memory_mb: 65536,
        };

        // Within limits.
        assert!(evaluate_quota(quota, usage(3, 2, 8000, 16384), "sandbox", 2000, 4096).is_ok());

        // Sandbox concurrency cap (sandbox type only).
        let err = evaluate_quota(quota, usage(5, 5, 0, 0), "sandbox", 0, 0).unwrap_err();
        assert!(
            format!("{err}").contains("sandbox environment limit reached (5/5)"),
            "{err}"
        );
        assert!(evaluate_quota(quota, usage(5, 5, 0, 0), "custom", 0, 0).is_ok());

        // Total concurrency cap.
        let err = evaluate_quota(quota, usage(10, 2, 0, 0), "custom", 0, 0).unwrap_err();
        assert!(
            format!("{err}").contains("environment limit reached (10/10)"),
            "{err}"
        );

        // CPU and memory additive checks.
        let err = evaluate_quota(quota, usage(1, 1, 31000, 0), "custom", 2000, 0).unwrap_err();
        assert!(
            format!("{err}")
                .contains("CPU limit would be exceeded (31000+2000 > 32000 millicores)"),
            "{err}"
        );
        let err = evaluate_quota(quota, usage(1, 1, 0, 65000), "custom", 0, 4096).unwrap_err();
        assert!(
            format!("{err}").contains("memory limit would be exceeded (65000+4096 > 65536 MB)"),
            "{err}"
        );

        // -1 disables a limit.
        let unlimited = OrgQuota {
            max_concurrent_environments: -1,
            max_concurrent_sandbox: -1,
            max_cpu_millicores: -1,
            max_memory_mb: -1,
        };
        assert!(
            evaluate_quota(
                unlimited,
                usage(1000, 1000, 1 << 30, 1 << 30),
                "sandbox",
                9999,
                9999
            )
            .is_ok()
        );
    }

    #[test]
    fn quota_plan_fallback_mirrors_go_defaults() {
        // Unknown plan (0) → all defaults.
        let q = resolve_quota_from_plan(0);
        assert_eq!(
            (
                q.max_concurrent_environments,
                q.max_concurrent_sandbox,
                q.max_cpu_millicores,
                q.max_memory_mb
            ),
            (10, 50, 32000, 65536)
        );
        // Plan cap propagates to the total-environments cap.
        let q = resolve_quota_from_plan(5);
        assert_eq!(
            (q.max_concurrent_environments, q.max_concurrent_sandbox),
            (5, 5)
        );
        // Unlimited plan.
        let q = resolve_quota_from_plan(-1);
        assert_eq!(
            (q.max_concurrent_environments, q.max_concurrent_sandbox),
            (-1, -1)
        );
    }

    #[test]
    fn environment_serializes_with_go_omitempty_semantics() {
        let env = Environment {
            id: "e1".into(),
            org_id: "o1".into(),
            created_by: "u1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            name: Some("n".into()),
            state: "running".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            error_reason: None,
            recoverable: true,
            state_changed_at: "2026-06-12T00:00:00Z".into(),
            retry_count: 0,
            setup_phase: 0,
            setup_complete: false,
            setup_error: None,
            ttl_seconds: None,
            shutdown_at: None,
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 10,
            total_running_seconds: 0,
            created_at: "2026-06-12T00:00:00Z".into(),
            started_at: None,
            stopped_at: None,
            destroyed_at: None,
            protected: false,
            deletion_requested_at: None,
            deletion_grace_until: None,
            preset_name: None,
            network: None,
            ports: Vec::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        // Omitted optionals + empty ports, exactly like Go omitempty.
        for absent in [
            "preset_id",
            "error_reason",
            "setup_error",
            "ttl_seconds",
            "shutdown_at",
            "started_at",
            "ports",
            "network",
            "preset_name",
        ] {
            assert!(v.get(absent).is_none(), "{absent} should be omitted");
        }
        assert_eq!(v["type"], "sandbox");
        assert_eq!(v["state_changed_at"], "2026-06-12T00:00:00Z");
    }

    #[test]
    fn extend_ttl_validation_rejects_missing_required_field() {
        let Err(AppError::Validation { errors }) =
            validate_value::<ExtendTtlBody>(serde_json::json!({}))
        else {
            panic!("expected missing additional_seconds to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("additional_seconds"));
    }

    #[test]
    fn extend_ttl_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<ExtendTtlBody>(serde_json::json!({
                "additional_seconds": "60"
            }))
        else {
            panic!("expected type-invalid additional_seconds to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/additional_seconds");
        assert!(errors[0].message.contains("integer"));
    }
}
