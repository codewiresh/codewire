//! Admin read models and queries for the Connect AdminService. These are
//! `is_admin`-gated reads, so the Connect service layers
//! [`require_admin`](codewire_server_core::auth::require_admin) on top of
//! `require_auth`.
//!
//! `getAdminStats`, `listAdminOrganizations`, `listAuditLogs`,
//! lifecycle journal, and environment startup timing/summary port here, with
//! the audited writes of one organization's environment quota.

use chrono::{Datelike, TimeZone, Utc};
use std::borrow::Cow;

use codewire_server_core::AppError;
use codewire_server_core::AppResult;
use codewire_server_core::ValidationIssue;
use serde::{Serialize, Serializer};
use sqlx::Row;

use super::ApiState;
use super::environments::{
    FALLBACK_QUOTA_DEFAULTS, OrgQuota, count_active_environments, format_time, get_org_quota,
    resolve_effective_plan,
};

pub mod capacity;
pub mod credit;
#[cfg(test)]
mod credit_database_tests;
#[cfg(test)]
mod dedicated_cpu_database_tests;
#[cfg(test)]
mod quota_database_tests;
#[cfg(test)]
mod startup_database_tests;

/// Mirrors `api.AdminStatsResponse`.
#[derive(Debug, Serialize)]
pub struct AdminStatsResponse {
    pub total_environments: i64,
    pub active_environments: i64,
    #[serde(serialize_with = "serialize_go_float")]
    pub monthly_cpu_hours: f64,
    #[serde(serialize_with = "serialize_go_float")]
    pub monthly_memory_gb_hours: f64,
    pub monthly_cost: i64,
}

fn serialize_go_float<S>(value: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if value.is_finite()
        && value.fract() == 0.0
        && *value >= i64::MIN as f64
        && *value <= i64::MAX as f64
    {
        serializer.serialize_i64(*value as i64)
    } else {
        serializer.serialize_f64(*value)
    }
}

/// Shared global-statistics query used by AdminService.
pub(crate) async fn get_admin_stats_core(state: &ApiState) -> AppResult<AdminStatsResponse> {
    let total_environments: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM environments"#)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "admin: count environments failed");
            AppError::InternalMsg("failed to count environments".into())
        })?;

    let active_environments: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM environments
           WHERE state NOT IN ('destroyed', 'destroying', 'error', 'stopped', 'archived')"#,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "admin: count active environments failed");
        AppError::InternalMsg("failed to count active environments".into())
    })?;

    let now = Utc::now();
    let month_start = Utc
        .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .ok_or_else(|| AppError::InternalMsg("failed to compute month start".into()))?;

    let row = sqlx::query(
        r#"SELECT
             COALESCE(SUM((metadata->>'elapsed_seconds')::float / 3600.0 * (metadata->>'cpu_millicores')::float / 1000.0), 0),
             COALESCE(SUM((metadata->>'elapsed_seconds')::float / 3600.0 * (metadata->>'memory_mb')::float / 1024.0), 0),
             COALESCE(SUM(amount_cents), 0)
           FROM billing_events
           WHERE event_type = 'environment_usage' AND created_at >= $1"#,
    )
    .bind(month_start)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "admin: query monthly usage stats failed");
        AppError::InternalMsg("failed to query monthly usage stats".into())
    })?;

    Ok(AdminStatsResponse {
        total_environments,
        active_environments,
        monthly_cpu_hours: row.try_get::<f64, _>(0).map_err(AppError::from)?,
        monthly_memory_gb_hours: row.try_get::<f64, _>(1).map_err(AppError::from)?,
        monthly_cost: row.try_get::<i64, _>(2).map_err(AppError::from)?,
    })
}

/// Mirrors `api.AdminOrg`. Bare-array body (`Body []AdminOrg`), so no
/// `$schema`.
#[derive(Debug, Serialize)]
pub struct AdminOrg {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_at: String,
    pub billing_plan: String,
    pub billing_status: String,
    pub dedicated_cpu: bool,
}

/// Shared global organization query used by AdminService.
pub(crate) async fn list_admin_organizations_core(state: &ApiState) -> AppResult<Vec<AdminOrg>> {
    let rows = sqlx::query(
        r#"SELECT id, name, slug, created_at, billing_plan, billing_status, dedicated_cpu
           FROM organizations
           ORDER BY name ASC"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "admin: list organizations failed");
        AppError::InternalMsg("failed to list organizations".into())
    })?;

    let mut orgs = Vec::with_capacity(rows.len());
    for r in &rows {
        let created_at: chrono::NaiveDateTime = r.try_get("created_at").map_err(AppError::from)?;
        orgs.push(AdminOrg {
            id: r.try_get("id").map_err(AppError::from)?,
            name: r.try_get("name").map_err(AppError::from)?,
            slug: r.try_get("slug").map_err(AppError::from)?,
            created_at: format_time(created_at),
            billing_plan: r.try_get("billing_plan").map_err(AppError::from)?,
            billing_status: r.try_get("billing_status").map_err(AppError::from)?,
            dedicated_cpu: r.try_get("dedicated_cpu").map_err(AppError::from)?,
        });
    }

    Ok(orgs)
}

pub(crate) fn default_limit() -> i64 {
    50
}

const MAX_AUDIT_LOG_LIMIT: i64 = 200;
const MAX_LIFECYCLE_JOURNAL_LIMIT: i64 = 500;

fn validate_pagination(limit: i64, maximum: i64, offset: Option<i64>) -> AppResult<()> {
    if !(1..=maximum).contains(&limit) {
        return Err(AppError::BadRequest(
            format!("limit must be between 1 and {maximum}").into(),
        ));
    }
    if offset.is_some_and(|offset| offset < 0) {
        return Err(AppError::BadRequest(
            "offset must be greater than or equal to zero".into(),
        ));
    }
    Ok(())
}

/// Filters for listing audit logs. The core enforces the documented limit
/// and non-negative offset before issuing SQL.
#[derive(Debug)]
pub struct ListAuditLogsParams {
    pub limit: i64,
    pub offset: i64,
    pub action: Option<String>,
    pub severity: Option<String>,
}

/// Mirrors `api.AuditLogEntry`. `user_id`/`user_email`/`ip_address`/
/// `user_agent` are Go `*string` → serialize as `null` when absent;
/// `metadata` is `any` with `omitempty` → dropped when the JSONB column
/// is NULL. Bare-array body (no `$schema`).
#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub severity: String,
}

/// Shared audit-log query used by AdminService.
pub(crate) async fn list_audit_logs_core(
    state: &ApiState,
    params: ListAuditLogsParams,
) -> AppResult<Vec<AuditLogEntry>> {
    validate_pagination(params.limit, MAX_AUDIT_LOG_LIMIT, Some(params.offset))?;

    // Empty query strings mean "no filter" on the Go side (`!= ""`), so
    // map them to NULL alongside absent params.
    let action = params.action.filter(|s| !s.is_empty());
    let severity = params.severity.filter(|s| !s.is_empty());

    let rows = sqlx::query(
        r#"SELECT a.id, a.timestamp, a.action, a.user_id, u.email,
                  a.ip_address, a.user_agent, a.metadata, a.severity
           FROM audit_logs a
           LEFT JOIN users u ON u.id = a.user_id
           WHERE ($1::text IS NULL OR a.action = $1)
             AND ($2::text IS NULL OR a.severity = $2)
           ORDER BY a.timestamp DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(&action)
    .bind(&severity)
    .bind(params.limit)
    .bind(params.offset)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "admin: query audit logs failed");
        AppError::InternalMsg("failed to query audit logs".into())
    })?;

    let mut entries = Vec::with_capacity(rows.len());
    for r in &rows {
        let ts: chrono::NaiveDateTime = r.try_get("timestamp").map_err(AppError::from)?;
        entries.push(AuditLogEntry {
            id: r.try_get("id").map_err(AppError::from)?,
            timestamp: format_time(ts),
            action: r.try_get("action").map_err(AppError::from)?,
            user_id: r.try_get("user_id").map_err(AppError::from)?,
            user_email: r.try_get("email").map_err(AppError::from)?,
            ip_address: r.try_get("ip_address").map_err(AppError::from)?,
            user_agent: r.try_get("user_agent").map_err(AppError::from)?,
            metadata: r.try_get("metadata").map_err(AppError::from)?,
            severity: r.try_get("severity").map_err(AppError::from)?,
        });
    }

    Ok(entries)
}

pub(crate) fn default_journal_limit() -> i64 {
    100
}

pub(crate) fn default_startup_window_minutes() -> i32 {
    240
}

/// Mirrors `api.AdminEnvironmentLifecycleJournalEntry`. The nullable text
/// columns are `COALESCE`d to `''` and serialized with `omitempty`
/// (dropped when empty); `metadata` is the raw jsonb (Go `COALESCE(...,
/// 'null')` → `json.RawMessage`, so `null` when absent, never dropped).
/// `created_at` is a timestamptz formatted with Go's seconds-precision
/// `formatTime`. Bare-array body (no `$schema`).
#[derive(Debug, Serialize)]
pub struct AdminEnvironmentLifecycleJournalEntry {
    pub id: String,
    pub environment_id: String,
    pub kind: String,
    pub actor: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub phase: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub from_state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to_state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub checkpoint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub metadata: serde_json::Value,
    pub created_at: String,
}

/// Shared lifecycle-journal query used by AdminService.
pub(crate) async fn list_admin_environment_lifecycle_journal_core(
    state: &ApiState,
    environment_id: &str,
    limit: i64,
) -> AppResult<Vec<AdminEnvironmentLifecycleJournalEntry>> {
    validate_pagination(limit, MAX_LIFECYCLE_JOURNAL_LIMIT, None)?;

    let exists: bool =
        sqlx::query_scalar(r#"SELECT EXISTS(SELECT 1 FROM environments WHERE id = $1)"#)
            .bind(environment_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "admin: check environment failed");
                AppError::InternalMsg("failed to check environment".into())
            })?;
    if !exists {
        return Err(AppError::NotFound("environment not found".into()));
    }

    let rows = sqlx::query(
        r#"SELECT id, environment_id, kind, actor,
                  COALESCE(phase, '') AS phase, COALESCE(status, '') AS status,
                  COALESCE(from_state, '') AS from_state, COALESCE(to_state, '') AS to_state,
                  COALESCE(checkpoint, '') AS checkpoint, COALESCE(reason, '') AS reason,
                  metadata, created_at
           FROM environment_lifecycle_journal
           WHERE environment_id = $1
           ORDER BY created_at DESC
           LIMIT $2"#,
    )
    .bind(environment_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "admin: query lifecycle journal failed");
        AppError::InternalMsg("failed to query lifecycle journal".into())
    })?;

    let mut entries = Vec::with_capacity(rows.len());
    for r in &rows {
        let created_at: chrono::DateTime<chrono::Utc> =
            r.try_get("created_at").map_err(AppError::from)?;
        let metadata: Option<serde_json::Value> = r.try_get("metadata").map_err(AppError::from)?;
        entries.push(AdminEnvironmentLifecycleJournalEntry {
            id: r.try_get("id").map_err(AppError::from)?,
            environment_id: r.try_get("environment_id").map_err(AppError::from)?,
            kind: r.try_get("kind").map_err(AppError::from)?,
            actor: r.try_get("actor").map_err(AppError::from)?,
            phase: r.try_get("phase").map_err(AppError::from)?,
            status: r.try_get("status").map_err(AppError::from)?,
            from_state: r.try_get("from_state").map_err(AppError::from)?,
            to_state: r.try_get("to_state").map_err(AppError::from)?,
            checkpoint: r.try_get("checkpoint").map_err(AppError::from)?,
            reason: r.try_get("reason").map_err(AppError::from)?,
            metadata: metadata.unwrap_or(serde_json::Value::Null),
            created_at: format_time(created_at.naive_utc()),
        });
    }

    Ok(entries)
}

#[derive(Debug, Serialize)]
pub struct AdminEnvironmentStartupPhaseSummary {
    pub phase: String,
    pub sample_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AdminEnvironmentStartupSummary {
    pub generated_at: String,
    pub window_minutes: i32,
    pub starting_backlog_count: i32,
    pub starting_backlog_over_5m_count: i32,
    pub starting_backlog_over_10m_count: i32,
    pub running_without_access_ready_count: i32,
    pub phase_durations: Vec<AdminEnvironmentStartupPhaseSummary>,
}

/// Summarized startup phases, in presentation order. Every stage that
/// `start_metrics` observes is listed, so the admin summary and Prometheus
/// describe the same stages.
const STARTUP_PHASES: [&str; 15] = [
    "create_claim",
    "wait_for_ready",
    "workspace_bind",
    "access_ready",
    "pod_created",
    "pod_volume_provisioned",
    "pod_volume_bound",
    "pod_scheduled",
    "pod_sandbox_ready",
    "pod_initialized",
    "pod_workspace_started",
    "pod_dind_started",
    "pod_running",
    "pod_containers_ready",
    "file_ready",
];

/// Environment states that still owe a start while `desired_state` is
/// `started`.
const STARTING_BACKLOG_STATES: [&str; 6] = [
    "pending",
    "pending_build",
    "building",
    "pulling_snapshot",
    "creating",
    "starting",
];

/// Transitions that begin a new runtime incarnation. A running environment's
/// access readiness counts only when recorded at or after the latest one.
const INCARNATION_START_STATES: [&str; 2] = ["creating", "starting"];

fn round_f64_to_i64(v: f64) -> i64 {
    v.round() as i64
}

fn extract_duration_ms(metadata: &serde_json::Value) -> Option<i64> {
    let value = metadata.get("duration_ms")?;
    if let Some(n) = value.as_i64() {
        return Some(n);
    }
    value.as_f64().map(|n| n as i64)
}

/// Shared startup-summary query used by AdminService.
pub(crate) async fn get_admin_environment_startup_summary_core(
    state: &ApiState,
    window_minutes: i32,
) -> AppResult<AdminEnvironmentStartupSummary> {
    startup_summary(&state.pool, window_minutes).await
}

/// `running_without_access_ready_count` counts running environments whose
/// current incarnation has no completed `access_ready`. Create and restart
/// both record it, so a completed row from an earlier incarnation no longer
/// hides a start whose access never became ready. An environment with no
/// recorded incarnation transition falls back to any completed row.
async fn startup_summary(
    pool: &sqlx::PgPool,
    window_minutes: i32,
) -> AppResult<AdminEnvironmentStartupSummary> {
    let row = sqlx::query(
        r#"SELECT
             COUNT(*) FILTER (
               WHERE desired_state = 'started'
                 AND state = ANY($1)
             )::int AS starting_backlog_count,
             COUNT(*) FILTER (
               WHERE desired_state = 'started'
                 AND state = ANY($1)
                 AND created_at <= NOW() - INTERVAL '5 minutes'
             )::int AS starting_backlog_over_5m_count,
             COUNT(*) FILTER (
               WHERE desired_state = 'started'
                 AND state = ANY($1)
                 AND created_at <= NOW() - INTERVAL '10 minutes'
             )::int AS starting_backlog_over_10m_count,
             COUNT(*) FILTER (
               WHERE desired_state = 'started'
                 AND state = 'running'
                 AND NOT EXISTS (
                   SELECT 1
                     FROM environment_logs l
                    WHERE l.environment_id = environments.id
                      AND l.phase = 'access_ready'
                      AND l.status = 'completed'
                      AND l.created_at >= COALESCE((
                        SELECT MAX(j.created_at)
                          FROM environment_lifecycle_journal j
                         WHERE j.environment_id = environments.id
                           AND j.kind = 'transition'
                           AND j.to_state = ANY($2)
                      ), '-infinity'::timestamptz)
                 )
             )::int AS running_without_access_ready_count
           FROM environments"#,
    )
    .bind(&STARTING_BACKLOG_STATES[..])
    .bind(&INCARNATION_START_STATES[..])
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "admin: query startup backlog summary failed");
        AppError::InternalMsg("failed to query startup backlog summary".into())
    })?;

    let mut phase_summaries = STARTUP_PHASES
        .iter()
        .map(|phase| {
            (
                (*phase).to_string(),
                AdminEnvironmentStartupPhaseSummary {
                    phase: (*phase).to_string(),
                    sample_count: 0,
                    p50_ms: None,
                    p95_ms: None,
                },
            )
        })
        .collect::<std::collections::HashMap<_, _>>();

    let rows = sqlx::query(
        r#"WITH phase_samples AS (
             SELECT phase, (metadata->>'duration_ms')::double precision AS duration_ms
               FROM environment_logs
              WHERE created_at >= NOW() - make_interval(mins => $1::int)
                AND phase = ANY($2)
                AND status = 'completed'
                AND metadata ? 'duration_ms'
           )
           SELECT phase,
                  COUNT(*)::int AS sample_count,
                  percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms) AS p50_ms,
                  percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95_ms
             FROM phase_samples
            GROUP BY phase"#,
    )
    .bind(window_minutes)
    .bind(&STARTUP_PHASES[..])
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "admin: query startup duration summary failed");
        AppError::InternalMsg("failed to query startup duration summary".into())
    })?;

    for r in &rows {
        let phase: String = r.try_get("phase").map_err(AppError::from)?;
        let p50_ms: Option<f64> = r.try_get("p50_ms").map_err(AppError::from)?;
        let p95_ms: Option<f64> = r.try_get("p95_ms").map_err(AppError::from)?;
        phase_summaries.insert(
            phase.clone(),
            AdminEnvironmentStartupPhaseSummary {
                phase,
                sample_count: r.try_get("sample_count").map_err(AppError::from)?,
                p50_ms: p50_ms.map(round_f64_to_i64),
                p95_ms: p95_ms.map(round_f64_to_i64),
            },
        );
    }

    let phase_durations = STARTUP_PHASES
        .iter()
        .filter_map(|phase| phase_summaries.remove(*phase))
        .collect();

    Ok(AdminEnvironmentStartupSummary {
        generated_at: format_time(Utc::now().naive_utc()),
        window_minutes,
        starting_backlog_count: row
            .try_get("starting_backlog_count")
            .map_err(AppError::from)?,
        starting_backlog_over_5m_count: row
            .try_get("starting_backlog_over_5m_count")
            .map_err(AppError::from)?,
        starting_backlog_over_10m_count: row
            .try_get("starting_backlog_over_10m_count")
            .map_err(AppError::from)?,
        running_without_access_ready_count: row
            .try_get("running_without_access_ready_count")
            .map_err(AppError::from)?,
        phase_durations,
    })
}

#[derive(Debug, Serialize)]
pub struct AdminEnvironmentStartupTiming {
    pub phase: String,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
    pub metadata: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct AdminEnvironmentStartupTimings {
    pub environment_id: String,
    pub created_at: String,
    pub timings: Vec<AdminEnvironmentStartupTiming>,
}

/// Shared startup-timing query used by AdminService.
pub(crate) async fn get_admin_environment_startup_timings_core(
    state: &ApiState,
    environment_id: &str,
) -> AppResult<AdminEnvironmentStartupTimings> {
    startup_timings(&state.pool, environment_id).await
}

async fn startup_timings(
    pool: &sqlx::PgPool,
    environment_id: &str,
) -> AppResult<AdminEnvironmentStartupTimings> {
    let created_at: chrono::NaiveDateTime =
        sqlx::query_scalar(r#"SELECT created_at FROM environments WHERE id = $1"#)
            .bind(environment_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "admin: load environment failed");
                AppError::InternalMsg("failed to load environment".into())
            })?
            .ok_or_else(|| AppError::NotFound("environment not found".into()))?;

    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (phase)
                  phase, status, COALESCE(message, '') AS message, metadata, created_at
           FROM environment_logs
           WHERE environment_id = $1
             AND phase = ANY($2)
           ORDER BY phase, created_at DESC"#,
    )
    .bind(environment_id)
    .bind(&STARTUP_PHASES[..])
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "admin: query startup timings failed");
        AppError::InternalMsg("failed to query startup timings".into())
    })?;

    let mut timings_by_phase: std::collections::HashMap<String, AdminEnvironmentStartupTiming> =
        std::collections::HashMap::with_capacity(STARTUP_PHASES.len());
    for r in &rows {
        let phase: String = r.try_get("phase").map_err(AppError::from)?;
        let phase_created_at: chrono::DateTime<Utc> =
            r.try_get("created_at").map_err(AppError::from)?;
        let metadata: Option<serde_json::Value> = r.try_get("metadata").map_err(AppError::from)?;
        let metadata = metadata.unwrap_or(serde_json::Value::Null);
        let duration_ms = extract_duration_ms(&metadata);
        timings_by_phase.insert(
            phase.clone(),
            AdminEnvironmentStartupTiming {
                phase,
                status: r.try_get("status").map_err(AppError::from)?,
                message: r.try_get("message").map_err(AppError::from)?,
                duration_ms,
                metadata,
                created_at: format_time(phase_created_at.naive_utc()),
            },
        );
    }

    let timings = STARTUP_PHASES
        .iter()
        .filter_map(|phase| timings_by_phase.remove(*phase))
        .collect();

    Ok(AdminEnvironmentStartupTimings {
        environment_id: environment_id.to_owned(),
        created_at: format_time(created_at),
        timings,
    })
}

/// One organization's environment limits, as `environment_quotas` stores them.
/// Each is -1 for unlimited or a positive value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AdminEnvironmentQuota {
    pub max_concurrent_environments: i32,
    pub max_concurrent_sandbox: i32,
    pub max_cpu_millicores: i32,
    pub max_memory_mb: i32,
}

impl From<OrgQuota> for AdminEnvironmentQuota {
    fn from(quota: OrgQuota) -> Self {
        Self {
            max_concurrent_environments: quota.max_concurrent_environments,
            max_concurrent_sandbox: quota.max_concurrent_sandbox,
            max_cpu_millicores: quota.max_cpu_millicores,
            max_memory_mb: quota.max_memory_mb,
        }
    }
}

/// One organization's explicit quota, when it has one, and the quota creates
/// are checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOrganizationEnvironmentQuota {
    pub organization_id: String,
    pub explicit: Option<AdminEnvironmentQuota>,
    pub effective: AdminEnvironmentQuota,
}

/// Refuses a limit that is neither -1 (unlimited) nor positive: zero would
/// silently fall back to a default, and other negatives mean nothing.
pub(crate) fn validate_environment_quota(quota: &AdminEnvironmentQuota) -> AppResult<()> {
    let fields = [
        (
            quota.max_concurrent_environments,
            "/quota/max_concurrent_environments",
        ),
        (
            quota.max_concurrent_sandbox,
            "/quota/max_concurrent_sandbox",
        ),
        (quota.max_cpu_millicores, "/quota/max_cpu_millicores"),
        (quota.max_memory_mb, "/quota/max_memory_mb"),
    ];
    let errors: Vec<_> = fields
        .into_iter()
        .filter(|(value, _)| *value != -1 && *value <= 0)
        .map(|(_, path)| ValidationIssue {
            path: Cow::Borrowed(path),
            message: Cow::Borrowed("must be -1 (unlimited) or positive"),
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation { errors })
    }
}

fn quota_failure(action: &'static str, error: sqlx::Error) -> AppError {
    tracing::error!(error = %error, action, "admin: environment quota query failed");
    AppError::InternalMsg(format!("failed to {action}").into())
}

async fn explicit_environment_quota<'e, E>(
    executor: E,
    organization_id: &str,
    lock: bool,
) -> Result<Option<AdminEnvironmentQuota>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let query = if lock {
        r#"SELECT max_concurrent_environments, max_concurrent_sandbox,
                  max_cpu_millicores, max_memory_mb
           FROM environment_quotas WHERE org_id = $1 FOR UPDATE"#
    } else {
        r#"SELECT max_concurrent_environments, max_concurrent_sandbox,
                  max_cpu_millicores, max_memory_mb
           FROM environment_quotas WHERE org_id = $1"#
    };
    let row: Option<(i32, i32, i32, i32)> = sqlx::query_as(query)
        .bind(organization_id)
        .fetch_optional(executor)
        .await?;
    Ok(row.map(
        |(environments, sandbox, cpu, memory)| AdminEnvironmentQuota {
            max_concurrent_environments: environments,
            max_concurrent_sandbox: sandbox,
            max_cpu_millicores: cpu,
            max_memory_mb: memory,
        },
    ))
}

/// Locks the organization row, so concurrent quota writes for one
/// organization apply one at a time, and refuses an unknown organization.
async fn lock_organization(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
) -> AppResult<()> {
    sqlx::query_scalar::<_, String>("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| quota_failure("read organization", error))?
        .map(|_| ())
        .ok_or_else(|| AppError::NotFound("organization not found".into()))
}

async fn audit_quota_change(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    action: &str,
    actor_user_id: &str,
    metadata: serde_json::Value,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), $1, $2, $3, 'warn')"#,
    )
    .bind(action)
    .bind(actor_user_id)
    .bind(metadata)
    .execute(&mut **transaction)
    .await
    .map_err(|error| quota_failure("record environment quota audit", error))?;
    Ok(())
}

/// Sets whether an organization's new sandboxes reserve a CPU per vCPU, and
/// records a change in the audit log, in one transaction. Setting the value it
/// already has changes nothing. Returns the previous value. A sandbox it already
/// runs keeps its reservation until it is replaced (#3635).
pub(crate) async fn set_organization_dedicated_cpu_core(
    pool: &sqlx::PgPool,
    actor_user_id: &str,
    organization_id: &str,
    dedicated_cpu: bool,
) -> AppResult<bool> {
    let failure = |action: &'static str| {
        move |error| {
            tracing::error!(error = %error, action, "admin: organization dedicated CPU");
            AppError::InternalMsg("failed to update the organization's dedicated CPU".into())
        }
    };
    let mut transaction = pool.begin().await.map_err(failure("start the update"))?;
    let previous: Option<bool> =
        sqlx::query_scalar("SELECT dedicated_cpu FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(organization_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(failure("read the organization"))?;
    let previous = previous.ok_or_else(|| AppError::NotFound("organization not found".into()))?;
    if previous == dedicated_cpu {
        return Ok(previous);
    }
    sqlx::query("UPDATE organizations SET dedicated_cpu = $2, updated_at = NOW() WHERE id = $1")
        .bind(organization_id)
        .bind(dedicated_cpu)
        .execute(&mut *transaction)
        .await
        .map_err(failure("update the organization"))?;
    sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity)
           VALUES (gen_random_uuid()::text, NOW(), 'admin.organization.dedicated_cpu_set', $1, $2, 'warn')"#,
    )
    .bind(actor_user_id)
    .bind(serde_json::json!({
        "organization_id": organization_id,
        "previous": previous,
        "dedicated_cpu": dedicated_cpu,
    }))
    .execute(&mut *transaction)
    .await
    .map_err(failure("record the audit entry"))?;
    transaction
        .commit()
        .await
        .map_err(failure("commit the update"))?;
    Ok(previous)
}

/// Shared quota read used by AdminService.
pub(crate) async fn get_organization_environment_quota_core(
    pool: &sqlx::PgPool,
    organization_id: &str,
) -> AppResult<AdminOrganizationEnvironmentQuota> {
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1")
        .bind(organization_id)
        .fetch_optional(pool)
        .await
        .map_err(|error| quota_failure("read organization", error))?;
    if exists.is_none() {
        return Err(AppError::NotFound("organization not found".into()));
    }
    let explicit = explicit_environment_quota(pool, organization_id, false)
        .await
        .map_err(|error| quota_failure("read environment quota", error))?;
    let effective = get_org_quota(pool, organization_id)
        .await
        .map_err(|error| quota_failure("read effective environment quota", error))?
        .into();
    Ok(AdminOrganizationEnvironmentQuota {
        organization_id: organization_id.to_owned(),
        explicit,
        effective,
    })
}

/// Creates or replaces one organization's explicit quota and records the
/// previous and new values in the audit log, in one transaction.
pub(crate) async fn set_organization_environment_quota_core(
    pool: &sqlx::PgPool,
    actor_user_id: &str,
    organization_id: &str,
    quota: AdminEnvironmentQuota,
) -> AppResult<AdminEnvironmentQuota> {
    validate_environment_quota(&quota)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| quota_failure("start environment quota update", error))?;
    lock_organization(&mut transaction, organization_id).await?;
    let previous = explicit_environment_quota(&mut *transaction, organization_id, true)
        .await
        .map_err(|error| quota_failure("read environment quota", error))?;
    sqlx::query(
        r#"INSERT INTO environment_quotas
               (org_id, max_concurrent_environments, max_concurrent_sandbox,
                max_cpu_millicores, max_memory_mb)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (org_id) DO UPDATE SET
               max_concurrent_environments = EXCLUDED.max_concurrent_environments,
               max_concurrent_sandbox = EXCLUDED.max_concurrent_sandbox,
               max_cpu_millicores = EXCLUDED.max_cpu_millicores,
               max_memory_mb = EXCLUDED.max_memory_mb"#,
    )
    .bind(organization_id)
    .bind(quota.max_concurrent_environments)
    .bind(quota.max_concurrent_sandbox)
    .bind(quota.max_cpu_millicores)
    .bind(quota.max_memory_mb)
    .execute(&mut *transaction)
    .await
    .map_err(|error| quota_failure("update environment quota", error))?;
    audit_quota_change(
        &mut transaction,
        "admin.organization.environment_quota_set",
        actor_user_id,
        serde_json::json!({
            "organization_id": organization_id,
            "previous": previous,
            "quota": quota,
        }),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| quota_failure("commit environment quota update", error))?;
    Ok(quota)
}

/// Removes one organization's explicit quota, so the defaults apply
/// again. Returns whether one existed; only a removal is audited.
pub(crate) async fn clear_organization_environment_quota_core(
    pool: &sqlx::PgPool,
    actor_user_id: &str,
    organization_id: &str,
) -> AppResult<bool> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| quota_failure("start environment quota clear", error))?;
    lock_organization(&mut transaction, organization_id).await?;
    let previous: Option<(i32, i32, i32, i32)> = sqlx::query_as(
        r#"DELETE FROM environment_quotas WHERE org_id = $1
           RETURNING max_concurrent_environments, max_concurrent_sandbox,
                     max_cpu_millicores, max_memory_mb"#,
    )
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| quota_failure("clear environment quota", error))?;
    let Some((environments, sandbox, cpu, memory)) = previous else {
        transaction
            .rollback()
            .await
            .map_err(|error| quota_failure("end environment quota clear", error))?;
        return Ok(false);
    };
    audit_quota_change(
        &mut transaction,
        "admin.organization.environment_quota_clear",
        actor_user_id,
        serde_json::json!({
            "organization_id": organization_id,
            "previous": AdminEnvironmentQuota {
                max_concurrent_environments: environments,
                max_concurrent_sandbox: sandbox,
                max_cpu_millicores: cpu,
                max_memory_mb: memory,
            },
        }),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| quota_failure("commit environment quota clear", error))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn admin_stats_serializes_whole_floats_like_go() {
        let value = serde_json::to_value(AdminStatsResponse {
            total_environments: 3,
            active_environments: 2,
            monthly_cpu_hours: 2.0,
            monthly_memory_gb_hours: 4.5,
            monthly_cost: 0,
        })
        .expect("serialize stats");

        assert_eq!(value["monthly_cpu_hours"], json!(2));
        assert_eq!(value["monthly_memory_gb_hours"], json!(4.5));
    }

    #[test]
    fn startup_phases_summarize_every_measured_start_stage_once() {
        let mut unique = STARTUP_PHASES.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), STARTUP_PHASES.len());
        for stage in crate::start_metrics::StartStage::ALL {
            assert!(
                STARTUP_PHASES.contains(&stage.as_str()),
                "{} is observed but not summarized",
                stage.as_str()
            );
        }
        for phase in STARTUP_PHASES {
            assert_ne!(
                crate::worker::env_log::env_phase_label(phase),
                phase,
                "{phase} needs a label"
            );
        }
    }

    #[test]
    fn duration_ms_extraction_matches_go_truncation() {
        assert_eq!(extract_duration_ms(&json!({"duration_ms": 42})), Some(42));
        assert_eq!(extract_duration_ms(&json!({"duration_ms": 42.9})), Some(42));
        assert_eq!(extract_duration_ms(&json!({"duration_ms": "42"})), None);
        assert_eq!(extract_duration_ms(&json!({})), None);
    }

    #[test]
    fn startup_timing_omits_empty_optional_fields() {
        let value = serde_json::to_value(AdminEnvironmentStartupTiming {
            phase: "create_claim".into(),
            status: "completed".into(),
            message: String::new(),
            duration_ms: None,
            metadata: serde_json::Value::Null,
            created_at: "2026-06-25T12:00:00Z".into(),
        })
        .expect("serialize timing");

        assert!(value.get("message").is_none());
        assert!(value.get("duration_ms").is_none());
        assert_eq!(value["metadata"], serde_json::Value::Null);
    }

    #[test]
    fn audit_pagination_enforces_documented_bounds() {
        validate_pagination(1, MAX_AUDIT_LOG_LIMIT, Some(0)).unwrap();
        validate_pagination(MAX_AUDIT_LOG_LIMIT, MAX_AUDIT_LOG_LIMIT, Some(i64::MAX)).unwrap();

        for (limit, offset, expected) in [
            (0, Some(0), "limit must be between 1 and 200"),
            (201, Some(0), "limit must be between 1 and 200"),
            (50, Some(-1), "offset must be greater than or equal to zero"),
        ] {
            let Err(AppError::BadRequest(detail)) =
                validate_pagination(limit, MAX_AUDIT_LOG_LIMIT, offset)
            else {
                panic!("expected an audit pagination error");
            };
            assert_eq!(detail, expected);
        }
    }

    #[test]
    fn lifecycle_journal_pagination_enforces_documented_bounds() {
        validate_pagination(1, MAX_LIFECYCLE_JOURNAL_LIMIT, None).unwrap();
        validate_pagination(
            MAX_LIFECYCLE_JOURNAL_LIMIT,
            MAX_LIFECYCLE_JOURNAL_LIMIT,
            None,
        )
        .unwrap();

        for limit in [0, 501] {
            let Err(AppError::BadRequest(detail)) =
                validate_pagination(limit, MAX_LIFECYCLE_JOURNAL_LIMIT, None)
            else {
                panic!("expected a lifecycle-journal pagination error");
            };
            assert_eq!(detail, "limit must be between 1 and 500");
        }
    }
}

/// One member of an organization, for the admin overview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOrganizationMember {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub joined_at: Option<chrono::NaiveDateTime>,
}

/// A live (active, trialing or past_due) subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOrganizationSubscription {
    /// "environment" or "organization".
    pub kind: &'static str,
    pub plan: String,
    pub status: String,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOrganizationBilling {
    pub billing_plan: String,
    pub billing_status: String,
    pub billing_exempt: bool,
    pub effective_plan: String,
    pub subscriptions: Vec<AdminOrganizationSubscription>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminOrganizationUsage {
    pub active_environments: i64,
    pub active_sandboxes: i64,
    pub cpu_millicores: i64,
    pub memory_mb: i64,
}

/// An API key's name and dates. Key hashes and prefixes are never read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOrganizationApiKey {
    pub name: String,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub last_used_at: Option<chrono::NaiveDateTime>,
    pub disabled: bool,
    pub expires_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOrganizationOverview {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub dedicated_cpu: bool,
    pub members: Vec<AdminOrganizationMember>,
    pub billing: AdminOrganizationBilling,
    /// The rate card, credit balance and newest ledger entries (#3381).
    pub credit: credit::AdminOrganizationCredit,
    pub quota: AdminOrganizationEnvironmentQuota,
    pub usage: AdminOrganizationUsage,
    pub api_keys: Vec<AdminOrganizationApiKey>,
}

/// Shared organization overview read used by AdminService.
pub(crate) async fn get_organization_overview_core(
    pool: &sqlx::PgPool,
    organization_id: &str,
) -> AppResult<AdminOrganizationOverview> {
    let failure = |action: &'static str| move |error| quota_failure(action, error);
    type OrganizationRow = (
        String,
        String,
        String,
        Option<chrono::NaiveDateTime>,
        String,
        String,
        bool,
        bool,
    );
    let organization: Option<OrganizationRow> = sqlx::query_as(
        r#"SELECT id, name, slug, created_at, billing_plan, billing_status, billing_exempt,
                  dedicated_cpu
           FROM organizations WHERE id = $1"#,
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .map_err(failure("read organization"))?;
    let Some((
        id,
        name,
        slug,
        created_at,
        billing_plan,
        billing_status,
        billing_exempt,
        dedicated_cpu,
    )) = organization
    else {
        return Err(AppError::NotFound("organization not found".into()));
    };

    let members = sqlx::query_as::<_, (String, String, String, Option<chrono::NaiveDateTime>)>(
        r#"SELECT m.user_id, COALESCE(u.email, ''), m.role, m.created_at
           FROM org_members m LEFT JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1
           ORDER BY m.created_at, m.user_id"#,
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await
    .map_err(failure("read organization members"))?
    .into_iter()
    .map(
        |(user_id, email, role, joined_at)| AdminOrganizationMember {
            user_id,
            email,
            role,
            joined_at,
        },
    )
    .collect();

    let subscriptions =
        sqlx::query_as::<_, (String, String, String, Option<chrono::NaiveDateTime>)>(
            r#"SELECT 'environment', plan, status, updated_at FROM environment_subscriptions
             WHERE org_id = $1 AND status IN ('active', 'trialing', 'past_due')
           UNION ALL
           SELECT 'organization', plan, status, updated_at FROM org_subscriptions
             WHERE org_id = $1 AND status IN ('active', 'trialing', 'past_due')
           ORDER BY 4 DESC NULLS LAST"#,
        )
        .bind(organization_id)
        .fetch_all(pool)
        .await
        .map_err(failure("read organization subscriptions"))?
        .into_iter()
        .map(
            |(kind, plan, status, updated_at)| AdminOrganizationSubscription {
                kind: if kind == "environment" {
                    "environment"
                } else {
                    "organization"
                },
                plan,
                status,
                updated_at,
            },
        )
        .collect();

    let usage = count_active_environments(pool, organization_id)
        .await
        .map_err(failure("count active environments"))?;

    let api_keys = sqlx::query_as::<
        _,
        (
            String,
            Option<chrono::NaiveDateTime>,
            Option<chrono::NaiveDateTime>,
            bool,
            Option<chrono::NaiveDateTime>,
        ),
    >(
        r#"SELECT name, created_at, last_used_at, disabled_at IS NOT NULL, expires_at
           FROM api_keys WHERE org_id = $1
           ORDER BY created_at DESC NULLS LAST, name"#,
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await
    .map_err(failure("read organization API keys"))?
    .into_iter()
    .map(
        |(name, created_at, last_used_at, disabled, expires_at)| AdminOrganizationApiKey {
            name,
            created_at,
            last_used_at,
            disabled,
            expires_at,
        },
    )
    .collect();

    Ok(AdminOrganizationOverview {
        id,
        name,
        slug,
        created_at,
        dedicated_cpu,
        members,
        billing: AdminOrganizationBilling {
            billing_plan,
            billing_status,
            billing_exempt,
            effective_plan: resolve_effective_plan(pool, organization_id).await,
            subscriptions,
        },
        credit: credit::organization_credit(pool, organization_id).await?,
        quota: get_organization_environment_quota_core(pool, organization_id).await?,
        usage: AdminOrganizationUsage {
            active_environments: usage.active_total,
            active_sandboxes: usage.active_sandbox,
            cpu_millicores: usage.total_cpu,
            memory_mb: usage.total_memory_mb,
        },
        api_keys,
    })
}

/// The defaults for organizations without their own quota, and whether they
/// are stored or the built-in fallback.
pub(crate) async fn get_default_environment_quota_core(
    pool: &sqlx::PgPool,
) -> AppResult<(AdminEnvironmentQuota, bool)> {
    let stored = stored_default_environment_quota(pool, false)
        .await
        .map_err(|error| quota_failure("read environment quota defaults", error))?;
    Ok(match stored {
        Some(quota) => (quota, true),
        None => (FALLBACK_QUOTA_DEFAULTS.into(), false),
    })
}

async fn stored_default_environment_quota<'e, E>(
    executor: E,
    lock: bool,
) -> Result<Option<AdminEnvironmentQuota>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let query = if lock {
        r#"SELECT max_concurrent_environments, max_concurrent_sandbox,
                  max_cpu_millicores, max_memory_mb
           FROM environment_quota_defaults WHERE singleton FOR UPDATE"#
    } else {
        r#"SELECT max_concurrent_environments, max_concurrent_sandbox,
                  max_cpu_millicores, max_memory_mb
           FROM environment_quota_defaults WHERE singleton"#
    };
    let row: Option<(i32, i32, i32, i32)> = sqlx::query_as(query).fetch_optional(executor).await?;
    Ok(row.map(
        |(environments, sandbox, cpu, memory)| AdminEnvironmentQuota {
            max_concurrent_environments: environments,
            max_concurrent_sandbox: sandbox,
            max_cpu_millicores: cpu,
            max_memory_mb: memory,
        },
    ))
}

/// Replaces the defaults for organizations without their own quota and
/// records the previous and new values in the audit log, in one transaction.
pub(crate) async fn set_default_environment_quota_core(
    pool: &sqlx::PgPool,
    actor_user_id: &str,
    quota: AdminEnvironmentQuota,
) -> AppResult<AdminEnvironmentQuota> {
    validate_environment_quota(&quota)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| quota_failure("start environment quota defaults update", error))?;
    let previous = stored_default_environment_quota(&mut *transaction, true)
        .await
        .map_err(|error| quota_failure("read environment quota defaults", error))?
        .unwrap_or_else(|| FALLBACK_QUOTA_DEFAULTS.into());
    sqlx::query(
        r#"INSERT INTO environment_quota_defaults
               (singleton, max_concurrent_environments, max_concurrent_sandbox,
                max_cpu_millicores, max_memory_mb, updated_at)
           VALUES (true, $1, $2, $3, $4, NOW())
           ON CONFLICT (singleton) DO UPDATE SET
               max_concurrent_environments = EXCLUDED.max_concurrent_environments,
               max_concurrent_sandbox = EXCLUDED.max_concurrent_sandbox,
               max_cpu_millicores = EXCLUDED.max_cpu_millicores,
               max_memory_mb = EXCLUDED.max_memory_mb,
               updated_at = EXCLUDED.updated_at"#,
    )
    .bind(quota.max_concurrent_environments)
    .bind(quota.max_concurrent_sandbox)
    .bind(quota.max_cpu_millicores)
    .bind(quota.max_memory_mb)
    .execute(&mut *transaction)
    .await
    .map_err(|error| quota_failure("update environment quota defaults", error))?;
    audit_quota_change(
        &mut transaction,
        "admin.environment_quota_defaults_set",
        actor_user_id,
        serde_json::json!({ "previous": previous, "quota": quota }),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| quota_failure("commit environment quota defaults update", error))?;
    Ok(quota)
}
