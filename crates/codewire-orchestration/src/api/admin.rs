//! Admin read surface (#38), mounted at `/api/v1/admin`. These are
//! `is_admin`-gated reads, so the
//! router layers [`require_admin`](codewire_server_core::auth::require_admin)
//! on top of `require_auth`, mirroring the Go `adminSecurity`.
//!
//! `getAdminStats`, `listAdminOrganizations`, `listAuditLogs`,
//! lifecycle journal, and environment startup timing/summary port here.

use axum::Json;
use axum::extract::{Query, State};
use chrono::{Datelike, TimeZone, Utc};
use codewire_server_core::AppError;
use codewire_server_core::AppResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, Serializer};
use sqlx::Row;

use super::ApiState;
use super::environments::format_time;

/// Mirrors `api.AdminStatsResponse`.
#[derive(Debug, Serialize, JsonSchema)]
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

/// `GET /api/v1/admin/stats` — mirrors `getAdminStats`. Admin-only;
/// dashboard overview cards consume this live, so it cannot remain on
/// the Go fallback for Rust-only closeout.
pub async fn get_admin_stats(State(state): State<ApiState>) -> AppResult<Json<AdminStatsResponse>> {
    Ok(Json(get_admin_stats_core(&state).await?))
}

/// Shared global-statistics query used by REST and AdminService.
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
#[derive(Debug, Serialize, JsonSchema)]
pub struct AdminOrg {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_at: String,
}

/// `GET /api/v1/admin/organizations` — mirrors `listAdminOrganizations`.
/// Lists every organization (admin-only) ordered by name.
pub async fn list_admin_organizations(
    State(state): State<ApiState>,
) -> AppResult<Json<Vec<AdminOrg>>> {
    Ok(Json(list_admin_organizations_core(&state).await?))
}

/// Shared global organization query used by REST and AdminService.
pub(crate) async fn list_admin_organizations_core(state: &ApiState) -> AppResult<Vec<AdminOrg>> {
    let rows = sqlx::query(
        r#"SELECT id, name, slug, created_at
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

/// Query params for `listAuditLogs`. huma `default:"50"`/`maximum:"200"`
/// on `limit`, `default:"0"` on `offset`; `action`/`severity` are
/// `omitempty` filters. The Rust handler enforces the documented limit and
/// non-negative offset before issuing SQL.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAuditLogsParams {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

/// Mirrors `api.AuditLogEntry`. `user_id`/`user_email`/`ip_address`/
/// `user_agent` are Go `*string` → serialize as `null` when absent;
/// `metadata` is `any` with `omitempty` → dropped when the JSONB column
/// is NULL. Bare-array body (no `$schema`).
#[derive(Debug, Serialize, JsonSchema)]
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

/// `GET /api/v1/admin/audit-logs` — mirrors `listAuditLogs`. Admin-only;
/// optional `action`/`severity` filters; newest first, paginated.
pub async fn list_audit_logs(
    State(state): State<ApiState>,
    Query(params): Query<ListAuditLogsParams>,
) -> AppResult<Json<Vec<AuditLogEntry>>> {
    Ok(Json(list_audit_logs_core(&state, params).await?))
}

/// Shared audit-log query used by REST and AdminService.
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

/// Query params for `listAdminEnvironmentLifecycleJournal` (huma
/// `default:"100"`/`maximum:"500"` on `limit`).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LifecycleJournalParams {
    #[serde(default = "default_journal_limit")]
    pub limit: i64,
}

/// Mirrors `api.AdminEnvironmentLifecycleJournalEntry`. The nullable text
/// columns are `COALESCE`d to `''` and serialized with `omitempty`
/// (dropped when empty); `metadata` is the raw jsonb (Go `COALESCE(...,
/// 'null')` → `json.RawMessage`, so `null` when absent, never dropped).
/// `created_at` is a timestamptz formatted with Go's seconds-precision
/// `formatTime`. Bare-array body (no `$schema`).
#[derive(Debug, Serialize, JsonSchema)]
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

/// `GET /api/v1/admin/environments/{environment_id}/lifecycle-journal` —
/// mirrors `listAdminEnvironmentLifecycleJournal`. Admin-only; `404` when
/// the environment does not exist; newest-first, limited.
pub async fn list_admin_environment_lifecycle_journal(
    State(state): State<ApiState>,
    axum::extract::Path(environment_id): axum::extract::Path<String>,
    Query(params): Query<LifecycleJournalParams>,
) -> AppResult<Json<Vec<AdminEnvironmentLifecycleJournalEntry>>> {
    Ok(Json(
        list_admin_environment_lifecycle_journal_core(&state, &environment_id, params.limit)
            .await?,
    ))
}

/// Shared lifecycle-journal query used by REST and AdminService.
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

/// Query params for `getAdminEnvironmentStartupSummary` (huma
/// `default:"240"`/`minimum:"5"`/`maximum:"10080"` on
/// `window_minutes`; Rust does not currently replicate huma validation).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartupSummaryParams {
    #[serde(default = "default_startup_window_minutes")]
    pub window_minutes: i32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AdminEnvironmentStartupPhaseSummary {
    pub phase: String,
    pub sample_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AdminEnvironmentStartupSummary {
    pub generated_at: String,
    pub window_minutes: i32,
    pub starting_backlog_count: i32,
    pub starting_backlog_over_5m_count: i32,
    pub starting_backlog_over_10m_count: i32,
    pub running_without_gateway_ready_count: i32,
    pub phase_durations: Vec<AdminEnvironmentStartupPhaseSummary>,
}

const STARTUP_PHASES: [&str; 4] = [
    "create_claim",
    "wait_for_ready",
    "gateway_ready",
    "file_ready",
];

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

/// `GET /api/v1/admin/environments/startup-summary` — mirrors
/// `getAdminEnvironmentStartupSummary`. Admin-only; returns backlog counts
/// plus recent phase duration percentiles for the startup lifecycle.
pub async fn get_admin_environment_startup_summary(
    State(state): State<ApiState>,
    Query(params): Query<StartupSummaryParams>,
) -> AppResult<Json<AdminEnvironmentStartupSummary>> {
    Ok(Json(
        get_admin_environment_startup_summary_core(&state, params.window_minutes).await?,
    ))
}

/// Shared startup-summary query used by REST and AdminService.
pub(crate) async fn get_admin_environment_startup_summary_core(
    state: &ApiState,
    window_minutes: i32,
) -> AppResult<AdminEnvironmentStartupSummary> {
    let row = sqlx::query(
        r#"SELECT
             COUNT(*) FILTER (
               WHERE desired_state = 'started'
                 AND state IN ('pending', 'pending_build', 'building', 'pulling_snapshot', 'creating', 'starting')
             )::int AS starting_backlog_count,
             COUNT(*) FILTER (
               WHERE desired_state = 'started'
                 AND state IN ('pending', 'pending_build', 'building', 'pulling_snapshot', 'creating', 'starting')
                 AND created_at <= NOW() - INTERVAL '5 minutes'
             )::int AS starting_backlog_over_5m_count,
             COUNT(*) FILTER (
               WHERE desired_state = 'started'
                 AND state IN ('pending', 'pending_build', 'building', 'pulling_snapshot', 'creating', 'starting')
                 AND created_at <= NOW() - INTERVAL '10 minutes'
             )::int AS starting_backlog_over_10m_count,
             COUNT(*) FILTER (
               WHERE desired_state = 'started'
                 AND state = 'running'
                 AND NOT EXISTS (
                   SELECT 1
                     FROM environment_logs l
                    WHERE l.environment_id = environments.id
                      AND l.phase = 'gateway_ready'
                      AND l.status = 'completed'
                 )
             )::int AS running_without_gateway_ready_count
           FROM environments"#,
    )
    .fetch_one(&state.pool)
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
                AND phase IN ('create_claim', 'wait_for_ready', 'gateway_ready', 'file_ready')
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
    .fetch_all(&state.pool)
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
        running_without_gateway_ready_count: row
            .try_get("running_without_gateway_ready_count")
            .map_err(AppError::from)?,
        phase_durations,
    })
}

#[derive(Debug, Serialize, JsonSchema)]
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

#[derive(Debug, Serialize, JsonSchema)]
pub struct AdminEnvironmentStartupTimings {
    pub environment_id: String,
    pub created_at: String,
    pub timings: Vec<AdminEnvironmentStartupTiming>,
}

/// `GET /api/v1/admin/environments/{environment_id}/startup-timings` —
/// mirrors `getAdminEnvironmentStartupTimings`. Admin-only; returns the latest
/// startup log entry per lifecycle phase in Go's fixed phase order.
pub async fn get_admin_environment_startup_timings(
    State(state): State<ApiState>,
    axum::extract::Path(environment_id): axum::extract::Path<String>,
) -> AppResult<Json<AdminEnvironmentStartupTimings>> {
    Ok(Json(
        get_admin_environment_startup_timings_core(&state, &environment_id).await?,
    ))
}

/// Shared startup-timing query used by REST and AdminService.
pub(crate) async fn get_admin_environment_startup_timings_core(
    state: &ApiState,
    environment_id: &str,
) -> AppResult<AdminEnvironmentStartupTimings> {
    let created_at: chrono::NaiveDateTime =
        sqlx::query_scalar(r#"SELECT created_at FROM environments WHERE id = $1"#)
            .bind(environment_id)
            .fetch_optional(&state.pool)
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
             AND phase IN ('create_claim', 'wait_for_ready', 'gateway_ready', 'file_ready')
           ORDER BY phase, created_at DESC"#,
    )
    .bind(environment_id)
    .fetch_all(&state.pool)
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
