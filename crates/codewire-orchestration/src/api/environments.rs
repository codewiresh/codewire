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
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row, Transaction};

use super::ApiState;
use crate::confidential_storage::require_confidential_access;

/// Mirrors `api.Environment` field-for-field (JSON tags included).
#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub id: String,
    pub org_id: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset_id: Option<String>,
    #[serde(rename = "type")]
    pub env_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: String,
    pub desired_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub error_code: Option<String>,
    pub recoverable: bool,
    pub state_changed_at: String,
    pub retry_count: i32,
    pub setup_phase: i32,
    pub setup_complete: bool,
    pub operation_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_selection: Option<super::environment_sources::EnvironmentSourceSelection>,
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
    /// `pending`, `attached`, `failed` or `revoked` when `network` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_state: Option<String>,
    /// Why joining `network` failed, with `network_state` `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_failure: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ports: Vec<EnvironmentPort>,
}

/// Mirrors `api.EnvironmentPort`.
#[derive(Debug, Clone, Serialize)]
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

/// A deletion deadline is a source value, not a seconds-rounded event label.
/// Keep RFC3339 UTC compatibility while preserving its database precision.
pub(crate) fn shutdown_deadline_string(t: Option<chrono::NaiveDateTime>) -> Option<String> {
    t.map(|deadline| deadline.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string())
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
    e.state, e.desired_state, e.error_reason, e.error_code, e.recoverable, e.state_changed_at, e.retry_count,
    e.environment_operation_generation,
    jsonb_build_object('secrets',COALESCE(e.project_spec->'secrets','{}'::jsonb),
                       'credentials',e.project_spec->'credentials') AS source_spec,
    ab.profile_id AS source_profile_id, ab.profile_revision AS source_profile_revision,
    COALESCE(b.setup_phase, 0) AS setup_phase, COALESCE(b.setup_complete, false) AS setup_complete,
    COALESCE(b.setup_error, '') AS setup_error,
    e.ttl_seconds, e.shutdown_at,
    e.cpu_millicores, e.memory_mb, e.disk_gb, e.isolation_tier,
    e.total_running_seconds,
    e.created_at, e.started_at, e.stopped_at, e.destroyed_at,
    e.protected, e.deletion_requested_at, e.deletion_grace_until,
    t.name AS preset_name,
    ma.network_id AS mesh_network_id,
    CASE WHEN ma.environment_id IS NULL THEN NULL
         WHEN ma.status = 'pending' OR ma.status_pod_uid IS DISTINCT FROM b.pod_uid THEN 'pending'
         ELSE ma.status END AS mesh_network_state,
    CASE WHEN ma.status = 'failed' AND ma.status_pod_uid IS NOT DISTINCT FROM b.pod_uid
         THEN ma.failure END AS mesh_network_failure"#;

pub(crate) const ENV_SELECT_JOINS: &str = r#"LEFT JOIN environment_presets t ON e.preset_id = t.id
    LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id
    LEFT JOIN platform_environment_access_bindings ab ON ab.environment_id = e.id
    LEFT JOIN environment_mesh_attachments ma ON ma.environment_id = e.id"#;

pub(crate) fn scan_environment(row: &PgRow) -> Result<Environment, sqlx::Error> {
    let setup_error: String = row.try_get("setup_error")?;
    // Read only canonical selections, not the ordinary environment configuration
    // or resolved values. This shares the row's MVCC statement with the profile
    // pin and operation fence so clients can submit an exact replacement CAS.
    let source_spec = row.try_get("source_spec")?;
    let profile_id: Option<String> = row.try_get("source_profile_id")?;
    let revision: Option<i64> = row.try_get("source_profile_revision")?;
    // Terminal cleanup releases the profile pin while retaining saved intent.
    // Inconsistent/missing metadata is explicitly unavailable, never an inferred
    // empty selection that a caller could use to overwrite unseen sources.
    let source_selection = source_selection_metadata(source_spec, profile_id, revision);
    let operation_generation =
        u64::try_from(row.try_get::<i64, _>("environment_operation_generation")?)
            .map_err(|_| invalid_source_metadata())?;
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
        error_code: row.try_get("error_code")?,
        recoverable: row.try_get("recoverable")?,
        state_changed_at: format_time(row.try_get("state_changed_at")?),
        retry_count: row.try_get("retry_count")?,
        setup_phase: row.try_get("setup_phase")?,
        setup_complete: row.try_get("setup_complete")?,
        operation_generation,
        source_selection,
        setup_error: if setup_error.trim().is_empty() {
            None
        } else {
            Some(setup_error)
        },
        ttl_seconds: row.try_get("ttl_seconds")?,
        shutdown_at: shutdown_deadline_string(row.try_get("shutdown_at")?),
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
        // Only the recorded attachment names a network; workload environment
        // values are never control input. A report for an earlier Pod reads
        // as pending.
        network: row.try_get("mesh_network_id")?,
        network_state: row.try_get("mesh_network_state")?,
        network_failure: row.try_get("mesh_network_failure")?,
        ports: Vec::new(),
    })
}

fn invalid_source_metadata() -> sqlx::Error {
    sqlx::Error::Decode(std::io::Error::other("invalid stored environment source metadata").into())
}

fn source_selection_metadata(
    source_spec: serde_json::Value,
    profile_id: Option<String>,
    revision: Option<i64>,
) -> Option<super::environment_sources::EnvironmentSourceSelection> {
    // The SQL projection intentionally contains only selector metadata, not a
    // whole ProjectSpec (or its required schema/work-directory fields). Decode
    // only those selected fields without reading ordinary application values.
    #[derive(Deserialize)]
    struct SourceMetadata {
        #[serde(default)]
        secrets: codewire_project::SecretBindings,
        #[serde(default)]
        credentials: Option<codewire_project::CredentialBinding>,
    }
    let selected = serde_json::from_value::<SourceMetadata>(source_spec).ok()?;
    let spec = codewire_project::ProjectSpec {
        secrets: selected.secrets,
        credentials: selected.credentials,
        ..Default::default()
    };
    let binding = match (profile_id, revision) {
        (None, None) => None,
        (Some(id), Some(revision)) => Some((id, revision)),
        _ => return None,
    };
    super::environment_sources::selection_from_spec(&spec, binding.as_ref()).ok()
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
    // Every shortcut below requires current membership. Removing a member
    // deletes only their membership row, so without this check the creator
    // shortcut and any old grant would outlive the removal (#3254).
    let Some(role) = user_org_role(pool, user, org_id).await? else {
        log_audit_event(
            pool,
            "environment.access.denied",
            &user.user_id,
            serde_json::json!({
                "environment_id": env_id, "org_id": org_id,
                "required": min_permission, "reason": "not a member",
            }),
        )
        .await;
        return Err(coded(StatusCode::FORBIDDEN, "access_denied", denied));
    };
    if created_by.as_deref() == Some(user.user_id.as_str()) || role == "owner" || role == "admin" {
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

/// Current operator fence for the additive cw-runtime journal. Existing pool
/// callers retain their behavior. The journal retains these row locks through
/// its admission/Issued commit; bearer authentication remains the transport
/// middleware's responsibility, not a claim made by this principal-only seam.
/// Lock order: enabled user, active organization, environment, membership,
/// grant. Membership is required even for the creator or a global admin.
pub(crate) async fn lock_cw_runtime_operator_in(
    tx: &mut Transaction<'_, Postgres>,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    flags: crate::confidential_storage::FeatureFlags,
) -> AppResult<()> {
    codewire_server_core::org_deletion::bound_environment_runtime_transaction(tx).await?;
    let denied = || coded(StatusCode::FORBIDDEN, "access_denied", "access denied");
    let current: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM users WHERE id=$1 FOR SHARE")
            .bind(&user.user_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(true) = current else {
        return Err(denied());
    };
    if !user.permits_organization(org_id) {
        return Err(denied());
    }
    let active: Option<bool> = sqlx::query_scalar(
        "SELECT deletion_state='active' FROM organizations WHERE id=$1 FOR UPDATE",
    )
    .bind(org_id)
    .fetch_optional(&mut **tx)
    .await?;
    if active != Some(true) {
        return Err(denied());
    }
    let environment: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT org_id,created_by,isolation_tier FROM environments WHERE id=$1 FOR UPDATE",
    )
    .bind(env_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((actual_org, creator, tier)) = environment else {
        return Err(denied());
    };
    if actual_org != org_id {
        return Err(denied());
    }
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM org_members WHERE org_id=$1 AND user_id=$2 FOR SHARE")
            .bind(org_id)
            .bind(&user.user_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(role) = role else {
        return Err(denied());
    };
    let grant: Option<String> = sqlx::query_scalar(
        "SELECT permission FROM environment_access WHERE environment_id=$1 AND user_id=$2 FOR SHARE",
    )
    .bind(env_id)
    .bind(&user.user_id)
    .fetch_optional(&mut **tx)
    .await?;
    if creator.as_deref() != Some(user.user_id.as_str())
        && !matches!(role.as_str(), "owner" | "admin")
        && !matches!(grant.as_deref(), Some("operator" | "owner"))
    {
        return Err(denied());
    }
    require_confidential_access(&mut **tx, flags, user, org_id, &tier).await
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
pub(crate) struct OrgEnvironmentUsage {
    pub(crate) active_total: i64,
    pub(crate) active_sandbox: i64,
    pub(crate) total_cpu: i64,
    pub(crate) total_memory_mb: i64,
}

/// Mirrors `api.OrgQuota`.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct OrgQuota {
    pub(crate) max_concurrent_environments: i32,
    pub(crate) max_concurrent_sandbox: i32,
    pub(crate) max_cpu_millicores: i32,
    pub(crate) max_memory_mb: i32,
}

/// Mirrors `countActiveEnvironments` (active = consuming compute). A stopped
/// environment whose start was admitted counts, since it is about to consume
/// compute; otherwise concurrent starts could both pass the check (#3256).
pub(crate) async fn count_active_environments<'e, E>(
    executor: E,
    org_id: &str,
) -> Result<OrgEnvironmentUsage, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let (active_total, active_sandbox, total_cpu, total_memory_mb): (i64, i64, i64, i64) =
        sqlx::query_as(
            r#"SELECT
                COUNT(*),
                COUNT(*) FILTER (WHERE type = 'sandbox'),
                COALESCE(SUM(cpu_millicores), 0),
                COALESCE(SUM(memory_mb), 0)
             FROM environments
             WHERE org_id = $1
               AND state NOT IN ('destroyed', 'destroying', 'error', 'archived')
               AND NOT (state = 'stopped' AND desired_state IS DISTINCT FROM 'started')"#,
        )
        .bind(org_id)
        .fetch_one(executor)
        .await?;
    Ok(OrgEnvironmentUsage {
        active_total,
        active_sandbox,
        total_cpu,
        total_memory_mb,
    })
}

/// The limits an organization without its own quota gets when no
/// `environment_quota_defaults` row can be read (0004 seeds these values).
pub(crate) const FALLBACK_QUOTA_DEFAULTS: OrgQuota = OrgQuota {
    max_concurrent_environments: 10,
    max_concurrent_sandbox: 50,
    max_cpu_millicores: 32_000,
    max_memory_mb: 65_536,
};

/// The administrator-set defaults for organizations without their own
/// quota (#3583), or [`FALLBACK_QUOTA_DEFAULTS`] when no row is stored. A
/// failed read is an error: admission refuses rather than guess (#3256).
pub(crate) async fn quota_defaults(pool: &PgPool) -> Result<OrgQuota, sqlx::Error> {
    Ok(sqlx::query_as::<_, (i32, i32, i32, i32)>(
        r#"SELECT max_concurrent_environments, max_concurrent_sandbox,
                  max_cpu_millicores, max_memory_mb
           FROM environment_quota_defaults WHERE singleton"#,
    )
    .fetch_optional(pool)
    .await?
    .map_or(FALLBACK_QUOTA_DEFAULTS, |(envs, sandbox, cpu, mem)| {
        OrgQuota {
            max_concurrent_environments: envs,
            max_concurrent_sandbox: sandbox,
            max_cpu_millicores: cpu,
            max_memory_mb: mem,
        }
    }))
}

/// The rate card with no charge and no quota (#3381).
pub(crate) const UNLIMITED_RATE_CARD: &str = "unlimited";

/// No limit of any kind: what an organization on the Unlimited card gets.
pub(crate) const NO_QUOTA: OrgQuota = OrgQuota {
    max_concurrent_environments: -1,
    max_concurrent_sandbox: -1,
    max_cpu_millicores: -1,
    max_memory_mb: -1,
};

/// An organization's limits (#3381): none on the Unlimited rate card;
/// otherwise its own quota (#3597), else the administrator defaults (#3583).
/// A failed read of the card, the organization's quota or the defaults is an
/// error, never looser limits: admission turns it into the retryable
/// `quota_unavailable` refusal (#3256).
pub(crate) async fn get_org_quota(pool: &PgPool, org_id: &str) -> Result<OrgQuota, sqlx::Error> {
    type Row = (String, Option<i32>, Option<i32>, Option<i32>, Option<i32>);
    match sqlx::query_as::<_, Row>(
        r#"SELECT o.rate_card, q.max_concurrent_environments, q.max_concurrent_sandbox,
                  q.max_cpu_millicores, q.max_memory_mb
           FROM organizations o
           LEFT JOIN environment_quotas q ON q.org_id = o.id
           WHERE o.id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    {
        Some((rate_card, ..)) if rate_card == UNLIMITED_RATE_CARD => Ok(NO_QUOTA),
        Some((_, Some(envs), Some(sandbox), Some(cpu), Some(mem))) => Ok(OrgQuota {
            max_concurrent_environments: envs,
            max_concurrent_sandbox: sandbox,
            max_cpu_millicores: cpu,
            max_memory_mb: mem,
        }),
        _ => quota_defaults(pool).await,
    }
}

/// The limits a create, start or resize is admitted against, or the
/// retryable `quota_unavailable` refusal when they cannot be read (#3256).
pub(crate) async fn admission_quota(pool: &PgPool, org_id: &str) -> Result<OrgQuota, AppError> {
    get_org_quota(pool, org_id).await.map_err(|error| {
        tracing::warn!(org_id, %error, "quota check: failed to read the organization's limits");
        coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "quota_unavailable",
            "the environment quota could not be checked; retry in a moment",
        )
    })
}

/// Mirrors `billing.ResolveEffectiveOrgEnvironmentPlan` (the plan-name
/// slice; the Stripe subscription id is irrelevant for quotas).
pub(crate) async fn resolve_effective_plan(pool: &PgPool, org_id: &str) -> String {
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

/// The quota cannot be enforced because the organization's usage could not
/// be read. The request is refused rather than admitted unchecked; it is
/// safe to retry.
pub(crate) fn quota_unavailable(org_id: &str, error: &sqlx::Error) -> AppError {
    tracing::warn!(org_id, %error, "quota check: failed to count active environments");
    coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "quota_unavailable",
        "the environment quota could not be checked; retry in a moment",
    )
}

/// Refuses a create or start when the organization's rate card draws credit
/// and its balance is zero or below (#3381). An organization on the
/// Unlimited card is never refused. A card or balance that cannot be read
/// refuses (fail closed); the request is safe to retry.
fn evaluate_credit(rate_card: &str, balance_nano_eur: i64) -> Result<(), AppError> {
    if rate_card == UNLIMITED_RATE_CARD || balance_nano_eur > 0 {
        return Ok(());
    }
    Err(coded(
        StatusCode::PAYMENT_REQUIRED,
        "credit_exhausted",
        "this organization has no compute credit left; add a card or credit on its billing page",
    ))
}

pub(crate) async fn check_credit_in(
    transaction: &mut Transaction<'_, Postgres>,
    org_id: &str,
) -> Result<(), AppError> {
    let credit: Option<(String, i64)> = sqlx::query_as(
        r#"SELECT o.rate_card, COALESCE(b.balance_nano_eur, 0)
           FROM organizations o
           LEFT JOIN billing_credit_balances b ON b.organization_id = o.id
           WHERE o.id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| {
        tracing::warn!(org_id, %error, "credit check: failed to read the balance");
        coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "credit_unavailable",
            "the organization's compute credit could not be checked; retry in a moment",
        )
    })?;
    let Some((rate_card, balance)) = credit else {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        ));
    };
    evaluate_credit(&rate_card, balance)
}

/// Mirrors `checkQuota`, with usage counted inside `transaction`, after the
/// organization's credit where this deployment enforces it (#3381). The
/// caller holds the organization row lock
/// and records the create or start in the same transaction, so concurrent
/// requests in one organization are counted one after another, and a
/// refused or failed one leaves nothing behind. A failed usage count or
/// balance read refuses the request (#3256).
pub(crate) async fn check_quota_in(
    transaction: &mut Transaction<'_, Postgres>,
    credit_enforcement: codewire_server_core::credit_enforcement::CreditEnforcement,
    quota: OrgQuota,
    org_id: &str,
    env_type: &str,
    cpu: i32,
    mem: i32,
) -> Result<(), AppError> {
    if credit_enforcement.is_on() {
        check_credit_in(transaction, org_id).await?;
    }
    let usage = count_active_environments(&mut **transaction, org_id)
        .await
        .map_err(|error| quota_unavailable(org_id, &error))?;
    evaluate_quota(quota, usage, env_type, cpu, mem)
}

/// Mirrors `auth.checkRateLimit` over the shared rate_limit table: at most
/// `max` requests in a fixed window keyed by `key`, which starts at the first
/// request and resets once it has passed. Any read error means "no record yet"
/// and resets the window, exactly like Go.
pub(crate) async fn check_rate_limit(
    pool: &PgPool,
    key: &str,
    window_secs: i64,
    max: i32,
) -> Result<bool, sqlx::Error> {
    rate_limit_at(
        pool,
        key,
        window_secs,
        max,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
}

/// `last_request` holds when the window started; a request inside the window
/// must not move it, or a steady caller's window never ends (#3923).
async fn rate_limit_at(
    pool: &PgPool,
    key: &str,
    window_secs: i64,
    max: i32,
    now: i64,
) -> Result<bool, sqlx::Error> {
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

    sqlx::query("UPDATE rate_limit SET count = count + 1 WHERE key = $1")
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
    // The admitted operation outlives a dropped request, so it owns its inputs.
    let owned_state = state.clone();
    run_environment_runtime_mutation(&state.pool, org_id, env_id, async move {
        let state = &owned_state;
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
    // The admitted operation outlives a dropped request, so it owns its inputs.
    let owned_state = state.clone();
    run_environment_runtime_mutation(&state.pool, org_id, env_id, async move {
        let state = &owned_state;
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
    require_confidential_access(
        &state.pool,
        state.confidential_storage_flags,
        user,
        org_id,
        &env.isolation_tier,
    )
    .await?;

    let dispatch_ambiguous = AtomicBool::new(false);
    // The admitted operation outlives a dropped request, so it owns its inputs.
    let owned_state = state.clone();
    let owned_user = user.clone();
    let owned_org_id = org_id.to_owned();
    run_environment_runtime_mutation(&state.pool, org_id, env_id, async move {
        let (state, user, org_id) = (&owned_state, &owned_user, owned_org_id.as_str());
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
                    if retry.is_err() {
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

            // Starting resumes compute allocation: the quota is checked and
            // the start intent recorded under the organization row lock.
            let quota = admission_quota(&state.pool, org_id).await?;
            if let Err(error) = lifecycle
                .admit_start(
                    &env.id,
                    org_id,
                    &env.isolation_tier,
                    crate::lifecycle::StartQuota {
                        credit_enforcement: state.credit_enforcement,
                        quota,
                        env_type: &env.env_type,
                        cpu_millicores: env.cpu_millicores,
                        memory_mb: env.memory_mb,
                    },
                )
                .await
            {
                let error = match error.downcast::<AppError>() {
                    Ok(refused) => return Err(refused),
                    Err(error) => error,
                };
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
    require_confidential_access(
        &state.pool,
        state.confidential_storage_flags,
        user,
        org_id,
        &env.isolation_tier,
    )
    .await?;

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
mod access_database_tests;

#[cfg(test)]
mod rate_limit_database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_refuses_charging_cards_at_zero_and_never_unlimited() {
        for card in ["regular", "discounted"] {
            assert!(evaluate_credit(card, 1).is_ok());
            for balance in [0, -1, i64::MIN] {
                let error = evaluate_credit(card, balance).unwrap_err();
                assert!(
                    matches!(
                        error,
                        AppError::Coded {
                            status: StatusCode::PAYMENT_REQUIRED,
                            code: "credit_exhausted",
                            ..
                        }
                    ),
                    "{card} {balance}: {error:?}"
                );
            }
        }
        for balance in [i64::MIN, -1, 0, 1] {
            assert!(evaluate_credit(UNLIMITED_RATE_CARD, balance).is_ok());
        }
    }

    #[test]
    fn shutdown_deadline_preserves_source_precision_and_legacy_absence() {
        assert_eq!(shutdown_deadline_string(None), None);
        for expected in ["2026-09-17T00:43:17Z", "2026-09-17T00:43:17.753549Z"] {
            let source = chrono::DateTime::parse_from_rfc3339(expected)
                .unwrap()
                .naive_utc();
            assert_eq!(
                shutdown_deadline_string(Some(source)).as_deref(),
                Some(expected)
            );
            // Other timestamp labels deliberately retain their old contract.
            assert_eq!(format_time(source), "2026-09-17T00:43:17Z");
        }
    }

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
            error_code: None,
            recoverable: true,
            state_changed_at: "2026-06-12T00:00:00Z".into(),
            retry_count: 0,
            setup_phase: 0,
            setup_complete: false,
            operation_generation: 7,
            source_selection: Some(Default::default()),
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
            network_state: None,
            network_failure: None,
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
            "network_state",
            "network_failure",
            "preset_name",
        ] {
            assert!(v.get(absent).is_none(), "{absent} should be omitted");
        }
        assert_eq!(v["type"], "sandbox");
        assert_eq!(v["state_changed_at"], "2026-06-12T00:00:00Z");
    }

    #[test]
    fn source_read_metadata_is_canonical_value_free_and_unavailable_on_inconsistent_pin() {
        let id = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        let spec = serde_json::json!({
            "environment": {"SYNTHETIC_CANARY": "never-return-this-value"},
            "secrets": {"user": "platform", "project": format!("platform:id:{id}")},
            "credentials": {"profile": format!("platform:id:{id}")}
        });
        let selected = source_selection_metadata(spec.clone(), Some(id.into()), Some(3)).unwrap();
        assert_eq!(selected.profile_revision, Some(3));
        assert!(
            !serde_json::to_string(&selected)
                .unwrap()
                .contains("never-return-this-value")
        );
        assert!(source_selection_metadata(spec.clone(), None, None).is_none());
        assert!(source_selection_metadata(spec.clone(), Some("other".into()), Some(3)).is_none());
        assert!(source_selection_metadata(spec, Some(id.into()), None).is_none());
        assert!(
            source_selection_metadata(serde_json::json!({}), Some(id.into()), Some(3)).is_none()
        );
        assert_eq!(
            source_selection_metadata(serde_json::json!({}), None, None),
            Some(Default::default())
        );
        assert!(ENV_SELECT_COLS.contains("e.project_spec->'secrets'"));
        assert!(ENV_SELECT_COLS.contains("e.project_spec->'credentials'"));
        assert!(!ENV_SELECT_COLS.contains("e.project_spec->'environment'"));
    }
}
