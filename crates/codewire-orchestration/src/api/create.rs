//! `POST /organizations/{org_id}/environments` (#38 slice 3) — port of
//! `createEnvironment` in environment_routes.go plus the preset /
//! insert helpers from environment_db.go.
//!
//! The smart-create branches mirror Go exactly:
//!   preset_id → preset_slug (image fallback) → image → repo_url
//!   (saved repo config, else AI detection) → 400 missing_input.
//! Setup-config JSON is written with Go `omitempty` semantics and
//! sorted map keys, so the stored JSONB matches what the Go handler
//! writes byte-for-byte.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_organization_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::ApiState;
use super::detect::{
    self, DetectionResult, apply_detection_workspace_defaults, call_claude_detect,
    call_claude_detect_multi_repo, fetch_all_repo_contexts, fetch_repo_context,
    fixup_detection_result, parse_repo_url, resolve_forge_token,
};
use super::environments::{
    ENV_SELECT_COLS, ENV_SELECT_JOINS, Environment, check_quota, check_rate_limit, coded,
    require_org_member, scan_environment, trigger_environment,
};

// ── Shared body types (environment_types.go) ────────────────────────────

/// Mirrors `api.RepoEntry`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RepoEntry {
    #[serde(default)]
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub branch: String,
}

/// Mirrors `api.AppPort`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AppPort {
    #[serde(default)]
    pub port: i32,
    #[serde(default)]
    pub label: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
}

/// Mirrors `api.SetupAgent`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SetupAgent {
    #[serde(rename = "type", default)]
    pub agent_type: String,
}

/// Mirrors `api.SetupConfig` (stored as JSONB; all fields omitempty —
/// BTreeMaps keep key order sorted like Go's map marshaling).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SetupConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub branch: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoEntry>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub install_command: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub startup_script: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_vars: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<SetupAgent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_agents: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agent_env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_ports: Vec<AppPort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_org_secrets: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_user_secrets: Option<bool>,
}

/// Mirrors `api.CreateEnvironmentBody`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct CreateEnvironmentBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millicores: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preset_slug: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub branch: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoEntry>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub image: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub install_command: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub startup_script: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_vars: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<SetupAgent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_agents: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agent_env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_project: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_ports: Vec<AppPort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_org_secrets: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_user_secrets: Option<bool>,
}

/// Mirrors `api.Preset` (the slice the create flow consumes; the full
/// wire shape comes with the presets endpoints).
#[derive(Debug, Clone, Default)]
pub struct Preset {
    pub id: String,
    pub org_id: Option<String>,
    pub official: bool,
    pub default_cpu_millicores: i32,
    pub default_memory_mb: i32,
    pub default_disk_gb: i32,
    pub default_ttl_seconds: Option<i32>,
}

/// Mirrors `normalizeCreateEnvironmentBody`.
pub fn normalize_create_environment_body(body: &mut CreateEnvironmentBody) {
    if body.agents.is_empty() && !body.agent.is_empty() {
        body.agents = vec![SetupAgent {
            agent_type: body.agent.clone(),
        }];
    }

    if !body.repos.is_empty() {
        if body.repo_url.is_empty() {
            body.repo_url = body.repos[0].url.clone();
        }
        if body.branch.is_empty() && !body.repos[0].branch.is_empty() {
            body.branch = body.repos[0].branch.clone();
        }
        return;
    }

    if !body.repo_url.is_empty() {
        body.repos = vec![RepoEntry {
            url: body.repo_url.clone(),
            branch: body.branch.clone(),
        }];
    }
}

fn validate_environment_resources(
    cpu_millicores: Option<i32>,
    memory_mb: Option<i32>,
    disk_gb: Option<i32>,
    ttl_seconds: Option<i32>,
) -> AppResult<()> {
    for (value, detail) in [
        (cpu_millicores, "cpu_millicores must be greater than zero"),
        (memory_mb, "memory_mb must be greater than zero"),
        (disk_gb, "disk_gb must be greater than zero"),
        (ttl_seconds, "ttl_seconds must be greater than zero"),
    ] {
        if value.is_some_and(|value| value <= 0) {
            return Err(coded(StatusCode::BAD_REQUEST, "invalid_resources", detail));
        }
    }
    Ok(())
}

/// Mirrors `worker.ValidAgentType` via the shared agent registry.
fn valid_agent_type(agent: &str) -> bool {
    crate::worker::scripts::agent_install_cmd(agent).is_some()
}

/// Mirrors `generateShortID` (2 random bytes, hex).
fn generate_short_id() -> String {
    let b = uuid::Uuid::new_v4().into_bytes();
    format!("{:02x}{:02x}", b[0], b[1])
}

// ── Preset helpers (environment_db.go) ──────────────────────────────────

/// Mirrors `normalizeImageRef`.
pub(crate) fn normalize_image_ref(image_ref: &str) -> String {
    match image_ref.trim() {
        "workspace" | "codewiresh/workspace" | "ghcr.io/codewiresh/workspace" => {
            crate::sandbox::CANONICAL_WORKSPACE_RUNTIME_IMAGE.to_string()
        }
        other => other.to_string(),
    }
}

/// Mirrors `sanitizeImageName` ("python:3.12" → "python-3-12").
pub(crate) fn sanitize_image_name(image_ref: &str) -> String {
    let mut name = image_ref;
    if let Some(i) = name.find('/')
        && name[..i].contains('.')
    {
        name = &name[i + 1..];
    }
    let lowered = name.to_lowercase();
    // Go: regexp [^a-z0-9]+ → "-", then trim dashes, cap at 50.
    let mut out = String::with_capacity(lowered.len());
    let mut last_dash = false;
    for c in lowered.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let mut out = out.trim_matches('-').to_string();
    if out.len() > 50 {
        out.truncate(50);
    }
    out
}

async fn get_preset(pool: &PgPool, preset_id: &str) -> Result<Preset, sqlx::Error> {
    let row: (String, Option<String>, bool, i32, i32, i32, Option<i32>) = sqlx::query_as(
        r#"SELECT et.id, et.org_id, et.official,
                  et.default_cpu_millicores, et.default_memory_mb, et.default_disk_gb,
                  et.default_ttl_seconds
           FROM environment_presets et WHERE et.id = $1"#,
    )
    .bind(preset_id)
    .fetch_one(pool)
    .await?;
    Ok(Preset {
        id: row.0,
        org_id: row.1,
        official: row.2,
        default_cpu_millicores: row.3,
        default_memory_mb: row.4,
        default_disk_gb: row.5,
        default_ttl_seconds: row.6,
    })
}

/// Mirrors `getPresetBySlug` (org presets first, then official).
async fn get_preset_by_slug(
    pool: &PgPool,
    org_id: &str,
    slug: &str,
) -> Result<Preset, sqlx::Error> {
    let row: (String, Option<String>, bool, i32, i32, i32, Option<i32>) = sqlx::query_as(
        r#"SELECT et.id, et.org_id, et.official,
                  et.default_cpu_millicores, et.default_memory_mb, et.default_disk_gb,
                  et.default_ttl_seconds
           FROM environment_presets et
           WHERE et.slug = $1 AND (et.org_id = $2 OR (et.official = true AND et.org_id IS NULL))
           ORDER BY CASE WHEN et.org_id = $2 THEN 0 ELSE 1 END
           LIMIT 1"#,
    )
    .bind(slug)
    .bind(org_id)
    .fetch_one(pool)
    .await?;
    Ok(Preset {
        id: row.0,
        org_id: row.1,
        official: row.2,
        default_cpu_millicores: row.3,
        default_memory_mb: row.4,
        default_disk_gb: row.5,
        default_ttl_seconds: row.6,
    })
}

/// Mirrors `resolveFromRepoConfig`: saved repo config → its preset.
async fn resolve_from_repo_config(pool: &PgPool, org_id: &str, repo_url: &str) -> Option<Preset> {
    let preset_id: Option<Option<String>> = sqlx::query_scalar(
        "SELECT preset_id FROM repo_configs WHERE org_id = $1 AND repo_url = $2",
    )
    .bind(org_id)
    .bind(repo_url)
    .fetch_optional(pool)
    .await
    .ok()?;
    let preset_id = preset_id??;
    get_preset(pool, &preset_id).await.ok()
}

/// Mirrors `findOrCreatePresetByImage`.
async fn find_or_create_preset_by_image(
    pool: &PgPool,
    org_id: &str,
    image_ref: &str,
    cpu: i32,
    mem: i32,
    disk: i32,
) -> anyhow::Result<String> {
    let image_ref = normalize_image_ref(image_ref);

    if let Some(id) = sqlx::query_scalar::<_, String>(
        r#"SELECT et.id FROM environment_presets et
           JOIN sandbox_template_config stc ON stc.preset_id = et.id
           WHERE stc.image_ref = $1 AND et.org_id = $2
           LIMIT 1"#,
    )
    .bind(&image_ref)
    .bind(org_id)
    .fetch_optional(pool)
    .await?
    {
        return Ok(id);
    }

    let sandbox_name = sanitize_image_name(&image_ref);
    let id: String = sqlx::query_scalar(
        r#"INSERT INTO environment_presets
              (org_id, name, slug, description, default_setup_config,
               default_cpu_millicores, default_memory_mb, default_disk_gb, default_ttl_seconds)
           VALUES ($1, $2, NULL, NULL, NULL, $3, $4, $5, NULL)
           RETURNING id"#,
    )
    .bind(org_id)
    .bind(&sandbox_name)
    .bind(cpu)
    .bind(mem)
    .bind(disk)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("auto-create preset: {e}"))?;

    sqlx::query(
        r#"INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name)
           VALUES ($1, $2, $3)"#,
    )
    .bind(&id)
    .bind(&image_ref)
    .bind(&sandbox_name)
    .execute(pool)
    .await
    .map_err(|e| anyhow::anyhow!("auto-create sandbox_template_config: {e}"))?;

    Ok(id)
}

/// Mirrors `getPresetDefaultSecretProject`.
async fn get_preset_default_secret_project(pool: &PgPool, preset_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT default_secret_project_id FROM environment_presets WHERE id = $1",
    )
    .bind(preset_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .flatten()
}

/// Mirrors `getSecretProjectByName` (the ID slice).
async fn get_secret_project_id_by_name(
    pool: &PgPool,
    org_id: &str,
    name: &str,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM secret_projects WHERE org_id = $1 AND name = $2")
        .bind(org_id)
        .bind(name)
        .fetch_one(pool)
        .await
}

// ── Insert (environment_db.go::insertEnvironment) ───────────────────────

struct InsertEnvironmentParams<'a> {
    org_id: &'a str,
    created_by: &'a str,
    preset_id: &'a str,
    env_type: &'a str,
    name: Option<String>,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
    ttl_seconds: Option<i32>,
    setup_config: Option<&'a SetupConfig>,
    secret_project_id: Option<String>,
}

async fn insert_environment(
    pool: &PgPool,
    p: InsertEnvironmentParams<'_>,
) -> anyhow::Result<Environment> {
    let setup_json = match p.setup_config {
        Some(cfg) => Some(serde_json::to_value(cfg)?),
        None => None,
    };

    // Auto-generate name if not provided: "env-{short-id}".
    let name = match p.name {
        Some(n) if !n.is_empty() => n,
        _ => format!("env-{}", generate_short_id()),
    };

    let preset_id = (!p.preset_id.is_empty()).then_some(p.preset_id);

    let sql = format!(
        r#"WITH ins AS (
            INSERT INTO environments
                (org_id, created_by, preset_id, type, name,
                 cpu_millicores, memory_mb, disk_gb, ttl_seconds,
                 shutdown_at, auth_token, setup_config, secret_project_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 CASE WHEN $10::int IS NOT NULL THEN NOW() + make_interval(secs => $10::int) END,
                 gen_random_uuid()::text, $11, $12)
             RETURNING *
         )
         SELECT {ENV_SELECT_COLS}
         FROM ins e
         {ENV_SELECT_JOINS}"#
    );
    let row = sqlx::query(&sql)
        .bind(p.org_id)
        .bind(p.created_by)
        .bind(preset_id)
        .bind(p.env_type)
        .bind(&name)
        .bind(p.cpu_millicores)
        .bind(p.memory_mb)
        .bind(p.disk_gb)
        .bind(p.ttl_seconds)
        .bind(p.ttl_seconds)
        .bind(setup_json)
        .bind(p.secret_project_id)
        .fetch_one(pool)
        .await?;
    Ok(scan_environment(&row)?)
}

// ── Handler ──────────────────────────────────────────────────────────────

fn int_or_default(v: Option<i32>, default: i32) -> i32 {
    v.unwrap_or(default)
}

/// `POST /api/v1/organizations/{org_id}/environments` — mirrors
/// `createEnvironment` (201 + the created environment).
pub async fn create_environment(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
    ValidatedJson(input): ValidatedJson<CreateEnvironmentBody>,
) -> AppResult<(StatusCode, Json<Environment>)> {
    let environment = create_environment_core(&state, &user, &org_id, input).await?;
    Ok((StatusCode::CREATED, Json(environment)))
}

pub(crate) async fn create_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    input: CreateEnvironmentBody,
) -> AppResult<Environment> {
    let pool = &state.pool;
    let mut body = input;

    require_org_member(pool, user, org_id).await?;

    // Rate limit environment creation per user (fail open on errors).
    match check_rate_limit(pool, &format!("env_create:{}", user.user_id), 60, 10).await {
        Err(e) => tracing::warn!(error = %e, "env rate limit check failed, allowing"),
        Ok(false) => {
            return Err(coded(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many environment creates",
            ));
        }
        Ok(true) => {}
    }

    normalize_create_environment_body(&mut body);
    // Reject explicit bad values before preset lookup or auto-creation can
    // write preset state. The effective values are checked again after
    // preset resolution so invalid stored defaults cannot reach quota or the
    // environment insert.
    validate_environment_resources(
        body.cpu_millicores,
        body.memory_mb,
        body.disk_gb,
        body.ttl_seconds,
    )?;

    let dispatch_ambiguous = AtomicBool::new(false);
    run_organization_runtime_mutation(pool, org_id, async {
        let result: AppResult<Environment> = async {
            let preset: Preset = if body.preset_id.as_deref().is_some_and(|s| !s.is_empty()) {
                // Explicit preset — existing behavior.
                let preset_id = body.preset_id.clone().unwrap();
                let preset = get_preset(pool, &preset_id).await.map_err(|_| {
                    coded(
                        StatusCode::BAD_REQUEST,
                        "preset_not_found",
                        "preset not found",
                    )
                })?;
                if preset.org_id.as_deref() != Some(org_id) && !preset.official {
                    return Err(coded(
                        StatusCode::BAD_REQUEST,
                        "preset_not_found",
                        "preset does not belong to this organization",
                    ));
                }
                preset
            } else if !body.preset_slug.is_empty() {
                // Slug-based resolution: org presets first, then official.
                match get_preset_by_slug(pool, org_id, &body.preset_slug).await {
                    Ok(p) => p,
                    Err(_) if body.image.is_empty() => {
                        return Err(super::environments::coded_owned(
                            StatusCode::BAD_REQUEST,
                            "preset_not_found",
                            format!("preset not found: {}", body.preset_slug),
                        ));
                    }
                    Err(_) => {
                        // Slug not in DB but image provided — resolve from image.
                        let preset_id = find_or_create_preset_by_image(
                    pool,
                    org_id,
                    &body.image,
                    int_or_default(body.cpu_millicores, 2000),
                    int_or_default(body.memory_mb, 4096),
                    int_or_default(body.disk_gb, 10),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "find-or-create preset by image (slug fallback)");
                    coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "failed to resolve preset for image",
                    )
                })?;
                        get_preset(pool, &preset_id).await.map_err(|_| {
                            coded(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "internal_error",
                                "failed to load auto-created preset",
                            )
                        })?
                    }
                }
            } else if !body.image.is_empty() {
                // Image provided — find or create preset.
                let preset_id = find_or_create_preset_by_image(
                    pool,
                    org_id,
                    &body.image,
                    int_or_default(body.cpu_millicores, 2000),
                    int_or_default(body.memory_mb, 4096),
                    int_or_default(body.disk_gb, 10),
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "find-or-create preset by image");
                    coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "failed to resolve preset for image",
                    )
                })?;
                get_preset(pool, &preset_id).await.map_err(|_| {
                    coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "failed to load auto-created preset",
                    )
                })?
            } else if !body.repo_url.is_empty() {
                // Repo URL — check saved repo config first, then detect.
                match resolve_from_repo_config(pool, org_id, &body.repo_url).await {
                    Some(p) => {
                        tracing::info!(
                            repo_url = body.repo_url,
                            "smart create: using saved repo config"
                        );
                        p
                    }
                    None => {
                        detect_preset_for_repo(state, pool, org_id, &user.user_id, &mut body)
                            .await?
                    }
                }
            } else {
                return Err(coded(
                    StatusCode::BAD_REQUEST,
                    "missing_input",
                    "one of preset_id, preset_slug, image, or repo_url is required",
                ));
            };

            let cpu = body.cpu_millicores.unwrap_or(preset.default_cpu_millicores);
            let mem = body.memory_mb.unwrap_or(preset.default_memory_mb);
            let disk = body.disk_gb.unwrap_or(preset.default_disk_gb);
            let ttl = match body.ttl_seconds {
                Some(t) => Some(t),
                None => preset.default_ttl_seconds,
            };

            validate_environment_resources(Some(cpu), Some(mem), Some(disk), ttl)?;

            // Check quota before inserting.
            check_quota(pool, org_id, "sandbox", cpu, mem).await?;

            for agent in &body.agents {
                if !valid_agent_type(&agent.agent_type) {
                    return Err(super::environments::coded_owned(
                        StatusCode::BAD_REQUEST,
                        "unsupported_agent",
                        format!("unsupported agent: {}", agent.agent_type),
                    ));
                }
            }
            if !body.agent.is_empty() && !valid_agent_type(&body.agent) {
                return Err(super::environments::coded_owned(
                    StatusCode::BAD_REQUEST,
                    "unsupported_agent",
                    format!("unsupported agent: {}", body.agent),
                ));
            }

            // Build setup_config if any smart fields are present.
            let needs_setup_cfg = !body.repo_url.is_empty()
                || !body.repos.is_empty()
                || !body.install_command.is_empty()
                || !body.startup_script.is_empty()
                || !body.env_vars.is_empty()
                || !body.agents.is_empty()
                || body.install_agents.is_some()
                || !body.agent.is_empty()
                || !body.agent_env.is_empty()
                || !body.app_ports.is_empty()
                || body.include_org_secrets == Some(false)
                || body.include_user_secrets == Some(false);
            let setup_cfg = needs_setup_cfg.then(|| SetupConfig {
                repo_url: body.repo_url.clone(),
                branch: body.branch.clone(),
                repos: body.repos.clone(),
                install_command: body.install_command.clone(),
                startup_script: body.startup_script.clone(),
                env_vars: body.env_vars.clone(),
                agents: body.agents.clone(),
                install_agents: body.install_agents,
                agent: body.agent.clone(),
                agent_env: body.agent_env.clone(),
                app_ports: body.app_ports.clone(),
                include_org_secrets: body.include_org_secrets,
                include_user_secrets: body.include_user_secrets,
            });

            // Resolve secret project name → ID if provided.
            let secret_project_id = if !body.secret_project.is_empty() {
                let id = get_secret_project_id_by_name(pool, org_id, &body.secret_project)
                    .await
                    .map_err(|_| {
                        super::environments::coded_owned(
                            StatusCode::BAD_REQUEST,
                            "secret_project_not_found",
                            format!("secret project not found: {}", body.secret_project),
                        )
                    })?;
                Some(id)
            } else {
                // Fall back to preset's default secret project.
                get_preset_default_secret_project(pool, &preset.id).await
            };

            let env = insert_environment(
                pool,
                InsertEnvironmentParams {
                    org_id,
                    created_by: &user.user_id,
                    preset_id: &preset.id,
                    env_type: "sandbox",
                    name: body.name.clone(),
                    cpu_millicores: cpu,
                    memory_mb: mem,
                    disk_gb: disk,
                    ttl_seconds: ttl,
                    setup_config: setup_cfg.as_ref(),
                    secret_project_id,
                },
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "insert environment failed");
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to create environment",
                )
            })?;

            // Auto-grant owner access to the creator (best-effort, like Go).
            let _ = sqlx::query(
                r#"INSERT INTO environment_access (environment_id, user_id, permission, granted_by)
           VALUES ($1, $2, 'owner', $2)"#,
            )
            .bind(&env.id)
            .bind(&user.user_id)
            .execute(pool)
            .await;

            if trigger_environment(state, &env.id, "create").await.is_err() {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to start environment lifecycle",
                ));
            }

            Ok(env)
        }
        .await;
        match result {
            Ok(environment) => Ok(environment),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

/// The repo-detection arm of `createEnvironment` (no saved config):
/// AI detection feeds defaults into the body, then preset resolution
/// by detected slug or image.
async fn detect_preset_for_repo(
    state: &ApiState,
    pool: &PgPool,
    org_id: &str,
    user_id: &str,
    body: &mut CreateEnvironmentBody,
) -> Result<Preset, AppError> {
    if state.anthropic_api_key.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "ai_detection_unavailable",
            "AI detection not configured; provide --image or --preset",
        ));
    }

    let result: DetectionResult = if body.repos.len() > 1 {
        let entries = fetch_all_repo_contexts(
            pool,
            &state.github_cfg,
            state.secrets.as_ref(),
            user_id,
            &body.repos,
        )
        .await;
        if !entries
            .iter()
            .any(|e| e.error.is_none() && e.context.is_some())
        {
            return Err(coded(
                StatusCode::BAD_GATEWAY,
                "repo_not_accessible",
                "failed to fetch any repo context",
            ));
        }
        let multi = call_claude_detect_multi_repo(&state.anthropic_api_key, &entries)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "smart create: multi-repo detection failed");
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ai_detection_failed",
                    "AI detection failed",
                )
            })?;
        let mut detection = multi.detection;
        apply_detection_workspace_defaults(&mut detection);
        detection
    } else {
        let r = parse_repo_url(&body.repo_url).map_err(|e| {
            super::environments::coded_owned(
                StatusCode::BAD_REQUEST,
                "invalid_repo_url",
                format!("invalid repo URL: {e}"),
            )
        })?;
        let forge_token = resolve_forge_token(
            pool,
            &state.github_cfg,
            state.secrets.as_ref(),
            user_id,
            &r.host,
        )
        .await;
        let repo_ctx = fetch_repo_context(&r, &body.branch, &forge_token)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "smart create: failed to fetch repo context");
                let msg = e.to_string();
                let code = if msg.contains("404") {
                    "repo_not_found"
                } else {
                    "repo_not_accessible"
                };
                super::environments::coded_owned(
                    StatusCode::BAD_GATEWAY,
                    code,
                    format!("failed to fetch repo: {msg}"),
                )
            })?;
        let mut detected =
            call_claude_detect(&state.anthropic_api_key, &r.owner, &r.repo, &repo_ctx)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "smart create: detection failed");
                    coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ai_detection_failed",
                        "AI detection failed",
                    )
                })?;
        fixup_detection_result(&mut detected, &repo_ctx);
        detected
    };

    if body.install_command.is_empty() {
        body.install_command = result.install_command.clone();
    }
    if body.app_ports.is_empty() && !result.app_ports.is_empty() {
        body.app_ports = result
            .app_ports
            .iter()
            .map(|p| AppPort {
                port: p.port,
                label: p.label.clone(),
                access: p.access.clone(),
            })
            .collect();
    }
    if body.startup_script.is_empty() {
        body.startup_script = result.startup_script.clone();
    }
    if body.name.is_none() && !result.suggested_name.is_empty() {
        body.name = Some(result.suggested_name.clone());
    }

    // Resolve preset slug if detection returned one; fall back to the
    // detected (or default) image.
    if !result.preset_slug.is_empty()
        && let Ok(p) = get_preset_by_slug(pool, org_id, &result.preset_slug).await
    {
        return Ok(p);
    }
    let detected_image = if result.preset_image.is_empty() {
        detect::DEFAULT_DETECTION_PRESET_IMAGE
    } else {
        &result.preset_image
    };
    let preset_id = find_or_create_preset_by_image(
        pool,
        org_id,
        detected_image,
        int_or_default(body.cpu_millicores, 2000),
        int_or_default(body.memory_mb, 4096),
        int_or_default(body.disk_gb, 10),
    )
    .await
    .map_err(|_| {
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to resolve preset from detection",
        )
    })?;
    get_preset(pool, &preset_id).await.map_err(|_| {
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load detected preset",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn normalize_mirrors_go() {
        // agent → agents promotion.
        let mut b = CreateEnvironmentBody {
            agent: "claude-code".into(),
            ..Default::default()
        };
        normalize_create_environment_body(&mut b);
        assert_eq!(b.agents.len(), 1);
        assert_eq!(b.agents[0].agent_type, "claude-code");

        // repo_url → repos.
        let mut b = CreateEnvironmentBody {
            repo_url: "https://github.com/a/b".into(),
            branch: "main".into(),
            ..Default::default()
        };
        normalize_create_environment_body(&mut b);
        assert_eq!(b.repos.len(), 1);
        assert_eq!(b.repos[0].url, "https://github.com/a/b");
        assert_eq!(b.repos[0].branch, "main");

        // repos → repo_url/branch backfill; repos untouched.
        let mut b = CreateEnvironmentBody {
            repos: vec![
                RepoEntry {
                    url: "https://github.com/x/y".into(),
                    branch: "dev".into(),
                },
                RepoEntry {
                    url: "https://github.com/x/z".into(),
                    branch: String::new(),
                },
            ],
            ..Default::default()
        };
        normalize_create_environment_body(&mut b);
        assert_eq!(b.repo_url, "https://github.com/x/y");
        assert_eq!(b.branch, "dev");
        assert_eq!(b.repos.len(), 2);
    }

    #[test]
    fn image_name_sanitization_mirrors_go() {
        assert_eq!(sanitize_image_name("python:3.12"), "python-3-12");
        assert_eq!(
            sanitize_image_name("ghcr.io/foo/bar:latest"),
            "foo-bar-latest"
        );
        assert_eq!(sanitize_image_name("Node:20-ALPINE"), "node-20-alpine");
        // Registry prefix only stripped when it has a dot.
        assert_eq!(sanitize_image_name("library/ubuntu"), "library-ubuntu");
        let long = sanitize_image_name(&format!("ghcr.io/{}:v1", "a".repeat(80)));
        assert_eq!(long.len(), 50);
    }

    #[test]
    fn image_ref_normalization_mirrors_go() {
        for alias in [
            "workspace",
            "codewiresh/workspace",
            "ghcr.io/codewiresh/workspace",
        ] {
            assert_eq!(
                normalize_image_ref(alias),
                crate::sandbox::CANONICAL_WORKSPACE_RUNTIME_IMAGE
            );
        }
        assert_eq!(normalize_image_ref("python:3.12"), "python:3.12");
    }

    #[test]
    fn setup_config_serializes_with_go_omitempty_semantics() {
        let cfg = SetupConfig {
            repo_url: "https://github.com/a/b".into(),
            repos: vec![RepoEntry {
                url: "https://github.com/a/b".into(),
                branch: String::new(),
            }],
            install_command: "npm install".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&cfg).unwrap();
        // Present fields only; nested RepoEntry omits empty branch.
        // (Key ORDER is irrelevant: the column is JSONB, which
        // normalizes ordering on both sides.)
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 3, "{v}");
        assert_eq!(v["repo_url"], "https://github.com/a/b");
        assert_eq!(v["install_command"], "npm install");
        assert_eq!(v["repos"][0]["url"], "https://github.com/a/b");
        assert!(v["repos"][0].get("branch").is_none());
    }

    #[test]
    fn create_environment_schema_has_no_top_level_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(CreateEnvironmentBody)).unwrap();

        assert!(
            schema.get("required").is_none(),
            "Go create-environment has no top-level body fields required by schema"
        );
    }

    #[test]
    fn create_environment_validation_accepts_empty_body() {
        let parsed =
            validate_value::<CreateEnvironmentBody>(serde_json::json!({})).expect("empty body");

        assert!(parsed.preset_id.is_none());
        assert!(parsed.preset_slug.is_empty());
        assert!(parsed.repo_url.is_empty());
        assert!(parsed.repos.is_empty());
    }

    #[test]
    fn create_environment_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreateEnvironmentBody>(serde_json::json!({
                "cpu_millicores": "2000"
            }))
        else {
            panic!("expected type-invalid CPU to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/cpu_millicores");
        assert!(errors[0].message.contains("integer"));
    }

    #[test]
    fn environment_resource_validation_rejects_each_non_positive_effective_value() {
        let cases = [
            (
                (Some(0), Some(4096), Some(10), Some(3600)),
                "cpu_millicores must be greater than zero",
            ),
            (
                (Some(2000), Some(-1), Some(10), Some(3600)),
                "memory_mb must be greater than zero",
            ),
            (
                (Some(2000), Some(4096), Some(0), Some(3600)),
                "disk_gb must be greater than zero",
            ),
            (
                (Some(2000), Some(4096), Some(10), Some(-1)),
                "ttl_seconds must be greater than zero",
            ),
        ];

        for ((cpu, memory, disk, ttl), expected_detail) in cases {
            let Err(AppError::Coded {
                status,
                code,
                detail,
            }) = validate_environment_resources(cpu, memory, disk, ttl)
            else {
                panic!("expected a coded resource validation error");
            };
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(code, "invalid_resources");
            assert_eq!(detail, expected_detail);
        }
    }

    #[test]
    fn environment_resource_validation_accepts_positive_values_and_absent_ttl() {
        validate_environment_resources(Some(1), Some(1), Some(1), Some(1)).unwrap();
        validate_environment_resources(Some(2000), Some(4096), Some(10), None).unwrap();
    }

    #[test]
    fn short_id_is_4_hex_chars() {
        let id = generate_short_id();
        assert_eq!(id.len(), 4);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
