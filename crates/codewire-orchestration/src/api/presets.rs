//! Presets CRUD (#38 slice 4) — port of the preset handlers in
//! `environment_routes.go` plus `updatePreset` from
//! `environment_db.go`. Admin gate mirrors `canAdmin` (org owner/admin
//! or a `super_admin` assignment).

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::run_organization_database_mutation;
use codewire_server_core::{AppError, AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::Deserialize;
use sqlx::PgPool;

use super::ApiState;
use super::create::{AppPort, SetupAgent, SetupConfig, sanitize_image_name};
use super::environments::{coded, coded_owned, require_org_member};
use super::prepare::{PresetWire, get_preset_wire, list_presets};

/// Mirrors `getUserAssignments`.
async fn get_user_assignments(pool: &PgPool, org_id: &str, user_id: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT a.assignment FROM org_member_assignments a
           JOIN org_members m ON m.id = a.org_member_id
           WHERE m.org_id = $1 AND m.user_id = $2"#,
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Mirrors `canAdmin`: owner/admin role or super_admin assignment.
pub(crate) async fn can_admin(pool: &PgPool, user: &AuthUser, org_id: &str, role: &str) -> bool {
    if role == "owner" || role == "admin" {
        return true;
    }
    get_user_assignments(pool, org_id, &user.user_id)
        .await
        .iter()
        .any(|a| a == "super_admin")
}

/// Org-role gate returning the role (handlers need it for canAdmin).
async fn require_org_role(
    pool: &PgPool,
    user: &AuthUser,
    org_id: &str,
) -> Result<String, AppError> {
    match user_org_role(pool, user, org_id).await? {
        Some(role) => Ok(role),
        None => Err(coded(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "organization not found",
        )),
    }
}

fn valid_agent_type(agent: &str) -> bool {
    crate::worker::scripts::agent_install_cmd(agent).is_some()
}

// ── Create ──────────────────────────────────────────────────────────────

/// Mirrors `api.CreatePresetBody`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct CreatePresetBody {
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_cpu_millicores: Option<i32>,
    #[serde(default)]
    pub default_memory_mb: Option<i32>,
    #[serde(default)]
    pub default_disk_gb: Option<i32>,
    #[serde(default)]
    pub default_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub install_command: String,
    #[serde(default)]
    pub startup_script: String,
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    #[serde(default)]
    pub agents: Vec<SetupAgent>,
    #[serde(default)]
    pub install_agents: Option<bool>,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub agent_env: BTreeMap<String, String>,
    #[serde(default)]
    pub app_ports: Vec<AppPort>,
    #[serde(default)]
    pub include_org_secrets: Option<bool>,
    #[serde(default)]
    pub include_user_secrets: Option<bool>,
    #[serde(default)]
    pub secret_project: String,
}

/// Renderer-specific selector for the shared preset service core. REST keeps
/// accepting a secret-project display name while Connect carries the stable
/// project ID; both resolve through the same organization-scoped lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SecretProjectSelection {
    Name(String),
    Id(String),
    Clear,
}

async fn resolve_secret_project_id(
    pool: &PgPool,
    org_id: &str,
    selection: &SecretProjectSelection,
) -> AppResult<Option<String>> {
    let (sql, value) = match selection {
        SecretProjectSelection::Name(name) => (
            "SELECT id FROM secret_projects WHERE org_id = $1 AND name = $2",
            name,
        ),
        SecretProjectSelection::Id(id) => (
            "SELECT id FROM secret_projects WHERE org_id = $1 AND id = $2",
            id,
        ),
        SecretProjectSelection::Clear => return Ok(None),
    };
    sqlx::query_scalar(sql)
        .bind(org_id)
        .bind(value)
        .fetch_optional(pool)
        .await
        .map_err(|error| {
            tracing::error!(%error, "secret-project lookup failed");
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to resolve secret project",
            )
        })?
        .ok_or_else(|| {
            coded_owned(
                StatusCode::BAD_REQUEST,
                "secret_project_not_found",
                format!("secret project not found: {value}"),
            )
        })
        .map(Some)
}

/// Mirrors `createPreset` (201).
pub async fn create_preset(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
    ValidatedJson(body): ValidatedJson<CreatePresetBody>,
) -> AppResult<(StatusCode, Json<PresetWire>)> {
    let secret_project = (!body.secret_project.is_empty())
        .then(|| SecretProjectSelection::Name(body.secret_project.clone()));
    let preset = create_preset_core(&state, &user, &org_id, body, secret_project).await?;
    Ok((StatusCode::CREATED, Json(preset)))
}

pub(crate) async fn create_preset_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    body: CreatePresetBody,
    secret_project: Option<SecretProjectSelection>,
) -> AppResult<PresetWire> {
    let pool = &state.pool;
    let role = require_org_role(pool, user, org_id).await?;
    if !can_admin(pool, user, org_id, &role).await {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only owner or admin can create presets",
        ));
    }
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "name_required",
            "name is required",
        ));
    }
    let cpu = body.default_cpu_millicores.unwrap_or(2000);
    let mem = body.default_memory_mb.unwrap_or(4096);
    let disk = body.default_disk_gb.unwrap_or(10);

    for agent in &body.agents {
        if !valid_agent_type(&agent.agent_type) {
            return Err(coded_owned(
                StatusCode::BAD_REQUEST,
                "unsupported_agent",
                format!("unsupported agent: {}", agent.agent_type),
            ));
        }
    }

    // Build default setup config if any runtime setup fields are
    // provided (note: ANY include_*_secrets value counts here, unlike
    // createEnvironment which only persists explicit false).
    let needs_cfg = !body.install_command.is_empty()
        || !body.startup_script.is_empty()
        || !body.env_vars.is_empty()
        || !body.agents.is_empty()
        || body.install_agents.is_some()
        || !body.agent.is_empty()
        || !body.agent_env.is_empty()
        || !body.app_ports.is_empty()
        || body.include_org_secrets.is_some()
        || body.include_user_secrets.is_some();
    let default_setup_config = needs_cfg.then(|| SetupConfig {
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
        ..Default::default()
    });
    let setup_json = match &default_setup_config {
        Some(cfg) => Some(serde_json::to_value(cfg).map_err(|_| {
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to create preset",
            )
        })?),
        None => None,
    };

    run_organization_database_mutation(pool, org_id, async {
        let slug = (!body.slug.is_empty()).then_some(body.slug.as_str());
        let id: String = match sqlx::query_scalar(
            r#"INSERT INTO environment_presets
              (org_id, name, slug, description, default_setup_config,
               default_cpu_millicores, default_memory_mb, default_disk_gb, default_ttl_seconds)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id"#,
        )
        .bind(org_id)
        .bind(&name)
        .bind(slug)
        .bind(&body.description)
        .bind(&setup_json)
        .bind(cpu)
        .bind(mem)
        .bind(disk)
        .bind(body.default_ttl_seconds)
        .fetch_one(pool)
        .await
        {
            Ok(id) => id,
            Err(e) if e.to_string().contains("idx_presets_slug_org") => {
                return Err(coded(
                    StatusCode::CONFLICT,
                    "preset_slug_conflict",
                    "preset with this slug already exists",
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "insert preset failed");
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to create preset",
                ));
            }
        };

        // If image is provided, create the sandbox_template_config row.
        if !body.image.is_empty() {
            let sandbox_name = sanitize_image_name(&body.image);
            if let Err(e) = sqlx::query(
                r#"INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name)
               VALUES ($1, $2, $3)"#,
            )
            .bind(&id)
            .bind(&body.image)
            .bind(&sandbox_name)
            .execute(pool)
            .await
            {
                tracing::error!(error = %e, "failed to create sandbox_preset_config");
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to create sandbox preset config",
                ));
            }
        }

        // Bind a renderer-selected project through one organization-scoped
        // lookup. The UPDATE remains best-effort to preserve the existing
        // REST service behavior.
        if let Some(selection) = secret_project.as_ref() {
            let sp_id = resolve_secret_project_id(pool, org_id, selection)
                .await?
                .expect("create never supplies the clear selector");
            let _ = sqlx::query(
                "UPDATE environment_presets SET default_secret_project_id = $1 WHERE id = $2",
            )
            .bind(&sp_id)
            .bind(&id)
            .execute(pool)
            .await;
        }

        let preset = get_preset_wire(pool, &id).await.map_err(|_| {
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to read created preset",
            )
        })?;
        Ok(preset)
    })
    .await
}

// ── Read ────────────────────────────────────────────────────────────────

/// Mirrors `listPresets` (the handler).
pub async fn list_presets_handler(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<Json<Vec<PresetWire>>> {
    Ok(Json(list_presets_core(&state, &user, &org_id).await?))
}

pub(crate) async fn list_presets_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<PresetWire>> {
    require_org_member(&state.pool, user, org_id).await?;
    let presets = list_presets(&state.pool, org_id).await.map_err(|e| {
        tracing::error!(error = %e, "list presets failed");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list presets",
        )
    })?;
    Ok(presets)
}

/// Mirrors `getPreset` (the handler — official presets readable
/// cross-org; foreign non-official 404).
pub async fn get_preset_handler(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, preset_id)): Path<(String, String)>,
) -> AppResult<Json<PresetWire>> {
    Ok(Json(
        get_preset_core(&state, &user, &org_id, &preset_id).await?,
    ))
}

pub(crate) async fn get_preset_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    preset_id: &str,
) -> AppResult<PresetWire> {
    require_org_member(&state.pool, user, org_id).await?;
    let preset = get_preset_wire(&state.pool, preset_id).await.map_err(|_| {
        coded(
            StatusCode::NOT_FOUND,
            "preset_not_found",
            "preset not found",
        )
    })?;
    if preset.org_id.as_deref() != Some(org_id) && !preset.official {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "preset_not_found",
            "preset not found",
        ));
    }
    Ok(preset)
}

// ── Update ──────────────────────────────────────────────────────────────

/// Mirrors `api.UpdatePresetBody` (all-optional PATCH semantics; for
/// maps/slices "present" means replace, mirroring Go nil-vs-empty).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct UpdatePresetBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub default_cpu_millicores: Option<i32>,
    #[serde(default)]
    pub default_memory_mb: Option<i32>,
    #[serde(default)]
    pub default_disk_gb: Option<i32>,
    #[serde(default)]
    pub default_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub install_command: Option<String>,
    #[serde(default)]
    pub startup_script: Option<String>,
    #[serde(default)]
    pub env_vars: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub agents: Option<Vec<SetupAgent>>,
    #[serde(default)]
    pub install_agents: Option<bool>,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub agent_env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub app_ports: Option<Vec<AppPort>>,
    #[serde(default)]
    pub include_org_secrets: Option<bool>,
    #[serde(default)]
    pub include_user_secrets: Option<bool>,
    #[serde(default)]
    pub secret_project: Option<String>,
}

/// Mirrors `updatePreset` (environment_db.go): dynamic UPDATE +
/// setup-config rebuild + secret-project resolution + image upsert.
async fn update_preset_db(
    pool: &PgPool,
    id: &str,
    body: &UpdatePresetBody,
    secret_project_id: Option<Option<String>>,
) -> anyhow::Result<()> {
    // Dynamic SET clauses. sqlx can't bind heterogenous Vec<dyn>, so
    // build the query with explicit positional binds per branch.
    let mut sets: Vec<String> = Vec::new();
    let mut texts: Vec<Option<String>> = Vec::new();
    let mut ints: Vec<(usize, i32)> = Vec::new(); // (set index, value)
    let mut jsons: Vec<(usize, serde_json::Value)> = Vec::new();

    let push_text = |sets: &mut Vec<String>,
                     texts: &mut Vec<Option<String>>,
                     col: &str,
                     val: Option<String>| {
        sets.push(col.to_string());
        texts.push(val);
    };

    if let Some(name) = &body.name {
        push_text(&mut sets, &mut texts, "name", Some(name.clone()));
    }
    if let Some(desc) = &body.description {
        push_text(&mut sets, &mut texts, "description", Some(desc.clone()));
    }
    if let Some(slug) = &body.slug {
        let v = (!slug.is_empty()).then(|| slug.clone());
        push_text(&mut sets, &mut texts, "slug", v);
    }
    if let Some(v) = body.default_cpu_millicores {
        sets.push("default_cpu_millicores".into());
        texts.push(None);
        ints.push((sets.len() - 1, v));
    }
    if let Some(v) = body.default_memory_mb {
        sets.push("default_memory_mb".into());
        texts.push(None);
        ints.push((sets.len() - 1, v));
    }
    if let Some(v) = body.default_disk_gb {
        sets.push("default_disk_gb".into());
        texts.push(None);
        ints.push((sets.len() - 1, v));
    }
    if let Some(v) = body.default_ttl_seconds {
        sets.push("default_ttl_seconds".into());
        texts.push(None);
        ints.push((sets.len() - 1, v));
    }

    // Setup-config rebuild from current + updates.
    if body.install_command.is_some()
        || body.startup_script.is_some()
        || body.env_vars.is_some()
        || body.agents.is_some()
        || body.install_agents.is_some()
        || body.agent.is_some()
        || body.agent_env.is_some()
        || body.app_ports.is_some()
        || body.include_org_secrets.is_some()
        || body.include_user_secrets.is_some()
    {
        let current: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT default_setup_config FROM environment_presets WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .flatten();
        let mut cfg: SetupConfig = current
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        if let Some(v) = &body.install_command {
            cfg.install_command = v.clone();
        }
        if let Some(v) = &body.startup_script {
            cfg.startup_script = v.clone();
        }
        if let Some(v) = &body.env_vars {
            cfg.env_vars = v.clone();
        }
        if let Some(v) = &body.agents {
            cfg.agents = v.clone();
        }
        if body.install_agents.is_some() {
            cfg.install_agents = body.install_agents;
        }
        if let Some(v) = &body.agent {
            cfg.agent = v.clone();
        }
        if let Some(v) = &body.agent_env {
            cfg.agent_env = v.clone();
        }
        if let Some(v) = &body.app_ports {
            cfg.app_ports = v.clone();
        }
        if body.include_org_secrets.is_some() {
            cfg.include_org_secrets = body.include_org_secrets;
        }
        if body.include_user_secrets.is_some() {
            cfg.include_user_secrets = body.include_user_secrets;
        }
        sets.push("default_setup_config".into());
        texts.push(None);
        jsons.push((sets.len() - 1, serde_json::to_value(&cfg)?));
    }

    if let Some(secret_project_id) = secret_project_id {
        push_text(
            &mut sets,
            &mut texts,
            "default_secret_project_id",
            secret_project_id,
        );
    }

    if !sets.is_empty() {
        let clauses: Vec<String> = sets
            .iter()
            .enumerate()
            .map(|(i, col)| format!("{col} = ${}", i + 1))
            .collect();
        let sql = format!(
            "UPDATE environment_presets SET {} WHERE id = ${}",
            clauses.join(", "),
            sets.len() + 1
        );
        let mut q = sqlx::query(&sql);
        for (i, text) in texts.iter().enumerate() {
            if let Some((_, v)) = ints.iter().find(|(idx, _)| *idx == i) {
                q = q.bind(*v);
            } else if let Some((_, v)) = jsons.iter().find(|(idx, _)| *idx == i) {
                q = q.bind(v.clone());
            } else {
                q = q.bind(text.clone());
            }
        }
        q = q.bind(id);
        q.execute(pool)
            .await
            .map_err(|e| anyhow::anyhow!("update preset: {e}"))?;
    }

    // Image upsert into sandbox_template_config.
    if let Some(image) = &body.image {
        sqlx::query(
            r#"INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name)
               VALUES ($1, $2, $3)
               ON CONFLICT (preset_id) DO UPDATE SET image_ref = $2"#,
        )
        .bind(id)
        .bind(image)
        .bind(sanitize_image_name(image))
        .execute(pool)
        .await
        .map_err(|e| anyhow::anyhow!("update sandbox_template_config: {e}"))?;
    }

    Ok(())
}

/// Mirrors `updatePreset` (the handler — PATCH).
pub async fn update_preset_handler(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, preset_id)): Path<(String, String)>,
    ValidatedJson(body): ValidatedJson<UpdatePresetBody>,
) -> AppResult<Json<PresetWire>> {
    let secret_project = body.secret_project.as_ref().map(|value| {
        if value.is_empty() {
            SecretProjectSelection::Clear
        } else {
            SecretProjectSelection::Name(value.clone())
        }
    });
    Ok(Json(
        update_preset_core(&state, &user, &org_id, &preset_id, body, secret_project).await?,
    ))
}

pub(crate) async fn update_preset_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    preset_id: &str,
    body: UpdatePresetBody,
    secret_project: Option<SecretProjectSelection>,
) -> AppResult<PresetWire> {
    let pool = &state.pool;
    let role = require_org_role(pool, user, org_id).await?;
    if !can_admin(pool, user, org_id, &role).await {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only owner or admin can update presets",
        ));
    }
    run_organization_database_mutation(pool, org_id, async {
        let preset = get_preset_wire(pool, preset_id).await.map_err(|_| {
            coded(
                StatusCode::NOT_FOUND,
                "preset_not_found",
                "preset not found",
            )
        })?;
        if preset.org_id.as_deref() != Some(org_id) {
            return Err(coded(
                StatusCode::NOT_FOUND,
                "preset_not_found",
                "preset not found",
            ));
        }

        let secret_project_id = match secret_project.as_ref() {
            Some(selection) => Some(resolve_secret_project_id(pool, org_id, selection).await?),
            None => None,
        };
        if let Err(e) = update_preset_db(pool, &preset.id, &body, secret_project_id).await {
            if e.to_string().contains("idx_presets_slug_org") {
                return Err(coded(
                    StatusCode::CONFLICT,
                    "preset_slug_conflict",
                    "preset with this slug already exists",
                ));
            }
            tracing::error!(error = %e, "update preset");
            return Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to update preset",
            ));
        }

        let updated = get_preset_wire(pool, &preset.id).await.map_err(|_| {
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to read updated preset",
            )
        })?;
        Ok(updated)
    })
    .await
}

// ── Delete ──────────────────────────────────────────────────────────────

/// Mirrors `deletePreset` (204; refuses while active environments use
/// it; purges destroyed rows to satisfy the FK).
pub async fn delete_preset_handler(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, preset_id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    delete_preset_core(&state, &user, &org_id, &preset_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_preset_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    preset_id: &str,
) -> AppResult<()> {
    let pool = &state.pool;
    let role = require_org_role(pool, user, org_id).await?;
    if !can_admin(pool, user, org_id, &role).await {
        return Err(coded(
            StatusCode::FORBIDDEN,
            "forbidden",
            "only owner or admin can delete presets",
        ));
    }
    run_organization_database_mutation(pool, org_id, async {
        let preset = get_preset_wire(pool, preset_id).await.map_err(|_| {
            coded(
                StatusCode::NOT_FOUND,
                "preset_not_found",
                "preset not found",
            )
        })?;
        if preset.org_id.as_deref() != Some(org_id) {
            return Err(coded(
                StatusCode::NOT_FOUND,
                "preset_not_found",
                "preset not found",
            ));
        }

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environments WHERE preset_id = $1 AND state != 'destroyed'",
        )
        .bind(&preset.id)
        .fetch_one(pool)
        .await
        .map_err(|_| {
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to check preset usage",
            )
        })?;
        if active_count > 0 {
            return Err(coded_owned(
                StatusCode::CONFLICT,
                "preset_in_use",
                format!(
                    "preset is used by {active_count} active environment(s) — delete them first"
                ),
            ));
        }

        sqlx::query("DELETE FROM environments WHERE preset_id = $1 AND state = 'destroyed'")
            .bind(&preset.id)
            .execute(pool)
            .await
            .map_err(|_| {
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to clean up destroyed environments",
                )
            })?;

        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&preset.id)
            .execute(pool)
            .await
            .map_err(|_| {
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to delete preset",
                )
            })?;

        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn create_preset_schema_requires_go_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(CreatePresetBody)).unwrap();

        assert_eq!(
            schema["required"],
            serde_json::json!(["name"]),
            "Go/huma marks only name required; blank names still return the handler 400"
        );
    }

    #[test]
    fn create_preset_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreatePresetBody>(serde_json::json!({
                "image": "ghcr.io/codewiresh/sandbox:latest"
            }))
        else {
            panic!("expected missing name to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("name"));
    }

    #[test]
    fn create_preset_validation_keeps_image_optional() {
        let parsed = validate_value::<CreatePresetBody>(serde_json::json!({
            "name": "Default"
        }))
        .expect("image stays optional like Go omitempty");

        assert_eq!(parsed.name, "Default");
        assert!(parsed.image.is_empty());
    }

    #[test]
    fn update_preset_schema_has_no_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(UpdatePresetBody)).unwrap();

        assert!(
            schema.get("required").is_none(),
            "PATCH body stays all-optional"
        );
    }

    #[test]
    fn rest_update_patch_presence_table_is_pinned() {
        let absent: UpdatePresetBody = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(absent.slug.is_none());
        assert!(absent.secret_project.is_none());
        assert!(absent.env_vars.is_none());

        let empty: UpdatePresetBody = serde_json::from_value(serde_json::json!({
            "slug": "",
            "secret_project": "",
            "env_vars": {}
        }))
        .unwrap();
        assert_eq!(empty.slug.as_deref(), Some(""));
        assert_eq!(empty.secret_project.as_deref(), Some(""));
        assert_eq!(empty.env_vars, Some(BTreeMap::new()));

        let value: UpdatePresetBody = serde_json::from_value(serde_json::json!({
            "slug": "rust",
            "secret_project": "workspace-secrets",
            "env_vars": {"RUST_LOG": "debug"}
        }))
        .unwrap();
        assert_eq!(value.slug.as_deref(), Some("rust"));
        assert_eq!(value.secret_project.as_deref(), Some("workspace-secrets"));
        assert_eq!(
            value
                .env_vars
                .as_ref()
                .and_then(|vars| vars.get("RUST_LOG"))
                .map(String::as_str),
            Some("debug")
        );
    }

    #[test]
    fn update_preset_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpdatePresetBody>(serde_json::json!({
                "default_cpu_millicores": "2000"
            }))
        else {
            panic!("expected type-invalid CPU to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/default_cpu_millicores");
        assert!(errors[0].message.contains("integer"));
    }
}
