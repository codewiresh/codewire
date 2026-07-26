//! Environment-create preparation surface (#38 slice 3b) — port of
//! `environment_create.go` (options + draft preparation) and
//! `environment_create_stream.go` (the raw SSE/sync prepare handler),
//! plus the standalone detect endpoint from `detect.go`.
//!
//! Wire notes:
//! - `/environment-create/options` and `/environment-create/detect`
//!   are huma handlers in Go: errors are CodedError / plain huma
//!   envelopes (the `$schema` field is the accepted drift).
//! - `/environment-create/prepare` is a RAW chi handler in Go: its
//!   auth/org/body failures are `http.Error` text/plain bodies like
//!   `{"error":"unauthorized"}`, its sync success is plain
//!   `json.NewEncoder` output (trailing newline, no `$schema`), and
//!   its draft errors are `writeCodedError` `{"code","message"}`
//!   objects — all reproduced byte-for-byte here.

use std::convert::Infallible;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use codewire_server_core::auth::{AuthUser, authenticate};
use codewire_server_core::org::user_org_role;
use codewire_server_core::{AppError, AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use super::ApiState;
use super::create::{CreateEnvironmentBody, SetupConfig, normalize_create_environment_body};
use super::detect::{
    self, DetectionResult, apply_detection_workspace_defaults, call_claude_detect,
    call_claude_detect_multi_repo, fetch_all_repo_contexts, fetch_repo_context,
    fixup_detection_result, parse_repo_url, resolve_forge_token,
};
use super::environments::{coded, coded_owned, format_time, require_org_member};
use super::secret_projects::SecretProject;

// ── Wire types ──────────────────────────────────────────────────────────

/// Mirrors `api.Preset` field-for-field (the full wire shape).
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct PresetWire {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub official: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub build_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_error: Option<String>,
    pub default_cpu_millicores: i32,
    pub default_memory_mb: i32,
    pub default_disk_gb: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_ttl_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_setup_config: Option<SetupConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_project_id: Option<String>,
    pub created_at: String,
}

const PRESET_SELECT: &str = r#"SELECT et.id, et.org_id, et.name, et.slug, et.language, et.official,
        et.description, et.build_status, et.build_error,
        et.default_cpu_millicores, et.default_memory_mb, et.default_disk_gb, et.default_ttl_seconds,
        et.created_at,
        stc.image_ref,
        et.default_setup_config,
        et.default_secret_project_id
   FROM environment_presets et
   LEFT JOIN sandbox_template_config stc ON stc.preset_id = et.id"#;

fn scan_preset(row: &sqlx::postgres::PgRow) -> Result<PresetWire, sqlx::Error> {
    let setup_json: Option<serde_json::Value> = row.try_get("default_setup_config")?;
    // Go: invalid JSON is silently dropped (best-effort decode).
    let default_setup_config =
        setup_json.and_then(|v| serde_json::from_value::<SetupConfig>(v).ok());
    Ok(PresetWire {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        name: row.try_get("name")?,
        slug: row.try_get("slug")?,
        language: row.try_get("language")?,
        official: row.try_get("official")?,
        description: row.try_get("description")?,
        build_status: row.try_get("build_status")?,
        build_error: row.try_get("build_error")?,
        default_cpu_millicores: row.try_get("default_cpu_millicores")?,
        default_memory_mb: row.try_get("default_memory_mb")?,
        default_disk_gb: row.try_get("default_disk_gb")?,
        default_ttl_seconds: row.try_get("default_ttl_seconds")?,
        image: row.try_get("image_ref")?,
        default_setup_config,
        secret_project_id: row.try_get("default_secret_project_id")?,
        created_at: format_time(row.try_get("created_at")?),
    })
}

/// Mirrors `getPreset` (full wire shape).
pub(crate) async fn get_preset_wire(
    pool: &PgPool,
    preset_id: &str,
) -> Result<PresetWire, sqlx::Error> {
    let sql = format!("{PRESET_SELECT} WHERE et.id = $1");
    let row = sqlx::query(&sql).bind(preset_id).fetch_one(pool).await?;
    scan_preset(&row)
}

/// Mirrors `getPresetBySlug` (org presets first, then official).
async fn get_preset_by_slug_wire(
    pool: &PgPool,
    org_id: &str,
    slug: &str,
) -> Result<PresetWire, sqlx::Error> {
    let sql = format!(
        r#"{PRESET_SELECT}
           WHERE et.slug = $1 AND (et.org_id = $2 OR (et.official = true AND et.org_id IS NULL))
           ORDER BY CASE WHEN et.org_id = $2 THEN 0 ELSE 1 END
           LIMIT 1"#
    );
    let row = sqlx::query(&sql)
        .bind(slug)
        .bind(org_id)
        .fetch_one(pool)
        .await?;
    scan_preset(&row)
}

/// Mirrors `listPresets` (org-specific + official).
pub(crate) async fn list_presets(
    pool: &PgPool,
    org_id: &str,
) -> Result<Vec<PresetWire>, sqlx::Error> {
    let sql = format!(
        r#"{PRESET_SELECT}
           WHERE (et.org_id = $1 OR (et.official = true AND et.org_id IS NULL))
           ORDER BY et.official DESC, et.created_at DESC"#
    );
    sqlx::query(&sql)
        .bind(org_id)
        .fetch_all(pool)
        .await?
        .iter()
        .map(scan_preset)
        .collect()
}

/// Mirrors `listSecretProjects`.
pub(crate) async fn list_secret_projects(
    pool: &PgPool,
    org_id: &str,
) -> Result<Vec<SecretProject>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT id, org_id, name, created_at
           FROM secret_projects WHERE org_id = $1 ORDER BY name"#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(SecretProject {
                id: r.try_get("id")?,
                org_id: r.try_get("org_id")?,
                name: r.try_get("name")?,
                secret_count: 0,
                created_at: format_time(r.try_get("created_at")?),
            })
        })
        .collect()
}

/// Mirrors `api.RepoConfig` (setup_config is raw JSON; updated_at is
/// Go `formatTime` — the Go handlers' string scan of the timestamp
/// column 500'd against the current schema and was fixed to this).
#[derive(Debug, Clone, Serialize)]
pub struct RepoConfig {
    pub id: String,
    pub org_id: String,
    pub repo_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset_id: Option<String>,
    pub setup_config: serde_json::Value,
    pub created_by: String,
    pub updated_at: String,
}

/// Mirrors `lookupRepoConfig`. Ok(None) = no saved config.
async fn lookup_repo_config(
    pool: &PgPool,
    org_id: &str,
    repo_url: &str,
) -> Result<Option<RepoConfig>, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT id, org_id, repo_url, preset_id, setup_config, created_by, updated_at
           FROM repo_configs WHERE org_id = $1 AND repo_url = $2"#,
    )
    .bind(org_id)
    .bind(repo_url)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(RepoConfig {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        repo_url: row.try_get("repo_url")?,
        preset_id: row.try_get("preset_id")?,
        setup_config: row
            .try_get::<Option<serde_json::Value>, _>("setup_config")?
            .unwrap_or(serde_json::Value::Null),
        created_by: row.try_get("created_by")?,
        updated_at: format_time(row.try_get("updated_at")?),
    }))
}

// ── Creation options (GET .../environment-create/options) ──────────────

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct EnvironmentCreateGitHubStatus {
    pub connected: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EnvironmentCreateOptionsBody {
    pub github_status: EnvironmentCreateGitHubStatus,
    pub presets: Vec<PresetWire>,
    pub secret_projects: Vec<SecretProject>,
}

/// Mirrors `getEnvironmentCreateOptions`.
pub async fn get_create_options(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<Json<EnvironmentCreateOptionsBody>> {
    Ok(Json(
        get_environment_create_options_core(&state, &user, &org_id).await?,
    ))
}

pub(crate) async fn get_environment_create_options_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<EnvironmentCreateOptionsBody> {
    require_org_member(&state.pool, user, org_id).await?;

    let presets = list_presets(&state.pool, org_id).await.map_err(|e| {
        tracing::error!(error = %e, "list presets failed");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list presets",
        )
    })?;
    let secret_projects = list_secret_projects(&state.pool, org_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list secret projects failed");
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to list secret projects",
            )
        })?;

    let mut github_status = EnvironmentCreateGitHubStatus::default();
    let row = sqlx::query(
        r#"SELECT github_username, installation_id,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS connected_at
           FROM user_github_tokens WHERE user_id = $1"#,
    )
    .bind(&user.user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "github status query failed");
        coded(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "failed to load GitHub status")
    })?;
    if let Some(row) = row {
        github_status.connected = true;
        github_status.username = row
            .try_get::<Option<String>, _>("github_username")
            .ok()
            .flatten()
            .unwrap_or_default();
        github_status.installation_id = row.try_get("installation_id").ok().flatten();
        github_status.connected_at = row.try_get("connected_at").ok().flatten();
    }

    Ok(EnvironmentCreateOptionsBody {
        github_status,
        presets,
        secret_projects,
    })
}

// ── Draft preparation (shared by sync + SSE prepare) ───────────────────

/// Mirrors `PrepareEnvironmentCreateBody` — CreateEnvironmentBody plus
/// the `analyze` toggle.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PrepareBody {
    #[serde(flatten)]
    pub body: CreateEnvironmentBody,
    #[serde(default)]
    pub analyze: Option<bool>,
}

/// Mirrors `shouldAnalyzeEnvironmentCreateDraft`.
fn should_analyze(analyze: Option<bool>, body: &CreateEnvironmentBody) -> bool {
    if let Some(a) = analyze {
        return a;
    }
    if body.repo_url.is_empty() {
        return false;
    }
    if !body.image.is_empty() || !body.preset_slug.is_empty() {
        return false;
    }
    body.preset_id.as_deref().unwrap_or_default().is_empty()
}

/// Mirrors `applySetupConfigDefaults` (saved repo config fills gaps).
fn apply_setup_config_defaults(body: &mut CreateEnvironmentBody, cfg: SetupConfig) {
    if body.repo_url.is_empty() && !cfg.repo_url.is_empty() {
        body.repo_url = cfg.repo_url;
    }
    if body.branch.is_empty() && !cfg.branch.is_empty() {
        body.branch = cfg.branch;
    }
    if body.repos.is_empty() && !cfg.repos.is_empty() {
        body.repos = cfg.repos;
    }
    if body.install_command.is_empty() {
        body.install_command = cfg.install_command;
    }
    if body.startup_script.is_empty() {
        body.startup_script = cfg.startup_script;
    }
    if body.env_vars.is_empty() && !cfg.env_vars.is_empty() {
        body.env_vars = cfg.env_vars;
    }
    if body.agents.is_empty() && !cfg.agents.is_empty() {
        body.agents = cfg.agents;
    }
    if body.install_agents.is_none() {
        body.install_agents = cfg.install_agents;
    }
    if body.agent.is_empty() {
        body.agent = cfg.agent;
    }
    if body.agent_env.is_empty() && !cfg.agent_env.is_empty() {
        body.agent_env = cfg.agent_env;
    }
    if body.app_ports.is_empty() && !cfg.app_ports.is_empty() {
        body.app_ports = cfg.app_ports;
    }
    if body.include_org_secrets.is_none() {
        body.include_org_secrets = cfg.include_org_secrets;
    }
    if body.include_user_secrets.is_none() {
        body.include_user_secrets = cfg.include_user_secrets;
    }
}

/// Mirrors `PrepareEnvironmentCreateResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct PrepareResponse {
    pub draft: CreateEnvironmentBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_preset: Option<PresetWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_config: Option<RepoConfig>,
}

/// Typed prepare feed shared by the raw SSE and Connect renderers.
#[derive(Debug, Clone)]
pub(crate) enum PrepareStreamEvent {
    Progress {
        phase: String,
        message: String,
        total: Option<i32>,
        repo: Option<String>,
    },
    RepoFetched {
        index: i32,
        repo: String,
        ok: bool,
    },
    Complete(Box<PrepareResponse>),
}

pub(crate) type PrepareStreamItem = Result<PrepareStreamEvent, AppError>;
pub(crate) type PrepareStreamRx = tokio::sync::mpsc::UnboundedReceiver<PrepareStreamItem>;

/// Progress event sink (Go: `PrepareProgressFunc`); None = sync.
type ProgressTx = Option<tokio::sync::mpsc::UnboundedSender<PrepareStreamItem>>;

fn emit_progress(
    progress: &ProgressTx,
    phase: &str,
    message: &str,
    total: Option<i32>,
    repo: Option<&str>,
) {
    if let Some(tx) = progress {
        let _ = tx.send(Ok(PrepareStreamEvent::Progress {
            phase: phase.to_owned(),
            message: message.to_owned(),
            total,
            repo: repo.map(str::to_owned),
        }));
    }
}

fn emit_repo_fetched(progress: &ProgressTx, index: i32, repo: &str, ok: bool) {
    if let Some(tx) = progress {
        let _ = tx.send(Ok(PrepareStreamEvent::RepoFetched {
            index,
            repo: repo.to_owned(),
            ok,
        }));
    }
}

/// Mirrors `prepareEnvironmentCreateDraft`. Errors carry the
/// `CodedError` code + detail that `writeCodedError` / the SSE `error`
/// event serialize.
async fn prepare_draft(
    state: &ApiState,
    org_id: &str,
    user_id: &str,
    mut body: CreateEnvironmentBody,
    analyze: bool,
    progress: &ProgressTx,
) -> Result<PrepareResponse, AppError> {
    let pool = &state.pool;
    normalize_create_environment_body(&mut body);

    let mut applied_repo_config: Option<RepoConfig> = None;
    if !body.repo_url.is_empty() {
        emit_progress(
            progress,
            "repo_config",
            "Checking saved configuration...",
            None,
            None,
        );
        match lookup_repo_config(pool, org_id, &body.repo_url).await {
            Err(e) => {
                tracing::error!(error = %e, "lookup repo config failed");
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to lookup repo config",
                ));
            }
            Ok(Some(rc)) => {
                if body.preset_id.is_none() && rc.preset_id.is_some() {
                    body.preset_id = rc.preset_id.clone();
                }
                if let Ok(cfg) = serde_json::from_value::<SetupConfig>(rc.setup_config.clone()) {
                    apply_setup_config_defaults(&mut body, cfg);
                    normalize_create_environment_body(&mut body);
                }
                applied_repo_config = Some(rc);
            }
            Ok(None) => {}
        }
    }

    emit_progress(progress, "resolving", "Resolving preset...", None, None);

    let mut resolved_preset: Option<PresetWire> = None;
    if let Some(preset_id) = body.preset_id.clone().filter(|s| !s.is_empty()) {
        let preset = get_preset_wire(pool, &preset_id).await.map_err(|_| {
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
        resolved_preset = Some(preset);
    }
    if resolved_preset.is_none() && !body.preset_slug.is_empty() {
        let preset = get_preset_by_slug_wire(pool, org_id, &body.preset_slug)
            .await
            .map_err(|_| {
                coded_owned(
                    StatusCode::BAD_REQUEST,
                    "preset_not_found",
                    format!("preset not found: {}", body.preset_slug),
                )
            })?;
        resolved_preset = Some(preset);
    }

    if !analyze || body.repo_url.is_empty() {
        return Ok(PrepareResponse {
            draft: body,
            detection: None,
            resolved_preset,
            repo_config: applied_repo_config,
        });
    }
    if !body.image.is_empty() || resolved_preset.is_some() {
        return Ok(PrepareResponse {
            draft: body,
            detection: None,
            resolved_preset,
            repo_config: applied_repo_config,
        });
    }
    if state.anthropic_api_key.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "ai_detection_unavailable",
            "AI detection not configured; provide an image or preset",
        ));
    }

    let detection: DetectionResult = if body.repos.len() > 1 {
        // Multi-repo: parallel fetch + unified detection.
        emit_progress(
            progress,
            "repo_fetch",
            "Fetching repository context...",
            Some(i32::try_from(body.repos.len()).unwrap_or(i32::MAX)),
            None,
        );
        let entries = fetch_all_repo_contexts(
            pool,
            &state.github_cfg,
            state.secrets.as_ref(),
            user_id,
            &body.repos,
        )
        .await;
        for (index, e) in entries.iter().enumerate() {
            emit_repo_fetched(
                progress,
                i32::try_from(index).unwrap_or(i32::MAX),
                &e.url,
                e.error.is_none(),
            );
        }
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

        emit_progress(
            progress,
            "analyzing",
            "Analyzing repositories...",
            None,
            None,
        );
        let multi = call_claude_detect_multi_repo(&state.anthropic_api_key, &entries)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "detect: multi-repo LLM analysis failed");
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
        emit_progress(
            progress,
            "repo_fetch",
            "Fetching repository context...",
            None,
            Some(&body.repo_url),
        );
        let r = parse_repo_url(&body.repo_url).map_err(|e| {
            coded_owned(
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
                let msg = e.to_string();
                let code: &'static str = if is_repo_not_found(&msg) {
                    "repo_not_found"
                } else {
                    "repo_not_accessible"
                };
                coded_owned(
                    StatusCode::BAD_GATEWAY,
                    code,
                    format!("failed to fetch repo: {msg}"),
                )
            })?;

        emit_progress(progress, "analyzing", "Analyzing repository...", None, None);
        let mut detected =
            call_claude_detect(&state.anthropic_api_key, &r.owner, &r.repo, &repo_ctx)
                .await
                .map_err(|_| {
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
        body.install_command = detection.install_command.clone();
    }
    if body.app_ports.is_empty() && !detection.app_ports.is_empty() {
        body.app_ports = detection.app_ports.clone();
    }
    if body.agents.is_empty() && !detection.agents.is_empty() {
        body.agents = detection.agents.clone();
    }
    if body.install_agents.is_none() {
        body.install_agents = detection.install_agents;
    }
    if body.startup_script.is_empty() {
        body.startup_script = detection.startup_script.clone();
    }
    if body.name.is_none() && !detection.suggested_name.is_empty() {
        body.name = Some(detection.suggested_name.clone());
    }
    if body.secret_project.is_empty() && !detection.secret_project.is_empty() {
        body.secret_project = detection.secret_project.clone();
    }
    if body.include_org_secrets.is_none() {
        body.include_org_secrets = detection.include_org_secrets;
    }
    if body.include_user_secrets.is_none() {
        body.include_user_secrets = detection.include_user_secrets;
    }
    if body.preset_slug.is_empty() && !detection.preset_slug.is_empty() {
        body.preset_slug = detection.preset_slug.clone();
    }
    if body.image.is_empty() && !detection.preset_image.is_empty() {
        body.image = detection.preset_image.clone();
    }

    if !body.preset_slug.is_empty()
        && let Ok(p) = get_preset_by_slug_wire(pool, org_id, &body.preset_slug).await
    {
        resolved_preset = Some(p);
    }

    Ok(PrepareResponse {
        draft: body,
        detection: Some(detection),
        resolved_preset,
        repo_config: applied_repo_config,
    })
}

/// Mirrors `isRepoNotFound`.
fn is_repo_not_found(msg: &str) -> bool {
    msg.contains("404") || msg.to_lowercase().contains("not found")
}

/// Starts one typed prepare run. Both streaming wire renderers consume this
/// exact source so progress ordering and terminal behavior cannot diverge.
pub(crate) fn start_prepare_stream(
    state: ApiState,
    org_id: String,
    user_id: String,
    body: CreateEnvironmentBody,
    analyze: Option<bool>,
) -> PrepareStreamRx {
    let analyze = should_analyze(analyze, &body);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<PrepareStreamItem>();
    let progress: ProgressTx = Some(tx.clone());
    tokio::spawn(async move {
        let item = match prepare_draft(&state, &org_id, &user_id, body, analyze, &progress).await {
            Ok(response) => Ok(PrepareStreamEvent::Complete(Box::new(response))),
            Err(error) => Err(error),
        };
        let _ = tx.send(item);
    });
    rx
}

/// Frozen raw-SSE renderer for a typed prepare event.
pub(crate) fn prepare_sse_frame(event: &PrepareStreamEvent) -> String {
    let (name, payload) = match event {
        PrepareStreamEvent::Progress {
            phase,
            message,
            total,
            repo,
        } => {
            // Go marshals map[string]any here. serde_json's default map keeps
            // keys sorted, retaining the accepted byte order.
            let mut payload = serde_json::json!({ "phase": phase, "message": message });
            let object = payload
                .as_object_mut()
                .expect("static progress payload is an object");
            if let Some(total) = total {
                object.insert("total".into(), (*total).into());
            }
            if let Some(repo) = repo {
                object.insert("repo".into(), repo.clone().into());
            }
            ("progress", payload.to_string())
        }
        PrepareStreamEvent::RepoFetched { index, repo, ok } => (
            "repo_fetched",
            serde_json::json!({
                "phase": "repo_fetch",
                "message": "",
                "index": index,
                "repo": repo,
                "ok": ok,
            })
            .to_string(),
        ),
        PrepareStreamEvent::Complete(response) => (
            "complete",
            serde_json::to_string(response).unwrap_or_else(|_| "null".to_owned()),
        ),
    };
    format!("event: {name}\ndata: {payload}\n\n")
}

fn prepare_sse_error_frame(error: &AppError) -> String {
    let (code, message) = match error {
        AppError::Coded { code, detail, .. } => (*code, detail.to_string()),
        other => ("INTERNAL_ERROR", other.to_string()),
    };
    let payload = serde_json::json!({ "code": code, "message": message }).to_string();
    format!("event: error\ndata: {payload}\n\n")
}

// ── Raw prepare handler (sync JSON + SSE) ───────────────────────────────

/// `http.Error` parity: text/plain + nosniff + trailing newline.
pub(crate) fn plain_error(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(format!("{body}\n")))
        .expect("static response")
}

/// `json.NewEncoder(w).Encode` parity: application/json + trailing \n.
pub(crate) fn json_response(status: StatusCode, value: &impl Serialize) -> Response {
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .expect("static response")
}

/// `writeCodedError` parity: `{"code","message"}` with the coded status.
fn coded_error_response(err: &AppError) -> Response {
    let (status, code, message) = match err {
        AppError::Coded {
            status,
            code,
            detail,
        } => (*status, *code, detail.to_string()),
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            other.to_string(),
        ),
    };
    json_response(
        status,
        &serde_json::json!({ "code": code, "message": message }),
    )
}

/// `POST /api/v1/organizations/{org_id}/environment-create/prepare` —
/// mirrors `prepareEnvironmentCreateHandler` (raw: SSE when the client
/// sends `Accept: text/event-stream`, sync JSON otherwise).
pub async fn prepare_environment_create(
    State(state): State<ApiState>,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Response {
    // Manual auth, mirroring auth.AuthenticateRequest in the raw handler.
    let session_token = read_session_cookie(&headers);
    let bearer = read_bearer(&headers);
    let user = match authenticate(&state.auth, session_token.as_deref(), bearer.as_deref()).await {
        Ok(u) => u,
        Err(err) if err.is_forbidden() => {
            return plain_error(StatusCode::FORBIDDEN, r#"{"error":"forbidden"}"#);
        }
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
    };

    match user_org_role(&state.pool, &user, &org_id).await {
        Ok(Some(_)) => {}
        _ => {
            return plain_error(
                StatusCode::NOT_FOUND,
                r#"{"error":"organization not found"}"#,
            );
        }
    }

    let input: PrepareBody = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => {
            return plain_error(
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid request body"}"#,
            );
        }
    };

    let analyze = should_analyze(input.analyze, &input.body);
    let wants_sse = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/event-stream"));

    if !wants_sse {
        return match prepare_draft(&state, &org_id, &user.user_id, input.body, analyze, &None).await
        {
            Ok(resp) => json_response(StatusCode::OK, &resp),
            Err(e) => coded_error_response(&e),
        };
    }

    // SSE streaming mode renders the shared typed prepare source with the
    // byte-frozen `event: NAME\ndata: JSON\n\n` framing.
    let rx = start_prepare_stream(state, org_id, user.user_id, input.body, input.analyze);

    let stream = futures::stream::unfold(rx, |mut rx| async move {
        let item = rx.recv().await?;
        let frame = match item {
            Ok(event) => prepare_sse_frame(&event),
            Err(error) => {
                tracing::error!(error = %error, "prepare stream: draft failed");
                prepare_sse_error_frame(&error)
            }
        };
        Some((Ok::<_, Infallible>(frame), rx))
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .expect("sse response")
}

pub(crate) fn read_session_cookie(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookies.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("codewire.session_token=") {
            return Some(v.to_string());
        }
    }
    None
}

pub(crate) fn read_bearer(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(str::to_string)
}

// ── Detect endpoint (POST /environment-create/detect) ──────────────────

/// Mirrors `api.DetectRequest`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DetectRequest {
    pub repo_url: String,
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub github_token: String,
}

/// Mirrors `detectEnvironmentRepo` — plain huma errors (no code/hint).
pub async fn detect_environment_repo(
    State(state): State<ApiState>,
    user: AuthUser,
    ValidatedJson(input): ValidatedJson<DetectRequest>,
) -> AppResult<Json<DetectionResult>> {
    Ok(Json(
        detect_environment_repo_core(&state, &user, input).await?,
    ))
}

pub(crate) async fn detect_environment_repo_core(
    state: &ApiState,
    user: &AuthUser,
    input: DetectRequest,
) -> AppResult<DetectionResult> {
    if state.anthropic_api_key.is_empty() {
        return Err(AppError::ServiceUnavailable(
            "AI detection is not configured".into(),
        ));
    }

    let r = parse_repo_url(&input.repo_url)
        .map_err(|e| AppError::BadRequest(format!("invalid repo URL: {e}").into()))?;

    // Client-supplied token > user-stored > org-level secrets.
    let forge_token = if input.github_token.is_empty() {
        resolve_forge_token(
            &state.pool,
            &state.github_cfg,
            state.secrets.as_ref(),
            &user.user_id,
            &r.host,
        )
        .await
    } else {
        input.github_token
    };

    let repo_ctx = fetch_repo_context(&r, &input.branch, &forge_token).await.map_err(|e| {
        tracing::warn!(error = %e, owner = r.owner, repo = r.repo, "detect: failed to fetch repo context");
        AppError::Upstream(format!("failed to fetch repo: {e}").into())
    })?;

    // codewire.yaml short-circuits Claude detection.
    if let Some(cw_yaml) = repo_ctx.config_files.get("codewire.yaml") {
        match detect::parse_codewire_yaml(cw_yaml, &r.repo) {
            Ok(result) => {
                tracing::info!(
                    owner = r.owner,
                    repo = r.repo,
                    "detect: using codewire.yaml from repo"
                );
                return Ok(result);
            }
            Err(e) => {
                tracing::warn!(error = %e, "detect: failed to parse codewire.yaml, falling back to AI");
            }
        }
    }

    let mut result = call_claude_detect(&state.anthropic_api_key, &r.owner, &r.repo, &repo_ctx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "detect: LLM analysis failed");
            AppError::InternalMsg("AI analysis failed".into())
        })?;
    fixup_detection_result(&mut result, &repo_ctx);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn analyze_gate_mirrors_go() {
        let body =
            |repo: &str, image: &str, slug: &str, preset: Option<&str>| CreateEnvironmentBody {
                repo_url: repo.into(),
                image: image.into(),
                preset_slug: slug.into(),
                preset_id: preset.map(str::to_string),
                ..Default::default()
            };
        // Explicit toggle wins.
        assert!(should_analyze(Some(true), &body("", "", "", None)));
        assert!(!should_analyze(
            Some(false),
            &body("https://github.com/a/b", "", "", None)
        ));
        // No repo → no analysis.
        assert!(!should_analyze(None, &body("", "", "", None)));
        // Repo with image/slug/preset already pinned → no analysis.
        assert!(!should_analyze(
            None,
            &body("https://github.com/a/b", "img", "", None)
        ));
        assert!(!should_analyze(
            None,
            &body("https://github.com/a/b", "", "go", None)
        ));
        assert!(!should_analyze(
            None,
            &body("https://github.com/a/b", "", "", Some("p1"))
        ));
        assert!(should_analyze(
            None,
            &body("https://github.com/a/b", "", "", Some(""))
        ));
        assert!(should_analyze(
            None,
            &body("https://github.com/a/b", "", "", None)
        ));
    }

    #[test]
    fn setup_config_defaults_fill_gaps_only() {
        let mut body = CreateEnvironmentBody {
            install_command: "bun install".into(),
            ..Default::default()
        };
        apply_setup_config_defaults(
            &mut body,
            SetupConfig {
                repo_url: "https://github.com/a/b".into(),
                install_command: "npm install".into(),
                startup_script: "make dev".into(),
                install_agents: Some(true),
                ..Default::default()
            },
        );
        assert_eq!(body.repo_url, "https://github.com/a/b");
        // Existing value wins.
        assert_eq!(body.install_command, "bun install");
        assert_eq!(body.startup_script, "make dev");
        assert_eq!(body.install_agents, Some(true));
    }

    #[test]
    fn prepare_body_parses_flat_json() {
        let p: PrepareBody = serde_json::from_str(
            r#"{"repo_url":"https://github.com/a/b","analyze":false,"name":"x"}"#,
        )
        .unwrap();
        assert_eq!(p.body.repo_url, "https://github.com/a/b");
        assert_eq!(p.analyze, Some(false));
        assert_eq!(p.body.name.as_deref(), Some("x"));
    }

    #[test]
    fn detect_request_schema_requires_go_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(DetectRequest)).unwrap();

        assert_eq!(
            schema["required"],
            serde_json::json!(["repo_url"]),
            "Go/huma marks only repo_url required"
        );
    }

    #[test]
    fn detect_request_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<DetectRequest>(serde_json::json!({
                "branch": "main"
            }))
        else {
            panic!("expected missing repo_url to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("repo_url"));
    }

    #[test]
    fn detect_request_validation_keeps_branch_and_token_optional() {
        let parsed = validate_value::<DetectRequest>(serde_json::json!({
            "repo_url": "https://github.com/codewiresh/codewire"
        }))
        .expect("branch and github_token stay optional");

        assert_eq!(parsed.repo_url, "https://github.com/codewiresh/codewire");
        assert!(parsed.branch.is_empty());
        assert!(parsed.github_token.is_empty());
    }

    #[test]
    fn http_error_and_encoder_parity() {
        let r = plain_error(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let r = json_response(StatusCode::OK, &serde_json::json!({"status":"ok"}));
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }
}
