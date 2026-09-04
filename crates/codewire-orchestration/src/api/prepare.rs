//! Shared environment-creation preparation and detection service logic.

use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use serde::Serialize;
use sqlx::{PgPool, Row};

use super::ApiState;
use super::create::{
    CreateEnvironmentBody, SetupConfig, apply_detection_defaults, apply_project_spec_defaults,
    ensure_no_legacy_preset_secret_delivery, ensure_no_legacy_secret_delivery,
    ensure_no_legacy_setup_secret_delivery, normalize_create_environment_body,
    synchronize_project_spec,
};
use super::detect::{
    self, DetectionResult, apply_detection_workspace_defaults, call_claude_detect,
    call_claude_detect_multi_repo, fetch_all_repo_contexts, fetch_repo_context,
    fixup_detection_result, parse_repo_url,
};
use super::environments::{coded, coded_owned, format_time, require_org_member};
use super::secret_projects::SecretProject;

// ── Wire types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PresetWire {
    pub id: String,
    pub org_id: Option<String>,
    pub name: String,
    pub slug: Option<String>,
    pub language: Option<String>,
    pub official: bool,
    pub description: Option<String>,
    pub build_status: String,
    pub build_error: Option<String>,
    pub default_cpu_millicores: i32,
    pub default_memory_mb: i32,
    pub default_disk_gb: i32,
    pub default_ttl_seconds: Option<i32>,
    pub image: Option<String>,
    pub default_setup_config: Option<SetupConfig>,
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

#[derive(Debug, Clone)]
pub struct RepoConfig {
    pub id: String,
    pub org_id: String,
    pub repo_url: String,
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

#[derive(Debug, Default)]
pub struct EnvironmentCreateGitHubStatus {
    pub connected: bool,
    pub username: String,
    pub installation_id: Option<i64>,
    pub connected_at: Option<String>,
}

#[derive(Debug)]
pub struct EnvironmentCreateOptionsBody {
    pub github_status: EnvironmentCreateGitHubStatus,
    pub presets: Vec<PresetWire>,
    pub secret_projects: Vec<SecretProject>,
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

/// Selects automatic analysis when a repository-based draft has no explicit
/// image or preset choice.
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
fn apply_setup_config_defaults(
    body: &mut CreateEnvironmentBody,
    cfg: SetupConfig,
) -> AppResult<()> {
    ensure_no_legacy_secret_delivery(body)?;
    ensure_no_legacy_setup_secret_delivery(&cfg)?;
    if body.project_spec.is_none() {
        body.project_spec = cfg.project_spec;
    }
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
    if body.app_ports.is_empty() && !cfg.app_ports.is_empty() {
        body.app_ports = cfg.app_ports;
    }
    if body.include_org_secrets.is_none() {
        body.include_org_secrets = cfg.include_org_secrets;
    }
    if body.include_user_secrets.is_none() {
        body.include_user_secrets = cfg.include_user_secrets;
    }
    Ok(())
}

fn ensure_resolved_preset_secret_delivery(preset: Option<&PresetWire>) -> AppResult<()> {
    let Some(preset) = preset else {
        return Ok(());
    };
    if let Some(config) = preset.default_setup_config.as_ref() {
        ensure_no_legacy_setup_secret_delivery(config)?;
    }
    ensure_no_legacy_preset_secret_delivery(preset.secret_project_id.as_deref())
}

#[derive(Debug, Clone)]
pub struct PrepareResponse {
    pub draft: CreateEnvironmentBody,
    pub detection: Option<DetectionResult>,
    pub resolved_preset: Option<PresetWire>,
    pub repo_config: Option<RepoConfig>,
}

/// Typed prepare feed consumed by the Connect stream.
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
    mut body: CreateEnvironmentBody,
    analyze: bool,
    progress: &ProgressTx,
) -> Result<PrepareResponse, AppError> {
    let pool = &state.pool;
    ensure_no_legacy_secret_delivery(&body)?;
    apply_project_spec_defaults(&mut body)?;
    normalize_create_environment_body(&mut body);
    synchronize_project_spec(&mut body)?;

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
                    apply_setup_config_defaults(&mut body, cfg)?;
                    apply_project_spec_defaults(&mut body)?;
                    normalize_create_environment_body(&mut body);
                    synchronize_project_spec(&mut body)?;
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
    ensure_resolved_preset_secret_delivery(resolved_preset.as_ref())?;

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
        let entries = fetch_all_repo_contexts(&body.repos).await;
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
        let repo_ctx = fetch_repo_context(&r, &body.branch).await.map_err(|e| {
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

    apply_detection_defaults(&mut body, &detection)?;

    if !body.preset_slug.is_empty()
        && let Ok(p) = get_preset_by_slug_wire(pool, org_id, &body.preset_slug).await
    {
        resolved_preset = Some(p);
    }
    ensure_resolved_preset_secret_delivery(resolved_preset.as_ref())?;

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

/// Starts one typed prepare run for the Connect stream.
pub(crate) fn start_prepare_stream(
    state: ApiState,
    org_id: String,
    body: CreateEnvironmentBody,
    analyze: Option<bool>,
) -> PrepareStreamRx {
    let analyze = should_analyze(analyze, &body);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<PrepareStreamItem>();
    let progress: ProgressTx = Some(tx.clone());
    tokio::spawn(async move {
        let item = match prepare_draft(&state, &org_id, body, analyze, &progress).await {
            Ok(response) => Ok(PrepareStreamEvent::Complete(Box::new(response))),
            Err(error) => Err(error),
        };
        let _ = tx.send(item);
    });
    rx
}

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
// ── Detect endpoint (POST /environment-create/detect) ──────────────────

#[derive(Debug)]
pub struct DetectRequest {
    pub repo_url: String,
    pub branch: String,
}
pub(crate) async fn detect_environment_repo_core(
    state: &ApiState,
    input: DetectRequest,
) -> AppResult<DetectionResult> {
    if state.anthropic_api_key.is_empty() {
        return Err(AppError::ServiceUnavailable(
            "AI detection is not configured".into(),
        ));
    }

    let r = parse_repo_url(&input.repo_url)
        .map_err(|e| AppError::BadRequest(format!("invalid repo URL: {e}").into()))?;

    let repo_ctx = fetch_repo_context(&r, &input.branch).await.map_err(|e| {
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

    fn assert_secret_delivery_pending(error: AppError, forbidden_value: Option<&str>) {
        match error {
            AppError::Coded {
                status,
                code: "secret_delivery_pending",
                detail,
            } => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                if let Some(value) = forbidden_value {
                    assert!(!detail.contains(value));
                }
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    fn preset_with_secret_defaults(
        default_setup_config: Option<SetupConfig>,
        secret_project_id: Option<&str>,
    ) -> PresetWire {
        PresetWire {
            id: "preset-test".to_owned(),
            org_id: Some("org-test".to_owned()),
            name: "Test".to_owned(),
            slug: None,
            language: None,
            official: false,
            description: None,
            build_status: "ready".to_owned(),
            build_error: None,
            default_cpu_millicores: 2000,
            default_memory_mb: 4096,
            default_disk_gb: 10,
            default_ttl_seconds: None,
            image: None,
            default_setup_config,
            secret_project_id: secret_project_id.map(str::to_owned),
            created_at: String::new(),
        }
    }

    #[test]
    fn saved_setup_secret_sources_fail_before_explicit_false_can_mask_them() {
        let configs = [
            SetupConfig {
                include_org_secrets: Some(true),
                ..Default::default()
            },
            SetupConfig {
                include_user_secrets: Some(true),
                ..Default::default()
            },
            SetupConfig {
                project_spec: Some(
                    codewire_project::parse_project_yaml(
                        "secrets: {project: saved-project-secret-value}\n",
                    )
                    .unwrap()
                    .spec,
                ),
                ..Default::default()
            },
        ];
        for config in configs {
            let mut body = CreateEnvironmentBody {
                include_org_secrets: Some(false),
                include_user_secrets: Some(false),
                ..Default::default()
            };
            assert_secret_delivery_pending(
                apply_setup_config_defaults(&mut body, config).unwrap_err(),
                Some("saved-project-secret-value"),
            );
        }

        let mut body = CreateEnvironmentBody::default();
        apply_setup_config_defaults(
            &mut body,
            SetupConfig {
                include_org_secrets: Some(false),
                include_user_secrets: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(body.include_org_secrets, Some(false));
        assert_eq!(body.include_user_secrets, Some(false));
    }

    #[test]
    fn resolved_preset_secret_defaults_fail_closed() {
        ensure_resolved_preset_secret_delivery(Some(&preset_with_secret_defaults(None, None)))
            .unwrap();

        let preset = preset_with_secret_defaults(None, Some("preset-project-secret-value"));
        assert_secret_delivery_pending(
            ensure_resolved_preset_secret_delivery(Some(&preset)).unwrap_err(),
            Some("preset-project-secret-value"),
        );

        let preset = preset_with_secret_defaults(
            Some(SetupConfig {
                include_user_secrets: Some(true),
                ..Default::default()
            }),
            None,
        );
        assert_secret_delivery_pending(
            ensure_resolved_preset_secret_delivery(Some(&preset)).unwrap_err(),
            None,
        );
    }
}
