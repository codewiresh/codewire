//! Shared environment-creation preparation service logic.

use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use serde::Serialize;
use sqlx::{PgPool, Row};

use super::ApiState;
use super::create::{
    CreateEnvironmentBody, apply_project_spec_defaults, ensure_current_platform_runtime_support,
    ensure_no_secret_delivery, merge_environment_defaults, preset_is_visible_to_org,
    preset_scope_is_well_formed, repository_analysis_pending,
};
use super::environments::{coded, coded_owned, format_time, require_org_member};

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
    pub default_ttl_seconds: Option<i32>,
    pub project_spec: codewire_project::ProjectSpec,
    pub created_at: String,
}

const PRESET_SELECT: &str = r#"SELECT et.id, et.org_id, et.name, et.slug, et.language, et.official,
        et.description, et.build_status, et.build_error,
        et.default_ttl_seconds, et.project_spec, et.created_at
   FROM environment_presets et"#;

fn scan_preset(row: &sqlx::postgres::PgRow) -> anyhow::Result<PresetWire> {
    let org_id: Option<String> = row.try_get("org_id")?;
    let official: bool = row.try_get("official")?;
    if !preset_scope_is_well_formed(org_id.as_deref(), official) {
        anyhow::bail!("preset scope is invalid");
    }
    let project_spec =
        serde_json::from_value::<codewire_project::ProjectSpec>(row.try_get("project_spec")?)?;
    project_spec.validate()?;
    if !project_spec.preset.is_empty() {
        anyhow::bail!("preset project_spec cannot select another preset");
    }
    Ok(PresetWire {
        id: row.try_get("id")?,
        org_id,
        name: row.try_get("name")?,
        slug: row.try_get("slug")?,
        language: row.try_get("language")?,
        official,
        description: row.try_get("description")?,
        build_status: row.try_get("build_status")?,
        build_error: row.try_get("build_error")?,
        default_ttl_seconds: row.try_get("default_ttl_seconds")?,
        project_spec,
        created_at: format_time(row.try_get("created_at")?),
    })
}

/// Mirrors `getPreset` (full wire shape).
pub(crate) async fn get_preset_wire(pool: &PgPool, preset_id: &str) -> anyhow::Result<PresetWire> {
    let sql = format!("{PRESET_SELECT} WHERE et.id = $1");
    let row = sqlx::query(&sql).bind(preset_id).fetch_one(pool).await?;
    scan_preset(&row)
}

/// Mirrors `getPresetBySlug` (org presets first, then official).
async fn get_preset_by_slug_wire(
    pool: &PgPool,
    org_id: &str,
    slug: &str,
) -> anyhow::Result<PresetWire> {
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

fn require_preset_lookup(slug: &str, result: anyhow::Result<PresetWire>) -> AppResult<PresetWire> {
    match result {
        Ok(preset) => Ok(preset),
        Err(error)
            if error
                .downcast_ref::<sqlx::Error>()
                .is_some_and(|source| matches!(source, sqlx::Error::RowNotFound)) =>
        {
            Err(coded_owned(
                StatusCode::BAD_REQUEST,
                "preset_not_found",
                format!("preset not found: {slug}"),
            ))
        }
        Err(_) => Err(coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to resolve preset",
        )),
    }
}

/// Mirrors `listPresets` (org-specific + official).
pub(crate) async fn list_presets(pool: &PgPool, org_id: &str) -> anyhow::Result<Vec<PresetWire>> {
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

#[derive(Debug, Clone)]
pub struct RepoConfig {
    pub id: String,
    pub org_id: String,
    pub repo_url: String,
    pub project_spec: codewire_project::ProjectSpec,
    pub created_by: String,
    pub updated_at: String,
}

/// Mirrors `lookupRepoConfig`. Ok(None) = no saved config.
async fn lookup_repo_config(
    pool: &PgPool,
    org_id: &str,
    repo_url: &str,
) -> anyhow::Result<Option<RepoConfig>> {
    let row = sqlx::query(
        r#"SELECT id, org_id, repo_url, project_spec, created_by, updated_at
           FROM repo_configs WHERE org_id = $1 AND repo_url = $2"#,
    )
    .bind(org_id)
    .bind(repo_url)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let project_spec: codewire_project::ProjectSpec =
        serde_json::from_value(row.try_get("project_spec")?)?;
    project_spec.validate()?;
    Ok(Some(RepoConfig {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        repo_url: row.try_get("repo_url")?,
        project_spec,
        created_by: row.try_get("created_by")?,
        updated_at: format_time(row.try_get("updated_at")?),
    }))
}

#[derive(Debug)]
pub struct EnvironmentCreateOptionsBody {
    pub presets: Vec<PresetWire>,
    pub preview_base_domain: String,
    /// Whether this caller may create a confidential environment here: the
    /// deployment enables it and the organization is opted in (#2497). No
    /// plan or catalog row is involved (#3381).
    pub confidential_available: bool,
}

fn preview_domain_is_valid(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && url::Url::parse(&format!("https://preview.{domain}"))
            .is_ok_and(|url| matches!(url.host(), Some(url::Host::Domain(_))))
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
    let confidential_available = crate::confidential_storage::require_confidential_access(
        &state.pool,
        state.confidential_storage_flags,
        user,
        org_id,
        "confidential",
    )
    .await
    .is_ok();
    Ok(EnvironmentCreateOptionsBody {
        presets,
        preview_base_domain: if preview_domain_is_valid(&state.preview_base_domain) {
            state.preview_base_domain.to_ascii_lowercase()
        } else {
            String::new()
        },
        confidential_available,
    })
}

fn requires_repository_analysis(body: &CreateEnvironmentBody) -> bool {
    !body.project_spec.repositories.is_empty()
        && body.project_spec.image.is_empty()
        && body.project_spec.preset.is_empty()
        && body.preset_id.as_deref().unwrap_or_default().is_empty()
}

fn validate_resolved_preset(preset: Option<&PresetWire>) -> AppResult<()> {
    let Some(preset) = preset else {
        return Ok(());
    };
    if !preset.project_spec.preset.is_empty() {
        return Err(coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_preset",
            "preset project specification cannot select another preset",
        ));
    }
    ensure_no_secret_delivery(&preset.project_spec)
}

#[derive(Debug, Clone)]
pub struct PrepareResponse {
    pub draft: CreateEnvironmentBody,
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

/// Mirrors `prepareEnvironmentCreateDraft`. Errors carry the
/// `CodedError` code + detail that `writeCodedError` / the SSE `error`
/// event serialize.
async fn prepare_draft(
    state: &ApiState,
    org_id: &str,
    mut body: CreateEnvironmentBody,
    requires_analysis: bool,
    progress: &ProgressTx,
) -> Result<PrepareResponse, AppError> {
    let pool = &state.pool;
    apply_project_spec_defaults(&mut body)?;

    let mut applied_repo_config: Option<RepoConfig> = None;
    if let Some(repo_url) = body
        .project_spec
        .repositories
        .first()
        .map(|repository| repository.source.clone())
    {
        emit_progress(
            progress,
            "repo_config",
            "Checking saved configuration...",
            None,
            None,
        );
        match lookup_repo_config(pool, org_id, &repo_url).await {
            Err(e) => {
                tracing::error!(error = %e, "lookup repo config failed");
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to lookup repo config",
                ));
            }
            Ok(Some(rc)) => {
                merge_environment_defaults(&mut body, &rc.project_spec)?;
                apply_project_spec_defaults(&mut body)?;
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
        if !preset_is_visible_to_org(preset.org_id.as_deref(), preset.official, org_id) {
            return Err(coded(
                StatusCode::BAD_REQUEST,
                "preset_not_found",
                "preset does not belong to this organization",
            ));
        }
        resolved_preset = Some(preset);
    }
    if resolved_preset.is_none() && !body.project_spec.preset.is_empty() {
        let preset = require_preset_lookup(
            &body.project_spec.preset,
            get_preset_by_slug_wire(pool, org_id, &body.project_spec.preset).await,
        )?;
        resolved_preset = Some(preset);
    }
    validate_resolved_preset(resolved_preset.as_ref())?;
    if let Some(preset) = resolved_preset.as_ref() {
        merge_environment_defaults(&mut body, &preset.project_spec)?;
    }
    apply_project_spec_defaults(&mut body)?;
    ensure_current_platform_runtime_support(&body)?;

    if requires_analysis && body.project_spec.image.is_empty() && resolved_preset.is_none() {
        return Err(repository_analysis_pending());
    }

    Ok(PrepareResponse {
        draft: body,
        resolved_preset,
        repo_config: applied_repo_config,
    })
}

/// Starts one typed prepare run for the Connect stream.
pub(crate) fn start_prepare_stream(
    state: ApiState,
    org_id: String,
    body: CreateEnvironmentBody,
) -> PrepareStreamRx {
    let requires_analysis = requires_repository_analysis(&body);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<PrepareStreamItem>();
    let progress: ProgressTx = Some(tx.clone());
    tokio::spawn(async move {
        let item = match prepare_draft(&state, &org_id, body, requires_analysis, &progress).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn preset(project_spec: codewire_project::ProjectSpec) -> PresetWire {
        PresetWire {
            id: "preset-test".to_owned(),
            org_id: Some("org-test".to_owned()),
            name: "Test".to_owned(),
            slug: Some("test".to_owned()),
            language: None,
            official: false,
            description: None,
            build_status: "ready".to_owned(),
            build_error: None,
            default_ttl_seconds: None,
            project_spec,
            created_at: String::new(),
        }
    }

    #[test]
    fn environment_create_options_have_presets_and_public_preview_metadata_only() {
        let options = EnvironmentCreateOptionsBody {
            presets: vec![preset(codewire_project::ProjectSpec::default())],
            preview_base_domain: "preview.example.test".into(),
            confidential_available: false,
        };
        assert_eq!(options.presets.len(), 1);
        assert_eq!(options.preview_base_domain, "preview.example.test");
    }

    #[test]
    fn preview_metadata_accepts_only_bounded_dns_suffixes() {
        for domain in ["cwpreview.sh", "codewire-dev.local", "preview.EXAMPLE.test"] {
            assert!(preview_domain_is_valid(domain));
        }
        for domain in [
            "",
            "https://cwpreview.sh",
            "*.cwpreview.sh",
            "cwpreview.sh:443",
            "cwpreview.sh/path",
            ".cwpreview.sh",
            "cwpreview.sh.",
            "-bad.example",
            "bad-.example",
            "bad_name.example",
            "localhost",
            "127.0.0.1",
            "example.123",
            "example.0x7f",
        ] {
            assert!(!preview_domain_is_valid(domain));
        }
        assert!(!preview_domain_is_valid(&format!(
            "{}.test",
            "a".repeat(64)
        )));
        assert!(!preview_domain_is_valid(&format!(
            "{}.{}.{}.{}.test",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        )));
    }

    fn assert_coded(
        error: AppError,
        expected_status: StatusCode,
        expected_code: &'static str,
    ) -> String {
        match error {
            AppError::Coded {
                status,
                code,
                detail,
            } => {
                assert_eq!(status, expected_status);
                assert_eq!(code, expected_code);
                detail.into_owned()
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn repository_analysis_is_required_only_for_unresolved_repositories() {
        let repository = codewire_project::parse_project_yaml(
            "repositories: [{source: https://example.test/org/app.git}]\n",
        )
        .unwrap()
        .spec;
        let body = CreateEnvironmentBody {
            project_spec: repository.clone(),
            ..Default::default()
        };
        assert!(requires_repository_analysis(&body));

        for project_spec in [
            codewire_project::ProjectSpec {
                image: "ghcr.io/example/workspace:1".to_owned(),
                ..repository.clone()
            },
            codewire_project::ProjectSpec {
                preset: "workspace".to_owned(),
                ..repository
            },
        ] {
            assert!(!requires_repository_analysis(&CreateEnvironmentBody {
                project_spec,
                ..Default::default()
            }));
        }

        assert!(!requires_repository_analysis(
            &CreateEnvironmentBody::default()
        ));

        let canary = "synthetic-repository-credential-material";
        let detail = assert_coded(
            repository_analysis_pending(),
            StatusCode::BAD_REQUEST,
            "project_feature_pending",
        );
        assert!(!detail.contains(canary));
    }

    #[test]
    fn resolved_preset_accepts_only_nonrecursive_secret_blind_project_specs() {
        validate_resolved_preset(None).unwrap();
        validate_resolved_preset(Some(&preset(codewire_project::ProjectSpec::default()))).unwrap();

        let recursive = preset(codewire_project::ProjectSpec {
            preset: "nested".to_owned(),
            ..Default::default()
        });
        assert_eq!(
            assert_coded(
                validate_resolved_preset(Some(&recursive)).unwrap_err(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_preset"
            ),
            "preset project specification cannot select another preset"
        );

        let secret = preset(
            codewire_project::parse_project_yaml(
                "secrets: {project: do-not-render-this-binding}\n",
            )
            .unwrap()
            .spec,
        );
        let detail = assert_coded(
            validate_resolved_preset(Some(&secret)).unwrap_err(),
            StatusCode::BAD_REQUEST,
            "secret_delivery_pending",
        );
        assert!(!detail.contains("do-not-render-this-binding"));
    }

    #[test]
    fn prepare_rejects_a_malformed_org_owned_official_preset() {
        let mut malformed = preset(codewire_project::ProjectSpec::default());
        malformed.official = true;
        assert!(!preset_is_visible_to_org(
            malformed.org_id.as_deref(),
            malformed.official,
            "org-test"
        ));
    }

    #[test]
    fn project_preset_lookup_errors_are_not_silently_ignored() {
        let missing = require_preset_lookup(
            "detected",
            Err(anyhow::Error::new(sqlx::Error::RowNotFound)),
        )
        .unwrap_err();
        assert_eq!(
            assert_coded(missing, StatusCode::BAD_REQUEST, "preset_not_found"),
            "preset not found: detected"
        );

        let canary = "synthetic-invalid-preset-do-not-render";
        let invalid = require_preset_lookup("detected", Err(anyhow::anyhow!(canary))).unwrap_err();
        let detail = assert_coded(invalid, StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
        assert_eq!(detail, "failed to resolve preset");
        assert!(!detail.contains(canary));
    }
}
